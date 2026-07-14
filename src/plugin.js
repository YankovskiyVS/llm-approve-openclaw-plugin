import { types as utilTypes } from 'node:util';
import { createAction, createJudgeEnvelope } from './action.js';
import { buildAuditEvent, createAuditWriter } from './audit.js';
import {
  APPROVAL_TIMEOUT_MS,
  MIN_CONFIDENCE,
  PLUGIN_ID,
} from './constants.js';
import { createContextStore } from './context-store.js';
import {
  applyLocalSafetyDowngrade,
  applyOpaqueDowngrade,
  mapVerdict,
  normalizeVerdict,
  parseJudgeResponse,
} from './decision.js';
import { resolveRuntimeSettings } from './environment.js';
import {
  JUDGE_DECISIONS,
  JUDGE_VERDICT_KEYS,
  validateJudgeVerdict,
} from './judge-schema.js';
import { createJudgeClient } from './judge-client.js';

const PLUGIN_NAME = 'LLM Action Judge';
const PLUGIN_DESCRIPTION = 'LLM-gated tool-call approval for OpenClaw';
const HOOK_PRIORITY = -1000;
const STORE_TTL_MS = 30 * 60 * 1000;
const STORE_MAX_ENTRIES = 1000;
const MAX_PROMPT_BYTES = 64 * 1024;
const SETUP_FAILED_MESSAGE = 'LLM action judge setup failed';
const REGISTERED_MESSAGE = 'LLM action judge registered';
const FAILURE_REASON = 'judge evaluation failed';
const SAFE_CONFIG = Object.freeze({ mode: 'supervised', enforcement: 'enforce' });
const LOG_LEVEL_RANK = Object.freeze({ silent: -1, error: 0, warn: 1, info: 2 });
const OUTCOMES = new Set(JUDGE_DECISIONS);
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const VERDICT_KEY_SET = new Set(JUDGE_VERDICT_KEYS);

function readData(source, key) {
  try {
    if ((source === null || typeof source !== 'object') && typeof source !== 'function') {
      return { ok: false, value: undefined };
    }
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (!descriptor) return { ok: true, value: undefined };
    if (!Object.hasOwn(descriptor, 'value')) return { ok: false, value: undefined };
    return { ok: true, value: descriptor.value };
  } catch {
    return { ok: false, value: undefined };
  }
}

function methodValue(source, name) {
  try {
    if ((source === null || typeof source !== 'object') && typeof source !== 'function') {
      return null;
    }
    const seen = new Set();
    let current = source;
    while (current !== null && !seen.has(current)) {
      seen.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, name);
      if (descriptor) {
        return Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function'
          ? descriptor.value
          : null;
      }
      current = Object.getPrototypeOf(current);
    }
  } catch {
    // Hostile accessors and proxies are treated as unavailable dependencies.
  }
  return null;
}

function nestedData(source, keys) {
  let current = source;
  for (const key of keys) {
    const field = readData(current, key);
    if (!field.ok) return { ok: false, value: undefined };
    current = field.value;
  }
  return { ok: true, value: current };
}

function suppressRejection(value) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return;
  try {
    Promise.resolve(value).catch(() => {});
  } catch {
    // A hostile thenable cannot affect capture or registration.
  }
}

function dependencyValue(deps, key, fallback) {
  const value = readData(deps, key);
  if (!value.ok || value.value === undefined) return fallback;
  return value.value;
}

function isNonBlankString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function promptIsTrusted(value) {
  try {
    return isNonBlankString(value) && Buffer.byteLength(value, 'utf8') <= MAX_PROMPT_BYTES;
  } catch {
    return false;
  }
}

function consistentValue(event, ctx, key, required) {
  const fromEvent = readData(event, key);
  const fromContext = readData(ctx, key);
  if (!fromEvent.ok || !fromContext.ok) return { ok: false };

  const eventPresent = isNonBlankString(fromEvent.value);
  const contextPresent = isNonBlankString(fromContext.value);
  if (eventPresent && contextPresent && fromEvent.value !== fromContext.value) {
    return { ok: false };
  }
  const value = eventPresent ? fromEvent.value : (contextPresent ? fromContext.value : undefined);
  if (required && value === undefined) return { ok: false };
  return { ok: true, value };
}

function identitySnapshot(event, ctx) {
  const runId = consistentValue(event, ctx, 'runId', true);
  const toolCallId = consistentValue(event, ctx, 'toolCallId', false);
  const toolName = consistentValue(event, ctx, 'toolName', true);
  if (!runId.ok || !toolCallId.ok || !toolName.ok) return { ok: false };
  return {
    ok: true,
    runId: runId.value,
    toolCallId: toolCallId.value,
    toolName: toolName.value,
  };
}

function plainParams(action) {
  const params = readData(action, 'params');
  if (!params.ok || params.value === null || typeof params.value !== 'object'
    || Array.isArray(params.value)) return null;
  return params.value;
}

function actionMatchesIdentity(action, identity) {
  if (!identity.ok) return false;
  const runId = readData(action, 'run_id');
  const toolCallId = readData(action, 'tool_call_id');
  const toolName = readData(action, 'tool_name');
  if (!runId.ok || !toolCallId.ok || !toolName.ok) return false;
  return runId.value === identity.runId
    && toolName.value === identity.toolName
    && (identity.toolCallId === undefined || toolCallId.value === identity.toolCallId);
}

function safeLatency(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0;
}

function failure() {
  return { kind: 'failure', reason: FAILURE_REASON };
}

function getStoredPrompt(store, runId) {
  try {
    const get = methodValue(store, 'get');
    if (!get) return undefined;
    const value = get.call(store, runId);
    if (typeof value === 'string') return value;
    suppressRejection(value);
  } catch {
    // Missing trusted intent is the safe result for all store failures.
  }
  return undefined;
}

function verdictSnapshot(value, expectedHash) {
  try {
    if (value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || utilTypes.isProxy(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== JUDGE_VERDICT_KEYS.length
      || keys.some((key) => typeof key !== 'string' || !VERDICT_KEY_SET.has(key))) {
      return null;
    }
    const snapshot = {};
    for (const key of JUDGE_VERDICT_KEYS) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return null;
      }
      snapshot[key] = descriptor.value;
    }
    validateJudgeVerdict(snapshot);
    if (typeof expectedHash !== 'string'
      || snapshot.action_hash !== expectedHash
      || !snapshot.rationale.trim()
      || snapshot.rationale.length > 500
      || CONTROL_PATTERN.test(snapshot.rationale)) return null;
    return Object.freeze(snapshot);
  } catch {
    return null;
  }
}

function normalizedSnapshot(value, verdict) {
  const kind = readData(value, 'kind');
  if (!kind.ok || !OUTCOMES.has(kind.value)) return null;
  const locallySafeAllow = verdict.decision === 'allow'
    && verdict.risk === 'low'
    && verdict.authorization === 'high'
    && typeof verdict.confidence === 'number'
    && Number.isFinite(verdict.confidence)
    && verdict.confidence >= MIN_CONFIDENCE;
  if (kind.value === 'allow' && !locallySafeAllow) return null;
  if (kind.value === 'deny' && verdict.decision !== 'deny') return null;
  if (kind.value === 'review'
    && verdict.decision !== 'review'
    && !(verdict.decision === 'allow' && !locallySafeAllow)) return null;
  return { kind: kind.value, verdict };
}

function safeFallbackMapping(config, result, params) {
  if (config.enforcement === 'shadow') return undefined;
  if (result.kind === 'allow') return { params };
  if (result.kind === 'deny') {
    return { block: true, blockReason: 'LLM action judge denied the tool call' };
  }
  if (config.mode === 'supervised') {
    return {
      params,
      requireApproval: {
        title: 'LLM action judge review required',
        description: 'LLM action judge could not safely allow this tool call. Approve this call once to continue.',
        severity: 'critical',
        timeoutMs: APPROVAL_TIMEOUT_MS,
        timeoutBehavior: 'deny',
        pluginId: PLUGIN_ID,
      },
    };
  }
  return { block: true, blockReason: 'LLM action judge review required' };
}

function mapSafely(config, result, params) {
  try {
    return mapVerdict({ ...config, result, params });
  } catch {
    return safeFallbackMapping(config, failure(), params);
  }
}

async function writeAuditBestEffort(audit, input) {
  try {
    const write = methodValue(audit, 'write');
    if (!write) return;
    const event = buildAuditEvent(input);
    await Promise.resolve().then(() => write.call(audit, event));
  } catch {
    // Audit availability never changes the tool decision.
  }
}

function createLifecycleLogger(api, logLevel) {
  const configuredRank = LOG_LEVEL_RANK[logLevel] ?? LOG_LEVEL_RANK.error;

  function notify(level, message) {
    if (configuredRank < LOG_LEVEL_RANK[level]) return;
    try {
      const logger = readData(api, 'logger');
      if (!logger.ok) return;
      const method = methodValue(logger.value, level);
      if (!method) return;
      suppressRejection(method.call(logger.value, message));
    } catch {
      // Logger failures cannot affect registration or tool decisions.
    }
  }

  return Object.freeze({
    error(message) { notify('error', message); },
    warn(message) { notify('warn', message); },
    info(message) { notify('info', message); },
  });
}

function notifySetupFailure(logger) {
  try {
    const error = methodValue(logger, 'error');
    if (!error) return;
    suppressRejection(error.call(logger, SETUP_FAILED_MESSAGE));
  } catch {
    // Logger failures cannot undo registered hooks.
  }
}

function inertStore() {
  return { put() {}, get() { return undefined; } };
}

function failingClient() {
  return { async review() { return { ok: false, reason: FAILURE_REASON, latencyMs: 0 }; } };
}

function inertAudit() {
  return { async write() { return false; } };
}

export function createActionJudgePlugin(deps = {}) {
  const injectedStore = dependencyValue(deps, 'store', undefined);
  const injectedClient = dependencyValue(deps, 'client', undefined);
  const injectedAudit = dependencyValue(deps, 'audit', undefined);
  const storeFactory = dependencyValue(deps, 'createContextStore', createContextStore);
  const clientFactory = dependencyValue(deps, 'createJudgeClient', createJudgeClient);
  const auditFactory = dependencyValue(deps, 'createAuditWriter', createAuditWriter);
  const injectedEnvironment = dependencyValue(deps, 'environment', undefined);
  const parse = dependencyValue(deps, 'parseJudgeResponse', parseJudgeResponse);
  const normalize = dependencyValue(deps, 'normalizeVerdict', normalizeVerdict);

  function register(api) {
    let setupFailed = false;
    let settingsValid = true;
    let settings;
    let config;
    const pluginConfig = readData(api, 'pluginConfig');
    try {
      if (!pluginConfig.ok) throw new TypeError('invalid plugin config');
      settings = resolveRuntimeSettings({
        environment: injectedEnvironment === undefined ? process.env : injectedEnvironment,
        pluginConfig: pluginConfig.value,
        getSharedProvider() {
          const provider = nestedData(api, ['config', 'models', 'providers', 'cloudru']);
          if (!provider.ok) throw new TypeError('invalid provider config');
          return provider.value;
        },
      });
      config = settings.config;
    } catch {
      config = SAFE_CONFIG;
      settingsValid = false;
      setupFailed = true;
    }
    const lifecycleLogger = createLifecycleLogger(
      api,
      settingsValid ? settings.logLevel : 'error',
    );

    let store = injectedStore;
    if (store === undefined) {
      try {
        if (typeof storeFactory !== 'function') throw new TypeError('invalid store factory');
        store = storeFactory({
          ttlMs: STORE_TTL_MS,
          maxEntries: STORE_MAX_ENTRIES,
          now: Date.now,
        });
      } catch {
        store = inertStore();
        setupFailed = true;
      }
    }

    let client = injectedClient;
    if (!settingsValid) {
      client = failingClient();
    } else if (client === undefined) {
      try {
        if (typeof clientFactory !== 'function') throw new TypeError('invalid client factory');
        client = clientFactory({
          providerConfig: settings.providerConfig,
          timeoutMs: settings.timeoutMs,
        });
      } catch {
        client = failingClient();
        setupFailed = true;
      }
    }

    let audit = injectedAudit;
    if (!settingsValid) {
      audit = inertAudit();
    } else if (audit === undefined) {
      try {
        if (typeof auditFactory !== 'function') throw new TypeError('invalid audit factory');
        audit = auditFactory({
          filePath: settings.auditPath,
          rootPath: settings.auditRoot,
          logger: lifecycleLogger,
        });
      } catch {
        audit = inertAudit();
        setupFailed = true;
      }
    }

    function captureTrustedIntent(event, ctx) {
      try {
        const prompt = readData(event, 'prompt');
        const runId = readData(ctx, 'runId');
        if (!prompt.ok || !runId.ok || !promptIsTrusted(prompt.value)
          || !isNonBlankString(runId.value)) return;
        const put = methodValue(store, 'put');
        if (!put) return;
        suppressRejection(put.call(store, runId.value, prompt.value));
      } catch {
        // Capture is deliberately fail-safe and has no transcript fallback.
      }
    }

    async function gateToolCall(event, ctx) {
      let action;
      let params = {};
      let judgeResult;
      let latencyMs = 0;
      let result = failure();

      try {
        const identity = identitySnapshot(event, ctx);
        let envelope;
        let expectedHash;
        try {
          action = createAction({ event, ctx });
          const copiedParams = plainParams(action);
          if (copiedParams !== null) params = copiedParams;
          envelope = createJudgeEnvelope(action);
          const hash = readData(envelope, 'action_hash');
          expectedHash = hash.ok ? hash.value : undefined;
        } catch {
          envelope = undefined;
        }

        if (identity.ok && actionMatchesIdentity(action, identity)
          && envelope !== undefined && typeof expectedHash === 'string') {
          const userPrompt = getStoredPrompt(store, identity.runId);
          if (promptIsTrusted(userPrompt)) {
            const review = methodValue(client, 'review');
            if (review) {
              const reviewed = await Promise.resolve().then(() => review.call(client, {
                userPrompt,
                envelope,
              }));
              const ok = readData(reviewed, 'ok');
              const latency = readData(reviewed, 'latencyMs');
              latencyMs = safeLatency(latency.ok ? latency.value : undefined);
              if (ok.ok && ok.value === true) {
                const text = readData(reviewed, 'text');
                if (text.ok && typeof text.value === 'string' && typeof parse === 'function') {
                  const parsed = parse(text.value, { expectedHash });
                  const parsedOk = readData(parsed, 'ok');
                  const parsedVerdict = readData(parsed, 'verdict');
                  if (parsedOk.ok && parsedOk.value === true && parsedVerdict.ok) {
                    const verdict = verdictSnapshot(parsedVerdict.value, expectedHash);
                    if (verdict && typeof normalize === 'function') {
                      const normalized = normalize(verdict);
                      const safeNormalized = normalizedSnapshot(normalized, verdict);
                      if (safeNormalized) {
                        judgeResult = verdict;
                        const envelopeParams = readData(createJudgeEnvelope(action), 'params');
                        const envelopeTool = readData(envelope, 'tool_name');
                        result = applyLocalSafetyDowngrade(
                          applyOpaqueDowngrade(safeNormalized, envelopeParams.value),
                          envelopeTool.ok ? envelopeTool.value : undefined,
                          envelopeParams.value,
                          action,
                        );
                      }
                    }
                  }
                }
              }
            }
          }
        }

        if (result.kind === 'allow') {
          try {
            const freshIdentity = identitySnapshot(event, ctx);
            const freshAction = createAction({ event, ctx });
            const freshEnvelope = createJudgeEnvelope(freshAction);
            const freshHash = readData(freshEnvelope, 'action_hash');
            const freshParams = plainParams(freshAction);
            if (!freshIdentity.ok
              || !actionMatchesIdentity(freshAction, freshIdentity)
              || !freshHash.ok
              || freshHash.value !== expectedHash
              || freshParams === null) {
              result = failure();
            } else {
              action = freshAction;
              params = freshParams;
            }
          } catch {
            result = failure();
          }
        }
      } catch {
        result = failure();
      }

      try {
        await writeAuditBestEffort(audit, {
          action,
          judgeResult,
          normalized: result,
          latencyMs,
          mode: config.mode,
          enforcement: config.enforcement,
        });
        return mapSafely(config, result, params);
      } catch {
        return safeFallbackMapping(config, failure(), params);
      }
    }

    const on = methodValue(api, 'on');
    if (on) {
      try {
        on.call(api, 'before_model_resolve', captureTrustedIntent, { priority: HOOK_PRIORITY });
      } catch {
        setupFailed = true;
      }
      try {
        on.call(api, 'before_tool_call', gateToolCall, { priority: HOOK_PRIORITY });
      } catch {
        setupFailed = true;
      }
    } else {
      setupFailed = true;
    }

    if (setupFailed) {
      notifySetupFailure(lifecycleLogger);
    } else {
      lifecycleLogger.info(REGISTERED_MESSAGE);
    }
  }

  return {
    id: PLUGIN_ID,
    name: PLUGIN_NAME,
    description: PLUGIN_DESCRIPTION,
    register,
  };
}
