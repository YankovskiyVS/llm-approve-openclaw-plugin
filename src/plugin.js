import { types as utilTypes } from 'node:util';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAction, createJudgeEnvelope } from './action.js';
import { scheduleA2ABridgeAttach } from './a2a-bridge-adapter.js';
import { createAutoApproveStore } from './autoapprove-store.js';
import { buildAuditEvent, createAuditWriter } from './audit.js';
import {
  APPROVAL_TIMEOUT_MS,
  isTrustedUserRequest,
  MIN_CONFIDENCE,
  PLUGIN_ID,
} from './constants.js';
import { extractAutoApproveMarker } from './control-marker.js';
import { createContextStore } from './context-store.js';
import {
  createApprovalDescription,
  createBlockFeedback,
  feedbackRequiresBlock,
  selectFeedbackCode,
  selectFeedbackOutcome,
} from './feedback.js';
import {
  applyLocalSafetyDowngrade,
  applyOpaqueDowngrade,
  mapVerdict,
  normalizeVerdict,
  parseJudgeResponse,
} from './decision.js';
import { resolvePolicySettings, resolveRuntimeSettings } from './environment.js';
import {
  JUDGE_DECISIONS,
  JUDGE_VERDICT_KEYS,
  validateJudgeVerdict,
} from './judge-schema.js';
import { createJudgeClient } from './judge-client.js';
import {
  arrayPrototypeIsPristine,
  objectPrototypeIsPristine,
} from './intrinsics.js';
import {
  classifyToolFamily,
  createRunDecisionStore,
} from './run-decision-store.js';
import { assessPolicyRoute } from './policy-routing.js';
import { redactForJudgeWithProvenance } from './redact.js';
import { resolveAgentModelId } from './model-id.js';

const PLUGIN_NAME = 'LLM Action Judge';
const PLUGIN_DESCRIPTION = 'LLM-gated tool-call approval for OpenClaw';
// Survive OpenClaw mid-run plugin re-registration (browser auto-enable / config
// rewrite). Without a process-wide store, before_model_resolve intent is wiped
// and before_tool_call fails closed with invalid_judge_response in ~10ms.
const PROCESS_STORES_KEY = '__openclaw_llm_action_judge_stores_v1__';
const HOOK_PRIORITY = -1000;
const STORE_TTL_MS = 30 * 60 * 1000;
const STORE_MAX_ENTRIES = 1000;
const DECISION_STORE_HISTORY_LIMIT = 50;
const DECISION_STORE_CONSECUTIVE_DENY_LIMIT = 3;
const DECISION_STORE_ROLLING_DENY_LIMIT = 10;
const PLUGIN_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const MAX_DECISION_ID_LENGTH = 256;
const MAX_DECISION_ID_BYTES = 512;
const SETUP_FAILED_MESSAGE = 'LLM action judge setup failed';
const REGISTERED_MESSAGE = 'LLM action judge registered';
const FAILURE_REASON = 'judge evaluation failed';
const SAFE_CONFIG = Object.freeze({ mode: 'supervised', enforcement: 'enforce' });
const SAFE_AUDIT_ROOT = join(homedir(), '.openclaw', 'logs');
const SAFE_POLICY_SETTINGS = Object.freeze({
  config: SAFE_CONFIG,
  auditPath: join(SAFE_AUDIT_ROOT, 'llm-action-judge.jsonl'),
  auditRoot: SAFE_AUDIT_ROOT,
});
const LOG_LEVEL_RANK = Object.freeze({ silent: -1, error: 0, warn: 1, info: 2 });
const OUTCOMES = new Set(JUDGE_DECISIONS);
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const VERDICT_KEY_SET = new Set(JUDGE_VERDICT_KEYS);
const ARRAY_IS_ARRAY = Array.isArray;
const ARRAY_PROTOTYPE = Array.prototype;
const BUFFER_OBJECT = Buffer;
const BUFFER_BYTE_LENGTH = Buffer.byteLength;
const OBJECT_PROTOTYPE = Object.prototype;
const GET_PROTOTYPE_OF = Object.getPrototypeOf;
const SET_PROTOTYPE_OF = Object.setPrototypeOf;
const GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const HAS_OWN = Object.hasOwn;
const REFLECT_OWN_KEYS = Reflect.ownKeys;
const CREATE_OBJECT = Object.create;
const FREEZE_OBJECT = Object.freeze;
const IS_PROXY = utilTypes.isProxy;
const REFLECT_APPLY = Reflect.apply;
const REGEXP_TEST = RegExp.prototype.test;
const SET_HAS = Set.prototype.has;
const STRING_TRIM = String.prototype.trim;
const DECISION_STATUS_KEYS = Object.freeze([
  'already_tripped',
  'newly_tripped',
  'tripped',
]);
const ROUTE_RESULT_KEYS = Object.freeze([
  'route',
  'hard_boundary',
  'safe_path_candidate',
  'safe_path_family',
]);
const HARD_BOUNDARIES = new Set([
  'self_modification',
  'secret_external_sink',
  'security_boundary_bypass',
]);
const SAFE_PATH_FAMILIES = new Set(['session_status_current', 'browser_wait']);

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
  return typeof value === 'string' && REFLECT_APPLY(STRING_TRIM, value, []) !== '';
}

function validDecisionIdentityValue(value) {
  return typeof value === 'string'
    && value.length > 0
    && REFLECT_APPLY(STRING_TRIM, value, []) !== ''
    && value.length <= MAX_DECISION_ID_LENGTH
    && REFLECT_APPLY(BUFFER_BYTE_LENGTH, BUFFER_OBJECT, [value, 'utf8'])
      <= MAX_DECISION_ID_BYTES
    && !REFLECT_APPLY(REGEXP_TEST, CONTROL_PATTERN, [value]);
}

function boundedDecisionIdentity(identity) {
  if (!identity.ok
    || !validDecisionIdentityValue(identity.runId)
    || !validDecisionIdentityValue(identity.toolName)) return false;
  try {
    classifyToolFamily(identity.toolName);
    return true;
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

function detachInheritedParams(value, ancestors) {
  let lineage = ancestors;
  if (lineage === undefined) {
    lineage = [];
    SET_PROTOTYPE_OF(lineage, null);
  }
  const valueType = typeof value;
  if (value === null
    || valueType === 'string'
    || valueType === 'number'
    || valueType === 'boolean') return true;
  if (typeof value !== 'object' || utilTypes.isProxy(value)) return false;
  for (let index = 0; index < lineage.length; index += 1) {
    if (lineage[index] === value) return false;
  }
  const prototype = GET_PROTOTYPE_OF(value);
  if (ARRAY_IS_ARRAY(value)) {
    if (prototype !== ARRAY_PROTOTYPE && prototype !== null) return false;
    SET_PROTOTYPE_OF(value, null);
  } else {
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return false;
    SET_PROTOTYPE_OF(value, null);
  }
  lineage[lineage.length] = value;
  try {
    const keys = REFLECT_OWN_KEYS(value);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (typeof key !== 'string') return false;
      if (key === 'length') continue;
      const descriptor = GET_OWN_PROPERTY_DESCRIPTOR(value, key);
      if (!descriptor || !HAS_OWN(descriptor, 'value')
        || !detachInheritedParams(descriptor.value, lineage)) return false;
    }
    return true;
  } finally {
    lineage.length -= 1;
  }
}

function safeParamsAfterPrototypePollution(params) {
  if (objectPrototypeIsPristine() && arrayPrototypeIsPristine()) return params;
  try {
    return detachInheritedParams(params) ? params : CREATE_OBJECT(null);
  } catch {
    return CREATE_OBJECT(null);
  }
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

function failure(feedbackCode = 'invalid_judge_response') {
  return { kind: 'failure', reason: FAILURE_REASON, feedback_code: feedbackCode };
}

function clientFailureCode(reviewed) {
  const reason = readData(reviewed, 'reason');
  return reason.ok
    && (reason.value === 'invalid judge request' || reason.value === 'invalid judge response')
    ? 'invalid_judge_response'
    : 'judge_unavailable';
}

function invalidDecisionStore() {
  throw new TypeError('invalid run decision store');
}

function decisionStoreMethod(store, name) {
  try {
    if (store === null || typeof store !== 'object' || ARRAY_IS_ARRAY(store)
      || IS_PROXY(store)) return null;
    const prototype = GET_PROTOTYPE_OF(store);
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return null;
    const descriptor = GET_OWN_PROPERTY_DESCRIPTOR(store, name);
    if (!descriptor || !HAS_OWN(descriptor, 'value')
      || typeof descriptor.value !== 'function' || IS_PROXY(descriptor.value)) return null;
    return descriptor.value;
  } catch {
    return null;
  }
}

function readDecisionStoreTrip(store, runId) {
  const isTripped = decisionStoreMethod(store, 'isTripped');
  if (!isTripped) return invalidDecisionStore();
  const value = REFLECT_APPLY(isTripped, store, [runId]);
  if (value === true || value === false) return value;
  suppressRejection(value);
  return invalidDecisionStore();
}

function decisionStatusSnapshot(value) {
  try {
    if (value === null || typeof value !== 'object' || ARRAY_IS_ARRAY(value)
      || IS_PROXY(value)) return null;
    const prototype = GET_PROTOTYPE_OF(value);
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return null;
    const keys = REFLECT_OWN_KEYS(value);
    if (keys.length !== DECISION_STATUS_KEYS.length) return null;
    const result = CREATE_OBJECT(null);
    for (let index = 0; index < DECISION_STATUS_KEYS.length; index += 1) {
      const key = DECISION_STATUS_KEYS[index];
      const descriptor = GET_OWN_PROPERTY_DESCRIPTOR(value, key);
      if (!descriptor || !descriptor.enumerable || !HAS_OWN(descriptor, 'value')
        || typeof descriptor.value !== 'boolean') return null;
      result[key] = descriptor.value;
    }
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (typeof key !== 'string'
        || (key !== 'already_tripped' && key !== 'newly_tripped' && key !== 'tripped')) {
        return null;
      }
    }
    const valid = !result.already_tripped && !result.newly_tripped && !result.tripped
      || !result.already_tripped && result.newly_tripped && result.tripped
      || result.already_tripped && !result.newly_tripped && result.tripped;
    return valid ? result : null;
  } catch {
    return null;
  }
}

function metadataAllowsNewTrip(metadata) {
  try {
    const outcome = GET_OWN_PROPERTY_DESCRIPTOR(metadata, 'outcome');
    const reasonCode = GET_OWN_PROPERTY_DESCRIPTOR(metadata, 'reason_code');
    return outcome && HAS_OWN(outcome, 'value') && outcome.value === 'deny'
      && reasonCode && HAS_OWN(reasonCode, 'value')
      && typeof reasonCode.value === 'string'
      && reasonCode.value !== 'repeated_denials';
  } catch {
    return false;
  }
}

function recordRunDecision(store, runId, metadata) {
  const record = decisionStoreMethod(store, 'record');
  if (!record) return invalidDecisionStore();
  const allowsNewTrip = metadataAllowsNewTrip(metadata);
  const value = REFLECT_APPLY(record, store, [runId, metadata]);
  const snapshot = decisionStatusSnapshot(value);
  if (snapshot && (!snapshot.newly_tripped || allowsNewTrip)) return snapshot;
  suppressRejection(value);
  return invalidDecisionStore();
}

function repeatedDenials() {
  return { kind: 'deny', feedback_code: 'repeated_denials' };
}

function hardPolicyBlock() {
  return { kind: 'deny', feedback_code: 'hard_policy_block' };
}

function applyTechnicalFailureMonotonically(result, decisionSource) {
  const kind = readData(result, 'kind');
  if (decisionSource === 'circuit_breaker'
    || decisionSource === 'hard_boundary'
    || kind.ok && kind.value === 'deny') {
    return { result, decisionSource };
  }
  return { result: failure(), decisionSource: 'failure' };
}

function policyRouteSnapshot(value) {
  try {
    if (value === null || typeof value !== 'object' || ARRAY_IS_ARRAY(value)
      || IS_PROXY(value)) return null;
    const prototype = GET_PROTOTYPE_OF(value);
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return null;
    const keys = REFLECT_OWN_KEYS(value);
    if (keys.length !== ROUTE_RESULT_KEYS.length) return null;
    const snapshot = CREATE_OBJECT(null);
    for (let index = 0; index < ROUTE_RESULT_KEYS.length; index += 1) {
      const key = ROUTE_RESULT_KEYS[index];
      const descriptor = GET_OWN_PROPERTY_DESCRIPTOR(value, key);
      if (!descriptor || !descriptor.enumerable || !HAS_OWN(descriptor, 'value')) return null;
      snapshot[key] = descriptor.value;
    }
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (typeof key !== 'string'
        || (key !== 'route'
          && key !== 'hard_boundary'
          && key !== 'safe_path_candidate'
          && key !== 'safe_path_family')) return null;
    }
    if (snapshot.route === 'hard_deny') {
      return typeof snapshot.hard_boundary === 'string'
        && REFLECT_APPLY(SET_HAS, HARD_BOUNDARIES, [snapshot.hard_boundary])
        && snapshot.safe_path_candidate === false
        && snapshot.safe_path_family === null
        ? snapshot
        : null;
    }
    if (snapshot.route !== 'judge' || snapshot.hard_boundary !== null
      || typeof snapshot.safe_path_candidate !== 'boolean') return null;
    if (snapshot.safe_path_candidate) {
      return typeof snapshot.safe_path_family === 'string'
        && REFLECT_APPLY(SET_HAS, SAFE_PATH_FAMILIES, [snapshot.safe_path_family])
        ? snapshot
        : null;
    }
    return snapshot.safe_path_family === null ? snapshot : null;
  } catch {
    return null;
  }
}

function samePolicyRoute(left, right) {
  return left !== null
    && right !== null
    && left.route === right.route
    && left.hard_boundary === right.hard_boundary
    && left.safe_path_candidate === right.safe_path_candidate
    && left.safe_path_family === right.safe_path_family;
}

function freezeDetachedData(value, ancestors) {
  let lineage = ancestors;
  if (lineage === undefined) {
    lineage = [];
    SET_PROTOTYPE_OF(lineage, null);
  }
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object' || IS_PROXY(value)) return false;
  for (let index = 0; index < lineage.length; index += 1) {
    if (lineage[index] === value) return false;
  }
  const prototype = GET_PROTOTYPE_OF(value);
  if (ARRAY_IS_ARRAY(value)) {
    if (prototype !== ARRAY_PROTOTYPE && prototype !== null) return false;
  } else if (prototype !== OBJECT_PROTOTYPE && prototype !== null) {
    return false;
  }
  lineage[lineage.length] = value;
  try {
    const keys = REFLECT_OWN_KEYS(value);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (typeof key !== 'string') return false;
      if (key === 'length' && ARRAY_IS_ARRAY(value)) continue;
      const descriptor = GET_OWN_PROPERTY_DESCRIPTOR(value, key);
      if (!descriptor || !HAS_OWN(descriptor, 'value')
        || !freezeDetachedData(descriptor.value, lineage)) return false;
    }
    FREEZE_OBJECT(value);
    return true;
  } finally {
    lineage.length -= 1;
  }
}

function immutableVisibleParams(action) {
  const envelope = createJudgeEnvelope(action);
  const params = readData(envelope, 'params');
  if (!params.ok || !freezeDetachedData(params.value)) {
    throw new TypeError('invalid visible params snapshot');
  }
  return params.value;
}

function ordinaryDecisionSource(result, judgeResult) {
  const kind = readData(result, 'kind');
  if (!kind.ok || kind.value === 'failure') return 'failure';
  const localGuard = readData(result, 'local_guard');
  const opaque = readData(result, 'opaque');
  const decision = readData(judgeResult, 'decision');
  if (localGuard.ok && localGuard.value === true
    || opaque.ok && opaque.value === true
    || decision.ok && decision.value === 'allow' && kind.value !== 'allow') {
    return 'local_downgrade';
  }
  return 'llm';
}

function decisionMetadata(identity, result, judgeResult) {
  const outcome = selectFeedbackOutcome(result);
  const reasonCode = outcome === 'allow'
    ? 'safe_and_authorized'
    : selectFeedbackCode(result);
  const repeated = reasonCode === 'repeated_denials';
  const risk = readData(judgeResult, 'risk');
  const authorization = readData(judgeResult, 'authorization');
  return {
    tool_name: identity.toolName,
    tool_family: classifyToolFamily(identity.toolName),
    outcome,
    risk: repeated ? null : (risk.ok && typeof risk.value === 'string' ? risk.value : null),
    authorization: repeated
      ? null
      : (authorization.ok && typeof authorization.value === 'string'
        ? authorization.value
        : null),
    reason_code: reasonCode,
  };
}

function getStoredPrompt(store, runId, sessionKey) {
  try {
    const get = methodValue(store, 'get');
    if (get && typeof runId === 'string' && runId.trim()) {
      const value = get.call(store, runId);
      if (typeof value === 'string') return value;
      suppressRejection(value);
    }
    // A2A tool calls often use a different runId (e.g. chatcmpl_*) than
    // before_model_resolve while sharing sessionKey=agent:…:a2a:{contextId}.
    const getBySession = methodValue(store, 'getBySession');
    if (getBySession && typeof sessionKey === 'string' && sessionKey.trim()) {
      const bySession = getBySession.call(store, sessionKey);
      if (typeof bySession === 'string') return bySession;
      suppressRejection(bySession);
    }
  } catch {
    // Missing trusted intent is the safe result for all store failures.
  }
  return undefined;
}

function getStoredModelId(store, runId, sessionKey) {
  try {
    const getModel = methodValue(store, 'getModel');
    if (getModel && typeof runId === 'string' && runId.trim()) {
      const value = getModel.call(store, runId);
      if (typeof value === 'string' && value.trim()) return value.trim();
      suppressRejection(value);
    }
    const getModelBySession = methodValue(store, 'getModelBySession');
    if (getModelBySession && typeof sessionKey === 'string' && sessionKey.trim()) {
      const bySession = getModelBySession.call(store, sessionKey);
      if (typeof bySession === 'string' && bySession.trim()) return bySession.trim();
      suppressRejection(bySession);
    }
  } catch {
    // Model fallback is handled by the judge client default.
  }
  return undefined;
}

function resolveHookModelId(event, ctx, fallbackModelId) {
  const eventModel = readData(event, 'model');
  const ctxModel = readData(ctx, 'model');
  const eventModelId = readData(event, 'modelId');
  const ctxModelId = readData(ctx, 'modelId');
  return resolveAgentModelId(
    eventModel.ok ? eventModel.value : undefined,
    ctxModel.ok ? ctxModel.value : undefined,
    eventModelId.ok ? eventModelId.value : undefined,
    ctxModelId.ok ? ctxModelId.value : undefined,
    fallbackModelId,
  );
}

function resolveCallIdForBridge(identity, action, event, ctx) {
  if (identity?.toolCallId && typeof identity.toolCallId === 'string' && identity.toolCallId.trim()) {
    return identity.toolCallId.trim();
  }
  const fromAction = readData(action, 'tool_call_id');
  if (fromAction.ok && typeof fromAction.value === 'string' && fromAction.value.trim()) {
    return fromAction.value.trim();
  }
  for (const [source, key] of [
    [event, 'toolCallId'],
    [ctx, 'toolCallId'],
    [event, 'callId'],
    [ctx, 'callId'],
  ]) {
    const value = readData(source, key);
    if (value.ok && typeof value.value === 'string' && value.value.trim()) {
      return value.value.trim();
    }
  }
  return undefined;
}

function resolveHookRunId(event, ctx) {
  const fromCtx = readData(ctx, 'runId');
  if (fromCtx.ok && isNonBlankString(fromCtx.value)) return fromCtx.value;
  const fromEvent = readData(event, 'runId');
  if (fromEvent.ok && isNonBlankString(fromEvent.value)) return fromEvent.value;
  return undefined;
}

function processLocalStores() {
  const root = globalThis;
  let bag = root[PROCESS_STORES_KEY];
  if (!bag || typeof bag !== 'object') {
    bag = Object.create(null);
    root[PROCESS_STORES_KEY] = bag;
  }
  return bag;
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
  const feedbackCode = selectFeedbackCode(result);
  if (result.kind === 'allow' && feedbackCode === null) return { params };
  if (result.kind === 'allow'
    || result.kind === 'deny'
    || feedbackRequiresBlock(feedbackCode)) {
    return { block: true, blockReason: createBlockFeedback(feedbackCode) };
  }
  if (config.mode === 'supervised') {
    return {
      params,
      requireApproval: {
        title: 'LLM action judge review required',
        description: createApprovalDescription(feedbackCode),
        severity: 'critical',
        timeoutMs: APPROVAL_TIMEOUT_MS,
        timeoutBehavior: 'deny',
        pluginId: PLUGIN_ID,
      },
    };
  }
  return { block: true, blockReason: createBlockFeedback(feedbackCode) };
}

function mapSafely(mapper, config, result, params, decisionSource) {
  try {
    if (typeof mapper !== 'function') throw new TypeError('invalid decision mapper');
    return {
      value: mapper({ ...config, result, params }),
      effectiveResult: result,
      effectiveDecisionSource: decisionSource,
      fellBack: false,
    };
  } catch {
    const effective = applyTechnicalFailureMonotonically(result, decisionSource);
    return {
      value: safeFallbackMapping(config, effective.result, params),
      effectiveResult: effective.result,
      effectiveDecisionSource: effective.decisionSource,
      fellBack: true,
    };
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
  return {
    put() {},
    get() { return undefined; },
    getModel() { return undefined; },
    getBySession() { return undefined; },
    getModelBySession() { return undefined; },
  };
}

function failingDecisionStore() {
  function unavailable() {
    return invalidDecisionStore();
  }
  return {
    isTripped: unavailable,
    record: unavailable,
    snapshot: unavailable,
    size: unavailable,
  };
}

function failingClient() {
  return { async review() { return { ok: false, reason: FAILURE_REASON, latencyMs: 0 }; } };
}

function inertAudit() {
  return { async write() { return false; } };
}

function sessionKeyFromHook(event, ctx) {
  const fromCtx = readData(ctx, 'sessionKey');
  if (fromCtx.ok && typeof fromCtx.value === 'string' && fromCtx.value.trim()) {
    return fromCtx.value.trim();
  }
  const fromEvent = readData(event, 'sessionKey');
  if (fromEvent.ok && typeof fromEvent.value === 'string' && fromEvent.value.trim()) {
    return fromEvent.value.trim();
  }
  return undefined;
}

function bridgeDecisionFromMapped(mapped) {
  if (mapped && mapped.block === true) return 'deny';
  if (mapped && mapped.requireApproval) return 'deny';
  if (mapped && mapped.params !== undefined && !mapped.block) return 'allow-once';
  return 'deny';
}

export function createActionJudgePlugin(deps = {}) {
  const injectedStore = dependencyValue(deps, 'store', undefined);
  const injectedClient = dependencyValue(deps, 'client', undefined);
  const injectedAudit = dependencyValue(deps, 'audit', undefined);
  const injectedDecisionStore = dependencyValue(deps, 'decisionStore', undefined);
  const injectedAutoApproveStore = dependencyValue(deps, 'autoApproveStore', undefined);
  const storeFactory = dependencyValue(deps, 'createContextStore', createContextStore);
  const decisionStoreFactory = dependencyValue(
    deps,
    'createRunDecisionStore',
    createRunDecisionStore,
  );
  const autoApproveStoreFactory = dependencyValue(
    deps,
    'createAutoApproveStore',
    createAutoApproveStore,
  );
  const clientFactory = dependencyValue(deps, 'createJudgeClient', createJudgeClient);
  const auditFactory = dependencyValue(deps, 'createAuditWriter', createAuditWriter);
  const assessRoute = dependencyValue(deps, 'assessPolicyRoute', assessPolicyRoute);
  const injectedEnvironment = dependencyValue(deps, 'environment', undefined);
  const parse = dependencyValue(deps, 'parseJudgeResponse', parseJudgeResponse);
  const normalize = dependencyValue(deps, 'normalizeVerdict', normalizeVerdict);
  const mapper = dependencyValue(deps, 'mapVerdict', mapVerdict);
  const bridgeAttach = dependencyValue(deps, 'scheduleA2ABridgeAttach', scheduleA2ABridgeAttach);

  function register(api) {
    let setupFailed = false;
    let enforcementRegistrationFailed = false;
    let settingsValid = true;
    let settings;
    let policySettings;
    let config;
    const pluginConfig = readData(api, 'pluginConfig');
    const settingsInput = {
      environment: injectedEnvironment === undefined ? process.env : injectedEnvironment,
      pluginConfig: pluginConfig.ok ? pluginConfig.value : undefined,
      getSharedProvider() {
        const provider = nestedData(api, ['config', 'models', 'providers', 'cloudru']);
        if (!provider.ok) throw new TypeError('invalid provider config');
        return provider.value;
      },
    };
    try {
      if (!pluginConfig.ok) throw new TypeError('invalid plugin config');
      policySettings = resolvePolicySettings(settingsInput);
      config = policySettings.config;
    } catch {
      policySettings = SAFE_POLICY_SETTINGS;
      config = SAFE_CONFIG;
      setupFailed = true;
    }
    try {
      if (!pluginConfig.ok) throw new TypeError('invalid plugin config');
      settings = resolveRuntimeSettings(settingsInput);
      config = settings.config;
    } catch {
      settingsValid = false;
      // A runtime-only configuration failure (provider, timeout, log level, or
      // an unknown OPENCLAW_JUDGE_* variable) must not inherit a policy-only
      // shadow profile. Keep policy paths available for deterministic routing
      // and audit, but make the effective delivery posture fail-closed.
      config = SAFE_CONFIG;
      setupFailed = true;
    }
    const lifecycleLogger = createLifecycleLogger(
      api,
      settingsValid ? settings.logLevel : 'error',
    );

    let store = injectedStore;
    if (store === undefined) {
      try {
        const bag = processLocalStores();
        if (bag.contextStore && typeof bag.contextStore.get === 'function') {
          store = bag.contextStore;
        } else {
          if (typeof storeFactory !== 'function') throw new TypeError('invalid store factory');
          store = storeFactory({
            ttlMs: STORE_TTL_MS,
            maxEntries: STORE_MAX_ENTRIES,
            now: Date.now,
          });
          bag.contextStore = store;
        }
      } catch {
        store = inertStore();
        setupFailed = true;
      }
    }

    let decisionStore = injectedDecisionStore;
    if (decisionStore === undefined) {
      try {
        const bag = processLocalStores();
        if (bag.decisionStore && typeof bag.decisionStore.isTripped === 'function') {
          decisionStore = bag.decisionStore;
        } else {
          if (typeof decisionStoreFactory !== 'function') {
            throw new TypeError('invalid decision store factory');
          }
          decisionStore = decisionStoreFactory({
            ttlMs: STORE_TTL_MS,
            maxRuns: STORE_MAX_ENTRIES,
            historyLimit: DECISION_STORE_HISTORY_LIMIT,
            consecutiveDenyLimit: DECISION_STORE_CONSECUTIVE_DENY_LIMIT,
            rollingDenyLimit: DECISION_STORE_ROLLING_DENY_LIMIT,
            now: Date.now,
          });
          bag.decisionStore = decisionStore;
        }
      } catch {
        decisionStore = failingDecisionStore();
        setupFailed = true;
      }
    }

    let client = injectedClient;
    const defaultsModel = nestedData(api, ['config', 'agents', 'defaults', 'model']);
    const agentDefaultModelId = resolveAgentModelId(
      defaultsModel.ok ? defaultsModel.value : undefined,
    );
    if (!settingsValid) {
      client = failingClient();
    } else if (client === undefined) {
      try {
        if (typeof clientFactory !== 'function') throw new TypeError('invalid client factory');
        client = clientFactory({
          providerConfig: settings.providerConfig,
          timeoutMs: settings.timeoutMs,
          ...(agentDefaultModelId ? { modelId: agentDefaultModelId } : {}),
        });
      } catch {
        client = failingClient();
        setupFailed = true;
      }
    }

    let audit = injectedAudit;
    if (audit === undefined && policySettings !== undefined) {
      try {
        if (typeof auditFactory !== 'function') throw new TypeError('invalid audit factory');
        audit = auditFactory({
          filePath: policySettings.auditPath,
          rootPath: policySettings.auditRoot,
          logger: lifecycleLogger,
        });
      } catch {
        audit = inertAudit();
        setupFailed = true;
      }
    }
    if (audit === undefined) audit = inertAudit();

    let autoApproveStore = injectedAutoApproveStore;
    if (autoApproveStore === undefined) {
      try {
        const bag = processLocalStores();
        if (bag.autoApproveStore && typeof bag.autoApproveStore.isActive === 'function') {
          autoApproveStore = bag.autoApproveStore;
        } else {
          if (typeof autoApproveStoreFactory !== 'function') {
            throw new TypeError('invalid autoapprove store factory');
          }
          autoApproveStore = autoApproveStoreFactory({
            ttlMs: STORE_TTL_MS,
            maxEntries: STORE_MAX_ENTRIES,
            now: Date.now,
          });
          bag.autoApproveStore = autoApproveStore;
        }
      } catch {
        autoApproveStore = createAutoApproveStore({
          ttlMs: STORE_TTL_MS,
          maxEntries: STORE_MAX_ENTRIES,
          now: Date.now,
        });
        setupFailed = true;
      }
    }

    try {
      if (typeof bridgeAttach === 'function') {
        bridgeAttach({
          autoApproveStore,
          logger: lifecycleLogger,
        });
      }
    } catch {
      // A2A adapter is best-effort; human HITL remains available via original bridge.
    }

    const a2aHitlReplace = settingsValid
      ? settings.a2aHitlReplace === true
      : false;

    function captureTrustedIntent(event, ctx) {
      try {
        const prompt = readData(event, 'prompt');
        const runId = resolveHookRunId(event, ctx);
        if (!prompt.ok || typeof prompt.value !== 'string' || runId === undefined) return;
        const extracted = extractAutoApproveMarker(prompt.value);
        const sessionKey = sessionKeyFromHook(event, ctx);
        if (extracted.enabled) {
          autoApproveStore.markRun(runId);
          if (sessionKey) autoApproveStore.markSession(sessionKey);
        }
        if (!isTrustedUserRequest(extracted.stripped)) return;
        const put = methodValue(store, 'put');
        if (!put) return;
        const modelId = resolveHookModelId(event, ctx, agentDefaultModelId);
        suppressRejection(put.call(store, runId, extracted.stripped, sessionKey, modelId));
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
      let expectedHash;
      let trackedIdentity;
      let decisionStoreCheckFailed = false;
      let skipJudge = false;
      let breakerCandidate = false;
      let hardBoundaryCandidate = false;
      let decisionSource = 'failure';
      let safePathCandidate = false;
      let safePathFamily = null;
      let safePathDisagreement = null;
      let routeSnapshot;
      let localVisibleParams;
      let localToolName;
      let routeAssessmentFailed = false;
      let assessingRoute = false;
      let mappedDecision;
      let autoApproveActive = false;

      try {
        const identity = identitySnapshot(event, ctx);
        const sessionKey = sessionKeyFromHook(event, ctx);
        autoApproveActive = autoApproveStore.isActive({
          runId: identity.ok ? identity.runId : undefined,
          sessionKey,
        });
        // In A2A HITL-replace mode, leave tools alone unless this chat opted in.
        // Local / non-A2A installs keep classic always-on gating.
        if (a2aHitlReplace && !autoApproveActive) {
          return undefined;
        }
        if (boundedDecisionIdentity(identity)) {
          trackedIdentity = identity;
          try {
            const alreadyTripped = readDecisionStoreTrip(decisionStore, identity.runId);
            if (alreadyTripped) {
              result = repeatedDenials();
              decisionSource = 'circuit_breaker';
              breakerCandidate = true;
              if (config.enforcement !== 'shadow') skipJudge = true;
            }
          } catch {
            result = failure();
            decisionSource = 'failure';
            decisionStoreCheckFailed = true;
          }
        }

        let envelope;
        try {
          action = createAction({ event, ctx });
          const copiedParams = plainParams(action);
          if (copiedParams !== null) params = copiedParams;
          if (!skipJudge && policySettings !== undefined) {
            if (typeof assessRoute !== 'function') throw new TypeError('invalid route assessor');
            assessingRoute = true;
            const route = policyRouteSnapshot(assessRoute({
              action,
              pluginRoot: PLUGIN_ROOT,
              auditPath: policySettings.auditPath,
              redaction: redactForJudgeWithProvenance(action.params),
            }));
            if (route === null) throw new TypeError('invalid route assessment');
            assessingRoute = false;
            routeSnapshot = route;
            safePathCandidate = route.safe_path_candidate;
            safePathFamily = route.safe_path_family;
            hardBoundaryCandidate = route.route === 'hard_deny';
            if (hardBoundaryCandidate && config.enforcement !== 'shadow') {
              result = hardPolicyBlock();
              decisionSource = 'hard_boundary';
              skipJudge = true;
            }
          }
          if (!skipJudge && policySettings === undefined) {
            result = failure();
            decisionSource = 'failure';
            skipJudge = true;
          }
          if (!skipJudge && !settingsValid) {
            result = failure('judge_unavailable');
            decisionSource = 'failure';
            skipJudge = true;
          }
          if (!skipJudge) {
            localVisibleParams = immutableVisibleParams(action);
            const actionTool = readData(action, 'tool_name');
            if (!actionTool.ok || typeof actionTool.value !== 'string') {
              throw new TypeError('invalid local tool snapshot');
            }
            localToolName = actionTool.value;
            envelope = createJudgeEnvelope(action);
            const hash = readData(envelope, 'action_hash');
            expectedHash = hash.ok ? hash.value : undefined;
          }
        } catch {
          routeAssessmentFailed = assessingRoute;
          assessingRoute = false;
          envelope = undefined;
          skipJudge = true;
          if (routeAssessmentFailed && config.enforcement === 'shadow'
            || !breakerCandidate && !hardBoundaryCandidate) {
            result = failure();
            decisionSource = 'failure';
            safePathCandidate = false;
            safePathFamily = null;
          }
        }

        if (trackedIdentity !== undefined && !skipJudge
          && actionMatchesIdentity(action, identity)
          && envelope !== undefined && typeof expectedHash === 'string') {
          const userPrompt = getStoredPrompt(store, identity.runId, sessionKey);
          if (isTrustedUserRequest(userPrompt)) {
            const review = methodValue(client, 'review');
            if (review) {
              let reviewed;
              try {
                reviewed = await Promise.resolve().then(() => review.call(client, {
                  userPrompt,
                  envelope,
                  modelId: getStoredModelId(store, identity.runId, sessionKey)
                    || resolveHookModelId(event, ctx, agentDefaultModelId),
                }));
              } catch {
                result = failure('judge_unavailable');
              }
              let routeConsistent = false;
              try {
                const freshRoute = policyRouteSnapshot(assessRoute({
                  action,
                  pluginRoot: PLUGIN_ROOT,
                  auditPath: policySettings.auditPath,
                  redaction: redactForJudgeWithProvenance(action.params),
                }));
                routeConsistent = samePolicyRoute(routeSnapshot, freshRoute);
              } catch {
                routeConsistent = false;
              }
              if (!routeConsistent) {
                result = failure();
              } else if (reviewed === undefined) {
                result = failure('judge_unavailable');
              } else {
                const ok = readData(reviewed, 'ok');
                const latency = readData(reviewed, 'latencyMs');
                latencyMs = safeLatency(latency.ok ? latency.value : undefined);
                if (!ok.ok || ok.value !== true) {
                  result = failure(ok.ok && ok.value === false
                    ? clientFailureCode(reviewed)
                    : 'invalid_judge_response');
                } else {
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
                          result = applyLocalSafetyDowngrade(
                            applyOpaqueDowngrade(safeNormalized, localVisibleParams),
                            localToolName,
                            localVisibleParams,
                            action,
                          );
                        }
                      }
                    }
                  }
                }
              }
            } else {
              result = failure('judge_unavailable');
            }
          }
        }

        decisionSource = ordinaryDecisionSource(result, judgeResult);
        if (safePathCandidate) safePathDisagreement = result.kind !== 'allow';
        const shadowAssessmentFailure = routeAssessmentFailed
          && config.enforcement === 'shadow';
        if (hardBoundaryCandidate && (!breakerCandidate || shadowAssessmentFailure)) {
          result = hardPolicyBlock();
          decisionSource = 'hard_boundary';
        }
        if (breakerCandidate && !shadowAssessmentFailure) {
          result = repeatedDenials();
          decisionSource = 'circuit_breaker';
        }
        if (decisionStoreCheckFailed) {
          ({ result, decisionSource } = applyTechnicalFailureMonotonically(
            result,
            decisionSource,
          ));
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
              decisionSource = 'failure';
            } else {
              action = freshAction;
              params = freshParams;
            }
          } catch {
            result = failure();
            decisionSource = 'failure';
          }
        }

        if (trackedIdentity !== undefined && !decisionStoreCheckFailed
          && !shadowAssessmentFailure) {
          try {
            if (readDecisionStoreTrip(decisionStore, trackedIdentity.runId)) {
              result = repeatedDenials();
              decisionSource = 'circuit_breaker';
            }
          } catch {
            ({ result, decisionSource } = applyTechnicalFailureMonotonically(
              result,
              decisionSource,
            ));
            decisionStoreCheckFailed = true;
          }
        }
      } catch {
        if (routeAssessmentFailed && config.enforcement === 'shadow') {
          result = failure();
          decisionSource = 'failure';
        } else if (breakerCandidate) {
          result = repeatedDenials();
          decisionSource = 'circuit_breaker';
        } else if (hardBoundaryCandidate) {
          result = hardPolicyBlock();
          decisionSource = 'hard_boundary';
        } else {
          result = failure();
          decisionSource = 'failure';
        }
      }

      params = safeParamsAfterPrototypePollution(params);
      mappedDecision = mapSafely(mapper, config, result, params, decisionSource);
      result = mappedDecision.effectiveResult;
      decisionSource = mappedDecision.effectiveDecisionSource;

      if (trackedIdentity !== undefined) {
        try {
          const recordStatus = recordRunDecision(
            decisionStore,
            trackedIdentity.runId,
            decisionMetadata(trackedIdentity, result, judgeResult),
          );
          if (recordStatus.already_tripped
            && !(routeAssessmentFailed && config.enforcement === 'shadow')
            && decisionSource !== 'circuit_breaker') {
            result = repeatedDenials();
            decisionSource = 'circuit_breaker';
          }
        } catch {
          ({ result, decisionSource } = applyTechnicalFailureMonotonically(
            result,
            decisionSource,
          ));
        }
      }

      if (result !== mappedDecision.effectiveResult
        || decisionSource !== mappedDecision.effectiveDecisionSource) {
        mappedDecision = mapSafely(mapper, config, result, params, decisionSource);
        result = mappedDecision.effectiveResult;
        decisionSource = mappedDecision.effectiveDecisionSource;
      }

      if (safePathCandidate && decisionSource !== 'circuit_breaker') {
        safePathDisagreement = result.kind !== 'allow';
      }

      try {
        await writeAuditBestEffort(audit, {
          action,
          judgeResult,
          normalized: result,
          latencyMs,
          mode: config.mode,
          enforcement: config.enforcement,
          decisionSource,
          safePathCandidate,
          safePathFamily,
          safePathDisagreement,
        });
        const postAuditParams = safeParamsAfterPrototypePollution(params);
        if (postAuditParams !== params) {
          params = postAuditParams;
          mappedDecision = {
            value: safeFallbackMapping(config, result, params),
            effectiveResult: result,
            effectiveDecisionSource: decisionSource,
            fellBack: mappedDecision.fellBack,
          };
        }
        if (autoApproveActive) {
          const bridgeCallId = resolveCallIdForBridge(trackedIdentity, action, event, ctx);
          if (bridgeCallId) {
            autoApproveStore.putDecision(
              bridgeCallId,
              bridgeDecisionFromMapped(mappedDecision.value),
            );
          }
        }
        // For A2A autoapprove: never use native requireApproval (A2A ignores it).
        // Allow continues so the patched bridge can return allow-once; deny blocks.
        if (autoApproveActive && mappedDecision.value?.requireApproval) {
          const blocked = {
            block: true,
            blockReason: mappedDecision.value.requireApproval.description
              || createBlockFeedback(selectFeedbackCode(result)),
          };
          const bridgeCallId = resolveCallIdForBridge(trackedIdentity, action, event, ctx);
          if (bridgeCallId) {
            autoApproveStore.putDecision(bridgeCallId, 'deny');
          }
          return blocked;
        }
        return mappedDecision.value;
      } catch {
        if (autoApproveActive) {
          const bridgeCallId = resolveCallIdForBridge(trackedIdentity, action, event, ctx);
          if (bridgeCallId) {
            autoApproveStore.putDecision(bridgeCallId, 'deny');
          }
        }
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
        enforcementRegistrationFailed = true;
      }
    } else {
      setupFailed = true;
      enforcementRegistrationFailed = true;
    }

    if (setupFailed) {
      notifySetupFailure(lifecycleLogger);
    }
    if (enforcementRegistrationFailed) {
      throw new Error(SETUP_FAILED_MESSAGE);
    }
    if (!setupFailed) {
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
