import { types as utilTypes } from 'node:util';
import { posix as pathPosix } from 'node:path';
import {
  APPROVAL_TIMEOUT_MS,
  MIN_CONFIDENCE,
  PLUGIN_ID,
  POLICY_VERSION,
} from './constants.js';
import {
  JUDGE_DECISIONS,
  validateJudgeVerdict,
} from './judge-schema.js';
import { containsOpaqueData } from './redact.js';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const DECISION_SET = new Set(JUDGE_DECISIONS);
const INVALID_RESPONSE_REASON = 'invalid judge response';
const DENY_BLOCK_REASON = 'LLM action judge denied the tool call';
const REVIEW_BLOCK_REASON = 'LLM action judge review required';
const APPROVAL_DESCRIPTION = 'LLM action judge could not safely allow this tool call. Approve this call once to continue.';
const LOCAL_GUARD_REASON = 'local safety guard requires human review';
const INVALID_LOCAL_GUARD_REASON = 'invalid local safety gate input';
const READ_ONLY_CRON_ACTIONS = new Set(['list', 'status', 'get', 'runs']);
const READ_ONLY_MESSAGE_ACTIONS = new Set([
  'channel-info',
  'channel-list',
  'emoji-list',
  'event-list',
  'list-pins',
  'member-info',
  'reactions',
  'read',
  'role-info',
  'search',
  'thread-list',
  'voice-status',
]);
const FILE_WRITE_TOOLS = new Set(['write', 'edit', 'apply_patch']);
const ACTIVE_REGISTRY_CONFIGS = new Set([
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
]);
const SECURITY_PATH_SEGMENTS = new Set([
  'acl',
  'auth',
  'iam',
  'oauth',
  'rbac',
  'security',
]);
const SECURITY_POLICY_FILE = /^(?:acl|config|permissions|policy|rbac|roles?|rules|scopes|session|settings|token)(?:\.(?:spec|test))?(?:\.(?:c|cc|cpp|cs|go|java|js|jsx|json|kt|kts|php|py|rb|rs|sh|toml|ts|tsx|ya?ml))?$/u;
const DEVCONTAINER_LIFECYCLE_FILE = /^(?:initialize|oncreate|postattach|postcreate|poststart|updatecontent|waitfor)(?:[._-].*)?$/u;
const ACTIVE_GIT_HOOKS = new Set([
  'applypatch-msg',
  'commit-msg',
  'fsmonitor-watchman',
  'p4-changelist',
  'p4-post-changelist',
  'p4-prepare-changelist',
  'p4-pre-submit',
  'post-applypatch',
  'post-checkout',
  'post-commit',
  'post-index-change',
  'post-merge',
  'post-receive',
  'post-rewrite',
  'post-update',
  'pre-applypatch',
  'pre-auto-gc',
  'pre-commit',
  'pre-merge-commit',
  'pre-push',
  'pre-rebase',
  'pre-receive',
  'prepare-commit-msg',
  'proc-receive',
  'push-to-checkout',
  'reference-transaction',
  'sendemail-validate',
  'update',
]);
const PATCH_FILE_HEADER = /^\*\*\* (?:Add|Delete|Update) File: (.+)$/u;
const PATCH_MOVE_HEADER = /^\*\*\* Move to: (.+)$/u;
const LOCAL_ACTION_KEYS = new Set([
  'policy_version',
  'tool_name',
  'params',
  'agent_id',
  'session_key',
  'run_id',
  'tool_call_id',
]);
const INERT_TEMPLATE_NAME = /(?:^|[._-])(?:example|sample|template|tmpl)$/u;
const DOCUMENTATION_FILE = /\.(?:adoc|markdown|md|rst)$/u;
const ENV_FILE = /^\.env(?:\..+)?$/u;
const PRIVATE_KEY_FILE = /^(?:id_(?:dsa|ecdsa|ed25519|rsa)|.*(?:private[._-]?key|privkey).*)$/u;
const PUBLIC_KEY_FILE = /^(?:id_(?:dsa|ecdsa|ed25519|rsa)|.*(?:public[._-]?key|pubkey).*)\.pub$/u;
const CREDENTIAL_NAME = /(?:^|[._-])(?:api[._-]?key|credentials?|secrets?|tokens?)(?:[._-]|$)/u;
const SENSITIVE_READ_FILES = new Set([
  '.netrc',
  '.npmrc',
  '.pypirc',
  '.yarnrc',
  '.yarnrc.yml',
  'credentials',
  'credentials.json',
  'kubeconfig',
  'service-account.json',
  'service_account.json',
]);
const SENSITIVE_READ_DIRECTORIES = new Set([
  '.kube',
  '.ssh',
  'credentials',
  'secrets',
  'vault',
]);
const SECRET_CONFIG_COMPONENTS = new Set([
  'accesskey',
  'accesstoken',
  'apikey',
  'apikeys',
  'apitoken',
  'authorization',
  'authtoken',
  'bottoken',
  'clientsecret',
  'credential',
  'credentials',
  'idtoken',
  'password',
  'passwordhash',
  'passwd',
  'privatekey',
  'refreshtoken',
  'secret',
  'secretaccesskey',
  'secretkey',
  'secrets',
  'sessiontoken',
  'token',
]);
const SAFE_CONFIG_METADATA_COMPONENTS = new Set([
  'apikeypath',
  'baseurl',
  'count',
  'enabled',
  'endpoint',
  'maxtokens',
  'model',
  'models',
  'passwordfile',
  'secretpath',
  'thinkingdefault',
  'tokenbudget',
  'timeoutms',
]);
const SENSITIVE_CONFIG_CONTAINERS = new Set(['auth', 'credentials', 'secrets']);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalidResponse() {
  return { ok: false, reason: INVALID_RESPONSE_REASON };
}

function skipWhitespace(source, index) {
  let next = index;
  while (next < source.length && /[\u0009\u000a\u000d\u0020]/u.test(source[next])) {
    next += 1;
  }
  return next;
}

function scanString(source, index) {
  let next = index + 1;
  while (next < source.length) {
    if (source[next] === '\\') {
      next += 2;
      continue;
    }
    if (source[next] === '"') return next + 1;
    next += 1;
  }
  return -1;
}

function scanTopLevelValue(source, index) {
  let next = index;
  let depth = 0;
  while (next < source.length) {
    const character = source[next];
    if (character === '"') {
      next = scanString(source, next);
      if (next < 0) return -1;
      continue;
    }
    if (character === '{' || character === '[') {
      depth += 1;
    } else if (character === '}' || character === ']') {
      if (character === '}' && depth === 0) return next;
      depth -= 1;
    } else if (character === ',' && depth === 0) {
      return next;
    }
    next += 1;
  }
  return -1;
}

function hasDuplicateTopLevelKeys(source) {
  const seen = new Set();
  let index = skipWhitespace(source, 1);
  if (source[index] === '}') return false;

  while (index < source.length) {
    if (source[index] !== '"') return true;
    const end = scanString(source, index);
    if (end < 0) return true;
    const key = JSON.parse(source.slice(index, end));
    if (seen.has(key)) return true;
    seen.add(key);

    index = skipWhitespace(source, end);
    if (source[index] !== ':') return true;
    index = skipWhitespace(source, index + 1);
    index = scanTopLevelValue(source, index);
    if (index < 0) return true;
    if (source[index] === '}') return false;
    index = skipWhitespace(source, index + 1);
  }
  return true;
}

export function parseJudgeResponse(text, options = {}) {
  try {
    const expectedHash = options?.expectedHash;
    if (typeof text !== 'string' || typeof expectedHash !== 'string') {
      return invalidResponse();
    }
    if (!HASH_PATTERN.test(expectedHash)) return invalidResponse();

    const source = text.trim();
    if (!source.startsWith('{') || !source.endsWith('}')) return invalidResponse();
    if (hasDuplicateTopLevelKeys(source)) return invalidResponse();

    const parsed = JSON.parse(source);
    if (!isPlainObject(parsed)) return invalidResponse();
    validateJudgeVerdict(parsed);
    if (parsed.action_hash !== expectedHash) return invalidResponse();
    if (!parsed.rationale.trim()
      || parsed.rationale.length > 500
      || CONTROL_PATTERN.test(parsed.rationale)) return invalidResponse();

    return { ok: true, verdict: parsed };
  } catch {
    return invalidResponse();
  }
}

export function normalizeVerdict(parsed) {
  if (!isPlainObject(parsed) || !DECISION_SET.has(parsed.decision)) {
    return { kind: 'failure', reason: INVALID_RESPONSE_REASON };
  }

  if (parsed.decision === 'deny' || parsed.decision === 'review') {
    return { kind: parsed.decision, reason: parsed.rationale, verdict: parsed };
  }

  if (parsed.risk === 'low'
    && parsed.authorization === 'high'
    && parsed.confidence >= MIN_CONFIDENCE) {
    return { kind: 'allow', reason: parsed.rationale, verdict: parsed };
  }

  return {
    kind: 'review',
    reason: 'judge allow did not satisfy local safety gate',
    verdict: parsed,
  };
}

export function applyOpaqueDowngrade(result, visibleParams) {
  if (result === null || typeof result !== 'object') {
    return { kind: 'failure', reason: 'invalid judge response' };
  }
  if (result.kind !== 'allow') return result;
  if (!containsOpaqueData(visibleParams)) return result;
  return {
    kind: 'review',
    reason: 'opaque action cannot be auto-approved',
    verdict: result.verdict,
    opaque: true,
  };
}

function ownDataValue(value, key) {
  if (value === null || typeof value !== 'object' || utilTypes.isProxy(value)) {
    return { ok: false };
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return { ok: false };
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) return { ok: false };
  return { ok: true, value: descriptor.value };
}

function isDataOnly(value, ancestors = new Set(), budget = { remaining: 10_000 }) {
  if (value === null) return true;
  if (['string', 'number', 'boolean'].includes(typeof value)) return true;
  if (typeof value !== 'object' || utilTypes.isProxy(value)) return false;
  if (budget.remaining <= 0 || ancestors.has(value)) return false;

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype
    && prototype !== null
    && prototype !== Array.prototype) return false;

  budget.remaining -= 1;
  ancestors.add(value);
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return false;
    if (!isDataOnly(descriptor.value, ancestors, budget)) return false;
  }
  ancestors.delete(value);
  return true;
}

function localReview(result) {
  const verdict = ownDataValue(result, 'verdict');
  if (!verdict.ok || !isDataOnly(verdict.value)) {
    return { kind: 'failure', reason: INVALID_LOCAL_GUARD_REASON };
  }
  return {
    kind: 'review',
    reason: LOCAL_GUARD_REASON,
    verdict: verdict.value,
    local_guard: true,
  };
}

function localActionSnapshot(value, expectedToolName) {
  try {
    if (!isDataOnly(value)) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== LOCAL_ACTION_KEYS.size
      || keys.some((key) => typeof key !== 'string' || !LOCAL_ACTION_KEYS.has(key))) {
      return null;
    }
    for (const key of LOCAL_ACTION_KEYS) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return null;
      }
    }
    if (descriptors.policy_version.value !== POLICY_VERSION
      || descriptors.tool_name.value !== expectedToolName
      || !isPlainObject(descriptors.params.value)) return null;
    return Object.freeze({
      params: descriptors.params.value,
      sessionKey: descriptors.session_key.value,
    });
  } catch {
    return null;
  }
}

function pathHasRawTraversal(path) {
  return /(?:^|[\\/])(?:[a-zA-Z]:)?\.\.(?=[\\/]|$)/u.test(path);
}

function targetsCredentialMaterial(path) {
  if (pathHasRawTraversal(path)) return true;
  const segments = path
    .replaceAll('\\', '/')
    .split('/')
    .filter((segment) => segment !== '')
    .map((segment) => segment.toLowerCase());
  if (segments.length === 0) return true;
  const name = segments.at(-1);

  if (INERT_TEMPLATE_NAME.test(name) || PUBLIC_KEY_FILE.test(name)) return false;
  if (ENV_FILE.test(name)
    || SENSITIVE_READ_FILES.has(name)
    || PRIVATE_KEY_FILE.test(name)) return true;
  if (segments.at(-2) === '.kube' && name === 'config') return true;
  if (DOCUMENTATION_FILE.test(name)) return false;
  if (CREDENTIAL_NAME.test(name)) return true;
  return segments.slice(0, -1).some((segment) => SENSITIVE_READ_DIRECTORIES.has(segment));
}

function gatewayPathIsSensitive(path) {
  const components = path
    .split(/[./:\[\]\\]+/u)
    .filter((component) => component !== '')
    .map((component) => component.toLowerCase().replace(/[^a-z0-9]+/gu, ''));
  if (components.length === 0 || components.some((component) => component === '')) return true;
  const last = components.at(-1);
  if (components.some((component) => SECRET_CONFIG_COMPONENTS.has(component))) return true;
  if (SAFE_CONFIG_METADATA_COMPONENTS.has(last)) return false;
  if (components.some((component) => SENSITIVE_CONFIG_CONTAINERS.has(component))) return true;
  const providersIndex = components.findIndex((component, index) => (
    component === 'models' && components[index + 1] === 'providers'
  ));
  return providersIndex >= 0;
}

function targetsActiveAutomation(path) {
  if (typeof path !== 'string' || !path) return null;
  const normalized = pathPosix.normalize(
    path.replaceAll('\\', '/').replace(/\/{2,}/gu, '/'),
  );
  const lower = normalized.toLowerCase();
  const name = lower.slice(lower.lastIndexOf('/') + 1);
  if (ACTIVE_REGISTRY_CONFIGS.has(name)) return true;
  if (/(?:^|\/)\.github\/workflows\//u.test(lower)) return /\.ya?ml$/u.test(name);
  if (/(?:^|\/)\.git\/hooks\//u.test(lower)) return ACTIVE_GIT_HOOKS.has(name);
  const devcontainer = /(?:^|\/)\.devcontainer\/(?:[^/]+\/)*([^/]+)$/u.exec(lower);
  if (devcontainer) {
    if (devcontainer[1] === 'devcontainer.json') return true;
    if (!/\.(?:example|sample)$/u.test(devcontainer[1])
      && DEVCONTAINER_LIFECYCLE_FILE.test(devcontainer[1])) return true;
  }
  const segments = lower.split('/');
  if (segments.slice(0, -1).some((segment) => SECURITY_PATH_SEGMENTS.has(segment))
    && SECURITY_POLICY_FILE.test(name)) return true;
  return false;
}

function fileTargets(params, toolName) {
  if (toolName === 'write' || toolName === 'edit') {
    const path = ownDataValue(params, 'path');
    return path.ok && typeof path.value === 'string' ? [path.value] : null;
  }

  const input = ownDataValue(params, 'input');
  if (!input.ok || typeof input.value !== 'string') return null;
  const targets = [];
  for (const line of input.value.split(/\r?\n/u)) {
    const match = PATCH_FILE_HEADER.exec(line) ?? PATCH_MOVE_HEADER.exec(line);
    if (match) targets.push(match[1]);
  }
  return targets.length > 0 ? targets : null;
}

export function applyLocalSafetyDowngrade(result, toolName, visibleParams, localAction) {
  const kind = ownDataValue(result, 'kind');
  if (!kind.ok || typeof kind.value !== 'string') {
    return { kind: 'failure', reason: INVALID_LOCAL_GUARD_REASON };
  }
  if (kind.value !== 'allow') return result;
  if (typeof toolName !== 'string' || !toolName || !isDataOnly(visibleParams)) {
    return localReview(result);
  }
  const action = localActionSnapshot(localAction, toolName);
  if (action === null) return localReview(result);

  if (toolName === 'read') {
    const path = ownDataValue(action.params, 'path');
    if (!path.ok || typeof path.value !== 'string' || path.value.trim() === ''
      || targetsCredentialMaterial(path.value)) return localReview(result);
    return result;
  }

  if (toolName === 'gateway') {
    const actionName = ownDataValue(action.params, 'action');
    const path = ownDataValue(action.params, 'path');
    if (!actionName.ok || actionName.value !== 'config.get'
      || !path.ok || typeof path.value !== 'string' || path.value.trim() === ''
      || gatewayPathIsSensitive(path.value)) return localReview(result);
    return result;
  }

  if (toolName === 'sessions_history') {
    const requestedSession = ownDataValue(action.params, 'sessionKey');
    if (!requestedSession.ok
      || typeof requestedSession.value !== 'string'
      || requestedSession.value.trim() === ''
      || typeof action.sessionKey !== 'string'
      || action.sessionKey.trim() === ''
      || requestedSession.value !== action.sessionKey) return localReview(result);
    return result;
  }

  if (toolName === 'message') {
    const action = ownDataValue(visibleParams, 'action');
    if (!action.ok || typeof action.value !== 'string') return localReview(result);
    if (action.value === 'send') {
      const dryRun = ownDataValue(visibleParams, 'dryRun');
      return dryRun.ok && dryRun.value === true ? result : localReview(result);
    }
    return READ_ONLY_MESSAGE_ACTIONS.has(action.value) ? result : localReview(result);
  }

  if (ownDataValue(visibleParams, 'dryRun').ok) return localReview(result);

  if (toolName === 'cron') {
    const action = ownDataValue(visibleParams, 'action');
    if (!action.ok
      || typeof action.value !== 'string'
      || !READ_ONLY_CRON_ACTIONS.has(action.value)) return localReview(result);
    return result;
  }

  if (toolName === 'browser') {
    const action = ownDataValue(visibleParams, 'action');
    if (!action.ok || typeof action.value !== 'string' || action.value === 'upload') {
      return localReview(result);
    }
    return result;
  }

  if (!FILE_WRITE_TOOLS.has(toolName)) return result;
  const targets = fileTargets(visibleParams, toolName);
  if (targets === null || targets.some((path) => targetsActiveAutomation(path) !== false)) {
    return localReview(result);
  }
  return result;
}

function approvalSeverity(result) {
  if (result?.opaque === true
    || result?.local_guard === true
    || result?.kind === 'failure'
    || result?.verdict?.risk === 'high'
    || result?.verdict?.risk === 'critical') return 'critical';
  return 'warning';
}

export function mapVerdict({ mode, enforcement, result, params } = {}) {
  if (enforcement === 'shadow') return undefined;

  if (enforcement === 'enforce'
    && (mode === 'autonomous' || mode === 'supervised')
    && result?.kind === 'allow') return { params };

  if (result?.kind === 'deny') {
    return {
      block: true,
      blockReason: DENY_BLOCK_REASON,
    };
  }

  if (enforcement === 'enforce' && mode === 'supervised') {
    return {
      params,
      requireApproval: {
        title: REVIEW_BLOCK_REASON,
        description: APPROVAL_DESCRIPTION,
        severity: approvalSeverity(result),
        timeoutMs: APPROVAL_TIMEOUT_MS,
        timeoutBehavior: 'deny',
        pluginId: PLUGIN_ID,
      },
    };
  }

  return { block: true, blockReason: REVIEW_BLOCK_REASON };
}
