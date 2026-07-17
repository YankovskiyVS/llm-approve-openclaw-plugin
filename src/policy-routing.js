import { constants as fsConstants, lstatSync, realpathSync } from 'node:fs';
import {
  isAbsolute,
  join,
  normalize,
  parse as parsePath,
  relative,
  resolve,
  sep,
} from 'node:path';
import { types as utilTypes } from 'node:util';
import { canonicalStringify } from './action.js';
import { POLICY_VERSION } from './constants.js';
import {
  arrayPrototypeIsPristine,
  objectPrototypeIsPristine,
} from './intrinsics.js';
import { redactForJudgeWithProvenance } from './redact.js';

const OBJECT_PROTOTYPE = Object.prototype;
const ARRAY_PROTOTYPE = Array.prototype;
const STRING_PROTOTYPE = String.prototype;
const SET_PROTOTYPE = Set.prototype;
const REGEXP_PROTOTYPE = RegExp.prototype;
const URL_PROTOTYPE = URL.prototype;
const SET_CONSTRUCTOR = Set;
const OBJECT_CREATE = Object.create;
const OBJECT_FREEZE = Object.freeze;
const OBJECT_GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const OBJECT_GET_OWN_PROPERTY_DESCRIPTORS = Object.getOwnPropertyDescriptors;
const OBJECT_GET_PROTOTYPE_OF = Object.getPrototypeOf;
const OBJECT_HAS_OWN = Object.hasOwn;
const REFLECT_APPLY = Reflect.apply;
const REFLECT_OWN_KEYS = Reflect.ownKeys;
const ARRAY_IS_ARRAY = Array.isArray;
const NUMBER_IS_FINITE = Number.isFinite;
const NUMBER_IS_INTEGER = Number.isInteger;
const JSON_PARSE = JSON.parse;
const JSON_STRINGIFY = JSON.stringify;
const SET_ADD = Set.prototype.add;
const SET_DELETE = Set.prototype.delete;
const SET_HAS = Set.prototype.has;
const STRING_ENDS_WITH = String.prototype.endsWith;
const STRING_INCLUDES = String.prototype.includes;
const STRING_INDEX_OF = String.prototype.indexOf;
const STRING_SLICE = String.prototype.slice;
const STRING_SPLIT = String.prototype.split;
const STRING_STARTS_WITH = String.prototype.startsWith;
const STRING_TRIM = String.prototype.trim;
const REGEXP_EXEC = RegExp.prototype.exec;
const REGEXP_TEST = RegExp.prototype.test;
const IS_PROXY = utilTypes.isProxy;
const URL_CONSTRUCTOR = URL;
const URL_PROTOCOL_DESCRIPTOR = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(URL_PROTOTYPE, 'protocol');
const URL_HOSTNAME_DESCRIPTOR = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(URL_PROTOTYPE, 'hostname');
const URL_PROTOCOL_GET = URL_PROTOCOL_DESCRIPTOR?.get;
const URL_HOSTNAME_GET = URL_HOSTNAME_DESCRIPTOR?.get;

const INPUT_KEYS = OBJECT_FREEZE(['action', 'pluginRoot', 'auditPath', 'redaction']);
const ACTION_KEYS = OBJECT_FREEZE([
  'policy_version',
  'tool_name',
  'params',
  'agent_id',
  'session_key',
  'run_id',
  'tool_call_id',
]);
const REDACTION_KEYS = OBJECT_FREEZE(['value', 'secret_redacted', 'truncated', 'opaque']);
const FILE_MUTATION_TOOLS = new Set(['write', 'edit', 'apply_patch']);
const SHIPPED_RUNTIME_FILES = new Set([
  'index.js',
  'openclaw.plugin.json',
  'package.json',
  join('schemas', 'judge-verdict.schema.json'),
  join('src', 'action.js'),
  join('src', 'audit.js'),
  join('src', 'config.js'),
  join('src', 'constants.js'),
  join('src', 'context-store.js'),
  join('src', 'decision.js'),
  join('src', 'environment.js'),
  join('src', 'feedback.js'),
  join('src', 'intrinsics.js'),
  join('src', 'judge-client.js'),
  join('src', 'judge-schema.js'),
  join('src', 'plugin.js'),
  join('src', 'policy-routing.js'),
  join('src', 'prompt.js'),
  join('src', 'redact.js'),
  join('src', 'run-decision-store.js'),
]);
const GATEWAY_MUTATION_KEYS = new Set([
  'action',
  'raw',
  'delayMs',
  'reason',
  'continuationMessage',
  'baseHash',
  'replacePaths',
  'sessionKey',
  'note',
  'restartDelayMs',
  'gatewayUrl',
  'gatewayToken',
  'timeoutMs',
]);
const MESSAGE_SEND_KEYS = new Set([
  'action',
  'channel',
  'target',
  'targets',
  'accountId',
  'dryRun',
  'message',
  'effectId',
  'effect',
  'media',
  'filename',
  'buffer',
  'contentType',
  'mimeType',
  'caption',
  'attachments',
  'replyTo',
  'threadId',
  'asVoice',
  'silent',
  'quoteText',
  'gifPlayback',
  'forceDocument',
  'asDocument',
  'presentation',
  'bestEffort',
  'delivery',
]);
const MESSAGE_STRING_FIELDS = new Set([
  'channel',
  'target',
  'accountId',
  'message',
  'effectId',
  'effect',
  'media',
  'filename',
  'buffer',
  'contentType',
  'mimeType',
  'caption',
  'replyTo',
  'threadId',
  'quoteText',
]);
const MESSAGE_BOOLEAN_FIELDS = new Set([
  'asVoice',
  'silent',
  'gifPlayback',
  'forceDocument',
  'asDocument',
  'bestEffort',
]);
const MESSAGE_ATTACHMENT_TYPES = new Set(['image', 'audio', 'video', 'file']);
const MESSAGE_ATTACHMENT_KEYS = new Set(['type', 'media', 'name', 'mimeType']);
const PRESENTATION_TONES = new Set(['info', 'success', 'warning', 'danger', 'neutral']);
const PRESENTATION_BLOCK_TYPES = new Set(['text', 'context', 'divider', 'buttons', 'select']);
const PRESENTATION_BUTTON_STYLES = new Set(['primary', 'secondary', 'success', 'danger']);
const PRESENTATION_KEYS = new Set(['title', 'tone', 'blocks']);
const PRESENTATION_BLOCK_KEYS = new Set(['type', 'text', 'buttons', 'placeholder', 'options']);
const PRESENTATION_BUTTON_KEYS = new Set([
  'label', 'action', 'value', 'url', 'webApp', 'web_app', 'disabled', 'reusable', 'style',
]);
const PRESENTATION_OPTION_KEYS = new Set(['label', 'action', 'value']);
const PRESENTATION_ACTION_KEYS = new Set(['type', 'command', 'value']);
const DELIVERY_KEYS = new Set(['pin']);
const DELIVERY_PIN_KEYS = new Set(['enabled', 'notify', 'required']);
const WEB_FETCH_KEYS = new Set(['url', 'extractMode', 'maxChars']);
const WEB_FETCH_MODES = new Set(['markdown', 'text']);
const BROWSER_TARGETS = new Set(['sandbox', 'host', 'node']);
const BROWSER_NAVIGATE_KEYS = new Set([
  'action', 'target', 'node', 'profile', 'targetUrl', 'url', 'targetId', 'timeoutMs',
]);
const BROWSER_OPEN_KEYS = new Set([
  'action', 'target', 'node', 'profile', 'targetUrl', 'url', 'label', 'timeoutMs',
]);
const BROWSER_TYPE_OUTER_NESTED_KEYS = new Set([
  'action', 'target', 'node', 'profile', 'targetId', 'timeoutMs', 'request',
]);
const BROWSER_TYPE_OUTER_FLAT_KEYS = new Set([
  'action', 'target', 'node', 'profile', 'kind', 'targetId', 'ref', 'selector', 'text',
  'submit', 'slowly', 'delayMs', 'timeoutMs',
]);
const BROWSER_TYPE_REQUEST_KEYS = new Set([
  'kind', 'targetId', 'ref', 'selector', 'text', 'submit', 'slowly', 'delayMs', 'timeoutMs',
]);
const PATCH_TARGET_PATTERN = /^\*\*\* (?:Add|Delete|Update) File: (.+)$/u;
const PATCH_MOVE_PATTERN = /^\*\*\* Move to: (.+)$/u;
const PATCH_TARGET_PREFIX = /^\*\*\* (?:Add|Delete|Update) File:/u;
const PATCH_MOVE_PREFIX = /^\*\*\* Move to:/u;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const BROWSER_MAX_WAIT_MS = 30_000;

function callString(method, value, ...args) {
  return REFLECT_APPLY(method, value, args);
}

function callRegExp(method, pattern, value) {
  return REFLECT_APPLY(method, pattern, [value]);
}

function sameDataProperty(owner, key, expected) {
  try {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(owner, key);
    return descriptor !== undefined
      && OBJECT_HAS_OWN(descriptor, 'value')
      && descriptor.value === expected;
  } catch {
    return false;
  }
}

function sameAccessorProperty(owner, key, expected) {
  try {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(owner, key);
    return descriptor !== undefined
      && !OBJECT_HAS_OWN(descriptor, 'value')
      && descriptor.get === expected.get
      && descriptor.set === expected.set
      && descriptor.enumerable === expected.enumerable
      && descriptor.configurable === expected.configurable;
  } catch {
    return false;
  }
}

function routingRuntimeIsPristine() {
  try {
    return objectPrototypeIsPristine()
      && arrayPrototypeIsPristine()
      && sameDataProperty(SET_PROTOTYPE, 'add', SET_ADD)
      && sameDataProperty(SET_PROTOTYPE, 'delete', SET_DELETE)
      && sameDataProperty(SET_PROTOTYPE, 'has', SET_HAS)
      && sameDataProperty(STRING_PROTOTYPE, 'endsWith', STRING_ENDS_WITH)
      && sameDataProperty(STRING_PROTOTYPE, 'includes', STRING_INCLUDES)
      && sameDataProperty(STRING_PROTOTYPE, 'indexOf', STRING_INDEX_OF)
      && sameDataProperty(STRING_PROTOTYPE, 'slice', STRING_SLICE)
      && sameDataProperty(STRING_PROTOTYPE, 'split', STRING_SPLIT)
      && sameDataProperty(STRING_PROTOTYPE, 'startsWith', STRING_STARTS_WITH)
      && sameDataProperty(STRING_PROTOTYPE, 'trim', STRING_TRIM)
      && sameDataProperty(REGEXP_PROTOTYPE, 'exec', REGEXP_EXEC)
      && sameDataProperty(REGEXP_PROTOTYPE, 'test', REGEXP_TEST)
      && URL_PROTOCOL_DESCRIPTOR !== undefined
      && URL_HOSTNAME_DESCRIPTOR !== undefined
      && typeof URL_PROTOCOL_GET === 'function'
      && typeof URL_HOSTNAME_GET === 'function'
      && sameAccessorProperty(URL_PROTOTYPE, 'protocol', URL_PROTOCOL_DESCRIPTOR)
      && sameAccessorProperty(URL_PROTOTYPE, 'hostname', URL_HOSTNAME_DESCRIPTOR)
      && Object.create === OBJECT_CREATE
      && Object.freeze === OBJECT_FREEZE
      && Object.getOwnPropertyDescriptor === OBJECT_GET_OWN_PROPERTY_DESCRIPTOR
      && Object.getOwnPropertyDescriptors === OBJECT_GET_OWN_PROPERTY_DESCRIPTORS
      && Object.getPrototypeOf === OBJECT_GET_PROTOTYPE_OF
      && Object.hasOwn === OBJECT_HAS_OWN
      && Reflect.apply === REFLECT_APPLY
      && Reflect.ownKeys === REFLECT_OWN_KEYS
      && Array.isArray === ARRAY_IS_ARRAY
      && Number.isFinite === NUMBER_IS_FINITE
      && Number.isInteger === NUMBER_IS_INTEGER
      && JSON.parse === JSON_PARSE
      && JSON.stringify === JSON_STRINGIFY
      && utilTypes.isProxy === IS_PROXY
      && globalThis.Set === SET_CONSTRUCTOR
      && globalThis.URL === URL_CONSTRUCTOR;
  } catch {
    return false;
  }
}

function invalidInput() {
  throw new TypeError('invalid policy route input');
}

function containsExact(values, expected) {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === expected) return true;
  }
  return false;
}

function exactDataRecord(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || ARRAY_IS_ARRAY(value)
      || IS_PROXY(value)) invalidInput();
    const prototype = OBJECT_GET_PROTOTYPE_OF(value);
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) invalidInput();
    const descriptors = OBJECT_GET_OWN_PROPERTY_DESCRIPTORS(value);
    const ownKeys = REFLECT_OWN_KEYS(descriptors);
    if (ownKeys.length !== keys.length) invalidInput();
    const result = OBJECT_CREATE(null);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !OBJECT_HAS_OWN(descriptor, 'value')) {
        invalidInput();
      }
      result[key] = descriptor.value;
    }
    for (let index = 0; index < ownKeys.length; index += 1) {
      const key = ownKeys[index];
      if (typeof key !== 'string' || !containsExact(keys, key)) invalidInput();
    }
    return result;
  } catch {
    return invalidInput();
  }
}

function exactOwnKeys(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || ARRAY_IS_ARRAY(value)
      || IS_PROXY(value)) return false;
    const prototype = OBJECT_GET_PROTOTYPE_OF(value);
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return false;
    const descriptors = OBJECT_GET_OWN_PROPERTY_DESCRIPTORS(value);
    const ownKeys = REFLECT_OWN_KEYS(descriptors);
    if (ownKeys.length !== keys.length) return false;
    for (let index = 0; index < keys.length; index += 1) {
      const descriptor = descriptors[keys[index]];
      if (!descriptor || !descriptor.enumerable || !OBJECT_HAS_OWN(descriptor, 'value')) {
        return false;
      }
    }
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (typeof ownKeys[index] !== 'string' || !containsExact(keys, ownKeys[index])) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function allowedOwnKeys(value, allowed, required) {
  try {
    if (value === null || typeof value !== 'object' || ARRAY_IS_ARRAY(value)
      || IS_PROXY(value)) return false;
    const prototype = OBJECT_GET_PROTOTYPE_OF(value);
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return false;
    const descriptors = OBJECT_GET_OWN_PROPERTY_DESCRIPTORS(value);
    const ownKeys = REFLECT_OWN_KEYS(descriptors);
    for (let index = 0; index < ownKeys.length; index += 1) {
      const key = ownKeys[index];
      const descriptor = descriptors[key];
      if (typeof key !== 'string'
        || !REFLECT_APPLY(SET_HAS, allowed, [key])
        || !descriptor.enumerable
        || !OBJECT_HAS_OWN(descriptor, 'value')) return false;
    }
    for (let index = 0; index < required.length; index += 1) {
      if (!OBJECT_HAS_OWN(descriptors, required[index])) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function ownData(value, key) {
  try {
    if (value === null || typeof value !== 'object' || IS_PROXY(value)) return { ok: false };
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
    if (!descriptor || !OBJECT_HAS_OWN(descriptor, 'value')) return { ok: false };
    return { ok: true, value: descriptor.value };
  } catch {
    return { ok: false };
  }
}

function validateDeepData(value, ancestors) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return NUMBER_IS_FINITE(value);
  if (typeof value !== 'object' || IS_PROXY(value) || REFLECT_APPLY(SET_HAS, ancestors, [value])) {
    return false;
  }
  REFLECT_APPLY(SET_ADD, ancestors, [value]);
  try {
    if (ARRAY_IS_ARRAY(value)) {
      const prototype = OBJECT_GET_PROTOTYPE_OF(value);
      if (prototype !== ARRAY_PROTOTYPE && prototype !== null) return false;
      const descriptors = OBJECT_GET_OWN_PROPERTY_DESCRIPTORS(value);
      const keys = REFLECT_OWN_KEYS(descriptors);
      if (keys.length !== value.length + 1 || !OBJECT_HAS_OWN(descriptors, 'length')) return false;
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !descriptor.enumerable || !OBJECT_HAS_OWN(descriptor, 'value')
          || !validateDeepData(descriptor.value, ancestors)) return false;
      }
      return true;
    }
    const prototype = OBJECT_GET_PROTOTYPE_OF(value);
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) return false;
    const descriptors = OBJECT_GET_OWN_PROPERTY_DESCRIPTORS(value);
    const keys = REFLECT_OWN_KEYS(descriptors);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = descriptors[key];
      if (typeof key !== 'string' || !descriptor.enumerable
        || !OBJECT_HAS_OWN(descriptor, 'value')
        || !validateDeepData(descriptor.value, ancestors)) return false;
    }
    return true;
  } finally {
    REFLECT_APPLY(SET_DELETE, ancestors, [value]);
  }
}

function canonicalAbsolute(value, allowRoot = true) {
  if (typeof value !== 'string' || value === '' || callRegExp(REGEXP_TEST, CONTROL_PATTERN, value)
    || !isAbsolute(value) || normalize(value) !== value || resolve(value) !== value) return false;
  const parts = callString(STRING_SPLIT, value, sep);
  for (let index = 0; index < parts.length; index += 1) {
    if (parts[index] === '..' || parts[index] === '.') return false;
  }
  return allowRoot || parsePath(value).root !== value;
}

function snapshotInput(input) {
  if (!routingRuntimeIsPristine()) invalidInput();
  const values = exactDataRecord(input, INPUT_KEYS);
  const action = exactDataRecord(values.action, ACTION_KEYS);
  const redaction = exactDataRecord(values.redaction, REDACTION_KEYS);
  if (action.policy_version !== POLICY_VERSION
    || typeof action.tool_name !== 'string'
    || callString(STRING_TRIM, action.tool_name) === ''
    || callRegExp(REGEXP_TEST, CONTROL_PATTERN, action.tool_name)
    || !canonicalAbsolute(values.pluginRoot, false)
    || !canonicalAbsolute(values.auditPath)
    || typeof redaction.secret_redacted !== 'boolean'
    || typeof redaction.truncated !== 'boolean'
    || typeof redaction.opaque !== 'boolean'
    || !validateDeepData(action.params, new Set())
    || !validateDeepData(redaction.value, new Set())) invalidInput();

  let canonicalParams;
  let canonicalRedaction;
  let recomputed;
  let paramsSnapshot;
  try {
    canonicalParams = canonicalStringify(action.params);
    canonicalRedaction = canonicalStringify(redaction.value);
    recomputed = redactForJudgeWithProvenance(action.params);
    paramsSnapshot = JSON_PARSE(canonicalParams);
  } catch {
    invalidInput();
  }
  if (typeof canonicalParams !== 'string'
    || canonicalRedaction !== canonicalStringify(recomputed.value)
    || redaction.secret_redacted !== recomputed.secret_redacted
    || redaction.truncated !== recomputed.truncated
    || redaction.opaque !== recomputed.opaque) invalidInput();

  action.params = paramsSnapshot;
  return OBJECT_FREEZE({
    action: OBJECT_FREEZE(action),
    pluginRoot: values.pluginRoot,
    auditPath: values.auditPath,
    redaction: OBJECT_FREEZE(redaction),
  });
}

function result(route, hardBoundary, safeCandidate, safeFamily) {
  return OBJECT_FREEZE({
    route,
    hard_boundary: hardBoundary,
    safe_path_candidate: safeCandidate,
    safe_path_family: safeFamily,
  });
}

function judgeRoute() {
  return result('judge', null, false, null);
}

function hardRoute(boundary) {
  return result('hard_deny', boundary, false, null);
}

function validEditList(value) {
  if (!ARRAY_IS_ARRAY(value) || value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    const edit = value[index];
    if (!exactOwnKeys(edit, ['oldText', 'newText'])) return false;
    const oldText = ownData(edit, 'oldText').value;
    const newText = ownData(edit, 'newText').value;
    if (typeof oldText !== 'string' || oldText === '' || typeof newText !== 'string') return false;
  }
  return true;
}

function patchMutationTargets(params) {
  if (!exactOwnKeys(params, ['input'])) return null;
  const input = ownData(params, 'input').value;
  if (typeof input !== 'string') return null;
  const trimmed = callString(STRING_TRIM, input);
  if (trimmed === '') return null;
  let lines = callString(STRING_SPLIT, trimmed, /\r?\n/u);
  const strictBoundaries = (candidate) => candidate.length >= 2
    && callString(STRING_TRIM, candidate[0]) === '*** Begin Patch'
    && callString(STRING_TRIM, candidate[candidate.length - 1]) === '*** End Patch';
  if (!strictBoundaries(lines)) {
    const first = lines[0];
    const last = lines[lines.length - 1];
    if (lines.length < 4
      || (first !== '<<EOF' && first !== "<<'EOF'" && first !== '<<"EOF"')
      || typeof last !== 'string'
      || !callString(STRING_ENDS_WITH, last, 'EOF')) return null;
    lines = lines.slice(1, -1);
    if (!strictBoundaries(lines)) return null;
  }

  const targets = [];
  const end = lines.length - 1;
  let index = 1;
  const addTarget = (target) => {
    if (!canonicalAbsolute(target)) return false;
    targets[targets.length] = target;
    return true;
  };
  const parseUpdateChunk = (start, allowMissingContext) => {
    if (start >= end) return 0;
    let cursor = start;
    const first = lines[cursor];
    if (first === '@@' || callString(STRING_STARTS_WITH, first, '@@ ')) cursor += 1;
    else if (!allowMissingContext) return 0;
    if (cursor >= end) return 0;
    let parsedLines = 0;
    for (; cursor < end; cursor += 1) {
      const line = lines[cursor];
      if (line === '*** End of File') {
        if (parsedLines === 0) return 0;
        parsedLines += 1;
        cursor += 1;
        break;
      }
      const marker = line[0];
      if (line === '' || marker === ' ' || marker === '+' || marker === '-') {
        parsedLines += 1;
        continue;
      }
      if (parsedLines === 0) return 0;
      break;
    }
    return cursor - start;
  };

  while (index < end) {
    const header = callString(STRING_TRIM, lines[index]);
    if (callString(STRING_STARTS_WITH, header, '*** Add File: ')) {
      if (!addTarget(callString(STRING_SLICE, header, 14))) return null;
      index += 1;
      while (index < end && callString(STRING_STARTS_WITH, lines[index], '+')) index += 1;
      continue;
    }
    if (callString(STRING_STARTS_WITH, header, '*** Delete File: ')) {
      if (!addTarget(callString(STRING_SLICE, header, 17))) return null;
      index += 1;
      continue;
    }
    if (!callString(STRING_STARTS_WITH, header, '*** Update File: ')
      || !addTarget(callString(STRING_SLICE, header, 17))) return null;
    index += 1;
    if (index < end) {
      const move = callString(STRING_TRIM, lines[index]);
      if (callString(STRING_STARTS_WITH, move, '*** Move to: ')) {
        if (!addTarget(callString(STRING_SLICE, move, 13))) return null;
        index += 1;
      }
    }
    let chunks = 0;
    while (index < end) {
      if (callString(STRING_TRIM, lines[index]) === '') {
        index += 1;
        continue;
      }
      if (callString(STRING_STARTS_WITH, lines[index], '***')) break;
      const consumed = parseUpdateChunk(index, chunks === 0);
      if (consumed === 0) return null;
      chunks += 1;
      index += consumed;
    }
    if (chunks === 0) return null;
  }
  return targets.length > 0 ? targets : null;
}

function normalizedMutationTargets(toolName, params) {
  if (!REFLECT_APPLY(SET_HAS, FILE_MUTATION_TOOLS, [toolName])) return null;
  if (toolName === 'write') {
    if (!exactOwnKeys(params, ['path', 'content'])) return null;
    const target = ownData(params, 'path').value;
    const content = ownData(params, 'content').value;
    return typeof content === 'string' && canonicalAbsolute(target) ? [target] : null;
  }
  if (toolName === 'edit') {
    if (!exactOwnKeys(params, ['path', 'edits'])) return null;
    const target = ownData(params, 'path').value;
    return canonicalAbsolute(target) && validEditList(ownData(params, 'edits').value)
      ? [target]
      : null;
  }
  return patchMutationTargets(params);
}

function isInside(root, target) {
  const rel = relative(root, target);
  return rel !== ''
    && rel !== '..'
    && !callString(STRING_STARTS_WITH, rel, `..${sep}`)
    && !isAbsolute(rel);
}

function existingShippedRuntimeTarget(pluginRoot, target) {
  try {
    const realRoot = realpathSync(pluginRoot);
    const realTarget = realpathSync(target);
    if (realRoot !== pluginRoot || realTarget !== target || !isInside(pluginRoot, target)) return false;
    const targetLstat = lstatSync(target);
    if ((targetLstat.mode & fsConstants.S_IFMT) !== fsConstants.S_IFREG) return false;
    return REFLECT_APPLY(SET_HAS, SHIPPED_RUNTIME_FILES, [relative(pluginRoot, target)]);
  } catch {
    return false;
  }
}

function selfModification(toolName, params, pluginRoot, auditPath) {
  const targets = normalizedMutationTargets(toolName, params);
  if (targets === null) return false;
  for (let index = 0; index < targets.length; index += 1) {
    if (targets[index] === auditPath
      || existingShippedRuntimeTarget(pluginRoot, targets[index])) return true;
  }
  return false;
}

function parsedNetworkUrl(value) {
  if (typeof value !== 'string' || value.length === 0
    || callString(STRING_TRIM, value) !== value
    || value.length > 8_192 || callRegExp(REGEXP_TEST, CONTROL_PATTERN, value)) return null;
  try {
    const parsed = new URL_CONSTRUCTOR(value);
    const protocol = REFLECT_APPLY(URL_PROTOCOL_GET, parsed, []);
    const hostname = REFLECT_APPLY(URL_HOSTNAME_GET, parsed, []);
    if (protocol !== 'http:' && protocol !== 'https:') return null;
    return hostname === '' ? null : parsed;
  } catch {
    return null;
  }
}

function transmittedUrl(value) {
  if (parsedNetworkUrl(value) === null) return null;
  const fragmentIndex = callString(STRING_INDEX_OF, value, '#');
  return fragmentIndex < 0 ? value : callString(STRING_SLICE, value, 0, fragmentIndex);
}

function hasProvenSecret(value) {
  try {
    return redactForJudgeWithProvenance(value).secret_redacted === true;
  } catch {
    return false;
  }
}

function validStringArrayBounded(value, { allowEmpty = true, maxItems = 256 } = {}) {
  if (!ARRAY_IS_ARRAY(value) || value.length > maxItems || !allowEmpty && value.length === 0) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    if (typeof value[index] !== 'string') return false;
  }
  return true;
}

function validPresentationAction(value) {
  if (!allowedOwnKeys(value, PRESENTATION_ACTION_KEYS, ['type'])) return false;
  const type = ownData(value, 'type').value;
  if (type === 'command') {
    return exactOwnKeys(value, ['type', 'command'])
      && typeof ownData(value, 'command').value === 'string';
  }
  return type === 'callback'
    && exactOwnKeys(value, ['type', 'value'])
    && typeof ownData(value, 'value').value === 'string';
}

function validPresentationOption(value) {
  if (!allowedOwnKeys(value, PRESENTATION_OPTION_KEYS, ['label'])
    || typeof ownData(value, 'label').value !== 'string') return false;
  const action = ownData(value, 'action');
  const optionValue = ownData(value, 'value');
  return (!action.ok || validPresentationAction(action.value))
    && (!optionValue.ok || typeof optionValue.value === 'string');
}

function validPresentationButton(value) {
  if (!allowedOwnKeys(value, PRESENTATION_BUTTON_KEYS, ['label'])
    || typeof ownData(value, 'label').value !== 'string') return false;
  for (const key of ['value', 'url']) {
    const field = ownData(value, key);
    if (field.ok && typeof field.value !== 'string') return false;
  }
  for (const key of ['disabled', 'reusable']) {
    const field = ownData(value, key);
    if (field.ok && typeof field.value !== 'boolean') return false;
  }
  const action = ownData(value, 'action');
  if (action.ok && !validPresentationAction(action.value)) return false;
  const style = ownData(value, 'style');
  if (style.ok && !REFLECT_APPLY(SET_HAS, PRESENTATION_BUTTON_STYLES, [style.value])) return false;
  for (const key of ['webApp', 'web_app']) {
    const field = ownData(value, key);
    if (field.ok && (!exactOwnKeys(field.value, ['url'])
      || typeof ownData(field.value, 'url').value !== 'string')) return false;
  }
  return true;
}

function validPresentation(value) {
  if (!allowedOwnKeys(value, PRESENTATION_KEYS, ['blocks'])) return false;
  const title = ownData(value, 'title');
  const tone = ownData(value, 'tone');
  const blocks = ownData(value, 'blocks').value;
  if (title.ok && typeof title.value !== 'string') return false;
  if (tone.ok && !REFLECT_APPLY(SET_HAS, PRESENTATION_TONES, [tone.value])) return false;
  if (!ARRAY_IS_ARRAY(blocks) || blocks.length === 0 || blocks.length > 256) return false;
  for (let index = 0; index < blocks.length; index += 1) {
    const block = blocks[index];
    if (!allowedOwnKeys(block, PRESENTATION_BLOCK_KEYS, ['type'])
      || !REFLECT_APPLY(SET_HAS, PRESENTATION_BLOCK_TYPES, [ownData(block, 'type').value])) {
      return false;
    }
    for (const key of ['text', 'placeholder']) {
      const field = ownData(block, key);
      if (field.ok && typeof field.value !== 'string') return false;
    }
    const buttons = ownData(block, 'buttons');
    if (buttons.ok) {
      if (!ARRAY_IS_ARRAY(buttons.value) || buttons.value.length > 256) return false;
      for (let item = 0; item < buttons.value.length; item += 1) {
        if (!validPresentationButton(buttons.value[item])) return false;
      }
    }
    const options = ownData(block, 'options');
    if (options.ok) {
      if (!ARRAY_IS_ARRAY(options.value) || options.value.length > 256) return false;
      for (let item = 0; item < options.value.length; item += 1) {
        if (!validPresentationOption(options.value[item])) return false;
      }
    }
  }
  return true;
}

function validMessageAttachments(value) {
  if (!ARRAY_IS_ARRAY(value) || value.length === 0 || value.length > 256) return false;
  for (let index = 0; index < value.length; index += 1) {
    const attachment = value[index];
    if (!allowedOwnKeys(attachment, MESSAGE_ATTACHMENT_KEYS, ['media'])) return false;
    const type = ownData(attachment, 'type');
    const media = ownData(attachment, 'media').value;
    const name = ownData(attachment, 'name');
    const mimeType = ownData(attachment, 'mimeType');
    if (type.ok && !REFLECT_APPLY(SET_HAS, MESSAGE_ATTACHMENT_TYPES, [type.value])) return false;
    if (typeof media !== 'string' || callString(STRING_TRIM, media) === '') return false;
    if (name.ok && typeof name.value !== 'string') return false;
    if (mimeType.ok && typeof mimeType.value !== 'string') return false;
  }
  return true;
}

function validDelivery(value) {
  if (!allowedOwnKeys(value, DELIVERY_KEYS, [])) return false;
  const pin = ownData(value, 'pin');
  if (!pin.ok || typeof pin.value === 'boolean') return true;
  if (!allowedOwnKeys(pin.value, DELIVERY_PIN_KEYS, ['enabled'])
    || typeof ownData(pin.value, 'enabled').value !== 'boolean') return false;
  for (const key of ['notify', 'required']) {
    const field = ownData(pin.value, key);
    if (field.ok && typeof field.value !== 'boolean') return false;
  }
  return true;
}

function exactMessageSink(params) {
  if (!allowedOwnKeys(params, MESSAGE_SEND_KEYS, ['action'])
    || ownData(params, 'action').value !== 'send') return false;
  const keys = REFLECT_OWN_KEYS(OBJECT_GET_OWN_PROPERTY_DESCRIPTORS(params));
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const field = ownData(params, key);
    if (REFLECT_APPLY(SET_HAS, MESSAGE_STRING_FIELDS, [key])
      && typeof field.value !== 'string') return false;
    if (REFLECT_APPLY(SET_HAS, MESSAGE_BOOLEAN_FIELDS, [key])
      && typeof field.value !== 'boolean') return false;
  }
  const targets = ownData(params, 'targets');
  if (targets.ok && !validStringArrayBounded(targets.value, { allowEmpty: false })) return false;
  const dryRun = ownData(params, 'dryRun');
  if (dryRun.ok && dryRun.value !== false) return false;
  const attachments = ownData(params, 'attachments');
  if (attachments.ok && !validMessageAttachments(attachments.value)) return false;
  const presentation = ownData(params, 'presentation');
  if (presentation.ok && !validPresentation(presentation.value)) return false;
  const delivery = ownData(params, 'delivery');
  if (delivery.ok && !validDelivery(delivery.value)) return false;

  let hasPayload = attachments.ok || presentation.ok;
  for (const key of ['message', 'media', 'buffer']) {
    const field = ownData(params, key);
    if (field.ok && callString(STRING_TRIM, field.value) !== '') hasPayload = true;
  }
  return hasPayload && hasProvenSecret(params);
}

function exactWebFetchSink(params) {
  if (!allowedOwnKeys(params, WEB_FETCH_KEYS, ['url'])) return false;
  const extractMode = ownData(params, 'extractMode');
  if (extractMode.ok && !REFLECT_APPLY(SET_HAS, WEB_FETCH_MODES, [extractMode.value])) return false;
  const maxChars = ownData(params, 'maxChars');
  if (maxChars.ok && (!NUMBER_IS_INTEGER(maxChars.value) || maxChars.value < 100)) return false;
  const url = transmittedUrl(ownData(params, 'url').value);
  return url !== null && hasProvenSecret(url);
}

function browserTargetIsExternal(params) {
  const target = ownData(params, 'target');
  const node = ownData(params, 'node');
  const profile = ownData(params, 'profile');
  if (target.ok && !REFLECT_APPLY(SET_HAS, BROWSER_TARGETS, [target.value])) return false;
  if (node.ok && (typeof node.value !== 'string' || callString(STRING_TRIM, node.value) === ''
    || target.ok && target.value !== 'node')) return false;
  if (profile.ok && (typeof profile.value !== 'string'
    || callString(STRING_TRIM, profile.value) === '')) return false;
  return true;
}

function exactBrowserNavigationSink(params) {
  const actionName = ownData(params, 'action').value;
  const allowed = actionName === 'open' ? BROWSER_OPEN_KEYS : BROWSER_NAVIGATE_KEYS;
  if ((actionName !== 'navigate' && actionName !== 'open')
    || !allowedOwnKeys(params, allowed, ['action'])
    || !browserTargetIsExternal(params)) return false;
  for (const key of actionName === 'open' ? ['label', 'timeoutMs'] : ['targetId', 'timeoutMs']) {
    const field = ownData(params, key);
    if (!field.ok) continue;
    if (key === 'timeoutMs') {
      if (!NUMBER_IS_INTEGER(field.value) || field.value <= 0) return false;
    } else if (typeof field.value !== 'string' || callString(STRING_TRIM, field.value) === '') {
      return false;
    }
  }
  const targetUrl = ownData(params, 'targetUrl');
  const legacyUrl = ownData(params, 'url');
  const value = targetUrl.ok ? targetUrl.value : (legacyUrl.ok ? legacyUrl.value : undefined);
  const url = transmittedUrl(value);
  return url !== null && hasProvenSecret(url);
}

function exactTypedBrowserRequest(request, params, nested) {
  if (nested && !allowedOwnKeys(request, BROWSER_TYPE_REQUEST_KEYS, ['kind', 'text'])) return false;
  const ref = ownData(request, 'ref').value;
  const selector = ownData(request, 'selector').value;
  const text = ownData(request, 'text').value;
  if (ownData(request, 'kind').value !== 'type'
    || !(typeof ref === 'string' && callString(STRING_TRIM, ref) !== ''
      || typeof selector === 'string' && callString(STRING_TRIM, selector) !== '')
    || typeof text !== 'string') return false;
  for (const key of ['targetId', 'ref', 'selector']) {
    const field = ownData(request, key);
    if (field.ok && (typeof field.value !== 'string'
      || callString(STRING_TRIM, field.value) === '')) return false;
  }
  for (const key of ['submit', 'slowly']) {
    const field = ownData(request, key);
    if (field.ok && typeof field.value !== 'boolean') return false;
  }
  const delayMs = ownData(request, 'delayMs');
  if (delayMs.ok && (!NUMBER_IS_INTEGER(delayMs.value) || delayMs.value < 0)) return false;
  const timeoutMs = ownData(request, 'timeoutMs');
  if (timeoutMs.ok && (!NUMBER_IS_INTEGER(timeoutMs.value) || timeoutMs.value <= 0)) return false;
  if (params !== request) {
    const outerTargetId = ownData(params, 'targetId');
    const outerTimeout = ownData(params, 'timeoutMs');
    if (outerTargetId.ok && (typeof outerTargetId.value !== 'string'
      || callString(STRING_TRIM, outerTargetId.value) === '')) return false;
    if (outerTimeout.ok && (!NUMBER_IS_INTEGER(outerTimeout.value) || outerTimeout.value <= 0)) {
      return false;
    }
  }
  return hasProvenSecret(text);
}

function exactBrowserTypeSink(params) {
  if (ownData(params, 'action').value !== 'act' || !browserTargetIsExternal(params)) return false;
  const request = ownData(params, 'request');
  if (request.ok) {
    return allowedOwnKeys(params, BROWSER_TYPE_OUTER_NESTED_KEYS, ['action', 'request'])
      && exactTypedBrowserRequest(request.value, params, true);
  }
  return allowedOwnKeys(params, BROWSER_TYPE_OUTER_FLAT_KEYS, ['action', 'kind', 'text'])
    && exactTypedBrowserRequest(params, params, false);
}

function exactBrowserSink(params) {
  return exactBrowserNavigationSink(params) || exactBrowserTypeSink(params);
}

function secretExternalSink(toolName, params) {
  if (toolName === 'message') return exactMessageSink(params);
  if (toolName === 'web_fetch') return exactWebFetchSink(params);
  if (toolName === 'browser') return exactBrowserSink(params);
  return false;
}

function validStringArray(value) {
  if (!ARRAY_IS_ARRAY(value) || value.length > 256) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (typeof value[index] !== 'string') return false;
  }
  return true;
}

function validGatewayMutationEnvelope(params) {
  if (!allowedOwnKeys(params, GATEWAY_MUTATION_KEYS, ['action', 'raw'])) return false;
  const actionName = ownData(params, 'action').value;
  if ((actionName !== 'config.patch' && actionName !== 'config.apply')
    || typeof ownData(params, 'raw').value !== 'string') return false;
  for (const key of ['baseHash', 'sessionKey', 'note', 'gatewayUrl', 'gatewayToken']) {
    const field = ownData(params, key);
    if (field.ok && typeof field.value !== 'string') return false;
  }
  for (const key of ['reason', 'continuationMessage']) {
    const field = ownData(params, key);
    if (field.ok && typeof field.value !== 'string') return false;
  }
  for (const key of ['delayMs', 'restartDelayMs']) {
    const field = ownData(params, key);
    if (field.ok && (!NUMBER_IS_INTEGER(field.value) || field.value < 0)) return false;
  }
  const timeoutMs = ownData(params, 'timeoutMs');
  if (timeoutMs.ok && (!NUMBER_IS_INTEGER(timeoutMs.value) || timeoutMs.value <= 0)) return false;
  const replacePaths = ownData(params, 'replacePaths');
  if (replacePaths.ok
    && (actionName !== 'config.patch' || !validStringArray(replacePaths.value))) return false;
  return true;
}

function judgeEntry(value) {
  const plugins = ownData(value, 'plugins');
  const entries = plugins.ok ? ownData(plugins.value, 'entries') : { ok: false };
  return entries.ok ? ownData(entries.value, 'llm-action-judge') : { ok: false };
}

function containsJudgeDisable(value, fullApply) {
  const judge = judgeEntry(value);
  if (!judge.ok) return fullApply;
  const enabled = ownData(judge.value, 'enabled');
  const config = ownData(judge.value, 'config');
  const enforcement = config.ok ? ownData(config.value, 'enforcement') : { ok: false };
  if (enabled.ok && enabled.value === false
    || enforcement.ok && enforcement.value === 'shadow') return true;
  return fullApply && (enabled.value !== true || enforcement.value !== 'enforce');
}

function currentGatewayBoundaryBypass(params) {
  if (!validGatewayMutationEnvelope(params)) return false;
  const raw = ownData(params, 'raw').value;
  let parsed;
  try {
    parsed = JSON_PARSE(raw);
    if (!validateDeepData(parsed, new Set())) return false;
  } catch {
    return false;
  }
  return containsJudgeDisable(parsed, ownData(params, 'action').value === 'config.apply');
}

function legacyGatewayBoundaryBypass(params) {
  return exactOwnKeys(params, ['action', 'path', 'value'])
    && ownData(params, 'action').value === 'config.set'
    && (ownData(params, 'path').value === 'plugins.entries.llm-action-judge.enabled'
      && ownData(params, 'value').value === false
      || ownData(params, 'path').value
        === 'plugins.entries.llm-action-judge.config.enforcement'
        && ownData(params, 'value').value === 'shadow');
}

function securityBoundaryBypass(toolName, params) {
  return toolName === 'gateway'
    && (legacyGatewayBoundaryBypass(params) || currentGatewayBoundaryBypass(params));
}

function exactSessionStatus(action) {
  if (action.tool_name !== 'session_status') return false;
  if (exactOwnKeys(action.params, [])) return true;
  if (!exactOwnKeys(action.params, ['sessionKey'])) return false;
  const requested = ownData(action.params, 'sessionKey').value;
  return requested === 'current'
    || typeof action.session_key === 'string'
      && callString(STRING_TRIM, action.session_key) !== ''
      && requested === action.session_key;
}

function exactBrowserWait(action) {
  if (action.tool_name !== 'browser') return false;
  const params = action.params;
  const nestedBase = exactOwnKeys(params, ['action', 'target', 'request']);
  const nestedProfile = exactOwnKeys(params, ['action', 'profile', 'request', 'target']);
  const legacyBase = exactOwnKeys(params, ['action', 'kind', 'target', 'timeMs']);
  const legacyProfile = exactOwnKeys(params, ['action', 'kind', 'profile', 'target', 'timeMs']);
  if (!nestedBase && !nestedProfile && !legacyBase && !legacyProfile) return false;
  if (ownData(params, 'action').value !== 'act' || ownData(params, 'target').value !== 'sandbox') {
    return false;
  }
  if (nestedProfile || legacyProfile) {
    const profile = ownData(params, 'profile').value;
    if (typeof profile !== 'string' || callString(STRING_TRIM, profile) === '') return false;
  }
  const wait = nestedBase || nestedProfile ? ownData(params, 'request').value : params;
  if ((nestedBase || nestedProfile) && !exactOwnKeys(wait, ['kind', 'timeMs'])) return false;
  const kind = ownData(wait, 'kind').value;
  const timeMs = ownData(wait, 'timeMs').value;
  return kind === 'wait' && NUMBER_IS_INTEGER(timeMs)
    && timeMs >= 0 && timeMs <= BROWSER_MAX_WAIT_MS;
}

export function classifySafePathShape(action) {
  try {
    if (!routingRuntimeIsPristine()
      || action === null || typeof action !== 'object' || IS_PROXY(action)) return null;
    const toolName = ownData(action, 'tool_name');
    const params = ownData(action, 'params');
    const sessionKey = ownData(action, 'session_key');
    if (!toolName.ok || typeof toolName.value !== 'string' || !params.ok) return null;
    const snapshot = {
      tool_name: toolName.value,
      params: params.value,
      session_key: sessionKey.ok ? sessionKey.value : undefined,
    };
    if (exactSessionStatus(snapshot)) return 'session_status_current';
    if (exactBrowserWait(snapshot)) return 'browser_wait';
    return null;
  } catch {
    return null;
  }
}

export function assessPolicyRoute(input) {
  const snapshot = snapshotInput(input);
  const { action, pluginRoot, auditPath, redaction } = snapshot;
  if (selfModification(action.tool_name, action.params, pluginRoot, auditPath)) {
    return hardRoute('self_modification');
  }
  if (secretExternalSink(action.tool_name, action.params)) {
    return hardRoute('secret_external_sink');
  }
  if (securityBoundaryBypass(action.tool_name, action.params)) {
    return hardRoute('security_boundary_bypass');
  }
  if (!redaction.opaque && !redaction.secret_redacted && !redaction.truncated) {
    const safeFamily = classifySafePathShape(action);
    if (safeFamily !== null) return result('judge', null, true, safeFamily);
  }
  return judgeRoute();
}
