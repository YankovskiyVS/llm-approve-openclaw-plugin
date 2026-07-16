import { types as utilTypes } from 'node:util';
import { FEEDBACK_CODES } from './feedback.js';
import { JUDGE_REASON_CODES } from './judge-schema.js';

const ARRAY_IS_ARRAY = Array.isArray;
const BUFFER_OBJECT = Buffer;
const BUFFER_BYTE_LENGTH = Buffer.byteLength;
const CREATE_OBJECT = Object.create;
const FREEZE_OBJECT = Object.freeze;
const GET_OWN_PROPERTY_DESCRIPTORS = Object.getOwnPropertyDescriptors;
const GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const GET_PROTOTYPE_OF = Object.getPrototypeOf;
const HAS_OWN = Object.hasOwn;
const IS_PROXY = utilTypes.isProxy;
const MAP_CONSTRUCTOR = Map;
const MAP_DELETE = Map.prototype.delete;
const MAP_FOR_EACH = Map.prototype.forEach;
const MAP_GET = Map.prototype.get;
const MAP_KEYS = Map.prototype.keys;
const MAP_SET = Map.prototype.set;
const MAP_SIZE_GETTER = GET_OWN_PROPERTY_DESCRIPTOR(Map.prototype, 'size').get;
const NUMBER_IS_SAFE_INTEGER = Number.isSafeInteger;
const OBJECT_PROTOTYPE = Object.prototype;
const REFLECT_APPLY = Reflect.apply;
const REFLECT_OWN_KEYS = Reflect.ownKeys;
const REGEXP_TEST = RegExp.prototype.test;
const SET_HAS = Set.prototype.has;
const SET_PROTOTYPE_OF = Object.setPrototypeOf;
const STRING_TRIM = String.prototype.trim;
const MAP_ITERATOR_NEXT = GET_PROTOTYPE_OF(
  REFLECT_APPLY(MAP_KEYS, new MAP_CONSTRUCTOR(), []),
).next;

const STORE_ERROR = 'invalid run decision store';
const MAX_RUN_ID_LENGTH = 256;
const MAX_RUN_ID_BYTES = 512;
const MAX_TOOL_NAME_LENGTH = 256;
const MAX_TOOL_NAME_BYTES = 512;
const MAX_RUNS_LIMIT = 1000;
const MAX_HISTORY_LIMIT = 50;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const OPTION_KEYS = FREEZE_OBJECT([
  'ttlMs',
  'maxRuns',
  'historyLimit',
  'consecutiveDenyLimit',
  'rollingDenyLimit',
  'now',
]);
const METADATA_KEYS = FREEZE_OBJECT([
  'tool_name',
  'tool_family',
  'outcome',
  'risk',
  'authorization',
  'reason_code',
]);
const TOOL_FAMILIES = new Set([
  'filesystem',
  'shell',
  'browser',
  'message',
  'network',
  'process',
  'session',
  'cron',
  'node',
  'generation',
  'skill',
  'unknown',
]);
const OUTCOMES = new Set(['allow', 'deny', 'review', 'failure']);
const RISKS = new Set(['low', 'medium', 'high', 'critical']);
const AUTHORIZATIONS = new Set(['unknown', 'low', 'medium', 'high']);
const REASON_CODES = new Set([...JUDGE_REASON_CODES, ...FEEDBACK_CODES]);
const FILESYSTEM_TOOLS = new Set(['read', 'write', 'edit', 'apply_patch']);
const NETWORK_TOOLS = new Set(['web_fetch', 'web_search', 'image_query']);
const SESSION_TOOLS = new Set([
  'sessions_list',
  'sessions_history',
  'sessions_send',
  'sessions_spawn',
  'session_status',
]);
const GENERATION_TOOLS = new Set([
  'image_generate',
  'music_generate',
  'video_generate',
]);

function invalidStore() {
  throw new TypeError(STORE_ERROR);
}

function setHas(set, value) {
  return REFLECT_APPLY(SET_HAS, set, [value]);
}

function exactKey(keys, key) {
  for (let index = 0; index < keys.length; index += 1) {
    if (keys[index] === key) return true;
  }
  return false;
}

function frozenScalarRecord(values) {
  const result = {};
  for (let index = 0; index < METADATA_KEYS.length; index += 1) {
    const key = METADATA_KEYS[index];
    result[key] = values[key];
  }
  return FREEZE_OBJECT(result);
}

function plainExactValues(source, keys) {
  try {
    if (source === null || typeof source !== 'object' || ARRAY_IS_ARRAY(source)
      || IS_PROXY(source)) invalidStore();
    const prototype = GET_PROTOTYPE_OF(source);
    if (prototype !== OBJECT_PROTOTYPE && prototype !== null) invalidStore();
    const descriptors = GET_OWN_PROPERTY_DESCRIPTORS(source);
    const ownKeys = REFLECT_OWN_KEYS(descriptors);
    if (ownKeys.length !== keys.length) invalidStore();
    for (let index = 0; index < ownKeys.length; index += 1) {
      const key = ownKeys[index];
      if (typeof key !== 'string' || !exactKey(keys, key)) invalidStore();
    }
    const result = CREATE_OBJECT(null);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !HAS_OWN(descriptor, 'value')) {
        invalidStore();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return invalidStore();
  }
}

function validBoundedName(value, maxLength, maxBytes) {
  return typeof value === 'string'
    && value.length > 0
    && REFLECT_APPLY(STRING_TRIM, value, []) !== ''
    && value.length <= maxLength
    && REFLECT_APPLY(BUFFER_BYTE_LENGTH, BUFFER_OBJECT, [value, 'utf8']) <= maxBytes
    && !REFLECT_APPLY(REGEXP_TEST, CONTROL_PATTERN, [value]);
}

function validRunId(value) {
  return validBoundedName(value, MAX_RUN_ID_LENGTH, MAX_RUN_ID_BYTES);
}

function validToolName(value) {
  return validBoundedName(value, MAX_TOOL_NAME_LENGTH, MAX_TOOL_NAME_BYTES);
}

export function classifyToolFamily(toolName) {
  if (!validToolName(toolName)) return invalidStore();
  if (setHas(FILESYSTEM_TOOLS, toolName)) return 'filesystem';
  if (toolName === 'exec' || toolName === 'bash') return 'shell';
  if (toolName === 'browser') return 'browser';
  if (toolName === 'message') return 'message';
  if (setHas(NETWORK_TOOLS, toolName)) return 'network';
  if (toolName === 'process') return 'process';
  if (setHas(SESSION_TOOLS, toolName)) return 'session';
  if (toolName === 'cron') return 'cron';
  if (toolName === 'nodes') return 'node';
  if (setHas(GENERATION_TOOLS, toolName)) return 'generation';
  if (toolName === 'skill_workshop') return 'skill';
  return 'unknown';
}

function validNullableEnum(value, allowed) {
  return value === null || (typeof value === 'string' && setHas(allowed, value));
}

function snapshotMetadata(input) {
  const values = plainExactValues(input, METADATA_KEYS);
  if (!validToolName(values.tool_name)
    || !setHas(TOOL_FAMILIES, values.tool_family)
    || values.tool_family !== classifyToolFamily(values.tool_name)
    || !setHas(OUTCOMES, values.outcome)
    || !validNullableEnum(values.risk, RISKS)
    || !validNullableEnum(values.authorization, AUTHORIZATIONS)
    || typeof values.reason_code !== 'string'
    || !setHas(REASON_CODES, values.reason_code)
    || (values.outcome === 'allow' && values.reason_code !== 'safe_and_authorized')
    || (values.outcome === 'allow'
      && (values.risk !== 'low' || values.authorization !== 'high'))
    || (values.outcome !== 'allow' && values.reason_code === 'safe_and_authorized')
    || (values.reason_code === 'repeated_denials'
      && (values.outcome !== 'deny' || values.risk !== null || values.authorization !== null))) {
    return invalidStore();
  }
  return frozenScalarRecord(values);
}

function repeatedDenialMetadata(input) {
  return frozenScalarRecord({
    tool_name: input.tool_name,
    tool_family: input.tool_family,
    outcome: 'deny',
    risk: null,
    authorization: null,
    reason_code: 'repeated_denials',
  });
}

function cloneMetadata(input) {
  return frozenScalarRecord(input);
}

function snapshotOptions(options) {
  const values = plainExactValues(options, OPTION_KEYS);
  if (!NUMBER_IS_SAFE_INTEGER(values.ttlMs) || values.ttlMs <= 0
    || !NUMBER_IS_SAFE_INTEGER(values.maxRuns) || values.maxRuns <= 0
    || values.maxRuns > MAX_RUNS_LIMIT
    || !NUMBER_IS_SAFE_INTEGER(values.historyLimit) || values.historyLimit <= 0
    || values.historyLimit > MAX_HISTORY_LIMIT
    || !NUMBER_IS_SAFE_INTEGER(values.consecutiveDenyLimit)
    || values.consecutiveDenyLimit <= 0
    || values.consecutiveDenyLimit > values.historyLimit
    || !NUMBER_IS_SAFE_INTEGER(values.rollingDenyLimit)
    || values.rollingDenyLimit <= 0
    || values.rollingDenyLimit > values.historyLimit
    || typeof values.now !== 'function'
    || IS_PROXY(values.now)) return invalidStore();
  return values;
}

function status(alreadyTripped, newlyTripped, tripped) {
  const result = {};
  result.already_tripped = alreadyTripped;
  result.newly_tripped = newlyTripped;
  result.tripped = tripped;
  return FREEZE_OBJECT(result);
}

export function createRunDecisionStore(options) {
  const settings = snapshotOptions(options);
  const runs = new MAP_CONSTRUCTOR();
  let lastClock;

  function readClock() {
    try {
      const value = settings.now();
      if (!NUMBER_IS_SAFE_INTEGER(value) || value < 0
        || (lastClock !== undefined && value < lastClock)) return invalidStore();
      lastClock = value;
      return value;
    } catch {
      return invalidStore();
    }
  }

  readClock();

  function cleanupExpired(now) {
    const expired = [];
    SET_PROTOTYPE_OF(expired, null);
    REFLECT_APPLY(MAP_FOR_EACH, runs, [function collectExpired(entry, runId) {
      if (now - entry.lastAccess >= settings.ttlMs) expired[expired.length] = runId;
    }]);
    for (let index = 0; index < expired.length; index += 1) {
      REFLECT_APPLY(MAP_DELETE, runs, [expired[index]]);
    }
  }

  function touch(runId, entry, now) {
    entry.lastAccess = now;
    REFLECT_APPLY(MAP_DELETE, runs, [runId]);
    REFLECT_APPLY(MAP_SET, runs, [runId, entry]);
  }

  function requireRunId(runId) {
    if (!validRunId(runId)) return invalidStore();
    return runId;
  }

  function find(runId) {
    const id = requireRunId(runId);
    const now = readClock();
    cleanupExpired(now);
    const entry = REFLECT_APPLY(MAP_GET, runs, [id]);
    if (entry) touch(id, entry, now);
    return { id, now, entry };
  }

  function isTripped(runId) {
    return find(runId).entry?.tripped === true;
  }

  function record(runId, metadata) {
    const id = requireRunId(runId);
    const safeMetadata = snapshotMetadata(metadata);
    const now = readClock();
    cleanupExpired(now);
    let entry = REFLECT_APPLY(MAP_GET, runs, [id]);
    if (!entry) {
      if (REFLECT_APPLY(MAP_SIZE_GETTER, runs, []) >= settings.maxRuns) {
        const iterator = REFLECT_APPLY(MAP_KEYS, runs, []);
        const oldest = REFLECT_APPLY(MAP_ITERATOR_NEXT, iterator, []).value;
        REFLECT_APPLY(MAP_DELETE, runs, [oldest]);
      }
      const history = [];
      SET_PROTOTYPE_OF(history, null);
      entry = CREATE_OBJECT(null);
      entry.lastAccess = now;
      entry.history = history;
      entry.consecutiveDenies = 0;
      entry.tripped = false;
    }

    const alreadyTripped = entry.tripped;
    const finalMetadata = alreadyTripped
      ? repeatedDenialMetadata(safeMetadata)
      : safeMetadata;
    entry.history[entry.history.length] = finalMetadata;
    if (entry.history.length > settings.historyLimit) {
      for (let index = 1; index < entry.history.length; index += 1) {
        entry.history[index - 1] = entry.history[index];
      }
      entry.history.length -= 1;
    }

    let newlyTripped = false;
    if (!alreadyTripped) {
      if (finalMetadata.outcome === 'allow') {
        entry.consecutiveDenies = 0;
      } else if (finalMetadata.outcome === 'deny') {
        entry.consecutiveDenies += 1;
      }
      let rollingDenies = 0;
      for (let index = 0; index < entry.history.length; index += 1) {
        if (entry.history[index].outcome === 'deny') rollingDenies += 1;
      }
      if (entry.consecutiveDenies >= settings.consecutiveDenyLimit
        || rollingDenies >= settings.rollingDenyLimit) {
        entry.tripped = true;
        newlyTripped = true;
      }
    }

    touch(id, entry, now);
    return status(alreadyTripped, newlyTripped, entry.tripped);
  }

  function snapshot(runId) {
    const entry = find(runId).entry;
    const result = [];
    if (entry) {
      for (let index = 0; index < entry.history.length; index += 1) {
        result[index] = cloneMetadata(entry.history[index]);
      }
    }
    return FREEZE_OBJECT(result);
  }

  function size() {
    const now = readClock();
    cleanupExpired(now);
    return REFLECT_APPLY(MAP_SIZE_GETTER, runs, []);
  }

  const api = {};
  api.isTripped = isTripped;
  api.record = record;
  api.snapshot = snapshot;
  api.size = size;
  return FREEZE_OBJECT(api);
}
