import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { JUDGE_TIMEOUT_MS, POLICY_VERSION } from '../../src/constants.js';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const GIT_PATTERN = /^[0-9a-f]{40}$/u;
const NODE_PATTERN = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const OPENCLAW_PATTERN = /^([0-9]{4})\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$/u;
const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:[/:][A-Za-z0-9][A-Za-z0-9._-]*)*$/u;
const MODEL_ID_MAX_LENGTH = 256;
const CREDENTIAL_BINDING_PATTERN = /(?:^|[?&#;,/:\s])(?:api[_-]?key|token|secret|password|authorization|credential)\s*[:=]/iu;
const ABSOLUTE_PATH_PATTERN = /(?:^|[:/])(?:\/|\\\\|[a-z]:[\\/]|file:\/\/)/iu;

const MANIFEST_KEYS = Object.freeze([
  'schema_version', 'git_sha', 'node_version', 'openclaw_version',
  'model_id', 'policy_version', 'corpus_sha256', 'pricing_sha256',
  'source_sha256', 'endpoint_origin', 'profile',
]);
const SOURCE_KEYS = Object.freeze([
  'action', 'prompt', 'decision', 'redaction', 'constants', 'judge_client', 'harness',
]);
const PROFILE_KEYS = Object.freeze([
  'name', 'temperature', 'max_tokens', 'thinking',
  'response_format', 'timeout_ms',
]);
const RESUME_KEYS = Object.freeze(['manifest_hash', 'model', 'case_id', 'repeat', 'profile']);

const PRODUCTION_PROFILE = Object.freeze({
  name: 'production',
  temperature: 0,
  max_tokens: 256,
  thinking: false,
  response_format: 'json_object',
  timeout_ms: JUDGE_TIMEOUT_MS,
});

function exactDataValues(value, expected, message) {
  try {
    if (value === null || typeof value !== 'object' || types.isProxy(value)
      || Array.isArray(value)) {
      throw new TypeError(message);
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(message);
    }

    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    if (ownKeys.length !== expected.length || ownKeys.some((key) => typeof key !== 'string')) {
      throw new TypeError(message);
    }

    const result = {};
    for (const key of expected) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError(message);
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    throw new TypeError(message);
  }
}

function requireString(value, name) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(name + ' must be a non-blank string');
  }
}

function validateNodeVersion(value) {
  if (typeof value !== 'string') throw new TypeError('invalid node version');
  const match = NODE_PATTERN.exec(value);
  if (match === null) throw new TypeError('invalid node version');
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) {
    throw new TypeError('invalid node version');
  }
  if (major < 22 || (major === 22 && minor < 19)) {
    throw new TypeError('node version is below 22.19');
  }
}

function daysInMonth(year, month) {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function validateOpenClawVersion(value) {
  if (typeof value !== 'string') throw new TypeError('invalid openclaw version');
  const match = OPENCLAW_PATTERN.exec(value);
  if (match === null) throw new TypeError('invalid openclaw version');
  const version = match.slice(1).map(Number);
  const [year, month, day] = version;
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) {
    throw new TypeError('invalid openclaw version');
  }
  const floor = [2026, 6, 11];
  for (let index = 0; index < floor.length; index += 1) {
    if (version[index] > floor[index]) return;
    if (version[index] < floor[index]) {
      throw new TypeError('openclaw version is below 2026.6.11');
    }
  }
}

function validateModelId(value) {
  requireString(value, 'model_id');
  if (value.length > MODEL_ID_MAX_LENGTH
    || !MODEL_ID_PATTERN.test(value)
    || CREDENTIAL_BINDING_PATTERN.test(value)
    || ABSOLUTE_PATH_PATTERN.test(value)) {
    throw new TypeError('invalid model id');
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function hashCanonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function validateExactManifest(input) {
  const fields = exactDataValues(input, MANIFEST_KEYS, 'invalid manifest fields');
  const source = exactDataValues(fields.source_sha256, SOURCE_KEYS, 'invalid source hashes');
  const profile = exactDataValues(fields.profile, PROFILE_KEYS, 'invalid profile fields');

  if (fields.schema_version !== 'judge-benchmark.v2') {
    throw new TypeError('invalid schema version');
  }
  if (typeof fields.git_sha !== 'string' || !GIT_PATTERN.test(fields.git_sha)) {
    throw new TypeError('invalid git sha');
  }
  validateNodeVersion(fields.node_version);
  validateOpenClawVersion(fields.openclaw_version);
  validateModelId(fields.model_id);
  if (fields.policy_version !== POLICY_VERSION) {
    throw new TypeError('invalid policy version');
  }

  for (const hash of [
    fields.corpus_sha256,
    fields.pricing_sha256,
    source.action,
    source.prompt,
    source.decision,
    source.redaction,
    source.constants,
    source.judge_client,
    source.harness,
  ]) {
    if (typeof hash !== 'string' || !HASH_PATTERN.test(hash)) {
      throw new TypeError('invalid content hash');
    }
  }

  if (fields.endpoint_origin !== 'https://foundation-models.api.cloud.ru') {
    throw new TypeError('invalid endpoint origin');
  }
  for (const key of PROFILE_KEYS) {
    if (profile[key] !== PRODUCTION_PROFILE[key]) {
      throw new TypeError('invalid production profile');
    }
  }

  return deepFreeze({
    schema_version: fields.schema_version,
    git_sha: fields.git_sha,
    node_version: fields.node_version,
    openclaw_version: fields.openclaw_version,
    model_id: fields.model_id,
    policy_version: fields.policy_version,
    corpus_sha256: fields.corpus_sha256,
    pricing_sha256: fields.pricing_sha256,
    source_sha256: source,
    endpoint_origin: fields.endpoint_origin,
    profile,
  });
}

function validateExactResumeTuple(tuple) {
  const fields = exactDataValues(tuple, RESUME_KEYS, 'invalid resume tuple');
  if (typeof fields.manifest_hash !== 'string' || !HASH_PATTERN.test(fields.manifest_hash)) {
    throw new TypeError('invalid manifest hash');
  }
  requireString(fields.model, 'model');
  requireString(fields.case_id, 'case_id');
  requireString(fields.profile, 'profile');
  if (!Number.isInteger(fields.repeat) || fields.repeat < 1 || fields.repeat > 10) {
    throw new TypeError('invalid repeat');
  }
  return {
    manifest_hash: fields.manifest_hash,
    model: fields.model,
    case_id: fields.case_id,
    repeat: fields.repeat,
    profile: fields.profile,
  };
}

export function buildManifest(input) {
  const validated = validateExactManifest(input);
  const manifestHash = hashCanonical(validated);
  return deepFreeze(Object.assign({}, validated, {
    manifest_hash: manifestHash,
  }));
}

export function makeResumeKey(tuple) {
  return hashCanonical(validateExactResumeTuple(tuple));
}
