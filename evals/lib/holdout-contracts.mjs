import { createHash, createHmac } from 'node:crypto';
import { canonicalStringify } from '../../src/action.js';
import { isTrustedUserRequest } from '../../src/constants.js';
import { assertProxyFreeTree } from './case-schema.mjs';
import { lintCorpus } from './corpus.mjs';

const INPUT_SCHEMA_VERSION = 'judge-holdout-input.v1';
const ORACLE_SCHEMA_VERSION = 'judge-holdout-oracle.v1';
const EVALUATION_ID_DOMAIN = 'judge-holdout-evaluation-id.v1';

const INPUT_KEYS = Object.freeze(['schema_version', 'holdout_id', 'cases']);
const INPUT_CASE_KEYS = Object.freeze([
  'evaluation_id', 'trusted_user_request', 'tool_name', 'params',
]);
const ORACLE_KEYS = Object.freeze([
  'schema_version', 'holdout_id', 'input_sha256', 'cases',
]);
const ORACLE_CASE_KEYS = Object.freeze([
  'evaluation_id', 'family_id', 'split', 'language', 'auto_allow_permitted',
  'preferred_disposition', 'intrinsic_risk', 'authorization', 'reversibility',
  'blast_radius', 'provenance', 'persistence', 'impact_tier',
  'acceptable_conservative_outcomes', 'oracle_rationale', 'tags',
]);

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const EVALUATION_ID_PATTERN = /^eval-[0-9a-f]{64}$/u;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const ID_KEY_PATTERN = /^[\x21-\x7e]{32,4096}$/u;
const CATASTROPHIC_BLAST_RADII = new Set(['org', 'external', 'production']);
const HOLDOUT_SPLITS = new Set(['frozen-holdout', 'reserve-holdout']);

const ENUMS = Object.freeze({
  split: new Set([
    'model-selection',
    'gate-validation',
    'frozen-holdout',
    'reserve-holdout',
    'runtime-e2e',
  ]),
  language: new Set(['ru', 'en', 'mixed']),
  preferred_disposition: new Set(['allow', 'review', 'deny']),
  intrinsic_risk: new Set(['low', 'medium', 'high', 'critical']),
  authorization: new Set(['explicit', 'implicit_necessary', 'ambiguous', 'absent', 'contradicted']),
  reversibility: new Set(['reversible', 'costly', 'irreversible']),
  blast_radius: new Set(['scratch', 'workspace', 'repo', 'host', 'org', 'external', 'production']),
  provenance: new Set([
    'trusted_user',
    'untrusted_web',
    'untrusted_email',
    'untrusted_file',
    'untrusted_rag',
    'tool_result',
  ]),
  persistence: new Set(['none', 'config', 'startup', 'ci', 'agent_self']),
  impact_tier: new Set(['normal', 'dangerous', 'catastrophic']),
});

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  try {
    if (Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function readExactObject(value, expectedKeys, name) {
  if (!isPlainObject(value)) throw new TypeError(name + ' must be a plain object');

  let descriptors;
  let symbols;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
    symbols = Object.getOwnPropertySymbols(value);
  } catch {
    throw new TypeError(name + ' must contain own data properties');
  }

  const actualKeys = Object.getOwnPropertyNames(descriptors);
  const expected = new Set(expectedKeys);
  if (symbols.length !== 0
    || actualKeys.length !== expectedKeys.length
    || actualKeys.some((key) => !expected.has(key))) {
    throw new TypeError(name + ' has missing or unknown fields');
  }

  const result = {};
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(name + ' must contain own data properties');
    }
    result[key] = descriptor.value;
  }
  return result;
}

function readDenseArray(value, name, { nonEmpty = false } = {}) {
  if (!Array.isArray(value)) throw new TypeError(name + ' must be an array');

  let descriptors;
  let symbols;
  let prototype;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
    symbols = Object.getOwnPropertySymbols(value);
  } catch {
    throw new TypeError(name + ' must contain dense data elements');
  }
  if (prototype !== Array.prototype) throw new TypeError(name + ' must be an array');
  const lengthDescriptor = descriptors.length;
  const length = lengthDescriptor?.value;
  if (symbols.length !== 0
    || !Number.isSafeInteger(length)
    || length < 0
    || Object.getOwnPropertyNames(descriptors).length !== length + 1
    || (nonEmpty && length === 0)) {
    throw new TypeError(name + (nonEmpty ? ' must be a non-empty dense array' : ' must be a dense array'));
  }

  const result = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(name + ' must contain dense data elements');
    }
    result.push(descriptor.value);
  }
  return result;
}

function clonePlainJsonObject(value, name) {
  if (!isPlainObject(value)) throw new TypeError(name + ' must be a plain object');
  try {
    return JSON.parse(canonicalStringify(value));
  } catch {
    throw new TypeError(name + ' must contain plain JSON data');
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function assertNonBlankString(value, field) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(field + ' must be a non-blank string');
  }
}

function assertIdentifier(value, field) {
  if (typeof value !== 'string' || !IDENTIFIER_PATTERN.test(value)) {
    throw new TypeError(field + ' has an invalid identifier');
  }
}

function assertEvaluationId(value) {
  if (typeof value !== 'string' || !EVALUATION_ID_PATTERN.test(value)) {
    throw new TypeError('evaluation_id has an invalid value');
  }
}

function assertEnum(value, field) {
  if (typeof value !== 'string' || !ENUMS[field].has(value)) {
    throw new TypeError(field + ' has an invalid value');
  }
}

function validateUniqueStringArray(value, name, allowedValues) {
  const items = readDenseArray(value, name);
  const unique = new Set();
  for (const item of items) {
    if (typeof item !== 'string' || item.trim() === '' || unique.has(item)) {
      throw new TypeError(name + ' must contain unique non-blank strings');
    }
    if (allowedValues && !allowedValues.has(item)) {
      throw new TypeError(name + ' contains an invalid value');
    }
    unique.add(item);
  }
  return items.slice();
}

function assertDispositionOutcomes(disposition, outcomes) {
  const expected = disposition === 'allow'
    ? []
    : disposition === 'review' ? ['review', 'deny'] : ['deny'];
  if (outcomes.length !== expected.length
    || outcomes.some((value, index) => value !== expected[index])) {
    throw new TypeError('acceptable_conservative_outcomes conflict with preferred_disposition');
  }
}

function isSafeAutoAllowOracle(item) {
  return item.auto_allow_permitted
    && item.intrinsic_risk === 'low'
    && (item.authorization === 'explicit' || item.authorization === 'implicit_necessary')
    && item.reversibility === 'reversible'
    && item.persistence === 'none'
    && item.blast_radius !== 'production'
    && item.impact_tier === 'normal';
}

function requiresCatastrophicImpact(item) {
  return item.intrinsic_risk === 'critical'
    || (item.reversibility === 'irreversible'
      && CATASTROPHIC_BLAST_RADII.has(item.blast_radius));
}

function assertUniqueEvaluationIds(cases) {
  const seen = new Set();
  for (const item of cases) {
    if (seen.has(item.evaluation_id)) throw new TypeError('duplicate evaluation_id');
    seen.add(item.evaluation_id);
  }
}

function hashCanonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function evaluationId({ holdoutId, originalCaseId, idKey }) {
  const payload = canonicalStringify({
    domain: EVALUATION_ID_DOMAIN,
    holdout_id: holdoutId,
    original_case_id: originalCaseId,
  });
  return 'eval-' + createHmac('sha256', idKey).update(payload, 'utf8').digest('hex');
}

export function validateHoldoutInputCase(value) {
  assertProxyFreeTree(value, 'holdout input case');
  const item = readExactObject(value, INPUT_CASE_KEYS, 'holdout input case');
  assertEvaluationId(item.evaluation_id);
  if (!isTrustedUserRequest(item.trusted_user_request)) {
    throw new TypeError('trusted_user_request exceeds the production trust boundary');
  }
  assertNonBlankString(item.tool_name, 'tool_name');
  const params = clonePlainJsonObject(item.params, 'params');

  return deepFreeze({
    evaluation_id: item.evaluation_id,
    trusted_user_request: item.trusted_user_request,
    tool_name: item.tool_name,
    params,
  });
}

export function validateHoldoutOracleCase(value) {
  assertProxyFreeTree(value, 'holdout oracle case');
  const item = readExactObject(value, ORACLE_CASE_KEYS, 'holdout oracle case');
  assertEvaluationId(item.evaluation_id);
  assertIdentifier(item.family_id, 'family_id');
  for (const field of Object.keys(ENUMS)) assertEnum(item[field], field);
  if (!HOLDOUT_SPLITS.has(item.split)) {
    throw new TypeError('split must be a holdout split');
  }
  if (typeof item.auto_allow_permitted !== 'boolean') {
    throw new TypeError('auto_allow_permitted must be boolean');
  }
  assertNonBlankString(item.oracle_rationale, 'oracle_rationale');
  const acceptableConservativeOutcomes = validateUniqueStringArray(
    item.acceptable_conservative_outcomes,
    'acceptable_conservative_outcomes',
    new Set(['allow', 'review', 'deny']),
  );
  assertDispositionOutcomes(item.preferred_disposition, acceptableConservativeOutcomes);
  const tags = validateUniqueStringArray(item.tags, 'tags');

  if (item.auto_allow_permitted !== (item.preferred_disposition === 'allow')) {
    throw new TypeError('binary and disposition labels conflict');
  }
  if (item.auto_allow_permitted && !isSafeAutoAllowOracle(item)) {
    throw new TypeError('auto-allow oracle case violates safety policy');
  }
  if (item.tags.includes('common-read-status') && !isSafeAutoAllowOracle(item)) {
    throw new TypeError('common-read-status tag requires safe auto-allow case');
  }
  const catastrophicImpact = item.impact_tier === 'catastrophic';
  if (catastrophicImpact !== requiresCatastrophicImpact(item)) {
    throw new TypeError('oracle case has inconsistent catastrophic impact tier');
  }

  return deepFreeze({
    evaluation_id: item.evaluation_id,
    family_id: item.family_id,
    split: item.split,
    language: item.language,
    auto_allow_permitted: item.auto_allow_permitted,
    preferred_disposition: item.preferred_disposition,
    intrinsic_risk: item.intrinsic_risk,
    authorization: item.authorization,
    reversibility: item.reversibility,
    blast_radius: item.blast_radius,
    provenance: item.provenance,
    persistence: item.persistence,
    impact_tier: item.impact_tier,
    acceptable_conservative_outcomes: acceptableConservativeOutcomes,
    oracle_rationale: item.oracle_rationale,
    tags,
  });
}

export function validateHoldoutInput(value) {
  assertProxyFreeTree(value, 'holdout input');
  const item = readExactObject(value, INPUT_KEYS, 'holdout input');
  if (item.schema_version !== INPUT_SCHEMA_VERSION) {
    throw new TypeError('holdout input has an invalid schema_version');
  }
  assertIdentifier(item.holdout_id, 'holdout_id');
  const cases = readDenseArray(item.cases, 'holdout input cases', { nonEmpty: true })
    .map(validateHoldoutInputCase);
  assertUniqueEvaluationIds(cases);

  return deepFreeze({
    schema_version: INPUT_SCHEMA_VERSION,
    holdout_id: item.holdout_id,
    cases,
  });
}

export function validateHoldoutOracle(value) {
  assertProxyFreeTree(value, 'holdout oracle');
  const item = readExactObject(value, ORACLE_KEYS, 'holdout oracle');
  if (item.schema_version !== ORACLE_SCHEMA_VERSION) {
    throw new TypeError('holdout oracle has an invalid schema_version');
  }
  assertIdentifier(item.holdout_id, 'holdout_id');
  if (typeof item.input_sha256 !== 'string' || !SHA256_PATTERN.test(item.input_sha256)) {
    throw new TypeError('input_sha256 has an invalid value');
  }
  const cases = readDenseArray(item.cases, 'holdout oracle cases', { nonEmpty: true })
    .map(validateHoldoutOracleCase);
  assertUniqueEvaluationIds(cases);
  if (new Set(cases.map((entry) => entry.split)).size !== 1) {
    throw new TypeError('oracle cases must use a single holdout split');
  }

  return deepFreeze({
    schema_version: ORACLE_SCHEMA_VERSION,
    holdout_id: item.holdout_id,
    input_sha256: item.input_sha256,
    cases,
  });
}

export function holdoutInputHash(value) {
  return hashCanonical(validateHoldoutInput(value));
}

export function buildHoldoutSplit(options) {
  assertProxyFreeTree(options, 'holdout split options');
  const fields = readExactObject(
    options,
    ['holdoutId', 'cases', 'idKey'],
    'holdout split options',
  );
  assertIdentifier(fields.holdoutId, 'holdoutId');
  if (typeof fields.idKey !== 'string' || !ID_KEY_PATTERN.test(fields.idKey)) {
    throw new TypeError('idKey must contain 32..4096 printable non-whitespace ASCII characters');
  }

  const sourceCases = readDenseArray(fields.cases, 'holdout source cases', { nonEmpty: true });
  const validatedCases = lintCorpus(sourceCases);
  if (validatedCases.some((item) => !HOLDOUT_SPLITS.has(item.split))) {
    throw new TypeError('source cases must use a holdout split');
  }
  if (new Set(validatedCases.map((item) => item.split)).size !== 1) {
    throw new TypeError('source cases must use a single holdout split');
  }
  const originalIds = new Set();
  const projected = validatedCases.map((item) => {
    if (originalIds.has(item.id)) throw new TypeError('duplicate case id');
    originalIds.add(item.id);
    const evaluation_id = evaluationId({
      holdoutId: fields.holdoutId,
      originalCaseId: item.id,
      idKey: fields.idKey,
    });
    return {
      input: validateHoldoutInputCase({
        evaluation_id,
        trusted_user_request: item.trusted_user_request,
        tool_name: item.tool_name,
        params: item.params,
      }),
      oracle: validateHoldoutOracleCase({
        evaluation_id,
        family_id: item.family_id,
        split: item.split,
        language: item.language,
        auto_allow_permitted: item.auto_allow_permitted,
        preferred_disposition: item.preferred_disposition,
        intrinsic_risk: item.intrinsic_risk,
        authorization: item.authorization,
        reversibility: item.reversibility,
        blast_radius: item.blast_radius,
        provenance: item.provenance,
        persistence: item.persistence,
        impact_tier: item.impact_tier,
        acceptable_conservative_outcomes: item.acceptable_conservative_outcomes,
        oracle_rationale: item.oracle_rationale,
        tags: item.tags,
      }),
    };
  });

  const input = validateHoldoutInput({
    schema_version: INPUT_SCHEMA_VERSION,
    holdout_id: fields.holdoutId,
    cases: projected.map((item) => item.input),
  });
  const oracle = validateHoldoutOracle({
    schema_version: ORACLE_SCHEMA_VERSION,
    holdout_id: fields.holdoutId,
    input_sha256: holdoutInputHash(input),
    cases: projected.map((item) => item.oracle),
  });

  return deepFreeze({ input, oracle });
}
