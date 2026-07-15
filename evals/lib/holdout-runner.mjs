import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import {
  JUDGE_TIMEOUT_MS,
  MODEL_ID,
  POLICY_VERSION,
} from '../../src/constants.js';
import { assertProxyFreeTree } from './case-schema.mjs';
import {
  evaluateInferenceAttempt,
  snapshotAttemptManifest,
  snapshotInferenceAttempt,
} from './attempt.mjs';
import {
  holdoutInputHash,
  validateHoldoutInput,
} from './holdout-contracts.mjs';
import { makeResumeKey } from './manifest.mjs';

const ARTIFACT_SCHEMA_VERSION = 'judge-holdout-inference.v1';
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const EVALUATION_ID_PATTERN = /^eval-[0-9a-f]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PRODUCTION_ENDPOINT_ORIGIN = 'https://foundation-models.api.cloud.ru';
const PRODUCTION_PROFILE = Object.freeze({
  name: 'production',
  temperature: 0,
  max_tokens: 256,
  thinking: false,
  response_format: 'json_schema',
  timeout_ms: JUDGE_TIMEOUT_MS,
});

const RUN_OPTION_KEYS = Object.freeze([
  'reviewer', 'input', 'manifest', 'repeats', 'concurrency',
]);
const BUILD_OPTION_KEYS = Object.freeze([
  'input', 'manifest', 'repeats', 'concurrency', 'attempts',
]);
const ARTIFACT_KEYS = Object.freeze([
  'schema_version', 'holdout_id', 'input_sha256', 'manifest',
  'repeats', 'concurrency', 'attempts', 'artifact_sha256',
]);
const ATTEMPT_KEYS = Object.freeze([
  'resume_key', 'manifest_hash', 'model', 'profile', 'evaluation_id', 'repeat',
  'raw_decision', 'raw_risk', 'raw_authorization', 'confidence',
  'normalized_kind', 'autonomous_outcome', 'supervised_outcome',
  'schema_valid', 'failure_stage', 'failure_code', 'latency_ms', 'usage',
  'rationale_sha256',
]);
const USAGE_KEYS = Object.freeze([
  'promptTokens', 'completionTokens', 'totalTokens',
  'reasoningTokens', 'cachedPromptTokens',
]);

const DECISIONS = new Set(['allow', 'deny', 'review']);
const RISKS = new Set(['low', 'medium', 'high', 'critical']);
const AUTHORIZATIONS = new Set(['unknown', 'low', 'medium', 'high']);
const NORMALIZED_KINDS = new Set(['allow', 'deny', 'review', 'failure']);
const TRANSPORT_CODES = new Set([
  'invalid_configuration',
  'invalid_request',
  'invalid_response',
  'request_failed',
  'request_timed_out',
]);

function exactDataValues(value, expected, message) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) throw new TypeError(message);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(message);

    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) {
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

function denseArrayValues(value, name, { nonEmpty = false } = {}) {
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError(name);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const symbols = Object.getOwnPropertySymbols(value);
    const length = descriptors.length?.value;
    if (symbols.length !== 0
      || !Number.isSafeInteger(length)
      || length < 0
      || (nonEmpty && length === 0)
      || Reflect.ownKeys(descriptors).length !== length + 1) throw new TypeError(name);

    const result = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError(name);
      }
      result.push(descriptor.value);
    }
    return result;
  } catch {
    throw new TypeError(name);
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function validateRepeats(value) {
  if (!Number.isInteger(value) || value < 1 || value > 10) {
    throw new TypeError('invalid holdout repeats');
  }
  return value;
}

function validateConcurrency(value) {
  if (!Number.isInteger(value) || value < 1 || value > 32) {
    throw new TypeError('invalid holdout concurrency');
  }
  return value;
}

function assertFixedProductionJudgeContract(manifest) {
  if (manifest.model_id !== MODEL_ID
    || manifest.policy_version !== POLICY_VERSION
    || manifest.endpoint_origin !== PRODUCTION_ENDPOINT_ORIGIN
    || Object.keys(PRODUCTION_PROFILE)
      .some((key) => manifest.profile[key] !== PRODUCTION_PROFILE[key])) {
    throw new TypeError('holdout manifest does not match fixed production judge contract');
  }
}

function snapshotInputAndManifest(inputValue, manifestValue) {
  const input = validateHoldoutInput(inputValue);
  const manifest = snapshotAttemptManifest(manifestValue);
  assertFixedProductionJudgeContract(manifest);
  const inputSha256 = holdoutInputHash(input);
  if (manifest.corpus_sha256 !== inputSha256) {
    throw new TypeError('holdout input hash does not match manifest');
  }
  return { input, manifest, inputSha256 };
}

function canonicalHash(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function artifactPayload({
  holdoutId, inputSha256, manifest, repeats, concurrency, attempts,
}) {
  return {
    schema_version: ARTIFACT_SCHEMA_VERSION,
    holdout_id: holdoutId,
    input_sha256: inputSha256,
    manifest,
    repeats,
    concurrency,
    attempts,
  };
}

function snapshotUsage(value) {
  if (value === null) return null;
  const fields = exactDataValues(value, USAGE_KEYS, 'invalid holdout attempt usage');
  for (const key of USAGE_KEYS) {
    if (fields[key] !== null
      && (!Number.isSafeInteger(fields[key]) || fields[key] < 0)) {
      throw new TypeError('invalid holdout attempt usage');
    }
  }
  if (fields.promptTokens === null
    || fields.completionTokens === null
    || fields.totalTokens === null
    || fields.promptTokens + fields.completionTokens !== fields.totalTokens
    || (fields.reasoningTokens !== null
      && fields.reasoningTokens > fields.completionTokens)
    || (fields.cachedPromptTokens !== null
      && fields.cachedPromptTokens > fields.promptTokens)) {
    throw new TypeError('invalid holdout attempt usage');
  }
  return deepFreeze({
    promptTokens: fields.promptTokens,
    completionTokens: fields.completionTokens,
    totalTokens: fields.totalTokens,
    reasoningTokens: fields.reasoningTokens,
    cachedPromptTokens: fields.cachedPromptTokens,
  });
}

function isTransportCode(value) {
  return TRANSPORT_CODES.has(value)
    || (typeof value === 'string' && /^http_[1-5][0-9]{2}$/u.test(value));
}

function assertFailureConsistency(fields, usage) {
  if (fields.failure_stage === null || fields.failure_code === null) {
    if (fields.failure_stage !== null
      || fields.failure_code !== null
      || fields.schema_valid !== true
      || fields.normalized_kind === 'failure') {
      throw new TypeError('inconsistent holdout attempt failure');
    }
    return;
  }
  if (fields.normalized_kind !== 'failure') {
    throw new TypeError('inconsistent holdout attempt failure');
  }
  if (fields.failure_stage === 'normalizer') {
    if (fields.failure_code !== 'normalizer_failure' || fields.schema_valid !== true) {
      throw new TypeError('inconsistent holdout attempt failure');
    }
    return;
  }
  if (fields.schema_valid !== false) {
    throw new TypeError('inconsistent holdout attempt failure');
  }
  if (fields.failure_stage === 'reviewer') {
    if (fields.failure_code !== 'reviewer_failure' || usage !== null) {
      throw new TypeError('inconsistent holdout attempt failure');
    }
    return;
  }
  if (fields.failure_stage === 'transport') {
    if (!isTransportCode(fields.failure_code) || usage !== null) {
      throw new TypeError('inconsistent holdout attempt failure');
    }
    return;
  }
  if (fields.failure_stage === 'parser' && fields.failure_code === 'parser_failure') return;
  throw new TypeError('inconsistent holdout attempt failure');
}

function assertVerdictConsistency(fields) {
  const rawValues = [
    fields.raw_decision,
    fields.raw_risk,
    fields.raw_authorization,
    fields.confidence,
    fields.rationale_sha256,
  ];
  if (!fields.schema_valid) {
    if (rawValues.some((value) => value !== null)) {
      throw new TypeError('inconsistent holdout attempt verdict');
    }
    return;
  }
  if (!DECISIONS.has(fields.raw_decision)
    || !RISKS.has(fields.raw_risk)
    || !AUTHORIZATIONS.has(fields.raw_authorization)
    || typeof fields.confidence !== 'number'
    || !Number.isFinite(fields.confidence)
    || fields.confidence < 0
    || fields.confidence > 1
    || typeof fields.rationale_sha256 !== 'string'
    || !HASH_PATTERN.test(fields.rationale_sha256)) {
    throw new TypeError('inconsistent holdout attempt verdict');
  }
  if (fields.normalized_kind === 'failure') {
    if (fields.failure_stage !== 'normalizer') {
      throw new TypeError('inconsistent holdout attempt verdict');
    }
    return;
  }
  if (fields.raw_decision === 'deny' && fields.normalized_kind !== 'deny') {
    throw new TypeError('inconsistent holdout attempt verdict');
  }
  if (fields.raw_decision === 'review' && fields.normalized_kind !== 'review') {
    throw new TypeError('inconsistent holdout attempt verdict');
  }
  if (fields.raw_decision === 'allow'
    && fields.normalized_kind !== 'allow'
    && fields.normalized_kind !== 'review') {
    throw new TypeError('inconsistent holdout attempt verdict');
  }
}

function assertOutcomeConsistency(fields) {
  if (fields.normalized_kind === 'allow') {
    if (fields.autonomous_outcome !== 'executed_without_human'
      || fields.supervised_outcome !== 'executed_without_human') {
      throw new TypeError('inconsistent holdout attempt outcome');
    }
    return;
  }
  if (fields.normalized_kind === 'deny') {
    if (fields.autonomous_outcome !== 'blocked'
      || fields.supervised_outcome !== 'blocked') {
      throw new TypeError('inconsistent holdout attempt outcome');
    }
    return;
  }
  if (fields.autonomous_outcome !== 'blocked'
    || fields.supervised_outcome !== 'sent_to_human') {
    throw new TypeError('inconsistent holdout attempt outcome');
  }
}

function snapshotBlindAttempt(value, { manifest, repeats }) {
  assertProxyFreeTree(value, 'holdout inference attempt');
  const fields = exactDataValues(value, ATTEMPT_KEYS, 'invalid holdout inference attempt');
  if (typeof fields.resume_key !== 'string' || !HASH_PATTERN.test(fields.resume_key)
    || fields.manifest_hash !== manifest.manifest_hash
    || fields.model !== manifest.model_id
    || fields.profile !== manifest.profile.name
    || typeof fields.evaluation_id !== 'string'
    || !EVALUATION_ID_PATTERN.test(fields.evaluation_id)
    || !Number.isInteger(fields.repeat)
    || fields.repeat < 1
    || fields.repeat > repeats
    || fields.resume_key !== makeResumeKey({
      manifest_hash: manifest.manifest_hash,
      model: manifest.model_id,
      profile: manifest.profile.name,
      case_id: fields.evaluation_id,
      repeat: fields.repeat,
    })
    || !NORMALIZED_KINDS.has(fields.normalized_kind)
    || typeof fields.schema_valid !== 'boolean'
    || typeof fields.latency_ms !== 'number'
    || !Number.isFinite(fields.latency_ms)
    || fields.latency_ms < 0) {
    throw new TypeError('invalid holdout inference attempt');
  }

  const usage = snapshotUsage(fields.usage);
  assertFailureConsistency(fields, usage);
  assertVerdictConsistency(fields);
  assertOutcomeConsistency(fields);

  return deepFreeze({
    resume_key: fields.resume_key,
    manifest_hash: fields.manifest_hash,
    model: fields.model,
    profile: fields.profile,
    evaluation_id: fields.evaluation_id,
    repeat: fields.repeat,
    raw_decision: fields.raw_decision,
    raw_risk: fields.raw_risk,
    raw_authorization: fields.raw_authorization,
    confidence: fields.confidence,
    normalized_kind: fields.normalized_kind,
    autonomous_outcome: fields.autonomous_outcome,
    supervised_outcome: fields.supervised_outcome,
    schema_valid: fields.schema_valid,
    failure_stage: fields.failure_stage,
    failure_code: fields.failure_code,
    latency_ms: fields.latency_ms,
    usage,
    rationale_sha256: fields.rationale_sha256,
  });
}

function snapshotAttemptBlocks(value, { manifest, repeats }) {
  assertProxyFreeTree(value, 'holdout inference attempts');
  const rawAttempts = denseArrayValues(value, 'invalid holdout inference attempts', {
    nonEmpty: true,
  });
  if (rawAttempts.length % repeats !== 0) {
    throw new TypeError('incomplete holdout inference tuples');
  }
  const attempts = rawAttempts.map((attempt) => snapshotBlindAttempt(attempt, {
    manifest,
    repeats,
  }));
  const seenEvaluationIds = new Set();
  for (let offset = 0; offset < attempts.length; offset += repeats) {
    const evaluationId = attempts[offset].evaluation_id;
    if (seenEvaluationIds.has(evaluationId)) {
      throw new TypeError('duplicate holdout inference tuple');
    }
    seenEvaluationIds.add(evaluationId);
    for (let index = 0; index < repeats; index += 1) {
      const attempt = attempts[offset + index];
      if (attempt.evaluation_id !== evaluationId || attempt.repeat !== index + 1) {
        throw new TypeError('incomplete holdout inference tuples');
      }
    }
  }
  return Object.freeze(attempts);
}

export async function runHoldoutInference(options) {
  const fields = exactDataValues(options, RUN_OPTION_KEYS, 'invalid holdout inference options');
  const repeats = validateRepeats(fields.repeats);
  const concurrency = validateConcurrency(fields.concurrency);
  const { input, manifest } = snapshotInputAndManifest(fields.input, fields.manifest);

  const tuples = [];
  for (const inputCase of input.cases) {
    for (let repeat = 1; repeat <= repeats; repeat += 1) {
      tuples.push(Object.freeze({ inputCase, repeat }));
    }
  }

  const attempts = new Array(tuples.length);
  let cursor = 0;
  async function worker() {
    while (cursor < tuples.length) {
      const index = cursor;
      cursor += 1;
      const tuple = tuples[index];
      const attempt = await evaluateInferenceAttempt({
        reviewer: fields.reviewer,
        inputCase: tuple.inputCase,
        manifest,
        repeat: tuple.repeat,
      });
      const snapshot = snapshotInferenceAttempt(attempt, {
        inputCase: tuple.inputCase,
        manifest,
        repeat: tuple.repeat,
      });
      if (snapshot === null) throw new TypeError('invalid evaluated holdout inference attempt');
      attempts[index] = snapshot;
    }
  }

  const workerCount = Math.min(concurrency, tuples.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return Object.freeze(attempts);
}

export function buildHoldoutInferenceArtifact(options) {
  assertProxyFreeTree(options, 'holdout inference artifact options');
  const fields = exactDataValues(
    options,
    BUILD_OPTION_KEYS,
    'invalid holdout inference artifact options',
  );
  const repeats = validateRepeats(fields.repeats);
  const concurrency = validateConcurrency(fields.concurrency);
  const { input, manifest, inputSha256 } = snapshotInputAndManifest(
    fields.input,
    fields.manifest,
  );
  assertProxyFreeTree(fields.attempts, 'holdout inference attempts');
  const rawAttempts = denseArrayValues(
    fields.attempts,
    'invalid holdout inference attempts',
    { nonEmpty: true },
  );
  if (rawAttempts.length !== input.cases.length * repeats) {
    throw new TypeError('incomplete holdout inference attempts');
  }

  const attempts = [];
  let offset = 0;
  for (const inputCase of input.cases) {
    for (let repeat = 1; repeat <= repeats; repeat += 1) {
      const attempt = snapshotInferenceAttempt(rawAttempts[offset], {
        inputCase,
        manifest,
        repeat,
      });
      if (attempt === null) throw new TypeError('invalid holdout inference attempt');
      attempts.push(attempt);
      offset += 1;
    }
  }

  const payload = artifactPayload({
    holdoutId: input.holdout_id,
    inputSha256,
    manifest,
    repeats,
    concurrency,
    attempts: Object.freeze(attempts),
  });
  return validateHoldoutInferenceArtifact({
    ...payload,
    artifact_sha256: canonicalHash(payload),
  });
}

export function validateHoldoutInferenceArtifact(value) {
  assertProxyFreeTree(value, 'holdout inference artifact');
  const fields = exactDataValues(value, ARTIFACT_KEYS, 'invalid holdout inference artifact');
  if (fields.schema_version !== ARTIFACT_SCHEMA_VERSION
    || typeof fields.holdout_id !== 'string'
    || !IDENTIFIER_PATTERN.test(fields.holdout_id)
    || typeof fields.input_sha256 !== 'string'
    || !HASH_PATTERN.test(fields.input_sha256)
    || typeof fields.artifact_sha256 !== 'string'
    || !HASH_PATTERN.test(fields.artifact_sha256)) {
    throw new TypeError('invalid holdout inference artifact');
  }

  const manifest = snapshotAttemptManifest(fields.manifest);
  assertFixedProductionJudgeContract(manifest);
  if (manifest.corpus_sha256 !== fields.input_sha256) {
    throw new TypeError('holdout inference artifact input hash mismatch');
  }
  const repeats = validateRepeats(fields.repeats);
  const concurrency = validateConcurrency(fields.concurrency);
  const attempts = snapshotAttemptBlocks(fields.attempts, { manifest, repeats });
  const payload = artifactPayload({
    holdoutId: fields.holdout_id,
    inputSha256: fields.input_sha256,
    manifest,
    repeats,
    concurrency,
    attempts,
  });
  if (canonicalHash(payload) !== fields.artifact_sha256) {
    throw new TypeError('holdout inference artifact hash mismatch');
  }
  return deepFreeze({ ...payload, artifact_sha256: fields.artifact_sha256 });
}
