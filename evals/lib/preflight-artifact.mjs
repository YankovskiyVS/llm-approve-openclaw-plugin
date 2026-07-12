import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { normalizeVerdict } from '../../src/decision.js';
import { validateCandidatePlan } from './candidate-plan.mjs';
import { corpusHash, lintCorpus } from './corpus.mjs';

const OPTION_KEYS = Object.freeze(['plan', 'preflightCases']);
const TOP_KEYS = Object.freeze([
  'schema_version',
  'git_sha',
  'node_version',
  'openclaw_version',
  'plan_sha256',
  'corpus_sha256',
  'source_sha256',
  'profile',
  'execution',
  'candidates',
]);
const SOURCE_KEYS = Object.freeze([
  'action',
  'prompt',
  'decision',
  'redaction',
  'constants',
  'candidate_plan',
  'candidate_client',
  'candidate_response',
  'case_input',
  'case_schema',
  'corpus',
  'preflight',
]);
const PROFILE_KEYS = Object.freeze([
  'temperature',
  'max_tokens',
  'max_reasoning_tokens',
  'thinking',
  'response_format',
  'timeout_ms',
]);
const EXECUTION_KEYS = Object.freeze(['candidate_concurrency', 'anchors_per_candidate']);
const CANDIDATE_KEYS = Object.freeze([
  'candidate_id',
  'model_id',
  'endpoint_profile',
  'response_profile',
  'capability_status',
  'anchor_count',
  'transport_ok_count',
  'schema_valid_count',
  'oracle_match_count',
  'anchors',
]);
const ANCHOR_KEYS = Object.freeze([
  'case_id',
  'oracle_disposition',
  'transport_status',
  'schema_valid',
  'raw_verdict',
  'normalized_verdict',
  'oracle_match',
  'failure_code',
  'latency_ms',
  'usage',
  'rationale_sha256',
]);
const RAW_VERDICT_KEYS = Object.freeze([
  'decision',
  'risk',
  'authorization',
  'confidence',
]);
const NORMALIZED_VERDICT_KEYS = Object.freeze(['kind']);
const USAGE_KEYS = Object.freeze([
  'promptTokens',
  'completionTokens',
  'totalTokens',
  'reasoningTokens',
  'cachedPromptTokens',
]);
const ANCHOR_IDS = Object.freeze([
  'ms-c001-p01-allow',
  'ms-c001-p06-allow',
  'ms-c001-p01-block',
  'ms-c001-q04',
  'ms-c001-q08',
  'ms-c001-q06',
]);
const PROFILE = Object.freeze({
  temperature: 0,
  max_tokens: 256,
  max_reasoning_tokens: 0,
  thinking: false,
  response_format: 'json_object',
  timeout_ms: 5000,
});
const EXECUTION = Object.freeze({
  candidate_concurrency: 4,
  anchors_per_candidate: 'sequential',
});
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const GIT_PATTERN = /^[0-9a-f]{40}$/u;
const NODE_PATTERN = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const OPENCLAW_PATTERN = /^([0-9]{4})\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$/u;
const DECISIONS = new Set(['allow', 'review', 'deny']);
const RISKS = new Set(['low', 'medium', 'high', 'critical']);
const AUTHORIZATIONS = new Set(['unknown', 'low', 'medium', 'high']);
const NORMALIZED_KINDS = new Set(['allow', 'review', 'deny']);
const FAILURE_CODES = new Set([
  'invalid_configuration',
  'invalid_request',
  'invalid_response',
  'request_timed_out',
  'request_failed',
  'invalid_schema',
]);
const HTTP_FAILURE_PATTERN = /^http_[1-5][0-9]{2}$/u;

function invalidArtifact() {
  throw new TypeError('invalid preflight artifact');
}

function exactDataValues(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || types.isProxy(value)) invalidArtifact();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalidArtifact();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) {
    invalidArtifact();
  }
  const result = {};
  for (const key of expected) {
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      invalidArtifact();
    }
    result[key] = descriptor.value;
  }
  return result;
}

function exactArrayValues(value, expectedLength) {
  if (value === null || typeof value !== 'object' || types.isProxy(value)
    || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    invalidArtifact();
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== expectedLength + 1 || keys.some((key) => typeof key !== 'string')) {
    invalidArtifact();
  }
  const length = descriptors.length;
  if (!length || !Object.hasOwn(length, 'value') || length.value !== expectedLength) {
    invalidArtifact();
  }
  const result = [];
  for (let index = 0; index < expectedLength; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      invalidArtifact();
    }
    result.push(descriptor.value);
  }
  return result;
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

function validHash(value) {
  return typeof value === 'string' && HASH_PATTERN.test(value);
}

function snapshotSourceHashes(value) {
  const fields = exactDataValues(value, SOURCE_KEYS);
  for (const key of SOURCE_KEYS) {
    if (!validHash(fields[key])) invalidArtifact();
  }
  return fields;
}

function validateNodeVersion(value) {
  if (typeof value !== 'string') invalidArtifact();
  const match = NODE_PATTERN.exec(value);
  if (match === null) invalidArtifact();
  const [major, minor, patch] = match.slice(1).map(Number);
  if (![major, minor, patch].every(Number.isSafeInteger)
    || major < 22 || (major === 22 && minor < 19)) invalidArtifact();
}

function daysInMonth(year, month) {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function validateOpenClawVersion(value) {
  if (typeof value !== 'string') invalidArtifact();
  const match = OPENCLAW_PATTERN.exec(value);
  if (match === null) invalidArtifact();
  const [year, month, day] = match.slice(1).map(Number);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)
    || year < 2026 || (year === 2026 && (month < 6 || (month === 6 && day < 11)))) {
    invalidArtifact();
  }
}

function snapshotProfile(value) {
  const fields = exactDataValues(value, PROFILE_KEYS);
  for (const key of PROFILE_KEYS) {
    if (!Object.is(fields[key], PROFILE[key])) invalidArtifact();
  }
  return fields;
}

function snapshotExecution(value) {
  const fields = exactDataValues(value, EXECUTION_KEYS);
  for (const key of EXECUTION_KEYS) {
    if (fields[key] !== EXECUTION[key]) invalidArtifact();
  }
  return fields;
}

function optionalUsageCount(value, maximum) {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) invalidArtifact();
  return value;
}

function snapshotUsage(value) {
  if (value === null) return null;
  const fields = exactDataValues(value, USAGE_KEYS);
  if (!Number.isSafeInteger(fields.promptTokens) || fields.promptTokens < 0
    || !Number.isSafeInteger(fields.completionTokens) || fields.completionTokens < 0
    || !Number.isSafeInteger(fields.totalTokens) || fields.totalTokens < 0
    || fields.promptTokens + fields.completionTokens !== fields.totalTokens) {
    invalidArtifact();
  }
  return {
    promptTokens: fields.promptTokens,
    completionTokens: fields.completionTokens,
    totalTokens: fields.totalTokens,
    reasoningTokens: optionalUsageCount(fields.reasoningTokens, fields.completionTokens),
    cachedPromptTokens: optionalUsageCount(fields.cachedPromptTokens, fields.promptTokens),
  };
}

function snapshotRawVerdict(value) {
  const fields = exactDataValues(value, RAW_VERDICT_KEYS);
  if (typeof fields.decision !== 'string' || !DECISIONS.has(fields.decision)
    || typeof fields.risk !== 'string' || !RISKS.has(fields.risk)
    || typeof fields.authorization !== 'string' || !AUTHORIZATIONS.has(fields.authorization)
    || typeof fields.confidence !== 'number' || !Number.isFinite(fields.confidence)
    || fields.confidence < 0 || fields.confidence > 1) invalidArtifact();
  return fields;
}

function snapshotNormalizedVerdict(value, rawVerdict) {
  const fields = exactDataValues(value, NORMALIZED_VERDICT_KEYS);
  if (typeof fields.kind !== 'string' || !NORMALIZED_KINDS.has(fields.kind)) {
    invalidArtifact();
  }
  const expected = normalizeVerdict({ ...rawVerdict, rationale: 'validated' });
  if (fields.kind !== expected.kind) invalidArtifact();
  return fields;
}

function validFailureCode(value) {
  return typeof value === 'string'
    && (FAILURE_CODES.has(value) || HTTP_FAILURE_PATTERN.test(value));
}

function snapshotValidAnchor(fields, caseData) {
  if (fields.transport_status !== 'ok' || fields.failure_code !== null
    || !validHash(fields.rationale_sha256)) invalidArtifact();
  const rawVerdict = snapshotRawVerdict(fields.raw_verdict);
  const normalizedVerdict = snapshotNormalizedVerdict(fields.normalized_verdict, rawVerdict);
  const oracleMatch = rawVerdict.decision === caseData.preferred_disposition;
  if (fields.oracle_match !== oracleMatch) invalidArtifact();
  return {
    rawVerdict,
    normalizedVerdict,
    oracleMatch,
    failureCode: null,
    rationaleSha256: fields.rationale_sha256,
  };
}

function snapshotFailedAnchor(fields) {
  if (fields.raw_verdict !== null || fields.normalized_verdict !== null
    || fields.oracle_match !== false || fields.rationale_sha256 !== null
    || !validFailureCode(fields.failure_code)) invalidArtifact();
  const responseReached = fields.failure_code === 'invalid_response'
    || fields.failure_code === 'invalid_schema';
  if (fields.transport_status !== (responseReached ? 'ok' : 'failure')) invalidArtifact();
  return {
    rawVerdict: null,
    normalizedVerdict: null,
    oracleMatch: false,
    failureCode: fields.failure_code,
    rationaleSha256: null,
  };
}

function snapshotAnchor(value, caseData) {
  const fields = exactDataValues(value, ANCHOR_KEYS);
  if (fields.case_id !== caseData.id
    || fields.oracle_disposition !== caseData.preferred_disposition
    || typeof fields.schema_valid !== 'boolean'
    || typeof fields.oracle_match !== 'boolean'
    || typeof fields.latency_ms !== 'number'
    || !Number.isFinite(fields.latency_ms)
    || fields.latency_ms < 0) invalidArtifact();

  const state = fields.schema_valid
    ? snapshotValidAnchor(fields, caseData)
    : snapshotFailedAnchor(fields);
  const usage = snapshotUsage(fields.usage);
  if (!fields.schema_valid && fields.failure_code !== 'invalid_schema' && usage !== null) {
    invalidArtifact();
  }
  return {
    case_id: fields.case_id,
    oracle_disposition: fields.oracle_disposition,
    transport_status: fields.transport_status,
    schema_valid: fields.schema_valid,
    raw_verdict: state.rawVerdict,
    normalized_verdict: state.normalizedVerdict,
    oracle_match: state.oracleMatch,
    failure_code: state.failureCode,
    latency_ms: fields.latency_ms,
    usage,
    rationale_sha256: state.rationaleSha256,
  };
}

function snapshotCount(value, expected) {
  if (!Number.isSafeInteger(value) || value !== expected) invalidArtifact();
  return value;
}

function snapshotCandidate(value, candidate, cases) {
  const fields = exactDataValues(value, CANDIDATE_KEYS);
  if (fields.candidate_id !== candidate.id
    || fields.model_id !== candidate.model_id
    || fields.endpoint_profile !== candidate.endpoint_profile
    || fields.response_profile !== candidate.response_profile
    || (fields.capability_status !== 'pass' && fields.capability_status !== 'fail')) {
    invalidArtifact();
  }
  const rawAnchors = exactArrayValues(fields.anchors, cases.length);
  const anchors = rawAnchors.map((anchor, index) => snapshotAnchor(anchor, cases[index]));
  const transportOkCount = anchors.filter((anchor) => anchor.transport_status === 'ok').length;
  const schemaValidCount = anchors.filter((anchor) => anchor.schema_valid).length;
  const oracleMatchCount = anchors.filter((anchor) => anchor.oracle_match).length;
  const status = transportOkCount === cases.length && schemaValidCount === cases.length
    ? 'pass'
    : 'fail';
  if (fields.capability_status !== status) invalidArtifact();
  return {
    candidate_id: fields.candidate_id,
    model_id: fields.model_id,
    endpoint_profile: fields.endpoint_profile,
    response_profile: fields.response_profile,
    capability_status: fields.capability_status,
    anchor_count: snapshotCount(fields.anchor_count, cases.length),
    transport_ok_count: snapshotCount(fields.transport_ok_count, transportOkCount),
    schema_valid_count: snapshotCount(fields.schema_valid_count, schemaValidCount),
    oracle_match_count: snapshotCount(fields.oracle_match_count, oracleMatchCount),
    anchors,
  };
}

function snapshotContext(options) {
  const fields = exactDataValues(options, OPTION_KEYS);
  let plan;
  let cases;
  try {
    plan = validateCandidatePlan(fields.plan);
    cases = lintCorpus(fields.preflightCases);
  } catch {
    invalidArtifact();
  }
  if (cases.length !== ANCHOR_IDS.length
    || cases.some((item, index) => item.id !== ANCHOR_IDS[index]
      || item.split !== 'model-selection')) invalidArtifact();
  return { plan, cases };
}

function validateArtifact(value, options) {
  const context = snapshotContext(options);
  const fields = exactDataValues(value, TOP_KEYS);
  if (fields.schema_version !== 'judge-candidate-preflight.v1'
    || typeof fields.git_sha !== 'string' || !GIT_PATTERN.test(fields.git_sha)) {
    invalidArtifact();
  }
  validateNodeVersion(fields.node_version);
  validateOpenClawVersion(fields.openclaw_version);
  if (fields.plan_sha256 !== hashCanonical(context.plan)
    || fields.corpus_sha256 !== corpusHash(context.cases)) invalidArtifact();

  const sourceSha256 = snapshotSourceHashes(fields.source_sha256);
  const profile = snapshotProfile(fields.profile);
  const execution = snapshotExecution(fields.execution);
  const rawCandidates = exactArrayValues(fields.candidates, context.plan.candidates.length);
  const candidates = rawCandidates.map((candidate, index) => snapshotCandidate(
    candidate,
    context.plan.candidates[index],
    context.cases,
  ));
  const base = {
    schema_version: fields.schema_version,
    git_sha: fields.git_sha,
    node_version: fields.node_version,
    openclaw_version: fields.openclaw_version,
    plan_sha256: fields.plan_sha256,
    corpus_sha256: fields.corpus_sha256,
    source_sha256: sourceSha256,
    profile,
    execution,
    candidates,
  };
  const eligibleCandidateIds = candidates
    .filter((candidate) => candidate.capability_status === 'pass')
    .map((candidate) => candidate.candidate_id);
  return deepFreeze({
    ...base,
    eligibleCandidateIds,
    artifactSha256: hashCanonical(base),
  });
}

export function validatePreflightArtifact(value, options) {
  try {
    return validateArtifact(value, options);
  } catch {
    invalidArtifact();
  }
}
