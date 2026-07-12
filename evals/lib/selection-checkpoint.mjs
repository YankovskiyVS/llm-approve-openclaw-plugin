import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  realpath,
} from 'node:fs/promises';
import {
  basename,
  dirname,
  join,
  resolve,
} from 'node:path';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { POLICY_VERSION } from '../../src/constants.js';
import { aggregateQualification } from './aggregate.mjs';
import { corpusHash, lintCorpus } from './corpus.mjs';
import { toAggregatePricing } from './model-selection-pricing.mjs';

export const MAX_SELECTION_CHECKPOINT_BYTES = 16 * 1024 * 1024;

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const GIT_PATTERN = /^[0-9a-f]{40}$/u;
const NODE_PATTERN = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const OPENCLAW_PATTERN = /^(\d{4})\.(0|[1-9]\d?)\.(0|[1-9]\d?)$/u;
const CANDIDATE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:[/:][A-Za-z0-9][A-Za-z0-9._-]*)*$/u;
const SOURCE_KEY_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;
const PROFILE_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/u;
const ENDPOINT_PROFILE_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const RESPONSE_PROFILE_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const CANDIDATE_ID_MAX_LENGTH = 256;

const BUILD_BINDING_KEYS = Object.freeze([
  'officialPreflightArtifactSha256',
  'preflightSha256',
  'planSha256',
  'corpusSha256',
  'pricingSha256',
  'sourceSha256',
  'gitSha',
  'nodeVersion',
  'openclawVersion',
  'policyVersion',
  'profile',
  'execution',
]);
const BINDING_KEYS = Object.freeze([
  'official_preflight_artifact_sha256',
  'preflight_sha256',
  'plan_sha256',
  'corpus_sha256',
  'pricing_sha256',
  'source_sha256',
  'git_sha',
  'runtime_sha256',
  'profile_sha256',
]);
const PROFILE_KEYS = Object.freeze([
  'name',
  'temperature',
  'max_tokens',
  'max_reasoning_tokens',
  'thinking',
  'response_format',
  'timeout_ms',
]);
const EXECUTION_KEYS = Object.freeze([
  'candidate_concurrency',
  'cases_per_candidate',
  'repeats',
]);
const MANIFEST_KEYS = Object.freeze([
  'schema_version',
  'git_sha',
  'node_version',
  'openclaw_version',
  'policy_version',
  'candidate',
  'plan_sha256',
  'preflight_sha256',
  'corpus_sha256',
  'pricing_sha256',
  'source_sha256',
  'profile',
  'execution',
  'manifest_hash',
]);
const CANDIDATE_KEYS = Object.freeze([
  'id',
  'model_id',
  'endpoint_profile',
  'response_profile',
]);
const CANDIDATE_RESULT_KEYS = Object.freeze([
  'manifest',
  'attempts',
  'summary',
  'case_outcomes',
  'family_outcomes',
]);
const CHECKPOINT_KEYS = Object.freeze([
  'schema_version',
  'binding',
  'candidate_id',
  'candidate_result_sha256',
  'candidate_result',
  'checkpoint_sha256',
]);
const CREATE_KEYS = Object.freeze([
  'binding',
  'candidateResult',
  'pricing',
  'cases',
]);
const CANDIDATE_VALIDATION_KEYS = Object.freeze([
  'expectedManifest',
  'pricing',
  'cases',
]);
const CONTEXT_KEYS = Object.freeze([
  'expectedBinding',
  'pricing',
  'cases',
  'expectedCandidateId',
]);
const WRITE_KEYS = Object.freeze([
  'directory',
  'checkpoint',
  ...CONTEXT_KEYS,
]);
const READ_KEYS = Object.freeze([
  'directory',
  'candidateId',
  ...CONTEXT_KEYS,
]);
const FILE_WRITE_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0);
const FILE_READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);

function invalidCheckpoint() {
  throw new TypeError('invalid selection checkpoint');
}

function fixedIoError(operation) {
  throw new TypeError(`selection checkpoint ${operation} failed`);
}

function exactDataValues(value, expected) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalidCheckpoint();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalidCheckpoint();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) {
      invalidCheckpoint();
    }
    const result = {};
    for (const key of expected) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        invalidCheckpoint();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    invalidCheckpoint();
  }
}

function snapshotJson(value, ancestors = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) invalidCheckpoint();
    return value;
  }
  if (typeof value !== 'object' || types.isProxy(value) || ancestors.has(value)) {
    invalidCheckpoint();
  }
  const prototype = Object.getPrototypeOf(value);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (prototype !== Array.prototype) invalidCheckpoint();
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Reflect.ownKeys(descriptors).length !== value.length + 1) invalidCheckpoint();
      const result = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          invalidCheckpoint();
        }
        result.push(snapshotJson(descriptor.value, ancestors));
      }
      return result;
    }
    if (prototype !== Object.prototype && prototype !== null) invalidCheckpoint();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string')) invalidCheckpoint();
    const result = {};
    for (const key of keys.slice().sort()) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalidCheckpoint();
      result[key] = snapshotJson(descriptor.value, ancestors);
    }
    return result;
  } catch {
    invalidCheckpoint();
  } finally {
    ancestors.delete(value);
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
  try {
    return 'sha256:' + createHash('sha256')
      .update(canonicalStringify(value), 'utf8')
      .digest('hex');
  } catch {
    invalidCheckpoint();
  }
}

function validHash(value) {
  return typeof value === 'string' && HASH_PATTERN.test(value);
}

function validCandidateId(value) {
  return typeof value === 'string'
    && value.length <= CANDIDATE_ID_MAX_LENGTH
    && CANDIDATE_ID_PATTERN.test(value);
}

function snapshotSourceHashes(value) {
  const snapshot = snapshotJson(value);
  if (snapshot === null || Array.isArray(snapshot) || typeof snapshot !== 'object') {
    invalidCheckpoint();
  }
  const keys = Object.keys(snapshot);
  if (keys.length === 0 || keys.length > 64
    || keys.some((key) => !SOURCE_KEY_PATTERN.test(key) || !validHash(snapshot[key]))) {
    invalidCheckpoint();
  }
  return deepFreeze(Object.fromEntries(keys.sort().map((key) => [key, snapshot[key]])));
}

function validateNodeVersion(value) {
  const match = typeof value === 'string' ? NODE_PATTERN.exec(value) : null;
  if (match === null) invalidCheckpoint();
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (major < 22 || (major === 22 && minor < 19)) invalidCheckpoint();
  return value;
}

function validateOpenClawVersion(value) {
  const match = typeof value === 'string' ? OPENCLAW_PATTERN.exec(value) : null;
  if (match === null) invalidCheckpoint();
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day || year < 2026
    || (year === 2026 && (month < 6 || (month === 6 && day < 11)))) {
    invalidCheckpoint();
  }
  return value;
}

function snapshotProfile(value) {
  const fields = exactDataValues(value, PROFILE_KEYS);
  if (typeof fields.name !== 'string' || !PROFILE_NAME_PATTERN.test(fields.name)
    || typeof fields.temperature !== 'number' || !Number.isFinite(fields.temperature)
    || fields.temperature < 0 || fields.temperature > 2
    || !Number.isSafeInteger(fields.max_tokens) || fields.max_tokens < 1
    || !Number.isSafeInteger(fields.max_reasoning_tokens)
    || fields.max_reasoning_tokens < 0
    || typeof fields.thinking !== 'boolean'
    || fields.response_format !== 'json_object'
    || !Number.isSafeInteger(fields.timeout_ms) || fields.timeout_ms < 1) {
    invalidCheckpoint();
  }
  return deepFreeze({
    name: fields.name,
    temperature: fields.temperature,
    max_tokens: fields.max_tokens,
    max_reasoning_tokens: fields.max_reasoning_tokens,
    thinking: fields.thinking,
    response_format: fields.response_format,
    timeout_ms: fields.timeout_ms,
  });
}

function snapshotExecution(value) {
  const fields = exactDataValues(value, EXECUTION_KEYS);
  if (!Number.isSafeInteger(fields.candidate_concurrency)
    || fields.candidate_concurrency < 1 || fields.candidate_concurrency > 64
    || fields.cases_per_candidate !== 'sequential'
    || fields.repeats !== 1) invalidCheckpoint();
  return deepFreeze({
    candidate_concurrency: fields.candidate_concurrency,
    cases_per_candidate: fields.cases_per_candidate,
    repeats: fields.repeats,
  });
}

function snapshotBinding(value) {
  const fields = exactDataValues(value, BINDING_KEYS);
  const sourceSha256 = snapshotSourceHashes(fields.source_sha256);
  if (!validHash(fields.official_preflight_artifact_sha256)
    || !validHash(fields.preflight_sha256)
    || !validHash(fields.plan_sha256)
    || !validHash(fields.corpus_sha256)
    || !validHash(fields.pricing_sha256)
    || typeof fields.git_sha !== 'string' || !GIT_PATTERN.test(fields.git_sha)
    || !validHash(fields.runtime_sha256)
    || !validHash(fields.profile_sha256)) invalidCheckpoint();
  return deepFreeze({
    official_preflight_artifact_sha256: fields.official_preflight_artifact_sha256,
    preflight_sha256: fields.preflight_sha256,
    plan_sha256: fields.plan_sha256,
    corpus_sha256: fields.corpus_sha256,
    pricing_sha256: fields.pricing_sha256,
    source_sha256: sourceSha256,
    git_sha: fields.git_sha,
    runtime_sha256: fields.runtime_sha256,
    profile_sha256: fields.profile_sha256,
  });
}

function canonicalEqual(left, right) {
  return canonicalStringify(left) === canonicalStringify(right);
}

export function buildSelectionCheckpointBinding(input) {
  try {
    const fields = exactDataValues(input, BUILD_BINDING_KEYS);
    const hashes = [
      fields.officialPreflightArtifactSha256,
      fields.preflightSha256,
      fields.planSha256,
      fields.corpusSha256,
      fields.pricingSha256,
    ];
    if (hashes.some((hash) => !validHash(hash))
      || typeof fields.gitSha !== 'string' || !GIT_PATTERN.test(fields.gitSha)
      || fields.policyVersion !== POLICY_VERSION) invalidCheckpoint();
    const sourceSha256 = snapshotSourceHashes(fields.sourceSha256);
    const nodeVersion = validateNodeVersion(fields.nodeVersion);
    const openclawVersion = validateOpenClawVersion(fields.openclawVersion);
    const profile = snapshotProfile(fields.profile);
    const execution = snapshotExecution(fields.execution);
    return deepFreeze({
      official_preflight_artifact_sha256: fields.officialPreflightArtifactSha256,
      preflight_sha256: fields.preflightSha256,
      plan_sha256: fields.planSha256,
      corpus_sha256: fields.corpusSha256,
      pricing_sha256: fields.pricingSha256,
      source_sha256: sourceSha256,
      git_sha: fields.gitSha,
      runtime_sha256: hashCanonical({
        node_version: nodeVersion,
        openclaw_version: openclawVersion,
        policy_version: fields.policyVersion,
        execution,
      }),
      profile_sha256: hashCanonical(profile),
    });
  } catch {
    invalidCheckpoint();
  }
}

function snapshotCandidate(value) {
  const fields = exactDataValues(value, CANDIDATE_KEYS);
  if (!validCandidateId(fields.id) || !validCandidateId(fields.model_id)
    || typeof fields.endpoint_profile !== 'string'
    || !ENDPOINT_PROFILE_PATTERN.test(fields.endpoint_profile)
    || typeof fields.response_profile !== 'string'
    || !RESPONSE_PROFILE_PATTERN.test(fields.response_profile)) invalidCheckpoint();
  return deepFreeze({
    id: fields.id,
    model_id: fields.model_id,
    endpoint_profile: fields.endpoint_profile,
    response_profile: fields.response_profile,
  });
}

function snapshotManifest(value, binding = null) {
  const fields = exactDataValues(value, MANIFEST_KEYS);
  const candidate = snapshotCandidate(fields.candidate);
  const sourceSha256 = snapshotSourceHashes(fields.source_sha256);
  const profile = snapshotProfile(fields.profile);
  const execution = snapshotExecution(fields.execution);
  if (fields.schema_version !== 'judge-candidate-selection-run.v1'
    || typeof fields.git_sha !== 'string' || !GIT_PATTERN.test(fields.git_sha)
    || validateNodeVersion(fields.node_version) !== fields.node_version
    || validateOpenClawVersion(fields.openclaw_version) !== fields.openclaw_version
    || fields.policy_version !== POLICY_VERSION
    || !validHash(fields.plan_sha256)
    || !validHash(fields.preflight_sha256)
    || !validHash(fields.corpus_sha256)
    || !validHash(fields.pricing_sha256)
    || !validHash(fields.manifest_hash)) invalidCheckpoint();
  const content = {
    schema_version: fields.schema_version,
    git_sha: fields.git_sha,
    node_version: fields.node_version,
    openclaw_version: fields.openclaw_version,
    policy_version: fields.policy_version,
    candidate,
    plan_sha256: fields.plan_sha256,
    preflight_sha256: fields.preflight_sha256,
    corpus_sha256: fields.corpus_sha256,
    pricing_sha256: fields.pricing_sha256,
    source_sha256: sourceSha256,
    profile,
    execution,
  };
  if (hashCanonical(content) !== fields.manifest_hash) invalidCheckpoint();
  if (binding !== null && (fields.git_sha !== binding.git_sha
    || fields.plan_sha256 !== binding.plan_sha256
    || fields.preflight_sha256 !== binding.preflight_sha256
    || fields.corpus_sha256 !== binding.corpus_sha256
    || fields.pricing_sha256 !== binding.pricing_sha256
    || !canonicalEqual(sourceSha256, binding.source_sha256)
    || hashCanonical(profile) !== binding.profile_sha256
    || hashCanonical({
      node_version: fields.node_version,
      openclaw_version: fields.openclaw_version,
      policy_version: fields.policy_version,
      execution,
    }) !== binding.runtime_sha256)) invalidCheckpoint();
  return deepFreeze({ ...content, manifest_hash: fields.manifest_hash });
}

function snapshotCases(value, expectedHash) {
  try {
    const cases = lintCorpus(snapshotJson(value));
    if (cases.length === 0 || corpusHash(cases) !== expectedHash) invalidCheckpoint();
    return cases;
  } catch {
    invalidCheckpoint();
  }
}

function snapshotPricing(value, expectedHash) {
  let aggregatePricing;
  try {
    aggregatePricing = toAggregatePricing(value);
  } catch {
    invalidCheckpoint();
  }
  const pricing = snapshotJson(value);
  if (hashCanonical(pricing) !== expectedHash) invalidCheckpoint();
  return { raw: pricing, aggregate: aggregatePricing };
}

function validateAttemptCorpus(attempts, cases, manifest) {
  if (!Array.isArray(attempts) || attempts.length !== cases.length) invalidCheckpoint();
  for (let index = 0; index < cases.length; index += 1) {
    const attempt = attempts[index];
    const caseData = cases[index];
    if (attempt.manifest_hash !== manifest.manifest_hash
      || attempt.model !== manifest.candidate.model_id
      || attempt.profile !== manifest.profile.name
      || attempt.case_id !== caseData.id
      || attempt.family_id !== caseData.family_id
      || attempt.split !== caseData.split
      || attempt.repeat !== 1
      || attempt.oracle_disposition !== caseData.preferred_disposition
      || attempt.auto_allow_permitted !== caseData.auto_allow_permitted
      || attempt.oracle_risk !== caseData.intrinsic_risk
      || attempt.oracle_authorization !== caseData.authorization
      || attempt.impact_tier !== caseData.impact_tier
      || !canonicalEqual(attempt.tags, caseData.tags)) invalidCheckpoint();
  }
}

function snapshotCandidateResult(value, { expectedManifest, pricing, cases }) {
  const snapshot = snapshotJson(value);
  const fields = exactDataValues(snapshot, CANDIDATE_RESULT_KEYS);
  const manifest = snapshotManifest(fields.manifest);
  if (!canonicalEqual(manifest, expectedManifest)) invalidCheckpoint();
  const attempts = fields.attempts;
  validateAttemptCorpus(attempts, cases, manifest);
  let aggregate;
  try {
    aggregate = aggregateQualification({
      attempts,
      expectedRepeats: manifest.execution.repeats,
      pricing,
    });
  } catch {
    invalidCheckpoint();
  }
  if (!canonicalEqual(fields.summary, aggregate.summary)
    || !canonicalEqual(fields.case_outcomes, aggregate.caseOutcomes)
    || !canonicalEqual(fields.family_outcomes, aggregate.familyOutcomes)) {
    invalidCheckpoint();
  }
  return deepFreeze({
    manifest,
    attempts: deepFreeze(attempts),
    summary: deepFreeze(fields.summary),
    case_outcomes: deepFreeze(fields.case_outcomes),
    family_outcomes: deepFreeze(fields.family_outcomes),
  });
}

function snapshotContext(value) {
  const fields = exactDataValues(value, CONTEXT_KEYS);
  const expectedBinding = snapshotBinding(fields.expectedBinding);
  if (!validCandidateId(fields.expectedCandidateId)) invalidCheckpoint();
  const pricing = snapshotPricing(fields.pricing, expectedBinding.pricing_sha256);
  const cases = snapshotCases(fields.cases, expectedBinding.corpus_sha256);
  return {
    expectedBinding,
    pricing: pricing.aggregate,
    cases,
    expectedCandidateId: fields.expectedCandidateId,
  };
}

function createCheckpoint(binding, candidateResult) {
  const candidateId = candidateResult.manifest.candidate.id;
  const candidateResultSha256 = hashCanonical(candidateResult);
  const content = {
    schema_version: 'judge-candidate-selection-checkpoint.v1',
    binding,
    candidate_id: candidateId,
    candidate_result_sha256: candidateResultSha256,
    candidate_result: candidateResult,
  };
  return deepFreeze({
    ...content,
    checkpoint_sha256: hashCanonical(content),
  });
}

export function validateSelectionCandidateResult(value, options) {
  try {
    const fields = exactDataValues(options, CANDIDATE_VALIDATION_KEYS);
    const expectedManifest = snapshotManifest(fields.expectedManifest);
    const pricing = snapshotPricing(fields.pricing, expectedManifest.pricing_sha256);
    const cases = snapshotCases(fields.cases, expectedManifest.corpus_sha256);
    return snapshotCandidateResult(value, {
      expectedManifest,
      pricing: pricing.aggregate,
      cases,
    });
  } catch {
    throw new TypeError('invalid selection candidate result');
  }
}

export function createSelectionCheckpoint(options) {
  try {
    const fields = exactDataValues(options, CREATE_KEYS);
    const binding = snapshotBinding(fields.binding);
    const pricing = snapshotPricing(fields.pricing, binding.pricing_sha256);
    const cases = snapshotCases(fields.cases, binding.corpus_sha256);
    const source = snapshotJson(fields.candidateResult);
    const sourceFields = exactDataValues(source, CANDIDATE_RESULT_KEYS);
    const expectedManifest = snapshotManifest(sourceFields.manifest, binding);
    const candidateResult = snapshotCandidateResult(fields.candidateResult, {
      expectedManifest,
      pricing: pricing.aggregate,
      cases,
    });
    return createCheckpoint(binding, candidateResult);
  } catch {
    invalidCheckpoint();
  }
}

export function validateSelectionCheckpoint(value, context) {
  try {
    const checkedContext = snapshotContext(context);
    const snapshot = snapshotJson(value);
    const fields = exactDataValues(snapshot, CHECKPOINT_KEYS);
    const binding = snapshotBinding(fields.binding);
    if (fields.schema_version !== 'judge-candidate-selection-checkpoint.v1'
      || !canonicalEqual(binding, checkedContext.expectedBinding)
      || !validCandidateId(fields.candidate_id)
      || fields.candidate_id !== checkedContext.expectedCandidateId
      || !validHash(fields.candidate_result_sha256)
      || !validHash(fields.checkpoint_sha256)) invalidCheckpoint();
    const candidateResult = snapshotCandidateResult(fields.candidate_result, {
      expectedManifest: snapshotManifest(fields.candidate_result.manifest, binding),
      pricing: checkedContext.pricing,
      cases: checkedContext.cases,
    });
    if (candidateResult.manifest.candidate.id !== fields.candidate_id
      || hashCanonical(candidateResult) !== fields.candidate_result_sha256) {
      invalidCheckpoint();
    }
    const checkpoint = createCheckpoint(binding, candidateResult);
    if (checkpoint.candidate_result_sha256 !== fields.candidate_result_sha256
      || checkpoint.checkpoint_sha256 !== fields.checkpoint_sha256) invalidCheckpoint();
    return checkpoint;
  } catch {
    invalidCheckpoint();
  }
}

export function canonicalSelectionCheckpointBytes(checkpoint, context) {
  try {
    const validated = validateSelectionCheckpoint(checkpoint, context);
    const bytes = Buffer.from(canonicalStringify(validated) + '\n', 'utf8');
    if (bytes.length === 0 || bytes.length > MAX_SELECTION_CHECKPOINT_BYTES) {
      invalidCheckpoint();
    }
    return bytes;
  } catch {
    invalidCheckpoint();
  }
}

export function selectionCheckpointBasename(candidateId) {
  try {
    if (!validCandidateId(candidateId)) invalidCheckpoint();
    const digest = createHash('sha256')
      .update('openclaw-judge:candidate-selection-checkpoint:v1\0', 'utf8')
      .update(candidateId, 'utf8')
      .digest('hex');
    return `selection-checkpoint-${digest}.json`;
  } catch {
    invalidCheckpoint();
  }
}

async function secureDirectory(value) {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0')) {
    invalidCheckpoint();
  }
  const absolute = resolve(value);
  const stats = await lstat(absolute);
  if (!stats.isDirectory() || stats.isSymbolicLink()) invalidCheckpoint();
  return realpath(absolute);
}

function containedPath(directory, filename) {
  if (filename !== basename(filename)) invalidCheckpoint();
  const path = join(directory, filename);
  if (dirname(path) !== directory) invalidCheckpoint();
  return path;
}

export async function writeSelectionCheckpoint(options) {
  let handle;
  try {
    const fields = exactDataValues(options, WRITE_KEYS);
    const context = Object.fromEntries(CONTEXT_KEYS.map((key) => [key, fields[key]]));
    const checkpoint = validateSelectionCheckpoint(fields.checkpoint, context);
    const bytes = canonicalSelectionCheckpointBytes(checkpoint, context);
    const directory = await secureDirectory(fields.directory);
    const filename = selectionCheckpointBasename(checkpoint.candidate_id);
    const path = containedPath(directory, filename);
    handle = await open(path, FILE_WRITE_FLAGS, 0o600);
    await handle.chmod(0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    return deepFreeze({
      filename,
      checkpoint_sha256: checkpoint.checkpoint_sha256,
      byte_length: bytes.length,
    });
  } catch {
    if (handle !== undefined) await handle.close().catch(() => {});
    fixedIoError('write');
  }
}

async function readCheckpoint(options, optional) {
  let handle;
  try {
    const fields = exactDataValues(options, READ_KEYS);
    if (fields.candidateId !== fields.expectedCandidateId) invalidCheckpoint();
    const context = Object.fromEntries(CONTEXT_KEYS.map((key) => [key, fields[key]]));
    snapshotContext(context);
    const directory = await secureDirectory(fields.directory);
    const filename = selectionCheckpointBasename(fields.candidateId);
    const path = containedPath(directory, filename);
    try {
      handle = await open(path, FILE_READ_FLAGS);
    } catch (error) {
      if (optional && error?.code === 'ENOENT') return null;
      throw error;
    }
    const stats = await handle.stat();
    if (!stats.isFile() || stats.size < 1 || stats.size > MAX_SELECTION_CHECKPOINT_BYTES
      || (stats.mode & 0o777) !== 0o600) invalidCheckpoint();
    const bytes = await handle.readFile();
    if (bytes.length !== stats.size || bytes.length > MAX_SELECTION_CHECKPOINT_BYTES) {
      invalidCheckpoint();
    }
    await handle.close();
    handle = undefined;
    const parsed = JSON.parse(bytes.toString('utf8'));
    const checkpoint = validateSelectionCheckpoint(parsed, context);
    const canonical = canonicalSelectionCheckpointBytes(checkpoint, context);
    if (!bytes.equals(canonical)) invalidCheckpoint();
    return checkpoint;
  } catch {
    if (handle !== undefined) await handle.close().catch(() => {});
    fixedIoError('read');
  }
}

export async function readSelectionCheckpoint(options) {
  return readCheckpoint(options, false);
}

export async function readSelectionCheckpointIfPresent(options) {
  return readCheckpoint(options, true);
}
