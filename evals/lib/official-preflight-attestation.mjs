import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { TextDecoder, types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { validatePreflightArtifact } from './preflight-artifact.mjs';

const TOP_KEYS = Object.freeze([
  'schema_version',
  'artifact_sha256',
  'artifact_canonical_sha256',
  'git_sha',
  'node_version',
  'openclaw_version',
  'plan_sha256',
  'corpus_sha256',
  'source_sha256',
  'eligible_candidate_ids',
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
const OPTION_KEYS = Object.freeze(['plan', 'preflightCases', 'attestation']);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const GIT_PATTERN = /^[0-9a-f]{40}$/u;
const NODE_PATTERN = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const OPENCLAW_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const CANDIDATE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u;
const ELIGIBLE_CANDIDATE_COUNT = 6;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

function invalidAttestation() {
  throw new TypeError('invalid official preflight attestation');
}

function invalidArtifact() {
  throw new TypeError('invalid official preflight artifact');
}

function exactDataValues(value, expected, invalid) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || types.isProxy(value)) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) {
    invalid();
  }
  const result = {};
  for (const key of expected) {
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      invalid();
    }
    result[key] = descriptor.value;
  }
  return result;
}

function exactArrayValues(value, expectedLength, invalid) {
  if (value === null || typeof value !== 'object' || types.isProxy(value)
    || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    invalid();
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== expectedLength + 1 || keys.some((key) => typeof key !== 'string')) {
    invalid();
  }
  const length = descriptors.length;
  if (!length || !Object.hasOwn(length, 'value') || length.value !== expectedLength) {
    invalid();
  }
  const result = [];
  for (let index = 0; index < expectedLength; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      invalid();
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

function hashBytes(value) {
  return 'sha256:' + createHash('sha256').update(value).digest('hex');
}

function hashCanonical(value) {
  return hashBytes(canonicalStringify(value));
}

function validHash(value) {
  return typeof value === 'string' && HASH_PATTERN.test(value);
}

function snapshotSourceHashes(value) {
  const fields = exactDataValues(value, SOURCE_KEYS, invalidAttestation);
  for (const key of SOURCE_KEYS) {
    if (!validHash(fields[key])) invalidAttestation();
  }
  return fields;
}

function snapshotEligibleCandidateIds(value) {
  const ids = exactArrayValues(value, ELIGIBLE_CANDIDATE_COUNT, invalidAttestation);
  if (ids.some((id) => typeof id !== 'string' || !CANDIDATE_ID_PATTERN.test(id))
    || new Set(ids).size !== ids.length) invalidAttestation();
  return ids;
}

function snapshotAttestation(value) {
  const fields = exactDataValues(value, TOP_KEYS, invalidAttestation);
  if (fields.schema_version !== 'judge-official-preflight.v1'
    || !validHash(fields.artifact_sha256)
    || !validHash(fields.artifact_canonical_sha256)
    || typeof fields.git_sha !== 'string' || !GIT_PATTERN.test(fields.git_sha)
    || typeof fields.node_version !== 'string' || !NODE_PATTERN.test(fields.node_version)
    || typeof fields.openclaw_version !== 'string'
    || !OPENCLAW_PATTERN.test(fields.openclaw_version)
    || !validHash(fields.plan_sha256)
    || !validHash(fields.corpus_sha256)) invalidAttestation();
  return {
    schema_version: fields.schema_version,
    artifact_sha256: fields.artifact_sha256,
    artifact_canonical_sha256: fields.artifact_canonical_sha256,
    git_sha: fields.git_sha,
    node_version: fields.node_version,
    openclaw_version: fields.openclaw_version,
    plan_sha256: fields.plan_sha256,
    corpus_sha256: fields.corpus_sha256,
    source_sha256: snapshotSourceHashes(fields.source_sha256),
    eligible_candidate_ids: snapshotEligibleCandidateIds(fields.eligible_candidate_ids),
  };
}

function snapshotArtifactBytes(value) {
  if (value === null || typeof value !== 'object' || types.isProxy(value)
    || !Buffer.isBuffer(value) || Object.getPrototypeOf(value) !== Buffer.prototype
    || value.length === 0 || value.length > MAX_ARTIFACT_BYTES) invalidArtifact();
  return Buffer.from(value);
}

function equalArrays(left, right) {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function assertAttestedArtifact(attestation, artifact, byteSha256) {
  if (attestation.artifact_sha256 !== byteSha256
    || attestation.artifact_canonical_sha256 !== artifact.artifactSha256
    || attestation.git_sha !== artifact.git_sha
    || attestation.node_version !== artifact.node_version
    || attestation.openclaw_version !== artifact.openclaw_version
    || attestation.plan_sha256 !== artifact.plan_sha256
    || attestation.corpus_sha256 !== artifact.corpus_sha256
    || canonicalStringify(attestation.source_sha256)
      !== canonicalStringify(artifact.source_sha256)
    || !equalArrays(attestation.eligible_candidate_ids, artifact.eligibleCandidateIds)) {
    invalidArtifact();
  }
}

export function validateOfficialPreflightAttestation(value) {
  try {
    const base = snapshotAttestation(value);
    return deepFreeze({
      ...base,
      attestationSha256: hashCanonical(base),
    });
  } catch {
    invalidAttestation();
  }
}

export function validateOfficialPreflightArtifact(artifactBytes, options) {
  try {
    const fields = exactDataValues(options, OPTION_KEYS, invalidArtifact);
    const attestation = validateOfficialPreflightAttestation(fields.attestation);
    const bytes = snapshotArtifactBytes(artifactBytes);
    const byteSha256 = hashBytes(bytes);
    const rawArtifact = JSON.parse(UTF8_DECODER.decode(bytes));
    const artifact = validatePreflightArtifact(rawArtifact, {
      plan: fields.plan,
      preflightCases: fields.preflightCases,
    });
    assertAttestedArtifact(attestation, artifact, byteSha256);
    return deepFreeze({
      ...artifact,
      artifactByteSha256: byteSha256,
      officialAttestationSha256: attestation.attestationSha256,
    });
  } catch {
    invalidArtifact();
  }
}
