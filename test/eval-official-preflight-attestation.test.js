import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalStringify } from '../src/action.js';
import { POLICY_VERSION } from '../src/constants.js';
import { CANDIDATE_PLAN_URL } from '../evals/lib/candidate-plan.mjs';
import { runCandidatePreflight } from '../evals/lib/candidate-preflight.mjs';
import { validatePreflightArtifact } from '../evals/lib/preflight-artifact.mjs';
import {
  validateOfficialPreflightArtifact,
  validateOfficialPreflightAttestation,
} from '../evals/lib/official-preflight-attestation.mjs';

const PREFLIGHT_URL = new URL(
  '../evals/corpus-v2/frozen/model-selection-preflight.json',
  import.meta.url,
);
const OFFICIAL_ATTESTATION_URL = new URL(
  '../evals/candidates/official-preflight.json',
  import.meta.url,
);
const PLAN = JSON.parse(readFileSync(CANDIDATE_PLAN_URL, 'utf8'));
const PREFLIGHT_CASES = JSON.parse(readFileSync(PREFLIGHT_URL, 'utf8'));
const HASH = `sha256:${'a'.repeat(64)}`;
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
const OFFICIAL_ELIGIBLE_IDS = Object.freeze([
  'zai-org/GLM-4.7',
  'Qwen/Qwen3.6-35B-A3B',
  'Qwen/Qwen3.5-397B-A17B',
  'Qwen/Qwen3-Coder-Next',
  'qwen36-27b-fp8',
  'deepseek-ai/DeepSeek-V4-Pro',
]);
const OFFICIAL_SOURCE_HASHES = Object.freeze({
  action: 'sha256:cf034c0e2acbc1b0186b8f0cfb894c121d6bd6b3d54e81fd00705013bee03fd4',
  candidate_client: 'sha256:151e123741030e9e24d3d993f26defd1f9b9907c784d5b553498df936a01979c',
  candidate_plan: 'sha256:b3ce5262805b877e3521a33372ed7e832f879b59cbf226ca593aeb30f2900393',
  candidate_response: 'sha256:19e40a108a2d48576d5d08b1ad98cb525ca0269390a0c56767cd74aee28e7a0c',
  case_input: 'sha256:fdeaa290ad1274c54353bc78c8a8015b6109fe596ab09e3d11c6fdc562eca6af',
  case_schema: 'sha256:c2be80869f788552c554271bb75c44d13e7344ef034fd1a3bec3988e434ec1fb',
  constants: 'sha256:ca1d7aabaae345c6a3c5de8423c78816bf4f451f1bbeaf0461a5a8ec03050b6b',
  corpus: 'sha256:f909f5b963cd61c89c131da8aae3fa0d5758ff085a2edc6c802ebaf7d502e321',
  decision: 'sha256:6680c587e2c4be777268fbc6bb86e442b6779ddafca5f91ead4a298118ed3773',
  preflight: 'sha256:75c06c759e5ae9a898090af722fce5424524dd3681910be32226d378d0a109ac',
  prompt: 'sha256:0fb20595c2b1748bcfadff5e9ec537740192378c7db9db90606c74da2bb280ca',
  redaction: 'sha256:5a038bc133617df1eb281c4294fe40947acea3174ec8c2f807ab9440e229cd6f',
});
const EXPECTED_OFFICIAL_ATTESTATION = Object.freeze({
  schema_version: 'judge-official-preflight.v1',
  artifact_sha256: 'sha256:639788d221fe9836c96bc210a4331fdd2997a60b4495402f179dfc0639efd204',
  artifact_canonical_sha256: 'sha256:6a305e7e969f7c9d0c89549ff36847c06a5b844de862ffec7d7f877d573b65a4',
  git_sha: '4a2bdd42bddb26fa543c63c3e309561797bd7d9b',
  node_version: 'v25.8.0',
  openclaw_version: '2026.6.11',
  plan_sha256: 'sha256:c296695a602d7bf75cf67e1037c40c4743cd8d0d62ce3029a69502f0bb770d51',
  corpus_sha256: 'sha256:832d1d985b69185713783fa32b2cb116efc7d0da3219ad3d07012fa972b9a498',
  source_sha256: OFFICIAL_SOURCE_HASHES,
  eligible_candidate_ids: OFFICIAL_ELIGIBLE_IDS,
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function hashBytes(value) {
  return 'sha256:' + createHash('sha256').update(value).digest('hex');
}

function hashCanonical(value) {
  return hashBytes(canonicalStringify(value));
}

function extractRequest(options) {
  const body = JSON.parse(options.body);
  const lines = body.messages[1].content.split('\n');
  const start = lines.indexOf('UNTRUSTED_ACTION_JSON_BEGIN');
  return { body, envelope: JSON.parse(lines[start + 1]) };
}

function fixtureFetch() {
  const eligible = new Set(OFFICIAL_ELIGIBLE_IDS);
  return async (_url, options) => {
    const { body, envelope } = extractRequest(options);
    if (!eligible.has(body.model)) {
      return { ok: false, status: 403, json: async () => ({}) };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        choices: [{
          finish_reason: 'stop',
          message: {
            content: JSON.stringify({
              policy_version: POLICY_VERSION,
              action_hash: envelope.action_hash,
              decision: 'deny',
              risk: 'critical',
              authorization: 'unknown',
              confidence: 0.75,
              rationale: 'Synthetic official-attestation fixture.',
            }),
          },
        }],
        usage: {
          prompt_tokens: 100,
          completion_tokens: 20,
          total_tokens: 120,
        },
      }),
    };
  };
}

const ARTIFACT_PROMISE = runCandidatePreflight({
  plan: PLAN,
  cases: PREFLIGHT_CASES,
  providerSecrets: {
    'cloudru-fm': 'official-attestation-fm-key',
    'qwen-vllm': 'official-attestation-vllm-key',
  },
  fetchImpl: fixtureFetch(),
  concurrency: 4,
  gitSha: 'b'.repeat(40),
  nodeVersion: 'v25.8.0',
  openclawVersion: '2026.6.11',
  sourceHashes: Object.fromEntries(SOURCE_KEYS.map((key) => [key, HASH])),
});

async function fixture() {
  const artifact = clone(await ARTIFACT_PROMISE);
  const artifactBytes = Buffer.from(JSON.stringify(artifact), 'utf8');
  const validated = validatePreflightArtifact(artifact, {
    plan: PLAN,
    preflightCases: PREFLIGHT_CASES,
  });
  const attestation = {
    schema_version: 'judge-official-preflight.v1',
    artifact_sha256: hashBytes(artifactBytes),
    artifact_canonical_sha256: validated.artifactSha256,
    git_sha: validated.git_sha,
    node_version: validated.node_version,
    openclaw_version: validated.openclaw_version,
    plan_sha256: validated.plan_sha256,
    corpus_sha256: validated.corpus_sha256,
    source_sha256: clone(validated.source_sha256),
    eligible_candidate_ids: [...validated.eligibleCandidateIds],
  };
  return { artifact, artifactBytes, attestation, validated };
}

function validateArtifact(artifactBytes, attestation) {
  return validateOfficialPreflightArtifact(artifactBytes, {
    plan: PLAN,
    preflightCases: PREFLIGHT_CASES,
    attestation,
  });
}

function assertInvalidAttestation(value) {
  assert.throws(
    () => validateOfficialPreflightAttestation(value),
    { name: 'TypeError', message: 'invalid official preflight attestation' },
  );
}

function assertInvalidArtifact(bytes, attestation, options = {}) {
  assert.throws(
    () => validateOfficialPreflightArtifact(bytes, {
      plan: PLAN,
      preflightCases: PREFLIGHT_CASES,
      attestation,
      ...options,
    }),
    { name: 'TypeError', message: 'invalid official preflight artifact' },
  );
}

test('tracked attestation contains the exact official byte, canonical and provenance bindings', () => {
  const source = JSON.parse(readFileSync(OFFICIAL_ATTESTATION_URL, 'utf8'));
  assert.deepEqual(source, EXPECTED_OFFICIAL_ATTESTATION);

  const validated = validateOfficialPreflightAttestation(source);
  const { attestationSha256, ...base } = validated;
  assert.deepEqual(base, EXPECTED_OFFICIAL_ATTESTATION);
  assert.equal(attestationSha256, hashCanonical(EXPECTED_OFFICIAL_ATTESTATION));
  assert.equal(Object.isFrozen(validated), true);
  assert.equal(Object.isFrozen(validated.source_sha256), true);
  assert.equal(Object.isFrozen(validated.eligible_candidate_ids), true);

  source.source_sha256.action = HASH;
  source.eligible_candidate_ids.reverse();
  assert.deepEqual(base, EXPECTED_OFFICIAL_ATTESTATION);
});

test('validates exact artifact bytes and independently binds the canonical artifact', async () => {
  const { artifactBytes, attestation, validated } = await fixture();
  const result = validateArtifact(artifactBytes, attestation);

  assert.deepEqual(result.candidates, validated.candidates);
  assert.deepEqual(result.eligibleCandidateIds, OFFICIAL_ELIGIBLE_IDS);
  assert.equal(result.artifactSha256, validated.artifactSha256);
  assert.equal(result.artifactByteSha256, hashBytes(artifactBytes));
  assert.equal(
    result.officialAttestationSha256,
    hashCanonical(attestation),
  );
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.candidates), true);
});

test('attestation loader hashes valid mutations and rejects invalid, missing and extra fields', async () => {
  const { attestation } = await fixture();
  const mutations = [
    (value) => { value.artifact_sha256 = HASH; },
    (value) => { value.artifact_canonical_sha256 = HASH; },
    (value) => { value.git_sha = 'c'.repeat(40); },
    (value) => { value.node_version = 'v25.8.1'; },
    (value) => { value.openclaw_version = '2026.6.12'; },
    (value) => { value.plan_sha256 = `sha256:${'b'.repeat(64)}`; },
    (value) => { value.corpus_sha256 = `sha256:${'b'.repeat(64)}`; },
    (value) => { value.source_sha256.action = `sha256:${'b'.repeat(64)}`; },
    (value) => { value.eligible_candidate_ids[0] = 'unknown/model'; },
    (value) => {
      [value.eligible_candidate_ids[0], value.eligible_candidate_ids[1]] = [
        value.eligible_candidate_ids[1],
        value.eligible_candidate_ids[0],
      ];
    },
  ];
  for (const mutate of mutations) {
    const value = clone(attestation);
    mutate(value);
    const loaded = validateOfficialPreflightAttestation(value);
    assert.notEqual(loaded.attestationSha256, hashCanonical(attestation));
  }

  const wrongSchema = clone(attestation);
  wrongSchema.schema_version = 'judge-official-preflight.v2';
  assertInvalidAttestation(wrongSchema);

  const extra = clone(attestation);
  extra.api_key = 'secret-never-echo';
  assertInvalidAttestation(extra);

  const nestedExtra = clone(attestation);
  nestedExtra.source_sha256.token = HASH;
  assertInvalidAttestation(nestedExtra);

  const missing = clone(attestation);
  delete missing.artifact_sha256;
  assertInvalidAttestation(missing);

  const sparse = clone(attestation);
  delete sparse.eligible_candidate_ids[2];
  assertInvalidAttestation(sparse);
});

test('official artifact check rejects byte, semantic, provenance and eligibility mismatches', async () => {
  const { artifact, artifactBytes, attestation } = await fixture();

  assertInvalidArtifact(Buffer.concat([artifactBytes, Buffer.from('\n')]), attestation);

  const changedArtifact = clone(artifact);
  changedArtifact.git_sha = 'c'.repeat(40);
  const changedBytes = Buffer.from(JSON.stringify(changedArtifact), 'utf8');
  const changedByteAttestation = clone(attestation);
  changedByteAttestation.artifact_sha256 = hashBytes(changedBytes);
  assertInvalidArtifact(changedBytes, changedByteAttestation);

  for (const mutate of [
    (value) => { value.artifact_canonical_sha256 = HASH; },
    (value) => { value.git_sha = 'c'.repeat(40); },
    (value) => { value.source_sha256.action = `sha256:${'b'.repeat(64)}`; },
    (value) => { value.eligible_candidate_ids.reverse(); },
  ]) {
    const changed = clone(attestation);
    mutate(changed);
    assertInvalidArtifact(artifactBytes, changed);
  }

  assertInvalidArtifact(Buffer.from('{"broken":', 'utf8'), attestation);
  assertInvalidArtifact(new Uint8Array(artifactBytes), attestation);
});

test('rejects hostile proxies, accessors and non-exact options without reading traps', async () => {
  const { artifactBytes, attestation } = await fixture();
  let traps = 0;
  const hostile = new Proxy({}, {
    getPrototypeOf() {
      traps += 1;
      throw new Error('secret-never-echo');
    },
    ownKeys() {
      traps += 1;
      throw new Error('secret-never-echo');
    },
    getOwnPropertyDescriptor() {
      traps += 1;
      throw new Error('secret-never-echo');
    },
  });
  assertInvalidAttestation(hostile);
  assert.equal(traps, 0);

  const accessor = clone(attestation);
  Object.defineProperty(accessor, 'artifact_sha256', {
    enumerable: true,
    get() {
      traps += 1;
      throw new Error('secret-never-echo');
    },
  });
  assertInvalidAttestation(accessor);
  assert.equal(traps, 0);

  assertInvalidArtifact(new Proxy(artifactBytes, hostile), attestation);
  assert.equal(traps, 0);

  assertInvalidArtifact(artifactBytes, attestation, { extra: true });
  assert.throws(
    () => validateOfficialPreflightArtifact(artifactBytes, hostile),
    { name: 'TypeError', message: 'invalid official preflight artifact' },
  );
  assert.equal(traps, 0);
});
