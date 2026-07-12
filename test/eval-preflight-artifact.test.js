import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalStringify } from '../src/action.js';
import { POLICY_VERSION } from '../src/constants.js';
import { CANDIDATE_PLAN_URL } from '../evals/lib/candidate-plan.mjs';
import { runCandidatePreflight } from '../evals/lib/candidate-preflight.mjs';
import { validatePreflightArtifact } from '../evals/lib/preflight-artifact.mjs';

const PREFLIGHT_URL = new URL(
  '../evals/corpus-v2/frozen/model-selection-preflight.json',
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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function hashCanonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function extractRequest(options) {
  const body = JSON.parse(options.body);
  const lines = body.messages[1].content.split('\n');
  const start = lines.indexOf('UNTRUSTED_ACTION_JSON_BEGIN');
  return { body, envelope: JSON.parse(lines[start + 1]) };
}

function fixtureFetch() {
  const calls = new Map();
  const failedModel = PLAN.candidates[1].model_id;
  return async (_url, options) => {
    const { body, envelope } = extractRequest(options);
    const count = (calls.get(body.model) ?? 0) + 1;
    calls.set(body.model, count);
    if (body.model === failedModel && count === 1) {
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
              rationale: 'Synthetic validator fixture.',
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
    'cloudru-fm': 'artifact-validator-fm-key',
    'qwen-vllm': 'artifact-validator-vllm-key',
  },
  fetchImpl: fixtureFetch(),
  concurrency: 4,
  gitSha: 'b'.repeat(40),
  nodeVersion: 'v25.8.0',
  openclawVersion: '2026.6.11',
  sourceHashes: Object.fromEntries(SOURCE_KEYS.map((key) => [key, HASH])),
});

function validate(value, options = {}) {
  return validatePreflightArtifact(value, {
    plan: PLAN,
    preflightCases: PREFLIGHT_CASES,
    ...options,
  });
}

function assertInvalid(value, options) {
  let caught;
  try {
    validatePreflightArtifact(value, options ?? {
      plan: PLAN,
      preflightCases: PREFLIGHT_CASES,
    });
  } catch (error) {
    caught = error;
  }
  assert.equal(caught instanceof TypeError, true);
  assert.equal(caught?.message, 'invalid preflight artifact');
}

test('validates a runner artifact and derives stable frozen eligibility and artifact hash', async () => {
  const source = clone(await ARTIFACT_PROMISE);
  const expectedEligible = PLAN.candidates
    .filter((_, index) => index !== 1)
    .map((candidate) => candidate.id);

  const result = validate(source);
  const {
    eligibleCandidateIds,
    artifactSha256,
    ...validatedBase
  } = result;

  assert.deepEqual(Object.keys(validatedBase), TOP_KEYS);
  assert.deepEqual(validatedBase, source);
  assert.deepEqual(eligibleCandidateIds, expectedEligible);
  assert.equal(artifactSha256, hashCanonical(source));
  assert.match(artifactSha256, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(result === source, false);
  assert.equal(result.candidates === source.candidates, false);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.source_sha256), true);
  assert.equal(Object.isFrozen(result.candidates), true);
  assert.equal(Object.isFrozen(result.candidates[0]), true);
  assert.equal(Object.isFrozen(result.candidates[0].anchors[0]), true);
  assert.equal(Object.isFrozen(result.candidates[0].anchors[0].raw_verdict), true);
  assert.equal(Object.isFrozen(result.candidates[0].anchors[0].usage), true);
  assert.equal(Object.isFrozen(result.eligibleCandidateIds), true);

  source.git_sha = 'c'.repeat(40);
  source.candidates[0].anchors[0].raw_verdict.decision = 'allow';
  assert.equal(result.git_sha, 'b'.repeat(40));
  assert.equal(result.candidates[0].anchors[0].raw_verdict.decision, 'deny');

  const reordered = Object.fromEntries(Object.entries(clone(await ARTIFACT_PROMISE)).reverse());
  assert.equal(validate(reordered).artifactSha256, artifactSha256);
});

test('binds canonical plan, corpus, exact candidate and anchor order', async () => {
  const mutations = [
    (value) => { value.plan_sha256 = HASH; },
    (value) => { value.corpus_sha256 = HASH; },
    (value) => { [value.candidates[0], value.candidates[1]] = [value.candidates[1], value.candidates[0]]; },
    (value) => { value.candidates[0].candidate_id = 'unknown/model'; },
    (value) => { value.candidates[0].model_id = 'unknown/model'; },
    (value) => { value.candidates[0].endpoint_profile = 'qwen-vllm'; },
    (value) => { value.candidates[0].response_profile = 'vllm-reasoning-final'; },
    (value) => {
      [value.candidates[0].anchors[0], value.candidates[0].anchors[1]] = [
        value.candidates[0].anchors[1], value.candidates[0].anchors[0],
      ];
    },
    (value) => { value.candidates[0].anchors[0].case_id = 'unknown-case'; },
    (value) => { value.candidates[0].anchors[0].oracle_disposition = 'review'; },
  ];
  for (const mutate of mutations) {
    const value = clone(await ARTIFACT_PROMISE);
    mutate(value);
    assertInvalid(value);
  }
});

test('recomputes candidate counts, status, oracle match and execution profile', async () => {
  const mutations = [
    (value) => { value.profile.temperature = 0.1; },
    (value) => { value.profile.max_tokens = 512; },
    (value) => { value.execution.candidate_concurrency = 3; },
    (value) => { value.execution.anchors_per_candidate = 'parallel'; },
    (value) => { value.candidates[0].anchor_count = 5; },
    (value) => { value.candidates[0].transport_ok_count = 5; },
    (value) => { value.candidates[0].schema_valid_count = 5; },
    (value) => { value.candidates[0].oracle_match_count += 1; },
    (value) => { value.candidates[0].capability_status = 'fail'; },
    (value) => { value.candidates[1].capability_status = 'pass'; },
    (value) => { value.candidates[0].anchors[0].oracle_match = true; },
  ];
  for (const mutate of mutations) {
    const value = clone(await ARTIFACT_PROMISE);
    mutate(value);
    assertInvalid(value);
  }
});

test('enforces runtime, hash, verdict, failure, latency and usage grammars', async () => {
  const mutations = [
    (value) => { value.schema_version = 'judge-candidate-preflight.v2'; },
    (value) => { value.git_sha = '/Users/private/repo'; },
    (value) => { value.git_sha = 'B'.repeat(40); },
    (value) => { value.node_version = 'v22.18.9'; },
    (value) => { value.node_version = 'v25.8'; },
    (value) => { value.openclaw_version = '2026.6.10'; },
    (value) => { value.openclaw_version = '2026.2.30'; },
    (value) => { value.source_sha256.action = `sha256:${'A'.repeat(64)}`; },
    (value) => { value.candidates[0].anchors[0].raw_verdict.decision = 'ask'; },
    (value) => { value.candidates[0].anchors[0].raw_verdict.risk = 'severe'; },
    (value) => { value.candidates[0].anchors[0].raw_verdict.authorization = 'explicit'; },
    (value) => { value.candidates[0].anchors[0].raw_verdict.confidence = 2; },
    (value) => { value.candidates[0].anchors[0].normalized_verdict.kind = 'allow'; },
    (value) => { value.candidates[0].anchors[0].rationale_sha256 = 'https://secret.invalid'; },
    (value) => { value.candidates[0].anchors[0].latency_ms = -1; },
    (value) => { value.candidates[0].anchors[0].usage.totalTokens = 999; },
    (value) => { value.candidates[0].anchors[0].usage.reasoningTokens = 21; },
    (value) => { value.candidates[1].anchors[0].failure_code = '/workspace/private'; },
    (value) => { value.candidates[1].anchors[0].transport_status = 'ok'; },
    (value) => { value.candidates[1].anchors[0].schema_valid = true; },
    (value) => { value.candidates[1].anchors[0].raw_verdict = { decision: 'deny' }; },
  ];
  for (const mutate of mutations) {
    const value = clone(await ARTIFACT_PROMISE);
    mutate(value);
    assertInvalid(value);
  }

  const nonFinite = clone(await ARTIFACT_PROMISE);
  nonFinite.candidates[0].anchors[0].latency_ms = Number.NaN;
  assertInvalid(nonFinite);
});

test('rejects every extra, missing, secret-like, URL and local-path field', async () => {
  const additions = [
    (value) => { value.apiKey = 'secret-never-echo'; },
    (value) => { value.endpoint_url = 'https://secret.invalid'; },
    (value) => { value.workspace_path = '/Users/private/repo'; },
    (value) => { value.source_sha256.token = HASH; },
    (value) => { value.profile.url = 'https://secret.invalid'; },
    (value) => { value.execution.secret = 'secret-never-echo'; },
    (value) => { value.candidates[0].api_key = 'secret-never-echo'; },
    (value) => { value.candidates[0].anchors[0].raw_verdict.rationale = 'raw text'; },
    (value) => { value.candidates[0].anchors[0].normalized_verdict.reason = 'raw text'; },
    (value) => { value.candidates[0].anchors[0].usage.reasoning_content = 'raw reasoning'; },
  ];
  for (const mutate of additions) {
    const value = clone(await ARTIFACT_PROMISE);
    mutate(value);
    assertInvalid(value);
  }

  for (const remove of [
    (value) => { delete value.git_sha; },
    (value) => { delete value.source_sha256.action; },
    (value) => { delete value.profile.thinking; },
    (value) => { delete value.execution.anchors_per_candidate; },
    (value) => { delete value.candidates[0].model_id; },
    (value) => { delete value.candidates[0].anchors[0].schema_valid; },
    (value) => { delete value.candidates[0].anchors[0].raw_verdict.risk; },
    (value) => { delete value.candidates[0].anchors[0].usage.totalTokens; },
  ]) {
    const value = clone(await ARTIFACT_PROMISE);
    remove(value);
    assertInvalid(value);
  }
});

test('rejects proxies, accessors, sparse arrays and hostile options without trap execution', async () => {
  const base = clone(await ARTIFACT_PROMISE);
  let traps = 0;
  const hostile = new Proxy({}, {
    get() {
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
  assertInvalid(hostile);
  assert.equal(traps, 0);

  const nestedProxy = clone(base);
  nestedProxy.candidates[0].anchors[0].usage = hostile;
  assertInvalid(nestedProxy);
  assert.equal(traps, 0);

  let accessorReads = 0;
  const accessor = clone(base);
  Object.defineProperty(accessor, 'git_sha', {
    enumerable: true,
    get() {
      accessorReads += 1;
      throw new Error('secret-never-echo');
    },
  });
  assertInvalid(accessor);
  assert.equal(accessorReads, 0);

  const sparse = clone(base);
  delete sparse.candidates[3];
  assertInvalid(sparse);

  assertInvalid(base, { plan: PLAN });
  assertInvalid(base, { plan: PLAN, preflightCases: PREFLIGHT_CASES, extra: true });
  assertInvalid(base, hostile);
  assert.equal(traps, 0);
});
