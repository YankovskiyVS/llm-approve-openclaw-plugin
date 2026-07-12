import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { POLICY_VERSION } from '../src/constants.js';
import { CANDIDATE_PLAN_URL } from '../evals/lib/candidate-plan.mjs';
import { runCandidatePreflight } from '../evals/lib/candidate-preflight.mjs';

const PREFLIGHT_URL = new URL(
  '../evals/corpus-v2/frozen/model-selection-preflight.json',
  import.meta.url,
);
const SECRET_FM = 'preflight-fm-secret-never-persist';
const SECRET_VLLM = 'preflight-vllm-secret-never-persist';
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

function inputs() {
  return {
    plan: JSON.parse(readFileSync(CANDIDATE_PLAN_URL, 'utf8')),
    cases: JSON.parse(readFileSync(PREFLIGHT_URL, 'utf8')),
    providerSecrets: {
      'cloudru-fm': SECRET_FM,
      'qwen-vllm': SECRET_VLLM,
    },
    concurrency: 4,
    gitSha: 'b'.repeat(40),
    nodeVersion: 'v25.8.0',
    openclawVersion: '2026.6.11',
    sourceHashes: Object.fromEntries(SOURCE_KEYS.map((key) => [key, HASH])),
  };
}

function extractEnvelope(options) {
  const body = JSON.parse(options.body);
  const lines = body.messages[1].content.split('\n');
  const start = lines.indexOf('UNTRUSTED_ACTION_JSON_BEGIN');
  return { body, envelope: JSON.parse(lines[start + 1]) };
}

function successfulFetch({ delayMs = 0, decide } = {}) {
  return async (_url, options) => {
    const { body, envelope } = extractEnvelope(options);
    if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
    const verdict = decide?.(body.model, envelope) ?? {
      decision: 'allow',
      risk: 'low',
      authorization: 'high',
      confidence: 0.99,
    };
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
              ...verdict,
              rationale: 'Synthetic capability response.',
            }),
          },
        }],
        usage: { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120 },
      }),
    };
  };
}

test('preflight executes exact 19x6 order with sequential anchors per candidate', async () => {
  const activeByModel = new Map();
  let globalActive = 0;
  let globalMaximum = 0;
  let perModelMaximum = 0;
  const order = [];
  const fetchImpl = async (url, options) => {
    const { body, envelope } = extractEnvelope(options);
    order.push([body.model, envelope.action_hash]);
    globalActive += 1;
    globalMaximum = Math.max(globalMaximum, globalActive);
    const modelActive = (activeByModel.get(body.model) ?? 0) + 1;
    activeByModel.set(body.model, modelActive);
    perModelMaximum = Math.max(perModelMaximum, modelActive);
    await new Promise((resolve) => setTimeout(resolve, 1));
    globalActive -= 1;
    activeByModel.set(body.model, modelActive - 1);
    return successfulFetch()('https://unused.invalid', options);
  };

  const artifact = await runCandidatePreflight({ ...inputs(), fetchImpl });

  assert.equal(artifact.schema_version, 'judge-candidate-preflight.v1');
  assert.equal(artifact.candidates.length, 19);
  assert.equal(artifact.candidates.flatMap((item) => item.anchors).length, 114);
  assert.deepEqual(
    artifact.candidates.map((item) => item.candidate_id),
    inputs().plan.candidates.map((item) => item.id),
  );
  assert.equal(artifact.candidates.every((item) => item.capability_status === 'pass'), true);
  assert.equal(globalMaximum <= 4, true);
  assert.equal(perModelMaximum, 1);
  assert.equal(order.length, 114);
  assert.equal(Object.isFrozen(artifact), true);
  assert.equal(Object.isFrozen(artifact.candidates[0].anchors[0]), true);
  assert.equal(JSON.stringify(artifact).includes(SECRET_FM), false);
  assert.equal(JSON.stringify(artifact).includes(SECRET_VLLM), false);
});

test('capability status depends on transport and strict schema, not oracle agreement', async () => {
  const fixture = inputs();
  const firstModel = fixture.plan.candidates[0].model_id;
  let firstModelCall = 0;
  const fetchImpl = async (url, options) => {
    const { body } = extractEnvelope(options);
    if (body.model === firstModel) {
      firstModelCall += 1;
      if (firstModelCall === 1) return { ok: false, status: 403, json: async () => ({}) };
      if (firstModelCall === 2) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ choices: [{ finish_reason: 'length', message: { content: '{}' } }] }),
        };
      }
    }
    return successfulFetch({
      decide: () => ({
        decision: 'deny',
        risk: 'critical',
        authorization: 'unknown',
        confidence: 0.51,
      }),
    })(url, options);
  };

  const artifact = await runCandidatePreflight({ ...fixture, fetchImpl });
  const failed = artifact.candidates[0];
  const mismatchedButCompatible = artifact.candidates[1];

  assert.equal(failed.capability_status, 'fail');
  assert.equal(failed.transport_ok_count, 5);
  assert.equal(failed.schema_valid_count, 4);
  assert.equal(failed.anchors[0].failure_code, 'http_403');
  assert.equal(failed.anchors[1].failure_code, 'invalid_response');
  assert.equal(mismatchedButCompatible.capability_status, 'pass');
  assert.equal(mismatchedButCompatible.schema_valid_count, 6);
  assert.equal(mismatchedButCompatible.oracle_match_count < 6, true);
});

test('preflight binds plan corpus runtime and source hashes without URLs or payload text', async () => {
  const artifact = await runCandidatePreflight({
    ...inputs(),
    fetchImpl: successfulFetch(),
  });
  assert.match(artifact.plan_sha256, /^sha256:[0-9a-f]{64}$/u);
  assert.match(artifact.corpus_sha256, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(artifact.source_sha256, inputs().sourceHashes);
  assert.equal(artifact.git_sha, 'b'.repeat(40));
  assert.equal(artifact.node_version, 'v25.8.0');
  assert.equal(artifact.openclaw_version, '2026.6.11');
  assert.deepEqual(artifact.profile, {
    temperature: 0,
    max_tokens: 256,
    max_reasoning_tokens: 0,
    thinking: false,
    response_format: 'json_object',
    timeout_ms: 5000,
  });
  assert.deepEqual(artifact.execution, {
    candidate_concurrency: 4,
    anchors_per_candidate: 'sequential',
  });
  const serialized = JSON.stringify(artifact);
  assert.doesNotMatch(serialized, /https?:\/\//u);
  assert.doesNotMatch(serialized, /UNTRUSTED_ACTION_JSON/u);
  assert.doesNotMatch(serialized, /rationale":"/u);
});

test('preflight snapshots and rejects malformed or hostile orchestration inputs', async () => {
  const base = inputs();
  for (const mutation of [
    { concurrency: 0 },
    { concurrency: 1 },
    { concurrency: 3 },
    { concurrency: 5 },
    { providerSecrets: { 'cloudru-fm': SECRET_FM } },
    { providerSecrets: { ...base.providerSecrets, extra: 'secret-extra' } },
    { gitSha: '/Users/secret/repo' },
    { nodeVersion: 'v20.0.0' },
    { openclawVersion: '2026.6.10' },
  ]) {
    await assert.rejects(
      runCandidatePreflight({ ...base, ...mutation, fetchImpl: successfulFetch() }),
      TypeError,
    );
  }

  let traps = 0;
  const hostilePlan = new Proxy({}, {
    get() {
      traps += 1;
      throw new Error('secret proxy');
    },
    ownKeys() {
      traps += 1;
      throw new Error('secret proxy');
    },
  });
  await assert.rejects(
    runCandidatePreflight({ ...base, plan: hostilePlan, fetchImpl: successfulFetch() }),
    TypeError,
  );
  assert.equal(traps, 0);
});
