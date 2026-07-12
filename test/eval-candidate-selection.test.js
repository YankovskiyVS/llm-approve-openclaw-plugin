import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { POLICY_VERSION } from '../src/constants.js';
import { createCaseInput } from '../evals/lib/case-input.mjs';
import { CANDIDATE_PLAN_URL } from '../evals/lib/candidate-plan.mjs';
import { runCandidatePreflight } from '../evals/lib/candidate-preflight.mjs';
import { runCandidateSelection } from '../evals/lib/candidate-selection.mjs';

const CORPUS_URL = new URL(
  '../evals/corpus-v2/frozen/model-selection.json',
  import.meta.url,
);
const PREFLIGHT_URL = new URL(
  '../evals/corpus-v2/frozen/model-selection-preflight.json',
  import.meta.url,
);
const PRICING_URL = new URL(
  '../evals/fixtures/model-selection-pricing.json',
  import.meta.url,
);
const FM_SECRET = 'selection-fm-secret-never-persist';
const VLLM_SECRET = 'selection-vllm-secret-never-persist';
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
  'manifest',
  'aggregate',
  'wilson',
  'preflight_artifact',
  'official_preflight_attestation',
  'model_selection_pricing',
  'selection_checkpoint',
  'selection_ranking',
  'candidate_selection',
]);
const PREFLIGHT_SOURCE_KEYS = Object.freeze([
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

async function fixture() {
  const plan = JSON.parse(readFileSync(CANDIDATE_PLAN_URL, 'utf8'));
  const cases = JSON.parse(readFileSync(CORPUS_URL, 'utf8'));
  const preflightCases = JSON.parse(readFileSync(PREFLIGHT_URL, 'utf8'));
  const eligibleCandidateIds = [plan.candidates[1].id, plan.candidates[6].id];
  const eligibleModels = new Set(plan.candidates
    .filter((candidate) => eligibleCandidateIds.includes(candidate.id))
    .map((candidate) => candidate.model_id));
  const success = verdictFetch(preflightCases, (_model, oracle) => oracle);
  const preflightArtifact = await runCandidatePreflight({
    plan,
    cases: preflightCases,
    providerSecrets: {
      'cloudru-fm': FM_SECRET,
      'qwen-vllm': VLLM_SECRET,
    },
    fetchImpl: async (url, options) => {
      const body = JSON.parse(options.body);
      if (eligibleModels.has(body.model)) return success(url, options);
      return { ok: false, status: 403, json: async () => ({}) };
    },
    concurrency: 4,
    gitSha: 'b'.repeat(40),
    nodeVersion: 'v25.8.0',
    openclawVersion: '2026.6.11',
    sourceHashes: Object.fromEntries(
      PREFLIGHT_SOURCE_KEYS.map((key) => [key, HASH]),
    ),
  });
  return {
    plan,
    cases,
    preflightArtifact,
    preflightCases,
    providerSecrets: {
      'cloudru-fm': FM_SECRET,
      'qwen-vllm': VLLM_SECRET,
    },
    fetchImpl: null,
    concurrency: 4,
    gitSha: 'b'.repeat(40),
    nodeVersion: 'v25.8.0',
    openclawVersion: '2026.6.11',
    officialPreflightArtifactSha256: `sha256:${'c'.repeat(64)}`,
    officialPreflightAttestationSha256: `sha256:${'d'.repeat(64)}`,
    sourceHashes: Object.fromEntries(SOURCE_KEYS.map((key) => [key, HASH])),
    pricing: JSON.parse(readFileSync(PRICING_URL, 'utf8')),
    completedCheckpoints: [],
    onCheckpoint: async () => {},
  };
}

function requestEnvelope(options) {
  const body = JSON.parse(options.body);
  const lines = body.messages[1].content.split('\n');
  const index = lines.indexOf('UNTRUSTED_ACTION_JSON_BEGIN');
  return { body, envelope: JSON.parse(lines[index + 1]) };
}

function verdictFetch(cases, decide, telemetry = {}) {
  const dispositionByHash = new Map(cases.map((item) => [
    createCaseInput(item).envelope.action_hash,
    item.preferred_disposition,
  ]));
  return async (_url, options) => {
    const { body, envelope } = requestEnvelope(options);
    telemetry.active = (telemetry.active ?? 0) + 1;
    telemetry.calls = (telemetry.calls ?? 0) + 1;
    telemetry.max = Math.max(telemetry.max ?? 0, telemetry.active);
    const perModel = (telemetry.byModel?.get(body.model) ?? 0) + 1;
    telemetry.byModel?.set(body.model, perModel);
    telemetry.perModelMax = Math.max(telemetry.perModelMax ?? 0, perModel);
    const decision = decide(body.model, dispositionByHash.get(envelope.action_hash));
    if ((telemetry.delayMs ?? 0) > 0) {
      await new Promise((resolve) => setTimeout(resolve, telemetry.delayMs));
    }
    telemetry.active -= 1;
    telemetry.byModel?.set(body.model, perModel - 1);
    const risk = decision === 'allow' ? 'low' : decision === 'deny' ? 'critical' : 'high';
    const authorization = decision === 'allow' ? 'high' : 'unknown';
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
              decision,
              risk,
              authorization,
              confidence: 0.99,
              rationale: 'Synthetic model-selection response.',
            }),
          },
        }],
        usage: { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120 },
      }),
    };
  };
}

test('selection runs eligible models over exact 120 cases and emits aggregate-valid records', async () => {
  const input = await fixture();
  const telemetry = { byModel: new Map(), delayMs: 1 };
  input.fetchImpl = verdictFetch(input.cases, (_model, oracle) => oracle, telemetry);

  const artifact = await runCandidateSelection(input);

  assert.equal(artifact.schema_version, 'judge-candidate-selection.v1');
  assert.equal(
    artifact.official_preflight_artifact_sha256,
    input.officialPreflightArtifactSha256,
  );
  const eligibleCandidateIds = input.preflightArtifact.candidates
    .filter((candidate) => candidate.capability_status === 'pass')
    .map((candidate) => candidate.candidate_id);
  assert.deepEqual(artifact.eligible_candidate_ids, eligibleCandidateIds);
  assert.equal(artifact.candidates.length, 2);
  assert.equal(artifact.candidates.every((item) => item.attempts.length === 120), true);
  assert.equal(artifact.candidates.every(
    (item) => item.summary.denominators.attempts === 120,
  ), true);
  assert.notEqual(
    artifact.candidates[0].manifest.manifest_hash,
    artifact.candidates[1].manifest.manifest_hash,
  );
  assert.equal(telemetry.max, 2);
  assert.equal(telemetry.perModelMax, 1);
  assert.equal(artifact.ranking.length, 2);
  assert.equal(Object.isFrozen(artifact.candidates[0].attempts[0]), true);
  const serialized = JSON.stringify(artifact);
  assert.equal(serialized.includes(FM_SECRET), false);
  assert.equal(serialized.includes(VLLM_SECRET), false);
  assert.doesNotMatch(serialized, /Synthetic model-selection response/u);
  assert.doesNotMatch(serialized, /trusted_user_request/u);
  assert.doesNotMatch(serialized, /params/u);
});

test('selection resumes exact completed candidates without repeating paid calls', async () => {
  const first = await fixture();
  const checkpoints = [];
  first.fetchImpl = verdictFetch(first.cases, (_model, oracle) => oracle);
  first.onCheckpoint = async (checkpoint) => checkpoints.push(checkpoint);
  await runCandidateSelection(first);
  assert.equal(checkpoints.length, 2);

  const resumed = await fixture();
  resumed.preflightArtifact = first.preflightArtifact;
  const telemetry = {};
  const emitted = [];
  resumed.fetchImpl = verdictFetch(resumed.cases, (_model, oracle) => oracle, telemetry);
  resumed.completedCheckpoints = [checkpoints[0]];
  resumed.onCheckpoint = async (checkpoint) => emitted.push(checkpoint);
  const artifact = await runCandidateSelection(resumed);

  assert.equal(telemetry.calls, 120);
  assert.equal(emitted.length, 1);
  assert.equal(artifact.candidates.length, 2);
  assert.deepEqual(artifact.candidates[0], checkpoints[0].candidate_result);
});

test('selection ranking penalizes unsafe auto-allow ahead of latency', async () => {
  const input = await fixture();
  const eligibleCandidateIds = input.preflightArtifact.candidates
    .filter((candidate) => candidate.capability_status === 'pass')
    .map((candidate) => candidate.candidate_id);
  const unsafeModel = eligibleCandidateIds[0];
  input.fetchImpl = verdictFetch(input.cases, (model, oracle) => (
    model === unsafeModel ? 'allow' : oracle
  ));

  const artifact = await runCandidateSelection(input);

  assert.equal(artifact.ranking[0].candidate_id, eligibleCandidateIds[1]);
  assert.equal(artifact.ranking[0].family_false_approve.must_block.numerator, 0);
  assert.equal(artifact.ranking[1].candidate_id, unsafeModel);
  assert.equal(
    artifact.ranking[1].family_false_approve.must_block.numerator > 0,
    true,
  );
});

test('selection rejects profile drift, unknown eligibility, malformed pricing, and hostile plan', async () => {
  const base = await fixture();
  base.fetchImpl = verdictFetch(base.cases, (_model, oracle) => oracle);
  const mutations = [];
  mutations.push({ eligibleCandidateIds: ['unknown/model'] });
  mutations.push({ concurrency: 3 });
  mutations.push({ preflightSha256: 'not-a-hash' });
  mutations.push({ cases: base.cases.slice().reverse() });
  const forged = JSON.parse(JSON.stringify(base.preflightArtifact));
  forged.candidates[0].capability_status = 'pass';
  mutations.push({ preflightArtifact: forged });
  mutations.push({ pricing: { ...base.pricing, currency: 'USD' } });
  for (const mutation of mutations) {
    await assert.rejects(runCandidateSelection({ ...base, ...mutation }), TypeError);
  }

  let traps = 0;
  const hostilePlan = new Proxy({}, {
    ownKeys() {
      traps += 1;
      throw new Error('secret trap');
    },
    get() {
      traps += 1;
      throw new Error('secret trap');
    },
  });
  await assert.rejects(runCandidateSelection({ ...base, plan: hostilePlan }), TypeError);
  assert.equal(traps, 0);
});
