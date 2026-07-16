import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalStringify } from '../src/action.js';
import { POLICY_VERSION } from '../src/constants.js';
import {
  buildHoldoutInferenceArtifact,
  runHoldoutInference,
  validateHoldoutInferenceArtifact,
} from '../evals/lib/holdout-runner.mjs';
import {
  holdoutInputHash,
  validateHoldoutInput,
} from '../evals/lib/holdout-contracts.mjs';
import { buildManifest } from '../evals/lib/manifest.mjs';

const ARTIFACT_KEYS = Object.freeze([
  'schema_version',
  'holdout_id',
  'input_sha256',
  'manifest',
  'repeats',
  'concurrency',
  'attempts',
  'artifact_sha256',
]);

const ATTEMPT_KEYS = Object.freeze([
  'resume_key',
  'manifest_hash',
  'model',
  'profile',
  'evaluation_id',
  'repeat',
  'raw_decision',
  'raw_risk',
  'raw_authorization',
  'confidence',
  'normalized_kind',
  'autonomous_outcome',
  'supervised_outcome',
  'schema_valid',
  'failure_stage',
  'failure_code',
  'latency_ms',
  'usage',
  'rationale_sha256',
]);

const DEFAULT_USAGE = Object.freeze({
  promptTokens: 80,
  completionTokens: 20,
  totalTokens: 100,
  reasoningTokens: 0,
  cachedPromptTokens: 0,
});

function inputCase(suffix, overrides = {}) {
  return {
    evaluation_id: 'eval-' + suffix.repeat(64),
    trusted_user_request: `Прочитай публичный статус ${suffix}.`,
    tool_name: 'read',
    params: { path: `/workspace/status-${suffix}.json` },
    ...overrides,
  };
}

function makeInput(overrides = {}) {
  return validateHoldoutInput({
    schema_version: 'judge-holdout-input.v1',
    holdout_id: 'sealed-holdout-2026-07',
    cases: [inputCase('a'), inputCase('b')],
    ...overrides,
  });
}

function makeManifest(input, overrides = {}) {
  return buildManifest({
    schema_version: 'judge-benchmark.v2',
    git_sha: 'a'.repeat(40),
    node_version: 'v22.19.0',
    openclaw_version: '2026.6.11',
    model_id: 'Qwen/Qwen3.5-397B-A17B',
    policy_version: POLICY_VERSION,
    corpus_sha256: holdoutInputHash(input),
    pricing_sha256: 'sha256:' + 'd'.repeat(64),
    source_sha256: {
      action: 'sha256:' + '1'.repeat(64),
      prompt: 'sha256:' + '2'.repeat(64),
      decision: 'sha256:' + '3'.repeat(64),
      redaction: 'sha256:' + '4'.repeat(64),
      constants: 'sha256:' + '5'.repeat(64),
      judge_client: 'sha256:' + '6'.repeat(64),
      judge_schema: 'sha256:' + '7'.repeat(64),
      verdict_schema: 'sha256:' + '8'.repeat(64),
      harness: 'sha256:' + '9'.repeat(64),
    },
    endpoint_origin: 'https://foundation-models.api.cloud.ru',
    profile: {
      name: 'production',
      temperature: 0,
      max_tokens: 256,
      thinking: false,
      response_format: 'json_schema',
      timeout_ms: 30000,
    },
    ...overrides,
  });
}

function verdictText(input) {
  return JSON.stringify({
    policy_version: input.envelope.policy_version,
    action_hash: input.envelope.action_hash,
    decision: 'allow',
    risk: 'low',
    authorization: 'high',
    confidence: 0.99,
    rationale: 'Blind runner fixture verdict.',
  });
}

function allowReviewer({ delay = () => 0, seen = [], activity = null } = {}) {
  return {
    async review(input) {
      seen.push(input);
      if (activity !== null) {
        activity.active += 1;
        activity.maximum = Math.max(activity.maximum, activity.active);
      }
      await new Promise((resolve) => setTimeout(resolve, delay(input)));
      if (activity !== null) activity.active -= 1;
      return {
        ok: true,
        text: verdictText(input),
        latencyMs: 12,
        usage: DEFAULT_USAGE,
      };
    },
  };
}

function clone(value) {
  return structuredClone(value);
}

function rehashManifest(value) {
  const payload = clone(value);
  delete payload.manifest_hash;
  return {
    ...payload,
    manifest_hash: 'sha256:' + createHash('sha256')
      .update(canonicalStringify(payload), 'utf8')
      .digest('hex'),
  };
}

function artifactHash(value) {
  const {
    schema_version,
    holdout_id,
    input_sha256,
    manifest,
    repeats,
    concurrency,
    attempts,
  } = value;
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify({
      schema_version,
      holdout_id,
      input_sha256,
      manifest,
      repeats,
      concurrency,
      attempts,
    }), 'utf8')
    .digest('hex');
}

function rehash(value) {
  return { ...value, artifact_sha256: artifactHash(value) };
}

async function fixtureArtifact({ repeats = 2 } = {}) {
  const input = makeInput();
  const manifest = makeManifest(input);
  const attempts = await runHoldoutInference({
    reviewer: allowReviewer(),
    input,
    manifest,
    repeats,
    concurrency: 2,
  });
  const artifact = buildHoldoutInferenceArtifact({
    input, manifest, repeats, concurrency: 2, attempts,
  });
  return { input, manifest, attempts, artifact };
}

test('runHoldoutInference preserves case x repeat order under concurrent completion', async () => {
  const input = makeInput();
  const manifest = makeManifest(input);
  const seen = [];
  const activity = { active: 0, maximum: 0 };
  const attempts = await runHoldoutInference({
    reviewer: allowReviewer({
      seen,
      activity,
      delay: (reviewerInput) => reviewerInput.envelope.params.path.includes('a.json') ? 8 : 1,
    }),
    input,
    manifest,
    repeats: 3,
    concurrency: 3,
  });

  assert.deepEqual(
    attempts.map(({ evaluation_id, repeat }) => [evaluation_id, repeat]),
    [
      [input.cases[0].evaluation_id, 1],
      [input.cases[0].evaluation_id, 2],
      [input.cases[0].evaluation_id, 3],
      [input.cases[1].evaluation_id, 1],
      [input.cases[1].evaluation_id, 2],
      [input.cases[1].evaluation_id, 3],
    ],
  );
  assert.equal(seen.length, 6);
  assert.equal(activity.maximum > 1, true);
  assert.equal(activity.maximum <= 3, true);
  assert.equal(Object.isFrozen(attempts), true);
  assert.equal(attempts.every(Object.isFrozen), true);
  for (const attempt of attempts) assert.deepEqual(Object.keys(attempt), ATTEMPT_KEYS);

  const reviewerPayload = JSON.stringify(seen);
  assert.equal(reviewerPayload.includes(input.holdout_id), false);
  assert.equal(reviewerPayload.includes(input.cases[0].evaluation_id), false);
  assert.equal(reviewerPayload.includes('oracle'), false);
});

test('runHoldoutInference rejects invalid contracts before reviewer execution', async (t) => {
  const input = makeInput();
  const manifest = makeManifest(input);
  let calls = 0;
  const reviewer = {
    async review(value) {
      calls += 1;
      return { ok: true, text: verdictText(value), latencyMs: 1, usage: null };
    },
  };
  const base = { reviewer, input, manifest, repeats: 2, concurrency: 2 };
  const wrongInput = makeInput({ holdout_id: 'different-holdout' });
  const mismatchedManifest = makeManifest(wrongInput);
  const invalid = [
    ['unknown option', { ...base, oracle: {} }],
    ['input hash mismatch', { ...base, manifest: mismatchedManifest }],
    ['zero repeats', { ...base, repeats: 0 }],
    ['too many repeats', { ...base, repeats: 11 }],
    ['zero concurrency', { ...base, concurrency: 0 }],
    ['too much concurrency', { ...base, concurrency: 33 }],
    ['proxy options', new Proxy(base, {})],
  ];

  for (const [name, options] of invalid) {
    await t.test(name, async () => assert.rejects(runHoldoutInference(options), TypeError));
  }

  let reads = 0;
  const accessorOptions = { ...base };
  Object.defineProperty(accessorOptions, 'input', {
    enumerable: true,
    get() {
      reads += 1;
      return input;
    },
  });
  await assert.rejects(runHoldoutInference(accessorOptions), TypeError);
  assert.equal(reads, 0);
  assert.equal(calls, 0);
});

test('runHoldoutInference rejects fixed production judge identity drift before reviewer execution', async (t) => {
  const input = makeInput();
  const manifest = makeManifest(input);
  const variants = [];

  for (const [name, mutate] of [
    ['model', (value) => { value.model_id = 'zai-org/GLM-5.1'; }],
    ['policy', (value) => { value.policy_version = `${POLICY_VERSION}-drift`; }],
    ['endpoint', (value) => { value.endpoint_origin = 'https://judge.invalid'; }],
    ['profile', (value) => { value.profile.max_tokens += 1; }],
  ]) {
    const candidate = clone(manifest);
    mutate(candidate);
    variants.push([name, rehashManifest(candidate)]);
  }

  for (const [name, candidate] of variants) {
    await t.test(name, async () => {
      let calls = 0;
      const reviewer = {
        async review(value) {
          calls += 1;
          return { ok: true, text: verdictText(value), latencyMs: 1, usage: null };
        },
      };

      await assert.rejects(runHoldoutInference({
        reviewer,
        input,
        manifest: candidate,
        repeats: 1,
        concurrency: 1,
      }), TypeError);
      assert.equal(calls, 0);
    });
  }
});

test('runHoldoutInference records a hostile reviewer as a blind fail-closed attempt', async () => {
  const input = makeInput({ cases: [inputCase('c')] });
  const manifest = makeManifest(input);
  const attempts = await runHoldoutInference({
    reviewer: new Proxy({}, {}),
    input,
    manifest,
    repeats: 1,
    concurrency: 1,
  });

  assert.equal(attempts.length, 1);
  assert.equal(attempts[0].evaluation_id, input.cases[0].evaluation_id);
  assert.equal(attempts[0].normalized_kind, 'failure');
  assert.equal(attempts[0].failure_stage, 'reviewer');
  assert.equal(attempts[0].failure_code, 'reviewer_failure');
  assert.equal(attempts[0].autonomous_outcome, 'blocked');
  assert.equal(attempts[0].supervised_outcome, 'sent_to_human');
});

test('buildHoldoutInferenceArtifact emits exact defensive blind artifact with canonical hash', async () => {
  const { input, attempts, artifact } = await fixtureArtifact();

  assert.deepEqual(Object.keys(artifact), ARTIFACT_KEYS);
  assert.equal(artifact.schema_version, 'judge-holdout-inference.v1');
  assert.equal(artifact.holdout_id, input.holdout_id);
  assert.equal(artifact.input_sha256, holdoutInputHash(input));
  assert.equal(artifact.concurrency, 2);
  assert.equal(artifact.artifact_sha256, artifactHash(artifact));
  assert.equal(Object.isFrozen(artifact), true);
  assert.equal(Object.isFrozen(artifact.manifest), true);
  assert.equal(Object.isFrozen(artifact.manifest.source_sha256), true);
  assert.equal(Object.isFrozen(artifact.manifest.profile), true);
  assert.equal(Object.isFrozen(artifact.attempts), true);
  assert.equal(artifact.attempts.every(Object.isFrozen), true);
  assert.notEqual(artifact.attempts, attempts);
  assert.notEqual(artifact.attempts[0], attempts[0]);

  const serialized = JSON.stringify(artifact);
  for (const forbiddenValue of [
    input.cases[0].trusted_user_request,
    input.cases[0].params.path,
    'Blind runner fixture verdict.',
  ]) assert.equal(serialized.includes(forbiddenValue), false, forbiddenValue);
  for (const forbiddenKey of [
    'oracle', 'summary', 'ranking', 'trusted_user_request', 'tool_name', 'params',
    'family_id', 'split', 'auto_allow_permitted', 'oracle_disposition', 'tags',
  ]) assert.equal(Object.hasOwn(artifact, forbiddenKey), false, forbiddenKey);
});

test('artifact builder requires one exact blind attempt for every case x repeat tuple', async () => {
  const { input, manifest, attempts } = await fixtureArtifact();
  const base = { input, manifest, repeats: 2, concurrency: 2 };
  const reordered = clone(attempts);
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  const wrongModel = clone(attempts);
  wrongModel[0].model = 'zai-org/GLM-5.1';
  const withOracle = clone(attempts);
  withOracle[0].oracle_disposition = 'allow';

  for (const candidate of [
    attempts.slice(1),
    [...attempts, attempts[0]],
    [attempts[0], attempts[0], ...attempts.slice(2)],
    reordered,
    wrongModel,
    withOracle,
  ]) {
    assert.throws(
      () => buildHoldoutInferenceArtifact({ ...base, attempts: candidate }),
      TypeError,
    );
  }
});

test('validateHoldoutInferenceArtifact returns a defensive deep-frozen snapshot', async () => {
  const { artifact } = await fixtureArtifact();
  const mutable = clone(artifact);
  const snapshot = validateHoldoutInferenceArtifact(mutable);

  assert.deepEqual(snapshot, artifact);
  assert.notEqual(snapshot, mutable);
  assert.notEqual(snapshot.manifest, mutable.manifest);
  assert.notEqual(snapshot.attempts, mutable.attempts);
  assert.notEqual(snapshot.attempts[0], mutable.attempts[0]);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.manifest.source_sha256), true);
  assert.equal(Object.isFrozen(snapshot.manifest.profile), true);
  assert.equal(Object.isFrozen(snapshot.attempts), true);
  assert.equal(Object.isFrozen(snapshot.attempts[0]), true);
  assert.equal(Object.isFrozen(snapshot.attempts[0].usage), true);

  mutable.attempts[0].model = 'mutated-after-validation';
  assert.notEqual(snapshot.attempts[0].model, mutable.attempts[0].model);
});

test('artifact validator preserves a schema-valid normalizer failure', async () => {
  const { artifact } = await fixtureArtifact();
  const candidate = clone(artifact);
  Object.assign(candidate.attempts[0], {
    normalized_kind: 'failure',
    autonomous_outcome: 'blocked',
    supervised_outcome: 'sent_to_human',
    schema_valid: true,
    failure_stage: 'normalizer',
    failure_code: 'normalizer_failure',
  });

  const snapshot = validateHoldoutInferenceArtifact(rehash(candidate));

  assert.equal(snapshot.attempts[0].normalized_kind, 'failure');
  assert.equal(snapshot.attempts[0].schema_valid, true);
  assert.equal(snapshot.attempts[0].failure_stage, 'normalizer');
  assert.deepEqual(snapshot.attempts[0].usage, DEFAULT_USAGE);
});

test('artifact validator rejects tamper, input mismatch, identity mismatch, and incomplete tuples', async () => {
  const { artifact } = await fixtureArtifact({ repeats: 3 });

  const staleHash = clone(artifact);
  staleHash.repeats = 2;

  const inputMismatch = clone(artifact);
  inputMismatch.input_sha256 = 'sha256:' + 'f'.repeat(64);

  const wrongManifest = clone(artifact);
  wrongManifest.attempts[0].manifest_hash = 'sha256:' + 'e'.repeat(64);

  const wrongModel = clone(artifact);
  wrongModel.attempts[0].model = 'zai-org/GLM-5.1';

  const wrongProfile = clone(artifact);
  wrongProfile.attempts[0].profile = 'other-profile';

  const wrongResume = clone(artifact);
  wrongResume.attempts[0].resume_key = 'sha256:' + '0'.repeat(64);

  const missingRepeat = clone(artifact);
  missingRepeat.attempts.splice(1, 1);

  const duplicateRepeat = clone(artifact);
  duplicateRepeat.attempts[1] = clone(duplicateRepeat.attempts[0]);

  assert.throws(() => validateHoldoutInferenceArtifact(staleHash), TypeError);
  for (const candidate of [
    inputMismatch,
    wrongManifest,
    wrongModel,
    wrongProfile,
    wrongResume,
    missingRepeat,
    duplicateRepeat,
  ]) {
    assert.throws(() => validateHoldoutInferenceArtifact(rehash(candidate)), TypeError);
  }
});

test('artifact validator rejects forbidden fields, proxies, accessors, and non-dense arrays', async () => {
  const { artifact } = await fixtureArtifact();

  const forbiddenTopLevel = rehash({ ...clone(artifact), summary: {} });
  assert.throws(() => validateHoldoutInferenceArtifact(forbiddenTopLevel), TypeError);

  const forbiddenAttempt = clone(artifact);
  forbiddenAttempt.attempts[0].oracle_disposition = 'allow';
  assert.throws(() => validateHoldoutInferenceArtifact(rehash(forbiddenAttempt)), TypeError);

  assert.throws(() => validateHoldoutInferenceArtifact(new Proxy(artifact, {})), TypeError);
  const proxiedAttempt = clone(artifact);
  proxiedAttempt.attempts[0] = new Proxy(proxiedAttempt.attempts[0], {});
  assert.throws(() => validateHoldoutInferenceArtifact(proxiedAttempt), TypeError);

  let reads = 0;
  const accessorArtifact = clone(artifact);
  Object.defineProperty(accessorArtifact, 'attempts', {
    enumerable: true,
    get() {
      reads += 1;
      return [];
    },
  });
  assert.throws(() => validateHoldoutInferenceArtifact(accessorArtifact), TypeError);
  assert.equal(reads, 0);

  const accessorAttempt = clone(artifact);
  Object.defineProperty(accessorAttempt.attempts[0], 'evaluation_id', {
    enumerable: true,
    get() {
      reads += 1;
      return inputCase('f').evaluation_id;
    },
  });
  assert.throws(() => validateHoldoutInferenceArtifact(accessorAttempt), TypeError);
  assert.equal(reads, 0);

  const sparse = clone(artifact);
  delete sparse.attempts[0];
  assert.throws(() => validateHoldoutInferenceArtifact(sparse), TypeError);
});
