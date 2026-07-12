import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  CANDIDATE_PLAN_URL,
  validateCandidatePlan,
} from '../evals/lib/candidate-plan.mjs';

const EXPECTED_MODEL_IDS = Object.freeze([
  'zai-org/GLM-5.1',
  'zai-org/GLM-4.7',
  'zai-org/GLM-5.2',
  'Qwen/Qwen3.6-35B-A3B',
  'Qwen/Qwen3.5-397B-A17B',
  'Qwen/Qwen3-Coder-Next',
  'qwen36-27b-fp8',
  'moonshotai/Kimi-K2.6',
  'deepseek-ai/DeepSeek-V4-Pro',
  'deepseek-ai/DeepSeek-V4-Flash',
  'deepseek-ai/DeepSeek-V3.1-Terminus',
  'deepseek-ai/DeepSeek-V3',
  'deepseek-ai/DeepSeek-R1-0528',
  'MiniMaxAI/MiniMax-M3',
  'MiniMaxAI/MiniMax-M2.5',
  'MiniMaxAI/MiniMax-M2',
  'openai/gpt-oss-120b',
  'openai/gpt-oss-20b',
  'ai-sage/GigaChat3-10B-A1.8B',
]);

const PLAN_KEYS = Object.freeze(['schema_version', 'candidates']);
const CANDIDATE_KEYS = Object.freeze([
  'id',
  'model_id',
  'endpoint_profile',
  'response_profile',
  'temperature',
  'max_tokens',
  'max_reasoning_tokens',
  'thinking',
  'response_format',
  'timeout_ms',
]);

function canonicalInput() {
  return JSON.parse(readFileSync(CANDIDATE_PLAN_URL, 'utf8'));
}

function assertSafeTypeError(run, secret, label = secret) {
  let caught;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  assert.equal(caught instanceof TypeError, true, label);
  assert.equal(caught?.message.includes(secret), false, label);
  assert.equal(caught?.message.length < 80, true, label);
}

test('canonical plan freezes the exact 19 candidates and closed qualification budget', () => {
  const input = canonicalInput();
  const result = validateCandidatePlan(input);

  assert.deepEqual(Object.keys(result), PLAN_KEYS);
  assert.equal(result.schema_version, 'judge-candidate-plan.v1');
  assert.equal(result.candidates.length, 19);
  assert.deepEqual(
    result.candidates.map(({ model_id }) => model_id),
    EXPECTED_MODEL_IDS,
  );
  assert.equal(new Set(result.candidates.map(({ id }) => id)).size, 19);

  for (const candidate of result.candidates) {
    assert.deepEqual(Object.keys(candidate), CANDIDATE_KEYS);
    assert.equal(candidate.temperature, 0);
    assert.equal(candidate.max_tokens, 256);
    assert.equal(candidate.max_reasoning_tokens, 0);
    assert.equal(candidate.thinking, false);
    assert.equal(candidate.response_format, 'json_object');
    assert.equal(candidate.timeout_ms, 5000);

    if (candidate.model_id === 'qwen36-27b-fp8') {
      assert.equal(candidate.endpoint_profile, 'qwen-vllm');
      assert.equal(candidate.response_profile, 'vllm-reasoning-final');
    } else {
      assert.equal(candidate.endpoint_profile, 'cloudru-fm');
      assert.equal(candidate.response_profile, 'openai-content');
    }
  }

  assert.notEqual(result, input);
  assert.notEqual(result.candidates, input.candidates);
  assert.notEqual(result.candidates[0], input.candidates[0]);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.candidates), true);
  assert.equal(result.candidates.every(Object.isFrozen), true);
});

test('validated plan is a defensive snapshot immune to later input mutation', () => {
  const input = canonicalInput();
  const result = validateCandidatePlan(input);
  const firstId = result.candidates[0].id;
  const firstModelId = result.candidates[0].model_id;

  input.schema_version = 'mutated';
  input.candidates[0].id = 'mutated';
  input.candidates[0].model_id = 'mutated';
  input.candidates.length = 0;

  assert.equal(result.schema_version, 'judge-candidate-plan.v1');
  assert.equal(result.candidates.length, 19);
  assert.equal(result.candidates[0].id, firstId);
  assert.equal(result.candidates[0].model_id, firstModelId);
  assert.throws(() => {
    result.candidates[0].timeout_ms = 1;
  }, TypeError);
  assert.throws(() => {
    result.candidates.push({});
  }, TypeError);
});

test('plan rejects extra or missing fields at every schema level', () => {
  const extraTop = canonicalInput();
  extraTop.endpoint_url = 'https://credential-sentinel.invalid';
  assertSafeTypeError(
    () => validateCandidatePlan(extraTop),
    'credential-sentinel',
    'extra top-level field',
  );

  const missingTop = canonicalInput();
  delete missingTop.schema_version;
  assert.throws(() => validateCandidatePlan(missingTop), TypeError);

  const extraCandidate = canonicalInput();
  extraCandidate.candidates[0].api_key = 'credential-sentinel';
  assertSafeTypeError(
    () => validateCandidatePlan(extraCandidate),
    'credential-sentinel',
    'extra candidate field',
  );

  const missingCandidate = canonicalInput();
  delete missingCandidate.candidates[0].timeout_ms;
  assert.throws(() => validateCandidatePlan(missingCandidate), TypeError);
});

test('plan rejects unknown or mismatched endpoint and response profiles', () => {
  for (const [field, value] of [
    ['endpoint_profile', 'credential-sentinel-endpoint'],
    ['response_profile', 'credential-sentinel-response'],
  ]) {
    const input = canonicalInput();
    input.candidates[0][field] = value;
    assertSafeTypeError(
      () => validateCandidatePlan(input),
      'credential-sentinel',
      field,
    );
  }

  const mismatched = canonicalInput();
  const qwen = mismatched.candidates.find(({ model_id }) => model_id === 'qwen36-27b-fp8');
  qwen.endpoint_profile = 'cloudru-fm';
  qwen.response_profile = 'openai-content';
  assert.throws(() => validateCandidatePlan(mismatched), TypeError);
});

test('plan rejects duplicate, missing, reordered, or unknown candidates', () => {
  const duplicateId = canonicalInput();
  duplicateId.candidates[1].id = duplicateId.candidates[0].id;
  assert.throws(() => validateCandidatePlan(duplicateId), /duplicate candidate/u);

  const duplicateModel = canonicalInput();
  duplicateModel.candidates[1].model_id = duplicateModel.candidates[0].model_id;
  assert.throws(() => validateCandidatePlan(duplicateModel), /duplicate candidate/u);

  const missing = canonicalInput();
  missing.candidates.pop();
  assert.throws(() => validateCandidatePlan(missing), TypeError);

  const reordered = canonicalInput();
  reordered.candidates.reverse();
  assert.throws(() => validateCandidatePlan(reordered), TypeError);

  const unknown = canonicalInput();
  unknown.candidates[0].model_id = 'unknown/model';
  assert.throws(() => validateCandidatePlan(unknown), TypeError);
});

test('plan rejects every qualification-budget mutation', () => {
  for (const [field, value] of [
    ['temperature', 0.1],
    ['max_tokens', 257],
    ['max_reasoning_tokens', 1],
    ['thinking', true],
    ['response_format', 'text'],
    ['timeout_ms', 5001],
  ]) {
    const input = canonicalInput();
    input.candidates[0][field] = value;
    assert.throws(() => validateCandidatePlan(input), TypeError, field);
  }
});

test('plan rejects proxy and accessor input without invoking hostile traps', () => {
  let trapCalls = 0;
  const traps = {
    get() {
      trapCalls += 1;
      throw new Error('credential-sentinel-proxy');
    },
    getOwnPropertyDescriptor() {
      trapCalls += 1;
      throw new Error('credential-sentinel-proxy');
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error('credential-sentinel-proxy');
    },
  };

  assertSafeTypeError(
    () => validateCandidatePlan(new Proxy(canonicalInput(), traps)),
    'credential-sentinel',
    'top-level proxy',
  );

  const proxyArray = canonicalInput();
  proxyArray.candidates = new Proxy(proxyArray.candidates, traps);
  assertSafeTypeError(
    () => validateCandidatePlan(proxyArray),
    'credential-sentinel',
    'candidate array proxy',
  );

  const proxyCandidate = canonicalInput();
  proxyCandidate.candidates[0] = new Proxy(proxyCandidate.candidates[0], traps);
  assertSafeTypeError(
    () => validateCandidatePlan(proxyCandidate),
    'credential-sentinel',
    'candidate proxy',
  );

  let getterCalls = 0;
  const accessor = canonicalInput();
  Object.defineProperty(accessor.candidates[0], 'model_id', {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error('credential-sentinel-accessor');
    },
  });
  assertSafeTypeError(
    () => validateCandidatePlan(accessor),
    'credential-sentinel',
    'candidate accessor',
  );

  assert.equal(trapCalls, 0);
  assert.equal(getterCalls, 0);
});

test('plan rejects URL, credential, and filesystem-path injection without disclosure', () => {
  for (const injected of [
    'https://credential-sentinel.invalid/v1',
    'model?api_key=credential-sentinel',
    '/Users/credential-sentinel/.env',
    '../../credential-sentinel',
    'file:///credential-sentinel',
  ]) {
    for (const field of ['id', 'model_id']) {
      const input = canonicalInput();
      input.candidates[0][field] = injected;
      assertSafeTypeError(
        () => validateCandidatePlan(input),
        'credential-sentinel',
        field + ' injection',
      );
    }
  }

  const raw = readFileSync(CANDIDATE_PLAN_URL, 'utf8');
  for (const forbidden of [
    /https?:\/\//iu,
    /file:\/\//iu,
    /\/Users\//u,
    /api[_-]?key/iu,
    /authorization/iu,
    /password/iu,
    /credential/iu,
    /secret/iu,
  ]) {
    assert.doesNotMatch(raw, forbidden);
  }
});
