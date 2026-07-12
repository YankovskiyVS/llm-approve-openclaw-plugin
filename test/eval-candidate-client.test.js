import test from 'node:test';
import assert from 'node:assert/strict';
import { POLICY_VERSION } from '../src/constants.js';
import { buildJudgeMessages } from '../src/prompt.js';
import { createCandidateJudgeClient } from '../evals/lib/candidate-client.mjs';

const API_KEY = 'candidate-client-test-key-never-persist';
const INPUT = Object.freeze({
  userPrompt: 'Read the workspace status file.',
  envelope: Object.freeze({
    policy_version: POLICY_VERSION,
    action_hash: `sha256:${'a'.repeat(64)}`,
    tool_name: 'read',
    params: Object.freeze({ path: '/workspace/status.json' }),
  }),
});
const VERDICT = JSON.stringify({
  policy_version: POLICY_VERSION,
  action_hash: INPUT.envelope.action_hash,
  decision: 'allow',
  risk: 'low',
  authorization: 'high',
  confidence: 0.99,
  rationale: 'Explicit low-risk workspace read.',
});

function candidate(overrides = {}) {
  return {
    id: 'zai-org/GLM-5.1',
    model_id: 'zai-org/GLM-5.1',
    endpoint_profile: 'cloudru-fm',
    response_profile: 'openai-content',
    temperature: 0,
    max_tokens: 256,
    max_reasoning_tokens: 0,
    thinking: false,
    response_format: 'json_object',
    timeout_ms: 5000,
    ...overrides,
  };
}

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

function successfulBody(message = { content: VERDICT }) {
  return {
    choices: [{ finish_reason: 'stop', message }],
    usage: { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120 },
  };
}

test('sends the exact common primary request to the frozen FM endpoint', async () => {
  let captured;
  const client = createCandidateJudgeClient({
    candidate: candidate(),
    apiKey: API_KEY,
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(successfulBody());
    },
  });

  const result = await client.review(INPUT);

  assert.equal(captured.url, 'https://foundation-models.api.cloud.ru/v1/chat/completions');
  assert.equal(captured.options.method, 'POST');
  assert.equal(captured.options.redirect, 'error');
  assert.deepEqual(captured.options.headers, {
    Authorization: `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
  });
  assert.equal(captured.options.signal instanceof AbortSignal, true);
  assert.deepEqual(JSON.parse(captured.options.body), {
    model: 'zai-org/GLM-5.1',
    messages: buildJudgeMessages(INPUT),
    temperature: 0,
    max_tokens: 256,
    response_format: { type: 'json_object' },
    chat_template_kwargs: { enable_thinking: false },
  });
  assert.equal(captured.options.body.includes(API_KEY), false);
  assert.deepEqual(result, {
    ok: true,
    text: VERDICT,
    latencyMs: result.latencyMs,
    usage: {
      promptTokens: 100,
      completionTokens: 20,
      totalTokens: 120,
      reasoningTokens: null,
      cachedPromptTokens: null,
    },
  });
});

test('routes only the frozen Qwen candidate to vLLM and never uses reasoning as verdict', async () => {
  let captured;
  let reasoningReads = 0;
  const message = { content: VERDICT };
  Object.defineProperty(message, 'reasoning_content', {
    enumerable: true,
    get() {
      reasoningReads += 1;
      throw new Error('hidden reasoning must not be read');
    },
  });
  const client = createCandidateJudgeClient({
    candidate: candidate({
      id: 'qwen36-27b-fp8',
      model_id: 'qwen36-27b-fp8',
      endpoint_profile: 'qwen-vllm',
      response_profile: 'vllm-reasoning-final',
    }),
    apiKey: API_KEY,
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return response(successfulBody(message));
    },
  });

  const result = await client.review(INPUT);

  assert.equal(
    captured.url,
    'https://45a768cf-dd2c-4d96-9a98-7e24ce4866e5.modelrun.inference.cloud.ru/v1/chat/completions',
  );
  assert.equal(JSON.parse(captured.options.body).model, 'qwen36-27b-fp8');
  assert.equal(Object.hasOwn(JSON.parse(captured.options.body), 'thinking_token_budget'), false);
  assert.equal(result.ok, true);
  assert.equal(result.text, VERDICT);
  assert.equal(reasoningReads, 0);
});

test('rejects non-canonical candidate transports and profile mutations before fetch', () => {
  for (const mutation of [
    { id: 'arbitrary/model-not-in-plan', model_id: 'arbitrary/model-not-in-plan' },
    { id: 'zai-org/GLM-4.7' },
    { endpoint_profile: 'arbitrary-url' },
    { response_profile: 'reasoning-fallback' },
    { temperature: 0.1 },
    { max_tokens: 4096 },
    { max_reasoning_tokens: 1 },
    { thinking: true },
    { response_format: 'text' },
    { timeout_ms: 15000 },
    { endpoint_profile: 'qwen-vllm' },
  ]) {
    assert.throws(() => createCandidateJudgeClient({
      candidate: candidate(mutation),
      apiKey: API_KEY,
      fetchImpl: async () => assert.fail('fetch must not run'),
    }), /invalid candidate client configuration/);
  }
  assert.throws(() => createCandidateJudgeClient({
    candidate: candidate(),
    apiKey: '',
    fetchImpl: async () => response(successfulBody()),
  }), /invalid candidate client configuration/);
});

test('rejects nested request proxies and hostile response proxies without executing traps', async () => {
  let requestTraps = 0;
  const nestedProxy = new Proxy({}, {
    ownKeys() {
      requestTraps += 1;
      throw new Error('request proxy trap must not execute');
    },
    getOwnPropertyDescriptor() {
      requestTraps += 1;
      throw new Error('request proxy trap must not execute');
    },
  });
  let fetchCalls = 0;
  const client = createCandidateJudgeClient({
    candidate: candidate(),
    apiKey: API_KEY,
    fetchImpl: async () => {
      fetchCalls += 1;
      return response(successfulBody());
    },
  });
  const requestResult = await client.review({
    userPrompt: INPUT.userPrompt,
    envelope: {
      ...INPUT.envelope,
      params: { nested: nestedProxy },
    },
  });
  assert.equal(requestResult.ok, false);
  assert.equal(requestResult.reason, 'invalid judge request');
  assert.equal(fetchCalls, 0);
  assert.equal(requestTraps, 0);

  let responseTraps = 0;
  const hostileResponse = new Proxy({}, {
    get() {
      responseTraps += 1;
      throw new Error('response proxy trap must not execute');
    },
    getPrototypeOf() {
      responseTraps += 1;
      throw new Error('response proxy trap must not execute');
    },
    getOwnPropertyDescriptor() {
      responseTraps += 1;
      throw new Error('response proxy trap must not execute');
    },
  });
  const responseResult = await createCandidateJudgeClient({
    candidate: candidate(),
    apiKey: API_KEY,
    fetchImpl: () => hostileResponse,
  }).review(INPUT);
  assert.equal(responseResult.ok, false);
  assert.equal(responseResult.reason, 'request failed');
  assert.equal(responseTraps, 0);
});

test('returns bounded fail-closed transport errors without response or key disclosure', async () => {
  const cases = [
    [async () => response({}, 403), 'http 403'],
    [async () => response({ choices: [] }), 'invalid judge response'],
    [async () => { throw new Error(`network ${API_KEY}`); }, 'request failed'],
  ];
  for (const [fetchImpl, reason] of cases) {
    const result = await createCandidateJudgeClient({
      candidate: candidate(),
      apiKey: API_KEY,
      fetchImpl,
    }).review(INPUT);
    assert.equal(result.ok, false);
    assert.equal(result.reason, reason);
    assert.equal(JSON.stringify(result).includes(API_KEY), false);
    assert.deepEqual(Object.keys(result).sort(), ['latencyMs', 'ok', 'reason']);
  }
});

test('refuses semantic input containing the provider credential without calling fetch', async () => {
  let calls = 0;
  const result = await createCandidateJudgeClient({
    candidate: candidate(),
    apiKey: API_KEY,
    fetchImpl: async () => {
      calls += 1;
      return response(successfulBody());
    },
  }).review({
    userPrompt: `Read ${API_KEY}`,
    envelope: INPUT.envelope,
  });

  assert.equal(calls, 0);
  assert.deepEqual(result, {
    ok: false,
    reason: 'invalid judge request',
    latencyMs: result.latencyMs,
  });
  assert.equal(JSON.stringify(result).includes(API_KEY), false);
});
