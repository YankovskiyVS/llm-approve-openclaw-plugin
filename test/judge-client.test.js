import test from 'node:test';
import assert from 'node:assert/strict';
import { createJudgeClient } from '../src/judge-client.js';
import { JUDGE_TIMEOUT_MS, MODEL_ID, POLICY_VERSION } from '../src/constants.js';
import { createJudgeResponseFormat } from '../src/judge-schema.js';
import { buildJudgeMessages } from '../src/prompt.js';

const ACTION_HASH = `sha256:${'a'.repeat(64)}`;
const USER_PROMPT = 'Read status.';
const ENVELOPE = {
  policy_version: POLICY_VERSION,
  action_hash: ACTION_HASH,
  tool_name: 'read',
  params: { path: '/tmp/status' },
};
const CONTENT = '{"decision":"allow"}';

function successfulResponse(content = CONTENT) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      model: MODEL_ID,
      choices: [{ finish_reason: 'stop', message: { content } }],
    }),
  };
}

function makeClient(fetchImpl, overrides = {}) {
  return createJudgeClient({
    providerConfig: {
      baseUrl: 'https://foundation-models.api.cloud.ru/v1',
      apiKey: 'ordinary-test-key',
    },
    fetchImpl,
    ...overrides,
  });
}

function assertLatency(latencyMs) {
  assert.equal(typeof latencyMs, 'number');
  assert.equal(Number.isFinite(latencyMs), true);
  assert.equal(latencyMs >= 0, true);
}

function assertSafeFailure(result, { reason, secret } = {}) {
  assert.equal(result.ok, false);
  assert.deepEqual(Object.keys(result).sort(), ['latencyMs', 'ok', 'reason']);
  assert.equal(typeof result.reason, 'string');
  assert.equal(result.reason.length > 0 && result.reason.length <= 80, true);
  if (reason !== undefined) assert.equal(result.reason, reason);
  if (secret !== undefined) {
    assert.equal(JSON.stringify(result).includes(secret), false, 'failure exposed fixture data');
  }
  assertLatency(result.latencyMs);
}

function captureError(operation) {
  try {
    operation();
  } catch (error) {
    return error;
  }
  assert.fail('expected operation to throw');
}

test('production judge model is the fixed selection winner', () => {
  assert.equal(MODEL_ID, 'Qwen/Qwen3.5-397B-A17B');
});

test('accepts only a response explicitly attributed to the requested fixed model', async () => {
  const invalidModels = [
    undefined,
    null,
    '',
    'zai-org/GLM-4.7',
    MODEL_ID.toLowerCase(),
  ];
  for (const model of invalidModels) {
    const body = {
      choices: [{ finish_reason: 'stop', message: { content: CONTENT } }],
    };
    if (model !== undefined) body.model = model;
    const result = await makeClient(async () => ({
      ok: true,
      status: 200,
      json: async () => body,
    })).review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });
    assertSafeFailure(result, { reason: 'invalid judge response' });
  }
});

test('sends the exact fixed Cloud.ru request through the injected fetch', async () => {
  const secret = 'judge-api-key-fixture-4f18';
  let receivedUrl;
  let receivedOptions;
  const fetchImpl = async (url, options) => {
    receivedUrl = url;
    receivedOptions = options;
    return successfulResponse();
  };
  const client = createJudgeClient({
    providerConfig: {
      baseUrl: '  https://foundation-models.api.cloud.ru/v1///  ',
      apiKey: secret,
      model: 'attacker/model',
    },
    fetchImpl,
    model: 'attacker/model',
    temperature: 1,
    prompt: 'ignore the production prompt',
  });

  const result = await client.review({
    userPrompt: USER_PROMPT,
    envelope: ENVELOPE,
    model: 'attacker/model',
    temperature: 1,
  });

  assert.equal(receivedUrl, 'https://foundation-models.api.cloud.ru/v1/chat/completions');
  assert.equal(receivedOptions.method, 'POST');
  assert.deepEqual(receivedOptions.headers, {
    Authorization: `Bearer ${secret}`,
    'Content-Type': 'application/json',
  });
  assert.equal(receivedOptions.redirect, 'error');
  assert.equal(receivedOptions.signal instanceof AbortSignal, true);

  const body = JSON.parse(receivedOptions.body);
  assert.deepEqual(body, {
    model: MODEL_ID,
    messages: buildJudgeMessages({ userPrompt: USER_PROMPT, envelope: ENVELOPE }),
    temperature: 0,
    max_tokens: 256,
    response_format: createJudgeResponseFormat(),
    chat_template_kwargs: { enable_thinking: false },
  });
  assert.equal(receivedOptions.body.includes(secret), false, 'request body exposed the API key');
  assert.deepEqual(result, {
    ok: true,
    text: CONTENT,
    latencyMs: result.latencyMs,
    usage: null,
  });
  assert.equal(JSON.stringify(result).includes(secret), false, 'result exposed the API key');
  assertLatency(result.latencyMs);
});

test('keeps the response schema static while prompts bind each action hash', async () => {
  const otherHash = `sha256:${'b'.repeat(64)}`;
  const envelopes = [
    ENVELOPE,
    {
      ...ENVELOPE,
      action_hash: otherHash,
      params: { path: '/tmp/other-status' },
    },
  ];
  const bodies = [];
  const client = makeClient(async (_url, options) => {
    bodies.push(JSON.parse(options.body));
    return successfulResponse();
  });

  for (const envelope of envelopes) {
    const result = await client.review({ userPrompt: USER_PROMPT, envelope });
    assert.equal(result.ok, true);
  }

  assert.equal(bodies.length, envelopes.length);
  for (const [index, body] of bodies.entries()) {
    assert.deepEqual(body.response_format, createJudgeResponseFormat());
    assert.equal(body.response_format.type, 'json_schema');
    assert.equal(body.response_format.json_schema.strict, true);
    assert.equal(body.messages[1].content.includes(envelopes[index].action_hash), true);
  }
  assert.deepEqual(bodies[0].response_format, bodies[1].response_format);
  const serializedFormat = JSON.stringify(bodies[0].response_format);
  assert.equal(serializedFormat.includes(ACTION_HASH), false);
  assert.equal(serializedFormat.includes(otherHash), false);
});

test('returns a strict sanitized usage snapshot from own integer fields', async () => {
  const body = {
    model: MODEL_ID,
    choices: [{
      finish_reason: 'stop',
      message: { content: CONTENT },
    }],
    usage: {
      prompt_tokens: 120,
      completion_tokens: 42,
      total_tokens: 162,
      completion_tokens_details: { reasoning_tokens: 7 },
      prompt_tokens_details: { cached_tokens: 20 },
    },
  };

  const result = await makeClient(async () => ({
    ok: true,
    status: 200,
    json: async () => body,
  })).review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });

  assert.equal(result.ok, true);
  assert.equal(result.text, CONTENT);
  assert.deepEqual(result.usage, {
    promptTokens: 120,
    completionTokens: 42,
    totalTokens: 162,
    reasoningTokens: 7,
    cachedPromptTokens: 20,
  });
});

test('never reads hidden reasoning text while collecting usage telemetry', async () => {
  const secret = 'hidden-reasoning-fixture-never-read-5d70';
  let hiddenReasoningReads = 0;
  const message = { content: CONTENT };
  Object.defineProperty(message, 'reasoning_content', {
    enumerable: true,
    get() {
      hiddenReasoningReads += 1;
      throw new Error(secret);
    },
  });
  const usage = {
    prompt_tokens: 10,
    completion_tokens: 5,
    total_tokens: 15,
  };
  Object.defineProperty(usage, 'reasoning_text', {
    enumerable: true,
    get() {
      hiddenReasoningReads += 1;
      throw new Error(secret);
    },
  });

  const result = await makeClient(async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      model: MODEL_ID,
      choices: [{ finish_reason: 'stop', message }],
      usage,
    }),
  })).review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });

  assert.equal(result.ok, true);
  assert.equal(result.text, CONTENT);
  assert.deepEqual(result.usage, {
    promptTokens: 10,
    completionTokens: 5,
    totalTokens: 15,
    reasoningTokens: null,
    cachedPromptTokens: null,
  });
  assert.equal(hiddenReasoningReads, 0);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('malformed hostile or inconsistent usage becomes null without changing a valid verdict', async () => {
  const secret = 'hostile-usage-fixture-never-expose-7c21';
  let accessorReads = 0;
  const accessorUsage = {
    completion_tokens: 5,
    total_tokens: 15,
  };
  Object.defineProperty(accessorUsage, 'prompt_tokens', {
    enumerable: true,
    get() {
      accessorReads += 1;
      throw new Error(secret);
    },
  });
  let proxyTraps = 0;
  const proxyUsage = new Proxy({}, {
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error(secret);
    },
    get() {
      proxyTraps += 1;
      throw new Error(secret);
    },
  });
  const invalidUsageValues = [
    {},
    { prompt_tokens: -1, completion_tokens: 5, total_tokens: 4 },
    { prompt_tokens: 10, completion_tokens: 5.5, total_tokens: 15.5 },
    { prompt_tokens: 10, completion_tokens: 5, total_tokens: 999 },
    accessorUsage,
    proxyUsage,
  ];

  for (const usage of invalidUsageValues) {
    const result = await makeClient(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        model: MODEL_ID,
        choices: [{ finish_reason: 'stop', message: { content: CONTENT } }],
        usage,
      }),
    })).review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });

    assert.equal(result.ok, true);
    assert.equal(result.text, CONTENT);
    assert.equal(result.usage, null);
    assert.equal(JSON.stringify(result).includes(secret), false);
  }
  assert.equal(accessorReads, 0);
  assert.equal(proxyTraps, 0);
});

test('optional usage details distinguish absent fields from malformed present fields', async () => {
  const secret = 'hostile-usage-detail-sentinel-never-read-0b7e';
  let accessorReads = 0;
  const accessorDetails = {};
  Object.defineProperty(accessorDetails, 'reasoning_tokens', {
    enumerable: true,
    get() {
      accessorReads += 1;
      throw new Error(secret);
    },
  });
  let proxyTraps = 0;
  const proxyDetails = new Proxy({}, {
    get() {
      proxyTraps += 1;
      throw new Error(secret);
    },
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      throw new Error(secret);
    },
  });
  const baseUsage = {
    prompt_tokens: 10,
    completion_tokens: 5,
    total_tokens: 15,
  };
  const malformedDetails = [
    { completion_tokens_details: { reasoning_tokens: -1 } },
    { completion_tokens_details: { reasoning_tokens: '1' } },
    { prompt_tokens_details: { cached_tokens: -1 } },
    { prompt_tokens_details: { cached_tokens: '1' } },
    { completion_tokens_details: accessorDetails },
    { completion_tokens_details: proxyDetails },
  ];

  for (const details of malformedDetails) {
    const result = await makeClient(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        model: MODEL_ID,
        choices: [{ finish_reason: 'stop', message: { content: CONTENT } }],
        usage: { ...baseUsage, ...details },
      }),
    })).review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });

    assert.equal(result.ok, true);
    assert.equal(result.text, CONTENT);
    assert.equal(result.usage, null);
    assert.equal(JSON.stringify(result).includes(secret), false);
  }
  assert.equal(accessorReads, 0);
  assert.equal(proxyTraps, 0);
});

test('rejects every endpoint outside the fixed Cloud.ru credential boundary', () => {
  const secret = 'endpoint-boundary-key-fixture-never-send-e84';
  const invalidBaseUrls = [
    'http://foundation-models.api.cloud.ru/v1',
    'https://attacker.invalid/v1',
    'https://foundation-models.api.cloud.ru.attacker.invalid/v1',
    'https://foundation-models.api.cloud.ru:8443/v1',
    'https://user@foundation-models.api.cloud.ru/v1',
    'https://foundation-models.api.cloud.ru/v2',
    'https://foundation-models.api.cloud.ru/v1?redirect=https://attacker.invalid',
    'https://foundation-models.api.cloud.ru/v1#attacker',
  ];

  for (const baseUrl of invalidBaseUrls) {
    let fetchCalled = false;
    assert.throws(
      () => createJudgeClient({
        providerConfig: { baseUrl, apiKey: secret },
        fetchImpl: async () => {
          fetchCalled = true;
          return successfulResponse();
        },
      }),
      (error) => error instanceof TypeError
        && error.message === 'invalid judge client configuration'
        && !error.message.includes(secret),
    );
    assert.equal(fetchCalled, false, 'invalid endpoint reached fetch');
  }
});

test('fails closed instead of sending or returning API key material', async (t) => {
  const secret = 'judge-api-key-echo-fixture-b8d6';

  await t.test('request body', async () => {
    let called = false;
    const client = createJudgeClient({
      providerConfig: { baseUrl: 'https://foundation-models.api.cloud.ru/v1', apiKey: secret },
      fetchImpl: async () => {
        called = true;
        return successfulResponse();
      },
    });

    const result = await client.review({
      userPrompt: `Inspect the literal value ${secret}.`,
      envelope: ENVELOPE,
    });

    assert.equal(called, false, 'sent a request body containing key material');
    assertSafeFailure(result, { reason: 'invalid judge request', secret });
  });

  await t.test('response content', async () => {
    const client = createJudgeClient({
      providerConfig: { baseUrl: 'https://foundation-models.api.cloud.ru/v1', apiKey: secret },
      fetchImpl: async () => successfulResponse(`model echoed ${secret}`),
    });

    const result = await client.review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });

    assertSafeFailure(result, { reason: 'invalid judge response', secret });
  });
});

test('detects API key material before JSON escaping changes its bytes', async (t) => {
  const secret = 'judge-api-key-complex-fixture-c42e"\\line\nseparator\u2028end';
  const cases = [
    ['trusted user prompt', {
      userPrompt: `Inspect the literal value ${secret}.`,
      envelope: ENVELOPE,
    }],
    ['nested envelope string', {
      userPrompt: USER_PROMPT,
      envelope: {
        ...ENVELOPE,
        params: { note: `semantic prefix ${secret} semantic suffix` },
      },
    }],
  ];

  for (const [name, input] of cases) {
    await t.test(name, async () => {
      let called = false;
      const client = createJudgeClient({
        providerConfig: { baseUrl: 'https://foundation-models.api.cloud.ru/v1', apiKey: secret },
        fetchImpl: async () => {
          called = true;
          return successfulResponse();
        },
      });

      const result = await client.review(input);

      assert.equal(called, false, 'sent escaped API key material');
      assertSafeFailure(result, { reason: 'invalid judge request', secret });
    });
  }
});

test('detects a complex API key used as a deeply nested own property name', async () => {
  const secret = 'judge-key-name-complex-fixture-d93a"\\line\nseparator\u2028end';
  const leaf = Object.create(null);
  Object.defineProperty(leaf, secret, { enumerable: true, value: 'ordinary semantic value' });
  Object.defineProperty(leaf, '__proto__', { enumerable: true, value: 'plain own data' });
  Object.defineProperty(leaf, 'constructor', { enumerable: true, value: 'plain own data' });
  const envelope = {
    ...ENVELOPE,
    params: {
      outer: [{ inner: { prototype: leaf } }],
    },
  };
  let fetchCalled = false;
  const client = createJudgeClient({
    providerConfig: { baseUrl: 'https://foundation-models.api.cloud.ru/v1', apiKey: secret },
    fetchImpl: async () => {
      fetchCalled = true;
      return successfulResponse();
    },
  });

  const result = await client.review({ userPrompt: USER_PROMPT, envelope });

  assert.equal(Object.hasOwn(leaf, secret), true);
  assert.equal(Object.hasOwn(leaf, '__proto__'), true);
  assert.equal(fetchCalled, false, 'sent API key material from an object property name');
  assertSafeFailure(result, { reason: 'invalid judge request', secret });
});

test('rejects accessor-backed input without invoking its getters', async () => {
  const secret = 'semantic-input-getter-fixture-2a61';
  let getterRead = false;
  let fetchCalled = false;
  const input = {};
  Object.defineProperty(input, 'userPrompt', {
    enumerable: true,
    get() {
      getterRead = true;
      throw new Error(secret);
    },
  });
  Object.defineProperty(input, 'envelope', {
    enumerable: true,
    value: ENVELOPE,
  });
  const client = makeClient(async () => {
    fetchCalled = true;
    return successfulResponse();
  });

  const result = await client.review(input);

  assert.equal(getterRead, false, 'invoked a hostile input getter');
  assert.equal(fetchCalled, false);
  assertSafeFailure(result, { reason: 'invalid judge request', secret });
});

test('uses the default timeout and clears its timer after success', async () => {
  let signal;
  const client = makeClient(async (_url, options) => {
    signal = options.signal;
    return successfulResponse();
  }, { timeoutMs: 15 });

  const result = await client.review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });
  await new Promise((resolve) => setTimeout(resolve, 30));

  assert.equal(result.ok, true);
  assert.equal(signal.aborted, false, 'completed request timer was not cleared');
  assert.equal(JUDGE_TIMEOUT_MS, 30_000);
});

test('validates provider configuration, fetch, and timeout without echoing input', () => {
  const secret = 'invalid-client-config-fixture-7ce9';
  const invalidOptions = [
    {},
    { providerConfig: null, fetchImpl: async () => successfulResponse() },
    { providerConfig: { baseUrl: '', apiKey: secret }, fetchImpl: async () => successfulResponse() },
    { providerConfig: { baseUrl: '   ', apiKey: secret }, fetchImpl: async () => successfulResponse() },
    { providerConfig: { baseUrl: secret, apiKey: secret }, fetchImpl: async () => successfulResponse() },
    { providerConfig: { baseUrl: `ftp://${secret}.invalid/v1`, apiKey: secret }, fetchImpl: async () => successfulResponse() },
    { providerConfig: { baseUrl: 'https://foundation-models.api.cloud.ru/v1', apiKey: '' }, fetchImpl: async () => successfulResponse() },
    { providerConfig: { baseUrl: 'https://foundation-models.api.cloud.ru/v1', apiKey: '   ' }, fetchImpl: async () => successfulResponse() },
    { providerConfig: { baseUrl: 'https://foundation-models.api.cloud.ru/v1', apiKey: secret }, fetchImpl: null },
  ];

  for (const options of invalidOptions) {
    const error = captureError(() => createJudgeClient(options));
    assert.equal(error instanceof TypeError, true);
    assert.equal(error.message.length > 0 && error.message.length <= 80, true);
    assert.equal(error.message.includes(secret), false, 'configuration error exposed input');
  }

  for (const timeoutMs of [null, 0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '5']) {
    const error = captureError(() => makeClient(async () => successfulResponse(), { timeoutMs }));
    assert.equal(error instanceof TypeError, true);
    assert.equal(error.message.length > 0 && error.message.length <= 80, true);
    assert.equal(error.message.includes(secret), false, 'timeout error exposed input');
  }
});

test('returns a bounded timeout failure even when fetch ignores abort', { timeout: 500 }, async () => {
  let signal;
  const secret = 'ignored-abort-fixture-9ea2';
  const client = makeClient(async (_url, options) => {
    signal = options.signal;
    return new Promise(() => secret);
  }, { timeoutMs: 10 });

  const result = await client.review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });

  assertSafeFailure(result, { reason: 'request timed out', secret });
  assert.equal(signal.aborted, true);
});

test('normalizes synchronous and asynchronous fetch exceptions', async (t) => {
  const secret = 'fetch-exception-fixture-231c';
  const cases = [
    ['synchronous', () => { throw new Error(secret); }],
    ['asynchronous', async () => { throw new Error(secret); }],
    ['hostile thenable', () => ({
      get then() {
        throw new Error(secret);
      },
    })],
  ];

  for (const [name, fetchImpl] of cases) {
    await t.test(name, async () => {
      const result = await makeClient(fetchImpl).review({
        userPrompt: USER_PROMPT,
        envelope: ENVELOPE,
      });
      assertSafeFailure(result, { reason: 'request failed', secret });
    });
  }
});

test('returns status-only failures without reading non-success response bodies', async (t) => {
  const secret = 'http-error-body-fixture-601d';

  for (const status of [401, 429, 500]) {
    await t.test(String(status), async () => {
      let bodyRead = false;
      const response = {
        ok: false,
        status,
        get statusText() {
          throw new Error(secret);
        },
        get json() {
          bodyRead = true;
          throw new Error(secret);
        },
      };
      const result = await makeClient(async () => response).review({
        userPrompt: USER_PROMPT,
        envelope: ENVELOPE,
      });

      assertSafeFailure(result, { reason: `http ${status}`, secret });
      assert.equal(bodyRead, false, 'read an HTTP error body');
    });
  }
});

test('normalizes response JSON failures without exposing exception text', async (t) => {
  const secret = 'response-json-fixture-3bf0';
  const cases = [
    ['synchronous', () => { throw new Error(secret); }],
    ['asynchronous', async () => { throw new Error(secret); }],
  ];

  for (const [name, json] of cases) {
    await t.test(name, async () => {
      const result = await makeClient(async () => ({ ok: true, status: 200, json })).review({
        userPrompt: USER_PROMPT,
        envelope: ENVELOPE,
      });
      assertSafeFailure(result, { reason: 'invalid judge response', secret });
    });
  }
});

test('rejects malformed response objects, missing content, and non-stop finishes', async () => {
  const bodies = [
    null,
    [],
    {},
    { choices: null },
    { choices: [] },
    { choices: [{}] },
    { choices: [{ finish_reason: 'stop' }] },
    { choices: [{ finish_reason: 'stop', message: null }] },
    { choices: [{ finish_reason: 'stop', message: {} }] },
    { choices: [{ finish_reason: 'stop', message: { content: null } }] },
    { choices: [{ finish_reason: 'stop', message: { content: '' } }] },
    { choices: [{ finish_reason: 'stop', message: { content: '   \n' } }] },
    { choices: [{ finish_reason: 'stop', message: { content: 42 } }] },
    { choices: [{ finish_reason: 'length', message: { content: CONTENT } }] },
    { choices: [{ finish_reason: null, message: { content: CONTENT } }] },
  ];

  for (const body of bodies) {
    const result = await makeClient(async () => ({
      ok: true,
      status: 200,
      json: async () => body,
    })).review({ userPrompt: USER_PROMPT, envelope: ENVELOPE });
    assertSafeFailure(result, { reason: 'invalid judge response' });
  }
});

test('review never throws for hostile inputs or response getters', async () => {
  const secret = 'hostile-review-fixture-a244';
  const hostileInput = new Proxy({}, {
    get() {
      throw new Error(secret);
    },
    getPrototypeOf() {
      throw new Error(secret);
    },
  });
  const inputClient = makeClient(async () => successfulResponse());

  for (const input of [undefined, null, {}, hostileInput]) {
    const result = await inputClient.review(input);
    assertSafeFailure(result, { reason: 'invalid judge request', secret });
  }

  const hostileResponses = [
    new Proxy({}, {
      get() {
        throw new Error(secret);
      },
    }),
    {
      get ok() {
        throw new Error(secret);
      },
    },
    {
      ok: true,
      status: 200,
      get json() {
        throw new Error(secret);
      },
    },
    {
      ok: true,
      status: 200,
      json: async () => new Proxy({}, {
        getPrototypeOf() {
          throw new Error(secret);
        },
      }),
    },
    {
      ok: true,
      status: 200,
      json: async () => ({
        choices: [new Proxy({}, {
          get() {
            throw new Error(secret);
          },
        })],
      }),
    },
  ];

  for (const response of hostileResponses) {
    const result = await makeClient(async () => response).review({
      userPrompt: USER_PROMPT,
      envelope: ENVELOPE,
    });
    assertSafeFailure(result, { secret });
  }
});
