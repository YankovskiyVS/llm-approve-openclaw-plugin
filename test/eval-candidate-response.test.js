import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCandidateResponse } from '../evals/lib/candidate-response.mjs';

const CONTENT = '{"decision":"allow"}';

function responseWith({ content = CONTENT, finishReason = 'stop', usage } = {}) {
  const response = {
    choices: [{
      finish_reason: finishReason,
      message: { content },
    }],
  };
  if (usage !== undefined) response.usage = usage;
  return response;
}

function hostileProxy(counter) {
  return new Proxy({}, {
    get() {
      counter.count += 1;
      throw new Error('proxy value must not be read');
    },
    getOwnPropertyDescriptor() {
      counter.count += 1;
      throw new Error('proxy descriptor must not be read');
    },
    getPrototypeOf() {
      counter.count += 1;
      throw new Error('proxy prototype must not be read');
    },
    ownKeys() {
      counter.count += 1;
      throw new Error('proxy keys must not be read');
    },
  });
}

test('accepts only the first stopped choice content and returns a frozen snapshot', () => {
  const parsed = parseCandidateResponse(responseWith());

  assert.deepEqual(parsed, { text: CONTENT, usage: null });
  assert.deepEqual(Object.keys(parsed), ['text', 'usage']);
  assert.equal(Object.isFrozen(parsed), true);
});

test('enforces the 4096 UTF-16 code-unit content boundary', () => {
  const atLimit = 'я'.repeat(4096);

  assert.equal(parseCandidateResponse(responseWith({ content: atLimit })).text, atLimit);
  assert.equal(parseCandidateResponse(responseWith({ content: 'x'.repeat(4097) })), null);
});

test('rejects empty content and non-stop responses without reasoning fallback', () => {
  for (const content of [null, '', '   ', 7, {}, new String(CONTENT)]) {
    assert.equal(parseCandidateResponse(responseWith({ content })), null);
  }
  for (const finishReason of [null, 'length', 'tool_calls', 'stop ']) {
    assert.equal(parseCandidateResponse(responseWith({ finishReason })), null);
  }

  let reasoningReads = 0;
  const message = { content: null };
  Object.defineProperty(message, 'reasoning_content', {
    enumerable: true,
    get() {
      reasoningReads += 1;
      return CONTENT;
    },
  });
  const result = parseCandidateResponse({
    choices: [{ finish_reason: 'stop', message }],
  });

  assert.equal(result, null);
  assert.equal(reasoningReads, 0);
});

test('rejects missing, multiple, sparse, accessor-backed, or hostile choices', () => {
  for (const choices of [undefined, null, {}, [], [responseWith().choices[0], {}]]) {
    const value = choices === undefined ? {} : { choices };
    assert.equal(parseCandidateResponse(value), null);
  }

  let accessorReads = 0;
  const accessorChoices = [];
  accessorChoices.length = 1;
  Object.defineProperty(accessorChoices, '0', {
    enumerable: true,
    get() {
      accessorReads += 1;
      return responseWith().choices[0];
    },
  });
  assert.equal(parseCandidateResponse({ choices: accessorChoices }), null);
  assert.equal(accessorReads, 0);

  const proxyReads = { count: 0 };
  const multiple = [responseWith().choices[0], hostileProxy(proxyReads)];
  assert.equal(parseCandidateResponse({ choices: multiple }), null);
  assert.equal(proxyReads.count, 0);
});

test('never triggers proxies or accessors in the response hierarchy', () => {
  const proxyReads = { count: 0 };
  const proxy = hostileProxy(proxyReads);
  for (const value of [
    proxy,
    { choices: proxy },
    { choices: [proxy] },
    { choices: [{ finish_reason: 'stop', message: proxy }] },
  ]) {
    assert.equal(parseCandidateResponse(value), null);
  }
  assert.equal(proxyReads.count, 0);

  let accessorReads = 0;
  const accessor = () => {
    accessorReads += 1;
    throw new Error('accessor must not be read');
  };
  const root = {};
  Object.defineProperty(root, 'choices', { enumerable: true, get: accessor });
  const choice = { message: { content: CONTENT } };
  Object.defineProperty(choice, 'finish_reason', { enumerable: true, get: accessor });
  const message = {};
  Object.defineProperty(message, 'content', { enumerable: true, get: accessor });

  assert.equal(parseCandidateResponse(root), null);
  assert.equal(parseCandidateResponse({ choices: [choice] }), null);
  assert.equal(parseCandidateResponse({
    choices: [{ finish_reason: 'stop', message }],
  }), null);
  assert.equal(accessorReads, 0);
});

test('returns a frozen strict usage snapshot without reading raw reasoning', () => {
  let hiddenReasoningReads = 0;
  const message = { content: CONTENT };
  Object.defineProperty(message, 'reasoning_content', {
    enumerable: true,
    get() {
      hiddenReasoningReads += 1;
      throw new Error('raw reasoning must not be read');
    },
  });
  const usage = {
    prompt_tokens: 120,
    completion_tokens: 42,
    total_tokens: 162,
    completion_tokens_details: { reasoning_tokens: 7 },
    prompt_tokens_details: { cached_tokens: 20 },
  };
  Object.defineProperty(usage, 'reasoning_content', {
    enumerable: true,
    get() {
      hiddenReasoningReads += 1;
      throw new Error('raw reasoning must not be read');
    },
  });

  const parsed = parseCandidateResponse({
    choices: [{ finish_reason: 'stop', message }],
    usage,
  });

  assert.deepEqual(parsed, {
    text: CONTENT,
    usage: {
      promptTokens: 120,
      completionTokens: 42,
      totalTokens: 162,
      reasoningTokens: 7,
      cachedPromptTokens: 20,
    },
  });
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.usage), true);
  assert.equal(hiddenReasoningReads, 0);
});

test('keeps valid content while invalid or hostile usage becomes null', () => {
  let accessorReads = 0;
  const accessorUsage = {
    completion_tokens: 5,
    total_tokens: 15,
  };
  Object.defineProperty(accessorUsage, 'prompt_tokens', {
    enumerable: true,
    get() {
      accessorReads += 1;
      return 10;
    },
  });
  const proxyReads = { count: 0 };
  const invalidUsage = [
    null,
    {},
    [],
    { prompt_tokens: -1, completion_tokens: 5, total_tokens: 4 },
    { prompt_tokens: 10, completion_tokens: 5.5, total_tokens: 15.5 },
    { prompt_tokens: 10, completion_tokens: 5, total_tokens: 999 },
    accessorUsage,
    hostileProxy(proxyReads),
  ];

  for (const usage of invalidUsage) {
    assert.deepEqual(parseCandidateResponse(responseWith({ usage })), {
      text: CONTENT,
      usage: null,
    });
  }
  assert.equal(accessorReads, 0);
  assert.equal(proxyReads.count, 0);
});

test('rejects malformed optional token details without reading their accessors', () => {
  const base = {
    prompt_tokens: 10,
    completion_tokens: 5,
    total_tokens: 15,
  };
  let accessorReads = 0;
  const accessorDetails = {};
  Object.defineProperty(accessorDetails, 'reasoning_tokens', {
    enumerable: true,
    get() {
      accessorReads += 1;
      return 1;
    },
  });
  const malformed = [
    { completion_tokens_details: null },
    { completion_tokens_details: { reasoning_tokens: null } },
    { completion_tokens_details: { reasoning_tokens: -1 } },
    { completion_tokens_details: { reasoning_tokens: '1' } },
    { completion_tokens_details: { reasoning_tokens: 6 } },
    { prompt_tokens_details: { cached_tokens: null } },
    { prompt_tokens_details: { cached_tokens: -1 } },
    { prompt_tokens_details: { cached_tokens: '1' } },
    { prompt_tokens_details: { cached_tokens: 11 } },
    { completion_tokens_details: accessorDetails },
  ];

  for (const details of malformed) {
    const parsed = parseCandidateResponse(responseWith({
      usage: { ...base, ...details },
    }));
    assert.deepEqual(parsed, { text: CONTENT, usage: null });
  }
  assert.equal(accessorReads, 0);
});
