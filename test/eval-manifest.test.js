import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalStringify } from '../src/action.js';
import { POLICY_VERSION } from '../src/constants.js';
import {
  buildManifest,
  makeResumeKey,
} from '../evals/lib/manifest.mjs';

const BASE_MANIFEST = {
  schema_version: 'judge-benchmark.v2',
  git_sha: 'a'.repeat(40),
  node_version: 'v22.19.0',
  openclaw_version: '2026.6.11',
  model_id: 'zai-org/GLM-5.1',
  policy_version: POLICY_VERSION,
  corpus_sha256: 'sha256:' + 'c'.repeat(64),
  pricing_sha256: 'sha256:' + 'd'.repeat(64),
  source_sha256: {
    action: 'sha256:' + '1'.repeat(64),
    prompt: 'sha256:' + '2'.repeat(64),
    decision: 'sha256:' + '3'.repeat(64),
    redaction: 'sha256:' + '4'.repeat(64),
    constants: 'sha256:' + '5'.repeat(64),
    judge_client: 'sha256:' + '6'.repeat(64),
    harness: 'sha256:' + '7'.repeat(64),
  },
  endpoint_origin: 'https://foundation-models.api.cloud.ru',
  profile: {
    name: 'production',
    temperature: 0,
    max_tokens: 256,
    thinking: false,
    response_format: 'json_object',
    timeout_ms: 8000,
  },
};

const MANIFEST_KEYS = [
  'schema_version',
  'git_sha',
  'node_version',
  'openclaw_version',
  'model_id',
  'policy_version',
  'corpus_sha256',
  'pricing_sha256',
  'source_sha256',
  'endpoint_origin',
  'profile',
];

const CURRENT_CANDIDATE_MODEL_IDS = Object.freeze([
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

function manifestInput(overrides = {}) {
  const result = JSON.parse(JSON.stringify(BASE_MANIFEST));
  return Object.assign(result, overrides);
}

function reorderedManifestInput() {
  const source = manifestInput();
  source.source_sha256 = Object.fromEntries(Object.entries(source.source_sha256).reverse());
  source.profile = Object.fromEntries(Object.entries(source.profile).reverse());
  return Object.fromEntries(Object.entries(source).reverse());
}

function resumeTuple(overrides = {}) {
  return Object.assign({
    manifest_hash: 'sha256:' + 'a'.repeat(64),
    model: 'zai-org/GLM-5.1',
    case_id: 'case-a',
    repeat: 1,
    profile: 'production',
  }, overrides);
}

function sha256Canonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function assertSafeTypeError(run, secret, label) {
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

test('manifest hash is stable across key order and binds every accepted reproducibility field', () => {
  const first = buildManifest(manifestInput());
  const reordered = buildManifest(reorderedManifestInput());
  assert.equal(first.manifest_hash, reordered.manifest_hash);

  const { manifest_hash: ignored, ...content } = first;
  assert.equal(first.manifest_hash, sha256Canonical(content));

  for (const [field, value] of [
    ['git_sha', 'b'.repeat(40)],
    ['node_version', 'v22.20.0'],
    ['openclaw_version', '2026.6.12'],
    ['model_id', 'candidate/model-v2'],
    ['corpus_sha256', 'sha256:' + 'b'.repeat(64)],
    ['pricing_sha256', 'sha256:' + 'e'.repeat(64)],
  ]) {
    const changed = buildManifest(manifestInput({ [field]: value }));
    assert.notEqual(first.manifest_hash, changed.manifest_hash, field);
  }

  for (const [field, value] of [
    ['action', 'sha256:' + '5'.repeat(64)],
    ['prompt', 'sha256:' + '6'.repeat(64)],
    ['decision', 'sha256:' + '7'.repeat(64)],
    ['redaction', 'sha256:' + '8'.repeat(64)],
    ['constants', 'sha256:' + '9'.repeat(64)],
    ['judge_client', 'sha256:' + 'a'.repeat(64)],
    ['harness', 'sha256:' + 'b'.repeat(64)],
  ]) {
    const input = manifestInput();
    input.source_sha256[field] = value;
    assert.notEqual(first.manifest_hash, buildManifest(input).manifest_hash, field);
  }
});

test('buildManifest returns a deeply frozen defensive exact-schema snapshot', () => {
  const input = manifestInput();
  const result = buildManifest(input);

  assert.deepEqual(Object.keys(result).sort(), [...MANIFEST_KEYS, 'manifest_hash'].sort());
  assert.deepEqual(result.source_sha256, input.source_sha256);
  assert.deepEqual(result.profile, input.profile);
  assert.notEqual(result, input);
  assert.notEqual(result.source_sha256, input.source_sha256);
  assert.notEqual(result.profile, input.profile);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.source_sha256), true);
  assert.equal(Object.isFrozen(result.profile), true);
  assert.match(result.manifest_hash, /^sha256:[0-9a-f]{64}$/u);

  input.git_sha = 'f'.repeat(40);
  input.source_sha256.action = 'sha256:' + 'f'.repeat(64);
  input.profile.name = 'mutated';
  assert.equal(result.git_sha, 'a'.repeat(40));
  assert.equal(result.source_sha256.action, 'sha256:' + '1'.repeat(64));
  assert.equal(result.profile.name, 'production');
});

test('closed manifest excludes timestamps, host paths, credential fields, and userinfo endpoints', () => {
  const result = buildManifest(manifestInput());
  for (const forbidden of [
    'timestamp',
    'workspace_path',
    'apiKey',
    'token',
    'secret',
  ]) {
    assert.equal(Object.hasOwn(result, forbidden), false, forbidden);
    assert.throws(
      () => buildManifest(manifestInput({
        [forbidden]: forbidden === 'workspace_path'
          ? '/Users/example/private/workspace'
          : 'credential-sentinel-never-persist',
      })),
      TypeError,
      forbidden,
    );
  }

  for (const endpoint_origin of [
    'http://foundation-models.api.cloud.ru',
    'https://foundation-models.api.cloud.ru/',
    'https://foundation-models.api.cloud.ru/v1',
    'https://foundation-models.api.cloud.ru?token=credential-sentinel',
    'https://foundation-models.api.cloud.ru#fragment',
    'https://user:password@foundation-models.api.cloud.ru',
    'https://foundation-models.api.cloud.ru.evil.invalid',
  ]) {
    assert.throws(
      () => buildManifest(manifestInput({ endpoint_origin })),
      /invalid endpoint origin/,
      endpoint_origin,
    );
  }
});

test('manifest enforces Node and OpenClaw floors, candidate model IDs, and production policy', () => {
  for (const node_version of ['v22.19.0', 'v22.19.9', 'v22.20.0', 'v23.0.0']) {
    assert.equal(buildManifest(manifestInput({ node_version })).node_version, node_version);
  }
  for (const node_version of ['v22.18.99', 'v21.99.99', '22.19.0', 'v22.19', 'v22.19.0-rc.1']) {
    assert.throws(() => buildManifest(manifestInput({ node_version })), TypeError, node_version);
  }

  for (const openclaw_version of ['2026.6.11', '2026.6.12', '2026.7.1', '2027.1.1']) {
    assert.equal(
      buildManifest(manifestInput({ openclaw_version })).openclaw_version,
      openclaw_version,
    );
  }
  for (const openclaw_version of [
    '2026.6.10',
    '2025.12.31',
    'v2026.6.11',
    '2026.6',
    '2026.13.1',
    '2026.2.30',
  ]) {
    assert.throws(
      () => buildManifest(manifestInput({ openclaw_version })),
      TypeError,
      openclaw_version,
    );
  }

  assert.equal(CURRENT_CANDIDATE_MODEL_IDS.length, 19);
  for (const model_id of [
    ...CURRENT_CANDIDATE_MODEL_IDS,
    'candidate/model-v2',
    'provider:model',
    'a'.repeat(256),
  ]) {
    assert.equal(buildManifest(manifestInput({ model_id })).model_id, model_id);
  }
  for (const model_id of [
    '',
    '   ',
    'candidate\u0000model',
    'Bearer credential-sentinel',
    'candidate?apiKey=credential-sentinel',
    'provider/api_key=credential-sentinel',
    'provider\\api_key=credential-sentinel',
    'https://user:password@example.invalid/model',
    'provider:https://user:password@example.invalid/model',
    '/Users/example/private/model',
    'provider:/Users/example/private/model',
    'C:\\Users\\example\\private-model',
    'provider:C:\\Users\\example\\private-model',
    'provider:\\Users\\example\\private-model',
    'file:///Users/example/private/model',
    'provider:file:///Users/example/private/model',
    ' /Users/example/private/model',
    'candidate/model-v2 ',
    'provider@model',
    'provider=model',
    'provider model',
    'provider//model',
    'provider::model',
    '/provider',
    'provider/',
    ':provider',
    'provider:',
    'provider/./model',
    'provider/../model',
    '.hidden/model',
    'provider/.hidden',
    '_provider/model',
    '-provider/model',
    'a'.repeat(257),
  ]) {
    assert.throws(
      () => buildManifest(manifestInput({ model_id })),
      (error) => error instanceof TypeError
        && error.message.length < 80
        && !error.message.includes('credential-sentinel')
        && !error.message.includes('/Users')
        && !error.message.includes('\\Users'),
      model_id,
    );
  }

  assert.equal(buildManifest(manifestInput()).policy_version, POLICY_VERSION);
  assert.throws(
    () => buildManifest(manifestInput({ policy_version: `${POLICY_VERSION}-candidate` })),
    /invalid policy version/,
  );
});

test('manifest rejects missing, unknown, accessor-backed, and malformed nested fields', () => {
  for (const field of MANIFEST_KEYS) {
    const input = manifestInput();
    delete input[field];
    assert.throws(() => buildManifest(input), TypeError, field);
  }
  assert.throws(() => buildManifest(manifestInput({ unknown: true })), TypeError);

  for (const field of [
    'action', 'prompt', 'decision', 'redaction', 'constants', 'judge_client', 'harness',
  ]) {
    const input = manifestInput();
    delete input.source_sha256[field];
    assert.throws(() => buildManifest(input), TypeError, field);
  }
  assert.throws(() => buildManifest(manifestInput({
    source_sha256: Object.assign({}, BASE_MANIFEST.source_sha256, {
      plugin: 'sha256:' + '8'.repeat(64),
    }),
  })), TypeError);
  for (const field of [
    'name',
    'temperature',
    'max_tokens',
    'thinking',
    'response_format',
    'timeout_ms',
  ]) {
    const input = manifestInput();
    delete input.profile[field];
    assert.throws(() => buildManifest(input), TypeError, field);
  }
  assert.throws(() => buildManifest(manifestInput({
    profile: Object.assign({}, BASE_MANIFEST.profile, { retries: 1 }),
  })), TypeError);

  const invalidHashes = [
    'sha256:' + 'a'.repeat(63),
    'sha256:' + 'A'.repeat(64),
    'md5:' + 'a'.repeat(64),
    1,
  ];
  for (const value of invalidHashes) {
    assert.throws(
      () => buildManifest(manifestInput({ corpus_sha256: value })),
      TypeError,
    );
  }
  assert.throws(() => buildManifest(manifestInput({ git_sha: 'A'.repeat(40) })), TypeError);

  for (const [field, value] of [
    ['name', 'candidate'],
    ['temperature', 0.1],
    ['max_tokens', 255],
    ['thinking', true],
    ['response_format', 'text'],
    ['timeout_ms', 5001],
  ]) {
    const input = manifestInput();
    input.profile[field] = value;
    assert.throws(() => buildManifest(input), /invalid production profile/, field);
  }
});

test('manifest validation never executes getters or Proxy traps and emits bounded TypeErrors', () => {
  const secret = 'hostile-manifest-sentinel-never-print';
  let reads = 0;
  const accessor = manifestInput();
  Object.defineProperty(accessor, 'model_id', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error(secret);
    },
  });
  assertSafeTypeError(() => buildManifest(accessor), secret, 'top-level accessor');
  assert.equal(reads, 0);

  const nestedAccessor = manifestInput();
  Object.defineProperty(nestedAccessor.source_sha256, 'action', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error(secret);
    },
  });
  assertSafeTypeError(() => buildManifest(nestedAccessor), secret, 'nested accessor');
  assert.equal(reads, 0);

  let trapCalls = 0;
  const hostile = new Proxy({}, {
    get() {
      trapCalls += 1;
      throw new Error(secret);
    },
    getPrototypeOf() {
      trapCalls += 1;
      throw new Error(secret);
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error(secret);
    },
  });
  assertSafeTypeError(() => buildManifest(hostile), secret, 'root Proxy');
  const nestedProxy = manifestInput({ source_sha256: hostile });
  assertSafeTypeError(() => buildManifest(nestedProxy), secret, 'nested Proxy');
  assert.equal(trapCalls, 0);

  const symbolInput = manifestInput();
  symbolInput[Symbol(secret)] = secret;
  assertSafeTypeError(() => buildManifest(symbolInput), secret, 'symbol field');
  assertSafeTypeError(() => buildManifest(Array(12)), secret, 'sparse array');
});

test('resume key binds its canonical tuple without delimiter collisions', () => {
  const first = makeResumeKey(resumeTuple({ model: 'model:a', case_id: 'b' }));
  const second = makeResumeKey(resumeTuple({ model: 'model', case_id: 'a:b' }));
  assert.notEqual(first, second);
  assert.match(first, /^sha256:[0-9a-f]{64}$/u);

  const canonical = resumeTuple();
  const reordered = Object.fromEntries(Object.entries(canonical).reverse());
  assert.equal(makeResumeKey(canonical), makeResumeKey(reordered));
  assert.equal(makeResumeKey(canonical), sha256Canonical(canonical));

  for (const [field, value] of [
    ['manifest_hash', 'sha256:' + 'b'.repeat(64)],
    ['model', 'candidate/model-v2'],
    ['case_id', 'case-b'],
    ['repeat', 2],
    ['profile', 'candidate'],
  ]) {
    assert.notEqual(makeResumeKey(canonical), makeResumeKey(resumeTuple({ [field]: value })), field);
  }
});

test('resume tuple is exact, bounded, and safely rejects hostile values', () => {
  for (const field of ['manifest_hash', 'model', 'case_id', 'repeat', 'profile']) {
    const tuple = resumeTuple();
    delete tuple[field];
    assert.throws(() => makeResumeKey(tuple), TypeError, field);
  }
  assert.throws(() => makeResumeKey(resumeTuple({ timestamp: 1 })), TypeError);
  assert.throws(() => makeResumeKey(resumeTuple({ manifest_hash: 'A'.repeat(64) })), TypeError);
  for (const field of ['model', 'case_id', 'profile']) {
    assert.throws(() => makeResumeKey(resumeTuple({ [field]: '   ' })), TypeError, field);
  }
  for (const repeat of [0, 11, 1.5, true, '1']) {
    assert.throws(() => makeResumeKey(resumeTuple({ repeat })), /invalid repeat/, repeat);
  }

  const secret = 'hostile-resume-sentinel-never-print';
  let reads = 0;
  const accessor = resumeTuple();
  Object.defineProperty(accessor, 'case_id', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error(secret);
    },
  });
  assertSafeTypeError(() => makeResumeKey(accessor), secret, 'resume accessor');
  assert.equal(reads, 0);

  let trapCalls = 0;
  const hostile = new Proxy({}, {
    get() {
      trapCalls += 1;
      throw new Error(secret);
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error(secret);
    },
  });
  assertSafeTypeError(() => makeResumeKey(hostile), secret, 'resume Proxy');
  assert.equal(trapCalls, 0);
  assertSafeTypeError(() => makeResumeKey(Array(5)), secret, 'resume sparse array');
});
