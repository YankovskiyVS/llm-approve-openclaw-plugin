import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveRuntimeSettings } from '../src/environment.js';
import {
  CLOUDRU_BASE_URL,
  JUDGE_TIMEOUT_MS,
  MAX_JUDGE_TIMEOUT_MS,
  MIN_JUDGE_TIMEOUT_MS,
} from '../src/constants.js';

const SHARED_KEY = 'shared-provider-key-fixture';
const DEDICATED_KEY = 'dedicated-judge-key-fixture';
const VALID_PROVIDER = Object.freeze({
  baseUrl: 'https://foundation-models.api.cloud.ru/v1',
  apiKey: SHARED_KEY,
});

function resolve(overrides = {}) {
  return resolveRuntimeSettings({
    environment: {},
    pluginConfig: undefined,
    getSharedProvider: () => VALID_PROVIDER,
    homeDirectory: '/home/tester',
    ...overrides,
  });
}

function captureError(operation) {
  try {
    operation();
  } catch (error) {
    return error;
  }
  assert.fail('expected invalid environment configuration');
}

function assertInvalid(options, forbidden = []) {
  const error = captureError(() => resolve(options));
  assert.equal(error instanceof TypeError, true);
  assert.equal(error.message, 'invalid judge environment configuration');
  for (const value of forbidden) {
    if (value === '') continue;
    assert.equal(error.message.includes(value), false);
  }
}

test('uses detached immutable legacy defaults and shared provider', () => {
  const provider = { ...VALID_PROVIDER };
  const settings = resolve({ getSharedProvider: () => provider });

  assert.deepEqual(settings, {
    config: { mode: 'autonomous', enforcement: 'shadow' },
    providerConfig: { baseUrl: CLOUDRU_BASE_URL, apiKey: SHARED_KEY },
    credentialSource: 'shared-provider',
    timeoutMs: JUDGE_TIMEOUT_MS,
    auditPath: '/home/tester/.openclaw/logs/llm-action-judge.jsonl',
    auditRoot: '/home/tester/.openclaw/logs',
    logLevel: 'info',
  });
  assert.equal(Object.isFrozen(settings), true);
  assert.equal(Object.isFrozen(settings.config), true);
  assert.equal(Object.isFrozen(settings.providerConfig), true);
  provider.apiKey = 'mutated-key';
  assert.equal(settings.providerConfig.apiKey, SHARED_KEY);
});

test('maps exact profiles over valid legacy config', () => {
  const profiles = [
    ['shadow', { mode: 'autonomous', enforcement: 'shadow' }],
    ['supervised', { mode: 'supervised', enforcement: 'enforce' }],
    ['autonomous', { mode: 'autonomous', enforcement: 'enforce' }],
  ];

  for (const [profile, expected] of profiles) {
    const settings = resolve({
      environment: { OPENCLAW_JUDGE_PROFILE: profile },
      pluginConfig: { mode: 'supervised', enforcement: 'shadow' },
    });
    assert.deepEqual(settings.config, expected);
  }
});

test('rejects prototype property names as profiles', () => {
  for (const profile of ['toString', 'constructor', '__proto__', 'hasOwnProperty']) {
    assertInvalid({ environment: { OPENCLAW_JUDGE_PROFILE: profile } }, [profile]);
  }
});

test('validates legacy plugin config even when ENV profile is valid', () => {
  assertInvalid({
    environment: { OPENCLAW_JUDGE_PROFILE: 'shadow' },
    pluginConfig: { unknown: 'secret-invalid-config-value' },
  }, ['secret-invalid-config-value']);
});

test('rejects own and inherited legacy accessors without invoking them', () => {
  let getterReads = 0;
  const ownAccessor = {};
  Object.defineProperty(ownAccessor, 'mode', {
    enumerable: true,
    get() { getterReads += 1; throw new Error('own-config-getter-secret'); },
  });
  assertInvalid({ pluginConfig: ownAccessor }, ['own-config-getter-secret']);

  const inheritedAccessor = Object.create({
    get mode() { getterReads += 1; throw new Error('inherited-config-getter-secret'); },
  });
  assertInvalid({ pluginConfig: inheritedAccessor }, ['inherited-config-getter-secret']);
  assert.equal(getterReads, 0);
});

test('dedicated key is atomic and never reads shared provider', () => {
  let providerReads = 0;
  const environment = { OPENCLAW_JUDGE_API_KEY: DEDICATED_KEY };
  const settings = resolve({
    environment,
    getSharedProvider() {
      providerReads += 1;
      throw new Error('shared provider must not be read');
    },
  });

  assert.equal(providerReads, 0);
  assert.deepEqual(settings.providerConfig, {
    baseUrl: CLOUDRU_BASE_URL,
    apiKey: DEDICATED_KEY,
  });
  assert.equal(settings.credentialSource, 'environment');
  environment.OPENCLAW_JUDGE_API_KEY = 'mutated-key';
  assert.equal(settings.providerConfig.apiKey, DEDICATED_KEY);
});

test('reads and clones the shared provider exactly once only without ENV key', () => {
  let reads = 0;
  const provider = { ...VALID_PROVIDER };
  const settings = resolve({
    getSharedProvider() {
      reads += 1;
      return provider;
    },
  });

  assert.equal(reads, 1);
  assert.notStrictEqual(settings.providerConfig, provider);
  assertInvalid({ getSharedProvider: () => ({ ...provider, baseUrl: 'https://attacker.invalid/v1' }) });
  assertInvalid({ getSharedProvider: () => ({ ...provider, apiKey: 'bad key' }) });
});

test('rejects invalid API keys without exposing them', () => {
  const invalidKeys = [
    '',
    ' ',
    ' leading',
    'trailing ',
    'embedded whitespace',
    'line\nbreak',
    'tab\tvalue',
    'unicode-я',
    'x'.repeat(4097),
  ];
  for (const apiKey of invalidKeys) {
    assertInvalid({ environment: { OPENCLAW_JUDGE_API_KEY: apiKey } });
  }
});

test('accepts only the fixed endpoint and never combines ENV URL with shared key', () => {
  const invalidUrls = [
    'http://foundation-models.api.cloud.ru/v1',
    'https://attacker.invalid/v1',
    'https://foundation-models.api.cloud.ru.attacker.invalid/v1',
    'https://foundation-models.api.cloud.ru:8443/v1',
    'https://user@foundation-models.api.cloud.ru/v1',
    'https://foundation-models.api.cloud.ru/v2',
    'https://foundation-models.api.cloud.ru/v1/',
    'https://foundation-models.api.cloud.ru/v1?x=1',
    'https://foundation-models.api.cloud.ru/v1#x',
  ];

  assertInvalid({ environment: { OPENCLAW_JUDGE_BASE_URL: CLOUDRU_BASE_URL } });
  for (const baseUrl of invalidUrls) {
    assertInvalid({
      environment: {
        OPENCLAW_JUDGE_API_KEY: DEDICATED_KEY,
        OPENCLAW_JUDGE_BASE_URL: baseUrl,
      },
    }, [baseUrl]);
  }
  assert.equal(resolve({
    environment: {
      OPENCLAW_JUDGE_API_KEY: DEDICATED_KEY,
      OPENCLAW_JUDGE_BASE_URL: CLOUDRU_BASE_URL,
    },
  }).providerConfig.baseUrl, CLOUDRU_BASE_URL);
});

test('accepts only canonical bounded timeout values', () => {
  for (const timeout of ['1000', '8000', '30000']) {
    assert.equal(resolve({
      environment: { OPENCLAW_JUDGE_TIMEOUT_MS: timeout },
    }).timeoutMs, Number(timeout));
  }
  assert.equal(MIN_JUDGE_TIMEOUT_MS, 1000);
  assert.equal(MAX_JUDGE_TIMEOUT_MS, 30000);
  for (const timeout of ['', '999', '30001', '1e3', '01000', '1000.0', ' 1000', '1000 ']) {
    assertInvalid({ environment: { OPENCLAW_JUDGE_TIMEOUT_MS: timeout } }, [timeout]);
  }
});

test('derives and confines the audit path to the OpenClaw logs root', () => {
  const settings = resolve({
    environment: {
      OPENCLAW_STATE_DIR: '/state/openclaw',
      OPENCLAW_JUDGE_AUDIT_PATH: '/state/openclaw/logs/team/judge.jsonl',
    },
  });
  assert.equal(settings.auditRoot, '/state/openclaw/logs');
  assert.equal(settings.auditPath, '/state/openclaw/logs/team/judge.jsonl');

  const invalidPaths = [
    '',
    'logs/judge.jsonl',
    '/state/openclaw/judge.jsonl',
    '/state/openclaw/logs',
    '/state/openclaw/logs/judge.log',
    '/state/openclaw/logs/team/../judge.jsonl',
    '/state/openclaw/logs/judge.jsonl\0suffix',
  ];
  for (const auditPath of invalidPaths) {
    assertInvalid({
      environment: {
        OPENCLAW_STATE_DIR: '/state/openclaw',
        OPENCLAW_JUDGE_AUDIT_PATH: auditPath,
      },
    }, [auditPath]);
  }
  for (const stateDir of ['', 'relative/state', '/state/../other']) {
    assertInvalid({ environment: { OPENCLAW_STATE_DIR: stateDir } }, [stateDir]);
  }
});

test('validates lifecycle log levels and defaults to info', () => {
  for (const logLevel of ['error', 'warn', 'info', 'silent']) {
    assert.equal(resolve({
      environment: { OPENCLAW_JUDGE_LOG_LEVEL: logLevel },
    }).logLevel, logLevel);
  }
  assert.equal(resolve().logLevel, 'info');
  for (const logLevel of ['', 'debug', 'INFO', 'none']) {
    assertInvalid({ environment: { OPENCLAW_JUDGE_LOG_LEVEL: logLevel } }, [logLevel]);
  }
});

test('rejects unknown judge variables but ignores unrelated environment', () => {
  assert.equal(resolve({ environment: { PATH: '/bin', OTHER_API_KEY: 'ordinary' } }).timeoutMs, 30000);
  assertInvalid({
    environment: { OPENCLAW_JUDGE_MODEL: 'secret-model-override' },
  }, ['OPENCLAW_JUDGE_MODEL', 'secret-model-override']);
});

test('rejects hostile containers and accessors without invoking traps', () => {
  let proxyTraps = 0;
  const hostileEnvironment = new Proxy({}, {
    ownKeys() { proxyTraps += 1; throw new Error('proxy-secret'); },
    getOwnPropertyDescriptor() { proxyTraps += 1; throw new Error('proxy-secret'); },
  });
  assertInvalid({ environment: hostileEnvironment }, ['proxy-secret']);
  assert.equal(proxyTraps, 0);

  let getterReads = 0;
  const accessorEnvironment = {};
  Object.defineProperty(accessorEnvironment, 'OPENCLAW_JUDGE_PROFILE', {
    enumerable: true,
    get() { getterReads += 1; throw new Error('getter-secret'); },
  });
  assertInvalid({ environment: accessorEnvironment }, ['getter-secret']);
  assert.equal(getterReads, 0);

  const symbolEnvironment = {};
  symbolEnvironment[Symbol('secret-symbol')] = 'secret-symbol-value';
  assertInvalid({ environment: symbolEnvironment }, ['secret-symbol-value']);

  const hostileProvider = new Proxy({}, {
    get() { proxyTraps += 1; throw new Error('provider-secret'); },
    ownKeys() { proxyTraps += 1; throw new Error('provider-secret'); },
  });
  assertInvalid({ getSharedProvider: () => hostileProvider }, ['provider-secret']);
  assert.equal(proxyTraps, 0);
});
