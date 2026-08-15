import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveRuntimeSettings } from '../src/environment.js';

function resolve(environment) {
  return resolveRuntimeSettings({
    environment,
    homeDirectory: '/home/tester',
    pluginConfig: undefined,
    getSharedProvider() {
      throw new Error('shared provider must not be read with dedicated key');
    },
  });
}

test('separate Judge model and breaker thresholds are configurable', () => {
  const settings = resolve({
    OPENCLAW_JUDGE_API_KEY: 'dedicated-test-key',
    OPENCLAW_JUDGE_PROFILE: 'supervised',
    OPENCLAW_JUDGE_MODEL_ID: 'Qwen/Qwen3.6-35B-A3B',
    OPENCLAW_JUDGE_BREAKER_TTL_MS: '60000',
    OPENCLAW_JUDGE_BREAKER_CONSECUTIVE_DENY_LIMIT: '4',
    OPENCLAW_JUDGE_BREAKER_ROLLING_DENY_LIMIT: '12',
  });
  assert.equal(settings.judgeModelId, 'Qwen/Qwen3.6-35B-A3B');
  assert.equal(settings.judgeModelSource, 'environment');
  assert.equal(settings.judgeModelFallbackReason, null);
  assert.equal(settings.breakerTtlMs, 60_000);
  assert.equal(settings.breakerConsecutiveDenyLimit, 4);
  assert.equal(settings.breakerRollingDenyLimit, 12);
});

test('invalid model and breaker values are configuration errors', () => {
  for (const environment of [
    { OPENCLAW_JUDGE_API_KEY: 'key', OPENCLAW_JUDGE_MODEL_ID: '' },
    { OPENCLAW_JUDGE_API_KEY: 'key', OPENCLAW_JUDGE_BREAKER_TTL_MS: '0' },
    { OPENCLAW_JUDGE_API_KEY: 'key', OPENCLAW_JUDGE_BREAKER_CONSECUTIVE_DENY_LIMIT: '51' },
    { OPENCLAW_JUDGE_API_KEY: 'key', OPENCLAW_JUDGE_BREAKER_ROLLING_DENY_LIMIT: '1e1' },
  ]) {
    assert.throws(
      () => resolve(environment),
      (error) => error instanceof TypeError
        && error.message === 'invalid judge environment configuration',
    );
  }
});

test('legacy OPENCLAW_JUDGE_MODEL remains rejected instead of silently overriding', () => {
  assert.throws(() => resolve({
    OPENCLAW_JUDGE_API_KEY: 'key',
    OPENCLAW_JUDGE_MODEL: 'agent-model',
  }), /invalid judge environment configuration/u);
});
