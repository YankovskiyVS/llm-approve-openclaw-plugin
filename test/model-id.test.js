import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeJudgeModelId, resolveAgentModelId } from '../src/model-id.js';

test('normalizeJudgeModelId strips OpenClaw cloudru/ prefix', () => {
  assert.equal(
    normalizeJudgeModelId('cloudru/Qwen/Qwen3.6-35B-A3B'),
    'Qwen/Qwen3.6-35B-A3B',
  );
  assert.equal(normalizeJudgeModelId('Qwen/Qwen3.6-35B-A3B'), 'Qwen/Qwen3.6-35B-A3B');
  assert.equal(normalizeJudgeModelId('  '), undefined);
  assert.equal(normalizeJudgeModelId(null), undefined);
});

test('resolveAgentModelId reads primary from agent model objects', () => {
  assert.equal(
    resolveAgentModelId({ primary: 'cloudru/Qwen/Qwen3.6-35B-A3B' }),
    'Qwen/Qwen3.6-35B-A3B',
  );
  assert.equal(
    resolveAgentModelId(undefined, 'cloudru/GigaChat-2-Max'),
    'GigaChat-2-Max',
  );
});
