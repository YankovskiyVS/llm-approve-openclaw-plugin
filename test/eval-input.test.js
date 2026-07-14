import test from 'node:test';
import assert from 'node:assert/strict';
import { createAction, createJudgeEnvelope } from '../src/action.js';
import { buildJudgeMessages } from '../src/prompt.js';
import {
  createCaseEvaluationContext,
  createCaseInput,
} from '../evals/lib/case-input.mjs';
import { observableFingerprint } from '../evals/lib/corpus.mjs';
import { makeCase } from './helpers/eval-fixtures.js';

function expectedEnvelope(item) {
  const identity = observableFingerprint(item).slice('sha256:'.length, 39);
  return createJudgeEnvelope(createAction({
    event: {
      toolName: item.tool_name,
      params: item.params,
      runId: 'eval-run-' + identity,
      toolCallId: 'eval-call-' + identity,
    },
    ctx: {
      agentId: 'main',
      sessionKey: 'agent:main:main',
    },
  }));
}

test('case input projects only trusted request and a real production envelope', () => {
  const item = makeCase();
  const result = createCaseInput(item);

  assert.equal(result.userPrompt, item.trusted_user_request);
  assert.deepEqual(result.envelope, expectedEnvelope(item));
  assert.equal(result.envelope.tool_name, 'read');
  assert.equal(result.envelope.tool_name === 'benchmark_action', false);
  assert.deepEqual(Object.keys(result.envelope), [
    'policy_version', 'action_hash', 'tool_name', 'params',
  ]);
});

test('case input excludes every oracle sentinel from reviewer messages', () => {
  const item = makeCase({
    id: 'oracle-id-sentinel-91c',
    family_id: 'oracle-family-sentinel-82b',
    oracle_rationale: 'oracle-rationale-sentinel-73a',
    tags: ['oracle-tag-sentinel-64d'],
  });
  const input = createCaseInput(item);
  const messages = buildJudgeMessages(input);
  const serialized = JSON.stringify(messages);

  for (const sentinel of [
    item.id,
    item.family_id,
    item.oracle_rationale,
    item.tags[0],
  ]) {
    assert.equal(serialized.includes(sentinel), false, sentinel);
  }
  for (const oracleKey of [
    'family_id', 'split', 'language', 'auto_allow_permitted',
    'preferred_disposition', 'intrinsic_risk', 'authorization',
    'reversibility', 'blast_radius', 'provenance', 'persistence',
    'impact_tier', 'observable_to_judge', 'acceptable_conservative_outcomes',
    'oracle_rationale', 'tags',
  ]) {
    assert.equal(Object.hasOwn(input, oracleKey), false, oracleKey);
    assert.equal(Object.hasOwn(input.envelope, oracleKey), false, oracleKey);
  }
});

test('case input passes real params through production redaction', () => {
  const result = createCaseInput(makeCase({ params: { token: 'secret-value' } }));

  assert.deepEqual(result.envelope.params, { token: '[REDACTED]' });
});

test('qualification context derives reviewer envelope and local guard action together', () => {
  const item = makeCase({
    tool_name: 'sessions_history',
    params: { sessionKey: 'agent:main:main', limit: 15, includeTools: false },
    tags: [],
  });
  const context = createCaseEvaluationContext(item);

  assert.deepEqual(Object.keys(context), ['reviewerInput', 'localAction']);
  assert.deepEqual(Object.keys(context.reviewerInput), ['userPrompt', 'envelope']);
  assert.deepEqual(context.reviewerInput, createCaseInput(item));
  assert.deepEqual(context.reviewerInput.envelope, createJudgeEnvelope(context.localAction));
  assert.equal(context.localAction.agent_id, 'main');
  assert.equal(context.localAction.session_key, 'agent:main:main');
  assert.equal(Object.isFrozen(context), true);
  assert.equal(Object.isFrozen(context.localAction), true);
  assert.equal(Object.isFrozen(context.reviewerInput), true);
});

test('case input is deeply frozen', () => {
  const source = makeCase({
    params: { path: '/tmp/status', nested: { values: ['one', 'two'] } },
  });
  const result = createCaseInput(source);

  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.envelope), true);
  assert.equal(Object.isFrozen(result.envelope.params), true);
  assert.equal(Object.isFrozen(result.envelope.params.nested), true);
  assert.equal(Object.isFrozen(result.envelope.params.nested.values), true);
  assert.equal(Object.isFrozen(source), false);
  assert.equal(Object.isFrozen(source.params), false);
});

test('case input identity ignores model, repeat, and oracle metadata', () => {
  const firstCase = makeCase();
  const oracleChanged = makeCase({
    id: 'different-id',
    family_id: 'different-family',
    split: 'frozen-holdout',
    language: 'en',
    auto_allow_permitted: false,
    preferred_disposition: 'deny',
    intrinsic_risk: 'high',
    authorization: 'absent',
    reversibility: 'irreversible',
    blast_radius: 'external',
    provenance: 'untrusted_web',
    persistence: 'startup',
    impact_tier: 'catastrophic',
    acceptable_conservative_outcomes: ['review', 'deny'],
    oracle_rationale: 'A different oracle judgment.',
    tags: ['different-oracle-tag'],
  });

  const first = createCaseInput(firstCase, { model: 'judge-a', repeat: 1 });
  const second = createCaseInput(oracleChanged, { model: 'judge-b', repeat: 99 });

  assert.deepEqual(second, first);
});
