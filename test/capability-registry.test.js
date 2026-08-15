import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyToolCapability } from '../src/capability-registry.js';
import { applyTrustedObservationAllow } from '../src/decision.js';
import { createRunDecisionStore } from '../src/run-decision-store.js';

test('Nango passive observations are classified and false out_of_scope is upgraded', () => {
  for (const toolName of [
    'nango_list_connections',
    'nango_yandex_mail_list',
    'nango_yandex_mail_get',
    'nango_yandex_disk_list',
    'nango_yandex_disk_get',
    'nango_yandex_calendar_list_events',
    'nango_yandex_calendar_get_event',
  ]) {
    assert.equal(classifyToolCapability(toolName).kind, 'passive');
  }
  const upgraded = applyTrustedObservationAllow({
    kind: 'deny',
    reason: 'judge denied',
    verdict: {
      decision: 'review',
      risk: 'low',
      authorization: 'medium',
      reason_code: 'out_of_scope',
    },
  }, 'nango_list_connections', {}, {});
  assert.equal(upgraded.kind, 'allow');
  assert.equal(upgraded.trusted_observation, true);
});

test('Nango mail send, filesystem, sessions, destructive and unknown are structured', () => {
  assert.equal(classifyToolCapability('nango_yandex_mail_send').kind, 'externalCommunication');
  assert.equal(classifyToolCapability('write').kind, 'mutation');
  assert.equal(classifyToolCapability('sessions_spawn').kind, 'resourceCreation');
  assert.equal(classifyToolCapability('nango_yandex_disk_delete').kind, 'destructive');
  assert.equal(classifyToolCapability('vendor_account_get').kind, 'unknown');
  const unknown = classifyToolCapability('vendor_custom_tool');
  assert.equal(unknown.kind, 'unknown');
  assert.equal(unknown.reason, 'unknown_tool_semantics');
});

function store() {
  return createRunDecisionStore({
    ttlMs: 60_000,
    maxRuns: 100,
    historyLimit: 50,
    consecutiveDenyLimit: 3,
    rollingDenyLimit: 10,
    now: () => 1,
  });
}

function decision(toolName, outcome, reasonCode) {
  return {
    tool_name: toolName,
    tool_family: classifyToolCapability(toolName).tool_family,
    outcome,
    risk: outcome === 'allow' ? 'low' : null,
    authorization: outcome === 'allow' ? 'high' : null,
    reason_code: reasonCode,
  };
}

test('breaker is scoped by user turn and tool family', () => {
  const breaker = store();
  for (let index = 0; index < 3; index += 1) {
    breaker.record('run-1', decision('web_fetch', 'deny', 'out_of_scope'), 'turn-1');
  }
  assert.equal(breaker.isTripped('run-1', 'turn-1', 'web'), true);
  assert.equal(breaker.isTripped('run-1', 'turn-1', 'nango_mail'), false);
  assert.equal(breaker.isTripped('run-1', 'turn-2', 'web'), false);

  breaker.record(
    'run-1',
    decision('nango_yandex_mail_send', 'allow', 'safe_and_authorized'),
    'turn-1',
  );
  assert.equal(breaker.isTripped('run-1', 'turn-1', 'nango_mail'), false);
  assert.equal(breaker.reset('run-1', 'turn-1', 'web'), 1);
  assert.equal(breaker.isTripped('run-1', 'turn-1', 'web'), false);
});

test('approval wait and Judge technical failure do not increment policy deny counter', () => {
  const breaker = store();
  for (let index = 0; index < 5; index += 1) {
    breaker.record('run-2', decision('web_fetch', 'review', 'other_policy_risk'), 'turn-1');
    breaker.record('run-2', decision('web_fetch', 'failure', 'judge_unavailable'), 'turn-1');
  }
  assert.equal(breaker.isTripped('run-2', 'turn-1', 'web'), false);
});
