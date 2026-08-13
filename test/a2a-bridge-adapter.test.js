import test from 'node:test';
import assert from 'node:assert/strict';

import {
  A2A_BRIDGE_GLOBAL_KEY,
  A2A_BRIDGE_WRAPPED_FLAG,
  attachA2ABridgeAdapter,
} from '../src/a2a-bridge-adapter.js';
import { createAutoApproveStore } from '../src/autoapprove-store.js';
import {
  AUTOAPPROVE_CONTROL_MARKER,
  extractAutoApproveMarker,
  autoApproveOutboundPrefix,
} from '../src/control-marker.js';

test('extractAutoApproveMarker detects and strips the HTML comment marker', () => {
  const prompt = `${autoApproveOutboundPrefix()}Hello world\nDo the thing.`;
  const extracted = extractAutoApproveMarker(prompt);
  assert.equal(extracted.enabled, true);
  assert.equal(extracted.stripped.includes(AUTOAPPROVE_CONTROL_MARKER), false);
  assert.match(extracted.stripped, /Hello world/u);
  assert.match(extracted.stripped, /Do the thing/u);
});

test('extractAutoApproveMarker is inert without marker', () => {
  const extracted = extractAutoApproveMarker('plain request');
  assert.equal(extracted.enabled, false);
  assert.equal(extracted.stripped, 'plain request');
});

test('autoapprove store tracks runs, sessions, and one-shot decisions', () => {
  const store = createAutoApproveStore({ ttlMs: 60_000, maxEntries: 10, now: () => 1_000 });
  assert.equal(store.isActive({ runId: 'run-1' }), false);
  store.markRun('run-1');
  store.markSession('agent:main:a2a:chat-42');
  assert.equal(store.isActive({ runId: 'run-1' }), true);
  assert.equal(store.isActive({ sessionKey: 'session:agent:main:a2a:chat-42' }), true);

  store.putDecision('call-1', 'allow-once');
  assert.equal(store.peekDecision('call-1'), 'allow-once');
  assert.equal(store.takeDecision('call-1'), 'allow-once');
  assert.equal(store.takeDecision('call-1'), undefined);
});

test('a2a bridge adapter returns allow-once from judge without HITL wait', async () => {
  const root = Object.create(null);
  const calls = [];
  root[A2A_BRIDGE_GLOBAL_KEY] = {
    async requestApproval(params) {
      calls.push(params);
      return 'allow-once';
    },
  };
  const autoApproveStore = createAutoApproveStore({ now: () => 1 });
  autoApproveStore.markRun('run-auto');
  autoApproveStore.putDecision('call-auto', 'allow-once');

  const attached = attachA2ABridgeAdapter({ autoApproveStore, root });
  assert.equal(attached.attached, true);
  assert.equal(root[A2A_BRIDGE_GLOBAL_KEY][A2A_BRIDGE_WRAPPED_FLAG], true);

  const decision = await root[A2A_BRIDGE_GLOBAL_KEY].requestApproval({
    runId: 'run-auto',
    toolCallId: 'call-auto',
    toolName: 'exec',
    params: {},
    timeoutMs: 1000,
  });
  assert.equal(decision, 'allow-once');
  // Judge is the approver — do not block on manager/HITL.
  assert.equal(calls.length, 0);

  const human = await root[A2A_BRIDGE_GLOBAL_KEY].requestApproval({
    runId: 'run-human',
    toolCallId: 'call-human',
    toolName: 'exec',
    params: {},
    timeoutMs: 1000,
  });
  assert.equal(human, 'allow-once');
  assert.equal(calls.length, 1);

  attached.detach();
});

test('a2a bridge adapter denies without HITL wait when judge says deny', async () => {
  const root = Object.create(null);
  const calls = [];
  root[A2A_BRIDGE_GLOBAL_KEY] = {
    async requestApproval(params) {
      calls.push(params);
      return 'allow-once';
    },
  };
  const autoApproveStore = createAutoApproveStore({ now: () => 1 });
  autoApproveStore.markRun('run-auto');
  autoApproveStore.putDecision('call-deny', 'deny');
  attachA2ABridgeAdapter({ autoApproveStore, root });

  const decision = await root[A2A_BRIDGE_GLOBAL_KEY].requestApproval({
    runId: 'run-auto',
    toolCallId: 'call-deny',
    toolName: 'exec',
    params: {},
    timeoutMs: 1000,
  });
  assert.equal(decision, 'deny');
  assert.equal(calls.length, 0);
});

test('a2a bridge adapter falls back to HITL when decision is missing', async () => {
  const root = Object.create(null);
  const calls = [];
  root[A2A_BRIDGE_GLOBAL_KEY] = {
    async requestApproval(params) {
      calls.push(params);
      return 'allow-once';
    },
  };
  const autoApproveStore = createAutoApproveStore({ now: () => 1 });
  autoApproveStore.markRun('run-auto');
  attachA2ABridgeAdapter({ autoApproveStore, root });

  const decision = await root[A2A_BRIDGE_GLOBAL_KEY].requestApproval({
    runId: 'run-auto',
    toolCallId: 'missing',
    toolName: 'exec',
    params: {},
    timeoutMs: 1000,
  });
  assert.equal(decision, 'allow-once');
  assert.equal(calls.length, 1);
});
