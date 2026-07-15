import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as actionModule from '../src/action.js';
import {
  canonicalStringify,
  computeActionHash,
  createAction,
  createJudgeEnvelope,
} from '../src/action.js';
import { buildAuditEvent } from '../src/audit.js';
import { POLICY_VERSION } from '../src/constants.js';

test('canonicalStringify recursively sorts object keys and preserves array order', () => {
  const first = {
    z: 3,
    nested: { b: 2, a: 1 },
    array: [{ d: 4, c: 3 }, 'second', 'third'],
    2: 'two',
    10: 'ten',
  };
  const second = {
    10: 'ten',
    2: 'two',
    array: [{ c: 3, d: 4 }, 'second', 'third'],
    nested: { a: 1, b: 2 },
    z: 3,
  };
  const expected = '{"10":"ten","2":"two","array":[{"c":3,"d":4},"second","third"],"nested":{"a":1,"b":2},"z":3}';

  assert.equal(canonicalStringify(first), expected);
  assert.equal(canonicalStringify(second), expected);
});

test('canonicalStringify rejects cyclic and non-JSON values with secret-free errors', () => {
  const secret = 'canonical-fixture-never-print-73b';
  const cyclic = { password: secret };
  cyclic.self = cyclic;

  assert.throws(
    () => canonicalStringify(cyclic),
    (error) => error instanceof TypeError
      && error.message === 'cannot canonicalize cyclic value'
      && !error.message.includes(secret),
  );

  const unsupported = [
    undefined,
    1n,
    Symbol(secret),
    () => secret,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    new Date(),
    { nested: undefined },
  ];
  for (const value of unsupported) {
    assert.throws(
      () => canonicalStringify(value),
      (error) => error instanceof TypeError
        && error.message === 'cannot canonicalize unsupported value'
        && !error.message.includes(secret),
    );
  }
});

test('canonicalStringify normalizes exceptions thrown by unsupported objects', () => {
  const secret = 'proxy-canonical-fixture-never-print-c8a';
  const hostile = new Proxy({}, {
    getPrototypeOf() {
      throw new Error(secret);
    },
  });
  let caught;

  try {
    canonicalStringify(hostile);
  } catch (error) {
    caught = error;
  }

  assert.equal(caught instanceof TypeError, true, 'unsupported object did not fail safely');
  assert.equal(
    caught?.message === 'cannot canonicalize unsupported value',
    true,
    'error was not normalized',
  );
  assert.equal(caught?.message.includes(secret), false, 'error exposed unsupported object text');
});

test('createAction binds every exact field and defensively copies params', () => {
  const params = {
    command: 'deploy',
    nested: { b: 2, a: 1 },
    array: ['first', { value: true }],
  };
  const event = {
    toolName: 'exec',
    params,
    runId: 'run-event',
    toolCallId: 'call-event',
  };
  const ctx = {
    runId: 'run-context',
    toolCallId: 'call-context',
    agentId: 'agent-main',
    sessionKey: 'session-main',
  };

  const action = createAction({ event, ctx });

  assert.deepEqual(action, {
    policy_version: POLICY_VERSION,
    tool_name: 'exec',
    params: {
      array: ['first', { value: true }],
      command: 'deploy',
      nested: { a: 1, b: 2 },
    },
    agent_id: 'agent-main',
    session_key: 'session-main',
    run_id: 'run-event',
    tool_call_id: 'call-event',
  });
  assert.notEqual(action.params, params);
  assert.notEqual(action.params.nested, params.nested);
  assert.notEqual(action.params.array, params.array);

  params.command = 'mutated';
  params.nested.a = 99;
  params.array[1].value = false;
  event.runId = 'mutated-run';

  assert.equal(action.params.command, 'deploy');
  assert.equal(action.params.nested.a, 1);
  assert.equal(action.params.array[1].value, true);
  assert.equal(action.run_id, 'run-event');
});

test('createAction normalizes absent identifiers to null and falls back to context IDs', () => {
  const absent = createAction({ event: { toolName: 'read', params: {} }, ctx: {} });
  assert.equal(absent.agent_id, null);
  assert.equal(absent.session_key, null);
  assert.equal(absent.run_id, null);
  assert.equal(absent.tool_call_id, null);

  const fallback = createAction({
    event: { toolName: 'read', params: {} },
    ctx: { runId: 'ctx-run', toolCallId: 'ctx-call' },
  });
  assert.equal(fallback.run_id, 'ctx-run');
  assert.equal(fallback.tool_call_id, 'ctx-call');
});

test('hash is stable across key order and changes for every bound action field', () => {
  const first = createAction({
    event: {
      toolName: 'exec',
      params: { b: 2, a: 1 },
      runId: 'run-1',
      toolCallId: 'call-1',
    },
    ctx: { agentId: 'agent-1', sessionKey: 'session-1' },
  });
  const reordered = createAction({
    event: {
      toolName: 'exec',
      params: { a: 1, b: 2 },
      runId: 'run-1',
      toolCallId: 'call-1',
    },
    ctx: { agentId: 'agent-1', sessionKey: 'session-1' },
  });
  const hash = computeActionHash(first);

  assert.equal(computeActionHash(reordered), hash);
  assert.match(hash, /^sha256:[0-9a-f]{64}$/);

  for (const field of [
    'policy_version',
    'tool_name',
    'agent_id',
    'session_key',
    'run_id',
    'tool_call_id',
  ]) {
    const changed = { ...first, [field]: `${first[field]}-changed` };
    assert.notEqual(computeActionHash(changed), hash, `${field} was not bound by the hash`);
  }

  reordered.params.a = 9;
  assert.notEqual(computeActionHash(reordered), hash, 'params were not bound by the hash');
});

test('action hash is an opaque process-local binding, not an offline-checkable public digest', () => {
  const passwordDictionary = [
    'summer-2026',
    'correct-low-entropy-secret',
    'openclaw-admin',
  ];
  const candidateActions = passwordDictionary.map((password) => createAction({
    event: {
      toolName: 'write',
      params: { path: '/tmp/service.json', password },
      runId: 'run-known-to-observer',
      toolCallId: 'call-known-to-observer',
    },
    ctx: {
      agentId: 'agent-known-to-observer',
      sessionKey: 'session-known-to-observer',
    },
  }));
  const action = candidateActions[1];
  const actionHash = computeActionHash(action);
  const publicDictionaryHashes = candidateActions.map((candidate) => {
    const digest = createHash('sha256')
      .update(canonicalStringify(candidate), 'utf8')
      .digest('hex');
    return `sha256:${digest}`;
  });

  assert.equal(computeActionHash(action), actionHash, 'binding changed within one process');
  assert.equal(
    publicDictionaryHashes.includes(actionHash),
    false,
    'action hash exposed an offline-checkable public SHA-256 digest',
  );

  const envelope = createJudgeEnvelope(action);
  const audit = buildAuditEvent({ action });
  const serializedArtifacts = JSON.stringify({ envelope, audit });
  for (const password of passwordDictionary) {
    assert.equal(
      serializedArtifacts.includes(password),
      false,
      'judge or audit artifact exposed a candidate secret',
    );
  }
  assert.deepEqual(
    Object.keys(actionModule),
    ['canonicalStringify', 'computeActionHash', 'createAction', 'createJudgeEnvelope'],
    'action module exported key material',
  );
});

test('createJudgeEnvelope exposes only the hash, tool, policy, and redacted params', () => {
  const secrets = ['judge-token-fixture-84c', 'judge-env-fixture-95d'];
  const action = createAction({
    event: {
      toolName: 'exec',
      params: {
        token: secrets[0],
        env: { SAFE_NAME_BUT_SECRET_VALUE: secrets[1] },
        command: 'status',
      },
      runId: 'raw-run-id-never-send',
      toolCallId: 'raw-tool-call-id-never-send',
    },
    ctx: {
      agentId: 'raw-agent-id-never-send',
      sessionKey: 'raw-session-key-never-send',
    },
  });
  const actionBefore = canonicalStringify(action);

  const envelope = createJudgeEnvelope(action);
  const serialized = JSON.stringify(envelope);

  assert.deepEqual(Object.keys(envelope), [
    'policy_version',
    'action_hash',
    'tool_name',
    'params',
  ]);
  assert.equal(envelope.policy_version, POLICY_VERSION);
  assert.equal(envelope.action_hash, computeActionHash(action));
  assert.equal(envelope.tool_name, 'exec');
  assert.equal(envelope.params.token, '[REDACTED]');
  assert.equal(envelope.params.env.SAFE_NAME_BUT_SECRET_VALUE, '[REDACTED]');
  assert.equal(envelope.params.command, 'status');
  assert.equal(
    [
      ...secrets,
      action.agent_id,
      action.session_key,
      action.run_id,
      action.tool_call_id,
    ].some((value) => serialized.includes(value)),
    false,
    'judge envelope exposed raw context or credential material',
  );
  assert.equal(canonicalStringify(action), actionBefore, 'envelope creation mutated the action');
});

test('createAction safely rejects params that cannot be exactly bound', () => {
  const secret = 'action-cycle-fixture-never-print-a6e';
  const params = { value: secret };
  params.self = params;

  assert.throws(
    () => createAction({ event: { toolName: 'exec', params }, ctx: {} }),
    (error) => error instanceof TypeError
      && error.message === 'cannot canonicalize cyclic value'
      && !error.message.includes(secret),
  );
});
