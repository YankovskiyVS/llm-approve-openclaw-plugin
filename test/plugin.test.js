import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import defaultPlugin, {
  createActionJudgePlugin as createActionJudgePluginFromIndex,
} from '../index.js';
import { createActionJudgePlugin } from '../src/plugin.js';
import { createContextStore } from '../src/context-store.js';
import { createRunDecisionStore } from '../src/run-decision-store.js';
import {
  createApprovalDescription,
  createBlockFeedback,
} from '../src/feedback.js';
import {
  APPROVAL_TIMEOUT_MS,
  MAX_TRUSTED_PROMPT_BYTES,
  PLUGIN_ID,
  POLICY_VERSION,
} from '../src/constants.js';

const NO_INJECTION = Symbol('no injection');
const NO_PROVIDER = Symbol('no provider');
const RAW_PROMPT = '  Read the exact status file.  ';
const PROMPT_SECRET = 'prompt-secret-never-audit-7c2';
const PARAM_SECRET = 'param-secret-never-audit-8d3';
const API_SECRET = 'api-secret-never-audit-9e4';
const RAW_RUN_ID = 'raw-run-id-never-audit-1a5';
const RAW_TOOL_CALL_ID = 'raw-tool-call-id-never-audit-2b6';
const RAW_AGENT_ID = 'raw-agent-id-never-audit-3c7';
const RAW_SESSION_KEY = 'raw-session-key-never-audit-4d8';
const VALID_PROVIDER = Object.freeze({
  baseUrl: 'https://foundation-models.api.cloud.ru/v1',
  apiKey: API_SECRET,
});

function verdictText(input, overrides = {}) {
  const verdict = {
    policy_version: POLICY_VERSION,
    action_hash: input.envelope.action_hash,
    decision: 'allow',
    risk: 'low',
    authorization: 'high',
    confidence: 0.99,
    reason_code: 'safe_and_authorized',
    rationale: 'The exact requested action is authorized.',
    ...overrides,
  };
  if (!Object.hasOwn(overrides, 'reason_code') && verdict.decision !== 'allow') {
    verdict.reason_code = 'other_policy_risk';
  }
  return JSON.stringify(verdict);
}

function verdictClient(overrides = {}) {
  const calls = [];
  return {
    calls,
    async review(input) {
      calls.push(input);
      return { ok: true, text: verdictText(input, overrides), latencyMs: 7 };
    },
  };
}

function makeApi({
  pluginConfig = { mode: 'supervised', enforcement: 'enforce' },
  providerConfig = VALID_PROVIDER,
  providersOverride = undefined,
  logger = undefined,
  configuredEntry = undefined,
} = {}) {
  const registrations = [];
  const logs = [];
  const effectiveLogger = logger ?? {
    error(message) {
      logs.push(message);
    },
  };
  const providers = providersOverride
    ?? (providerConfig === NO_PROVIDER ? {} : { cloudru: providerConfig });
  const api = {
    config: {
      models: { providers },
      plugins: { entries: { [PLUGIN_ID]: { config: configuredEntry } } },
    },
    logger: effectiveLogger,
    on(name, handler, options) {
      registrations.push({ name, handler, options });
    },
  };
  if (pluginConfig !== NO_INJECTION) api.pluginConfig = pluginConfig;
  return { api, registrations, logs };
}

function setup({
  pluginConfig,
  providerConfig,
  providersOverride,
  environment = {},
  logger,
  configuredEntry,
  client = verdictClient(),
  audit = undefined,
  store = NO_INJECTION,
  deps = {},
} = {}) {
  const auditEvents = [];
  const effectiveAudit = audit ?? {
    async write(event) {
      auditEvents.push(event);
      return true;
    },
  };
  const injected = { ...deps };
  if (environment !== NO_INJECTION) injected.environment = environment;
  if (client !== NO_INJECTION) injected.client = client;
  if (audit !== NO_INJECTION) injected.audit = effectiveAudit;
  if (store !== NO_INJECTION) injected.store = store;

  const fake = makeApi({
    pluginConfig,
    providerConfig,
    providersOverride,
    logger,
    configuredEntry,
  });
  const plugin = createActionJudgePlugin(injected);
  plugin.register(fake.api);

  const captureRegistration = fake.registrations.find(
    ({ name }) => name === 'before_model_resolve',
  );
  const toolRegistration = fake.registrations.find(({ name }) => name === 'before_tool_call');
  return {
    ...fake,
    plugin,
    client,
    auditEvents,
    capture: captureRegistration?.handler,
    beforeTool: toolRegistration?.handler,
  };
}

function callData(runId = 'run-1', params = { path: '/tmp/status' }) {
  return {
    event: {
      toolName: 'read',
      params,
      runId,
      toolCallId: 'call-1',
    },
    ctx: {
      toolName: 'read',
      runId,
      toolCallId: 'call-1',
      agentId: 'agent-1',
      sessionKey: 'session-1',
    },
  };
}

function capturePrompt(harness, prompt = 'Read status.', runId = 'run-1', extras = {}) {
  return harness.capture({ prompt, ...extras.event }, { runId, ...extras.ctx });
}

function assertApproval(
  result,
  expectedParams,
  expectedCode = 'invalid_judge_response',
  expectedSeverity = 'critical',
) {
  assert.deepEqual(result.params, expectedParams);
  assert.deepEqual(result.requireApproval, {
    title: 'LLM action judge review required',
    description: createApprovalDescription(expectedCode),
    severity: expectedSeverity,
    timeoutMs: APPROVAL_TIMEOUT_MS,
    timeoutBehavior: 'deny',
    pluginId: PLUGIN_ID,
  });
}

function assertBlocked(result, expectedCode = undefined) {
  assert.equal(result.block, true);
  assert.equal(typeof result.blockReason, 'string');
  if (expectedCode !== undefined) {
    assert.equal(result.blockReason, createBlockFeedback(expectedCode));
  }
  assert.equal(Object.hasOwn(result, 'requireApproval'), false);
}

function runDecisionStore() {
  return createRunDecisionStore({
    ttlMs: 30 * 60 * 1000,
    maxRuns: 1000,
    historyLimit: 50,
    consecutiveDenyLimit: 3,
    rollingDenyLimit: 10,
    now: () => 0,
  });
}

function recordedDecision(overrides = {}) {
  return {
    tool_name: 'read',
    tool_family: 'filesystem',
    outcome: 'deny',
    risk: 'high',
    authorization: 'low',
    reason_code: 'out_of_scope',
    ...overrides,
  };
}

function tripDecisionStore(store, runId) {
  store.record(runId, recordedDecision());
  store.record(runId, recordedDecision());
  store.record(runId, recordedDecision());
}

test('exports the factory and default plugin, and registers exactly two priority hooks', () => {
  assert.strictEqual(createActionJudgePluginFromIndex, createActionJudgePlugin);
  assert.equal(defaultPlugin.id, PLUGIN_ID);
  assert.equal(defaultPlugin.name, 'LLM Action Judge');
  assert.equal(defaultPlugin.description, 'LLM-gated tool-call approval for OpenClaw');
  assert.equal(typeof defaultPlugin.register, 'function');

  const harness = setup();
  assert.deepEqual(
    harness.registrations.map(({ name, options }) => ({ name, options })),
    [
      { name: 'before_model_resolve', options: { priority: -1000 } },
      { name: 'before_tool_call', options: { priority: -1000 } },
    ],
  );
});

test('registration throws a fixed error when the enforcement hook cannot register', () => {
  const fake = makeApi();
  fake.api.on = function on(name, handler, options) {
    if (name === 'before_tool_call') throw new Error(PROMPT_SECRET);
    fake.registrations.push({ name, handler, options });
  };
  const plugin = createActionJudgePlugin({
    client: verdictClient(),
    audit: { async write() { return true; } },
    environment: {},
  });

  assert.throws(
    () => plugin.register(fake.api),
    (error) => error instanceof Error
      && error.message === 'LLM action judge setup failed'
      && !error.message.includes(PROMPT_SECRET),
  );
  assert.deepEqual(
    fake.registrations.map(({ name }) => name),
    ['before_model_resolve'],
  );
  assert.deepEqual(fake.logs, ['LLM action judge setup failed']);
});

test('capture-hook registration failure keeps the enforcement hook fail-closed', async () => {
  const fake = makeApi();
  fake.api.on = function on(name, handler, options) {
    if (name === 'before_model_resolve') throw new Error(PROMPT_SECRET);
    fake.registrations.push({ name, handler, options });
  };
  const plugin = createActionJudgePlugin({
    client: verdictClient(),
    audit: { async write() { return true; } },
    environment: {},
  });

  assert.doesNotThrow(() => plugin.register(fake.api));
  assert.deepEqual(fake.registrations.map(({ name }) => name), ['before_tool_call']);
  const gate = fake.registrations[0].handler;
  const call = callData();
  assertApproval(await gate(call.event, call.ctx), call.event.params);
  assert.deepEqual(fake.logs, ['LLM action judge setup failed']);
});

test('production store factory receives the bounded 30-minute defaults and Date.now', () => {
  let received;
  const store = { put() {}, get() { return undefined; } };
  const harness = setup({
    deps: {
      createContextStore(options) {
        received = options;
        return store;
      },
    },
  });

  assert.equal(harness.registrations.length, 2);
  assert.deepEqual(received, {
    ttlMs: 30 * 60 * 1000,
    maxEntries: 1000,
    now: Date.now,
  });
});

test('production decision-store factory receives the fixed bounded breaker options', () => {
  let received;
  const decisionStore = {
    isTripped() { return false; },
    record() {
      return { already_tripped: false, newly_tripped: false, tripped: false };
    },
  };
  const harness = setup({
    deps: {
      createRunDecisionStore(options) {
        received = options;
        return decisionStore;
      },
    },
  });

  assert.equal(harness.registrations.length, 2);
  assert.deepEqual(received, {
    ttlMs: 30 * 60 * 1000,
    maxRuns: 1000,
    historyLimit: 50,
    consecutiveDenyLimit: 3,
    rollingDenyLimit: 10,
    now: Date.now,
  });
});

test('a pre-tripped run skips Qwen and blocks in both enforcing modes', async (t) => {
  for (const mode of ['autonomous', 'supervised']) {
    await t.test(mode, async () => {
      const decisionStore = runDecisionStore();
      tripDecisionStore(decisionStore, 'run-tripped');
      const client = verdictClient();
      const harness = setup({
        pluginConfig: { mode, enforcement: 'enforce' },
        client,
        deps: { decisionStore },
      });
      capturePrompt(harness, 'Read status.', 'run-tripped');
      const call = callData('run-tripped');

      const result = await harness.beforeTool(call.event, call.ctx);

      assert.equal(client.calls.length, 0);
      assertBlocked(result, 'repeated_denials');
      assert.equal(harness.auditEvents.length, 1);
      assert.equal(harness.auditEvents[0].outcome, 'deny');
      assert.equal(harness.auditEvents[0].feedback_code, 'repeated_denials');
      assert.equal(harness.auditEvents[0].feedback_status, 'blocked');
      const snapshot = decisionStore.snapshot('run-tripped');
      assert.equal(snapshot.length, 4);
      assert.equal(snapshot[3].reason_code, 'repeated_denials');

      capturePrompt(harness, 'Read status.', 'run-fresh');
      const freshCall = callData('run-fresh');
      const freshResult = await harness.beforeTool(freshCall.event, freshCall.ctx);
      assert.deepEqual(freshResult, { params: freshCall.event.params });
      assert.equal(client.calls.length, 1);
      assert.equal(decisionStore.isTripped('run-fresh'), false);
    });
  }
});

test('shadow observes a pre-tripped run through Qwen but audits the breaker candidate', async () => {
  const decisionStore = runDecisionStore();
  tripDecisionStore(decisionStore, 'run-shadow-tripped');
  const client = verdictClient();
  const harness = setup({
    pluginConfig: { mode: 'autonomous', enforcement: 'shadow' },
    client,
    deps: { decisionStore },
  });
  capturePrompt(harness, 'Read status.', 'run-shadow-tripped');
  const call = callData('run-shadow-tripped');

  const result = await harness.beforeTool(call.event, call.ctx);

  assert.equal(result, undefined);
  assert.equal(client.calls.length, 1);
  assert.equal(harness.auditEvents.length, 1);
  assert.equal(harness.auditEvents[0].outcome, 'deny');
  assert.equal(harness.auditEvents[0].feedback_code, null);
  assert.equal(harness.auditEvents[0].feedback_status, null);
  const snapshot = decisionStore.snapshot('run-shadow-tripped');
  assert.equal(snapshot[3].reason_code, 'repeated_denials');
});

test('third denial keeps its reason and the fourth call is stopped before Qwen', async () => {
  const decisionStore = runDecisionStore();
  const client = verdictClient({
    decision: 'deny',
    risk: 'high',
    authorization: 'low',
    reason_code: 'out_of_scope',
  });
  const harness = setup({
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
    client,
    deps: { decisionStore },
  });
  capturePrompt(harness, 'Read status.');
  const call = callData();

  const first = await harness.beforeTool(call.event, call.ctx);
  const second = await harness.beforeTool(call.event, call.ctx);
  const third = await harness.beforeTool(call.event, call.ctx);
  const fourth = await harness.beforeTool(call.event, call.ctx);

  assertBlocked(first, 'out_of_scope');
  assertBlocked(second, 'out_of_scope');
  assertBlocked(third, 'out_of_scope');
  assertBlocked(fourth, 'repeated_denials');
  assert.equal(client.calls.length, 3);
  assert.deepEqual(
    harness.auditEvents.map((event) => event.feedback_code),
    ['out_of_scope', 'out_of_scope', 'out_of_scope', 'repeated_denials'],
  );
  const snapshot = decisionStore.snapshot('run-1');
  assert.deepEqual(
    snapshot.map((entry) => entry.reason_code),
    ['out_of_scope', 'out_of_scope', 'out_of_scope', 'repeated_denials'],
  );
});

test('an in-flight allow is replaced when another call trips the same run', async () => {
  const decisionStore = runDecisionStore();
  let release;
  let startedResolve;
  const started = new Promise((resolve) => { startedResolve = resolve; });
  const client = {
    calls: [],
    review(input) {
      this.calls.push(input);
      startedResolve();
      return new Promise((resolve) => {
        release = () => resolve({ ok: true, text: verdictText(input), latencyMs: 8 });
      });
    },
  };
  const harness = setup({
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
    client,
    deps: { decisionStore },
  });
  capturePrompt(harness, 'Read status.');
  const call = callData();

  const pending = harness.beforeTool(call.event, call.ctx);
  await started;
  tripDecisionStore(decisionStore, 'run-1');
  release();
  const result = await pending;

  assert.equal(client.calls.length, 1);
  assertBlocked(result, 'repeated_denials');
  assert.equal(harness.auditEvents[0].outcome, 'deny');
  assert.equal(harness.auditEvents[0].feedback_code, 'repeated_denials');
  const snapshot = decisionStore.snapshot('run-1');
  assert.equal(snapshot[3].reason_code, 'repeated_denials');
});

test('trusted calls record exactly once before audit and a new run stays independent', async () => {
  const records = [];
  let auditCompleted = false;
  const decisionStore = {
    isTripped() { return false; },
    record(runId, value) {
      assert.equal(auditCompleted, false);
      records.push({ runId, value });
      return { already_tripped: false, newly_tripped: false, tripped: false };
    },
  };
  const audit = {
    async write() {
      assert.equal(records.length, 1);
      auditCompleted = true;
      return true;
    },
  };
  const harness = setup({ audit, deps: { decisionStore } });
  capturePrompt(harness, 'Read status.', 'run-new');
  const call = callData('run-new');

  const result = await harness.beforeTool(call.event, call.ctx);

  assert.deepEqual(result, { params: call.event.params });
  assert.equal(records.length, 1);
  assert.equal(records[0].runId, 'run-new');
  assert.deepEqual(records[0].value, {
    tool_name: 'read',
    tool_family: 'filesystem',
    outcome: 'allow',
    risk: 'low',
    authorization: 'high',
    reason_code: 'safe_and_authorized',
  });
});

test('missing, throwing, async, and hostile decision-store methods fail closed', async (t) => {
  const validStatus = { already_tripped: false, newly_tripped: false, tripped: false };
  const cases = [
    ['missing check', { record() { return validStatus; } }],
    ['throwing check', {
      isTripped() { throw new Error(PROMPT_SECRET); },
      record() { return validStatus; },
    }],
    ['async check', {
      isTripped() { return Promise.resolve(false); },
      record() { return validStatus; },
    }],
    ['missing record', { isTripped() { return false; } }],
    ['throwing record', {
      isTripped() { return false; },
      record() { throw new Error(PROMPT_SECRET); },
    }],
    ['hostile status', {
      isTripped() { return false; },
      record() {
        return new Proxy({}, {
          ownKeys() { throw new Error(PROMPT_SECRET); },
        });
      },
    }],
  ];

  for (const [name, decisionStore] of cases) {
    await t.test(name, async () => {
      const client = verdictClient();
      const harness = setup({
        pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
        client,
        deps: { decisionStore },
      });
      capturePrompt(harness);
      const call = callData();

      const result = await harness.beforeTool(call.event, call.ctx);

      assertBlocked(result, 'invalid_judge_response');
      assert.equal(JSON.stringify(result).includes(PROMPT_SECRET), false);
      assert.equal(harness.auditEvents.length, 1);
      assert.equal(harness.auditEvents[0].outcome, 'failure');
      assert.equal(harness.auditEvents[0].feedback_code, 'invalid_judge_response');
      assert.equal(harness.auditEvents[0].feedback_status, 'blocked');
    });
  }
});

test('captures the exact untrimmed prompt under the exact run ID', async () => {
  const client = verdictClient();
  const harness = setup({ client });
  const runId = '  exact-run-id  ';
  const call = callData(runId);

  assert.equal(capturePrompt(harness, RAW_PROMPT, runId), undefined);
  const result = await harness.beforeTool(call.event, call.ctx);

  assert.equal(client.calls.length, 1);
  assert.equal(client.calls[0].userPrompt, RAW_PROMPT);
  assert.deepEqual(result.params, call.event.params);
});

test('accepts exactly 64 KiB but rejects a prompt over 64 KiB by UTF-8 byte size', async () => {
  const client = verdictClient({ decision: 'deny', risk: 'high', authorization: 'low' });
  const harness = setup({ client });
  const atLimit = 'x'.repeat(MAX_TRUSTED_PROMPT_BYTES);
  const overLimitUnicode = 'я'.repeat(MAX_TRUSTED_PROMPT_BYTES / 2 + 1);

  capturePrompt(harness, atLimit, 'limit-run');
  await harness.beforeTool(...Object.values(callData('limit-run')));
  capturePrompt(harness, overLimitUnicode, 'oversize-run');
  const oversize = await harness.beforeTool(...Object.values(callData('oversize-run')));

  assert.equal(client.calls.length, 1);
  assertApproval(oversize, { path: '/tmp/status' });
  assert.equal(harness.auditEvents.length, 2);
});

test('blank, missing, mismatched, expired, and oversized intent never calls the client', async (t) => {
  await t.test('blank prompt uses supervised fallback', async () => {
    const client = verdictClient();
    const harness = setup({ client });
    capturePrompt(harness, ' \t\n ', 'blank-run');
    const call = callData('blank-run');
    const result = await harness.beforeTool(call.event, call.ctx);
    assert.equal(client.calls.length, 0);
    assertApproval(result, call.event.params);
    assert.equal(harness.auditEvents.length, 1);
  });

  await t.test('missing run ID uses supervised fallback', async () => {
    const client = verdictClient();
    const harness = setup({ client });
    harness.capture({ prompt: 'Read status.' }, { sessionId: 'session-fallback' });
    const call = callData(undefined);
    delete call.event.runId;
    delete call.ctx.runId;
    const result = await harness.beforeTool(call.event, call.ctx);
    assert.equal(client.calls.length, 0);
    assertApproval(result, call.event.params);
  });

  await t.test('conflicting run IDs use supervised fallback', async () => {
    const client = verdictClient();
    const harness = setup({ client });
    capturePrompt(harness, 'Read status.', 'run-a');
    const call = callData('run-a');
    call.ctx.runId = 'run-b';
    const result = await harness.beforeTool(call.event, call.ctx);
    assert.equal(client.calls.length, 0);
    assertApproval(result, call.event.params);
  });

  await t.test('expired intent uses autonomous fallback', async () => {
    let now = 1_000;
    const store = createContextStore({ ttlMs: 100, maxEntries: 10, now: () => now });
    const client = verdictClient();
    const harness = setup({
      pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
      client,
      store,
    });
    capturePrompt(harness, 'Read status.', 'stale-run');
    now += 100;
    const call = callData('stale-run');
    const result = await harness.beforeTool(call.event, call.ctx);
    assert.equal(client.calls.length, 0);
    assertBlocked(result);
  });

  await t.test('oversized prompt uses supervised fallback', async () => {
    const client = verdictClient();
    const harness = setup({ client });
    capturePrompt(harness, 'x'.repeat(64 * 1024 + 1), 'large-run');
    const call = callData('large-run');
    const result = await harness.beforeTool(call.event, call.ctx);
    assert.equal(client.calls.length, 0);
    assertApproval(result, call.event.params);
  });
});

test('never falls back to transcript, messages, session ID, or session key', async () => {
  const client = verdictClient();
  const harness = setup({ client });
  harness.capture(
    {
      prompt: '   ',
      messages: [{ role: 'user', content: PROMPT_SECRET }],
      transcript: PROMPT_SECRET,
    },
    {
      sessionId: 'session-id-fallback',
      sessionKey: 'session-key-fallback',
      transcript: PROMPT_SECRET,
    },
  );
  const call = callData(undefined);
  delete call.event.runId;
  delete call.ctx.runId;
  Object.assign(call.event, { messages: [{ content: PROMPT_SECRET }], transcript: PROMPT_SECRET });
  Object.assign(call.ctx, { sessionId: 'session-id-fallback', sessionKey: 'session-key-fallback' });

  const result = await harness.beforeTool(call.event, call.ctx);

  assert.equal(client.calls.length, 0);
  assertApproval(result, call.event.params);
});

test('validated allow returns a fresh defensive params copy and audit receives no raw data', async () => {
  const client = verdictClient();
  const harness = setup({ client });
  const params = {
    path: '/tmp/status',
    note: PARAM_SECRET,
    nested: { value: PARAM_SECRET },
  };
  const event = {
    toolName: 'read',
    params,
    runId: RAW_RUN_ID,
    toolCallId: RAW_TOOL_CALL_ID,
  };
  const ctx = {
    toolName: 'read',
    runId: RAW_RUN_ID,
    toolCallId: RAW_TOOL_CALL_ID,
    agentId: RAW_AGENT_ID,
    sessionKey: RAW_SESSION_KEY,
  };
  capturePrompt(harness, `${RAW_PROMPT} ${PROMPT_SECRET}`, RAW_RUN_ID);

  const result = await harness.beforeTool(event, ctx);

  assert.deepEqual(result, { params });
  assert.notStrictEqual(result.params, params);
  assert.notStrictEqual(result.params.nested, params.nested);
  assert.equal(client.calls[0].envelope.params.note, PARAM_SECRET);
  assert.equal(harness.auditEvents.length, 1);
  const serializedAudit = JSON.stringify(harness.auditEvents[0]);
  for (const raw of [
    RAW_PROMPT,
    PROMPT_SECRET,
    PARAM_SECRET,
    API_SECRET,
    RAW_RUN_ID,
    RAW_TOOL_CALL_ID,
    RAW_AGENT_ID,
    RAW_SESSION_KEY,
  ]) {
    assert.equal(serializedAudit.includes(raw), false, `audit exposed ${raw}`);
  }
  for (const forbiddenKey of [
    'prompt',
    'userPrompt',
    'params',
    'run_id',
    'tool_call_id',
    'agent_id',
    'session_key',
    'apiKey',
    'exception',
    'raw_response',
  ]) {
    assert.equal(Object.hasOwn(harness.auditEvents[0], forbiddenKey), false);
  }
});

test('locally unsafe model allow is normalized to review before mapping and audit', async () => {
  const client = verdictClient({
    decision: 'allow',
    risk: 'medium',
    authorization: 'high',
    confidence: 0.99,
  });
  const harness = setup({ client });
  capturePrompt(harness);
  const call = callData();

  const result = await harness.beforeTool(call.event, call.ctx);

  assert.deepEqual(result.params, call.event.params);
  assert.equal(
    result.requireApproval.description,
    createApprovalDescription('local_policy_review'),
  );
  assert.equal(result.requireApproval.severity, 'warning');
  assert.equal(result.requireApproval.timeoutBehavior, 'deny');
  assert.equal(harness.auditEvents.length, 1);
  assert.equal(harness.auditEvents[0].decision, 'allow');
  assert.equal(harness.auditEvents[0].outcome, 'review');
});

test('local surface guard catches an active CI write despite a confident model allow', async (t) => {
  for (const mode of ['autonomous', 'supervised']) {
    await t.test(mode, async () => {
      const harness = setup({
        client: verdictClient(),
        pluginConfig: { mode, enforcement: 'enforce' },
      });
      capturePrompt(harness, 'Fix the typo in the active release workflow.');
      const call = callData('run-1', {
        path: '/workspace/repo/.github/workflows/release.yml',
        edits: [{ oldText: 'teh release', newText: 'the release' }],
      });
      call.event.toolName = 'edit';
      call.ctx.toolName = 'edit';

      const result = await harness.beforeTool(call.event, call.ctx);

      if (mode === 'autonomous') assertBlocked(result, 'local_policy_review');
      else assertApproval(result, call.event.params, 'local_policy_review');
      assert.equal(harness.auditEvents[0].decision, 'allow');
      assert.equal(harness.auditEvents[0].outcome, 'review');
    });
  }
});

test('local surface guard catches browser upload and auth-policy edits in both modes', async (t) => {
  const riskyCalls = [
    ['browser', {
      action: 'upload',
      target: 'host',
      profile: 'user',
      paths: ['/workspace/reports/q3-summary.pdf'],
      inputRef: 'file-input',
    }],
    ['browser', {
      action: 'act',
      request: { kind: 'click', ref: 'confirm' },
    }],
    ['edit', {
      path: '/workspace/src/auth/policy.js',
      edits: [{ oldText: 'expirySeconds = 3600', newText: 'expirySeconds = 7200' }],
    }],
    ['write', {
      path: '/workspace/.devcontainer/scripts/postCreate.sh',
      content: '#!/bin/sh\nnpm ci\n',
    }],
    ['message', {
      action: 'delete',
      channel: 'discord',
      messageId: '123',
    }],
    ['apply_patch', {
      input: '*** Begin Patch\n*** Update File: package.json\n@@\n-  "foo": "1"\n+  "foo": "2"\n*** End Patch',
    }],
    ['sessions_history', {
      sessionKey: 'agent:main:main',
      includeTools: true,
      limit: 15,
    }],
    ['apply_patch', {
      input: '*** Begin Patch\n*** Update File: .npmignore\n@@\n-internal/\n*** End Patch',
    }],
  ];

  for (const mode of ['autonomous', 'supervised']) {
    await t.test(mode, async () => {
      for (const [toolName, params] of riskyCalls) {
        const harness = setup({
          client: verdictClient(),
          pluginConfig: { mode, enforcement: 'enforce' },
        });
        capturePrompt(harness, 'Perform the requested action.');
        const call = callData('run-1', params);
        call.event.toolName = toolName;
        call.ctx.toolName = toolName;

        const result = await harness.beforeTool(call.event, call.ctx);

        if (mode === 'autonomous') assertBlocked(result, 'local_policy_review');
        else assertApproval(result, call.event.params, 'local_policy_review');
        assert.equal(harness.auditEvents[0].decision, 'allow');
        assert.equal(harness.auditEvents[0].outcome, 'review');
      }
    });
  }
});

test('local surface guard catches sensitive reads, gateway secrets, and cross-session history', async (t) => {
  const riskyCalls = [
    ['path traversal', 'read', { path: '/workspace/../tenant-b/repo/CHANGELOG.md' }],
    ['kubeconfig', 'read', { path: '/workspace/.kube/config' }],
    ['production env', 'read', { path: '/workspace/services/api/.env.production' }],
    ['provider key', 'gateway', {
      action: 'config.get',
      path: 'models.providers.openai.apiKey',
    }],
    ['cross-session history', 'sessions_history', {
      sessionKey: 'agent:finance:private',
      includeTools: false,
      limit: 15,
    }],
    ['browser focus without an explicit sandbox target', 'browser', {
      action: 'focus',
      targetId: 'tab-1',
    }],
  ];

  for (const [name, toolName, params] of riskyCalls) {
    await t.test(name, async () => {
      const harness = setup({
        client: verdictClient(),
        pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
      });
      capturePrompt(harness, 'Perform the exact requested read.');
      const call = callData('run-1', params);
      call.event.toolName = toolName;
      call.ctx.toolName = toolName;
      call.ctx.sessionKey = 'agent:main:main';

      const result = await harness.beforeTool(call.event, call.ctx);

      assertBlocked(result);
      assert.equal(harness.auditEvents[0].decision, 'allow');
      assert.equal(harness.auditEvents[0].outcome, 'review');
    });
  }
});

test('local surface guard preserves inert reads, safe config, and own-session history', async (t) => {
  const safeCalls = [
    ['env example', 'read', { path: '/workspace/.env.example' }],
    ['ordinary file', 'read', { path: '/workspace/repo/CHANGELOG.md' }],
    ['gateway config', 'gateway', {
      action: 'config.get',
      path: 'agents.defaults.thinkingDefault',
    }],
    ['own-session history', 'sessions_history', {
      sessionKey: 'agent:main:main',
      includeTools: false,
      limit: 15,
    }],
    ['own-session history default', 'sessions_history', {
      sessionKey: 'agent:main:main',
      limit: 15,
    }],
    ['protective exclusion addition', 'apply_patch', {
      input: '*** Begin Patch\n*** Update File: .npmignore\n@@\n+internal/\n*** End Patch',
    }],
    ['inert package example', 'write', {
      path: '/workspace/repo/package.json.example',
      content: '{"dependencies":{}}',
    }],
  ];

  for (const [name, toolName, params] of safeCalls) {
    await t.test(name, async () => {
      const harness = setup({ client: verdictClient() });
      capturePrompt(harness, 'Perform the exact requested read.');
      const call = callData('run-1', params);
      call.event.toolName = toolName;
      call.ctx.toolName = toolName;
      call.ctx.sessionKey = 'agent:main:main';

      const result = await harness.beforeTool(call.event, call.ctx);

      assert.deepEqual(result, { params: call.event.params });
      assert.equal(harness.auditEvents[0].outcome, 'allow');
    });
  }
});

test('local surface guard preserves a scoped README edit', async () => {
  const harness = setup({ client: verdictClient() });
  capturePrompt(harness, 'Fix the typo in README.');
  const call = callData('run-1', {
    path: '/workspace/repo/README.md',
    edits: [{ oldText: 'teh release', newText: 'the release' }],
  });
  call.event.toolName = 'edit';
  call.ctx.toolName = 'edit';

  const result = await harness.beforeTool(call.event, call.ctx);

  assert.deepEqual(result, { params: call.event.params });
  assert.equal(harness.auditEvents[0].outcome, 'allow');
});

test('a hostile client cannot erase opaque markers before the shared downgrade', async (t) => {
  const cases = [
    ['redacted', { token: 'credential-fixture-never-send-t91' }, 'token', '[REDACTED]'],
    [
      'truncated',
      { command: `${'echo safe '.padEnd(4200, 'x')} && destructive-hidden-suffix` },
      'command',
      '[TRUNCATED]',
    ],
  ];

  for (const [name, rawParams, field, marker] of cases) {
    await t.test(name, async () => {
      let visibleBeforeMutation;
      const client = {
        async review(input) {
          visibleBeforeMutation = input.envelope.params[field];
          input.envelope.params[field] = 'attacker-replaced-with-safe-looking-text';
          return { ok: true, text: verdictText(input), latencyMs: 7 };
        },
      };
      const harness = setup({
        pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
        client,
      });
      capturePrompt(harness, 'Inspect the exact requested action.');
      const call = callData('run-1', rawParams);

      const result = await harness.beforeTool(call.event, call.ctx);

      assert.equal(visibleBeforeMutation.includes(marker), true);
      assertBlocked(result);
      assert.equal(harness.auditEvents[0].decision, 'allow');
      assert.equal(harness.auditEvents[0].outcome, 'review');
    });
  }
});

test('Object.prototype pollution cannot turn inherited runtime fields into an approved call', async () => {
  const client = verdictClient();
  const harness = setup({
    client,
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
  });
  capturePrompt(harness, 'Wait in the active browser page.');
  const call = callData('run-1', { action: 'act', kind: 'wait' });
  call.event.toolName = 'browser';
  call.ctx.toolName = 'browser';

  let result;
  Object.defineProperty(Object.prototype, 'request', {
    configurable: true,
    value: { kind: 'click', ref: 'confirm' },
  });
  try {
    result = await harness.beforeTool(call.event, call.ctx);
  } finally {
    delete Object.prototype.request;
  }

  assertBlocked(result);
  assert.equal(client.calls.length, 0);
});

test('audit cannot pollute Object.prototype after the final allow check', async (t) => {
  for (const mode of ['autonomous', 'supervised']) {
    await t.test(mode, async () => {
      const client = verdictClient();
      const audit = {
        async write() {
          Object.defineProperty(Object.prototype, 'request', {
            configurable: true,
            value: { kind: 'click', ref: 'confirm' },
          });
        },
      };
      const harness = setup({
        audit,
        client,
        pluginConfig: { mode, enforcement: 'enforce' },
      });
      capturePrompt(harness, 'Wait in the active browser page.');
      const call = callData('run-1', { action: 'act', kind: 'wait' });
      call.event.toolName = 'browser';
      call.ctx.toolName = 'browser';

      let result;
      let inheritedRequest;
      try {
        result = await harness.beforeTool(call.event, call.ctx);
        inheritedRequest = result.params?.request;
      } finally {
        delete Object.prototype.request;
      }

      if (mode === 'autonomous') {
        assertBlocked(result, 'local_policy_review');
      } else {
        assert.equal(
          result.requireApproval.description,
          createApprovalDescription('local_policy_review'),
        );
        assert.equal(result.requireApproval.timeoutBehavior, 'deny');
        assert.equal(inheritedRequest, undefined);
      }
      assert.equal(client.calls.length, 1);
    });
  }
});

test('audit side effects cannot create a delivered-outcome mismatch or inherited params', async () => {
  let audited;
  const audit = {
    async write(event) {
      audited = event;
      Object.defineProperty(Object.prototype, 'auditInjectedValue', {
        configurable: true,
        value: PROMPT_SECRET,
      });
      Object.defineProperty(Array.prototype, 'auditInjectedArrayValue', {
        configurable: true,
        value: PROMPT_SECRET,
      });
      Object.defineProperty(Array.prototype, 'toJSON', {
        configurable: true,
        value() {
          return ['attacker-replaced-after-judge'];
        },
      });
    },
  };
  const harness = setup({
    audit,
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
  });
  capturePrompt(harness);
  const call = callData('run-1', {
    path: '/tmp/status',
    nested: { ok: true },
    items: [{ safe: true }],
  });

  let result;
  let inheritedObjectValue;
  let inheritedArrayValue;
  let serializedItems;
  try {
    result = await harness.beforeTool(call.event, call.ctx);
    inheritedObjectValue = result.params.auditInjectedValue;
    inheritedArrayValue = result.params.items.auditInjectedArrayValue;
    serializedItems = JSON.stringify(result.params.items);
  } finally {
    delete Object.prototype.auditInjectedValue;
    delete Array.prototype.auditInjectedArrayValue;
    delete Array.prototype.toJSON;
  }

  assert.equal(audited.outcome, 'allow');
  assert.equal(audited.feedback_code, null);
  assert.equal(audited.feedback_status, null);
  assert.equal(Object.hasOwn(result, 'block'), false);
  assert.equal(result.params.path, '/tmp/status');
  assert.equal(result.params.nested.ok, true);
  assert.equal(result.params.items[0].safe, true);
  assert.equal(inheritedObjectValue, undefined);
  assert.equal(inheritedArrayValue, undefined);
  assert.equal(serializedItems, '[{"safe":true}]');
  assert.equal(Object.hasOwn(result.params, 'auditInjectedValue'), false);
  assert.equal(Object.hasOwn(result.params.nested, 'auditInjectedValue'), false);
  assert.equal(Object.hasOwn(result.params.items, 'auditInjectedArrayValue'), false);
});

test('audit cannot attach approved arrays to a replaced Array.prototype chain', async () => {
  const originalPrototype = Object.getPrototypeOf(Array.prototype);
  const maliciousPrototype = Object.create(originalPrototype, {
    auditInjectedChainValue: {
      configurable: true,
      value: PROMPT_SECRET,
    },
  });
  let audited;
  const audit = {
    async write(event) {
      audited = event;
      Object.setPrototypeOf(Array.prototype, maliciousPrototype);
    },
  };
  const harness = setup({
    audit,
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
  });
  capturePrompt(harness);
  const call = callData('run-1', {
    path: '/tmp/status',
    items: ['reviewed-safe-target'],
  });

  let result;
  let inheritedValue;
  try {
    result = await harness.beforeTool(call.event, call.ctx);
    inheritedValue = result.params.items.auditInjectedChainValue;
  } finally {
    Object.setPrototypeOf(Array.prototype, originalPrototype);
  }

  assert.equal(audited.outcome, 'allow');
  assert.equal(Object.hasOwn(result, 'block'), false);
  assert.equal(inheritedValue, undefined);
  assert.equal(JSON.stringify(result.params.items), '["reviewed-safe-target"]');
});

test('audit cannot bypass recursive detachment through a replaced array iterator', async () => {
  const iteratorDescriptor = Object.getOwnPropertyDescriptor(
    Array.prototype,
    Symbol.iterator,
  );
  const audit = {
    async write() {
      Object.defineProperty(Object.prototype, 'auditIteratorInjectedValue', {
        configurable: true,
        value: PROMPT_SECRET,
      });
      Object.defineProperty(Array.prototype, Symbol.iterator, {
        configurable: true,
        writable: true,
        value() {
          return {
            next() { return { done: true, value: undefined }; },
          };
        },
      });
    },
  };
  const harness = setup({
    audit,
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
  });
  capturePrompt(harness);
  const call = callData('run-1', {
    path: '/tmp/status',
    nested: { safe: true },
    items: [{ safe: true }],
  });

  let result;
  let inheritedNested;
  let inheritedItems;
  try {
    result = await harness.beforeTool(call.event, call.ctx);
    inheritedNested = result.params.nested.auditIteratorInjectedValue;
    inheritedItems = result.params.items.auditIteratorInjectedValue;
  } finally {
    delete Object.prototype.auditIteratorInjectedValue;
    Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
  }

  assert.equal(Object.hasOwn(result, 'block'), false);
  assert.equal(result.params.nested.safe, true);
  assert.equal(result.params.items[0].safe, true);
  assert.equal(inheritedNested, undefined);
  assert.equal(inheritedItems, undefined);
});

test('a credential-redacted action can never be auto-approved by an allow verdict', async () => {
  const client = verdictClient();
  const harness = setup({ client });
  capturePrompt(harness, 'Run the requested authenticated command.');
  const call = callData('run-1', {
    command: 'API_KEY=credential-fixture-never-send-p66 command --safe',
  });

  const result = await harness.beforeTool(call.event, call.ctx);

  assertApproval(result, call.event.params, 'opaque_or_unverifiable');
  assert.equal(client.calls[0].envelope.params.command, '[REDACTED]');
  assert.equal(harness.auditEvents[0].decision, 'allow');
  assert.equal(harness.auditEvents[0].outcome, 'review');
});

test('a truncated action can never be auto-approved by an allow verdict', async () => {
  const client = verdictClient();
  const harness = setup({ client });
  capturePrompt(harness, 'Inspect the requested long command.');
  const call = callData('run-1', {
    command: `${'echo safe '.padEnd(4200, 'x')} && destructive-hidden-suffix`,
  });

  const result = await harness.beforeTool(call.event, call.ctx);

  assertApproval(result, call.event.params, 'opaque_or_unverifiable');
  assert.equal(client.calls[0].envelope.params.command.endsWith('[TRUNCATED]'), true);
  assert.equal(harness.auditEvents[0].decision, 'allow');
  assert.equal(harness.auditEvents[0].outcome, 'review');
});

test('an autonomous action with a camelCase credential field is blocked despite allow', async () => {
  const client = verdictClient();
  const harness = setup({
    client,
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
  });
  capturePrompt(harness, 'Run the authenticated action.');
  const call = callData('run-1', {
    apiKeyValue: 'camel-plugin-secret-fixture-never-send-r88',
  });

  const result = await harness.beforeTool(call.event, call.ctx);

  assertBlocked(result);
  assert.equal(client.calls[0].envelope.params.apiKeyValue, '[REDACTED]');
  assert.equal(harness.auditEvents[0].decision, 'allow');
  assert.equal(harness.auditEvents[0].outcome, 'review');
});

test('explicit deny blocks in autonomous and supervised modes', async (t) => {
  for (const mode of ['autonomous', 'supervised']) {
    await t.test(mode, async () => {
      const client = verdictClient({
        decision: 'deny',
        risk: 'critical',
        authorization: 'low',
        reason_code: 'out_of_scope',
        rationale: 'The action is not authorized.',
      });
      const harness = setup({ pluginConfig: { mode, enforcement: 'enforce' }, client });
      capturePrompt(harness);
      const call = callData();
      const result = await harness.beforeTool(call.event, call.ctx);
      assertBlocked(result, 'out_of_scope');
      assert.equal(Object.hasOwn(result, 'params'), false);
    });
  }
});

test('autonomous review and every judge failure path use the classified safe feedback', async (t) => {
  const cases = [
    ['review', verdictClient({ decision: 'review', risk: 'medium', authorization: 'medium' }), 'other_policy_risk'],
    ['client error', { async review() { return { ok: false, reason: PROMPT_SECRET, latencyMs: 3 }; } }, 'judge_unavailable'],
    ['client throw', { review() { throw new Error(PROMPT_SECRET); } }, 'judge_unavailable'],
    ['client rejection', { async review() { throw new Error(PROMPT_SECRET); } }, 'judge_unavailable'],
    ['client undefined', { async review() { return undefined; } }, 'judge_unavailable'],
    ['client invalid response', { async review() { return { ok: false, reason: 'invalid judge response', latencyMs: 1 }; } }, 'invalid_judge_response'],
    ['client invalid request', { async review() { return { ok: false, reason: 'invalid judge request', latencyMs: 1 }; } }, 'invalid_judge_response'],
    ['parser error', { async review() { return { ok: true, text: '{invalid', latencyMs: 1 }; } }, 'invalid_judge_response'],
    ['wrong policy', {
      async review(input) {
        return {
          ok: true,
          text: verdictText(input, { policy_version: 'wrong-policy' }),
          latencyMs: 1,
        };
      },
    }, 'invalid_judge_response'],
    ['wrong hash', {
      async review(input) {
        return {
          ok: true,
          text: verdictText(input, { action_hash: `sha256:${'f'.repeat(64)}` }),
          latencyMs: 1,
        };
      },
    }, 'invalid_judge_response'],
  ];

  for (const [name, client, expectedCode] of cases) {
    await t.test(name, async () => {
      const harness = setup({
        pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
        client,
      });
      capturePrompt(harness);
      const call = callData();
      const result = await harness.beforeTool(call.event, call.ctx);
      assertBlocked(result, expectedCode);
      assert.equal(harness.auditEvents.length, 1);
      assert.equal(JSON.stringify(harness.auditEvents[0]).includes(PROMPT_SECRET), false);
    });
  }
});

test('injected parser cannot allow an independently invalid eight-field verdict', async (t) => {
  function parsedVerdict(expectedHash, overrides = {}) {
    const verdict = {
      policy_version: POLICY_VERSION,
      action_hash: expectedHash,
      decision: 'allow',
      risk: 'low',
      authorization: 'high',
      confidence: 0.99,
      reason_code: 'safe_and_authorized',
      rationale: 'The exact requested action is authorized.',
      ...overrides,
    };
    if (!Object.hasOwn(overrides, 'reason_code') && verdict.decision !== 'allow') {
      verdict.reason_code = 'other_policy_risk';
    }
    return verdict;
  }

  const cases = [
    ['confidence above one', ({ expectedHash }) => parsedVerdict(expectedHash, { confidence: 2 })],
    ['confidence below zero', ({ expectedHash }) => parsedVerdict(expectedHash, { confidence: -0.1 })],
    ['confidence not finite', ({ expectedHash }) => parsedVerdict(expectedHash, { confidence: Infinity })],
    ['confidence wrong type', ({ expectedHash }) => parsedVerdict(expectedHash, { confidence: '0.99' })],
    ['empty rationale', ({ expectedHash }) => parsedVerdict(expectedHash, { rationale: '' })],
    ['blank rationale', ({ expectedHash }) => parsedVerdict(expectedHash, { rationale: '   ' })],
    ['C0 control in rationale', ({ expectedHash }) => parsedVerdict(expectedHash, { rationale: 'allow\nnow' })],
    ['C1 control in rationale', ({ expectedHash }) => parsedVerdict(expectedHash, { rationale: `allow${String.fromCharCode(0x85)}now` })],
    ['oversized rationale', ({ expectedHash }) => parsedVerdict(expectedHash, { rationale: 'x'.repeat(501) })],
    ['invalid decision enum', ({ expectedHash }) => parsedVerdict(expectedHash, { decision: 'ALLOW' })],
    ['invalid risk enum', ({ expectedHash }) => parsedVerdict(expectedHash, { risk: 'safe' })],
    ['invalid authorization enum', ({ expectedHash }) => parsedVerdict(expectedHash, { authorization: 'none' })],
    ['invalid reason code enum', ({ expectedHash }) => parsedVerdict(expectedHash, { reason_code: 'safe' })],
    ['allow with non-safe reason code', ({ expectedHash }) => parsedVerdict(expectedHash, { reason_code: 'authorization_missing' })],
    ['review with safe reason code', ({ expectedHash }) => parsedVerdict(expectedHash, { decision: 'review', reason_code: 'safe_and_authorized' })],
    ['deny with safe reason code', ({ expectedHash }) => parsedVerdict(expectedHash, { decision: 'deny', reason_code: 'safe_and_authorized' })],
    ['wrong policy type', ({ expectedHash }) => parsedVerdict(expectedHash, { policy_version: 1 })],
    ['wrong hash type', ({ expectedHash }) => parsedVerdict(expectedHash, { action_hash: { expectedHash } })],
    ['wrong rationale type', ({ expectedHash }) => parsedVerdict(expectedHash, { rationale: true })],
    ['missing field', ({ expectedHash }) => {
      const verdict = parsedVerdict(expectedHash);
      delete verdict.authorization;
      return verdict;
    }],
    ['additional field', ({ expectedHash }) => ({
      ...parsedVerdict(expectedHash),
      extra: 'not in the contract',
    })],
    ['symbol key', ({ expectedHash }) => {
      const verdict = parsedVerdict(expectedHash);
      verdict[Symbol('hidden')] = 'extra';
      return verdict;
    }],
    ['non-plain object', ({ expectedHash }) => Object.assign(
      Object.create({ inherited: true }),
      parsedVerdict(expectedHash),
    )],
  ];

  for (const [name, makeVerdict] of cases) {
    await t.test(name, async () => {
      const harness = setup({
        pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
        deps: {
          parseJudgeResponse(_text, options) {
            return { ok: true, verdict: makeVerdict(options) };
          },
        },
      });
      capturePrompt(harness);
      const call = callData();

      const result = await harness.beforeTool(call.event, call.ctx);

      assertBlocked(result);
      assert.equal(Object.hasOwn(result, 'params'), false);
      assert.equal(harness.auditEvents[0].outcome, 'failure');
    });
  }
});

test('plugin snapshots use schema-derived keys and the shared validator', async () => {
  const source = await readFile(new URL('../src/plugin.js', import.meta.url), 'utf8');

  assert.match(source, /from '\.\/judge-schema\.js';/u);
  assert.match(source, /validateJudgeVerdict\(snapshot\);/u);
  assert.doesNotMatch(source, /const VERDICT_KEYS\s*=|const DECISIONS\s*=\s*new Set\(\[|const RISKS\s*=|const AUTHORIZATIONS\s*=/u);
});

test('injected parser cannot pass a proxy or accessor verdict to the safety gate', async (t) => {
  function parsedVerdict(expectedHash) {
    return {
      policy_version: POLICY_VERSION,
      action_hash: expectedHash,
      decision: 'allow',
      risk: 'low',
      authorization: 'high',
      confidence: 0.99,
      reason_code: 'safe_and_authorized',
      rationale: 'The exact requested action is authorized.',
    };
  }

  let getterCalls = 0;
  const cases = [
    ['proxy', ({ expectedHash }) => new Proxy(parsedVerdict(expectedHash), {
      get() {
        getterCalls += 1;
        throw new Error(PROMPT_SECRET);
      },
    })],
    ['accessor', ({ expectedHash }) => {
      const verdict = parsedVerdict(expectedHash);
      Object.defineProperty(verdict, 'rationale', {
        enumerable: true,
        get() {
          getterCalls += 1;
          throw new Error(PROMPT_SECRET);
        },
      });
      return verdict;
    }],
  ];

  for (const [name, makeVerdict] of cases) {
    await t.test(name, async () => {
      const harness = setup({
        pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
        deps: {
          parseJudgeResponse(_text, options) {
            return { ok: true, verdict: makeVerdict(options) };
          },
        },
      });
      capturePrompt(harness);
      const call = callData();

      const result = await harness.beforeTool(call.event, call.ctx);

      assertBlocked(result);
      assert.equal(harness.auditEvents[0].outcome, 'failure');
      assert.equal(JSON.stringify(harness.auditEvents[0]).includes(PROMPT_SECRET), false);
    });
  }
  assert.equal(getterCalls, 0);
});

test('hostile normalizer cannot rewrite a frozen validated deny verdict into allow', async () => {
  let receivedFrozen = false;
  let mutationResults;
  let observedAfter;
  const client = verdictClient({
    decision: 'deny',
    risk: 'critical',
    authorization: 'low',
    confidence: 0.99,
    reason_code: 'other_policy_risk',
    rationale: 'The action is not authorized.',
  });
  const harness = setup({
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
    client,
    deps: {
      normalizeVerdict(verdict) {
        receivedFrozen = Object.isFrozen(verdict);
        mutationResults = [
          Reflect.set(verdict, 'decision', 'allow'),
          Reflect.set(verdict, 'risk', 'low'),
          Reflect.set(verdict, 'authorization', 'high'),
          Reflect.deleteProperty(verdict, 'rationale'),
          Reflect.defineProperty(verdict, 'confidence', { value: 1 }),
        ];
        observedAfter = { ...verdict };
        return { kind: 'allow', verdict };
      },
    },
  });
  capturePrompt(harness);
  const call = callData();

  const result = await harness.beforeTool(call.event, call.ctx);

  assertBlocked(result);
  assert.equal(receivedFrozen, true);
  assert.deepEqual(mutationResults, [false, false, false, false, false]);
  assert.deepEqual(observedAfter, {
    policy_version: POLICY_VERSION,
    action_hash: client.calls[0].envelope.action_hash,
    decision: 'deny',
    risk: 'critical',
    authorization: 'low',
    confidence: 0.99,
    reason_code: 'other_policy_risk',
    rationale: 'The action is not authorized.',
  });
});

test('supervised review, client failures, and missing provider return classified one-call approval', async (t) => {
  const cases = [
    ['review', verdictClient({ decision: 'review', risk: 'critical', authorization: 'unknown' }), {}, 1, 'other_policy_risk'],
    ['client error', { async review() { return { ok: false, reason: 'request failed', latencyMs: 4 }; } }, {}, 1, 'judge_unavailable'],
    ['client throw', { review() { throw new Error(PROMPT_SECRET); } }, {}, 1, 'judge_unavailable'],
    ['client undefined', { async review() { return undefined; } }, {}, 1, 'judge_unavailable'],
    ['client invalid response', { async review() { return { ok: false, reason: 'invalid judge response', latencyMs: 4 }; } }, {}, 1, 'invalid_judge_response'],
    ['client invalid request', { async review() { return { ok: false, reason: 'invalid judge request', latencyMs: 4 }; } }, {}, 1, 'invalid_judge_response'],
    ['parser error', { async review() { return { ok: true, text: 'not json', latencyMs: 4 }; } }, {}, 1, 'invalid_judge_response'],
    ['missing provider', NO_INJECTION, { providerConfig: NO_PROVIDER }, 0, 'judge_unavailable'],
  ];

  for (const [name, client, options, expectedAuditEvents, expectedCode] of cases) {
    await t.test(name, async () => {
      const harness = setup({ client, ...options });
      capturePrompt(harness);
      const call = callData();
      const result = await harness.beforeTool(call.event, call.ctx);
      assertApproval(result, call.event.params, expectedCode);
      assert.notStrictEqual(result.params, call.event.params);
      assert.equal(harness.registrations.length, 2);
      assert.equal(harness.auditEvents.length, expectedAuditEvents);
    });
  }
});

test('shadow evaluates and audits allow, review, deny, and failure without enforcing', async (t) => {
  const cases = [
    ['allow', verdictClient()],
    ['review', verdictClient({ decision: 'review', risk: 'medium', authorization: 'unknown' })],
    ['deny', verdictClient({ decision: 'deny', risk: 'critical', authorization: 'low' })],
    ['failure', { async review() { return { ok: false, reason: 'request failed', latencyMs: 1 }; } }],
  ];
  for (const [name, client] of cases) {
    await t.test(name, async () => {
      const harness = setup({
        pluginConfig: { mode: 'autonomous', enforcement: 'shadow' },
        client,
      });
      capturePrompt(harness);
      const call = callData();
      assert.equal(await harness.beforeTool(call.event, call.ctx), undefined);
      assert.equal(harness.auditEvents.length, 1);
    });
  }
});

test('only api.pluginConfig is parsed; absent pluginConfig keeps autonomous shadow defaults', async () => {
  const client = verdictClient({ decision: 'deny', risk: 'critical', authorization: 'low' });
  const harness = setup({
    pluginConfig: NO_INJECTION,
    configuredEntry: { mode: 'autonomous', enforcement: 'enforce' },
    client,
  });
  capturePrompt(harness);
  const call = callData();

  assert.equal(await harness.beforeTool(call.event, call.ctx), undefined);
  assert.equal(client.calls.length, 1);
  assert.equal(harness.auditEvents.length, 1);
  assert.equal(harness.auditEvents[0].mode, 'autonomous');
  assert.equal(harness.auditEvents[0].enforcement, 'shadow');
});

test('dedicated ENV settings reach factories without reading shared provider', () => {
  const client = verdictClient();
  const audit = { async write() { return true; } };
  const received = {};
  let providerReads = 0;
  const providersOverride = {};
  Object.defineProperty(providersOverride, 'cloudru', {
    enumerable: true,
    get() {
      providerReads += 1;
      throw new Error(API_SECRET);
    },
  });

  const harness = setup({
    client: NO_INJECTION,
    audit: NO_INJECTION,
    providersOverride,
    environment: {
      OPENCLAW_STATE_DIR: '/state',
      OPENCLAW_JUDGE_API_KEY: API_SECRET,
      OPENCLAW_JUDGE_PROFILE: 'supervised',
      OPENCLAW_JUDGE_TIMEOUT_MS: '1000',
      OPENCLAW_JUDGE_AUDIT_PATH: '/state/logs/team/judge.jsonl',
    },
    deps: {
      createJudgeClient(options) {
        received.client = options;
        return client;
      },
      createAuditWriter(options) {
        received.audit = options;
        return audit;
      },
    },
  });

  assert.equal(providerReads, 0);
  assert.equal(harness.registrations.length, 2);
  assert.deepEqual(received.client, {
    providerConfig: {
      baseUrl: 'https://foundation-models.api.cloud.ru/v1',
      apiKey: API_SECRET,
    },
    timeoutMs: 1000,
  });
  assert.equal(received.audit.filePath, '/state/logs/team/judge.jsonl');
  assert.equal(received.audit.rootPath, '/state/logs');
  assert.equal(typeof received.audit.logger.error, 'function');
});

test('ENV profiles map judge failures to shadow, approval, and block', async (t) => {
  const profiles = [
    ['shadow', 'shadow'],
    ['supervised', 'approval'],
    ['autonomous', 'block'],
  ];
  for (const [profile, expected] of profiles) {
    await t.test(profile, async () => {
      const harness = setup({
        environment: { OPENCLAW_JUDGE_PROFILE: profile },
        client: { async review() { return { ok: false, reason: 'request failed', latencyMs: 1 }; } },
      });
      capturePrompt(harness);
      const call = callData();
      const result = await harness.beforeTool(call.event, call.ctx);
      if (expected === 'shadow') assert.equal(result, undefined);
      if (expected === 'approval') assertApproval(result, call.event.params, 'judge_unavailable');
      if (expected === 'block') assertBlocked(result, 'judge_unavailable');
      assert.equal(harness.auditEvents.length, 1);
      assert.equal(harness.auditEvents[0].enforcement, profile === 'shadow' ? 'shadow' : 'enforce');
    });
  }
});

test('invalid ENV keeps both hooks but ignores injected allow and requires approval', async () => {
  const client = verdictClient();
  const harness = setup({
    environment: { OPENCLAW_JUDGE_MODEL: API_SECRET },
    pluginConfig: { mode: 'autonomous', enforcement: 'shadow' },
    client,
  });
  capturePrompt(harness);
  const call = callData();
  const result = await harness.beforeTool(call.event, call.ctx);

  assert.equal(harness.registrations.length, 2);
  assert.equal(client.calls.length, 0);
  assertApproval(result, call.event.params, 'judge_unavailable');
  assert.equal(harness.auditEvents.length, 0);
  assert.deepEqual(harness.logs, ['LLM action judge setup failed']);
});

test('environment is snapshotted once during registration', async () => {
  const environment = { OPENCLAW_JUDGE_PROFILE: 'supervised' };
  const harness = setup({
    environment,
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
    client: { async review() { return { ok: false, reason: 'request failed', latencyMs: 1 }; } },
  });
  environment.OPENCLAW_JUDGE_PROFILE = 'autonomous';
  capturePrompt(harness);
  const call = callData();

  assertApproval(
    await harness.beforeTool(call.event, call.ctx),
    call.event.params,
    'judge_unavailable',
  );
  assert.equal(harness.auditEvents[0].mode, 'supervised');
});

test('dependency injection cannot replace the production settings resolver', async () => {
  let injectedCalls = 0;
  const harness = setup({
    environment: { OPENCLAW_JUDGE_PROFILE: 'supervised' },
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
    client: { async review() { return { ok: false, reason: 'request failed', latencyMs: 1 }; } },
    deps: {
      resolveRuntimeSettings() {
        injectedCalls += 1;
        return {
          config: { mode: 'autonomous', enforcement: 'shadow' },
          providerConfig: VALID_PROVIDER,
          timeoutMs: 1,
          auditPath: '/attacker',
          auditRoot: '/',
          logLevel: 'silent',
        };
      },
    },
  });
  capturePrompt(harness);
  const call = callData();

  assert.equal(injectedCalls, 0);
  assertApproval(
    await harness.beforeTool(call.event, call.ctx),
    call.event.params,
    'judge_unavailable',
  );
});

test('info log level emits one fixed registration message without runtime values', () => {
  const messages = [];
  const logger = {
    error(message) { messages.push(['error', message]); },
    info(message) { messages.push(['info', message]); },
  };
  setup({
    environment: {
      OPENCLAW_JUDGE_API_KEY: API_SECRET,
      OPENCLAW_JUDGE_LOG_LEVEL: 'info',
    },
    logger,
  });

  assert.deepEqual(messages, [['info', 'LLM action judge registered']]);
  assert.equal(JSON.stringify(messages).includes(API_SECRET), false);
});

test('invalid plugin config still registers and uses permanent supervised enforce fallback', async () => {
  const invalidKey = `unknown-${PROMPT_SECRET}`;
  const harness = setup({
    pluginConfig: { mode: 'autonomous', enforcement: 'shadow', [invalidKey]: API_SECRET },
    client: { async review() { return { ok: false, reason: PARAM_SECRET, latencyMs: 1 }; } },
  });
  assert.equal(harness.registrations.length, 2);
  capturePrompt(harness);
  const call = callData();

  const result = await harness.beforeTool(call.event, call.ctx);

  assertApproval(result, call.event.params, 'judge_unavailable');
  assert.equal(harness.logs.length, 1);
  assert.equal(typeof harness.logs[0], 'string');
  assert.ok(harness.logs[0].length <= 80);
  for (const raw of [invalidKey, PROMPT_SECRET, PARAM_SECRET, API_SECRET]) {
    assert.equal(harness.logs[0].includes(raw), false);
  }
});

test('uses api.config.models.providers.cloudru with the default timeout', () => {
  let received;
  const client = verdictClient();
  const providerConfig = { ...VALID_PROVIDER };
  const harness = setup({
    client: NO_INJECTION,
    providerConfig,
    deps: {
      createJudgeClient(options) {
        received = options;
        return client;
      },
    },
  });

  assert.equal(harness.registrations.length, 2);
  assert.deepEqual(received, {
    providerConfig,
    timeoutMs: 30_000,
  });
});

test('missing, invalid, and throwing Cloud.ru client configuration still registers and fails safely', async (t) => {
  const cases = [
    ['missing', { providerConfig: NO_PROVIDER }, 0],
    ['invalid', { providerConfig: { baseUrl: '', apiKey: API_SECRET } }, 0],
    ['factory throw', {
      providerConfig: VALID_PROVIDER,
      deps: { createJudgeClient() { throw new Error(API_SECRET); } },
    }, 1],
  ];
  for (const [name, options, expectedAuditEvents] of cases) {
    await t.test(name, async () => {
      const harness = setup({ client: NO_INJECTION, ...options });
      assert.equal(harness.registrations.length, 2);
      capturePrompt(harness);
      const call = callData();
      assertApproval(
        await harness.beforeTool(call.event, call.ctx),
        call.event.params,
        'judge_unavailable',
      );
      assert.equal(harness.auditEvents.length, expectedAuditEvents);
    });
  }
});

test('pre-existing run, tool call, or tool name conflicts fail before the client', async (t) => {
  const mutations = [
    ['run ID', (call) => { call.ctx.runId = 'other-run'; }],
    ['tool call ID', (call) => { call.ctx.toolCallId = 'other-call'; }],
    ['tool name', (call) => { call.ctx.toolName = 'exec'; }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, async () => {
      const client = verdictClient();
      const harness = setup({ client });
      capturePrompt(harness);
      const call = callData();
      mutate(call);
      const result = await harness.beforeTool(call.event, call.ctx);
      assert.equal(client.calls.length, 0);
      assertApproval(result, call.event.params);
    });
  }
});

test('params, IDs, or tool name mutated during async review can never allow', async (t) => {
  const mutations = [
    ['params', (call) => { call.event.params.nested.value = 'mutated'; }],
    ['run ID', (call) => {
      call.event.runId = 'mutated-run';
      call.ctx.runId = 'mutated-run';
    }],
    ['tool call ID', (call) => {
      call.event.toolCallId = 'mutated-call';
      call.ctx.toolCallId = 'mutated-call';
    }],
    ['tool name', (call) => {
      call.event.toolName = 'exec';
      call.ctx.toolName = 'exec';
    }],
    ['hostile params getter', (call) => {
      Object.defineProperty(call.event, 'params', {
        configurable: true,
        get() {
          throw new Error(PARAM_SECRET);
        },
      });
    }],
  ];

  for (const [name, mutate] of mutations) {
    await t.test(name, async () => {
      let release;
      let startedResolve;
      const started = new Promise((resolve) => { startedResolve = resolve; });
      const client = {
        review(input) {
          startedResolve();
          return new Promise((resolve) => {
            release = () => resolve({ ok: true, text: verdictText(input), latencyMs: 8 });
          });
        },
      };
      const harness = setup({
        pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
        client,
      });
      capturePrompt(harness);
      const call = callData('run-1', {
        path: '/tmp/status',
        nested: { value: 'original' },
      });
      const pending = harness.beforeTool(call.event, call.ctx);
      await started;
      mutate(call);
      release();
      const result = await pending;
      assertBlocked(result, 'invalid_judge_response');
      assert.equal(harness.auditEvents.length, 1);
      assert.equal(harness.auditEvents[0].outcome, 'failure');
      assert.equal(harness.auditEvents[0].feedback_code, 'invalid_judge_response');
      assert.equal(harness.auditEvents[0].feedback_status, 'blocked');
    });
  }
});

test('store, client, parser, audit, and logger hostile getter/throw paths never escape', async (t) => {
  await t.test('store put/get accessors and rejections', async () => {
    const stores = [];
    const putGetter = { get() { return undefined; } };
    Object.defineProperty(putGetter, 'put', { get() { throw new Error(PROMPT_SECRET); } });
    stores.push(putGetter);
    const getGetter = { put() {} };
    Object.defineProperty(getGetter, 'get', { get() { throw new Error(PROMPT_SECRET); } });
    stores.push(getGetter);
    stores.push({ put() { return Promise.reject(new Error(PROMPT_SECRET)); }, get() { return undefined; } });
    stores.push({ put() {}, get() { return Promise.reject(new Error(PROMPT_SECRET)); } });

    for (const store of stores) {
      const harness = setup({ store });
      assert.doesNotThrow(() => capturePrompt(harness));
      const call = callData();
      assertApproval(await harness.beforeTool(call.event, call.ctx), call.event.params);
    }
  });

  await t.test('client review accessor, throw, rejection, and hostile result', async () => {
    const getterClient = {};
    Object.defineProperty(getterClient, 'review', { get() { throw new Error(PROMPT_SECRET); } });
    const hostileResultClient = {
      async review() {
        const result = {};
        Object.defineProperty(result, 'ok', { get() { throw new Error(PROMPT_SECRET); } });
        return result;
      },
    };
    const clients = [
      [getterClient, 'judge_unavailable'],
      [{ review() { throw new Error(PROMPT_SECRET); } }, 'judge_unavailable'],
      [{ review() { return Promise.reject(new Error(PROMPT_SECRET)); } }, 'judge_unavailable'],
      [hostileResultClient, 'invalid_judge_response'],
    ];
    for (const [client, expectedCode] of clients) {
      const harness = setup({ client });
      capturePrompt(harness);
      const call = callData();
      assertApproval(
        await harness.beforeTool(call.event, call.ctx),
        call.event.params,
        expectedCode,
      );
    }
  });

  await t.test('parser throw and hostile parser result', async () => {
    const parsers = [
      () => { throw new Error(PROMPT_SECRET); },
      () => {
        const result = {};
        Object.defineProperty(result, 'ok', { get() { throw new Error(PROMPT_SECRET); } });
        return result;
      },
    ];
    for (const parseJudgeResponse of parsers) {
      const harness = setup({ deps: { parseJudgeResponse } });
      capturePrompt(harness);
      const call = callData();
      assertApproval(await harness.beforeTool(call.event, call.ctx), call.event.params);
    }
  });

  await t.test('normalizer throw becomes failure', async () => {
    const harness = setup({
      deps: { normalizeVerdict() { throw new Error(PROMPT_SECRET); } },
    });
    capturePrompt(harness);
    const call = callData();
    assertApproval(await harness.beforeTool(call.event, call.ctx), call.event.params);
  });

  await t.test('audit write accessor, throw, and rejection never changes allow', async () => {
    const getterAudit = {};
    Object.defineProperty(getterAudit, 'write', { get() { throw new Error(PROMPT_SECRET); } });
    const audits = [
      getterAudit,
      { write() { throw new Error(PROMPT_SECRET); } },
      { write() { return Promise.reject(new Error(PROMPT_SECRET)); } },
    ];
    for (const audit of audits) {
      const harness = setup({ audit });
      capturePrompt(harness);
      const call = callData();
      const result = await harness.beforeTool(call.event, call.ctx);
      assert.deepEqual(result.params, call.event.params);
      assert.notStrictEqual(result.params, call.event.params);
    }
  });

  await t.test('logger accessor, throwing method, and rejected method do not affect registration', async () => {
    const getterApi = makeApi({ pluginConfig: { invalid: PROMPT_SECRET } });
    Object.defineProperty(getterApi.api, 'logger', {
      configurable: true,
      get() {
        throw new Error(PROMPT_SECRET);
      },
    });
    assert.doesNotThrow(() => createActionJudgePlugin({
      client: verdictClient(),
      audit: { write() {} },
    }).register(getterApi.api));
    assert.equal(getterApi.registrations.length, 2);

    for (const logger of [
      { error() { throw new Error(PROMPT_SECRET); } },
      { error() { return Promise.reject(new Error(PROMPT_SECRET)); } },
    ]) {
      const harness = setup({ pluginConfig: { invalid: PROMPT_SECRET }, logger });
      assert.equal(harness.registrations.length, 2);
    }
    await new Promise((resolve) => setImmediate(resolve));
  });
});

test('store/decision/audit factory failures use safe fallbacks without escaping registration', async (t) => {
  await t.test('store factory failure leaves a registered missing-intent path', async () => {
    const harness = setup({
      deps: { createContextStore() { throw new Error(PROMPT_SECRET); } },
    });
    assert.equal(harness.registrations.length, 2);
    assert.doesNotThrow(() => capturePrompt(harness));
    const call = callData();
    assertApproval(await harness.beforeTool(call.event, call.ctx), call.event.params);
  });

  await t.test('decision-store factory failure leaves a registered fail-closed path', async () => {
    const client = verdictClient();
    const harness = setup({
      pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
      client,
      deps: { createRunDecisionStore() { throw new Error(PROMPT_SECRET); } },
    });
    assert.equal(harness.registrations.length, 2);
    capturePrompt(harness);
    const call = callData();
    assertBlocked(
      await harness.beforeTool(call.event, call.ctx),
      'invalid_judge_response',
    );
    assert.equal(client.calls.length, 0);
  });

  await t.test('audit factory failure does not change allow', async () => {
    const harness = setup({
      audit: NO_INJECTION,
      deps: { createAuditWriter() { throw new Error(PROMPT_SECRET); } },
    });
    assert.equal(harness.registrations.length, 2);
    capturePrompt(harness);
    const call = callData();
    const result = await harness.beforeTool(call.event, call.ctx);
    assert.deepEqual(result.params, call.event.params);
    assert.notStrictEqual(result.params, call.event.params);
  });
});

test('malformed event getters return an explicit safe mapping and still attempt audit', async () => {
  const harness = setup();
  capturePrompt(harness);
  const call = callData();
  Object.defineProperty(call.event, 'toolName', {
    get() {
      throw new Error(PROMPT_SECRET);
    },
  });

  const result = await harness.beforeTool(call.event, call.ctx);

  assertApproval(result, {});
  assert.equal(harness.auditEvents.length, 1);
  assert.equal(JSON.stringify(harness.auditEvents[0]).includes(PROMPT_SECRET), false);
});

test('concurrent distinct run IDs never cross-contaminate trusted intent', async () => {
  const seen = [];
  const client = {
    async review(input) {
      seen.push({ prompt: input.userPrompt, path: input.envelope.params.path });
      await new Promise((resolve) => setImmediate(resolve));
      return { ok: true, text: verdictText(input), latencyMs: 2 };
    },
  };
  const harness = setup({ client });
  capturePrompt(harness, 'Prompt for run A', 'run-a');
  capturePrompt(harness, 'Prompt for run B', 'run-b');
  const callA = callData('run-a', { path: '/a' });
  const callB = callData('run-b', { path: '/b' });

  const [resultB, resultA] = await Promise.all([
    harness.beforeTool(callB.event, callB.ctx),
    harness.beforeTool(callA.event, callA.ctx),
  ]);

  assert.deepEqual(resultA.params, { path: '/a' });
  assert.deepEqual(resultB.params, { path: '/b' });
  assert.deepEqual(
    seen.sort((left, right) => left.path.localeCompare(right.path)),
    [
      { prompt: 'Prompt for run A', path: '/a' },
      { prompt: 'Prompt for run B', path: '/b' },
    ],
  );
  assert.equal(harness.auditEvents.length, 2);
});
