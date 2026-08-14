import test from 'node:test';
import assert from 'node:assert/strict';

import {
  A2A_BRIDGE_GLOBAL_KEY,
  attachA2ABridgeAdapter,
} from '../src/a2a-bridge-adapter.js';
import { createAutoApproveStore } from '../src/autoapprove-store.js';
import { createActionJudgePlugin } from '../src/plugin.js';
import { createContextStore } from '../src/context-store.js';
import { POLICY_VERSION } from '../src/constants.js';

/**
 * Mirrors openclaw-a2a-gateway/index.ts before_tool_call:
 * priority 100, awaits bridge.requestApproval, returns { block } on deny/timeout.
 */
function createA2AGatewayHook(bridge) {
  return async (event, ctx) => {
    const toolName = event.toolName || ctx.toolName;
    if (!toolName) return undefined;
    const decision = await bridge.requestApproval({
      toolName,
      params: event.params ?? {},
      toolCallId: event.toolCallId ?? ctx.toolCallId,
      runId: event.runId ?? ctx.runId,
      sessionKey: ctx.sessionKey,
      timeoutMs: 120_000,
    });
    if (decision === 'deny' || decision === 'timeout' || decision === 'cancelled') {
      return {
        block: true,
        blockReason:
          decision === 'deny'
            ? `Tool "${toolName}" denied by user`
            : `Tool "${toolName}" approval ${decision}`,
      };
    }
    return undefined;
  };
}

/**
 * OpenClaw merges before_tool_call results: any { block: true } wins.
 */
function mergeHookResults(results) {
  for (const result of results) {
    if (result && result.block === true) return result;
  }
  for (const result of results) {
    if (result && result.params !== undefined) return result;
  }
  return undefined;
}

test('a2a-gateway + judge composition allows tools on technical judge failure', async () => {
  const root = Object.create(null);
  const hitlCalls = [];
  root[A2A_BRIDGE_GLOBAL_KEY] = {
    async requestApproval(params) {
      hitlCalls.push(params);
      // Would hang 120s in production without our monkey-patch.
      return 'timeout';
    },
  };

  const autoApproveStore = createAutoApproveStore({ now: () => 1 });
  attachA2ABridgeAdapter({
    autoApproveStore,
    root,
    decisionWaitMs: 30,
    decisionPollIntervalMs: 5,
  });

  const registrations = [];
  const api = {
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
    config: {
      models: {
        providers: {
          cloudru: {
            baseUrl: 'https://foundation-models.api.cloud.ru/v1',
            apiKey: 'test-key',
          },
        },
      },
      agents: {
        defaults: {
          model: { primary: 'cloudru/Qwen/Qwen3.6-35B-A3B' },
        },
      },
    },
    logger: { info() {}, error() {} },
    on(name, handler, options) {
      registrations.push({ name, handler, options });
    },
  };

  const store = createContextStore({
    ttlMs: 60_000,
    maxEntries: 100,
    now: Date.now,
  });
  createActionJudgePlugin({
    environment: {
      OPENCLAW_JUDGE_API_KEY: 'test-key',
      OPENCLAW_JUDGE_PROFILE: 'autonomous',
      OPENCLAW_JUDGE_A2A_HITL_REPLACE: 'true',
    },
    store,
    autoApproveStore,
    // Force technical failure path (no trusted prompt / no LLM).
    client: {
      async review() {
        return { ok: false, reason: 'invalid judge response', latencyMs: 1 };
      },
    },
    scheduleA2ABridgeAttach() {
      return { attached: true, detach() {} };
    },
  }).register(api);

  const capture = registrations.find((r) => r.name === 'before_model_resolve')?.handler;
  const judgeGate = registrations.find((r) => r.name === 'before_tool_call')?.handler;
  assert.equal(typeof capture, 'function');
  assert.equal(typeof judgeGate, 'function');
  assert.equal(
    registrations.find((r) => r.name === 'before_tool_call')?.options?.priority,
    -1000,
  );

  const sessionKey = 'agent:main:a2a:ctx-compose';
  // Mark autoapprove without storing a usable prompt → technical failure path.
  capture(
    { prompt: '<!--openclaw:autoapprove=1-->\n' },
    { runId: 'run-compose', sessionKey },
  );
  // Empty stripped prompt is not trusted; mark session explicitly like a prior turn.
  autoApproveStore.markSession(sessionKey);

  const event = {
    toolName: 'read',
    params: { path: '/tmp/BOOTSTRAP.md' },
    runId: 'run-compose',
    toolCallId: 'chatcmpl-tool-compose-1',
  };
  const ctx = {
    toolName: 'read',
    runId: 'run-compose',
    toolCallId: 'chatcmpl-tool-compose-1',
    sessionKey,
  };

  const a2aHook = createA2AGatewayHook(root[A2A_BRIDGE_GLOBAL_KEY]);

  // Same order as OpenClaw: judge priority -1000, then a2a priority 100.
  const judgeResult = await judgeGate(event, ctx);
  const a2aResult = await a2aHook(event, ctx);
  const merged = mergeHookResults([judgeResult, a2aResult]);

  assert.equal(judgeResult?.block, undefined, 'judge must fail-open, not block');
  assert.deepEqual(judgeResult?.params, { path: '/tmp/BOOTSTRAP.md' });
  assert.equal(a2aResult, undefined, 'a2a allow path returns undefined');
  assert.equal(merged?.block, undefined, 'merged result must not block the tool');
  assert.equal(hitlCalls.length, 0, 'must not fall through to native HITL wait');
});

test('a2a-gateway + judge composition still denies policy deny', async () => {
  const root = Object.create(null);
  root[A2A_BRIDGE_GLOBAL_KEY] = {
    async requestApproval() {
      return 'timeout';
    },
  };
  const autoApproveStore = createAutoApproveStore({ now: () => 1 });
  attachA2ABridgeAdapter({
    autoApproveStore,
    root,
    decisionWaitMs: 30,
    decisionPollIntervalMs: 5,
  });

  const registrations = [];
  const api = {
    pluginConfig: { mode: 'autonomous', enforcement: 'enforce' },
    config: {
      models: {
        providers: {
          cloudru: {
            baseUrl: 'https://foundation-models.api.cloud.ru/v1',
            apiKey: 'test-key',
          },
        },
      },
    },
    logger: { info() {}, error() {} },
    on(name, handler) {
      registrations.push({ name, handler });
    },
  };

  const store = createContextStore({
    ttlMs: 60_000,
    maxEntries: 100,
    now: Date.now,
  });
  createActionJudgePlugin({
    environment: {
      OPENCLAW_JUDGE_API_KEY: 'test-key',
      OPENCLAW_JUDGE_PROFILE: 'autonomous',
      OPENCLAW_JUDGE_A2A_HITL_REPLACE: 'true',
    },
    store,
    autoApproveStore,
    client: {
      async review(input) {
        return {
          ok: true,
          text: JSON.stringify({
            policy_version: POLICY_VERSION,
            action_hash: input.envelope.action_hash,
            decision: 'deny',
            risk: 'high',
            authorization: 'low',
            confidence: 0.99,
            reason_code: 'out_of_scope',
            rationale: 'Denied by policy for the composition test.',
          }),
          latencyMs: 1,
        };
      },
    },
    scheduleA2ABridgeAttach() {
      return { attached: true, detach() {} };
    },
  }).register(api);

  const capture = registrations.find((r) => r.name === 'before_model_resolve').handler;
  const judgeGate = registrations.find((r) => r.name === 'before_tool_call').handler;
  const sessionKey = 'agent:main:a2a:ctx-deny';
  capture(
    { prompt: '<!--openclaw:autoapprove=1-->\nOnly say hello.' },
    { runId: 'run-deny', sessionKey },
  );

  const event = {
    toolName: 'exec',
    params: { command: 'rm -rf /' },
    runId: 'run-deny',
    toolCallId: 'chatcmpl-tool-deny-1',
  };
  const ctx = {
    toolName: 'exec',
    runId: 'run-deny',
    toolCallId: 'chatcmpl-tool-deny-1',
    sessionKey,
  };

  const a2aHook = createA2AGatewayHook(root[A2A_BRIDGE_GLOBAL_KEY]);
  const judgeResult = await judgeGate(event, ctx);
  const a2aResult = await a2aHook(event, ctx);
  const merged = mergeHookResults([judgeResult, a2aResult]);

  assert.equal(merged?.block, true, 'policy deny must still block');
});
