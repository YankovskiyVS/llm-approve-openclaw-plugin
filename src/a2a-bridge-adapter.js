/**
 * A2A HITL replace adapter.
 *
 * openclaw-a2a-gateway exposes a process-wide ToolApprovalBridge on
 * `globalThis.__openclaw_a2a_tool_approval_bridge_v1__`. Its before_tool_call
 * hook awaits `requestApproval(...)`.
 *
 * For autoapprove chats the judge is the approver: allow-once and deny are
 * returned immediately (no human / manager wait). If no verdict arrives within
 * the judge wait window, autoapprove fails open with allow-once.
 */

import { JUDGE_TIMEOUT_MS } from './constants.js';

export const A2A_BRIDGE_GLOBAL_KEY = '__openclaw_a2a_tool_approval_bridge_v1__';
export const A2A_BRIDGE_WRAPPED_FLAG = '__llmActionJudgeA2aWrapped';

const DECISION_POLL_INTERVAL_MS = 50;
// Cover a full judge LLM round-trip (default 30s) plus local guard slack.
const DECISION_WAIT_MS = JUDGE_TIMEOUT_MS + 5_000;

/**
 * @param {object} options
 * @param {{ isActive: Function, takeDecision: Function, peekDecision?: Function }} options.autoApproveStore
 * @param {{ info?: Function, warn?: Function, error?: Function }} [options.logger]
 * @param {typeof globalThis} [options.root]
 * @returns {{ attached: boolean, detach: Function }}
 */
export function attachA2ABridgeAdapter({
  autoApproveStore,
  logger = {},
  root = globalThis,
  decisionWaitMs = DECISION_WAIT_MS,
  decisionPollIntervalMs = DECISION_POLL_INTERVAL_MS,
} = {}) {
  if (!autoApproveStore || typeof autoApproveStore.isActive !== 'function') {
    return { attached: false, detach() {} };
  }

  const bridge = root?.[A2A_BRIDGE_GLOBAL_KEY];
  if (!bridge || typeof bridge.requestApproval !== 'function') {
    return { attached: false, detach() {} };
  }
  if (bridge[A2A_BRIDGE_WRAPPED_FLAG] === true) {
    return { attached: true, detach() {} };
  }

  const original = bridge.requestApproval.bind(bridge);
  const waitAttempts = Math.max(
    1,
    Math.ceil(Math.max(0, decisionWaitMs) / Math.max(1, decisionPollIntervalMs)),
  );

  async function wrappedRequestApproval(params = {}) {
    const sessionKey = typeof params.sessionKey === 'string' ? params.sessionKey : undefined;
    const runId = typeof params.runId === 'string' ? params.runId : undefined;
    const callId = typeof params.toolCallId === 'string' && params.toolCallId.trim()
      ? params.toolCallId.trim()
      : undefined;

    const active = autoApproveStore.isActive({ runId, sessionKey });
    if (!active) {
      return original(params);
    }

    // Wait for before_tool_call (priority -1000) to store the verdict.
    let decision = callId ? autoApproveStore.takeDecision(callId) : undefined;
    if (decision !== 'allow-once' && decision !== 'deny' && callId) {
      decision = await waitForBridgeDecision(autoApproveStore, callId, {
        attempts: waitAttempts,
        intervalMs: decisionPollIntervalMs,
      });
    }

    if (decision === 'allow-once') {
      try {
        logger.info?.('llm-action-judge: a2a autoapprove allow-once (judge approved)');
      } catch {
        // ignore logger failures
      }
      return 'allow-once';
    }

    if (decision === 'deny') {
      try {
        logger.info?.('llm-action-judge: a2a autoapprove deny (no human wait)');
      } catch {
        // ignore logger failures
      }
      return 'deny';
    }

    // Autoapprove chats must not hang on HITL when the judge is slow/missing.
    try {
      logger.info?.('llm-action-judge: a2a autoapprove missing verdict; allow-once');
    } catch {
      // ignore
    }
    return 'allow-once';
  }

  bridge.requestApproval = wrappedRequestApproval;
  bridge[A2A_BRIDGE_WRAPPED_FLAG] = true;

  return {
    attached: true,
    detach() {
      if (bridge.requestApproval === wrappedRequestApproval) {
        bridge.requestApproval = original;
      }
      try {
        delete bridge[A2A_BRIDGE_WRAPPED_FLAG];
      } catch {
        bridge[A2A_BRIDGE_WRAPPED_FLAG] = false;
      }
    },
  };
}

async function waitForBridgeDecision(store, callId, {
  attempts = 1,
  intervalMs = DECISION_POLL_INTERVAL_MS,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  for (let i = 0; i < attempts; i += 1) {
    const peeked = typeof store.peekDecision === 'function'
      ? store.peekDecision(callId)
      : undefined;
    if (peeked === 'allow-once' || peeked === 'deny') {
      return store.takeDecision(callId);
    }
    const taken = store.takeDecision(callId);
    if (taken === 'allow-once' || taken === 'deny') {
      return taken;
    }
    await sleep(intervalMs);
  }
  return undefined;
}

/**
 * Retry attach until a2a-gateway registers the singleton (plugin load order
 * is not guaranteed).
 */
export function scheduleA2ABridgeAttach(options = {}, {
  attempts = 40,
  intervalMs = 250,
  setTimeoutFn = setTimeout,
} = {}) {
  let remaining = attempts;
  let timer;
  let handle = { attached: false, detach() {} };

  function tryAttach() {
    handle = attachA2ABridgeAdapter(options);
    if (handle.attached || remaining <= 0) {
      return handle;
    }
    remaining -= 1;
    timer = setTimeoutFn(tryAttach, intervalMs);
    return handle;
  }

  tryAttach();
  return {
    get attached() {
      return handle.attached;
    },
    detach() {
      if (timer) {
        try {
          clearTimeout(timer);
        } catch {
          // ignore
        }
      }
      handle.detach();
    },
  };
}
