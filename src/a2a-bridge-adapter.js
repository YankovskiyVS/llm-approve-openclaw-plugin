/**
 * A2A HITL replace adapter.
 *
 * openclaw-a2a-gateway exposes a process-wide ToolApprovalBridge on
 * `globalThis.__openclaw_a2a_tool_approval_bridge_v1__`. Its before_tool_call
 * hook awaits `requestApproval(...)`.
 *
 * For autoapprove chats we still call the original bridge for allow decisions so
 * pending_approval / tool artifacts are published on the A2A bus (WS/UI see the
 * same tool timeline as manual HITL). agent-space-manager then auto-sends
 * allow-once. Only judge deny short-circuits without waiting on a human.
 */

export const A2A_BRIDGE_GLOBAL_KEY = '__openclaw_a2a_tool_approval_bridge_v1__';
export const A2A_BRIDGE_WRAPPED_FLAG = '__llmActionJudgeA2aWrapped';

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

    // Wait briefly for before_tool_call (priority -1000) to store the verdict.
    let decision = callId ? autoApproveStore.takeDecision(callId) : undefined;
    if (decision !== 'allow-once' && decision !== 'deny' && callId) {
      decision = await waitForBridgeDecision(autoApproveStore, callId, {
        attempts: 40,
        intervalMs: 25,
      });
    }

    if (decision === 'deny') {
      try {
        logger.info?.('llm-action-judge: a2a autoapprove deny (no human wait)');
      } catch {
        // ignore logger failures
      }
      return 'deny';
    }

    // allow-once or unknown: use the real HITL path so pending_approval is
    // published to A2A clients (tools visible over WS). Manager auto-approves.
    try {
      logger.info?.('llm-action-judge: a2a autoapprove deferring to HITL publish path');
    } catch {
      // ignore
    }
    return original(params);
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
  attempts = 40,
  intervalMs = 25,
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
