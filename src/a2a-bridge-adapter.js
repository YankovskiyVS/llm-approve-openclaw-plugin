/**
 * A2A HITL replace adapter.
 *
 * openclaw-a2a-gateway exposes a process-wide ToolApprovalBridge on
 * `globalThis.__openclaw_a2a_tool_approval_bridge_v1__`. Its before_tool_call
 * hook awaits `requestApproval(...)`. We wrap that method so that when the
 * chat has autoapprove enabled, the LLM judge decision (stored by our
 * before_tool_call) replaces the human without modifying a2a-gateway source.
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

    // Prefer decision already produced by before_tool_call (same turn, earlier hook).
    let decision = callId ? autoApproveStore.takeDecision(callId) : undefined;
    if (decision !== 'allow-once' && decision !== 'deny') {
      // Race: a2a hook may run before our store write settles in exotic hosts.
      // Fail closed for autoapprove sessions.
      try {
        logger.warn?.('llm-action-judge: a2a autoapprove missing prior decision; denying');
      } catch {
        // ignore logger failures
      }
      decision = 'deny';
    }

    // When allow-once: skip original wait so the human UI is not required.
    // Bridge publish of pending_approval is skipped; after_tool_call still emits
    // terminal tool status via a2a hooks.
    return decision;
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
