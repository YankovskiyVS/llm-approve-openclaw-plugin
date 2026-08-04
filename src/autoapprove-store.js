const DEFAULT_TTL_MS = 30 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 1000;

/**
 * Tracks per-run / per-session autoapprove activation and pending A2A bridge
 * decisions produced by before_tool_call for the monkey-patched requestApproval.
 */
export function createAutoApproveStore({
  ttlMs = DEFAULT_TTL_MS,
  maxEntries = DEFAULT_MAX_ENTRIES,
  now = Date.now,
} = {}) {
  const runs = new Map();
  const sessions = new Map();
  const decisions = new Map();

  function prune(map) {
    const ts = now();
    for (const [key, entry] of map) {
      if (!entry || typeof entry.expiresAt !== 'number' || entry.expiresAt <= ts) {
        map.delete(key);
      }
    }
    while (map.size > maxEntries) {
      const oldest = map.keys().next().value;
      if (oldest === undefined) break;
      map.delete(oldest);
    }
  }

  function putFlag(map, key) {
    if (typeof key !== 'string' || key.trim() === '') return;
    prune(map);
    map.delete(key);
    map.set(key, { expiresAt: now() + ttlMs });
    prune(map);
  }

  function hasFlag(map, key) {
    if (typeof key !== 'string' || key.trim() === '') return false;
    prune(map);
    const entry = map.get(key);
    if (!entry || entry.expiresAt <= now()) {
      map.delete(key);
      return false;
    }
    return true;
  }

  return {
    markRun(runId) {
      putFlag(runs, runId);
    },
    markSession(sessionKey) {
      putFlag(sessions, normalizeSessionKey(sessionKey));
    },
    isActive({ runId, sessionKey } = {}) {
      if (hasFlag(runs, runId)) return true;
      return hasFlag(sessions, normalizeSessionKey(sessionKey));
    },
    putDecision(callId, decision) {
      if (typeof callId !== 'string' || callId.trim() === '') return;
      if (decision !== 'allow-once' && decision !== 'deny') return;
      prune(decisions);
      decisions.delete(callId);
      decisions.set(callId, { decision, expiresAt: now() + ttlMs });
      prune(decisions);
    },
    takeDecision(callId) {
      if (typeof callId !== 'string' || callId.trim() === '') return undefined;
      prune(decisions);
      const entry = decisions.get(callId);
      if (!entry || entry.expiresAt <= now()) {
        decisions.delete(callId);
        return undefined;
      }
      decisions.delete(callId);
      return entry.decision;
    },
    peekDecision(callId) {
      if (typeof callId !== 'string' || callId.trim() === '') return undefined;
      prune(decisions);
      const entry = decisions.get(callId);
      if (!entry || entry.expiresAt <= now()) {
        decisions.delete(callId);
        return undefined;
      }
      return entry.decision;
    },
  };
}

export function normalizeSessionKey(sessionKey) {
  if (typeof sessionKey !== 'string') return undefined;
  const raw = sessionKey.trim();
  if (!raw) return undefined;
  return raw.replace(/^session:/u, '');
}

/**
 * Derive A2A contextId from OpenClaw session keys like
 * `agent:{agentId}:a2a:{contextId}`.
 */
export function contextIdFromSessionKey(sessionKey) {
  const normalized = normalizeSessionKey(sessionKey);
  if (!normalized) return undefined;
  const marker = ':a2a:';
  const index = normalized.lastIndexOf(marker);
  if (index < 0) return undefined;
  const contextId = normalized.slice(index + marker.length).trim();
  return contextId || undefined;
}
