function assertNonBlankString(value, name) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${name} must be a non-blank string`);
  }
}

function normalizeSessionKey(sessionKey) {
  if (typeof sessionKey !== 'string') return undefined;
  const raw = sessionKey.trim();
  if (!raw) return undefined;
  return raw.replace(/^session:/u, '');
}

export function createContextStore({ ttlMs, maxEntries, now } = {}) {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new TypeError('ttlMs must be a positive finite number');
  }
  if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
    throw new TypeError('maxEntries must be a positive integer');
  }
  if (typeof now !== 'function') {
    throw new TypeError('now must be a function');
  }

  const byRun = new Map();
  const bySession = new Map();

  function pruneMap(map, timestamp) {
    for (const [key, entry] of map) {
      if (timestamp - entry.createdAt >= ttlMs) map.delete(key);
    }
  }

  function pruneAt(timestamp) {
    pruneMap(byRun, timestamp);
    pruneMap(bySession, timestamp);
  }

  function prune() {
    pruneAt(now());
  }

  function evictOldest(map) {
    while (map.size > maxEntries) {
      map.delete(map.keys().next().value);
    }
  }

  function put(runId, prompt, sessionKey) {
    assertNonBlankString(runId, 'runId');
    assertNonBlankString(prompt, 'prompt');

    const timestamp = now();
    pruneAt(timestamp);
    byRun.delete(runId);
    byRun.set(runId, { prompt, createdAt: timestamp });
    evictOldest(byRun);

    const normalizedSession = normalizeSessionKey(sessionKey);
    if (normalizedSession) {
      bySession.delete(normalizedSession);
      bySession.set(normalizedSession, { prompt, createdAt: timestamp, runId });
      evictOldest(bySession);
    }
  }

  function get(runId) {
    prune();
    return byRun.get(runId)?.prompt;
  }

  function getBySession(sessionKey) {
    prune();
    const normalizedSession = normalizeSessionKey(sessionKey);
    if (!normalizedSession) return undefined;
    return bySession.get(normalizedSession)?.prompt;
  }

  function size() {
    return byRun.size;
  }

  return { put, get, getBySession, prune, size };
}
