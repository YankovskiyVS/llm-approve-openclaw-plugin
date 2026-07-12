function assertNonBlankString(value, name) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${name} must be a non-blank string`);
  }
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

  const entries = new Map();

  function pruneAt(timestamp) {
    for (const [runId, entry] of entries) {
      if (timestamp - entry.createdAt >= ttlMs) entries.delete(runId);
    }
  }

  function prune() {
    pruneAt(now());
  }

  function put(runId, prompt) {
    assertNonBlankString(runId, 'runId');
    assertNonBlankString(prompt, 'prompt');

    const timestamp = now();
    pruneAt(timestamp);
    entries.delete(runId);
    entries.set(runId, { prompt, createdAt: timestamp });

    while (entries.size > maxEntries) {
      entries.delete(entries.keys().next().value);
    }
  }

  function get(runId) {
    prune();
    return entries.get(runId)?.prompt;
  }

  function size() {
    return entries.size;
  }

  return { put, get, prune, size };
}
