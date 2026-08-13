import test from 'node:test';
import assert from 'node:assert/strict';
import { createContextStore } from '../src/context-store.js';

test('returns the prompt only for the exact run ID', () => {
  const store = createContextStore({ ttlMs: 50, maxEntries: 2, now: () => 100 });

  store.put(' run-a ', '  trusted request  ');

  assert.equal(store.get('run-a'), undefined);
  assert.equal(store.get('RUN-A'), undefined);
  assert.equal(store.get(' run-a '), '  trusted request  ');
});

test('indexes prompts by session key for A2A runId mismatch', () => {
  const store = createContextStore({ ttlMs: 50, maxEntries: 2, now: () => 100 });

  store.put('agent-run', 'Read BOOTSTRAP.md', 'session:agent:main:a2a:ctx-1');

  assert.equal(store.get('agent-run'), 'Read BOOTSTRAP.md');
  assert.equal(store.get('chatcmpl_other'), undefined);
  assert.equal(
    store.getBySession('agent:main:a2a:ctx-1'),
    'Read BOOTSTRAP.md',
  );
  assert.equal(
    store.getBySession('session:agent:main:a2a:ctx-1'),
    'Read BOOTSTRAP.md',
  );
});

test('expires entries at the TTL boundary', () => {
  let now = 100;
  const store = createContextStore({ ttlMs: 50, maxEntries: 2, now: () => now });

  store.put('run-a', 'trusted request');
  now = 149;
  assert.equal(store.get('run-a'), 'trusted request');

  now = 150;
  assert.equal(store.get('run-a'), undefined);
  assert.equal(store.size(), 0);
});

test('evicts the oldest entry when capacity is exceeded', () => {
  let now = 1;
  const store = createContextStore({ ttlMs: 1_000, maxEntries: 2, now: () => now });

  store.put('a', 'A');
  now = 2;
  store.put('b', 'B');
  now = 3;
  store.put('c', 'C');

  assert.equal(store.get('a'), undefined);
  assert.equal(store.get('b'), 'B');
  assert.equal(store.get('c'), 'C');
  assert.equal(store.size(), 2);
});

test('replacing an ID makes it the newest entry', () => {
  let now = 1;
  const store = createContextStore({ ttlMs: 1_000, maxEntries: 2, now: () => now });

  store.put('a', 'A');
  now = 2;
  store.put('b', 'B');
  now = 3;
  store.put('a', 'A2');
  now = 4;
  store.put('c', 'C');

  assert.equal(store.get('b'), undefined);
  assert.equal(store.get('a'), 'A2');
  assert.equal(store.get('c'), 'C');
});

test('rejects blank and non-string IDs and prompts', () => {
  const store = createContextStore({ ttlMs: 50, maxEntries: 2, now: () => 100 });

  for (const runId of ['', '   ', '\n', null, undefined, 42, {}]) {
    assert.throws(() => store.put(runId, 'prompt'), /runId/);
  }

  for (const prompt of ['', '   ', '\n', null, undefined, 42, {}]) {
    assert.throws(() => store.put('run-a', prompt), /prompt/);
  }
});

test('prunes expired entries explicitly and reports the stored size', () => {
  let now = 0;
  const store = createContextStore({ ttlMs: 10, maxEntries: 2, now: () => now });

  store.put('a', 'A');
  now = 5;
  store.put('b', 'B');
  now = 11;
  assert.equal(store.size(), 2);

  store.prune();
  assert.equal(store.size(), 1);
  assert.equal(store.get('b'), 'B');

  now = 15;
  store.prune();
  assert.equal(store.size(), 0);
});

test('validates constructor options', () => {
  for (const ttlMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, '50']) {
    assert.throws(
      () => createContextStore({ ttlMs, maxEntries: 2, now: () => 0 }),
      /ttlMs/,
    );
  }

  for (const maxEntries of [0, -1, 1.5, Number.POSITIVE_INFINITY, '2']) {
    assert.throws(
      () => createContextStore({ ttlMs: 50, maxEntries, now: () => 0 }),
      /maxEntries/,
    );
  }

  for (const now of [null, 0, 'clock', {}]) {
    assert.throws(() => createContextStore({ ttlMs: 50, maxEntries: 2, now }), /now/);
  }
});
