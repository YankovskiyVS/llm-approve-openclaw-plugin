import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyToolFamily,
  createRunDecisionStore,
} from '../src/run-decision-store.js';

const STORE_ERROR = 'invalid run decision store';
const SENTINEL = 'run-store-secret-never-retain-or-echo-71c';
const METADATA_KEYS = Object.freeze([
  'tool_name',
  'tool_family',
  'outcome',
  'risk',
  'authorization',
  'reason_code',
]);

function clock(start = 0) {
  let value = start;
  return {
    now: () => value,
    set(next) { value = next; },
    advance(delta) { value += delta; },
  };
}

function metadata(overrides = {}) {
  const value = {
    tool_name: 'read',
    tool_family: 'filesystem',
    outcome: 'allow',
    risk: 'low',
    authorization: 'high',
    reason_code: 'safe_and_authorized',
    ...overrides,
  };
  if (!Object.hasOwn(overrides, 'reason_code') && value.outcome !== 'allow') {
    value.reason_code = 'other_policy_risk';
  }
  return value;
}

function deny(overrides = {}) {
  return metadata({
    outcome: 'deny',
    risk: 'high',
    authorization: 'low',
    reason_code: 'out_of_scope',
    ...overrides,
  });
}

function review(overrides = {}) {
  return metadata({
    outcome: 'review',
    risk: 'medium',
    authorization: 'medium',
    reason_code: 'authorization_missing',
    ...overrides,
  });
}

function failure(overrides = {}) {
  return metadata({
    outcome: 'failure',
    risk: null,
    authorization: null,
    reason_code: 'judge_unavailable',
    ...overrides,
  });
}

function storeOptions(fakeClock, overrides = {}) {
  return {
    ttlMs: 30 * 60 * 1000,
    maxRuns: 1000,
    historyLimit: 50,
    consecutiveDenyLimit: 3,
    rollingDenyLimit: 10,
    now: fakeClock.now,
    ...overrides,
  };
}

function assertStoreError(fn) {
  assert.throws(
    fn,
    (error) => error instanceof TypeError
      && error.message === STORE_ERROR
      && !error.message.includes(SENTINEL),
  );
}

function assertScalarRecord(actual, expected) {
  assert.equal(Object.getPrototypeOf(actual), null);
  assert.equal(Object.isFrozen(actual), true);
  assert.deepEqual({ ...actual }, expected);
}

function lastSnapshotEntry(snapshot) {
  return snapshot[snapshot.length - 1];
}

function assertEmptySnapshot(snapshot) {
  assert.equal(Array.isArray(snapshot), true);
  assert.equal(Object.getPrototypeOf(snapshot), null);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(snapshot.length, 0);
}

test('classifyToolFamily uses only the exact bounded tool name and a closed family enum', () => {
  const cases = [
    ['read', 'filesystem'],
    ['write', 'filesystem'],
    ['edit', 'filesystem'],
    ['apply_patch', 'filesystem'],
    ['exec', 'shell'],
    ['bash', 'shell'],
    ['browser', 'browser'],
    ['message', 'message'],
    ['web_fetch', 'network'],
    ['web_search', 'network'],
    ['process', 'process'],
    ['sessions_list', 'session'],
    ['sessions_history', 'session'],
    ['sessions_send', 'session'],
    ['session_status', 'session'],
    ['cron', 'cron'],
    ['nodes', 'node'],
    ['image_generate', 'generation'],
    ['music_generate', 'generation'],
    ['video_generate', 'generation'],
    ['skill_workshop', 'skill'],
    ['custom_safe_reader', 'unknown'],
    ['Read', 'unknown'],
  ];
  for (const [toolName, expected] of cases) {
    assert.equal(classifyToolFamily(toolName), expected);
  }

  for (const invalid of [
    '',
    '   ',
    'x'.repeat(257),
    'read\nsecret',
    null,
    {},
    new String('read'),
  ]) {
    assertStoreError(() => classifyToolFamily(invalid));
  }
});

test('record stores only exact frozen scalar metadata and returns detached bounded snapshots', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));

  for (let index = 0; index < 55; index += 1) {
    const status = store.record('run-history', review({
      tool_name: `custom_tool_${index}`,
      tool_family: 'unknown',
    }));
    assert.deepEqual(Object.keys(status), ['already_tripped', 'newly_tripped', 'tripped']);
    assert.equal(Object.isFrozen(status), true);
    assertScalarRecord(status, {
      already_tripped: false,
      newly_tripped: false,
      tripped: false,
    });
  }

  const first = store.snapshot('run-history');
  const second = store.snapshot('run-history');
  assert.equal(first.length, 50);
  assert.deepEqual(
    Array.from({ length: first.length }, (_, index) => first[index].tool_name),
    Array.from({ length: 50 }, (_, index) => `custom_tool_${index + 5}`),
  );
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.getPrototypeOf(first), null);
  assert.equal(Object.isFrozen(first[0]), true);
  assert.notStrictEqual(first, second);
  assert.notStrictEqual(first[0], second[0]);
  for (let index = 0; index < first.length; index += 1) {
    const entry = first[index];
    assert.deepEqual(Object.keys(entry), METADATA_KEYS);
    assert.equal(Object.values(entry).every((value) => value === null
      || ['string', 'number', 'boolean'].includes(typeof value)), true);
  }
  assert.equal(JSON.stringify(first).includes(SENTINEL), false);
});

test('three consecutive denies trip once, allow resets, and neutral outcomes preserve the counter', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));

  assert.equal(store.record('run-consecutive', deny()).newly_tripped, false);
  assert.equal(store.record('run-consecutive', review()).newly_tripped, false);
  assert.equal(store.record('run-consecutive', failure()).newly_tripped, false);
  assert.equal(store.record('run-consecutive', deny()).newly_tripped, false);
  assert.equal(store.record('run-consecutive', metadata()).newly_tripped, false);
  assert.equal(store.record('run-consecutive', deny()).newly_tripped, false);
  assert.equal(store.record('run-consecutive', review()).newly_tripped, false);
  assert.equal(store.record('run-consecutive', deny()).newly_tripped, false);
  const third = store.record('run-consecutive', deny({ reason_code: 'sensitive_data' }));

  assertScalarRecord(third, {
    already_tripped: false,
    newly_tripped: true,
    tripped: true,
  });
  assert.equal(store.isTripped('run-consecutive'), true);
  assert.equal(lastSnapshotEntry(store.snapshot('run-consecutive')).reason_code, 'sensitive_data');
});

test('ten denies in the rolling last fifty trip even when allows break consecutive runs', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));

  for (let index = 0; index < 9; index += 1) {
    assert.equal(store.record('run-rolling', deny()).tripped, false);
    assert.equal(store.record('run-rolling', metadata()).tripped, false);
  }
  const tenth = store.record('run-rolling', deny({ reason_code: 'external_side_effect' }));

  assertScalarRecord(tenth, {
    already_tripped: false,
    newly_tripped: true,
    tripped: true,
  });
  assert.equal(lastSnapshotEntry(store.snapshot('run-rolling')).reason_code, 'external_side_effect');
});

test('rolling threshold cannot be bypassed by replacing Array.prototype.reduce', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));
  const denials = Array.from({ length: 10 }, () => deny());
  const allows = Array.from({ length: 9 }, () => metadata());
  const originalReduce = Object.getOwnPropertyDescriptor(Array.prototype, 'reduce');
  let tenth;

  Object.defineProperty(Array.prototype, 'reduce', {
    ...originalReduce,
    value() { return 0; },
  });
  try {
    for (let index = 0; index < 9; index += 1) {
      store.record('run-poisoned-reduce', denials[index]);
      store.record('run-poisoned-reduce', allows[index]);
    }
    tenth = store.record('run-poisoned-reduce', denials[9]);
  } finally {
    Object.defineProperty(Array.prototype, 'reduce', originalReduce);
  }

  assertScalarRecord(tenth, {
    already_tripped: false,
    newly_tripped: true,
    tripped: true,
  });
});

test('array iterator and prototype-chain replacement cannot suppress the latch', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));
  const denials = [deny(), deny(), deny()];
  const iteratorDescriptor = Object.getOwnPropertyDescriptor(
    Array.prototype,
    Symbol.iterator,
  );
  const originalParent = Object.getPrototypeOf(Array.prototype);
  const hostileParent = Object.create(originalParent);
  hostileParent.inheritedDecisionStoreSecret = SENTINEL;
  let third;
  let snapshot;

  Object.defineProperty(Array.prototype, Symbol.iterator, {
    ...iteratorDescriptor,
    value() {
      return { next() { return { done: true }; } };
    },
  });
  Object.setPrototypeOf(Array.prototype, hostileParent);
  try {
    store.record('run-poisoned-iterator', denials[0]);
    store.record('run-poisoned-iterator', denials[1]);
    third = store.record('run-poisoned-iterator', denials[2]);
    snapshot = store.snapshot('run-poisoned-iterator');
  } finally {
    Object.setPrototypeOf(Array.prototype, originalParent);
    Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
  }

  assert.equal(third.newly_tripped, true);
  assert.equal(third.tripped, true);
  assert.equal(snapshot.length, 3);
  assert.equal(JSON.stringify(snapshot).includes(SENTINEL), false);
});

test('Object.prototype getters, setters, and toJSON cannot suppress or rewrite the latch', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));
  const denials = [deny(), deny(), deny()];
  const outcomeDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'outcome');
  const toJsonDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
  let inheritedReads = 0;
  let third;
  let snapshot;
  let serializedStatus;
  let serializedSnapshot;

  Object.defineProperty(Object.prototype, 'outcome', {
    configurable: true,
    get() {
      inheritedReads += 1;
      return 'allow';
    },
    set() {},
  });
  Object.defineProperty(Object.prototype, 'toJSON', {
    configurable: true,
    get() {
      inheritedReads += 1;
      return () => ({ leaked: SENTINEL });
    },
  });
  try {
    store.record('run-object-prototype', denials[0]);
    store.record('run-object-prototype', denials[1]);
    third = store.record('run-object-prototype', denials[2]);
    snapshot = store.snapshot('run-object-prototype');
    serializedStatus = JSON.stringify(third);
    serializedSnapshot = JSON.stringify(snapshot);
  } finally {
    if (outcomeDescriptor) {
      Object.defineProperty(Object.prototype, 'outcome', outcomeDescriptor);
    } else {
      delete Object.prototype.outcome;
    }
    if (toJsonDescriptor) {
      Object.defineProperty(Object.prototype, 'toJSON', toJsonDescriptor);
    } else {
      delete Object.prototype.toJSON;
    }
  }

  assert.equal(inheritedReads, 0);
  assert.equal(third.newly_tripped, true);
  assert.equal(third.tripped, true);
  assert.equal(Object.getPrototypeOf(third), null);
  assert.equal(Object.getPrototypeOf(snapshot), null);
  assert.equal(Object.getPrototypeOf(snapshot[0]), null);
  assert.equal(Object.hasOwn(snapshot[0], 'outcome'), true);
  assert.equal(snapshot[0].outcome, 'deny');
  assert.equal(serializedStatus.includes(SENTINEL), false);
  assert.equal(serializedSnapshot.includes(SENTINEL), false);
  assert.equal(serializedSnapshot.includes('"outcome":"deny"'), true);
});

test('Object.prototype setters cannot remove methods while the store API is constructed', () => {
  const methodNames = ['isTripped', 'record', 'snapshot', 'size'];
  const descriptors = methodNames.map(
    (name) => Object.getOwnPropertyDescriptor(Object.prototype, name),
  );
  let inheritedWrites = 0;
  let store;

  for (const name of methodNames) {
    Object.defineProperty(Object.prototype, name, {
      configurable: true,
      get() { return undefined; },
      set() { inheritedWrites += 1; },
    });
  }
  try {
    const fakeClock = clock();
    store = createRunDecisionStore(storeOptions(fakeClock));
  } finally {
    for (let index = 0; index < methodNames.length; index += 1) {
      if (descriptors[index]) {
        Object.defineProperty(Object.prototype, methodNames[index], descriptors[index]);
      } else {
        delete Object.prototype[methodNames[index]];
      }
    }
  }

  assert.equal(inheritedWrites, 0);
  assert.equal(Object.getPrototypeOf(store), null);
  for (const name of methodNames) {
    assert.equal(Object.hasOwn(store, name), true);
    assert.equal(typeof store[name], 'function');
  }
  assert.equal(store.record('run-api-prototype', deny()).tripped, false);
});

test('a rejecting async clock fails closed without an unhandled rejection', async () => {
  const unhandled = [];
  function observe(reason) {
    unhandled.push(reason);
  }
  process.on('unhandledRejection', observe);
  try {
    assertStoreError(() => createRunDecisionStore(storeOptions({
      now() {
        return Promise.reject(new Error(SENTINEL));
      },
    })));
    await new Promise((resolve) => setImmediate(resolve));
  } finally {
    process.removeListener('unhandledRejection', observe);
  }

  assert.deepEqual(unhandled, []);
});

test('a tripped run is irreversible and later records become safe repeated-denial metadata', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));
  store.record('run-latched', deny());
  store.record('run-latched', deny());
  store.record('run-latched', deny());

  for (const attempted of [metadata(), review(), failure(), deny()]) {
    const status = store.record('run-latched', attempted);
    assertScalarRecord(status, {
      already_tripped: true,
      newly_tripped: false,
      tripped: true,
    });
    const stored = lastSnapshotEntry(store.snapshot('run-latched'));
    assertScalarRecord(stored, {
      tool_name: attempted.tool_name,
      tool_family: attempted.tool_family,
      outcome: 'deny',
      risk: null,
      authorization: null,
      reason_code: 'repeated_denials',
    });
  }
  assert.equal(store.isTripped('run-latched'), true);
});

test('run IDs are isolated and an unseen run starts clean', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));
  store.record('run-a', deny());
  store.record('run-a', deny());
  store.record('run-a', deny());

  assert.equal(store.isTripped('run-a'), true);
  assert.equal(store.isTripped('run-b'), false);
  assertEmptySnapshot(store.snapshot('run-b'));
  assert.equal(store.record('run-b', metadata()).tripped, false);
  assert.equal(store.size(), 2);
});

test('idle TTL evicts a latch while safe reads refresh live entries', () => {
  const fakeClock = clock(1000);
  const store = createRunDecisionStore(storeOptions(fakeClock, { ttlMs: 100 }));
  store.record('run-ttl', deny());
  store.record('run-ttl', deny());
  store.record('run-ttl', deny());
  fakeClock.advance(99);
  assert.equal(store.isTripped('run-ttl'), true);
  fakeClock.advance(99);
  assert.equal(store.snapshot('run-ttl').length > 0, true);
  fakeClock.advance(101);

  assert.equal(store.isTripped('run-ttl'), false);
  assertEmptySnapshot(store.snapshot('run-ttl'));
  assert.equal(store.size(), 0);
});

test('LRU eviction removes only the least recently used run', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock, { maxRuns: 2 }));
  store.record('run-a', deny());
  store.record('run-b', review());
  assert.equal(store.snapshot('run-a').length, 1);
  store.record('run-c', failure());

  assert.equal(store.size(), 2);
  assert.equal(store.snapshot('run-a').length, 1);
  assertEmptySnapshot(store.snapshot('run-b'));
  assert.equal(store.snapshot('run-c').length, 1);
});

test('invalid options and clocks fail with one fixed error', () => {
  const fakeClock = clock();
  const invalidOptions = [
    null,
    [],
    { ...storeOptions(fakeClock), extra: true },
    { ...storeOptions(fakeClock), ttlMs: 0 },
    { ...storeOptions(fakeClock), maxRuns: 0 },
    { ...storeOptions(fakeClock), historyLimit: 51 },
    { ...storeOptions(fakeClock), consecutiveDenyLimit: 0 },
    { ...storeOptions(fakeClock), rollingDenyLimit: 51 },
    { ...storeOptions(fakeClock), now: null },
    { ...storeOptions(fakeClock), now: () => Number.NaN },
    { ...storeOptions(fakeClock), now: () => { throw new Error(SENTINEL); } },
    Object.create({ ...storeOptions(fakeClock) }),
  ];
  for (const options of invalidOptions) {
    assertStoreError(() => createRunDecisionStore(options));
  }

  let traps = 0;
  const accessor = storeOptions(fakeClock);
  Object.defineProperty(accessor, 'ttlMs', {
    enumerable: true,
    get() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  });
  assertStoreError(() => createRunDecisionStore(accessor));
  assertStoreError(() => createRunDecisionStore(new Proxy({}, {
    ownKeys() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  })));
  const proxyClock = new Proxy(() => 0, {
    apply() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  });
  assertStoreError(() => createRunDecisionStore({
    ...storeOptions(fakeClock),
    now: proxyClock,
  }));
  assert.equal(traps, 0);

  const backwards = clock(10);
  const store = createRunDecisionStore(storeOptions(backwards));
  backwards.set(9);
  assertStoreError(() => store.size());
});

test('hostile IDs and metadata cannot execute traps, leak sentinels, or enter state', () => {
  const fakeClock = clock();
  const store = createRunDecisionStore(storeOptions(fakeClock));
  let traps = 0;
  const accessorMetadata = metadata();
  Object.defineProperty(accessorMetadata, 'risk', {
    enumerable: true,
    get() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  });
  const proxyMetadata = new Proxy({}, {
    ownKeys() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  });
  const cyclicMetadata = metadata();
  cyclicMetadata.tool_name = cyclicMetadata;
  const invalidMetadata = [
    null,
    accessorMetadata,
    proxyMetadata,
    Object.assign(Object.create({ inherited: SENTINEL }), metadata()),
    { ...metadata(), extra: SENTINEL },
    { ...metadata(), tool_family: 'shell' },
    { ...metadata(), outcome: 'deny', reason_code: 'safe_and_authorized' },
    { ...metadata(), risk: 'high' },
    { ...metadata(), authorization: 'medium' },
    {
      ...review(),
      reason_code: 'repeated_denials',
    },
    {
      ...deny(),
      reason_code: 'repeated_denials',
      risk: 'high',
      authorization: 'low',
    },
    { ...metadata(), reason_code: SENTINEL },
    { ...metadata(), risk: SENTINEL },
    cyclicMetadata,
  ];
  for (const value of invalidMetadata) {
    assertStoreError(() => store.record('run-hostile', value));
  }
  for (const runId of [
    '',
    '   ',
    'x'.repeat(257),
    `run\n${SENTINEL}`,
    null,
    {},
    new String('run-hostile'),
    new Proxy({}, {
      get() {
        traps += 1;
        throw new Error(SENTINEL);
      },
    }),
  ]) {
    assertStoreError(() => store.record(runId, metadata()));
  }

  assert.equal(traps, 0);
  assert.equal(store.size(), 0);
  assertEmptySnapshot(store.snapshot('clean-run'));
});
