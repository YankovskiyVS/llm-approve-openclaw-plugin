import test from 'node:test';
import assert from 'node:assert/strict';
import { rankSelectionCandidates } from '../evals/lib/selection-ranking.mjs';

const PAYLOAD_SENTINEL = 'raw-summary-payload-must-not-survive';

function rate(numerator, denominator) {
  return denominator === 0 ? null : numerator / denominator;
}

function summary(overrides = {}) {
  const values = {
    catastrophicUnsafe: 0,
    catastrophicTotal: 2,
    blockUnsafe: 0,
    blockTotal: 5,
    allowPassed: 5,
    allowTotal: 5,
    commonPassed: 2,
    commonTotal: 2,
    failure: 0,
    schemaInvalid: 0,
    timeout: 0,
    p95: 100,
    ...overrides,
  };
  const safeRecall = rate(values.allowPassed, values.allowTotal);
  const rawBlockUnsafe = overrides.rawBlockUnsafe ?? values.blockUnsafe;
  const rawAllowPassed = overrides.rawAllowPassed ?? values.allowPassed;
  return {
    denominators: {
      attempts: 10,
      cases: 10,
      must_allow_families: values.allowTotal,
      must_block_families: values.blockTotal,
      catastrophic_families: values.catastrophicTotal,
      common_read_status_families: values.commonTotal,
    },
    raw_matrix: { payload: PAYLOAD_SENTINEL },
    autonomous_matrix: {},
    supervised_matrix: {},
    risk_confusion: {},
    authorization_confusion: {},
    confidence_buckets: {},
    family: {
      must_block: { total: values.blockTotal, unsafe: values.blockUnsafe },
      must_allow: { total: values.allowTotal, passed: values.allowPassed },
      catastrophic: {
        total: values.catastrophicTotal,
        unsafe: values.catastrophicUnsafe,
      },
      common_read_status: { total: values.commonTotal, passed: values.commonPassed },
    },
    raw_family: {
      must_block: { total: values.blockTotal, unsafe: rawBlockUnsafe },
      must_allow: { total: values.allowTotal, passed: rawAllowPassed },
      gate_saves: rawBlockUnsafe - values.blockUnsafe,
      gate_friction: rawAllowPassed - values.allowPassed,
    },
    rates: {
      unsafe_auto_allow: rate(values.blockUnsafe, values.blockTotal),
      safe_action_recall: safeRecall,
      safe_overblock: safeRecall === null ? null : 1 - safeRecall,
      auto_allow_precision: 1,
      failure: values.failure,
      schema_invalid: values.schemaInvalid,
      timeout: values.timeout,
      decision_flip: 0,
      unsafe_allow_flip: 0,
      common_read_status_recall: rate(values.commonPassed, values.commonTotal),
    },
    bounds: {
      unsafe_auto_allow_upper_95: null,
      safe_action_recall_lower_95: null,
      common_read_status_recall_lower_95: null,
    },
    latency_ms: {
      p50: values.p95 === null ? null : values.p95 / 2,
      p95: values.p95,
      p99: values.p95,
    },
    usage: {
      covered_attempts: 10,
      prompt_tokens: 1000,
      completion_tokens: 200,
      reasoning_tokens: 0,
      cached_prompt_tokens: 0,
      cost: null,
    },
  };
}

function candidate(candidateId, overrides = {}) {
  return {
    candidate_id: candidateId,
    model_id: `provider/${candidateId}`,
    summary: summary(overrides),
  };
}

function rankedFirst(leftOverrides, rightOverrides) {
  const rows = rankSelectionCandidates([
    candidate('right', rightOverrides),
    candidate('left', leftOverrides),
  ]);
  return rows[0].candidate_id;
}

test('returns frozen payload-free rows with explicit family error metrics', () => {
  const rows = rankSelectionCandidates([candidate('model-a', {
    catastrophicUnsafe: 1,
    catastrophicTotal: 3,
    blockUnsafe: 2,
    blockTotal: 5,
    allowPassed: 7,
    allowTotal: 10,
    commonPassed: 3,
    commonTotal: 4,
    failure: 0.1,
    schemaInvalid: 0.05,
    timeout: 0.02,
    p95: 321,
  })]);

  assert.deepEqual(rows, [{
    rank: 1,
    candidate_id: 'model-a',
    model_id: 'provider/model-a',
    family_false_approve: {
      catastrophic: { numerator: 1, denominator: 3, rate: 1 / 3 },
      must_block: { numerator: 2, denominator: 5, rate: 0.4 },
    },
    family_false_reject: { numerator: 3, denominator: 10, rate: 0.3 },
    rates: {
      unsafe_auto_allow: 0.4,
      safe_action_recall: 0.7,
      common_read_status_recall: 0.75,
      failure: 0.1,
      schema_invalid: 0.05,
      timeout: 0.02,
    },
    latency_ms: { p95: 321 },
  }]);
  assert.equal(JSON.stringify(rows).includes(PAYLOAD_SENTINEL), false);
  assert.equal(Object.isFrozen(rows), true);
  assert.equal(Object.isFrozen(rows[0]), true);
  assert.equal(Object.isFrozen(rows[0].family_false_approve), true);
  assert.equal(Object.isFrozen(rows[0].family_false_approve.catastrophic), true);
  assert.equal(Object.isFrozen(rows[0].family_false_reject), true);
  assert.equal(Object.isFrozen(rows[0].rates), true);
  assert.equal(Object.isFrozen(rows[0].latency_ms), true);
});

test('ranks family false approvals by catastrophic count, block count, then unsafe rate', () => {
  assert.equal(rankedFirst(
    { catastrophicUnsafe: 0, blockUnsafe: 5, blockTotal: 5 },
    { catastrophicUnsafe: 1, blockUnsafe: 1 },
  ), 'left');
  assert.equal(rankedFirst(
    { catastrophicUnsafe: 0, blockUnsafe: 0 },
    { catastrophicUnsafe: 0, blockUnsafe: 1, blockTotal: 100 },
  ), 'left');
  assert.equal(rankedFirst(
    { catastrophicUnsafe: 0, blockUnsafe: 1, blockTotal: 100 },
    { catastrophicUnsafe: 0, blockUnsafe: 1, blockTotal: 2 },
  ), 'left');
});

test('ranks recalls descending and treats null common-read recall as worst', () => {
  assert.equal(rankedFirst(
    { allowPassed: 5, allowTotal: 5, commonPassed: 0, commonTotal: 0 },
    { allowPassed: 4, allowTotal: 5, commonPassed: 2, commonTotal: 2 },
  ), 'left');
  assert.equal(rankedFirst(
    { allowPassed: 4, allowTotal: 5, commonPassed: 1, commonTotal: 2 },
    { allowPassed: 4, allowTotal: 5, commonPassed: 0, commonTotal: 0 },
  ), 'left');
  assert.equal(rankedFirst(
    { allowPassed: 4, allowTotal: 5, commonPassed: 2, commonTotal: 2 },
    { allowPassed: 4, allowTotal: 5, commonPassed: 1, commonTotal: 2 },
  ), 'left');
});

test('ranks failure, schema-invalid, timeout, p95, then candidate_id', () => {
  assert.equal(rankedFirst({ failure: 0 }, { failure: 0.1 }), 'left');
  assert.equal(rankedFirst(
    { failure: 0, schemaInvalid: 0 },
    { failure: 0, schemaInvalid: 0.1 },
  ), 'left');
  assert.equal(rankedFirst(
    { failure: 0, schemaInvalid: 0, timeout: 0 },
    { failure: 0, schemaInvalid: 0, timeout: 0.1 },
  ), 'left');
  assert.equal(rankedFirst({ p95: 99 }, { p95: 100 }), 'left');
  assert.equal(rankedFirst({ p95: 100 }, { p95: null }), 'left');

  const tied = rankSelectionCandidates([candidate('a-model'), candidate('A-model')]);
  assert.deepEqual(tied.map(({ candidate_id }) => candidate_id), ['A-model', 'a-model']);
  assert.deepEqual(tied.map(({ rank }) => rank), [1, 2]);
});

test('rejects non-exact, inconsistent, duplicate, or non-repeat-one summaries', () => {
  const extraCandidate = candidate('extra-candidate');
  extraCandidate.extra = true;
  const extraSummary = candidate('extra-summary');
  extraSummary.summary.extra = true;
  const wrongRepeats = candidate('wrong-repeats');
  wrongRepeats.summary.denominators.attempts = 20;
  const inconsistent = candidate('inconsistent');
  inconsistent.summary.rates.unsafe_auto_allow = 0.5;

  for (const input of [
    [extraCandidate],
    [extraSummary],
    [wrongRepeats],
    [inconsistent],
    [candidate('duplicate'), candidate('duplicate')],
  ]) {
    assert.throws(() => rankSelectionCandidates(input), /invalid selection ranking input/);
  }
});

test('rejects hostile proxies and accessors without invoking them or disclosing values', () => {
  const secret = 'ranking-hostile-secret-never-disclose';
  let traps = 0;
  const hostile = new Proxy({}, {
    get() {
      traps += 1;
      throw new Error(secret);
    },
    getPrototypeOf() {
      traps += 1;
      throw new Error(secret);
    },
    ownKeys() {
      traps += 1;
      throw new Error(secret);
    },
  });
  let getterReads = 0;
  const accessor = candidate('accessor');
  Object.defineProperty(accessor.summary.rates, 'failure', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error(secret);
    },
  });

  for (const input of [hostile, [hostile], [candidate('nested', { }), hostile], [accessor]]) {
    let caught;
    try {
      rankSelectionCandidates(input);
    } catch (error) {
      caught = error;
    }
    assert.equal(caught instanceof TypeError, true);
    assert.equal(caught.message, 'invalid selection ranking input');
    assert.equal(caught.message.includes(secret), false);
  }
  assert.equal(traps, 0);
  assert.equal(getterReads, 0);
});
