import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createApprovalDescription,
  createBlockFeedback,
  selectFeedbackCode,
} from '../src/feedback.js';

const MODEL_CODES = Object.freeze({
  authorization_missing: 'after_user_input',
  out_of_scope: 'after_change',
  destructive_or_irreversible: 'after_user_input',
  sensitive_data: 'do_not_retry',
  external_side_effect: 'after_user_input',
  privilege_or_security_boundary: 'after_user_input',
  untrusted_instruction: 'do_not_retry',
  self_modification: 'do_not_retry',
  opaque_or_unverifiable: 'after_change',
  other_policy_risk: 'after_user_input',
});
const HOST_CODES = Object.freeze({
  hard_policy_block: 'do_not_retry',
  local_policy_review: 'after_change',
  judge_unavailable: 'after_user_input',
  invalid_judge_response: 'after_user_input',
  repeated_denials: 'after_user_input',
});
const ALL_CODES = Object.freeze({ ...MODEL_CODES, ...HOST_CODES });
const FEEDBACK_KEYS = Object.freeze([
  'schema', 'status', 'code', 'message', 'retry', 'next_step',
]);
const SENTINEL = 'raw-secret-rationale-param-error-never-expose-42f';

function parsedFeedback(code) {
  const raw = createBlockFeedback(code);
  assert.equal(typeof raw, 'string');
  assert.equal(raw.includes('\n'), false);
  assert.ok(Buffer.byteLength(raw, 'utf8') <= 1024);
  const parsed = JSON.parse(raw);
  assert.deepEqual(Object.keys(parsed), FEEDBACK_KEYS);
  return { raw, parsed };
}

test('createBlockFeedback returns the exact bounded contract for every supported code', () => {
  for (const [code, retry] of Object.entries(ALL_CODES)) {
    const { parsed } = parsedFeedback(code);
    assert.equal(parsed.schema, 'openclaw.action-gate.feedback.v1');
    assert.equal(parsed.status, 'blocked');
    assert.equal(parsed.code, code);
    assert.equal(parsed.retry, retry);
    assert.equal(typeof parsed.message, 'string');
    assert.equal(parsed.message.length > 0, true);
    assert.equal(typeof parsed.next_step, 'string');
    assert.equal(parsed.next_step.length > 0, true);
  }
});

test('createApprovalDescription is fixed, bounded, and derived from the selected template', () => {
  for (const code of Object.keys(ALL_CODES)) {
    const { parsed } = parsedFeedback(code);
    const description = createApprovalDescription(code);
    assert.equal(description, `${parsed.message} ${parsed.next_step}`);
    assert.equal(description.includes('\n'), false);
    assert.ok(Buffer.byteLength(description, 'utf8') <= 1024);
  }
});

test('unknown, safe, malformed, prototype, accessor, and proxy inputs use the invalid fallback', () => {
  const fallback = createBlockFeedback('invalid_judge_response');
  const fallbackApproval = createApprovalDescription('invalid_judge_response');
  let traps = 0;
  const accessor = {};
  Object.defineProperty(accessor, Symbol.toPrimitive, {
    get() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  });
  const proxy = new Proxy({}, {
    get() {
      traps += 1;
      throw new Error(SENTINEL);
    },
    getOwnPropertyDescriptor() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  });
  const prototypeInput = Object.create({ code: 'out_of_scope' });
  const inputs = [
    undefined,
    null,
    '',
    'unknown_code',
    'safe_and_authorized',
    42,
    true,
    Symbol(SENTINEL),
    accessor,
    proxy,
    prototypeInput,
    new String('out_of_scope'),
  ];

  for (const input of inputs) {
    assert.equal(createBlockFeedback(input), fallback);
    assert.equal(createApprovalDescription(input), fallbackApproval);
  }
  assert.equal(traps, 0);
  assert.equal(fallback.includes(SENTINEL), false);
  assert.equal(fallbackApproval.includes(SENTINEL), false);
});

test('selectFeedbackCode maps validated outcomes without reading raw sentinels', () => {
  const verdict = (reasonCode) => ({ reason_code: reasonCode, rationale: SENTINEL });
  const cases = [
    [{ kind: 'allow', verdict: verdict('safe_and_authorized') }, null],
    [{ kind: 'deny', verdict: verdict('out_of_scope') }, 'out_of_scope'],
    [{ kind: 'review', verdict: verdict('authorization_missing') }, 'authorization_missing'],
    [{ kind: 'review', verdict: { decision: 'allow', reason_code: 'safe_and_authorized' } }, 'local_policy_review'],
    [{ kind: 'review', opaque: true, verdict: verdict('other_policy_risk') }, 'opaque_or_unverifiable'],
    [{ kind: 'review', local_guard: true, verdict: verdict('safe_and_authorized') }, 'local_policy_review'],
    [{ kind: 'failure', feedback_code: 'judge_unavailable', reason: SENTINEL }, 'judge_unavailable'],
    [{ kind: 'failure', feedback_code: 'invalid_judge_response', reason: SENTINEL }, 'invalid_judge_response'],
    [{ kind: 'deny', feedback_code: 'hard_policy_block' }, 'hard_policy_block'],
    [{ kind: 'deny', feedback_code: 'repeated_denials' }, 'repeated_denials'],
    [{ kind: 'deny', verdict: verdict('safe_and_authorized') }, 'invalid_judge_response'],
    [{ kind: 'review', verdict: verdict('unknown') }, 'invalid_judge_response'],
    [{ kind: 'failure', feedback_code: SENTINEL }, 'invalid_judge_response'],
  ];

  for (const [result, expected] of cases) {
    const selected = selectFeedbackCode(result);
    assert.equal(selected, expected);
    assert.equal(String(selected).includes(SENTINEL), false);
  }
});

test('selectFeedbackCode treats hostile result and verdict shapes as invalid without traps', () => {
  let traps = 0;
  const accessor = { kind: 'deny' };
  Object.defineProperty(accessor, 'verdict', {
    enumerable: true,
    get() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  });
  const proxy = new Proxy({}, {
    get() {
      traps += 1;
      throw new Error(SENTINEL);
    },
  });
  const inherited = Object.create({ kind: 'deny' });

  for (const result of [undefined, null, accessor, proxy, inherited]) {
    assert.equal(selectFeedbackCode(result), 'invalid_judge_response');
  }
  assert.equal(traps, 0);
});
