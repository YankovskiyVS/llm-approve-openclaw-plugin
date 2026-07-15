import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSyntheticPilotGate,
  renderSyntheticPilotGateJunit,
} from '../evals/lib/holdout-gate.mjs';

function summary(overrides = {}) {
  return {
    denominators: {
      must_block_families: 80,
      catastrophic_families: 11,
      common_read_status_families: 20,
      ...(overrides.denominators ?? {}),
    },
    family: {
      must_block: { total: 80, unsafe: 0 },
      catastrophic: { total: 11, unsafe: 0 },
      ...(overrides.family ?? {}),
    },
    rates: {
      failure: 0,
      schema_invalid: 0,
      timeout: 0,
      unsafe_allow_flip: 0,
      decision_flip: 0,
      ...(overrides.rates ?? {}),
    },
    bounds: {
      unsafe_auto_allow_upper_95: 0.0458,
      safe_action_recall_lower_95: 0.95,
      common_read_status_recall_lower_95: 0.98,
      ...(overrides.bounds ?? {}),
    },
    latency_ms: { p50: 1000, p95: 1800, p99: 2400, ...(overrides.latency_ms ?? {}) },
  };
}

test('synthetic pilot gate is mechanically launch-ineligible even with zero unsafe actions', () => {
  const gate = buildSyntheticPilotGate(summary());
  assert.equal(gate.evidence_tier, 'synthetic_pilot');
  assert.equal(gate.launch_gate_eligible, false);
  assert.equal(gate.launch_gate_passed, false);
  assert.equal(gate.checks.find(({ id }) => id === 'combined_unsafe_zero').passed, true);
  assert.equal(gate.checks.find(({ id }) => id === 'must_block_families_minimum').passed, false);
  assert.equal(gate.checks.find(({ id }) => id === 'unsafe_upper_95').passed, false);
  assert.equal(Object.isFrozen(gate), true);
});

test('gate JUnit exposes every failed design criterion to CI', () => {
  const gate = buildSyntheticPilotGate(summary({
    rates: { failure: 0.01, timeout: 0.02, decision_flip: 0.02 },
    latency_ms: { p95: 2500 },
  }));
  const xml = renderSyntheticPilotGateJunit(gate);
  assert.match(xml, /name="failure_rate">\n    <failure/u);
  assert.match(xml, /name="timeout_rate">\n    <failure/u);
  assert.match(xml, /name="p95_latency_ms">\n    <failure/u);
  assert.match(xml, /name="repeat_agreement">\n    <failure/u);
});

test('gate rejects malformed or hostile summary values', () => {
  assert.throws(() => buildSyntheticPilotGate({}), TypeError);
  assert.throws(() => buildSyntheticPilotGate(new Proxy({}, {})), TypeError);
  assert.throws(() => buildSyntheticPilotGate(summary({
    rates: { failure: Number.NaN },
  })), TypeError);
});
