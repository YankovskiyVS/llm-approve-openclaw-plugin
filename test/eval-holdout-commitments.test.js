import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildHoldoutFreezeCommitment,
  buildHoldoutFreezeReceipt,
  holdoutFreezeCommitmentHash,
  holdoutFreezeReceiptHash,
  holdoutOracleHash,
  validateHoldoutFreezeCommitment,
  validateHoldoutFreezeReceipt,
} from '../evals/lib/holdout-commitments.mjs';
import { buildHoldoutSplit } from '../evals/lib/holdout-contracts.mjs';
import { auditHoldoutPartitions } from '../evals/lib/holdout-partition-audit.mjs';
import { makeCase } from './helpers/eval-fixtures.js';

function fixture() {
  const corpus = [makeCase({
    id: 'commitment-safe-read',
    family_id: 'commitment-safe-read-family',
    split: 'frozen-holdout',
  })];
  const split = buildHoldoutSplit({
    holdoutId: 'commitment-holdout-2026-07-15',
    cases: corpus,
    idKey: 'commitment-test-key-0123456789-abcdef',
  });
  return { corpus, ...split };
}

function buildCommitment(data, partitionAuditSha256 = 'sha256:' + 'd'.repeat(64)) {
  return buildHoldoutFreezeCommitment({
    ...data,
    partitionName: 'primary',
    partitionAuditSha256,
    commitmentNonce: 'e'.repeat(64),
  });
}

test('freeze commitment binds canonical corpus, blind input, and oracle labels', () => {
  const data = fixture();
  const commitment = buildCommitment(data);

  assert.deepEqual(Object.keys(commitment), [
    'schema_version', 'holdout_id', 'input_sha256', 'oracle_sha256',
    'corpus_sha256', 'partition_name', 'partition_split',
    'partition_audit_sha256', 'commitment_nonce', 'cases',
  ]);
  assert.equal(commitment.schema_version, 'judge-holdout-freeze-commitment.v2');
  assert.equal(commitment.holdout_id, data.input.holdout_id);
  assert.equal(commitment.oracle_sha256, holdoutOracleHash(data.oracle));
  assert.match(commitment.corpus_sha256, /^sha256:[0-9a-f]{64}$/u);
  assert.match(holdoutFreezeCommitmentHash(commitment), /^sha256:[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(commitment), true);
});

test('freeze commitment validator is exact, defensive, and detects label tampering', () => {
  const data = fixture();
  const commitment = buildCommitment(data);
  const snapshot = validateHoldoutFreezeCommitment(JSON.parse(JSON.stringify(commitment)));
  assert.deepEqual(snapshot, commitment);
  assert.equal(Object.isFrozen(snapshot), true);

  assert.throws(() => validateHoldoutFreezeCommitment({ ...commitment, extra: true }), TypeError);
  assert.throws(() => validateHoldoutFreezeCommitment({
    ...commitment,
    oracle_sha256: 'sha256:00',
  }), TypeError);
  assert.throws(() => validateHoldoutFreezeCommitment(new Proxy({ ...commitment }, {})), TypeError);

  const changedOracle = JSON.parse(JSON.stringify(data.oracle));
  changedOracle.cases[0].oracle_rationale = 'Changed after freeze.';
  assert.notEqual(holdoutOracleHash(changedOracle), commitment.oracle_sha256);
});

test('public freeze receipt binds blind input and private commitment without oracle metadata', () => {
  const data = fixture();
  const partitionAudit = auditHoldoutPartitions([
    { name: 'primary', cases: data.corpus },
  ]);
  const commitment = buildCommitment(data, partitionAudit.audit_sha256);
  const receipt = buildHoldoutFreezeReceipt({
    commitment,
    partitionAudit,
  });

  assert.deepEqual(Object.keys(receipt), [
    'schema_version', 'holdout_id', 'input_sha256', 'partition_name',
    'partition_audit_sha256', 'commitment_sha256',
  ]);
  assert.equal(receipt.schema_version, 'judge-holdout-freeze-receipt.v1');
  assert.equal(receipt.commitment_sha256, holdoutFreezeCommitmentHash(commitment));
  assert.equal(JSON.stringify(receipt).includes('oracle_sha256'), false);
  assert.equal(JSON.stringify(receipt).includes('corpus_sha256'), false);
  assert.deepEqual(validateHoldoutFreezeReceipt(JSON.parse(JSON.stringify(receipt))), receipt);
  assert.match(holdoutFreezeReceiptHash(receipt), /^sha256:[0-9a-f]{64}$/u);
  assert.throws(() => validateHoldoutFreezeReceipt({ ...receipt, extra: true }), TypeError);
  assert.throws(() => buildHoldoutFreezeReceipt({
    commitment,
    partitionAudit: { ...partitionAudit, audit_sha256: 'sha256:' + 'f'.repeat(64) },
  }), TypeError);
});
