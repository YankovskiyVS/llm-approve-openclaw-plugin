import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { corpusHash, lintCorpus } from './corpus.mjs';
import {
  holdoutInputHash,
  validateHoldoutInput,
  validateHoldoutOracle,
} from './holdout-contracts.mjs';
import { validateHoldoutPartitionAudit } from './holdout-partition-audit.mjs';

const FREEZE_COMMITMENT_KEYS = Object.freeze([
  'schema_version',
  'holdout_id',
  'input_sha256',
  'oracle_sha256',
  'corpus_sha256',
  'partition_name',
  'partition_split',
  'partition_audit_sha256',
  'commitment_nonce',
  'cases',
]);
const FREEZE_RECEIPT_KEYS = Object.freeze([
  'schema_version',
  'holdout_id',
  'input_sha256',
  'partition_name',
  'partition_audit_sha256',
  'commitment_sha256',
]);
const BUILD_KEYS = Object.freeze([
  'input', 'oracle', 'corpus', 'partitionName', 'partitionAuditSha256',
  'commitmentNonce',
]);
const RECEIPT_BUILD_KEYS = Object.freeze(['commitment', 'partitionAudit']);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function exactDataValues(value, expected, message) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) throw new TypeError(message);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string' || !expected.includes(key))) {
      throw new TypeError(message);
    }
    const result = {};
    for (const key of expected) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError(message);
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    throw new TypeError(message);
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function sha256Canonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

export function holdoutOracleHash(value) {
  return sha256Canonical(validateHoldoutOracle(value));
}

export function validateHoldoutFreezeCommitment(value) {
  const fields = exactDataValues(
    value,
    FREEZE_COMMITMENT_KEYS,
    'invalid holdout freeze commitment',
  );
  if (fields.schema_version !== 'judge-holdout-freeze-commitment.v2'
    || typeof fields.holdout_id !== 'string'
    || !IDENTIFIER_PATTERN.test(fields.holdout_id)
    || !HASH_PATTERN.test(fields.input_sha256)
    || !HASH_PATTERN.test(fields.oracle_sha256)
    || !HASH_PATTERN.test(fields.corpus_sha256)
    || typeof fields.partition_name !== 'string'
    || !IDENTIFIER_PATTERN.test(fields.partition_name)
    || typeof fields.partition_split !== 'string'
    || !IDENTIFIER_PATTERN.test(fields.partition_split)
    || !HASH_PATTERN.test(fields.partition_audit_sha256)
    || typeof fields.commitment_nonce !== 'string'
    || !/^[0-9a-f]{64}$/u.test(fields.commitment_nonce)
    || !Number.isSafeInteger(fields.cases)
    || fields.cases < 1
    || fields.cases > 1_000_000) {
    throw new TypeError('invalid holdout freeze commitment');
  }
  return deepFreeze({ ...fields });
}

export function holdoutFreezeCommitmentHash(value) {
  return sha256Canonical(validateHoldoutFreezeCommitment(value));
}

export function validateHoldoutFreezeReceipt(value) {
  const fields = exactDataValues(
    value,
    FREEZE_RECEIPT_KEYS,
    'invalid holdout freeze receipt',
  );
  if (fields.schema_version !== 'judge-holdout-freeze-receipt.v1'
    || typeof fields.holdout_id !== 'string'
    || !IDENTIFIER_PATTERN.test(fields.holdout_id)
    || !HASH_PATTERN.test(fields.input_sha256)
    || typeof fields.partition_name !== 'string'
    || !IDENTIFIER_PATTERN.test(fields.partition_name)
    || !HASH_PATTERN.test(fields.partition_audit_sha256)
    || !HASH_PATTERN.test(fields.commitment_sha256)) {
    throw new TypeError('invalid holdout freeze receipt');
  }
  return deepFreeze({ ...fields });
}

export function holdoutFreezeReceiptHash(value) {
  return sha256Canonical(validateHoldoutFreezeReceipt(value));
}

export function buildHoldoutFreezeReceipt(value) {
  const fields = exactDataValues(
    value,
    RECEIPT_BUILD_KEYS,
    'invalid holdout freeze receipt source',
  );
  const commitment = validateHoldoutFreezeCommitment(fields.commitment);
  const partitionAudit = validateHoldoutPartitionAudit(fields.partitionAudit);
  const partition = partitionAudit.partitions.find(
    (entry) => entry.name === commitment.partition_name,
  );
  if (partition === undefined
    || partitionAudit.audit_sha256 !== commitment.partition_audit_sha256
    || partition.split !== commitment.partition_split
    || partition.corpus_sha256 !== commitment.corpus_sha256
    || partition.cases !== commitment.cases) {
    throw new TypeError('invalid holdout freeze receipt source');
  }
  return validateHoldoutFreezeReceipt({
    schema_version: 'judge-holdout-freeze-receipt.v1',
    holdout_id: commitment.holdout_id,
    input_sha256: commitment.input_sha256,
    partition_name: commitment.partition_name,
    partition_audit_sha256: commitment.partition_audit_sha256,
    commitment_sha256: holdoutFreezeCommitmentHash(commitment),
  });
}

export function buildHoldoutFreezeCommitment(value) {
  const fields = exactDataValues(value, BUILD_KEYS, 'invalid holdout freeze source');
  const input = validateHoldoutInput(fields.input);
  const oracle = validateHoldoutOracle(fields.oracle);
  const corpus = lintCorpus(fields.corpus);
  const inputSha256 = holdoutInputHash(input);
  const splits = new Set(corpus.map((item) => item.split));
  if (input.holdout_id !== oracle.holdout_id
    || oracle.input_sha256 !== inputSha256
    || input.cases.length !== oracle.cases.length
    || input.cases.length !== corpus.length
    || splits.size !== 1) {
    throw new TypeError('invalid holdout freeze source');
  }
  return validateHoldoutFreezeCommitment({
    schema_version: 'judge-holdout-freeze-commitment.v2',
    holdout_id: input.holdout_id,
    input_sha256: inputSha256,
    oracle_sha256: holdoutOracleHash(oracle),
    corpus_sha256: corpusHash(corpus),
    partition_name: fields.partitionName,
    partition_split: [...splits][0],
    partition_audit_sha256: fields.partitionAuditSha256,
    commitment_nonce: fields.commitmentNonce,
    cases: input.cases.length,
  });
}
