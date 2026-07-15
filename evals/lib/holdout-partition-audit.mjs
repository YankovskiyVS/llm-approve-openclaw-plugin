import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { assertProxyFreeTree } from './case-schema.mjs';
import {
  corpusHash,
  lintCorpus,
  observableFingerprint,
} from './corpus.mjs';

const PARTITION_KEYS = Object.freeze(['name', 'cases']);
const ARTIFACT_KEYS = Object.freeze([
  'schema_version', 'partitions', 'total', 'collisions', 'audit_sha256',
]);
const SUMMARY_KEYS = Object.freeze([
  'name', 'split', 'corpus_sha256', 'cases', 'families',
]);
const TOTAL_KEYS = Object.freeze(['partitions', 'cases', 'families']);
const COLLISION_KEYS = Object.freeze([
  'case_ids', 'family_ids', 'observable_fingerprints',
]);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function readDenseArray(value, name, { nonEmpty = false } = {}) {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be a dense array`);

  let descriptors;
  let prototype;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw new TypeError(`${name} must be a dense array`);
  }
  const length = descriptors.length?.value;
  if (prototype !== Array.prototype
    || !Number.isSafeInteger(length)
    || length < 0
    || (nonEmpty && length === 0)
    || Reflect.ownKeys(descriptors).length !== length + 1) {
    throw new TypeError(`${name} must be a ${nonEmpty ? 'non-empty ' : ''}dense array`);
  }

  const result = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${name} must contain dense data elements`);
    }
    result.push(descriptor.value);
  }
  return result;
}

function readPartition(value) {
  let descriptors;
  let prototype;
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw new TypeError('partition must be an exact data object');
  }
  const keys = Reflect.ownKeys(descriptors);
  if ((prototype !== Object.prototype && prototype !== null)
    || keys.length !== PARTITION_KEYS.length
    || keys.some((key) => typeof key !== 'string' || !PARTITION_KEYS.includes(key))) {
    throw new TypeError('partition must contain exactly name and cases');
  }

  const result = {};
  for (const key of PARTITION_KEYS) {
    const descriptor = descriptors[key];
    if (!descriptor
      || !descriptor.enumerable
      || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('partition must contain own data properties');
    }
    result[key] = descriptor.value;
  }
  return result;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

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

function payloadHash(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function artifactPayload({ partitions, total, collisions }) {
  return {
    schema_version: 'judge-holdout-partition-audit.v1',
    partitions,
    total,
    collisions,
  };
}

export function validateHoldoutPartitionAudit(value) {
  const fields = exactDataValues(value, ARTIFACT_KEYS, 'invalid holdout partition audit');
  const partitions = readDenseArray(fields.partitions, 'partition audit partitions', {
    nonEmpty: true,
  }).map((entry) => {
    const item = exactDataValues(entry, SUMMARY_KEYS, 'invalid holdout partition audit');
    if (typeof item.name !== 'string' || !IDENTIFIER_PATTERN.test(item.name)
      || typeof item.split !== 'string' || !IDENTIFIER_PATTERN.test(item.split)
      || typeof item.corpus_sha256 !== 'string' || !HASH_PATTERN.test(item.corpus_sha256)
      || !Number.isSafeInteger(item.cases) || item.cases < 1
      || !Number.isSafeInteger(item.families) || item.families < 1
      || item.families > item.cases) {
      throw new TypeError('invalid holdout partition audit');
    }
    return { ...item };
  });
  if (new Set(partitions.map((entry) => entry.name)).size !== partitions.length) {
    throw new TypeError('invalid holdout partition audit');
  }
  const total = exactDataValues(fields.total, TOTAL_KEYS, 'invalid holdout partition audit');
  const collisions = exactDataValues(
    fields.collisions,
    COLLISION_KEYS,
    'invalid holdout partition audit',
  );
  if (fields.schema_version !== 'judge-holdout-partition-audit.v1'
    || !HASH_PATTERN.test(fields.audit_sha256)
    || TOTAL_KEYS.some((key) => !Number.isSafeInteger(total[key]) || total[key] < 1)
    || COLLISION_KEYS.some((key) => collisions[key] !== 0)
    || total.partitions !== partitions.length
    || total.cases !== partitions.reduce((sum, entry) => sum + entry.cases, 0)
    || total.families !== partitions.reduce((sum, entry) => sum + entry.families, 0)) {
    throw new TypeError('invalid holdout partition audit');
  }
  const payload = artifactPayload({ partitions, total, collisions });
  if (payloadHash(payload) !== fields.audit_sha256) {
    throw new TypeError('invalid holdout partition audit');
  }
  return deepFreeze({ ...payload, audit_sha256: fields.audit_sha256 });
}

export function holdoutPartitionAuditHash(value) {
  return validateHoldoutPartitionAudit(value).audit_sha256;
}

export function auditHoldoutPartitions(values) {
  assertProxyFreeTree(values, 'holdout partitions');
  const partitions = readDenseArray(values, 'holdout partitions', { nonEmpty: true });
  const names = new Set();
  const caseIds = new Set();
  const familyIds = new Set();
  const fingerprints = new Set();
  const summaries = [];
  let totalCases = 0;
  let totalFamilies = 0;

  for (const value of partitions) {
    const partition = readPartition(value);
    if (typeof partition.name !== 'string' || partition.name.trim() === '') {
      throw new TypeError('partition name must be a non-blank string');
    }
    if (names.has(partition.name)) throw new TypeError('duplicate partition name');
    names.add(partition.name);

    const cases = lintCorpus(partition.cases);
    const splits = new Set(cases.map((item) => item.split));
    if (splits.size !== 1) throw new TypeError('partition must contain exactly one split');
    const partitionFamilies = new Set();
    for (const item of cases) {
      if (caseIds.has(item.id)) throw new TypeError('duplicate case id across partitions');
      caseIds.add(item.id);

      if (familyIds.has(item.family_id)) throw new TypeError('family reused across partitions');
      partitionFamilies.add(item.family_id);

      const fingerprint = observableFingerprint(item);
      if (fingerprints.has(fingerprint)) {
        throw new TypeError('observable input collision across partitions');
      }
      fingerprints.add(fingerprint);
    }
    for (const familyId of partitionFamilies) familyIds.add(familyId);

    totalCases += cases.length;
    totalFamilies += partitionFamilies.size;
    summaries.push({
      name: partition.name,
      split: [...splits][0],
      corpus_sha256: corpusHash(cases),
      cases: cases.length,
      families: partitionFamilies.size,
    });
  }

  const payload = artifactPayload({
    partitions: summaries,
    total: {
      partitions: summaries.length,
      cases: totalCases,
      families: totalFamilies,
    },
    collisions: {
      case_ids: 0,
      family_ids: 0,
      observable_fingerprints: 0,
    },
  });
  return validateHoldoutPartitionAudit({ ...payload, audit_sha256: payloadHash(payload) });
}
