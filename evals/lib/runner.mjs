import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { assertProxyFreeTree, validateCase } from './case-schema.mjs';
import {
  attemptIdentity,
  evaluateAttempt,
  snapshotAttemptManifest,
  snapshotCompletedAttempt,
} from './attempt.mjs';

const REQUIRED_OPTION_KEYS = Object.freeze([
  'reviewer', 'cases', 'manifest', 'repeats', 'concurrency',
]);
const OPTION_KEYS = new Set([...REQUIRED_OPTION_KEYS, 'completed']);

function snapshotOptions(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) throw new TypeError('invalid qualification options');
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('invalid qualification options');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string' || !OPTION_KEYS.has(key))) {
      throw new TypeError('invalid qualification options');
    }
    const result = {};
    for (const key of REQUIRED_OPTION_KEYS) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError('invalid qualification options');
      }
      result[key] = descriptor.value;
    }
    const completed = descriptors.completed;
    if (completed && (!completed.enumerable || !Object.hasOwn(completed, 'value'))) {
      throw new TypeError('invalid qualification options');
    }
    result.completed = completed?.value;
    return result;
  } catch {
    throw new TypeError('invalid qualification options');
  }
}

function snapshotCases(value) {
  try {
    assertProxyFreeTree(value, 'qualification cases');
    if (!Array.isArray(value) || types.isProxy(value)) {
      throw new TypeError('invalid qualification cases');
    }
    const items = JSON.parse(canonicalStringify(value)).map(validateCase);
    const ids = new Set();
    for (const item of items) {
      if (ids.has(item.id)) throw new TypeError('duplicate qualification case id');
      ids.add(item.id);
    }
    return Object.freeze(items.slice());
  } catch (error) {
    if (error instanceof TypeError && error.message === 'duplicate qualification case id') {
      throw error;
    }
    throw new TypeError('invalid qualification cases');
  }
}

function snapshotCompleted(value) {
  if (value === undefined) return new Map();
  try {
    if (types.isProxy(value) || !(value instanceof Map)) {
      throw new TypeError('invalid completed attempts');
    }
    Map.prototype.has.call(value, '__qualification_map_probe__');
    return value;
  } catch {
    throw new TypeError('invalid completed attempts');
  }
}

function resumedValue(completed, key) {
  try {
    if (!Map.prototype.has.call(completed, key)) return undefined;
    return Map.prototype.get.call(completed, key);
  } catch {
    return undefined;
  }
}

export async function runQualification(options) {
  const fields = snapshotOptions(options);
  if (!Number.isInteger(fields.repeats) || fields.repeats < 1 || fields.repeats > 10) {
    throw new TypeError('invalid repeats');
  }
  if (!Number.isInteger(fields.concurrency)
    || fields.concurrency < 1 || fields.concurrency > 32) {
    throw new TypeError('invalid concurrency');
  }

  const cases = snapshotCases(fields.cases);
  const manifest = snapshotAttemptManifest(fields.manifest);
  const completed = snapshotCompleted(fields.completed);
  const tuples = [];
  for (let caseIndex = 0; caseIndex < cases.length; caseIndex += 1) {
    const caseData = cases[caseIndex];
    for (let repeat = 1; repeat <= fields.repeats; repeat += 1) {
      const identity = attemptIdentity({ caseData, manifest, repeat });
      tuples.push(Object.freeze({ caseData, caseIndex, repeat, identity }));
    }
  }

  const attempts = new Array(tuples.length);
  const pending = [];
  for (let index = 0; index < tuples.length; index += 1) {
    const tuple = tuples[index];
    const candidate = resumedValue(completed, tuple.identity.resume_key);
    const resumed = candidate === undefined ? null : snapshotCompletedAttempt(candidate, {
      caseData: tuple.caseData,
      manifest,
      repeat: tuple.repeat,
    });
    if (resumed === null) pending.push(Object.freeze({ index, tuple }));
    else attempts[index] = resumed;
  }

  let cursor = 0;
  async function worker() {
    while (cursor < pending.length) {
      const position = cursor;
      cursor += 1;
      const { index, tuple } = pending[position];
      attempts[index] = await evaluateAttempt({
        reviewer: fields.reviewer,
        caseData: tuple.caseData,
        manifest,
        repeat: tuple.repeat,
      });
    }
  }

  const workerCount = Math.min(fields.concurrency, pending.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));

  const caseOrder = new Map(cases.map((item, index) => [item.id, index]));
  const sorted = attempts.slice().sort((left, right) => {
    const caseDifference = caseOrder.get(left.case_id) - caseOrder.get(right.case_id);
    return caseDifference === 0 ? left.repeat - right.repeat : caseDifference;
  });
  return Object.freeze(sorted);
}
