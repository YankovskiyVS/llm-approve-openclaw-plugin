import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
} from 'node:fs';
import { join } from 'node:path';
import { lintCorpus } from './corpus.mjs';

const SPLIT_PREFIXES = Object.freeze({
  'model-selection': 'ms',
  'gate-validation': 'gv',
  'frozen-holdout': 'fh',
  'reserve-holdout': 'rh',
  'runtime-e2e': 'e2e',
});
const MAX_CHUNK_BYTES = 4 * 1024 * 1024;

export function readRegularJsonFile(path) {
  let descriptor;
  try {
    if (typeof path !== 'string' || path === '') throw new Error('path');
    const before = lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink()) throw new Error('file');
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor);
    const after = lstatSync(path);
    if (!opened.isFile()
      || !after.isFile()
      || after.isSymbolicLink()
      || opened.dev !== after.dev
      || opened.ino !== after.ino
      || opened.size < 1
      || opened.size > MAX_CHUNK_BYTES) throw new Error('file');
    return JSON.parse(readFileSync(descriptor, 'utf8'));
  } catch {
    throw new TypeError('corpus JSON file is invalid');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function countBy(values, field) {
  const counts = new Map();
  for (const value of values) {
    const key = value[field];
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function exactArray(value, expected) {
  return Array.isArray(value)
    && value.length === expected.length
    && value.every((item, index) => item === expected[index]);
}

function assertQuota(counts, key, expected) {
  if (expected !== undefined && counts.get(key) !== expected) throw new Error('quota');
}

function assertPositiveInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('integer');
}

function validateQualificationChunk(values, { plan, split, chunkIndex }) {
  assertPositiveInteger(chunkIndex);
  const splitPlan = plan?.splits?.[split];
  const splitPrefix = SPLIT_PREFIXES[split];
  if (!splitPlan || !splitPrefix) throw new Error('plan');
  assertPositiveInteger(splitPlan.chunks);
  if (chunkIndex > splitPlan.chunks) throw new Error('chunk');

  const cases = lintCorpus(values);
  if (cases.length !== splitPlan.cases_per_chunk) throw new Error('count');

  const chunk = String(chunkIndex).padStart(3, '0');
  const idPrefix = `${splitPrefix}-c${chunk}-`;
  const familyPrefix = `${splitPrefix}-c${chunk}-f-`;
  for (const item of cases) {
    if (item.split !== split
      || !item.id.startsWith(idPrefix)
      || !item.family_id.startsWith(familyPrefix)) throw new Error('identity');
    if (item.preferred_disposition === 'allow'
      && !exactArray(item.acceptable_conservative_outcomes, [])) throw new Error('outcome');
    if (item.preferred_disposition === 'review'
      && !exactArray(item.acceptable_conservative_outcomes, ['review', 'deny'])) {
      throw new Error('outcome');
    }
    if (item.preferred_disposition === 'deny'
      && !exactArray(item.acceptable_conservative_outcomes, ['deny'])) throw new Error('outcome');
  }

  const dispositions = countBy(cases, 'preferred_disposition');
  assertQuota(dispositions, 'allow', splitPlan.allow_per_chunk);
  assertQuota(dispositions, 'review', splitPlan.review_per_chunk);
  assertQuota(dispositions, 'deny', splitPlan.deny_per_chunk);

  const languages = countBy(cases, 'language');
  assertQuota(languages, 'ru', splitPlan.ru_per_chunk);
  assertQuota(languages, 'en', splitPlan.en_per_chunk);
  assertQuota(languages, 'mixed', splitPlan.mixed_per_chunk);

  const families = new Map();
  for (const item of cases) {
    const family = families.get(item.family_id) ?? [];
    family.push(item);
    families.set(item.family_id, family);
  }
  if (splitPlan.distinct_families_per_chunk !== undefined
    && families.size !== splitPlan.distinct_families_per_chunk) throw new Error('families');

  if (splitPlan.contrast_families_per_chunk !== undefined) {
    const pairs = [...families.values()].filter((family) => family.length === 2);
    const singletons = [...families.values()].filter((family) => family.length === 1);
    if (pairs.length !== splitPlan.contrast_families_per_chunk
      || pairs.length + singletons.length !== families.size) throw new Error('family size');

    const pairedBlocks = [];
    for (const family of pairs) {
      const allow = family.filter((item) => item.preferred_disposition === 'allow');
      const block = family.filter((item) => item.preferred_disposition !== 'allow');
      if (allow.length !== 1 || block.length !== 1 || allow[0].language !== block[0].language) {
        throw new Error('contrast');
      }
      pairedBlocks.push(block[0]);
    }
    if (singletons.some((family) => family[0].preferred_disposition === 'allow')) {
      throw new Error('singleton');
    }
    const pairedDispositions = countBy(pairedBlocks, 'preferred_disposition');
    const singletonDispositions = countBy(singletons.flat(), 'preferred_disposition');
    assertQuota(pairedDispositions, 'review', splitPlan.paired_review_per_chunk);
    assertQuota(pairedDispositions, 'deny', splitPlan.paired_deny_per_chunk);
    assertQuota(singletonDispositions, 'review', splitPlan.singleton_review_per_chunk);
    assertQuota(singletonDispositions, 'deny', splitPlan.singleton_deny_per_chunk);
  }

  return cases;
}

export function lintQualificationChunk(values, options) {
  try {
    return validateQualificationChunk(values, options);
  } catch {
    throw new TypeError('qualification chunk is invalid');
  }
}

function validateCandidateDirectory(directory, { plan, split }) {
  const splitPlan = plan?.splits?.[split];
  if (typeof directory !== 'string' || directory === '' || !splitPlan) throw new Error('input');
  const directoryStat = lstatSync(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error('directory');
  assertPositiveInteger(splitPlan.chunks);

  const expectedNames = Array.from(
    { length: splitPlan.chunks },
    (_, index) => `chunk-${String(index + 1).padStart(3, '0')}.json`,
  );
  const entries = readdirSync(directory, { withFileTypes: true });
  const actualNames = entries.map((entry) => entry.name).sort();
  if (actualNames.length !== expectedNames.length
    || actualNames.some((name, index) => name !== expectedNames[index])) throw new Error('entries');

  const chunks = [];
  const familyChunks = new Map();
  for (let index = 0; index < expectedNames.length; index += 1) {
    const name = expectedNames[index];
    const entry = entries.find((candidate) => candidate.name === name);
    const path = join(directory, name);
    const stat = lstatSync(path);
    if (!entry?.isFile() || entry.isSymbolicLink() || !stat.isFile() || stat.isSymbolicLink()) {
      throw new Error('file');
    }
    const values = readRegularJsonFile(path);
    const cases = validateQualificationChunk(values, {
      plan,
      split,
      chunkIndex: index + 1,
    });
    for (const item of cases) {
      const previous = familyChunks.get(item.family_id);
      if (previous !== undefined && previous !== index) throw new Error('family chunk');
      familyChunks.set(item.family_id, index);
    }
    chunks.push(cases);
  }

  const cases = lintCorpus(chunks.flat());
  if (splitPlan.required_tool_names !== undefined) {
    if (!Array.isArray(splitPlan.required_tool_names)
      || splitPlan.required_tool_names.length === 0
      || new Set(splitPlan.required_tool_names).size !== splitPlan.required_tool_names.length
      || splitPlan.required_tool_names.some((name) => typeof name !== 'string' || name === '')) {
      throw new Error('tool plan');
    }
    const presentTools = new Set(cases.map((item) => item.tool_name));
    if (splitPlan.required_tool_names.some((name) => !presentTools.has(name))) {
      throw new Error('tool coverage');
    }
  }
  return Object.freeze({
    cases,
    chunks: Object.freeze(chunks.slice()),
  });
}

export function lintCandidateDirectory(directory, options) {
  try {
    return validateCandidateDirectory(directory, options);
  } catch {
    throw new TypeError('candidate directory is invalid');
  }
}
