import { canonicalStringify } from '../../src/action.js';
import { assertProxyFreeTree } from './case-schema.mjs';
import { lintCorpus } from './corpus.mjs';

const REPORT_KEYS = Object.freeze(['reviewer_id', 'split', 'independent', 'cases']);
const ENTRY_KEYS = Object.freeze([
  'id',
  'verdict',
  'finding_codes',
  'rationale',
  'suggested_disposition',
]);
const VERDICTS = new Set(['accept', 'relabel', 'rewrite', 'remove']);
const DISPOSITIONS = new Set(['allow', 'review', 'deny']);
const FINDING_CODES = new Set([
  'shape-invalid',
  'label-unsafe-allow',
  'label-review-vs-deny',
  'label-deny-vs-review',
  'label-overblocked-allow',
  'unobservable',
  'label-leakage',
  'unrealistic',
  'duplicate',
  'contrast-not-single-factor',
  'real-secret-pii',
  'policy-factor-inconsistent',
]);

function assertPlainDataObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('object');
  const prototype = Object.getPrototypeOf(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || Object.getOwnPropertySymbols(value).length !== 0
    || Object.values(descriptors).some((descriptor) => !Object.hasOwn(descriptor, 'value'))) {
    throw new Error('object');
  }
}

function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = expected.slice().sort();
  if (canonicalStringify(actual) !== canonicalStringify(wanted)) throw new Error('keys');
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function validateReviewReport(report, { reviewerId, split, candidateCases }) {
  if (typeof reviewerId !== 'string' || reviewerId === ''
    || typeof split !== 'string' || split === '') throw new Error('options');
  const candidates = lintCorpus(candidateCases);
  if (candidates.some((item) => item.split !== split)) throw new Error('candidate split');
  assertProxyFreeTree(report, 'review report');
  assertPlainDataObject(report);
  assertExactKeys(report, REPORT_KEYS);
  if (report.reviewer_id !== reviewerId || report.split !== split || report.independent !== true
    || !Array.isArray(report.cases)) throw new Error('metadata');

  const candidateIds = new Set(candidates.map((item) => item.id));
  const seen = new Set();
  for (const entry of report.cases) {
    assertPlainDataObject(entry);
    assertExactKeys(entry, ENTRY_KEYS);
    if (typeof entry.id !== 'string' || !candidateIds.has(entry.id) || seen.has(entry.id)) {
      throw new Error('id');
    }
    seen.add(entry.id);
    if (!VERDICTS.has(entry.verdict)
      || typeof entry.rationale !== 'string'
      || entry.rationale.trim() === ''
      || !Array.isArray(entry.finding_codes)
      || new Set(entry.finding_codes).size !== entry.finding_codes.length
      || entry.finding_codes.some((code) => !FINDING_CODES.has(code))
      || (entry.suggested_disposition !== null
        && !DISPOSITIONS.has(entry.suggested_disposition))) throw new Error('entry');
    if (entry.verdict === 'accept'
      && (entry.finding_codes.length !== 0 || entry.suggested_disposition !== null)) {
      throw new Error('accept');
    }
    if (entry.verdict !== 'accept' && entry.finding_codes.length === 0) throw new Error('finding');
    if (entry.verdict === 'relabel' && entry.suggested_disposition === null) {
      throw new Error('relabel');
    }
  }
  if (seen.size !== candidateIds.size) throw new Error('coverage');
  return deepFreeze(JSON.parse(canonicalStringify(report)));
}

export function lintReviewReport(report, options) {
  try {
    return validateReviewReport(report, options);
  } catch {
    throw new TypeError('corpus review report is invalid');
  }
}
