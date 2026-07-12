import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { lintReviewReport } from '../evals/lib/corpus-review.mjs';

const candidates = JSON.parse(readFileSync(
  new URL('../evals/fixtures/honest-corpus.json', import.meta.url),
  'utf8',
));

function reportEntries() {
  return candidates.map((item) => ({
    id: item.id,
    verdict: 'accept',
    finding_codes: [],
    rationale: 'Label and observable action are consistent.',
    suggested_disposition: null,
  }));
}

function report(overrides = {}) {
  return {
    reviewer_id: 'reviewer-a',
    split: 'model-selection',
    independent: true,
    cases: reportEntries(),
    ...overrides,
  };
}

test('review report requires exactly one independent entry per candidate case', () => {
  const result = lintReviewReport(report(), {
    reviewerId: 'reviewer-a',
    split: 'model-selection',
    candidateCases: candidates,
  });

  assert.equal(result.cases.length, 4);
  assert.equal(Object.isFrozen(result), true);
});

test('review report rejects missing, duplicate and unknown case IDs', () => {
  const mutations = [
    (entries) => entries.pop(),
    (entries) => { entries[1].id = entries[0].id; },
    (entries) => { entries[1].id = 'unknown-case'; },
  ];
  for (const mutate of mutations) {
    const entries = reportEntries();
    mutate(entries);
    assert.throws(
      () => lintReviewReport(report({ cases: entries }), {
        reviewerId: 'reviewer-a',
        split: 'model-selection',
        candidateCases: candidates,
      }),
      /corpus review report is invalid/,
    );
  }
});

test('review report enforces verdict, findings and suggested disposition consistency', () => {
  const invalidEntries = [
    { verdict: 'accept', finding_codes: ['unrealistic'] },
    { verdict: 'relabel', finding_codes: [], suggested_disposition: 'deny' },
    { verdict: 'relabel', finding_codes: ['label-review-vs-deny'], suggested_disposition: null },
    { verdict: 'rewrite', finding_codes: ['not-a-code'] },
  ];
  for (const overrides of invalidEntries) {
    const entries = reportEntries();
    Object.assign(entries[0], overrides);
    assert.throws(
      () => lintReviewReport(report({ cases: entries }), {
        reviewerId: 'reviewer-a',
        split: 'model-selection',
        candidateCases: candidates,
      }),
      /corpus review report is invalid/,
    );
  }
});
