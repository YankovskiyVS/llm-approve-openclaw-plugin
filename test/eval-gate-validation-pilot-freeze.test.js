import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalStringify } from '../src/action.js';
import { corpusHash, lintCorpus } from '../evals/lib/corpus.mjs';

const SOURCE_ROOT = new URL('../evals/corpus-v2/', import.meta.url);
const SCRIPT_URL = new URL(
  '../evals/corpus-v2/scripts/freeze-gate-validation-pilot.mjs',
  import.meta.url,
);

const INPUT_PATHS = Object.freeze([
  'contracts/generation-plan.json',
  'candidates/gate-validation/chunk-002.json',
  'reviews/gate-validation-pilot/reviewer-a.json',
  'reviews/gate-validation-pilot/reviewer-b.json',
  'reviews/gate-validation-pilot/generation-provenance.json',
  'frozen/model-selection.json',
]);

function readJson(url) {
  return JSON.parse(readFileSync(url, 'utf8'));
}

function render(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function acceptReport(reviewerId, cases) {
  return {
    reviewer_id: reviewerId,
    split: 'gate-validation',
    independent: true,
    cases: cases.map((item) => ({
      id: item.id,
      verdict: 'accept',
      finding_codes: [],
      rationale: `${reviewerId} independently accepts the policy-derived label.`,
      suggested_disposition: null,
    })),
  };
}

function makeFixture() {
  const corpusRoot = mkdtempSync(join(tmpdir(), 'judge-gate-pilot-'));
  for (const directory of [
    'contracts',
    'candidates/gate-validation',
    'reviews/gate-validation-pilot',
    'frozen',
  ]) {
    mkdirSync(join(corpusRoot, directory), { recursive: true });
  }

  const plan = readJson(new URL('contracts/generation-plan.json', SOURCE_ROOT));
  const cases = readJson(new URL(
    'candidates/gate-validation/chunk-002.json',
    SOURCE_ROOT,
  ));
  const modelSelection = readJson(new URL('frozen/model-selection.json', SOURCE_ROOT));
  const reviewerA = acceptReport('reviewer-a', cases);
  const reviewerB = acceptReport('reviewer-b', cases);
  const generationProvenance = {
    schema_version: 'gate-validation-pilot-generation-provenance.v1',
    final_review: {
      policy_version: '2026-07-12.4',
      candidate_sha256: sha256(Buffer.from(render(cases), 'utf8')),
      corpus_sha256: corpusHash(lintCorpus(cases)),
      reviewers: [
        {
          reviewer_id: 'reviewer-a',
          lineage_id: '/root/gv_pilot_review_a_v2',
          peer_report_access_attested_false: true,
          report_path: 'reviews/gate-validation-pilot/reviewer-a.json',
          report_sha256: sha256(Buffer.from(render(reviewerA), 'utf8')),
        },
        {
          reviewer_id: 'reviewer-b',
          lineage_id: '/root/gv_pilot_review_b_v2',
          peer_report_access_attested_false: true,
          report_path: 'reviews/gate-validation-pilot/reviewer-b.json',
          report_sha256: sha256(Buffer.from(render(reviewerB), 'utf8')),
        },
      ],
    },
  };
  const values = {
    'contracts/generation-plan.json': plan,
    'candidates/gate-validation/chunk-002.json': cases,
    'reviews/gate-validation-pilot/reviewer-a.json': reviewerA,
    'reviews/gate-validation-pilot/reviewer-b.json': reviewerB,
    'reviews/gate-validation-pilot/generation-provenance.json': generationProvenance,
    'frozen/model-selection.json': modelSelection,
  };
  for (const [relativePath, value] of Object.entries(values)) {
    writeFileSync(join(corpusRoot, relativePath), render(value));
  }
  return {
    corpusRoot,
    cases,
    cleanup: () => rmSync(corpusRoot, { recursive: true, force: true }),
  };
}

async function loadFreezer() {
  const module = await import(SCRIPT_URL.href);
  assert.equal(typeof module.freezeGateValidationPilot, 'function');
  return module.freezeGateValidationPilot;
}

function expectedInputFiles(corpusRoot) {
  return INPUT_PATHS.map((path) => ({
    path,
    sha256: sha256(readFileSync(join(corpusRoot, path))),
  }));
}

test('write mode freezes the exact reviewed pilot and a deterministic hash manifest', async () => {
  const freezeGateValidationPilot = await loadFreezer();
  const fixture = makeFixture();
  try {
    const result = freezeGateValidationPilot({
      corpusRoot: fixture.corpusRoot,
      mode: 'write',
    });
    const corpusPath = join(fixture.corpusRoot, 'frozen/gate-validation-pilot.json');
    const manifestPath = join(
      fixture.corpusRoot,
      'reviews/gate-validation-pilot/freeze-manifest.json',
    );
    const frozen = lintCorpus(readJson(corpusPath));
    const manifest = readJson(manifestPath);
    const inputFiles = expectedInputFiles(fixture.corpusRoot);
    const reports = inputFiles.slice(2, 4).map((item, index) => ({
      reviewer_id: index === 0 ? 'reviewer-a' : 'reviewer-b',
      path: item.path,
      sha256: item.sha256,
    }));

    assert.deepEqual(frozen, lintCorpus(fixture.cases));
    assert.equal(readFileSync(corpusPath, 'utf8'), render(frozen));
    assert.deepEqual(manifest, {
      schema_version: 'gate-validation-pilot-freeze.v1',
      split: 'gate-validation',
      chunk_index: 2,
      label_source: 'policy-derived-multi-review',
      corpus_sha256: corpusHash(frozen),
      reports_sha256: sha256(canonicalStringify(reports)),
      input_sha256: sha256(canonicalStringify(inputFiles)),
      input_files: inputFiles,
      review_reports: reports,
      counts: {
        cases: 30,
        families: 20,
        review_reports: 2,
        double_accepted_cases: 30,
        preferred_disposition: { allow: 10, review: 10, deny: 10 },
        language: { ru: 15, en: 15, mixed: 0 },
      },
    });
    assert.equal(readFileSync(manifestPath, 'utf8'), render(manifest));
    assert.deepEqual(result, {
      ok: true,
      corpus_sha256: corpusHash(frozen),
      cases: 30,
      families: 20,
      double_accepted_cases: 30,
    });

    assert.deepEqual(freezeGateValidationPilot({
      corpusRoot: fixture.corpusRoot,
      mode: 'write',
    }), result, 'identical write is idempotent');
    assert.deepEqual(freezeGateValidationPilot({
      corpusRoot: fixture.corpusRoot,
      mode: 'verify',
    }), result, 'verify checks exact stored bytes');
  } finally {
    fixture.cleanup();
  }
});

test('freezer requires two exact all-accept review reports', async () => {
  const freezeGateValidationPilot = await loadFreezer();
  for (const mutate of [
    (root) => {
      const path = join(root, 'reviews/gate-validation-pilot/reviewer-a.json');
      const report = readJson(path);
      report.cases[0] = {
        ...report.cases[0],
        verdict: 'rewrite',
        finding_codes: ['unrealistic'],
      };
      writeFileSync(path, render(report));
    },
    (root) => {
      const path = join(root, 'reviews/gate-validation-pilot/reviewer-b.json');
      const report = readJson(path);
      report.reviewer_id = 'reviewer-a';
      writeFileSync(path, render(report));
    },
  ]) {
    const fixture = makeFixture();
    try {
      mutate(fixture.corpusRoot);
      assert.throws(
        () => freezeGateValidationPilot({ corpusRoot: fixture.corpusRoot, mode: 'write' }),
        /gate-validation pilot freeze failed/,
      );
      assert.equal(
        existsSync(join(fixture.corpusRoot, 'frozen/gate-validation-pilot.json')),
        false,
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test('freezer rejects family overlap with the frozen model-selection corpus', async () => {
  const freezeGateValidationPilot = await loadFreezer();
  const fixture = makeFixture();
  try {
    const modelPath = join(fixture.corpusRoot, 'frozen/model-selection.json');
    const modelSelection = readJson(modelPath);
    modelSelection[0].family_id = fixture.cases[0].family_id;
    writeFileSync(modelPath, render(modelSelection));

    assert.throws(
      () => freezeGateValidationPilot({ corpusRoot: fixture.corpusRoot, mode: 'write' }),
      /gate-validation pilot freeze failed/,
    );
  } finally {
    fixture.cleanup();
  }
});

test('freezer rejects a same-ID candidate mutation against the reviewed hash', async () => {
  const freezeGateValidationPilot = await loadFreezer();
  const fixture = makeFixture();
  try {
    const candidatePath = join(
      fixture.corpusRoot,
      'candidates/gate-validation/chunk-002.json',
    );
    const candidate = readJson(candidatePath);
    candidate[0].trusted_user_request += ' changed after review';
    writeFileSync(candidatePath, render(candidate));

    assert.throws(
      () => freezeGateValidationPilot({ corpusRoot: fixture.corpusRoot, mode: 'write' }),
      /gate-validation pilot freeze failed/,
    );
  } finally {
    fixture.cleanup();
  }
});

test('freezer never clobbers different output bytes', async () => {
  const freezeGateValidationPilot = await loadFreezer();
  const fixture = makeFixture();
  try {
    const corpusPath = join(fixture.corpusRoot, 'frozen/gate-validation-pilot.json');
    const manifestPath = join(
      fixture.corpusRoot,
      'reviews/gate-validation-pilot/freeze-manifest.json',
    );
    writeFileSync(corpusPath, 'different\n');

    assert.throws(
      () => freezeGateValidationPilot({ corpusRoot: fixture.corpusRoot, mode: 'write' }),
      /gate-validation pilot freeze failed/,
    );
    assert.equal(readFileSync(corpusPath, 'utf8'), 'different\n');
    assert.equal(existsSync(manifestPath), false, 'preflight prevents a partial write');
    assert.throws(
      () => freezeGateValidationPilot({ corpusRoot: fixture.corpusRoot, mode: 'verify' }),
      /gate-validation pilot freeze failed/,
    );
  } finally {
    fixture.cleanup();
  }
});

test('freezer rejects symlinked inputs and outputs', async () => {
  const freezeGateValidationPilot = await loadFreezer();
  for (const linkOutput of [false, true]) {
    const fixture = makeFixture();
    try {
      const target = join(fixture.corpusRoot, 'target.json');
      writeFileSync(target, '{}\n');
      if (linkOutput) {
        symlinkSync(target, join(fixture.corpusRoot, 'frozen/gate-validation-pilot.json'));
      } else {
        const input = join(
          fixture.corpusRoot,
          'candidates/gate-validation/chunk-002.json',
        );
        rmSync(input);
        symlinkSync(target, input);
      }

      assert.throws(
        () => freezeGateValidationPilot({ corpusRoot: fixture.corpusRoot, mode: 'write' }),
        /gate-validation pilot freeze failed/,
      );
      assert.equal(readFileSync(target, 'utf8'), '{}\n');
    } finally {
      fixture.cleanup();
    }
  }
});
