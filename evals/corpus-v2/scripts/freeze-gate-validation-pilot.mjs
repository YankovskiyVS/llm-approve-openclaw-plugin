import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalStringify } from '../../../src/action.js';
import { POLICY_VERSION } from '../../../src/constants.js';
import { corpusHash, lintCorpus } from '../../lib/corpus.mjs';
import { lintQualificationChunk } from '../../lib/corpus-qualification.mjs';
import { lintReviewReport } from '../../lib/corpus-review.mjs';

const DEFAULT_CORPUS_ROOT = resolve(fileURLToPath(new URL('../', import.meta.url)));
const MAX_INPUT_BYTES = 4 * 1024 * 1024;
const INPUT_SPECS = Object.freeze([
  Object.freeze({ key: 'plan', path: 'contracts/generation-plan.json' }),
  Object.freeze({
    key: 'candidate',
    path: 'candidates/gate-validation/chunk-002.json',
  }),
  Object.freeze({
    key: 'reviewerA',
    path: 'reviews/gate-validation-pilot/reviewer-a.json',
  }),
  Object.freeze({
    key: 'reviewerB',
    path: 'reviews/gate-validation-pilot/reviewer-b.json',
  }),
  Object.freeze({
    key: 'generationProvenance',
    path: 'reviews/gate-validation-pilot/generation-provenance.json',
  }),
  Object.freeze({ key: 'modelSelection', path: 'frozen/model-selection.json' }),
]);
const CORPUS_OUTPUT = 'frozen/gate-validation-pilot.json';
const MANIFEST_OUTPUT = 'reviews/gate-validation-pilot/freeze-manifest.json';

function invalid() {
  throw new TypeError('gate-validation pilot freeze failed');
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function render(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sameFile(left, right) {
  return left.isFile()
    && right.isFile()
    && left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function assertDirectory(path) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('directory');
}

function assertRelativeDirectories(corpusRoot, relativePath) {
  assertDirectory(corpusRoot);
  const segments = dirname(relativePath).split(sep).filter(Boolean);
  let current = corpusRoot;
  for (const segment of segments) {
    current = join(current, segment);
    assertDirectory(current);
  }
}

function readRegularBytes(path) {
  let descriptor;
  try {
    const before = lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink() || before.size < 1
      || before.size > MAX_INPUT_BYTES) throw new Error('file');
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor);
    const bytes = readFileSync(descriptor);
    const afterRead = fstatSync(descriptor);
    const afterPath = lstatSync(path);
    if (!sameFile(before, opened)
      || !sameFile(opened, afterRead)
      || !sameFile(afterRead, afterPath)
      || bytes.length !== opened.size) throw new Error('changed');
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function readInput(corpusRoot, spec) {
  assertRelativeDirectories(corpusRoot, spec.path);
  const bytes = readRegularBytes(join(corpusRoot, spec.path));
  return Object.freeze({
    ...spec,
    bytes,
    value: JSON.parse(bytes.toString('utf8')),
    sha256: sha256(bytes),
  });
}

function countsBy(values, field, keys) {
  const counts = Object.fromEntries(keys.map((key) => [key, 0]));
  for (const value of values) {
    if (!Object.hasOwn(counts, value[field])) throw new Error('count');
    counts[value[field]] += 1;
  }
  return counts;
}

function assertExactCounts(cases) {
  const families = new Set(cases.map((item) => item.family_id));
  const preferredDisposition = countsBy(
    cases,
    'preferred_disposition',
    ['allow', 'review', 'deny'],
  );
  const language = countsBy(cases, 'language', ['ru', 'en', 'mixed']);
  if (cases.length !== 30
    || families.size !== 20
    || canonicalStringify(preferredDisposition)
      !== canonicalStringify({ allow: 10, review: 10, deny: 10 })
    || canonicalStringify(language) !== canonicalStringify({ ru: 15, en: 15, mixed: 0 })) {
    throw new Error('count');
  }
  return { families: families.size, preferredDisposition, language };
}

function assertNoFamilyOverlap(cases, modelSelection) {
  if (modelSelection.some((item) => item.split !== 'model-selection')) {
    throw new Error('model-selection split');
  }
  const modelFamilies = new Set(modelSelection.map((item) => item.family_id));
  if (cases.some((item) => modelFamilies.has(item.family_id))) throw new Error('family overlap');
}

function assertExactObjectKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('provenance object');
  }
  const actual = Object.keys(value).sort();
  const wanted = expected.slice().sort();
  if (canonicalStringify(actual) !== canonicalStringify(wanted)) {
    throw new Error('provenance keys');
  }
}

function assertReviewProvenance(value, { candidateSha256, corpusSha256, reports }) {
  if (value?.schema_version !== 'gate-validation-pilot-generation-provenance.v1') {
    throw new Error('provenance schema');
  }
  const finalReview = value.final_review;
  assertExactObjectKeys(finalReview, [
    'policy_version',
    'candidate_sha256',
    'corpus_sha256',
    'reviewers',
  ]);
  if (finalReview.policy_version !== POLICY_VERSION
    || finalReview.candidate_sha256 !== candidateSha256
    || finalReview.corpus_sha256 !== corpusSha256
    || !Array.isArray(finalReview.reviewers)
    || finalReview.reviewers.length !== 2) throw new Error('provenance binding');

  const expectedLineages = [
    '/root/gv_pilot_review_a_v2',
    '/root/gv_pilot_review_b_v2',
  ];
  for (let index = 0; index < reports.length; index += 1) {
    const reviewer = finalReview.reviewers[index];
    assertExactObjectKeys(reviewer, [
      'reviewer_id',
      'lineage_id',
      'peer_report_access_attested_false',
      'report_path',
      'report_sha256',
    ]);
    if (reviewer.reviewer_id !== reports[index].reviewer_id
      || reviewer.lineage_id !== expectedLineages[index]
      || reviewer.peer_report_access_attested_false !== true
      || reviewer.report_path !== reports[index].path
      || reviewer.report_sha256 !== reports[index].sha256) {
      throw new Error('provenance reviewer');
    }
  }
}

function inspectOutput(corpusRoot, relativePath, expectedBytes, mode) {
  assertRelativeDirectories(corpusRoot, relativePath);
  const path = join(corpusRoot, relativePath);
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('output');
    if (!readRegularBytes(path).equals(expectedBytes)) throw new Error('stale');
    return Object.freeze({ path, create: false });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    if (mode !== 'write') throw new Error('missing');
    return Object.freeze({ path, create: true });
  }
}

function writeNewFile(path, bytes) {
  let descriptor;
  try {
    descriptor = openSync(
      path,
      constants.O_WRONLY
        | constants.O_CREAT
        | constants.O_EXCL
        | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  if (!readRegularBytes(path).equals(bytes)) throw new Error('write');
}

function runFreeze({ corpusRoot, mode }) {
  if (typeof corpusRoot !== 'string'
    || corpusRoot === ''
    || !isAbsolute(corpusRoot)
    || resolve(corpusRoot) !== corpusRoot
    || (mode !== 'write' && mode !== 'verify')) throw new Error('options');

  const inputs = Object.fromEntries(INPUT_SPECS.map((spec) => {
    const input = readInput(corpusRoot, spec);
    return [spec.key, input];
  }));
  const cases = lintQualificationChunk(inputs.candidate.value, {
    plan: inputs.plan.value,
    split: 'gate-validation',
    chunkIndex: 2,
  });
  const reviewReports = [
    lintReviewReport(inputs.reviewerA.value, {
      reviewerId: 'reviewer-a',
      split: 'gate-validation',
      candidateCases: cases,
    }),
    lintReviewReport(inputs.reviewerB.value, {
      reviewerId: 'reviewer-b',
      split: 'gate-validation',
      candidateCases: cases,
    }),
  ];
  if (reviewReports.some((report) => report.cases.some((item) => item.verdict !== 'accept'))) {
    throw new Error('review verdict');
  }

  const modelSelection = lintCorpus(inputs.modelSelection.value);
  assertNoFamilyOverlap(cases, modelSelection);
  const counts = assertExactCounts(cases);
  const inputFiles = INPUT_SPECS.map((spec) => ({
    path: spec.path,
    sha256: inputs[spec.key].sha256,
  }));
  const reports = [inputs.reviewerA, inputs.reviewerB].map((input, index) => ({
    reviewer_id: index === 0 ? 'reviewer-a' : 'reviewer-b',
    path: input.path,
    sha256: input.sha256,
  }));
  assertReviewProvenance(inputs.generationProvenance.value, {
    candidateSha256: inputs.candidate.sha256,
    corpusSha256: corpusHash(cases),
    reports,
  });
  const manifest = {
    schema_version: 'gate-validation-pilot-freeze.v1',
    split: 'gate-validation',
    chunk_index: 2,
    label_source: 'policy-derived-multi-review',
    corpus_sha256: corpusHash(cases),
    reports_sha256: sha256(canonicalStringify(reports)),
    input_sha256: sha256(canonicalStringify(inputFiles)),
    input_files: inputFiles,
    review_reports: reports,
    counts: {
      cases: cases.length,
      families: counts.families,
      review_reports: reviewReports.length,
      double_accepted_cases: cases.length,
      preferred_disposition: counts.preferredDisposition,
      language: counts.language,
    },
  };
  const corpusBytes = Buffer.from(render(cases), 'utf8');
  const manifestBytes = Buffer.from(render(manifest), 'utf8');
  const outputPlans = [
    inspectOutput(corpusRoot, CORPUS_OUTPUT, corpusBytes, mode),
    inspectOutput(corpusRoot, MANIFEST_OUTPUT, manifestBytes, mode),
  ];
  if (mode === 'write') {
    if (outputPlans[0].create) writeNewFile(outputPlans[0].path, corpusBytes);
    if (outputPlans[1].create) writeNewFile(outputPlans[1].path, manifestBytes);
  }

  return Object.freeze({
    ok: true,
    corpus_sha256: manifest.corpus_sha256,
    cases: cases.length,
    families: counts.families,
    double_accepted_cases: cases.length,
  });
}

export function freezeGateValidationPilot(options) {
  try {
    return runFreeze(options);
  } catch {
    return invalid();
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== '--write')) {
    throw new Error('usage: freeze-gate-validation-pilot.mjs [--write]');
  }
  const result = freezeGateValidationPilot({
    corpusRoot: DEFAULT_CORPUS_ROOT,
    mode: args[0] === '--write' ? 'write' : 'verify',
  });
  console.log(JSON.stringify(result));
}

if (process.argv[1]
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main();
}
