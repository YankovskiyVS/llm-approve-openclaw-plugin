import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalStringify } from '../../../src/action.js';
import { corpusHash, lintCorpus } from '../../lib/corpus.mjs';
import { lintReviewReport } from '../../lib/corpus-review.mjs';
import { readRegularJsonFile } from '../../lib/corpus-qualification.mjs';

const corpusRoot = new URL('../', import.meta.url);
const repositoryRoot = fileURLToPath(new URL('../../../../', import.meta.url));
const candidatePath = 'openclaw-llm-action-judge/evals/corpus-v2/candidates/model-selection';
const reviewRoot = new URL('reviews/model-selection/', corpusRoot);
const outputFile = new URL('review-chain.json', reviewRoot);
const verifierSource = readFileSync(new URL(import.meta.url));

function sha256Bytes(value) {
  return 'sha256:' + createHash('sha256').update(value).digest('hex');
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function loadCasesFromCommit(commit) {
  const chunks = [];
  for (let index = 1; index <= 4; index += 1) {
    const file = `${candidatePath}/chunk-${String(index).padStart(3, '0')}.json`;
    const source = execFileSync('git', ['-C', repositoryRoot, 'show', `${commit}:${file}`], {
      encoding: 'utf8',
    });
    chunks.push(JSON.parse(source));
  }
  return lintCorpus(chunks.flat());
}

function chunkHashesFromCommit(commit) {
  const result = {};
  for (let index = 1; index <= 4; index += 1) {
    const name = `chunk-${String(index).padStart(3, '0')}.json`;
    const file = `${candidatePath}/${name}`;
    const source = execFileSync('git', ['-C', repositoryRoot, 'show', `${commit}:${file}`]);
    result[name] = sha256Hex(source);
  }
  return result;
}

function currentChunkHashes() {
  const result = {};
  for (let index = 1; index <= 4; index += 1) {
    const name = `chunk-${String(index).padStart(3, '0')}.json`;
    result[name] = sha256Hex(readFileSync(new URL(`candidates/model-selection/${name}`, corpusRoot)));
  }
  return result;
}

function loadCurrentCases() {
  const values = [];
  for (let index = 1; index <= 4; index += 1) {
    const file = new URL(
      `candidates/model-selection/chunk-${String(index).padStart(3, '0')}.json`,
      corpusRoot,
    );
    values.push(...readRegularJsonFile(fileURLToPath(file)));
  }
  return lintCorpus(values);
}

function mapById(cases) {
  return new Map(cases.map((item) => [item.id, item]));
}

function changedIds(before, after) {
  const prior = mapById(before);
  return after
    .filter((item) => canonicalStringify(item) !== canonicalStringify(prior.get(item.id)))
    .map((item) => item.id)
    .sort();
}

function assertSameIds(actual, expected, name) {
  if (canonicalStringify([...actual].sort()) !== canonicalStringify([...expected].sort())) {
    throw new Error(`${name} ID set mismatch`);
  }
}

function loadReport(name, reviewerId, candidateCases) {
  const url = new URL(name, reviewRoot);
  const source = readFileSync(url);
  const report = lintReviewReport(JSON.parse(source.toString('utf8')), {
    reviewerId,
    split: 'model-selection',
    candidateCases,
  });
  return {
    report,
    sha256: sha256Bytes(source),
  };
}

function verdictsById(report) {
  return new Map(report.cases.map((item) => [item.id, item.verdict]));
}

const initialCases = loadCasesFromCommit('4ed7ddb');
const v2Cases = loadCasesFromCommit('c3852e4');
const v3Cases = loadCasesFromCommit('b4afb19');
const finalCases = loadCurrentCases();
const v3Delta = readRegularJsonFile(fileURLToPath(new URL('v3-delta.json', reviewRoot)));
const v4Delta = readRegularJsonFile(fileURLToPath(new URL('v4-delta.json', reviewRoot)));
const provenanceUrl = new URL('generation-provenance.json', reviewRoot);
const provenanceSource = readFileSync(provenanceUrl);
const provenance = JSON.parse(provenanceSource.toString('utf8'));
const reviewerProvenanceUrl = new URL('reviewer-provenance.json', reviewRoot);
const reviewerProvenanceSource = readFileSync(reviewerProvenanceUrl);
const reviewerProvenance = JSON.parse(reviewerProvenanceSource.toString('utf8'));

const v2ManifestBaseCases = loadCasesFromCommit(v3Delta.base_commit);
const v3ManifestCandidateCases = loadCasesFromCommit(v3Delta.candidate_commit);
const v4ManifestBaseCases = loadCasesFromCommit(v4Delta.base_commit);
const finalCommitCases = loadCasesFromCommit(v4Delta.candidate_commit);
if (canonicalStringify(v2ManifestBaseCases) !== canonicalStringify(v2Cases)
  || canonicalStringify(v3ManifestCandidateCases) !== canonicalStringify(v3Cases)
  || canonicalStringify(v4ManifestBaseCases) !== canonicalStringify(v3Cases)
  || canonicalStringify(finalCommitCases) !== canonicalStringify(finalCases)) {
  throw new Error('manifest commit does not bind the expected corpus tree');
}

if (provenance.generator.model !== 'claude-opus-4-8'
  || provenance.generator.effort !== 'high'
  || provenance.generator.cloudru_model_calls !== 0
  || provenance.initial_candidate.commit !== '4ed7ddb'
  || provenance.final_candidate.commit !== v4Delta.candidate_commit
  || provenance.initial_candidate.corpus_sha256 !== corpusHash(initialCases)
  || provenance.final_candidate.corpus_sha256 !== corpusHash(finalCases)
  || canonicalStringify(provenance.initial_candidate.chunk_file_sha256)
    !== canonicalStringify(chunkHashesFromCommit('4ed7ddb'))
  || canonicalStringify(provenance.final_candidate.chunk_file_sha256)
    !== canonicalStringify(currentChunkHashes())) {
  throw new Error('generation provenance mismatch');
}

if (corpusHash(v2Cases) !== v3Delta.base_corpus_sha256
  || corpusHash(v3Cases) !== v3Delta.candidate_corpus_sha256
  || corpusHash(v3Cases) !== v4Delta.base_corpus_sha256
  || corpusHash(finalCases) !== v4Delta.candidate_corpus_sha256) {
  throw new Error('corpus hash chain mismatch');
}
assertSameIds(changedIds(v2Cases, v3Cases), v3Delta.ids, 'v3 delta');
assertSameIds(changedIds(v3Cases, finalCases), v4Delta.ids, 'v4 delta');

const v3Ids = new Set(v3Delta.ids);
const v4Ids = new Set(v4Delta.ids);
const v3Subset = v3Cases.filter((item) => v3Ids.has(item.id));
const v4Subset = finalCases.filter((item) => v4Ids.has(item.id));

const reportSpecs = [
  ['reviewer-a-v2.json', 'reviewer-a-v2', v2Cases, 'v2-a'],
  ['reviewer-b-v2.json', 'reviewer-b-v2', v2Cases, 'v2-b'],
  ['reviewer-a-v3-delta.json', 'reviewer-a-v3-delta', v3Subset, 'v3-a'],
  ['reviewer-b-v3-delta.json', 'reviewer-b-v3-delta', v3Subset, 'v3-b'],
  ['reviewer-a-v4-delta.json', 'reviewer-a-v4-delta', v4Subset, 'v4-a'],
  ['reviewer-b-v4-delta.json', 'reviewer-b-v4-delta', v4Subset, 'v4-b'],
];
const reports = new Map();
const reportObjects = new Map();
const reportArtifacts = [];
for (const [file, reviewerId, cases, key] of reportSpecs) {
  const result = loadReport(file, reviewerId, cases);
  reports.set(key, verdictsById(result.report));
  reportObjects.set(key, result.report);
  reportArtifacts.push({ file, reviewer_id: reviewerId, sha256: result.sha256 });
}

for (const [first, second] of [['v2-a', 'v2-b'], ['v3-a', 'v3-b'], ['v4-a', 'v4-b']]) {
  if (canonicalStringify(reportObjects.get(first).cases)
    === canonicalStringify(reportObjects.get(second).cases)) {
    throw new Error('independent reviewer reports are identical copies');
  }
}

if (reviewerProvenance.schema_version !== 'independent-reviewer-provenance.v1'
  || reviewerProvenance.evidence_level !== 'orchestrator-lineage-attestation'
  || !Array.isArray(reviewerProvenance.reviewers)
  || reviewerProvenance.reviewers.length !== 2) {
  throw new Error('reviewer provenance metadata is invalid');
}
const [reviewerA, reviewerB] = reviewerProvenance.reviewers;
if (reviewerA.lineage_id === reviewerB.lineage_id
  || reviewerA.peer_lineage_id !== reviewerB.lineage_id
  || reviewerB.peer_lineage_id !== reviewerA.lineage_id
  || reviewerA.initial_context_fork !== 'none'
  || reviewerB.initial_context_fork !== 'none'
  || reviewerA.peer_report_access_prohibited !== true
  || reviewerB.peer_report_access_prohibited !== true
  || reviewerA.peer_report_access_attested_false !== true
  || reviewerB.peer_report_access_attested_false !== true) {
  throw new Error('reviewer lineage independence is invalid');
}
const expectedReviewerAHashes = Object.fromEntries(
  reportArtifacts
    .filter((item) => item.reviewer_id.startsWith('reviewer-a-'))
    .map((item) => [item.file, item.sha256]),
);
const expectedReviewerBHashes = Object.fromEntries(
  reportArtifacts
    .filter((item) => item.reviewer_id.startsWith('reviewer-b-'))
    .map((item) => [item.file, item.sha256]),
);
if (canonicalStringify(reviewerA.reports) !== canonicalStringify(expectedReviewerAHashes)
  || canonicalStringify(reviewerB.reports) !== canonicalStringify(expectedReviewerBHashes)
  || Object.keys(reviewerA.reports).some((file) => Object.hasOwn(reviewerB.reports, file))) {
  throw new Error('reviewer provenance does not bind per-lineage report hashes');
}

const v2ById = mapById(v2Cases);
const v3ById = mapById(v3Cases);
const coverage = { v2_full: 0, v3_delta: 0, v4_delta: 0 };
const finalCoverage = [];
for (const item of finalCases) {
  let layer;
  let sourceCase;
  let first;
  let second;
  if (v4Ids.has(item.id)) {
    layer = 'v4_delta';
    sourceCase = item;
    first = reports.get('v4-a').get(item.id);
    second = reports.get('v4-b').get(item.id);
  } else if (v3Ids.has(item.id)) {
    layer = 'v3_delta';
    sourceCase = v3ById.get(item.id);
    first = reports.get('v3-a').get(item.id);
    second = reports.get('v3-b').get(item.id);
  } else {
    layer = 'v2_full';
    sourceCase = v2ById.get(item.id);
    first = reports.get('v2-a').get(item.id);
    second = reports.get('v2-b').get(item.id);
  }
  if (canonicalStringify(sourceCase) !== canonicalStringify(item)) {
    throw new Error(`reviewed source differs from final case ${item.id}`);
  }
  if (first !== 'accept' || second !== 'accept') {
    throw new Error(`final case lacks two accepts ${item.id}`);
  }
  coverage[layer] += 1;
  finalCoverage.push({ id: item.id, layer, reviewer_verdicts: ['accept', 'accept'] });
}

if (coverage.v2_full !== 88 || coverage.v3_delta !== 23 || coverage.v4_delta !== 9) {
  throw new Error('unexpected review coverage counts');
}

const artifact = {
  schema_version: 'model-selection-review-chain.v1',
  final_candidate_commit: v4Delta.candidate_commit,
  final_corpus_sha256: corpusHash(finalCases),
  cases: finalCases.length,
  coverage,
  all_final_cases_double_accepted: true,
  verifier_source_sha256: sha256Bytes(verifierSource),
  generation_provenance_sha256: sha256Bytes(provenanceSource),
  reviewer_provenance_sha256: sha256Bytes(reviewerProvenanceSource),
  report_artifacts: reportArtifacts,
  final_case_coverage: finalCoverage,
};

if (process.argv.slice(2).includes('--write')) {
  writeFileSync(outputFile, `${JSON.stringify(artifact, null, 2)}\n`);
} else {
  const storedArtifact = readRegularJsonFile(fileURLToPath(outputFile));
  if (canonicalStringify(storedArtifact) !== canonicalStringify(artifact)) {
    throw new Error('stored review chain is stale or corrupted');
  }
}
console.log(JSON.stringify({
  ok: true,
  final_corpus_sha256: artifact.final_corpus_sha256,
  cases: artifact.cases,
  coverage,
}));
