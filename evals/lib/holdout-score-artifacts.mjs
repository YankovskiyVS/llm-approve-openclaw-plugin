import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import {
  buildArtifactFiles,
  HOLDOUT_SCORE_REPRODUCE_SCRIPT,
} from './artifacts.mjs';
import { snapshotAttemptManifest } from './attempt.mjs';
import {
  buildSyntheticPilotGate,
  renderSyntheticPilotGateJunit,
} from './holdout-gate.mjs';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const INPUT_KEYS = Object.freeze([
  'holdoutId',
  'inputSha256',
  'freezeCommitmentSha256',
  'freezeReceiptSha256',
  'partitionAuditSha256',
  'oracleSha256',
  'inferenceArtifactSha256',
  'inferencePayloadSha256',
  'manifest',
  'attempts',
  'summary',
  'pricing',
  'caseOutcomes',
  'familyOutcomes',
  'repeats',
  'concurrency',
  'scorerGitSha',
  'scorerSourceSha256',
  'forbiddenValues',
]);
const RESULT_FILE_NAMES = Object.freeze([
  'manifest.json',
  'attempts.jsonl',
  'cases.csv',
  'summary.json',
  'ranking.csv',
  'report.md',
  'pricing-snapshot.json',
  'junit.xml',
  'gate-result.json',
  'gate-junit.xml',
  'reproduce.sh',
]);
const RESULT_SET_FILE_NAMES = Object.freeze([
  ...RESULT_FILE_NAMES,
  'score-attestation.json',
]);
const SCORER_SOURCE_FILES = Object.freeze([
  ['package.json', new URL('../../package.json', import.meta.url)],
  ['package-lock.json', new URL('../../package-lock.json', import.meta.url)],
  ['schemas/judge-verdict.schema.json', new URL('../../schemas/judge-verdict.schema.json', import.meta.url)],
  ['src/action.js', new URL('../../src/action.js', import.meta.url)],
  ['src/constants.js', new URL('../../src/constants.js', import.meta.url)],
  ['src/decision.js', new URL('../../src/decision.js', import.meta.url)],
  ['src/feedback.js', new URL('../../src/feedback.js', import.meta.url)],
  ['src/intrinsics.js', new URL('../../src/intrinsics.js', import.meta.url)],
  ['src/judge-schema.js', new URL('../../src/judge-schema.js', import.meta.url)],
  ['src/policy-routing.js', new URL('../../src/policy-routing.js', import.meta.url)],
  ['src/redact.js', new URL('../../src/redact.js', import.meta.url)],
  ['src/run-decision-store.js', new URL('../../src/run-decision-store.js', import.meta.url)],
  ['evals/lib/aggregate.mjs', new URL('./aggregate.mjs', import.meta.url)],
  ['evals/lib/artifacts.mjs', new URL('./artifacts.mjs', import.meta.url)],
  ['evals/lib/attempt.mjs', new URL('./attempt.mjs', import.meta.url)],
  ['evals/lib/case-input.mjs', new URL('./case-input.mjs', import.meta.url)],
  ['evals/lib/case-schema.mjs', new URL('./case-schema.mjs', import.meta.url)],
  ['evals/lib/corpus.mjs', new URL('./corpus.mjs', import.meta.url)],
  ['evals/lib/holdout-commitments.mjs', new URL('./holdout-commitments.mjs', import.meta.url)],
  ['evals/lib/holdout-contracts.mjs', new URL('./holdout-contracts.mjs', import.meta.url)],
  ['evals/lib/holdout-gate.mjs', new URL('./holdout-gate.mjs', import.meta.url)],
  ['evals/lib/holdout-partition-audit.mjs', new URL('./holdout-partition-audit.mjs', import.meta.url)],
  ['evals/lib/holdout-runner.mjs', new URL('./holdout-runner.mjs', import.meta.url)],
  ['evals/lib/holdout-score-artifacts.mjs', new URL('./holdout-score-artifacts.mjs', import.meta.url)],
  ['evals/lib/holdout-score-cli.mjs', new URL('./holdout-score-cli.mjs', import.meta.url)],
  ['evals/lib/holdout-scorer.mjs', new URL('./holdout-scorer.mjs', import.meta.url)],
  ['evals/lib/manifest.mjs', new URL('./manifest.mjs', import.meta.url)],
  ['evals/lib/render.mjs', new URL('./render.mjs', import.meta.url)],
  ['evals/lib/wilson.mjs', new URL('./wilson.mjs', import.meta.url)],
  ['evals/holdout-score.mjs', new URL('../holdout-score.mjs', import.meta.url)],
]);

function invalidInput() {
  throw new TypeError('invalid holdout score artifact input');
}

function exactDataValues(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalidInput();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalidInput();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== INPUT_KEYS.length
      || keys.some((key) => typeof key !== 'string' || !INPUT_KEYS.includes(key))) {
      invalidInput();
    }
    const result = {};
    for (const key of INPUT_KEYS) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        invalidInput();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    invalidInput();
  }
}

function sha256Bytes(value) {
  return 'sha256:' + createHash('sha256').update(value).digest('hex');
}

function assertHash(value) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) invalidInput();
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function resultFileHashes(files, names) {
  if (!(files instanceof Map) || files.size !== names.length) invalidInput();
  const result = {};
  for (const name of names) {
    const content = files.get(name);
    if (typeof content !== 'string' && !Buffer.isBuffer(content)) invalidInput();
    result[name] = sha256Bytes(Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8'));
  }
  return result;
}

export async function computeScorerSourceCompositeHash(readSource = async (_name, url) => readFile(url)) {
  if (typeof readSource !== 'function') invalidInput();
  const entries = await Promise.all(SCORER_SOURCE_FILES.map(async ([name, url]) => [
    name,
    sha256Bytes(await readSource(name, url)),
  ]));
  const sourceHashes = Object.fromEntries(entries);
  return sha256Bytes(Buffer.from(canonicalStringify(sourceHashes), 'utf8'));
}

export function buildHoldoutScoreArtifacts(input) {
  const fields = exactDataValues(input);
  const manifest = snapshotAttemptManifest(fields.manifest);
  if (typeof fields.holdoutId !== 'string'
    || fields.holdoutId.trim() === ''
    || fields.holdoutId.length > 128
    || /[\u0000-\u001f\u007f]/u.test(fields.holdoutId)
    || !Number.isInteger(fields.repeats)
    || fields.repeats < 1
    || fields.repeats > 10
    || !Number.isInteger(fields.concurrency)
    || fields.concurrency < 1
    || fields.concurrency > 32
    || typeof fields.scorerGitSha !== 'string'
    || !/^[0-9a-f]{40}$/u.test(fields.scorerGitSha)) invalidInput();
  for (const hash of [
    fields.inputSha256,
    fields.freezeCommitmentSha256,
    fields.freezeReceiptSha256,
    fields.partitionAuditSha256,
    fields.oracleSha256,
    fields.inferenceArtifactSha256,
    fields.inferencePayloadSha256,
    fields.scorerSourceSha256,
  ]) assertHash(hash);
  if (fields.inputSha256 !== manifest.corpus_sha256) invalidInput();

  const files = buildArtifactFiles({
    manifest,
    attempts: fields.attempts,
    summary: fields.summary,
    pricing: fields.pricing,
    caseOutcomes: fields.caseOutcomes,
    familyOutcomes: fields.familyOutcomes,
    forbiddenValues: fields.forbiddenValues,
  }, {
    expectedRepeats: fields.repeats,
    reproduceScript: HOLDOUT_SCORE_REPRODUCE_SCRIPT,
  });
  const gate = buildSyntheticPilotGate(fields.summary);
  const report = files.get('report.md');
  if (typeof report !== 'string' || !report.startsWith('# Judge qualification report\n')) {
    invalidInput();
  }
  files.set('report.md', report.replace(
    '# Judge qualification report\n',
    '# Synthetic pilot diagnostic report\n\n'
      + '> This artifact is not launch qualification evidence. See `gate-result.json`.\n',
  ));
  files.set('gate-result.json', canonicalStringify(gate) + '\n');
  files.set('gate-junit.xml', renderSyntheticPilotGateJunit(gate));
  const attestation = deepFreeze({
    schema_version: 'judge-holdout-score-attestation.v3',
    holdout_id: fields.holdoutId,
    input_sha256: fields.inputSha256,
    freeze_commitment_sha256: fields.freezeCommitmentSha256,
    freeze_receipt_sha256: fields.freezeReceiptSha256,
    partition_audit_sha256: fields.partitionAuditSha256,
    oracle_sha256: fields.oracleSha256,
    inference_artifact_sha256: fields.inferenceArtifactSha256,
    inference_payload_sha256: fields.inferencePayloadSha256,
    pricing_sha256: manifest.pricing_sha256,
    manifest_hash: manifest.manifest_hash,
    model_id: manifest.model_id,
    policy_version: manifest.policy_version,
    repeats: fields.repeats,
    concurrency: fields.concurrency,
    scorer_git_sha: fields.scorerGitSha,
    scorer_source_sha256: fields.scorerSourceSha256,
    files_sha256: resultFileHashes(files, RESULT_FILE_NAMES),
  });
  const attestationContent = canonicalStringify(attestation) + '\n';
  const attestationHash = sha256Bytes(Buffer.from(attestationContent, 'utf8'));
  files.set('score-attestation.json', attestationContent);
  const resultSet = deepFreeze({
    schema_version: 'judge-holdout-result-set.v1',
    files_sha256: resultFileHashes(files, RESULT_SET_FILE_NAMES),
  });
  const resultSetCanonical = canonicalStringify(resultSet);
  const resultSetHash = sha256Bytes(Buffer.from(resultSetCanonical, 'utf8'));
  files.set('result-set.json', resultSetCanonical + '\n');
  return Object.freeze({ files, attestation, attestationHash, resultSetHash });
}
