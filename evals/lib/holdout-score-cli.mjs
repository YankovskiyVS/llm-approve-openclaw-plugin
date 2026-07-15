import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep, win32 } from 'node:path';
import { promisify, types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { aggregateQualification } from './aggregate.mjs';
import { publishArtifacts } from './artifacts.mjs';
import {
  holdoutFreezeCommitmentHash,
  holdoutFreezeReceiptHash,
  holdoutOracleHash,
  validateHoldoutFreezeCommitment,
  validateHoldoutFreezeReceipt,
} from './holdout-commitments.mjs';
import {
  holdoutInputHash,
  validateHoldoutInput,
  validateHoldoutOracle,
} from './holdout-contracts.mjs';
import { validateHoldoutInferenceArtifact } from './holdout-runner.mjs';
import {
  buildHoldoutScoreArtifacts,
  computeScorerSourceCompositeHash,
} from './holdout-score-artifacts.mjs';
import { scoreHoldout } from './holdout-scorer.mjs';

const INVALID_ARGUMENTS = 'invalid holdout score arguments';
const execFile = promisify(execFileCallback);
const PACKAGE_ROOT = new URL('../..', import.meta.url);
const FLAGS = Object.freeze({
  '--input': 'inputPath',
  '--oracle': 'oraclePath',
  '--freeze-commitment': 'freezeCommitmentPath',
  '--freeze-commitment-sha256': 'expectedFreezeCommitmentSha256',
  '--freeze-receipt': 'freezeReceiptPath',
  '--freeze-receipt-sha256': 'expectedFreezeReceiptSha256',
  '--inference': 'inferencePath',
  '--inference-artifact-sha256': 'expectedInferenceArtifactSha256',
  '--pricing': 'pricingPath',
  '--scorer-git-sha': 'expectedScorerGitSha',
  '--output': 'outputPath',
});
const OPTION_KEYS = Object.freeze([
  'inputPath', 'oraclePath', 'freezeCommitmentPath',
  'expectedFreezeCommitmentSha256', 'freezeReceiptPath',
  'expectedFreezeReceiptSha256', 'inferencePath',
  'expectedInferenceArtifactSha256', 'pricingPath', 'expectedScorerGitSha',
  'outputPath',
]);
const INPUT_PATH_KEYS = Object.freeze([
  'inputPath', 'oraclePath', 'freezeCommitmentPath', 'freezeReceiptPath',
  'inferencePath', 'pricingPath',
]);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const GIT_PATTERN = /^[0-9a-f]{40}$/u;
const DEPENDENCY_KEYS = Object.freeze(['forbiddenValues', 'scorerGitSha']);
const MAX_INPUT_BYTES = 64 * 1024 * 1024;
const READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);

function invalidArguments() {
  throw new TypeError(INVALID_ARGUMENTS);
}

function snapshotArgv(value) {
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) invalidArguments();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1
      || descriptors.length?.value !== value.length) invalidArguments();
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'string') invalidArguments();
      result.push(descriptor.value);
    }
    return result;
  } catch {
    invalidArguments();
  }
}

function safeRelativePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024
    || value.includes('\0') || value.includes('\\')
    || value === '.' || value === './'
    || isAbsolute(value) || win32.isAbsolute(value)) return false;
  const segments = value.split('/');
  return segments.every((segment) => segment !== '' && segment !== '..'
    && segment.length <= 255 && !/[\u0000-\u001f\u007f]/u.test(segment));
}

function safeJsonPath(value) {
  return safeRelativePath(value) && value.endsWith('.json');
}

function isInsideRoot(root, target) {
  const path = relative(root, target);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

export async function assertHoldoutScoreCliPathBoundary(options) {
  try {
    const root = await realpath(PACKAGE_ROOT);
    const cwd = await realpath(process.cwd());
    if (cwd !== root) throw new TypeError('wrong invocation root');
    for (const key of INPUT_PATH_KEYS) {
      const canonical = await realpath(resolve(cwd, options[key]));
      if (!isInsideRoot(root, canonical)) throw new TypeError('input path escaped root');
    }
    const outputParent = await realpath(dirname(resolve(cwd, options.outputPath)));
    if (!isInsideRoot(root, outputParent)) throw new TypeError('output path escaped root');
  } catch {
    throw new TypeError('invalid holdout score path boundary');
  }
}

export function parseHoldoutScoreArgs(argv) {
  const values = snapshotArgv(argv);
  if (values.length !== Object.keys(FLAGS).length * 2) invalidArguments();
  const parsed = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!Object.hasOwn(FLAGS, flag) || parsed.has(flag)) invalidArguments();
    parsed.set(flag, value);
  }
  if (Object.keys(FLAGS).some((flag) => !parsed.has(flag))) invalidArguments();
  for (const flag of [
    '--input', '--oracle', '--freeze-commitment', '--freeze-receipt',
    '--inference', '--pricing',
  ]) {
    if (!safeJsonPath(parsed.get(flag))) invalidArguments();
  }
  for (const flag of [
    '--freeze-commitment-sha256', '--freeze-receipt-sha256',
    '--inference-artifact-sha256',
  ]) {
    if (!HASH_PATTERN.test(parsed.get(flag))) invalidArguments();
  }
  if (!GIT_PATTERN.test(parsed.get('--scorer-git-sha'))) invalidArguments();
  if (!safeRelativePath(parsed.get('--output'))) invalidArguments();

  return Object.freeze({
    inputPath: parsed.get('--input'),
    oraclePath: parsed.get('--oracle'),
    freezeCommitmentPath: parsed.get('--freeze-commitment'),
    expectedFreezeCommitmentSha256: parsed.get('--freeze-commitment-sha256'),
    freezeReceiptPath: parsed.get('--freeze-receipt'),
    expectedFreezeReceiptSha256: parsed.get('--freeze-receipt-sha256'),
    inferencePath: parsed.get('--inference'),
    expectedInferenceArtifactSha256: parsed.get('--inference-artifact-sha256'),
    pricingPath: parsed.get('--pricing'),
    expectedScorerGitSha: parsed.get('--scorer-git-sha'),
    outputPath: parsed.get('--output'),
  });
}

function exactDataValues(value, expectedKeys, message, { optional = false } = {}) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) throw new TypeError(message);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
      || (!optional && keys.length !== expectedKeys.length)) throw new TypeError(message);
    const result = {};
    for (const key of expectedKeys) {
      const descriptor = descriptors[key];
      if (descriptor === undefined) {
        if (optional) continue;
        throw new TypeError(message);
      }
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError(message);
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    throw new TypeError(message);
  }
}

function snapshotOptions(value) {
  const fields = exactDataValues(value, OPTION_KEYS, 'invalid holdout score options');
  const result = {};
  for (const key of [...INPUT_PATH_KEYS, 'outputPath']) {
    if (typeof fields[key] !== 'string' || fields[key].trim() === ''
      || fields[key].includes('\0')) throw new TypeError('invalid holdout score options');
    try {
      result[key] = resolve(fields[key]);
    } catch {
      throw new TypeError('invalid holdout score options');
    }
  }
  for (const key of [
    'expectedFreezeCommitmentSha256', 'expectedFreezeReceiptSha256',
    'expectedInferenceArtifactSha256',
  ]) {
    if (typeof fields[key] !== 'string' || !HASH_PATTERN.test(fields[key])) {
      throw new TypeError('invalid holdout score options');
    }
    result[key] = fields[key];
  }
  if (typeof fields.expectedScorerGitSha !== 'string'
    || !GIT_PATTERN.test(fields.expectedScorerGitSha)) {
    throw new TypeError('invalid holdout score options');
  }
  result.expectedScorerGitSha = fields.expectedScorerGitSha;
  const inputs = INPUT_PATH_KEYS.map((key) => result[key]);
  if (new Set(inputs).size !== inputs.length || inputs.includes(result.outputPath)) {
    throw new TypeError('invalid holdout score options');
  }
  return Object.freeze(result);
}

function snapshotStringArray(value) {
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) {
      throw new TypeError('invalid holdout score dependencies');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1
      || descriptors.length?.value !== value.length) {
      throw new TypeError('invalid holdout score dependencies');
    }
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'string') {
        throw new TypeError('invalid holdout score dependencies');
      }
      result.push(descriptor.value);
    }
    return Object.freeze(result);
  } catch {
    throw new TypeError('invalid holdout score dependencies');
  }
}

function snapshotDependencies(value) {
  const fields = exactDataValues(
    value,
    DEPENDENCY_KEYS,
    'invalid holdout score dependencies',
    { optional: true },
  );
  if (fields.scorerGitSha !== undefined
    && (typeof fields.scorerGitSha !== 'string' || !GIT_PATTERN.test(fields.scorerGitSha))) {
    throw new TypeError('invalid holdout score dependencies');
  }
  return Object.freeze({
    forbiddenValues: snapshotStringArray(fields.forbiddenValues ?? []),
    scorerGitSha: fields.scorerGitSha,
  });
}

async function currentScorerGitSha() {
  try {
    const env = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (!key.toUpperCase().startsWith('GIT_')) env[key] = value;
    }
    const options = {
      cwd: PACKAGE_ROOT,
      encoding: 'utf8',
      windowsHide: true,
      env,
      maxBuffer: 4 * 1024 * 1024,
    };
    const [root, topLevel] = await Promise.all([
      realpath(PACKAGE_ROOT),
      execFile('git', ['rev-parse', '--show-toplevel'], options),
    ]);
    if (await realpath(topLevel.stdout.trim()) !== root) {
      throw new TypeError('wrong scorer repository');
    }
    const status = await execFile(
      'git',
      ['status', '--porcelain=v1', '--untracked-files=all', '--', '.'],
      options,
    );
    if (status.stdout !== '') throw new TypeError('dirty scorer revision');
    const revision = await execFile('git', ['rev-parse', 'HEAD'], options);
    const value = revision.stdout.trim();
    if (!GIT_PATTERN.test(value)) throw new TypeError('invalid scorer revision');
    return value;
  } catch {
    throw new TypeError('unable to identify clean scorer revision');
  }
}

function sanitizedGitEnvironment() {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith('GIT_')) env[key] = value;
  }
  return env;
}

async function computeAnchoredScorerSourceHash(revision) {
  try {
    return await computeScorerSourceCompositeHash(async (filename) => {
      const result = await execFile('git', ['show', `${revision}:${filename}`], {
        cwd: PACKAGE_ROOT,
        encoding: null,
        windowsHide: true,
        env: sanitizedGitEnvironment(),
        maxBuffer: 64 * 1024 * 1024,
      });
      return result.stdout;
    });
  } catch {
    throw new TypeError('unable to verify anchored scorer sources');
  }
}

function sameFileSnapshot(before, after, byteLength) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.mode === after.mode
    && before.size === after.size
    && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs
    && before.size === BigInt(byteLength);
}

async function readRegularJson(path) {
  let handle;
  try {
    handle = await open(path, READ_FLAGS);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 2n || before.size > BigInt(MAX_INPUT_BYTES)) {
      throw new TypeError('invalid holdout score input file');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (bytes.length < 2 || bytes.length > MAX_INPUT_BYTES
      || !sameFileSnapshot(before, after, bytes.length)) {
      throw new TypeError('invalid holdout score input file');
    }
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new TypeError('invalid holdout score input file');
  } finally {
    await handle?.close().catch(() => {});
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function canonicalPricing(value) {
  try {
    const canonical = canonicalStringify(value);
    const pricing = JSON.parse(canonical);
    aggregateQualification({ attempts: [], expectedRepeats: 3, pricing });
    return Object.freeze({
      pricing: deepFreeze(pricing),
      hash: 'sha256:' + createHash('sha256').update(canonical, 'utf8').digest('hex'),
    });
  } catch {
    throw new TypeError('invalid holdout score pricing');
  }
}

function canonicalHash(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

export async function runHoldoutScoreCli(options, deps = {}) {
  const fields = snapshotOptions(options);
  const dependencies = snapshotDependencies(deps);
  const scorerGitSha = dependencies.scorerGitSha ?? await currentScorerGitSha();
  if (scorerGitSha !== fields.expectedScorerGitSha) {
    throw new TypeError('holdout scorer revision mismatch');
  }
  let input;
  let oracle;
  let freezeCommitment;
  let freezeReceipt;
  let inferenceArtifact;
  let priceSnapshot;
  try {
    const values = await Promise.all([
      readRegularJson(fields.inputPath),
      readRegularJson(fields.oraclePath),
      readRegularJson(fields.freezeCommitmentPath),
      readRegularJson(fields.freezeReceiptPath),
      readRegularJson(fields.inferencePath),
      readRegularJson(fields.pricingPath),
    ]);
    input = validateHoldoutInput(values[0]);
    oracle = validateHoldoutOracle(values[1]);
    freezeCommitment = validateHoldoutFreezeCommitment(values[2]);
    freezeReceipt = validateHoldoutFreezeReceipt(values[3]);
    inferenceArtifact = validateHoldoutInferenceArtifact(values[4]);
    priceSnapshot = canonicalPricing(values[5]);
  } catch {
    throw new TypeError('invalid holdout score input');
  }

  if (inferenceArtifact.manifest.pricing_sha256 !== priceSnapshot.hash) {
    throw new TypeError('holdout score pricing does not match inference manifest');
  }
  const inputSha256 = holdoutInputHash(input);
  const freezeCommitmentSha256 = holdoutFreezeCommitmentHash(freezeCommitment);
  const freezeReceiptSha256 = holdoutFreezeReceiptHash(freezeReceipt);
  if (freezeCommitmentSha256 !== fields.expectedFreezeCommitmentSha256
    || freezeReceiptSha256 !== fields.expectedFreezeReceiptSha256
    || inferenceArtifact.artifact_sha256 !== fields.expectedInferenceArtifactSha256
    || freezeCommitment.holdout_id !== input.holdout_id
    || freezeCommitment.input_sha256 !== inputSha256
    || freezeCommitment.oracle_sha256 !== holdoutOracleHash(oracle)
    || freezeReceipt.holdout_id !== input.holdout_id
    || freezeReceipt.input_sha256 !== inputSha256
    || freezeReceipt.commitment_sha256 !== freezeCommitmentSha256
    || freezeReceipt.partition_name !== freezeCommitment.partition_name
    || freezeReceipt.partition_audit_sha256 !== freezeCommitment.partition_audit_sha256
    || freezeCommitment.cases !== input.cases.length) {
    throw new TypeError('holdout score commitment mismatch');
  }

  let scored;
  let files;
  let attestationHash;
  let resultSetHash;
  try {
    scored = scoreHoldout({
      input,
      oracle,
      inferenceArtifact,
      pricing: priceSnapshot.pricing,
    });
    const scorerSourceSha256 = await computeScorerSourceCompositeHash();
    if (dependencies.scorerGitSha === undefined
      && scorerSourceSha256 !== await computeAnchoredScorerSourceHash(scorerGitSha)) {
      throw new TypeError('scorer sources do not match anchored revision');
    }
    const artifacts = buildHoldoutScoreArtifacts({
      holdoutId: input.holdout_id,
      inputSha256: inferenceArtifact.input_sha256,
      freezeCommitmentSha256,
      freezeReceiptSha256,
      partitionAuditSha256: freezeCommitment.partition_audit_sha256,
      oracleSha256: canonicalHash(oracle),
      inferenceArtifactSha256: canonicalHash(inferenceArtifact),
      inferencePayloadSha256: inferenceArtifact.artifact_sha256,
      manifest: inferenceArtifact.manifest,
      attempts: scored.attempts,
      summary: scored.summary,
      pricing: priceSnapshot.pricing,
      caseOutcomes: scored.caseOutcomes,
      familyOutcomes: scored.familyOutcomes,
      repeats: inferenceArtifact.repeats,
      concurrency: inferenceArtifact.concurrency,
      scorerGitSha,
      scorerSourceSha256,
      forbiddenValues: dependencies.forbiddenValues,
    });
    files = artifacts.files;
    attestationHash = artifacts.attestationHash;
    resultSetHash = artifacts.resultSetHash;
  } catch (error) {
    if (error instanceof TypeError && error.message === 'artifact contains forbidden value') {
      throw error;
    }
    throw new TypeError('invalid holdout score input');
  }

  await publishArtifacts({
    outputDir: fields.outputPath,
    files,
    forbiddenValues: dependencies.forbiddenValues,
  });
  return Object.freeze({
    schema_version: 'judge-holdout-score-publication.v1',
    holdout_id: input.holdout_id,
    input_sha256: inputSha256,
    partition_audit_sha256: freezeCommitment.partition_audit_sha256,
    freeze_commitment_sha256: freezeCommitmentSha256,
    freeze_receipt_sha256: freezeReceiptSha256,
    inference_payload_sha256: inferenceArtifact.artifact_sha256,
    manifest_hash: inferenceArtifact.manifest.manifest_hash,
    scorer_git_sha: scorerGitSha,
    score_attestation_sha256: attestationHash,
    result_set_sha256: resultSetHash,
  });
}

export async function main() {
  try {
    const options = parseHoldoutScoreArgs(process.argv.slice(2));
    await assertHoldoutScoreCliPathBoundary(options);
    const result = await runHoldoutScoreCli(options, {});
    process.stdout.write(canonicalStringify(result) + '\n');
    return result;
  } catch {
    process.stderr.write('holdout scoring failed\n');
    process.exitCode = 1;
    return null;
  }
}
