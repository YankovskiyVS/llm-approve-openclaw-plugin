import { execFile as execFileCallback } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  link,
  lstat,
  open,
  readFile,
  realpath,
  rm,
} from 'node:fs/promises';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
  win32,
} from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify, types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import {
  CLOUDRU_BASE_URL,
  JUDGE_TIMEOUT_MS,
  MODEL_ID,
  POLICY_VERSION,
} from '../../src/constants.js';
import { createJudgeClient } from '../../src/judge-client.js';
import { aggregateQualification } from './aggregate.mjs';
import {
  holdoutInputHash,
  validateHoldoutInput,
} from './holdout-contracts.mjs';
import {
  holdoutFreezeReceiptHash,
  validateHoldoutFreezeReceipt,
} from './holdout-commitments.mjs';
import {
  buildHoldoutInferenceArtifact,
  runHoldoutInference,
  validateHoldoutInferenceArtifact,
} from './holdout-runner.mjs';
import { buildManifest } from './manifest.mjs';

const execFile = promisify(execFileCallback);
const PACKAGE_ROOT = new URL('../..', import.meta.url);
const PACKAGE_ROOT_PATH = resolve(fileURLToPath(PACKAGE_ROOT));
const ENDPOINT_ORIGIN = 'https://foundation-models.api.cloud.ru';
const TARGET_OPENCLAW_CONTRACT_VERSION = '2026.6.11';
const INPUT_LIMIT_BYTES = 16 * 1024 * 1024;
const INVALID_ARGUMENTS = 'invalid holdout inference arguments';
const FILE_READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
const FILE_WRITE_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0);

const FLAG_NAMES = Object.freeze({
  '--input': 'inputPath',
  '--freeze-receipt': 'freezeReceiptPath',
  '--freeze-receipt-sha256': 'expectedFreezeReceiptSha256',
  '--pricing': 'pricingPath',
  '--output': 'outputPath',
  '--repeats': 'repeats',
  '--concurrency': 'concurrency',
});
const REQUIRED_FLAGS = Object.freeze([
  '--input', '--freeze-receipt', '--freeze-receipt-sha256', '--pricing', '--output',
]);
const PATH_FLAGS = Object.freeze([
  '--input', '--freeze-receipt', '--pricing', '--output',
]);
const OPTION_KEYS = Object.freeze([
  'inputPath', 'freezeReceiptPath', 'expectedFreezeReceiptSha256',
  'pricingPath', 'outputPath', 'repeats', 'concurrency',
]);
const DEPENDENCY_KEYS = new Set([
  'apiKey', 'fetchImpl', 'gitSha', 'nodeVersion', 'sourceHashes', 'forbiddenValues',
]);
const SOURCE_KEYS = Object.freeze([
  'action', 'prompt', 'decision', 'redaction', 'constants', 'judge_client',
  'judge_schema', 'verdict_schema', 'harness',
]);
const SOURCE_URLS = Object.freeze({
  action: new URL('../../src/action.js', import.meta.url),
  prompt: new URL('../../src/prompt.js', import.meta.url),
  decision: new URL('../../src/decision.js', import.meta.url),
  redaction: new URL('../../src/redact.js', import.meta.url),
  constants: new URL('../../src/constants.js', import.meta.url),
  judge_client: new URL('../../src/judge-client.js', import.meta.url),
  judge_schema: new URL('../../src/judge-schema.js', import.meta.url),
  verdict_schema: new URL('../../schemas/judge-verdict.schema.json', import.meta.url),
});
const INFERENCE_SOURCE_DEPENDENCIES = Object.freeze([
  ['src/plugin.js', new URL('../../src/plugin.js', import.meta.url)],
  ['lib/case-schema.mjs', new URL('./case-schema.mjs', import.meta.url)],
  ['lib/corpus.mjs', new URL('./corpus.mjs', import.meta.url)],
  ['lib/case-input.mjs', new URL('./case-input.mjs', import.meta.url)],
  ['lib/manifest.mjs', new URL('./manifest.mjs', import.meta.url)],
  ['lib/attempt.mjs', new URL('./attempt.mjs', import.meta.url)],
  ['lib/wilson.mjs', new URL('./wilson.mjs', import.meta.url)],
  ['lib/aggregate.mjs', new URL('./aggregate.mjs', import.meta.url)],
  ['lib/holdout-contracts.mjs', new URL('./holdout-contracts.mjs', import.meta.url)],
  ['lib/holdout-commitments.mjs', new URL('./holdout-commitments.mjs', import.meta.url)],
  ['lib/holdout-runner.mjs', new URL('./holdout-runner.mjs', import.meta.url)],
  ['lib/holdout-infer-cli.mjs', new URL('./holdout-infer-cli.mjs', import.meta.url)],
  ['holdout-infer.mjs', new URL('../holdout-infer.mjs', import.meta.url)],
]);
const PRODUCTION_PROFILE = Object.freeze({
  name: 'production',
  temperature: 0,
  max_tokens: 256,
  thinking: false,
  response_format: 'json_schema',
  timeout_ms: JUDGE_TIMEOUT_MS,
});

function invalidArguments() {
  throw new TypeError(INVALID_ARGUMENTS);
}

function exactDataValues(value, expected, message) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) throw new TypeError(message);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) {
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

function dataValues(value, allowed, required, message) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) throw new TypeError(message);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))
      || required.some((key) => !Object.hasOwn(descriptors, key))) {
      throw new TypeError(message);
    }
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
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

function denseArrayValues(value, message) {
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const length = descriptors.length?.value;
    if (!Number.isSafeInteger(length) || length < 0
      || Reflect.ownKeys(descriptors).length !== length + 1) throw new TypeError(message);
    const result = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError(message);
      }
      result.push(descriptor.value);
    }
    return result;
  } catch {
    throw new TypeError(message);
  }
}

function snapshotArgv(value) {
  try {
    return denseArrayValues(value, INVALID_ARGUMENTS).map((entry) => {
      if (typeof entry !== 'string') invalidArguments();
      return entry;
    });
  } catch {
    invalidArguments();
  }
}

function safeRelativeJsonPath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024
    || value.trim() === '' || value.includes('\0')
    || isAbsolute(value) || win32.isAbsolute(value)) return false;
  const segments = value.split(/[\\/]/u);
  if (segments.length === 0 || segments.some((segment) => segment === '' || segment === '..')) {
    return false;
  }
  return segments.at(-1).endsWith('.json');
}

function isInsideRoot(root, path) {
  const relativePath = relative(root, path);
  return relativePath === ''
    || (relativePath !== '..'
      && !relativePath.startsWith(`..${sep}`)
      && !isAbsolute(relativePath));
}

function resolvePackagePath(path) {
  const absolute = resolve(PACKAGE_ROOT_PATH, path);
  if (!isInsideRoot(PACKAGE_ROOT_PATH, absolute)) throw new TypeError('invalid path');
  return absolute;
}

async function assertCanonicalInsidePackageRoot(path) {
  const [canonicalRoot, canonicalPath] = await Promise.all([
    realpath(PACKAGE_ROOT_PATH),
    realpath(path),
  ]);
  if (canonicalPath !== path || !isInsideRoot(canonicalRoot, canonicalPath)) {
    throw new TypeError('invalid path');
  }
}

function boundedInteger(value, minimum, maximum) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value)) invalidArguments();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) invalidArguments();
  return parsed;
}

function snapshotOptions(value) {
  const fields = exactDataValues(value, OPTION_KEYS, 'invalid holdout inference options');
  if (!safeRelativeJsonPath(fields.inputPath)
    || !safeRelativeJsonPath(fields.freezeReceiptPath)
    || typeof fields.expectedFreezeReceiptSha256 !== 'string'
    || !/^sha256:[0-9a-f]{64}$/u.test(fields.expectedFreezeReceiptSha256)
    || !safeRelativeJsonPath(fields.pricingPath)
    || !safeRelativeJsonPath(fields.outputPath)
    || !Number.isInteger(fields.repeats) || fields.repeats < 1 || fields.repeats > 10
    || !Number.isInteger(fields.concurrency) || fields.concurrency < 1
    || fields.concurrency > 32) {
    throw new TypeError('invalid holdout inference options');
  }
  return Object.freeze(fields);
}

function snapshotSourceHashes(value) {
  if (value === undefined) return undefined;
  return Object.freeze(exactDataValues(
    value,
    SOURCE_KEYS,
    'invalid holdout inference dependencies',
  ));
}

function snapshotForbiddenValues(value) {
  if (value === undefined) return Object.freeze([]);
  const entries = denseArrayValues(value, 'invalid holdout inference dependencies');
  if (entries.some((entry) => typeof entry !== 'string')) {
    throw new TypeError('invalid holdout inference dependencies');
  }
  return Object.freeze(entries.filter((entry) => entry !== ''));
}

function snapshotDependencies(value) {
  const fields = dataValues(
    value,
    DEPENDENCY_KEYS,
    ['apiKey'],
    'invalid holdout inference dependencies',
  );
  if (typeof fields.apiKey !== 'string' || fields.apiKey.trim() === '') {
    throw new TypeError('invalid holdout inference dependencies');
  }
  if (fields.fetchImpl !== undefined && typeof fields.fetchImpl !== 'function') {
    throw new TypeError('invalid holdout inference dependencies');
  }
  return Object.freeze({
    apiKey: fields.apiKey,
    fetchImpl: fields.fetchImpl,
    gitSha: fields.gitSha,
    nodeVersion: fields.nodeVersion,
    sourceHashes: snapshotSourceHashes(fields.sourceHashes),
    forbiddenValues: snapshotForbiddenValues(fields.forbiddenValues),
  });
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function sha256(value) {
  return 'sha256:' + createHash('sha256').update(value).digest('hex');
}

function snapshotPricing(value) {
  try {
    const canonical = canonicalStringify(value);
    const pricing = deepFreeze(JSON.parse(canonical));
    aggregateQualification({ attempts: [], expectedRepeats: 3, pricing });
    return Object.freeze({ pricing, hash: sha256(canonical) });
  } catch {
    throw new TypeError('invalid holdout inference pricing');
  }
}

async function readRegularJson(path) {
  let handle;
  try {
    const absolute = resolvePackagePath(path);
    await assertCanonicalInsidePackageRoot(absolute);
    handle = await open(absolute, FILE_READ_FLAGS);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 2n || before.size > BigInt(INPUT_LIMIT_BYTES)) {
      throw new TypeError('invalid file');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (bytes.length < 2 || bytes.length > INPUT_LIMIT_BYTES
      || before.dev !== after.dev || before.ino !== after.ino
      || before.mode !== after.mode || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
      || bytes.length !== Number(after.size)) throw new TypeError('invalid file');
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new TypeError('invalid holdout inference input file');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function assertFreshOutput(path) {
  const absolute = resolvePackagePath(path);
  const parent = dirname(absolute);
  try {
    await assertCanonicalInsidePackageRoot(parent);
    const parentStats = await lstat(parent);
    if (!parentStats.isDirectory() || parentStats.isSymbolicLink()
      || await realpath(parent) !== parent) {
      throw new TypeError('invalid parent');
    }
    const outputStats = await lstat(absolute).catch((error) => {
      if (error?.code === 'ENOENT') return null;
      throw error;
    });
    if (outputStats !== null) throw new TypeError('exists');
    return absolute;
  } catch {
    throw new TypeError('invalid holdout inference output');
  }
}

function assertForbiddenValuesAbsent(content, values) {
  for (const value of values) {
    const escaped = JSON.stringify(value).slice(1, -1);
    if (content.includes(value) || content.includes(escaped)) {
      throw new TypeError('holdout inference artifact contains forbidden value');
    }
  }
}

export async function publishHoldoutInferenceArtifact(
  path,
  artifact,
  forbiddenValues,
  removeTemporary = rm,
) {
  const validated = validateHoldoutInferenceArtifact(artifact);
  const content = canonicalStringify(validated) + '\n';
  assertForbiddenValuesAbsent(content, forbiddenValues);
  const output = await assertFreshOutput(path);
  const temporary = join(dirname(output), `.${basename(output)}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, FILE_WRITE_FLAGS, 0o600);
    await handle.chmod(0o600);
    await handle.writeFile(content, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(temporary, output);
  } catch {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw new TypeError('holdout inference publication failed');
  }
  try {
    await removeTemporary(temporary, { force: true });
  } catch {
    // The no-clobber hard link is already committed; temporary cleanup is best-effort.
  }
}

async function currentGitSha() {
  try {
    const options = { cwd: PACKAGE_ROOT, encoding: 'utf8', windowsHide: true };
    const status = await execFile(
      'git',
      ['status', '--porcelain=v1', '--untracked-files=all', '--', '.'],
      options,
    );
    if (status.stdout !== '') throw new TypeError('dirty package');
    const revision = await execFile('git', ['rev-parse', 'HEAD'], options);
    const value = revision.stdout.trim();
    if (!/^[0-9a-f]{40}$/u.test(value)) throw new TypeError('invalid revision');
    return value;
  } catch {
    throw new TypeError('unable to identify holdout inference revision');
  }
}

export async function computeHoldoutInferenceSourceHashes(readSource = readFile) {
  try {
    const entries = await Promise.all(Object.entries(SOURCE_URLS).map(async ([key, url]) => [
      key,
      sha256(await readSource(url)),
    ]));
    const files = await Promise.all(INFERENCE_SOURCE_DEPENDENCIES.map(async ([filename, url]) => ({
      filename,
      sha256: sha256(await readSource(url)),
    })));
    entries.push(['harness', sha256(canonicalStringify({
      domain: 'openclaw-llm-action-judge:holdout-inference-source:v1',
      files,
    }))]);
    return Object.freeze(Object.fromEntries(entries));
  } catch {
    throw new TypeError('unable to identify holdout inference sources');
  }
}

export function parseHoldoutInferArgs(argv) {
  const values = snapshotArgv(argv);
  const parsed = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!Object.hasOwn(FLAG_NAMES, flag) || parsed.has(flag)
      || typeof value !== 'string' || value === '' || value.startsWith('--')) {
      invalidArguments();
    }
    parsed.set(flag, value);
  }
  if (REQUIRED_FLAGS.some((flag) => !parsed.has(flag))) invalidArguments();
  for (const flag of PATH_FLAGS) {
    if (!safeRelativeJsonPath(parsed.get(flag))) invalidArguments();
  }
  if (!/^sha256:[0-9a-f]{64}$/u.test(parsed.get('--freeze-receipt-sha256'))) {
    invalidArguments();
  }

  return {
    inputPath: parsed.get('--input'),
    freezeReceiptPath: parsed.get('--freeze-receipt'),
    expectedFreezeReceiptSha256: parsed.get('--freeze-receipt-sha256'),
    pricingPath: parsed.get('--pricing'),
    outputPath: parsed.get('--output'),
    repeats: parsed.has('--repeats')
      ? boundedInteger(parsed.get('--repeats'), 1, 10)
      : 3,
    concurrency: parsed.has('--concurrency')
      ? boundedInteger(parsed.get('--concurrency'), 1, 32)
      : 2,
  };
}

export async function runHoldoutInferCli(options, deps) {
  const fields = snapshotOptions(options);
  const dependencies = snapshotDependencies(deps);
  await assertFreshOutput(fields.outputPath);

  let input;
  let freezeReceipt;
  let pricingSnapshot;
  try {
    const [inputValue, freezeReceiptValue, pricingValue] = await Promise.all([
      readRegularJson(fields.inputPath),
      readRegularJson(fields.freezeReceiptPath),
      readRegularJson(fields.pricingPath),
    ]);
    input = validateHoldoutInput(inputValue);
    freezeReceipt = validateHoldoutFreezeReceipt(freezeReceiptValue);
    pricingSnapshot = snapshotPricing(pricingValue);
  } catch {
    throw new TypeError('invalid holdout inference inputs');
  }

  const inputSha256 = holdoutInputHash(input);
  if (holdoutFreezeReceiptHash(freezeReceipt) !== fields.expectedFreezeReceiptSha256
    || freezeReceipt.holdout_id !== input.holdout_id
    || freezeReceipt.input_sha256 !== inputSha256) {
    throw new TypeError('holdout inference freeze receipt mismatch');
  }

  const [gitSha, sourceHashes] = await Promise.all([
    dependencies.gitSha === undefined ? currentGitSha() : dependencies.gitSha,
    dependencies.sourceHashes === undefined
      ? computeHoldoutInferenceSourceHashes()
      : dependencies.sourceHashes,
  ]);

  let manifest;
  try {
    manifest = buildManifest({
      schema_version: 'judge-benchmark.v2',
      git_sha: gitSha,
      node_version: dependencies.nodeVersion ?? process.version,
      openclaw_version: TARGET_OPENCLAW_CONTRACT_VERSION,
      model_id: MODEL_ID,
      policy_version: POLICY_VERSION,
      corpus_sha256: inputSha256,
      pricing_sha256: pricingSnapshot.hash,
      source_sha256: sourceHashes,
      endpoint_origin: ENDPOINT_ORIGIN,
      profile: PRODUCTION_PROFILE,
    });
  } catch {
    throw new TypeError('invalid holdout inference manifest');
  }

  const reviewer = createJudgeClient({
    providerConfig: {
      baseUrl: CLOUDRU_BASE_URL,
      apiKey: dependencies.apiKey,
    },
    fetchImpl: dependencies.fetchImpl,
    timeoutMs: JUDGE_TIMEOUT_MS,
  });

  const attempts = await runHoldoutInference({
    reviewer,
    input,
    manifest,
    repeats: fields.repeats,
    concurrency: fields.concurrency,
  });
  const artifact = buildHoldoutInferenceArtifact({
    input,
    manifest,
    repeats: fields.repeats,
    concurrency: fields.concurrency,
    attempts,
  });
  await publishHoldoutInferenceArtifact(
    fields.outputPath,
    artifact,
    [dependencies.apiKey, ...dependencies.forbiddenValues],
  );
  return artifact;
}

export async function main() {
  try {
    const options = parseHoldoutInferArgs(process.argv.slice(2));
    const apiKey = process.env.LLM_API_KEY;
    if (typeof apiKey !== 'string' || apiKey.trim() === '') {
      throw new TypeError('missing judge API key');
    }
    const artifact = await runHoldoutInferCli(options, {
      apiKey,
      forbiddenValues: [],
    });
    process.stdout.write(canonicalStringify({
      ok: true,
      freeze_receipt_sha256: options.expectedFreezeReceiptSha256,
      artifact_sha256: artifact.artifact_sha256,
    }) + '\n');
    return artifact;
  } catch {
    process.stderr.write('holdout inference failed\n');
    process.exitCode = 1;
    return null;
  }
}
