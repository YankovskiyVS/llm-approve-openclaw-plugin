import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve, win32 } from 'node:path';
import { promisify, types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { JUDGE_TIMEOUT_MS, MODEL_ID, POLICY_VERSION } from '../../src/constants.js';
import { createJudgeClient } from '../../src/judge-client.js';
import { aggregateQualification } from './aggregate.mjs';
import { buildArtifactFiles, publishArtifacts } from './artifacts.mjs';
import { corpusHash, lintCorpus } from './corpus.mjs';
import { buildManifest } from './manifest.mjs';
import { runQualification } from './runner.mjs';

const INVALID_ARGUMENTS = 'invalid benchmark arguments';
const FLAG_NAMES = Object.freeze({
  '--corpus': 'corpusPath',
  '--pricing': 'pricingPath',
  '--output': 'outputPath',
  '--repeats': 'repeats',
  '--concurrency': 'concurrency',
  '--openclaw-version': 'openclawVersion',
});
const REQUIRED_FLAGS = Object.freeze(['--corpus', '--pricing', '--output']);
const OPTION_KEYS = Object.freeze([
  'corpusPath', 'pricingPath', 'outputPath', 'repeats', 'concurrency',
  'openclawVersion', 'resumeFrom',
]);
const DEPENDENCY_KEYS = new Set([
  'reviewer', 'gitSha', 'gitExecutor', 'nodeVersion', 'sourceHashes', 'forbiddenValues',
]);
const SOURCE_KEYS = Object.freeze([
  'action', 'prompt', 'decision', 'redaction', 'constants', 'judge_client', 'harness',
]);
const SOURCE_URLS = Object.freeze({
  action: new URL('../../src/action.js', import.meta.url),
  prompt: new URL('../../src/prompt.js', import.meta.url),
  decision: new URL('../../src/decision.js', import.meta.url),
  redaction: new URL('../../src/redact.js', import.meta.url),
  constants: new URL('../../src/constants.js', import.meta.url),
  judge_client: new URL('../../src/judge-client.js', import.meta.url),
});
const HARNESS_SOURCE_NAMES = Object.freeze([
  'case-schema.mjs',
  'corpus.mjs',
  'case-input.mjs',
  'manifest.mjs',
  'attempt.mjs',
  'runner.mjs',
  'wilson.mjs',
  'aggregate.mjs',
  'render.mjs',
  'artifacts.mjs',
  'cli.mjs',
]);
const HARNESS_HASH_DOMAIN = 'openclaw-llm-action-judge:harness-source:v1';
const ENDPOINT_ORIGIN = 'https://foundation-models.api.cloud.ru';
const CLOUDRU_BASE_URL = `${ENDPOINT_ORIGIN}/v1`;
const PRODUCTION_PROFILE = Object.freeze({
  name: 'production',
  temperature: 0,
  max_tokens: 256,
  thinking: false,
  response_format: 'json_object',
  timeout_ms: JUDGE_TIMEOUT_MS,
});
const execFile = promisify(execFileCallback);

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

function nonBlank(value) {
  return typeof value === 'string' && value.trim() !== '' && !value.includes('\0');
}

function boundedInteger(value, minimum, maximum) {
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) invalidArguments();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    invalidArguments();
  }
  return parsed;
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
    if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
      throw new TypeError(message);
    }
    const result = {};
    for (const key of required) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError(message);
      }
      result[key] = descriptor.value;
    }
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

function snapshotOptions(value) {
  const fields = exactDataValues(value, OPTION_KEYS, 'invalid benchmark options');
  for (const key of ['corpusPath', 'pricingPath', 'outputPath', 'openclawVersion']) {
    if (!nonBlank(fields[key])) throw new TypeError('invalid benchmark options');
  }
  if (!Number.isInteger(fields.repeats) || fields.repeats < 1 || fields.repeats > 10
    || !Number.isInteger(fields.concurrency)
    || fields.concurrency < 1 || fields.concurrency > 32) {
    throw new TypeError('invalid benchmark options');
  }
  if (fields.resumeFrom !== null) throw new TypeError('external benchmark resume is disabled');
  return Object.freeze(fields);
}

function snapshotSourceHashes(value) {
  if (value === undefined) return undefined;
  return Object.freeze(exactDataValues(value, SOURCE_KEYS, 'invalid benchmark dependencies'));
}

function snapshotForbiddenValues(value) {
  if (value === undefined) return Object.freeze([]);
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) {
      throw new TypeError('invalid benchmark dependencies');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1
      || descriptors.length?.value !== value.length) {
      throw new TypeError('invalid benchmark dependencies');
    }
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError('invalid benchmark dependencies');
      }
      result.push(descriptor.value);
    }
    return Object.freeze(result);
  } catch {
    throw new TypeError('invalid benchmark dependencies');
  }
}

function snapshotDependencies(value) {
  const fields = dataValues(
    value,
    DEPENDENCY_KEYS,
    ['reviewer'],
    'invalid benchmark dependencies',
  );
  return Object.freeze({
    reviewer: fields.reviewer,
    gitSha: fields.gitSha,
    gitExecutor: fields.gitExecutor,
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

async function readJson(path) {
  try {
    const content = await readFile(path, 'utf8');
    return JSON.parse(content);
  } catch {
    throw new TypeError('invalid benchmark input');
  }
}

function snapshotPricing(value) {
  try {
    const canonical = canonicalStringify(value);
    const pricing = deepFreeze(JSON.parse(canonical));
    aggregateQualification({ attempts: [], expectedRepeats: 3, pricing });
    return { pricing, hash: sha256(canonical) };
  } catch {
    throw new TypeError('invalid benchmark input');
  }
}

async function assertFreshOutput(outputPath) {
  let output;
  try {
    output = resolve(outputPath);
  } catch {
    throw new TypeError('invalid benchmark output');
  }
  try {
    await lstat(output);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw new TypeError('invalid benchmark output');
    let parent;
    try {
      parent = await lstat(dirname(output));
    } catch {
      throw new TypeError('invalid benchmark output parent');
    }
    if (!parent.isDirectory() || parent.isSymbolicLink()) {
      throw new TypeError('invalid benchmark output parent');
    }
    return;
  }
  throw new TypeError('benchmark output already exists');
}

async function currentGitSha(gitExecutor = execFile) {
  try {
    const packageRoot = new URL('../..', import.meta.url);
    const options = {
      cwd: packageRoot,
      encoding: 'utf8',
      windowsHide: true,
    };
    const status = await gitExecutor(
      'git',
      ['status', '--porcelain=v1', '--untracked-files=all', '--', '.'],
      options,
    );
    if (status.stdout !== '') throw new TypeError('dirty package tree');
    const { stdout } = await gitExecutor('git', ['rev-parse', 'HEAD'], options);
    const sha = stdout.trim();
    if (!/^[0-9a-f]{40}$/u.test(sha)) throw new TypeError('invalid git sha');
    return sha;
  } catch {
    throw new TypeError('unable to identify benchmark sources');
  }
}

async function hashProductionSources() {
  try {
    const directKeys = SOURCE_KEYS.slice(0, -1);
    const entries = await Promise.all(directKeys.map(async (key) => [
      key,
      sha256(await readFile(SOURCE_URLS[key])),
    ]));
    const files = await Promise.all(HARNESS_SOURCE_NAMES.map(async (name) => ({
      filename: `evals/lib/${name}`,
      sha256: sha256(await readFile(new URL(`./${name}`, import.meta.url))),
    })));
    entries.push(['harness', sha256(canonicalStringify({
      domain: HARNESS_HASH_DOMAIN,
      files,
    }))]);
    return Object.freeze(Object.fromEntries(entries));
  } catch {
    throw new TypeError('unable to identify benchmark sources');
  }
}

export function parseCliArgs(argv) {
  const values = snapshotArgv(argv);
  const parsed = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!Object.hasOwn(FLAG_NAMES, flag) || parsed.has(flag) || !nonBlank(value)
      || value.startsWith('--')) invalidArguments();
    parsed.set(flag, value);
  }
  if (REQUIRED_FLAGS.some((flag) => !parsed.has(flag))) invalidArguments();

  const outputPath = parsed.get('--output');
  if (isAbsolute(outputPath) || win32.isAbsolute(outputPath)) invalidArguments();

  return {
    corpusPath: parsed.get('--corpus'),
    pricingPath: parsed.get('--pricing'),
    outputPath,
    repeats: parsed.has('--repeats')
      ? boundedInteger(parsed.get('--repeats'), 1, 10)
      : 3,
    concurrency: parsed.has('--concurrency')
      ? boundedInteger(parsed.get('--concurrency'), 1, 32)
      : 4,
    openclawVersion: parsed.get('--openclaw-version') ?? '2026.6.11',
    resumeFrom: null,
  };
}

export async function runCli(options, deps) {
  const fields = snapshotOptions(options);
  const dependencies = snapshotDependencies(deps);
  if (fields.repeats !== 3 || fields.concurrency !== 4) {
    throw new TypeError('unsupported benchmark profile');
  }
  await assertFreshOutput(fields.outputPath);

  let cases;
  let pricingSnapshot;
  try {
    const [corpusValue, pricingValue] = await Promise.all([
      readJson(fields.corpusPath),
      readJson(fields.pricingPath),
    ]);
    cases = lintCorpus(corpusValue);
    pricingSnapshot = snapshotPricing(pricingValue);
  } catch {
    throw new TypeError('invalid benchmark input');
  }

  const [gitSha, sourceHashes] = await Promise.all([
    dependencies.gitSha === undefined
      ? currentGitSha(dependencies.gitExecutor)
      : dependencies.gitSha,
    dependencies.sourceHashes === undefined
      ? hashProductionSources()
      : dependencies.sourceHashes,
  ]);
  const nodeVersion = dependencies.nodeVersion ?? process.version;
  let manifest;
  try {
    manifest = buildManifest({
      schema_version: 'judge-benchmark.v2',
      git_sha: gitSha,
      node_version: nodeVersion,
      openclaw_version: fields.openclawVersion,
      model_id: MODEL_ID,
      policy_version: POLICY_VERSION,
      corpus_sha256: corpusHash(cases),
      pricing_sha256: pricingSnapshot.hash,
      source_sha256: sourceHashes,
      endpoint_origin: ENDPOINT_ORIGIN,
      profile: PRODUCTION_PROFILE,
    });
  } catch {
    throw new TypeError('invalid benchmark manifest');
  }

  const attempts = await runQualification({
    reviewer: dependencies.reviewer,
    cases,
    manifest,
    repeats: fields.repeats,
    concurrency: fields.concurrency,
  });
  const aggregate = aggregateQualification({
    attempts,
    expectedRepeats: fields.repeats,
    pricing: pricingSnapshot.pricing,
  });
  const files = buildArtifactFiles({
    manifest,
    attempts,
    summary: aggregate.summary,
    pricing: pricingSnapshot.pricing,
    caseOutcomes: aggregate.caseOutcomes,
    familyOutcomes: aggregate.familyOutcomes,
    forbiddenValues: dependencies.forbiddenValues,
  });
  await publishArtifacts({
    outputDir: fields.outputPath,
    files,
    forbiddenValues: dependencies.forbiddenValues,
  });
  return Object.freeze({
    outputDir: fields.outputPath,
    summary: aggregate.summary,
  });
}

export async function main() {
  try {
    const options = parseCliArgs(process.argv.slice(2));
    const apiKey = process.env.LLM_API_KEY;
    const reviewer = createJudgeClient({
      providerConfig: {
        baseUrl: CLOUDRU_BASE_URL,
        apiKey,
      },
    });
    const result = await runCli(options, {
      reviewer,
      forbiddenValues: [apiKey],
    });
    process.stdout.write(canonicalStringify(result) + '\n');
    return result;
  } catch {
    process.stderr.write('judge benchmark failed\n');
    process.exitCode = 1;
    return null;
  }
}
