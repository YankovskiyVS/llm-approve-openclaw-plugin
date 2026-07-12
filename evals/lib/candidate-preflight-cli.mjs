import { execFile as execFileCallback } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  readFile,
  link,
  rm,
} from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve, win32 } from 'node:path';
import { promisify, types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { CANDIDATE_PLAN_URL } from './candidate-plan.mjs';
import { runCandidatePreflight } from './candidate-preflight.mjs';

const execFile = promisify(execFileCallback);
const PACKAGE_ROOT = new URL('../..', import.meta.url);
const PREFLIGHT_CORPUS_URL = new URL(
  '../corpus-v2/frozen/model-selection-preflight.json',
  import.meta.url,
);
const PROVIDERS = Object.freeze({
  'cloudru-fm': Object.freeze({
    configId: 'cloudru',
    baseUrl: 'https://foundation-models.api.cloud.ru/v1',
    host: 'foundation-models.api.cloud.ru',
  }),
  'qwen-vllm': Object.freeze({
    configId: 'qwen36-fp8',
    baseUrl: 'https://45a768cf-dd2c-4d96-9a98-7e24ce4866e5.modelrun.inference.cloud.ru/v1',
    host: '45a768cf-dd2c-4d96-9a98-7e24ce4866e5.modelrun.inference.cloud.ru',
  }),
});
const SOURCE_URLS = Object.freeze({
  action: new URL('../../src/action.js', import.meta.url),
  prompt: new URL('../../src/prompt.js', import.meta.url),
  decision: new URL('../../src/decision.js', import.meta.url),
  redaction: new URL('../../src/redact.js', import.meta.url),
  constants: new URL('../../src/constants.js', import.meta.url),
  candidate_plan: new URL('./candidate-plan.mjs', import.meta.url),
  candidate_client: new URL('./candidate-client.mjs', import.meta.url),
  candidate_response: new URL('./candidate-response.mjs', import.meta.url),
  case_input: new URL('./case-input.mjs', import.meta.url),
  case_schema: new URL('./case-schema.mjs', import.meta.url),
  corpus: new URL('./corpus.mjs', import.meta.url),
});
const PREFLIGHT_SOURCE_URLS = Object.freeze([
  new URL('./candidate-preflight.mjs', import.meta.url),
  new URL('./candidate-preflight-cli.mjs', import.meta.url),
  new URL('../candidate-preflight.mjs', import.meta.url),
]);
const FILE_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0);

function invalidArguments() {
  throw new TypeError('invalid candidate preflight arguments');
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

function snapshotArgv(value) {
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) invalidArguments();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1) invalidArguments();
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
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/u.test(value)
    && value.trim() !== '' && !value.includes('\0')
    && !isAbsolute(value) && !win32.isAbsolute(value)
    && !value.split(/[\\/]/u).includes('..')
    && value === basename(value);
}

export function parseCandidatePreflightArgs(argv) {
  const values = snapshotArgv(argv);
  if (values.length !== 2 || values[0] !== '--output' || !safeRelativePath(values[1])) {
    invalidArguments();
  }
  return { outputPath: values[1] };
}

function hashBytes(value) {
  return 'sha256:' + createHash('sha256').update(value).digest('hex');
}

async function sourceHashes() {
  try {
    const entries = await Promise.all(Object.entries(SOURCE_URLS).map(async ([key, url]) => [
      key,
      hashBytes(await readFile(url)),
    ]));
    const files = await Promise.all(PREFLIGHT_SOURCE_URLS.map(async (url) => ({
      filename: url.pathname.split('/').slice(-2).join('/'),
      sha256: hashBytes(await readFile(url)),
    })));
    entries.push(['preflight', hashBytes(canonicalStringify({
      domain: 'openclaw-llm-action-judge:candidate-preflight-source:v1',
      files,
    }))]);
    return Object.freeze(Object.fromEntries(entries));
  } catch {
    throw new TypeError('unable to identify candidate preflight sources');
  }
}

async function cleanGitSha() {
  try {
    const options = { cwd: PACKAGE_ROOT, encoding: 'utf8', windowsHide: true };
    const status = await execFile(
      'git',
      ['status', '--porcelain=v1', '--untracked-files=all', '--', '.'],
      options,
    );
    if (status.stdout !== '') throw new TypeError('dirty package');
    const revision = await execFile('git', ['rev-parse', 'HEAD'], options);
    const sha = revision.stdout.trim();
    if (!/^[0-9a-f]{40}$/u.test(sha)) throw new TypeError('invalid revision');
    return sha;
  } catch {
    throw new TypeError('unable to identify candidate preflight revision');
  }
}

async function installedOpenClawVersion() {
  try {
    const result = await execFile('openclaw', ['--version'], {
      encoding: 'utf8',
      windowsHide: true,
    });
    const match = /(?:^|\s)([0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2})(?:\s|$)/u.exec(result.stdout);
    if (match === null) throw new TypeError('invalid version');
    return match[1];
  } catch {
    throw new TypeError('unable to identify OpenClaw version');
  }
}

async function readJson(url) {
  try {
    return JSON.parse(await readFile(url, 'utf8'));
  } catch {
    throw new TypeError('invalid candidate preflight input file');
  }
}

function assertNoProxy() {
  const entries = `${process.env.no_proxy ?? ''},${process.env.NO_PROXY ?? ''}`
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  for (const provider of Object.values(PROVIDERS)) {
    if (!entries.includes(provider.host)) {
      throw new TypeError('candidate preflight no_proxy is incomplete');
    }
  }
}

async function providerSecrets() {
  try {
    const config = JSON.parse(await readFile(join(homedir(), '.openclaw', 'openclaw.json'), 'utf8'));
    const result = {};
    for (const [profile, expected] of Object.entries(PROVIDERS)) {
      const provider = config.models.providers[expected.configId];
      if (provider.baseUrl !== expected.baseUrl
        || typeof provider.apiKey !== 'string' || provider.apiKey.trim() === '') {
        throw new TypeError('invalid provider');
      }
      result[profile] = provider.apiKey;
    }
    return Object.freeze(result);
  } catch {
    throw new TypeError('invalid OpenClaw candidate providers');
  }
}

async function assertFreshOutput(outputPath) {
  const absolute = resolve(outputPath);
  const parent = dirname(absolute);
  const parentStats = await lstat(parent).catch(() => null);
  if (parentStats === null || !parentStats.isDirectory() || parentStats.isSymbolicLink()) {
    throw new TypeError('invalid candidate preflight output parent');
  }
  const outputStats = await lstat(absolute).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (outputStats !== null) throw new TypeError('candidate preflight output already exists');
  return absolute;
}

function forbiddenValuesSnapshot(value) {
  if (!Array.isArray(value) || types.isProxy(value)) {
    throw new TypeError('invalid forbidden values');
  }
  return value.filter((item) => typeof item === 'string' && item !== '');
}

export async function publishCandidatePreflightArtifact(options) {
  const fields = exactDataValues(
    options,
    ['outputPath', 'artifact', 'forbiddenValues'],
    'invalid candidate preflight publication',
  );
  if (typeof fields.outputPath !== 'string' || fields.outputPath.trim() === '') {
    throw new TypeError('invalid candidate preflight publication');
  }
  let content;
  try {
    content = canonicalStringify(fields.artifact) + '\n';
  } catch {
    throw new TypeError('invalid candidate preflight artifact');
  }
  for (const secret of forbiddenValuesSnapshot(fields.forbiddenValues)) {
    const serialized = JSON.stringify(secret);
    const escaped = serialized.slice(1, -1);
    if (content.includes(secret) || content.includes(escaped)) {
      throw new TypeError('artifact contains forbidden value');
    }
  }

  const outputPath = await assertFreshOutput(fields.outputPath);
  const temporary = join(dirname(outputPath), `.${basename(outputPath)}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, FILE_FLAGS, 0o600);
    await handle.chmod(0o600);
    await handle.writeFile(content, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(temporary, outputPath);
    await rm(temporary);
  } catch {
    if (handle !== undefined) await handle.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw new TypeError('candidate preflight publication failed');
  }
}

export async function main() {
  try {
    const { outputPath } = parseCandidatePreflightArgs(process.argv.slice(2));
    await assertFreshOutput(outputPath);
    assertNoProxy();
    const [plan, cases, secrets, gitSha, openclawVersion, hashes] = await Promise.all([
      readJson(CANDIDATE_PLAN_URL),
      readJson(PREFLIGHT_CORPUS_URL),
      providerSecrets(),
      cleanGitSha(),
      installedOpenClawVersion(),
      sourceHashes(),
    ]);
    const artifact = await runCandidatePreflight({
      plan,
      cases,
      providerSecrets: secrets,
      fetchImpl: globalThis.fetch,
      concurrency: 4,
      gitSha,
      nodeVersion: process.version,
      openclawVersion,
      sourceHashes: hashes,
    });
    await publishCandidatePreflightArtifact({
      outputPath,
      artifact,
      forbiddenValues: Object.values(secrets),
    });
    const passed = artifact.candidates.filter(
      (candidate) => candidate.capability_status === 'pass',
    ).length;
    process.stdout.write(canonicalStringify({
      ok: true,
      candidates: artifact.candidates.length,
      passed,
    }) + '\n');
    return artifact;
  } catch {
    process.stderr.write('candidate preflight failed\n');
    process.exitCode = 1;
    return null;
  }
}
