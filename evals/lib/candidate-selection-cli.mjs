import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { promisify, types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { POLICY_VERSION } from '../../src/constants.js';
import { CANDIDATE_PLAN_URL } from './candidate-plan.mjs';
import { runCandidateSelection } from './candidate-selection.mjs';
import { publishCandidatePreflightArtifact } from './candidate-preflight-cli.mjs';
import { corpusHash } from './corpus.mjs';
import { validateOfficialPreflightArtifact } from './official-preflight-attestation.mjs';
import {
  buildSelectionCheckpointBinding,
  readSelectionCheckpointIfPresent,
  writeSelectionCheckpoint,
} from './selection-checkpoint.mjs';

const execFile = promisify(execFileCallback);
const PACKAGE_ROOT = new URL('../..', import.meta.url);
const CORPUS_URL = new URL('../corpus-v2/frozen/model-selection.json', import.meta.url);
const PREFLIGHT_CASES_URL = new URL(
  '../corpus-v2/frozen/model-selection-preflight.json',
  import.meta.url,
);
const PRICING_URL = new URL('../fixtures/model-selection-pricing.json', import.meta.url);
const OFFICIAL_ATTESTATION_URL = new URL(
  '../candidates/official-preflight.json',
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
  manifest: new URL('./manifest.mjs', import.meta.url),
  aggregate: new URL('./aggregate.mjs', import.meta.url),
  wilson: new URL('./wilson.mjs', import.meta.url),
  preflight_artifact: new URL('./preflight-artifact.mjs', import.meta.url),
  official_preflight_attestation: new URL(
    './official-preflight-attestation.mjs',
    import.meta.url,
  ),
  model_selection_pricing: new URL('./model-selection-pricing.mjs', import.meta.url),
  selection_checkpoint: new URL('./selection-checkpoint.mjs', import.meta.url),
  selection_ranking: new URL('./selection-ranking.mjs', import.meta.url),
});
const SELECTION_SOURCE_URLS = Object.freeze([
  new URL('./candidate-preflight-cli.mjs', import.meta.url),
  new URL('./candidate-selection.mjs', import.meta.url),
  new URL('./candidate-selection-cli.mjs', import.meta.url),
  new URL('../candidate-selection.mjs', import.meta.url),
]);

function invalidArguments() {
  throw new TypeError('invalid candidate selection arguments');
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

function safeJsonBasename(value) {
  return typeof value === 'string'
    && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/u.test(value)
    && value === basename(value);
}

export function parseCandidateSelectionArgs(argv) {
  const values = snapshotArgv(argv);
  if (values.length !== 4 || values[0] !== '--preflight' || values[2] !== '--output'
    || !safeJsonBasename(values[1]) || !safeJsonBasename(values[3])
    || values[1] === values[3]) invalidArguments();
  return { preflightPath: values[1], outputPath: values[3] };
}

function hashBytes(value) {
  return 'sha256:' + createHash('sha256').update(value).digest('hex');
}

async function selectionSourceHashes() {
  try {
    const entries = await Promise.all(Object.entries(SOURCE_URLS).map(async ([key, url]) => [
      key,
      hashBytes(await readFile(url)),
    ]));
    const files = await Promise.all(SELECTION_SOURCE_URLS.map(async (url) => ({
      filename: url.pathname.split('/').slice(-2).join('/'),
      sha256: hashBytes(await readFile(url)),
    })));
    entries.push(['candidate_selection', hashBytes(canonicalStringify({
      domain: 'openclaw-llm-action-judge:candidate-selection-source:v1',
      files,
    }))]);
    return Object.freeze(Object.fromEntries(entries));
  } catch {
    throw new TypeError('unable to identify candidate selection sources');
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
    throw new TypeError('unable to identify candidate selection revision');
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

function assertNoProxy() {
  const entries = `${process.env.no_proxy ?? ''},${process.env.NO_PROXY ?? ''}`
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (Object.values(PROVIDERS).some((provider) => !entries.includes(provider.host))) {
    throw new TypeError('candidate selection no_proxy is incomplete');
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

async function readRegularBytes(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stats = await handle.stat();
    if (!stats.isFile() || stats.size < 2 || stats.size > 16 * 1024 * 1024) {
      throw new TypeError('not regular');
    }
    return await handle.readFile();
  } catch {
    throw new TypeError('invalid candidate selection input file');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function readJsonUrl(url) {
  try {
    return JSON.parse(await readFile(url, 'utf8'));
  } catch {
    throw new TypeError('invalid candidate selection input file');
  }
}

async function assertOutputAbsent(path) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw new TypeError('invalid candidate selection output');
  }
  throw new TypeError('candidate selection output already exists');
}

export async function main() {
  try {
    const parsed = parseCandidateSelectionArgs(process.argv.slice(2));
    const invocationDirectory = resolve(process.env.INIT_CWD ?? process.cwd());
    const preflightPath = join(invocationDirectory, parsed.preflightPath);
    const outputPath = join(invocationDirectory, parsed.outputPath);
    await assertOutputAbsent(outputPath);
    assertNoProxy();
    const [
      preflightBytes,
      plan,
      preflightCases,
      cases,
      pricing,
      attestation,
      secrets,
      gitSha,
      openclawVersion,
      sourceHashes,
    ] = await Promise.all([
      readRegularBytes(preflightPath),
      readJsonUrl(CANDIDATE_PLAN_URL),
      readJsonUrl(PREFLIGHT_CASES_URL),
      readJsonUrl(CORPUS_URL),
      readJsonUrl(PRICING_URL),
      readJsonUrl(OFFICIAL_ATTESTATION_URL),
      providerSecrets(),
      cleanGitSha(),
      installedOpenClawVersion(),
      selectionSourceHashes(),
    ]);
    const preflight = validateOfficialPreflightArtifact(preflightBytes, {
      plan,
      preflightCases,
      attestation,
    });
    const preflightValue = JSON.parse(preflightBytes.toString('utf8'));
    const firstCandidate = plan.candidates.find(
      (candidate) => candidate.id === preflight.eligibleCandidateIds[0],
    );
    if (firstCandidate === undefined) throw new TypeError('invalid official preflight');
    const profile = {
      name: 'production',
      temperature: firstCandidate.temperature,
      max_tokens: firstCandidate.max_tokens,
      max_reasoning_tokens: firstCandidate.max_reasoning_tokens,
      thinking: firstCandidate.thinking,
      response_format: firstCandidate.response_format,
      timeout_ms: firstCandidate.timeout_ms,
    };
    const execution = {
      candidate_concurrency: 4,
      cases_per_candidate: 'sequential',
      repeats: 1,
    };
    const checkpointBinding = buildSelectionCheckpointBinding({
      officialPreflightArtifactSha256: preflight.artifactByteSha256,
      preflightSha256: preflight.artifactSha256,
      planSha256: hashBytes(canonicalStringify(plan)),
      corpusSha256: corpusHash(cases),
      pricingSha256: hashBytes(canonicalStringify(pricing)),
      sourceSha256: sourceHashes,
      gitSha,
      nodeVersion: process.version,
      openclawVersion,
      policyVersion: POLICY_VERSION,
      profile,
      execution,
    });
    const checkpointContext = (candidateId) => ({
      directory: invocationDirectory,
      candidateId,
      expectedBinding: checkpointBinding,
      pricing,
      cases,
      expectedCandidateId: candidateId,
    });
    const completedCheckpoints = (await Promise.all(
      preflight.eligibleCandidateIds.map((candidateId) => (
        readSelectionCheckpointIfPresent(checkpointContext(candidateId))
      )),
    )).filter((checkpoint) => checkpoint !== null);
    let completedCount = completedCheckpoints.length;
    const artifact = await runCandidateSelection({
      plan,
      cases,
      preflightArtifact: preflightValue,
      preflightCases,
      officialPreflightArtifactSha256: preflight.artifactByteSha256,
      officialPreflightAttestationSha256: preflight.officialAttestationSha256,
      providerSecrets: secrets,
      fetchImpl: globalThis.fetch,
      concurrency: 4,
      gitSha,
      nodeVersion: process.version,
      openclawVersion,
      sourceHashes,
      pricing,
      completedCheckpoints,
      onCheckpoint: async (checkpoint) => {
        await writeSelectionCheckpoint({
          directory: invocationDirectory,
          checkpoint,
          expectedBinding: checkpointBinding,
          pricing,
          cases,
          expectedCandidateId: checkpoint.candidate_id,
        });
        completedCount += 1;
        process.stderr.write(
          `candidate selection checkpoint ${completedCount}/${preflight.eligibleCandidateIds.length}\n`,
        );
      },
    });
    await publishCandidatePreflightArtifact({
      outputPath,
      artifact,
      forbiddenValues: Object.values(secrets),
    });
    process.stdout.write(canonicalStringify({
      ok: true,
      candidates: artifact.candidates.length,
      top4: artifact.ranking.slice(0, 4).map((item) => item.candidate_id),
    }) + '\n');
    return artifact;
  } catch {
    process.stderr.write('candidate selection failed\n');
    process.exitCode = 1;
    return null;
  }
}
