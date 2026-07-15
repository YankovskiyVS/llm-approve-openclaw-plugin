import { constants as fsConstants } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  realpath,
  rm,
  rmdir,
} from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { types } from 'node:util';
import { aggregateQualification } from './aggregate.mjs';
import { snapshotAttemptManifest } from './attempt.mjs';
import {
  renderAttemptsJsonl,
  renderCasesCsv,
  renderJunit,
  renderRankingCsv,
  renderReportMarkdown,
  renderReproduceScript,
} from './render.mjs';

const ARTIFACT_NAMES = Object.freeze([
  'manifest.json',
  'attempts.jsonl',
  'cases.csv',
  'summary.json',
  'ranking.csv',
  'report.md',
  'pricing-snapshot.json',
  'junit.xml',
  'reproduce.sh',
]);
const ARTIFACT_NAME_SET = new Set(ARTIFACT_NAMES);
const HOLDOUT_ARTIFACT_NAMES = Object.freeze([
  ...ARTIFACT_NAMES,
  'gate-result.json',
  'gate-junit.xml',
  'score-attestation.json',
  'result-set.json',
]);
const HOLDOUT_ARTIFACT_NAME_SET = new Set(HOLDOUT_ARTIFACT_NAMES);
const BUILD_REQUIRED_KEYS = Object.freeze([
  'manifest', 'attempts', 'summary', 'pricing', 'caseOutcomes', 'familyOutcomes',
]);
const BUILD_OPTIONAL_KEYS = Object.freeze(['forbiddenValues']);
const PUBLISH_KEYS = Object.freeze(['outputDir', 'files', 'forbiddenValues']);
const BUILD_OPTION_KEYS = Object.freeze(['expectedRepeats', 'reproduceScript']);
const ATTEMPT_KEYS = Object.freeze([
  'resume_key', 'manifest_hash', 'model', 'profile', 'case_id',
  'family_id', 'split', 'repeat', 'oracle_disposition',
  'auto_allow_permitted', 'oracle_risk', 'oracle_authorization',
  'impact_tier', 'tags', 'raw_decision', 'raw_risk',
  'raw_authorization', 'confidence', 'normalized_kind',
  'autonomous_outcome', 'supervised_outcome', 'schema_valid',
  'failure_stage', 'failure_code', 'latency_ms', 'usage',
  'rationale_sha256',
]);
const PRICING_KEYS = Object.freeze(['schema_version', 'currency', 'captured_on', 'models']);
const PRICE_KEYS = Object.freeze(['input_per_million', 'output_per_million', 'source']);
const SYNTHETIC_SOURCE = 'synthetic-test-fixture';
const FILE_OPEN_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0);
const DIRECTORY_OPEN_FLAGS = fsConstants.O_RDONLY
  | (fsConstants.O_DIRECTORY ?? 0)
  | (fsConstants.O_NOFOLLOW ?? 0);

export const HOLDOUT_SCORE_REPRODUCE_SCRIPT = [
  '#!/bin/sh',
  'set -eu',
  'if [ "$#" -ne 11 ]; then',
  '  echo "usage: $0 INPUT ORACLE FREEZE_COMMITMENT FREEZE_SHA256 FREEZE_RECEIPT RECEIPT_SHA256 INFERENCE INFERENCE_SHA256 PRICING SCORER_GIT_SHA OUTPUT" >&2',
  '  exit 64',
  'fi',
  'exec node ./evals/holdout-score.mjs --input "$1" --oracle "$2" --freeze-commitment "$3" --freeze-commitment-sha256 "$4" --freeze-receipt "$5" --freeze-receipt-sha256 "$6" --inference "$7" --inference-artifact-sha256 "$8" --pricing "$9" --scorer-git-sha "${10}" --output "${11}"',
  '',
].join('\n');

function invalidArtifactInput() {
  throw new TypeError('invalid artifact input');
}

function compareCodeUnits(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function plainDataDescriptors(value, message) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) throw new TypeError(message);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const key of Reflect.ownKeys(descriptors)) {
      const descriptor = descriptors[key];
      if (typeof key !== 'string' || !descriptor.enumerable
        || !Object.hasOwn(descriptor, 'value')) throw new TypeError(message);
    }
    return descriptors;
  } catch {
    throw new TypeError(message);
  }
}

function exactDataValues(value, expected, message) {
  const descriptors = plainDataDescriptors(value, message);
  const keys = Object.keys(descriptors);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    throw new TypeError(message);
  }
  const result = {};
  for (const key of expected) result[key] = descriptors[key].value;
  return result;
}

function buildDataValues(value) {
  const descriptors = plainDataDescriptors(value, 'invalid artifact input');
  const keys = Object.keys(descriptors);
  const allowed = new Set([...BUILD_REQUIRED_KEYS, ...BUILD_OPTIONAL_KEYS]);
  if (keys.some((key) => !allowed.has(key))
    || BUILD_REQUIRED_KEYS.some((key) => descriptors[key] === undefined)
    || keys.length < BUILD_REQUIRED_KEYS.length
    || keys.length > BUILD_REQUIRED_KEYS.length + BUILD_OPTIONAL_KEYS.length) {
    invalidArtifactInput();
  }
  const result = {};
  for (const key of BUILD_REQUIRED_KEYS) result[key] = descriptors[key].value;
  result.forbiddenValues = descriptors.forbiddenValues?.value ?? [];
  return result;
}

function snapshotBuildOptions(value) {
  const descriptors = plainDataDescriptors(value, 'invalid artifact input');
  const keys = Object.keys(descriptors);
  if (keys.some((key) => !BUILD_OPTION_KEYS.includes(key))) invalidArtifactInput();
  const expectedRepeats = descriptors.expectedRepeats?.value ?? 3;
  const reproduceScript = descriptors.reproduceScript?.value ?? null;
  if (!Number.isInteger(expectedRepeats) || expectedRepeats < 1 || expectedRepeats > 10) {
    invalidArtifactInput();
  }
  if (reproduceScript !== null && reproduceScript !== HOLDOUT_SCORE_REPRODUCE_SCRIPT) {
    invalidArtifactInput();
  }
  return { expectedRepeats, reproduceScript };
}

function denseArrayValues(value, message) {
  try {
    if (types.isProxy(value) || !Array.isArray(value)
      || Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const length = descriptors.length?.value;
    if (!Number.isSafeInteger(length) || length < 0 || keys.length !== length + 1
      || keys.some((key) => typeof key !== 'string')) throw new TypeError(message);
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

function canonicalJson(value, ancestors = new Set()) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) invalidArtifactInput();
    return JSON.stringify(value);
  }
  if (typeof value !== 'object' || types.isProxy(value) || ancestors.has(value)) {
    invalidArtifactInput();
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return '[' + denseArrayValues(value, 'invalid artifact input')
        .map((item) => canonicalJson(item, ancestors))
        .join(',') + ']';
    }
    const descriptors = plainDataDescriptors(value, 'invalid artifact input');
    const keys = Object.keys(descriptors).sort(compareCodeUnits);
    return '{' + keys.map((key) => (
      JSON.stringify(key) + ':' + canonicalJson(descriptors[key].value, ancestors)
    )).join(',') + '}';
  } finally {
    ancestors.delete(value);
  }
}

function canonicalArrayMembers(value) {
  return denseArrayValues(value, 'invalid artifact input')
    .map((item) => canonicalJson(item))
    .sort(compareCodeUnits);
}

function snapshotForbiddenValues(value) {
  return denseArrayValues(value, 'invalid forbidden values')
    .filter((item) => typeof item === 'string' && item.length >= 8)
    .slice();
}

function forbiddenValueEncodings(value) {
  const json = JSON.stringify(value);
  return new Set([
    value,
    json.slice(1, -1),
    value.replaceAll('"', '""'),
    value
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&apos;'),
  ]);
}

function assertForbiddenValuesAbsent(buffers, forbiddenValues) {
  const values = snapshotForbiddenValues(forbiddenValues);
  for (const value of values) {
    for (const encoding of forbiddenValueEncodings(value)) {
      const needle = Buffer.from(encoding, 'utf8');
      for (const content of buffers.values()) {
        if (content.includes(needle)) throw new TypeError('artifact contains forbidden value');
      }
    }
  }
}

function assertSemanticForbiddenValuesAbsent(roots, forbiddenValues) {
  const values = snapshotForbiddenValues(forbiddenValues);
  if (values.length === 0) return;
  const pending = roots.slice();
  const seen = new Set();
  const assertText = (text) => {
    if (values.some((value) => text.includes(value))) {
      throw new TypeError('artifact contains forbidden value');
    }
  };

  while (pending.length > 0) {
    const value = pending.pop();
    if (typeof value === 'string') {
      assertText(value);
      continue;
    }
    if (value === null || typeof value === 'boolean'
      || (typeof value === 'number' && Number.isFinite(value))) continue;
    if (typeof value !== 'object' || types.isProxy(value)) {
      invalidArtifactInput();
    }
    if (seen.has(value)) continue;
    seen.add(value);
    if (Array.isArray(value)) {
      pending.push(...denseArrayValues(value, 'invalid artifact input'));
      continue;
    }
    const descriptors = plainDataDescriptors(value, 'invalid artifact input');
    for (const [key, descriptor] of Object.entries(descriptors)) {
      assertText(key);
      pending.push(descriptor.value);
    }
  }
}

function assertRunIdentity(attempts, manifest) {
  for (const value of attempts) {
    const fields = exactDataValues(value, ATTEMPT_KEYS, 'invalid artifact input');
    if (fields.manifest_hash !== manifest.manifest_hash
      || fields.model !== manifest.model_id
      || fields.profile !== manifest.profile.name) invalidArtifactInput();
  }
}

function assertSyntheticZeroPricing(pricing) {
  const fields = exactDataValues(pricing, PRICING_KEYS, 'invalid artifact input');
  const models = plainDataDescriptors(fields.models, 'invalid artifact input');
  for (const descriptor of Object.values(models)) {
    const price = exactDataValues(descriptor.value, PRICE_KEYS, 'invalid artifact input');
    if ((price.input_per_million === 0 || price.output_per_million === 0)
      && price.source !== SYNTHETIC_SOURCE) invalidArtifactInput();
  }
}

function snapshotFiles(files) {
  try {
    if (files === null || typeof files !== 'object' || types.isProxy(files)
      || Object.getPrototypeOf(files) !== Map.prototype) {
      throw new TypeError('invalid artifact files');
    }
    const entries = [...Map.prototype.entries.call(files)];
    const holdout = entries.length === HOLDOUT_ARTIFACT_NAMES.length;
    const names = holdout ? HOLDOUT_ARTIFACT_NAMES : ARTIFACT_NAMES;
    const nameSet = holdout ? HOLDOUT_ARTIFACT_NAME_SET : ARTIFACT_NAME_SET;
    if (entries.length !== names.length) throw new TypeError('invalid artifact files');
    const result = new Map();
    for (const entry of entries) {
      if (!Array.isArray(entry) || entry.length !== 2) throw new TypeError('invalid artifact files');
      const [name, content] = entry;
      if (typeof name !== 'string' || !nameSet.has(name) || result.has(name)) {
        throw new TypeError('invalid artifact files');
      }
      if (typeof content === 'string') {
        result.set(name, Buffer.from(content, 'utf8'));
      } else if (!types.isProxy(content) && Buffer.isBuffer(content)) {
        result.set(name, Buffer.from(content));
      } else {
        throw new TypeError('invalid artifact files');
      }
    }
    for (const name of names) {
      if (!result.has(name)) throw new TypeError('invalid artifact files');
    }
    return new Map(names.map((name) => [name, result.get(name)]));
  } catch {
    throw new TypeError('invalid artifact files');
  }
}

function inMemoryBuffers(files) {
  return new Map([...files].map(([name, content]) => [name, Buffer.from(content, 'utf8')]));
}

function sha256(value) {
  return 'sha256:' + createHash('sha256').update(value, 'utf8').digest('hex');
}

export function buildArtifactFiles(input, options = {}) {
  try {
    const fields = buildDataValues(input);
    const buildOptions = snapshotBuildOptions(options);
    const manifest = snapshotAttemptManifest(fields.manifest);
    const attempts = denseArrayValues(fields.attempts, 'invalid artifact input');
    const aggregate = aggregateQualification({
      attempts,
      expectedRepeats: buildOptions.expectedRepeats,
      pricing: fields.pricing,
    });
    assertRunIdentity(attempts, manifest);
    assertSyntheticZeroPricing(fields.pricing);

    if (canonicalJson(fields.summary) !== canonicalJson(aggregate.summary)
      || canonicalJson(canonicalArrayMembers(fields.caseOutcomes))
        !== canonicalJson(canonicalArrayMembers(aggregate.caseOutcomes))
      || canonicalJson(canonicalArrayMembers(fields.familyOutcomes))
        !== canonicalJson(canonicalArrayMembers(aggregate.familyOutcomes))) {
      invalidArtifactInput();
    }

    const pricingJson = canonicalJson(fields.pricing);
    if (sha256(pricingJson) !== manifest.pricing_sha256) invalidArtifactInput();
    const pricing = JSON.parse(pricingJson);
    assertSemanticForbiddenValuesAbsent([
      manifest,
      attempts,
      aggregate.summary,
      aggregate.caseOutcomes,
      aggregate.familyOutcomes,
      pricing,
    ], fields.forbiddenValues);
    const files = new Map([
      ['manifest.json', canonicalJson(manifest) + '\n'],
      ['attempts.jsonl', renderAttemptsJsonl(attempts)],
      ['cases.csv', renderCasesCsv(aggregate.caseOutcomes)],
      ['summary.json', canonicalJson(aggregate.summary) + '\n'],
      ['ranking.csv', renderRankingCsv(aggregate.summary, manifest, pricing)],
      ['report.md', renderReportMarkdown(aggregate.summary, manifest)],
      ['pricing-snapshot.json', pricingJson + '\n'],
      ['junit.xml', renderJunit({
        model_id: manifest.model_id,
        family_outcomes: aggregate.familyOutcomes,
      })],
      ['reproduce.sh', buildOptions.reproduceScript
        ?? renderReproduceScript(manifest.openclaw_version)],
    ]);
    assertForbiddenValuesAbsent(inMemoryBuffers(files), fields.forbiddenValues);
    return files;
  } catch (error) {
    if (error instanceof TypeError && error.message === 'artifact contains forbidden value') {
      throw error;
    }
    invalidArtifactInput();
  }
}

function snapshotPublishOptions(options) {
  return exactDataValues(options, PUBLISH_KEYS, 'invalid artifact publish options');
}

function snapshotOutputPath(value) {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0')) {
    throw new TypeError('invalid artifact output path');
  }
  let outputDir;
  try {
    outputDir = resolve(value);
  } catch {
    throw new TypeError('invalid artifact output path');
  }
  const name = basename(outputDir);
  if (name === '' || name === '.' || name === '..') {
    throw new TypeError('invalid artifact output path');
  }
  return { outputDir, parent: dirname(outputDir) };
}

async function assertParentDirectory(parent) {
  let parentStats;
  try {
    parentStats = await lstat(parent);
  } catch {
    throw new TypeError('invalid artifact output parent');
  }
  const canonical = await realpath(parent).catch(() => null);
  let canonicalStats = null;
  if (canonical !== null) {
    canonicalStats = await lstat(canonical).catch(() => null);
  }
  if (!parentStats.isDirectory() || canonicalStats === null
    || !canonicalStats.isDirectory() || canonicalStats.isSymbolicLink()) {
    throw new TypeError('invalid artifact output parent');
  }
  return canonical;
}

async function assertOutputAbsent(outputDir) {
  try {
    await lstat(outputDir);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw new TypeError('artifact output check failed');
  }
  throw new TypeError('artifact output already exists');
}

async function writeDurableFile(path, content, mode) {
  let handle;
  let failed = false;
  try {
    handle = await open(path, FILE_OPEN_FLAGS, mode);
    await handle.chmod(mode);
    await handle.writeFile(content);
    await handle.sync();
  } catch {
    failed = true;
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        failed = true;
      }
    }
  }
  if (failed) throw new TypeError('artifact publication failed');
}

async function syncDirectory(path, required) {
  let handle;
  let failed = false;
  try {
    handle = await open(path, DIRECTORY_OPEN_FLAGS);
    await handle.sync();
  } catch {
    failed = true;
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        failed = true;
      }
    }
  }
  if (required && failed) throw new TypeError('artifact publication failed');
}

async function cleanupTemporaryDirectory(path) {
  if (path === null) return;
  try {
    await rm(path, { recursive: true, force: true });
  } catch {
    // Preserve the original bounded publication error.
  }
}

export async function publishArtifacts(options) {
  const fields = snapshotPublishOptions(options);
  const requestedPath = snapshotOutputPath(fields.outputDir);
  const files = snapshotFiles(fields.files);
  assertForbiddenValuesAbsent(files, fields.forbiddenValues);

  const parent = await assertParentDirectory(requestedPath.parent);
  const outputDir = join(parent, basename(requestedPath.outputDir));
  await assertOutputAbsent(outputDir);

  let temporaryDir = null;
  let outputReserved = false;
  const publishedNames = [];
  try {
    temporaryDir = await mkdtemp(join(parent, '.judge-artifacts-tmp-'));
    await chmod(temporaryDir, 0o700);
    for (const [name, content] of files) {
      await writeDurableFile(
        join(temporaryDir, name),
        content,
        name === 'reproduce.sh' ? 0o700 : 0o600,
      );
    }
    await syncDirectory(temporaryDir, true);
    try {
      await mkdir(outputDir, { mode: 0o700 });
      outputReserved = true;
    } catch (error) {
      if (error?.code === 'EEXIST') throw new TypeError('artifact output already exists');
      throw new TypeError('artifact publication failed');
    }
    for (const [name] of files) {
      await link(join(temporaryDir, name), join(outputDir, name));
      publishedNames.push(name);
    }
    await syncDirectory(outputDir, true);
    await cleanupTemporaryDirectory(temporaryDir);
    temporaryDir = null;
    await syncDirectory(parent, false);
  } catch (error) {
    await cleanupTemporaryDirectory(temporaryDir);
    if (outputReserved) {
      for (const name of publishedNames) {
        await rm(join(outputDir, name), { force: true }).catch(() => {});
      }
      await rmdir(outputDir).catch(() => {});
    }
    if (error instanceof TypeError && [
      'artifact output already exists',
      'artifact output check failed',
      'artifact publication failed',
    ].includes(error.message)) throw error;
    throw new TypeError('artifact publication failed');
  }
}
