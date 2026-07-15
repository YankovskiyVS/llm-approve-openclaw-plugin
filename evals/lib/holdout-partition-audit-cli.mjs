import { randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  link,
  lstat,
  open,
  realpath,
  rm,
} from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { auditHoldoutPartitions } from './holdout-partition-audit.mjs';

const MANIFEST_KEYS = Object.freeze(['schema_version', 'partitions']);
const PARTITION_KEYS = Object.freeze(['name', 'path']);
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const JSON_BASENAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/u;
const READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
const WRITE_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0);
const MAX_INPUT_BYTES = 64 * 1024 * 1024;

function invalid(message = 'invalid holdout partition audit arguments') {
  throw new TypeError(message);
}

function exactDataValues(value, keys, message) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalid(message);
    const prototype = Object.getPrototypeOf(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if ((prototype !== Object.prototype && prototype !== null)
      || Reflect.ownKeys(descriptors).length !== keys.length) invalid(message);
    const result = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        invalid(message);
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    invalid(message);
  }
}

function denseArray(value, message) {
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) invalid(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (!Number.isSafeInteger(descriptors.length?.value)
      || descriptors.length.value < 1
      || Reflect.ownKeys(descriptors).length !== descriptors.length.value + 1) invalid(message);
    const result = [];
    for (let index = 0; index < descriptors.length.value; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        invalid(message);
      }
      result.push(descriptor.value);
    }
    return result;
  } catch {
    invalid(message);
  }
}

function safeJsonBasename(value) {
  return typeof value === 'string'
    && JSON_BASENAME_PATTERN.test(value)
    && value === basename(value);
}

function snapshotArgv(value) {
  const entries = denseArray(value, 'invalid holdout partition audit arguments');
  if (entries.length !== 4 || entries.some((entry) => typeof entry !== 'string')) invalid();
  const parsed = new Map();
  for (let index = 0; index < entries.length; index += 2) {
    const flag = entries[index];
    const item = entries[index + 1];
    if (!['--manifest', '--output'].includes(flag) || parsed.has(flag)
      || !safeJsonBasename(item)) invalid();
    parsed.set(flag, item);
  }
  if (parsed.size !== 2) invalid();
  if (parsed.get('--manifest') === parsed.get('--output')) invalid();
  return Object.freeze({
    manifestPath: parsed.get('--manifest'),
    outputPath: parsed.get('--output'),
  });
}

function snapshotOptions(value) {
  const fields = exactDataValues(
    value,
    ['manifestPath', 'outputPath'],
    'invalid holdout partition audit options',
  );
  if (!safeJsonBasename(fields.manifestPath)
    || !safeJsonBasename(fields.outputPath)
    || fields.manifestPath === fields.outputPath) {
    invalid('invalid holdout partition audit options');
  }
  return Object.freeze(fields);
}

function validateManifest(value) {
  const fields = exactDataValues(value, MANIFEST_KEYS, 'invalid partition manifest');
  const partitions = denseArray(fields.partitions, 'invalid partition manifest').map((value) => {
    const entry = exactDataValues(value, PARTITION_KEYS, 'invalid partition manifest');
    if (typeof entry.name !== 'string' || !IDENTIFIER_PATTERN.test(entry.name)
      || !safeJsonBasename(entry.path)) invalid('invalid partition manifest');
    return Object.freeze(entry);
  });
  if (fields.schema_version !== 'judge-holdout-partition-manifest.v1'
    || new Set(partitions.map((entry) => entry.name)).size !== partitions.length
    || new Set(partitions.map((entry) => entry.path)).size !== partitions.length) {
    invalid('invalid partition manifest');
  }
  return Object.freeze(partitions);
}

function snapshotDependencies(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalid('invalid holdout partition audit dependencies');
    const prototype = Object.getPrototypeOf(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if ((prototype !== Object.prototype && prototype !== null)
      || keys.some((key) => key !== 'invocationDirectory')
      || keys.length > 1) invalid('invalid holdout partition audit dependencies');
    const descriptor = descriptors.invocationDirectory;
    if (descriptor === undefined) return Object.freeze({ invocationDirectory: undefined });
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
      || typeof descriptor.value !== 'string' || descriptor.value.trim() === '') {
      invalid('invalid holdout partition audit dependencies');
    }
    return Object.freeze({ invocationDirectory: descriptor.value });
  } catch {
    invalid('invalid holdout partition audit dependencies');
  }
}

async function invocationRoot(value) {
  if (value !== undefined && (typeof value !== 'string' || value.trim() === '')) {
    invalid('invalid holdout partition audit directory');
  }
  const root = await realpath(resolve(value ?? process.env.INIT_CWD ?? process.cwd()))
    .catch(() => null);
  const stats = root === null ? null : await lstat(root).catch(() => null);
  if (stats === null || !stats.isDirectory() || stats.isSymbolicLink()) {
    invalid('invalid holdout partition audit directory');
  }
  return root;
}

async function readRegularJson(path) {
  let handle;
  try {
    handle = await open(path, READ_FLAGS);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 2n || before.size > BigInt(MAX_INPUT_BYTES)) {
      invalid('invalid holdout partition audit input');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino
      || before.mode !== after.mode || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
      || bytes.length !== Number(after.size)) invalid('invalid holdout partition audit input');
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    invalid('invalid holdout partition audit input');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function publish(path, artifact) {
  const existing = await lstat(path).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (existing !== null) invalid('holdout partition audit output already exists');
  const temporary = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, WRITE_FLAGS, 0o600);
    await handle.chmod(0o600);
    await handle.writeFile(canonicalStringify(artifact) + '\n', 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(temporary, path);
  } catch {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    invalid('holdout partition audit publication failed');
  }
  await rm(temporary, { force: true }).catch(() => {});
}

export function parseHoldoutPartitionAuditArgs(argv) {
  return snapshotArgv(argv);
}

export async function runHoldoutPartitionAuditCli(options, deps = {}) {
  const fields = snapshotOptions(options);
  const dependencyFields = snapshotDependencies(deps);
  const root = await invocationRoot(dependencyFields.invocationDirectory);
  const output = join(root, fields.outputPath);
  const manifest = validateManifest(await readRegularJson(join(root, fields.manifestPath)));
  const partitions = await Promise.all(manifest.map(async (entry) => ({
    name: entry.name,
    cases: await readRegularJson(join(root, entry.path)),
  })));
  const artifact = auditHoldoutPartitions(partitions);
  await publish(output, artifact);
  return artifact;
}

export async function main() {
  try {
    const options = parseHoldoutPartitionAuditArgs(process.argv.slice(2));
    const artifact = await runHoldoutPartitionAuditCli(options);
    process.stdout.write(canonicalStringify({
      schema_version: 'judge-holdout-partition-audit-publication.v1',
      audit_sha256: artifact.audit_sha256,
    }) + '\n');
    return artifact;
  } catch {
    process.stderr.write('holdout partition audit failed\n');
    process.exitCode = 1;
    return null;
  }
}
