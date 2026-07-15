import { randomBytes, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  link,
  lstat,
  open,
  realpath,
  rm,
} from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import {
  buildHoldoutFreezeCommitment,
  buildHoldoutFreezeReceipt,
  holdoutFreezeReceiptHash,
} from './holdout-commitments.mjs';
import { buildHoldoutSplit } from './holdout-contracts.mjs';
import { corpusHash, lintCorpus } from './corpus.mjs';
import { validateHoldoutPartitionAudit } from './holdout-partition-audit.mjs';

const OPTION_KEYS = Object.freeze([
  'corpusPath', 'partitionAuditPath', 'partitionName', 'holdoutId',
  'inputOutputPath', 'oracleOutputPath', 'commitmentOutputPath',
  'receiptOutputPath',
]);
const DEPENDENCY_KEYS = new Set([
  'idKey', 'invocationDirectory', 'forbiddenValues', 'commitmentNonce',
]);
const REQUIRED_DEPENDENCIES = Object.freeze(['idKey']);
const FLAG_NAMES = Object.freeze({
  '--corpus': 'corpusPath',
  '--partition-audit': 'partitionAuditPath',
  '--partition-name': 'partitionName',
  '--holdout-id': 'holdoutId',
  '--input-output': 'inputOutputPath',
  '--oracle-output': 'oracleOutputPath',
  '--commitment-output': 'commitmentOutputPath',
  '--receipt-output': 'receiptOutputPath',
});
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const JSON_BASENAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/u;
const READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
const WRITE_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0);

function invalidArguments() {
  throw new TypeError('invalid holdout freeze arguments');
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

function allowedDataValues(value, allowed, required, message) {
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

function safeJsonBasename(value) {
  return typeof value === 'string'
    && JSON_BASENAME_PATTERN.test(value)
    && value === basename(value);
}

function validateOptions(value) {
  const fields = exactDataValues(value, OPTION_KEYS, 'invalid holdout freeze options');
  if (!safeJsonBasename(fields.corpusPath)
    || !safeJsonBasename(fields.partitionAuditPath)
    || !safeJsonBasename(fields.inputOutputPath)
    || !safeJsonBasename(fields.oracleOutputPath)
    || !safeJsonBasename(fields.commitmentOutputPath)
    || !safeJsonBasename(fields.receiptOutputPath)
    || new Set([
      fields.inputOutputPath,
      fields.oracleOutputPath,
      fields.commitmentOutputPath,
      fields.receiptOutputPath,
    ]).size !== 4
    || typeof fields.partitionName !== 'string'
    || !IDENTIFIER_PATTERN.test(fields.partitionName)
    || typeof fields.holdoutId !== 'string'
    || !IDENTIFIER_PATTERN.test(fields.holdoutId)) {
    throw new TypeError('invalid holdout freeze options');
  }
  return Object.freeze(fields);
}

function denseStrings(value, message) {
  if (value === undefined) return [];
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError(message);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1) throw new TypeError(message);
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'string') throw new TypeError(message);
      if (descriptor.value !== '') result.push(descriptor.value);
    }
    return result;
  } catch {
    throw new TypeError(message);
  }
}

function validateDependencies(value) {
  const fields = allowedDataValues(
    value,
    DEPENDENCY_KEYS,
    REQUIRED_DEPENDENCIES,
    'invalid holdout freeze dependencies',
  );
  if (typeof fields.idKey !== 'string') {
    throw new TypeError('invalid holdout freeze dependencies');
  }
  if (fields.invocationDirectory !== undefined
    && (typeof fields.invocationDirectory !== 'string'
      || fields.invocationDirectory.trim() === '')) {
    throw new TypeError('invalid holdout freeze dependencies');
  }
  if (fields.commitmentNonce !== undefined
    && (typeof fields.commitmentNonce !== 'string'
      || !/^[0-9a-f]{64}$/u.test(fields.commitmentNonce))) {
    throw new TypeError('invalid holdout freeze dependencies');
  }
  return Object.freeze({
    idKey: fields.idKey,
    invocationDirectory: fields.invocationDirectory,
    commitmentNonce: fields.commitmentNonce ?? randomBytes(32).toString('hex'),
    forbiddenValues: Object.freeze(denseStrings(
      fields.forbiddenValues,
      'invalid holdout freeze dependencies',
    )),
  });
}

async function invocationRoot(value) {
  const requested = resolve(value ?? process.env.INIT_CWD ?? process.cwd());
  const root = await realpath(requested).catch(() => null);
  if (root === null) throw new TypeError('invalid holdout freeze directory');
  const stats = await lstat(root).catch(() => null);
  if (stats === null || !stats.isDirectory() || stats.isSymbolicLink()) {
    throw new TypeError('invalid holdout freeze directory');
  }
  return root;
}

async function readRegularJson(path) {
  let handle;
  try {
    handle = await open(path, READ_FLAGS);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 2n || before.size > 16n * 1024n * 1024n) {
      throw new TypeError('invalid holdout freeze corpus');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino
      || before.mode !== after.mode || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
      || bytes.length !== Number(after.size)) {
      throw new TypeError('invalid holdout freeze corpus');
    }
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new TypeError('invalid holdout freeze corpus');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function assertAbsent(path) {
  const stats = await lstat(path).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (stats !== null) throw new TypeError('holdout freeze output already exists');
}

function assertForbiddenAbsent(contents, forbiddenValues) {
  for (const value of forbiddenValues) {
    const escaped = JSON.stringify(value).slice(1, -1);
    if (contents.some((content) => content.includes(value) || content.includes(escaped))) {
      throw new TypeError('holdout freeze output contains forbidden value');
    }
  }
}

async function writeTemporary(path, content) {
  let handle;
  try {
    handle = await open(path, WRITE_FLAGS, 0o600);
    await handle.chmod(0o600);
    await handle.writeFile(content, 'utf8');
    await handle.sync();
  } catch {
    throw new TypeError('holdout freeze publication failed');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function publishBundle({ root, outputs }) {
  const finalPaths = outputs.map((item) => join(root, item.path));
  await Promise.all(finalPaths.map(assertAbsent));
  const token = randomUUID();
  const temporaryPaths = outputs.map((item) => join(root, `.${item.path}.${token}.tmp`));
  const linked = [];
  try {
    await Promise.all(outputs.map((item, index) => (
      writeTemporary(temporaryPaths[index], item.content)
    )));
    for (let index = 0; index < outputs.length; index += 1) {
      await link(temporaryPaths[index], finalPaths[index]);
      linked.push(finalPaths[index]);
    }
  } catch {
    await Promise.all(linked.map((path) => rm(path, { force: true }).catch(() => {})));
    throw new TypeError('holdout freeze publication failed');
  } finally {
    await Promise.all(temporaryPaths.map((path) => rm(path, { force: true }).catch(() => {})));
  }
}

export function parseHoldoutFreezeArgs(argv) {
  const values = snapshotArgv(argv);
  if (values.length !== Object.keys(FLAG_NAMES).length * 2) invalidArguments();
  const parsed = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!Object.hasOwn(FLAG_NAMES, flag) || parsed.has(flag)
      || typeof value !== 'string' || value.trim() === '' || value.startsWith('--')) {
      invalidArguments();
    }
    parsed.set(flag, value);
  }
  if (Object.keys(FLAG_NAMES).some((flag) => !parsed.has(flag))) invalidArguments();
  return validateOptions(Object.fromEntries(
    Object.entries(FLAG_NAMES).map(([flag, key]) => [key, parsed.get(flag)]),
  ));
}

export async function runHoldoutFreezeCli(options, deps) {
  const fields = validateOptions(options);
  const dependencies = validateDependencies(deps);
  const root = await invocationRoot(dependencies.invocationDirectory);
  await Promise.all([
    assertAbsent(join(root, fields.inputOutputPath)),
    assertAbsent(join(root, fields.oracleOutputPath)),
    assertAbsent(join(root, fields.commitmentOutputPath)),
    assertAbsent(join(root, fields.receiptOutputPath)),
  ]);
  const [corpusValue, partitionAuditValue] = await Promise.all([
    readRegularJson(join(root, fields.corpusPath)),
    readRegularJson(join(root, fields.partitionAuditPath)),
  ]);
  let corpus;
  let partitionAudit;
  let auditedPartition;
  let split;
  try {
    corpus = lintCorpus(corpusValue);
    partitionAudit = validateHoldoutPartitionAudit(partitionAuditValue);
    auditedPartition = partitionAudit.partitions.find(
      (entry) => entry.name === fields.partitionName,
    );
    const splits = new Set(corpus.map((item) => item.split));
    const families = new Set(corpus.map((item) => item.family_id));
    if (auditedPartition === undefined
      || splits.size !== 1
      || auditedPartition.split !== [...splits][0]
      || auditedPartition.corpus_sha256 !== corpusHash(corpus)
      || auditedPartition.cases !== corpus.length
      || auditedPartition.families !== families.size) {
      throw new TypeError('partition mismatch');
    }
    split = buildHoldoutSplit({
      holdoutId: fields.holdoutId,
      cases: corpus,
      idKey: dependencies.idKey,
    });
  } catch {
    throw new TypeError('invalid holdout freeze corpus');
  }

  const inputContent = canonicalStringify(split.input) + '\n';
  const oracleContent = canonicalStringify(split.oracle) + '\n';
  const commitment = buildHoldoutFreezeCommitment({
    input: split.input,
    oracle: split.oracle,
    corpus,
    partitionName: fields.partitionName,
    partitionAuditSha256: partitionAudit.audit_sha256,
    commitmentNonce: dependencies.commitmentNonce,
  });
  const commitmentContent = canonicalStringify(commitment) + '\n';
  const receipt = buildHoldoutFreezeReceipt({ commitment, partitionAudit });
  const receiptContent = canonicalStringify(receipt) + '\n';
  assertForbiddenAbsent(
    [inputContent, oracleContent, commitmentContent, receiptContent],
    [dependencies.idKey, ...dependencies.forbiddenValues],
  );
  assertForbiddenAbsent(
    [inputContent, oracleContent, receiptContent],
    [dependencies.commitmentNonce],
  );
  await publishBundle({
    root,
    outputs: [
      { path: fields.inputOutputPath, content: inputContent },
      { path: fields.oracleOutputPath, content: oracleContent },
      { path: fields.commitmentOutputPath, content: commitmentContent },
      { path: fields.receiptOutputPath, content: receiptContent },
    ],
  });
  return receipt;
}

export async function main() {
  try {
    const options = parseHoldoutFreezeArgs(process.argv.slice(2));
    const result = await runHoldoutFreezeCli(options, {
      idKey: process.env.HOLDOUT_ID_KEY,
      forbiddenValues: [process.env.HOLDOUT_ID_KEY ?? ''],
    });
    process.stdout.write(canonicalStringify({
      schema_version: 'judge-holdout-freeze-publication.v1',
      holdout_id: result.holdout_id,
      input_sha256: result.input_sha256,
      partition_audit_sha256: result.partition_audit_sha256,
      commitment_sha256: result.commitment_sha256,
      freeze_receipt_sha256: holdoutFreezeReceiptHash(result),
    }) + '\n');
    return result;
  } catch {
    process.stderr.write('holdout freeze failed\n');
    process.exitCode = 1;
    return null;
  }
}
