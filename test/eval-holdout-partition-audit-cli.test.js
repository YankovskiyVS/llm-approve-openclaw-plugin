import test from 'node:test';
import assert from 'node:assert/strict';
import {
  lstat,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalStringify } from '../src/action.js';
import {
  parseHoldoutPartitionAuditArgs,
  runHoldoutPartitionAuditCli,
} from '../evals/lib/holdout-partition-audit-cli.mjs';
import { validateHoldoutPartitionAudit } from '../evals/lib/holdout-partition-audit.mjs';
import { makeCase } from './helpers/eval-fixtures.js';

function caseFor({ id, family, split, path }) {
  return makeCase({
    id,
    family_id: family,
    split,
    trusted_user_request: `Read the public fixture ${id}.`,
    params: { path },
  });
}

function partitions() {
  return {
    primary: [caseFor({
      id: 'audit-cli-primary', family: 'audit-cli-primary-family',
      split: 'frozen-holdout', path: '/workspace/primary.txt',
    })],
    reserve: [caseFor({
      id: 'audit-cli-reserve', family: 'audit-cli-reserve-family',
      split: 'reserve-holdout', path: '/workspace/reserve.txt',
    })],
    historical: [caseFor({
      id: 'audit-cli-historical', family: 'audit-cli-historical-family',
      split: 'model-selection', path: '/workspace/historical.txt',
    })],
  };
}

async function directory(t) {
  const path = await mkdtemp(join(tmpdir(), 'holdout-partition-audit-cli-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}

async function prepare(path, values = partitions()) {
  const entries = Object.entries(values).map(([name]) => ({
    name,
    path: `${name}.json`,
  }));
  await Promise.all([
    writeFile(join(path, 'manifest.json'), canonicalStringify({
      schema_version: 'judge-holdout-partition-manifest.v1',
      partitions: entries,
    }) + '\n'),
    ...Object.entries(values).map(([name, cases]) => (
      writeFile(join(path, `${name}.json`), canonicalStringify(cases) + '\n')
    )),
  ]);
}

test('partition audit CLI parses only exact basename inputs', () => {
  assert.deepEqual(parseHoldoutPartitionAuditArgs([
    '--manifest', 'manifest.json', '--output', 'partition-audit.json',
  ]), {
    manifestPath: 'manifest.json',
    outputPath: 'partition-audit.json',
  });
  for (const argv of [
    [],
    ['--manifest', 'manifest.json'],
    ['--manifest', '../manifest.json', '--output', 'audit.json'],
    ['--manifest', 'manifest.json', '--output', '/tmp/audit.json'],
    ['--manifest', 'manifest.json', '--unknown', 'audit.json'],
    ['--manifest', 'same.json', '--output', 'same.json'],
  ]) assert.throws(() => parseHoldoutPartitionAuditArgs(argv), TypeError);
  assert.throws(() => parseHoldoutPartitionAuditArgs(new Proxy([], {})), TypeError);
});

test('partition audit CLI atomically publishes an exact private artifact', async (t) => {
  const root = await directory(t);
  await prepare(root);
  const artifact = await runHoldoutPartitionAuditCli({
    manifestPath: 'manifest.json',
    outputPath: 'partition-audit.json',
  }, { invocationDirectory: root });

  assert.deepEqual(validateHoldoutPartitionAudit(artifact), artifact);
  assert.deepEqual(artifact.partitions.map(({ name, split, cases, families }) => ({
    name, split, cases, families,
  })), [
    { name: 'primary', split: 'frozen-holdout', cases: 1, families: 1 },
    { name: 'reserve', split: 'reserve-holdout', cases: 1, families: 1 },
    { name: 'historical', split: 'model-selection', cases: 1, families: 1 },
  ]);
  const output = join(root, 'partition-audit.json');
  assert.equal(await readFile(output, 'utf8'), canonicalStringify(artifact) + '\n');
  assert.equal((await lstat(output)).mode & 0o777, 0o600);
  await assert.rejects(runHoldoutPartitionAuditCli({
    manifestPath: 'manifest.json',
    outputPath: 'partition-audit.json',
  }, { invocationDirectory: root }), TypeError);
});

test('partition audit CLI rejects symlinks and cross-partition collisions without output', async (t) => {
  const root = await directory(t);
  const values = partitions();
  values.reserve[0] = {
    ...values.reserve[0],
    id: values.primary[0].id,
  };
  await prepare(root, values);
  await assert.rejects(runHoldoutPartitionAuditCli({
    manifestPath: 'manifest.json', outputPath: 'collision-audit.json',
  }, { invocationDirectory: root }), TypeError);
  await assert.rejects(lstat(join(root, 'collision-audit.json')), { code: 'ENOENT' });

  await rm(join(root, 'primary.json'));
  await writeFile(join(root, 'real-primary.json'), canonicalStringify(partitions().primary));
  await symlink(join(root, 'real-primary.json'), join(root, 'primary.json'));
  await assert.rejects(runHoldoutPartitionAuditCli({
    manifestPath: 'manifest.json', outputPath: 'symlink-audit.json',
  }, { invocationDirectory: root }), TypeError);
  await assert.rejects(lstat(join(root, 'symlink-audit.json')), { code: 'ENOENT' });
});

test('partition audit CLI rejects hostile dependency shapes without reading accessors', async () => {
  const options = { manifestPath: 'manifest.json', outputPath: 'audit.json' };
  await assert.rejects(runHoldoutPartitionAuditCli(options, new Proxy({}, {})), TypeError);
  let reads = 0;
  const deps = {};
  Object.defineProperty(deps, 'invocationDirectory', {
    enumerable: true,
    get() {
      reads += 1;
      return '/tmp';
    },
  });
  await assert.rejects(runHoldoutPartitionAuditCli(options, deps), TypeError);
  assert.equal(reads, 0);
});
