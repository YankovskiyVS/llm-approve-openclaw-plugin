import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditHoldoutPartitions,
  holdoutPartitionAuditHash,
  validateHoldoutPartitionAudit,
} from '../evals/lib/holdout-partition-audit.mjs';
import { corpusHash } from '../evals/lib/corpus.mjs';
import { makeCase } from './helpers/eval-fixtures.js';

function corpusCase({
  id,
  family,
  split,
  request = `Read public fixture ${id}.`,
  params = { path: `/workspace/public/${id}.md` },
} = {}) {
  return makeCase({
    id,
    family_id: family,
    split,
    trusted_user_request: request,
    params,
  });
}

function validPartitions() {
  const primary = [
    corpusCase({
      id: 'primary-pair-allow',
      family: 'primary-pair',
      split: 'frozen-holdout',
    }),
    corpusCase({
      id: 'primary-pair-neighbor',
      family: 'primary-pair',
      split: 'frozen-holdout',
    }),
  ];
  const reserve = [corpusCase({
    id: 'reserve-single',
    family: 'reserve-single-family',
    split: 'reserve-holdout',
  })];
  const historical = [corpusCase({
    id: 'historical-single',
    family: 'historical-single-family',
    split: 'model-selection',
  })];
  return {
    primary,
    reserve,
    historical,
    partitions: [
      { name: 'primary', cases: primary },
      { name: 'reserve', cases: reserve },
      { name: 'historical', cases: historical },
    ],
  };
}

test('partition audit returns deterministic deep-frozen counts and hashes', () => {
  const fixture = validPartitions();
  const summary = auditHoldoutPartitions(fixture.partitions);

  assert.deepEqual(summary, {
    schema_version: 'judge-holdout-partition-audit.v1',
    partitions: [
      {
        name: 'primary', split: 'frozen-holdout',
        corpus_sha256: corpusHash(fixture.primary), cases: 2, families: 1,
      },
      {
        name: 'reserve', split: 'reserve-holdout',
        corpus_sha256: corpusHash(fixture.reserve), cases: 1, families: 1,
      },
      {
        name: 'historical', split: 'model-selection',
        corpus_sha256: corpusHash(fixture.historical), cases: 1, families: 1,
      },
    ],
    total: { partitions: 3, cases: 4, families: 3 },
    collisions: { case_ids: 0, family_ids: 0, observable_fingerprints: 0 },
    audit_sha256: summary.audit_sha256,
  });
  assert.match(summary.audit_sha256, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(holdoutPartitionAuditHash(summary), summary.audit_sha256);
  assert.deepEqual(validateHoldoutPartitionAudit(JSON.parse(JSON.stringify(summary))), summary);
  for (const value of [
    summary,
    summary.partitions,
    ...summary.partitions,
    summary.total,
    summary.collisions,
  ]) {
    assert.equal(Object.isFrozen(value), true);
  }
});

test('partition audit validator rejects tampering and extra fields', () => {
  const artifact = auditHoldoutPartitions(validPartitions().partitions);
  assert.throws(() => validateHoldoutPartitionAudit({ ...artifact, extra: true }), TypeError);
  assert.throws(() => validateHoldoutPartitionAudit({
    ...artifact,
    total: { ...artifact.total, cases: artifact.total.cases + 1 },
  }), TypeError);
  assert.throws(() => validateHoldoutPartitionAudit({
    ...artifact,
    audit_sha256: 'sha256:' + 'f'.repeat(64),
  }), TypeError);
});

test('partition audit rejects a case ID reused across partitions', () => {
  const first = corpusCase({
    id: 'shared-id',
    family: 'primary-family',
    split: 'frozen-holdout',
  });
  const second = corpusCase({
    id: 'shared-id',
    family: 'reserve-family',
    split: 'reserve-holdout',
    request: 'Read a different public fixture.',
    params: { path: '/workspace/public/different.md' },
  });

  assert.throws(
    () => auditHoldoutPartitions([
      { name: 'primary', cases: [first] },
      { name: 'reserve', cases: [second] },
    ]),
    /duplicate case id across partitions/u,
  );
});

test('partition audit rejects a family reused across partitions even under one split', () => {
  const first = corpusCase({
    id: 'family-primary',
    family: 'shared-family',
    split: 'frozen-holdout',
  });
  const second = corpusCase({
    id: 'family-reserve',
    family: 'shared-family',
    split: 'frozen-holdout',
  });

  assert.throws(
    () => auditHoldoutPartitions([
      { name: 'primary', cases: [first] },
      { name: 'reserve', cases: [second] },
    ]),
    /family reused across partitions/u,
  );
});

test('partition audit rejects production-observable input reused across partitions', () => {
  const first = corpusCase({
    id: 'visible-primary',
    family: 'visible-primary-family',
    split: 'frozen-holdout',
    request: 'Read this configuration for me.',
    params: { path: '/workspace/config.json', token: 'primary-secret' },
  });
  const second = corpusCase({
    id: 'visible-reserve',
    family: 'visible-reserve-family',
    split: 'reserve-holdout',
    request: 'Read this configuration for me.',
    params: { path: '/workspace/config.json', token: 'reserve-secret' },
  });

  assert.throws(
    () => auditHoldoutPartitions([
      { name: 'primary', cases: [first] },
      { name: 'reserve', cases: [second] },
    ]),
    /observable input collision across partitions/u,
  );
});

test('partition audit preserves lintCorpus rules inside every partition', () => {
  const first = corpusCase({
    id: 'duplicate-inside',
    family: 'inside-first-family',
    split: 'frozen-holdout',
  });
  const second = corpusCase({
    id: 'duplicate-inside',
    family: 'inside-second-family',
    split: 'frozen-holdout',
    request: 'Read another public fixture.',
    params: { path: '/workspace/public/another.md' },
  });

  assert.throws(
    () => auditHoldoutPartitions([{ name: 'primary', cases: [first, second] }]),
    /duplicate case id/u,
  );
});

test('partition audit requires an exact non-empty dense partition contract', () => {
  const oneCase = [corpusCase({
    id: 'contract-case',
    family: 'contract-family',
    split: 'frozen-holdout',
  })];

  for (const invalid of [
    [],
    Array(1),
    [{ name: 'primary', cases: [] }],
    [{ name: '', cases: oneCase }],
    [{ name: 'primary', cases: oneCase, extra: true }],
    [
      { name: 'primary', cases: oneCase },
      { name: 'primary', cases: [corpusCase({
        id: 'other-contract-case',
        family: 'other-contract-family',
        split: 'reserve-holdout',
      })] },
    ],
  ]) {
    assert.throws(() => auditHoldoutPartitions(invalid), TypeError);
  }
});

test('partition audit rejects Proxy and accessor containers without reading secrets', () => {
  const secret = 'partition-audit-secret-must-never-leak';
  const validCase = corpusCase({
    id: 'hostile-case',
    family: 'hostile-family',
    split: 'frozen-holdout',
  });
  let reads = 0;
  const accessorPartition = { cases: [validCase] };
  Object.defineProperty(accessorPartition, 'name', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error(secret);
    },
  });
  const accessorArray = [{ name: 'primary', cases: [validCase] }];
  Object.defineProperty(accessorArray, '0', {
    enumerable: true,
    get() {
      reads += 1;
      throw new Error(secret);
    },
  });
  const hostileValues = [
    new Proxy([{ name: 'primary', cases: [validCase] }], {
      ownKeys() {
        throw new Error(secret);
      },
    }),
    [new Proxy({ name: 'primary', cases: [validCase] }, {})],
    [accessorPartition],
    accessorArray,
  ];

  for (const values of hostileValues) {
    let caught;
    try {
      auditHoldoutPartitions(values);
    } catch (error) {
      caught = error;
    }
    assert.equal(caught instanceof TypeError, true);
    assert.equal(caught?.message.includes(secret), false);
    assert.equal(caught?.message.length < 100, true);
  }
  assert.equal(reads, 0);
});
