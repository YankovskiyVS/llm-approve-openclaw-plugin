import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalStringify } from '../src/action.js';
import { POLICY_VERSION } from '../src/constants.js';
import { aggregateQualification } from '../evals/lib/aggregate.mjs';
import { corpusHash } from '../evals/lib/corpus.mjs';
import { makeResumeKey } from '../evals/lib/manifest.mjs';
import { toAggregatePricing } from '../evals/lib/model-selection-pricing.mjs';
import {
  MAX_SELECTION_CHECKPOINT_BYTES,
  buildSelectionCheckpointBinding,
  canonicalSelectionCheckpointBytes,
  createSelectionCheckpoint,
  readSelectionCheckpoint,
  readSelectionCheckpointIfPresent,
  selectionCheckpointBasename,
  validateSelectionCandidateResult,
  validateSelectionCheckpoint,
  writeSelectionCheckpoint,
} from '../evals/lib/selection-checkpoint.mjs';

const CORPUS_URL = new URL(
  '../evals/corpus-v2/frozen/model-selection.json',
  import.meta.url,
);
const PRICING_URL = new URL(
  '../evals/fixtures/model-selection-pricing.json',
  import.meta.url,
);
const HASH = (character) => `sha256:${character.repeat(64)}`;

function hashCanonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

async function fixture() {
  const cases = JSON.parse(await readFile(CORPUS_URL, 'utf8'));
  const pricing = JSON.parse(await readFile(PRICING_URL, 'utf8'));
  const profile = {
    name: 'production',
    temperature: 0,
    max_tokens: 256,
    max_reasoning_tokens: 0,
    thinking: false,
    response_format: 'json_object',
    timeout_ms: 5000,
  };
  const execution = {
    candidate_concurrency: 4,
    cases_per_candidate: 'sequential',
    repeats: 1,
  };
  const binding = buildSelectionCheckpointBinding({
    officialPreflightArtifactSha256: HASH('a'),
    preflightSha256: HASH('b'),
    planSha256: HASH('c'),
    corpusSha256: corpusHash(cases),
    pricingSha256: hashCanonical(pricing),
    sourceSha256: {
      candidate_selection: HASH('e'),
      action: HASH('d'),
    },
    gitSha: 'f'.repeat(40),
    nodeVersion: 'v25.8.0',
    openclawVersion: '2026.6.11',
    policyVersion: POLICY_VERSION,
    profile,
    execution,
  });
  const manifestContent = {
    schema_version: 'judge-candidate-selection-run.v1',
    git_sha: 'f'.repeat(40),
    node_version: 'v25.8.0',
    openclaw_version: '2026.6.11',
    policy_version: POLICY_VERSION,
    candidate: {
      id: 'zai-org/GLM-4.7',
      model_id: 'zai-org/GLM-4.7',
      endpoint_profile: 'cloudru-fm',
      response_profile: 'openai-strict-final',
    },
    plan_sha256: HASH('c'),
    preflight_sha256: HASH('b'),
    corpus_sha256: corpusHash(cases),
    pricing_sha256: hashCanonical(pricing),
    source_sha256: {
      action: HASH('d'),
      candidate_selection: HASH('e'),
    },
    profile,
    execution,
  };
  const manifest = {
    ...manifestContent,
    manifest_hash: hashCanonical(manifestContent),
  };
  const attempts = cases.map((caseData, index) => {
    const decision = caseData.preferred_disposition;
    const normalized = decision;
    const base = {
      manifest_hash: manifest.manifest_hash,
      model: manifest.candidate.model_id,
      case_id: caseData.id,
      repeat: 1,
      profile: profile.name,
    };
    return {
      resume_key: makeResumeKey(base),
      ...base,
      family_id: caseData.family_id,
      split: caseData.split,
      oracle_disposition: caseData.preferred_disposition,
      auto_allow_permitted: caseData.auto_allow_permitted,
      oracle_risk: caseData.intrinsic_risk,
      oracle_authorization: caseData.authorization,
      impact_tier: caseData.impact_tier,
      tags: caseData.tags,
      raw_decision: decision,
      raw_risk: decision === 'allow' ? 'low' : decision === 'deny' ? 'critical' : 'high',
      raw_authorization: decision === 'allow' ? 'high' : 'unknown',
      confidence: 0.99,
      normalized_kind: normalized,
      autonomous_outcome: decision === 'allow' ? 'executed_without_human' : 'blocked',
      supervised_outcome: decision === 'allow'
        ? 'executed_without_human'
        : decision === 'deny' ? 'blocked' : 'sent_to_human',
      schema_valid: true,
      failure_stage: null,
      failure_code: null,
      latency_ms: index + 1,
      usage: null,
      rationale_sha256: HASH('9'),
    };
  });
  const aggregate = aggregateQualification({
    attempts,
    expectedRepeats: 1,
    pricing: toAggregatePricing(pricing),
  });
  const candidateResult = {
    manifest,
    attempts,
    summary: aggregate.summary,
    case_outcomes: aggregate.caseOutcomes,
    family_outcomes: aggregate.familyOutcomes,
  };
  return { binding, candidateResult, cases, pricing };
}

function context(fields, extra = {}) {
  return {
    expectedBinding: fields.binding,
    pricing: fields.pricing,
    cases: fields.cases,
    expectedCandidateId: fields.candidateResult.manifest.candidate.id,
    ...extra,
  };
}

test('checkpoint canonicalizes one exact candidate result and all run bindings', async () => {
  const fields = await fixture();
  const checkpoint = createSelectionCheckpoint({
    binding: fields.binding,
    candidateResult: fields.candidateResult,
    pricing: fields.pricing,
    cases: fields.cases,
  });
  const again = createSelectionCheckpoint({
    binding: buildSelectionCheckpointBinding({
      officialPreflightArtifactSha256: HASH('a'),
      preflightSha256: HASH('b'),
      planSha256: HASH('c'),
      corpusSha256: corpusHash(fields.cases),
      pricingSha256: hashCanonical(fields.pricing),
      sourceSha256: {
        action: HASH('d'),
        candidate_selection: HASH('e'),
      },
      gitSha: 'f'.repeat(40),
      nodeVersion: 'v25.8.0',
      openclawVersion: '2026.6.11',
      policyVersion: POLICY_VERSION,
      profile: fields.candidateResult.manifest.profile,
      execution: fields.candidateResult.manifest.execution,
    }),
    candidateResult: fields.candidateResult,
    pricing: fields.pricing,
    cases: fields.cases,
  });

  assert.deepEqual(Object.keys(checkpoint), [
    'schema_version',
    'binding',
    'candidate_id',
    'candidate_result_sha256',
    'candidate_result',
    'checkpoint_sha256',
  ]);
  assert.deepEqual(Object.keys(checkpoint.binding), [
    'official_preflight_artifact_sha256',
    'preflight_sha256',
    'plan_sha256',
    'corpus_sha256',
    'pricing_sha256',
    'source_sha256',
    'git_sha',
    'runtime_sha256',
    'profile_sha256',
  ]);
  assert.equal(checkpoint.schema_version, 'judge-candidate-selection-checkpoint.v1');
  assert.equal(checkpoint.candidate_id, 'zai-org/GLM-4.7');
  assert.equal(checkpoint.candidate_result_sha256, hashCanonical(checkpoint.candidate_result));
  assert.match(checkpoint.checkpoint_sha256, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(checkpoint, again);
  assert.deepEqual(
    canonicalSelectionCheckpointBytes(checkpoint, context(fields)),
    canonicalSelectionCheckpointBytes(again, context(fields)),
  );
  assert.ok(Object.isFrozen(validateSelectionCheckpoint(checkpoint, context(fields))));
});

test('validation fails closed on extra keys, semantic tampering, or mismatched run input', async () => {
  const fields = await fixture();
  const valid = createSelectionCheckpoint({
    binding: fields.binding,
    candidateResult: fields.candidateResult,
    pricing: fields.pricing,
    cases: fields.cases,
  });
  const extra = structuredClone(valid);
  extra.candidate_result.manifest.unexpected = true;
  assert.throws(
    () => validateSelectionCheckpoint(extra, context(fields)),
    { name: 'TypeError', message: 'invalid selection checkpoint' },
  );

  const forgedSummary = structuredClone(fields.candidateResult);
  forgedSummary.summary.rates.failure = 1;
  assert.throws(
    () => createSelectionCheckpoint({
      binding: fields.binding,
      candidateResult: forgedSummary,
      pricing: fields.pricing,
      cases: fields.cases,
    }),
    { name: 'TypeError', message: 'invalid selection checkpoint' },
  );

  const otherBinding = { ...fields.binding, corpus_sha256: HASH('0') };
  assert.throws(
    () => validateSelectionCheckpoint(valid, context(fields, { expectedBinding: otherBinding })),
    { name: 'TypeError', message: 'invalid selection checkpoint' },
  );
  assert.throws(
    () => validateSelectionCheckpoint(valid, context(fields, {
      expectedCandidateId: 'secret-token=/private/path',
    })),
    { name: 'TypeError', message: 'invalid selection checkpoint' },
  );
});

test('detached candidate validator requires exact manifest and recomputes aggregate', async () => {
  const fields = await fixture();
  const validated = validateSelectionCandidateResult(fields.candidateResult, {
    expectedManifest: fields.candidateResult.manifest,
    pricing: fields.pricing,
    cases: fields.cases,
  });
  assert.deepEqual(validated, fields.candidateResult);
  assert.ok(Object.isFrozen(validated));

  const mismatched = structuredClone(fields.candidateResult.manifest);
  mismatched.candidate.id = 'Qwen/Qwen3.6-35B-A3B';
  assert.throws(
    () => validateSelectionCandidateResult(fields.candidateResult, {
      expectedManifest: mismatched,
      pricing: fields.pricing,
      cases: fields.cases,
    }),
    { name: 'TypeError', message: 'invalid selection candidate result' },
  );
});

test('writer creates one deterministic private no-clobber file and reader restores it', async (t) => {
  const fields = await fixture();
  const checkpoint = createSelectionCheckpoint({
    binding: fields.binding,
    candidateResult: fields.candidateResult,
    pricing: fields.pricing,
    cases: fields.cases,
  });
  const directory = await mkdtemp(join(tmpdir(), 'judge-selection-checkpoint-'));
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(directory, { recursive: true, force: true });
  });

  const filename = selectionCheckpointBasename(checkpoint.candidate_id);
  assert.match(filename, /^selection-checkpoint-[0-9a-f]{64}\.json$/u);
  assert.equal(filename.includes('/'), false);
  const written = await writeSelectionCheckpoint({
    directory,
    checkpoint,
    ...context(fields),
  });
  assert.deepEqual(written, {
    filename,
    checkpoint_sha256: checkpoint.checkpoint_sha256,
    byte_length: canonicalSelectionCheckpointBytes(checkpoint, context(fields)).length,
  });
  const output = join(directory, filename);
  assert.equal((await stat(output)).mode & 0o777, 0o600);
  assert.deepEqual(
    await readFile(output),
    canonicalSelectionCheckpointBytes(checkpoint, context(fields)),
  );
  assert.deepEqual(await readSelectionCheckpoint({
    directory,
    candidateId: checkpoint.candidate_id,
    ...context(fields),
  }), checkpoint);

  await assert.rejects(
    writeSelectionCheckpoint({ directory, checkpoint, ...context(fields) }),
    { name: 'TypeError', message: 'selection checkpoint write failed' },
  );
});

test('reader rejects symlinks, oversized files, and permissive modes with sanitized errors', async (t) => {
  const fields = await fixture();
  const checkpoint = createSelectionCheckpoint({
    binding: fields.binding,
    candidateResult: fields.candidateResult,
    pricing: fields.pricing,
    cases: fields.cases,
  });
  const root = await mkdtemp(join(tmpdir(), 'judge-selection-checkpoint-hostile-'));
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true, force: true });
  });
  const target = join(root, 'target.json');
  await writeFile(target, canonicalSelectionCheckpointBytes(checkpoint, context(fields)), {
    mode: 0o600,
  });

  const symlinkDirectory = join(root, 'symlink');
  await mkdir(symlinkDirectory);
  await symlink(target, join(
    symlinkDirectory,
    selectionCheckpointBasename(checkpoint.candidate_id),
  ));
  await assert.rejects(
    readSelectionCheckpoint({
      directory: symlinkDirectory,
      candidateId: checkpoint.candidate_id,
      ...context(fields),
    }),
    (error) => error?.name === 'TypeError'
      && error.message === 'selection checkpoint read failed'
      && !error.message.includes(root),
  );

  const largeDirectory = join(root, 'large');
  await mkdir(largeDirectory);
  await writeFile(
    join(largeDirectory, selectionCheckpointBasename(checkpoint.candidate_id)),
    Buffer.alloc(MAX_SELECTION_CHECKPOINT_BYTES + 1, 0x20),
    { mode: 0o600 },
  );
  await assert.rejects(
    readSelectionCheckpoint({
      directory: largeDirectory,
      candidateId: checkpoint.candidate_id,
      ...context(fields),
    }),
    { name: 'TypeError', message: 'selection checkpoint read failed' },
  );

  const modeDirectory = join(root, 'mode');
  await mkdir(modeDirectory);
  const modePath = join(modeDirectory, selectionCheckpointBasename(checkpoint.candidate_id));
  await writeFile(modePath, canonicalSelectionCheckpointBytes(checkpoint, context(fields)), {
    mode: 0o600,
  });
  await chmod(modePath, 0o644);
  await assert.rejects(
    readSelectionCheckpoint({
      directory: modeDirectory,
      candidateId: checkpoint.candidate_id,
      ...context(fields),
    }),
    { name: 'TypeError', message: 'selection checkpoint read failed' },
  );
});

test('writer rejects a symlinked output directory without disclosing it', async (t) => {
  const fields = await fixture();
  const checkpoint = createSelectionCheckpoint({
    binding: fields.binding,
    candidateResult: fields.candidateResult,
    pricing: fields.pricing,
    cases: fields.cases,
  });
  const root = await mkdtemp(join(tmpdir(), 'judge-selection-checkpoint-dir-'));
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(root, { recursive: true, force: true });
  });
  const real = join(root, 'real');
  const alias = join(root, 'secret-token-output');
  await mkdir(real);
  await symlink(real, alias);

  await assert.rejects(
    writeSelectionCheckpoint({ directory: alias, checkpoint, ...context(fields) }),
    (error) => error?.name === 'TypeError'
      && error.message === 'selection checkpoint write failed'
      && !error.message.includes(alias),
  );
});

test('optional reader returns null only when the candidate file is absent', async (t) => {
  const fields = await fixture();
  const directory = await mkdtemp(join(tmpdir(), 'judge-selection-checkpoint-optional-'));
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(directory, { recursive: true, force: true });
  });
  assert.equal(await readSelectionCheckpointIfPresent({
    directory,
    candidateId: fields.candidateResult.manifest.candidate.id,
    ...context(fields),
  }), null);

  const path = join(
    directory,
    selectionCheckpointBasename(fields.candidateResult.manifest.candidate.id),
  );
  await writeFile(path, '{not-json}\n', { mode: 0o600 });
  await assert.rejects(
    readSelectionCheckpointIfPresent({
      directory,
      candidateId: fields.candidateResult.manifest.candidate.id,
      ...context(fields),
    }),
    { name: 'TypeError', message: 'selection checkpoint read failed' },
  );
});
