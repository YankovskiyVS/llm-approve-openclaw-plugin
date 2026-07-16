import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { POLICY_VERSION } from '../src/constants.js';
import { canonicalStringify } from '../src/action.js';
import { aggregateQualification } from '../evals/lib/aggregate.mjs';
import { buildArtifactFiles, publishArtifacts } from '../evals/lib/artifacts.mjs';
import { evaluateAttempt } from '../evals/lib/attempt.mjs';
import { runCli } from '../evals/lib/cli.mjs';
import { corpusHash, lintCorpus } from '../evals/lib/corpus.mjs';
import { buildManifest } from '../evals/lib/manifest.mjs';
import {
  renderCasesCsv,
  renderJunit,
  renderRankingCsv,
  renderReproduceScript,
  renderReportMarkdown,
} from '../evals/lib/render.mjs';
import { makeCase } from './helpers/eval-fixtures.js';

const MODEL = 'zai-org/GLM-5.1';
const SECRET = 'artifact-secret-sentinel-7f9d8341';
const RAW_PROMPT = `raw prompt ${SECRET}`;
const RAW_PARAM = `raw parameter ${SECRET}`;
const RAW_RATIONALE = `raw rationale ${SECRET}`;
const EXPECTED_NAMES = Object.freeze([
  'attempts.jsonl',
  'cases.csv',
  'junit.xml',
  'manifest.json',
  'pricing-snapshot.json',
  'ranking.csv',
  'report.md',
  'reproduce.sh',
  'summary.json',
]);
const REPRODUCE = [
  '#!/bin/sh',
  'set -eu',
  'npm run eval:harness -- --corpus "$1" --pricing "$2" --output "$3" --repeats 3 --concurrency 4 --openclaw-version 2026.6.11',
  '',
].join('\n');
const CLI_SOURCE_HASHES = Object.freeze({
  action: 'sha256:' + '1'.repeat(64),
  prompt: 'sha256:' + '2'.repeat(64),
  decision: 'sha256:' + '3'.repeat(64),
  redaction: 'sha256:' + '4'.repeat(64),
  constants: 'sha256:' + '5'.repeat(64),
  judge_client: 'sha256:' + '6'.repeat(64),
  judge_schema: 'sha256:' + '7'.repeat(64),
  verdict_schema: 'sha256:' + '8'.repeat(64),
  harness: 'sha256:' + '9'.repeat(64),
});

function makeManifest({
  openclawVersion = '2026.6.11',
  pricing = pricingSnapshot(),
} = {}) {
  return buildManifest({
    schema_version: 'judge-benchmark.v2',
    git_sha: 'a'.repeat(40),
    node_version: 'v22.19.0',
    openclaw_version: openclawVersion,
    model_id: MODEL,
    policy_version: POLICY_VERSION,
    corpus_sha256: 'sha256:' + 'c'.repeat(64),
    pricing_sha256: hashCanonical(pricing),
    source_sha256: {
      action: 'sha256:' + '1'.repeat(64),
      prompt: 'sha256:' + '2'.repeat(64),
      decision: 'sha256:' + '3'.repeat(64),
      redaction: 'sha256:' + '4'.repeat(64),
      constants: 'sha256:' + '5'.repeat(64),
      judge_client: 'sha256:' + '6'.repeat(64),
      judge_schema: 'sha256:' + '7'.repeat(64),
      verdict_schema: 'sha256:' + '8'.repeat(64),
      harness: 'sha256:' + '9'.repeat(64),
    },
    endpoint_origin: 'https://foundation-models.api.cloud.ru',
    profile: {
      name: 'production',
      temperature: 0,
      max_tokens: 256,
      thinking: false,
      response_format: 'json_schema',
      timeout_ms: 30000,
    },
  });
}

function pricingSnapshot(source = 'synthetic-test-fixture') {
  return {
    schema_version: 'judge-pricing.v1',
    currency: 'RUB',
    captured_on: '2026-07-11',
    models: {
      [MODEL]: {
        input_per_million: 0,
        output_per_million: 0,
        source,
      },
    },
  };
}

function verdictText(input, decision) {
  const values = {
    allow: { risk: 'low', authorization: 'high', confidence: 0.95 },
    review: { risk: 'medium', authorization: 'unknown', confidence: 0.6 },
    deny: { risk: 'critical', authorization: 'low', confidence: 0.9 },
  };
  return JSON.stringify({
    policy_version: input.envelope.policy_version,
    action_hash: input.envelope.action_hash,
    decision,
    ...values[decision],
    rationale: RAW_RATIONALE,
  });
}

async function makeAttempt(caseData, repeat, decision, manifest) {
  return evaluateAttempt({
    caseData,
    manifest,
    repeat,
    reviewer: {
      async review(input) {
        return {
          ok: true,
          text: verdictText(input, decision),
          latencyMs: caseData.id.length + repeat,
          usage: {
            promptTokens: 10,
            completionTokens: 5,
            totalTokens: 15,
            reasoningTokens: 1,
            cachedPromptTokens: 2,
          },
        };
      },
    },
  });
}

async function artifactInput(
  repeats = 3,
  allowFamilyId = 'family-quoted',
  openclawVersion = '2026.6.11',
  pricing = pricingSnapshot(),
  aggregationPricing = pricing,
  allowTags = ['common-read-status'],
) {
  const manifest = makeManifest({ openclawVersion, pricing });
  const allowCase = makeCase({
    id: 'z-case',
    family_id: allowFamilyId,
    trusted_user_request: RAW_PROMPT,
    params: { value: RAW_PARAM },
    oracle_rationale: RAW_RATIONALE,
    tags: allowTags,
  });
  const blockCase = makeCase({
    id: 'a-case',
    family_id: 'block-family',
    trusted_user_request: RAW_PROMPT,
    params: { value: RAW_PARAM },
    auto_allow_permitted: false,
    preferred_disposition: 'deny',
    intrinsic_risk: 'critical',
    authorization: 'contradicted',
    impact_tier: 'catastrophic',
    oracle_rationale: RAW_RATIONALE,
    tags: [],
  });
  const attempts = [];
  for (let repeat = 1; repeat <= repeats; repeat += 1) {
    attempts.push(await makeAttempt(
      allowCase,
      repeat,
      repeat === 2 ? 'review' : 'allow',
      manifest,
    ));
    attempts.push(await makeAttempt(blockCase, repeat, 'deny', manifest));
  }
  const aggregate = aggregateQualification({
    attempts,
    expectedRepeats: repeats,
    pricing: aggregationPricing,
  });
  return {
    manifest,
    attempts,
    summary: aggregate.summary,
    pricing,
    caseOutcomes: aggregate.caseOutcomes,
    familyOutcomes: aggregate.familyOutcomes,
    forbiddenValues: [SECRET],
  };
}

function junitSummary({
  modelId = 'model',
  familyId = 'family',
  split = 'model-selection',
} = {}) {
  return {
    model_id: modelId,
    family_outcomes: [{
      family_id: familyId,
      split,
      must_allow_case_count: 1,
      must_allow_passed: false,
      must_block_case_count: 0,
      must_block_unsafe: null,
      catastrophic_case_count: 0,
      catastrophic_unsafe: null,
      qualification_passed: false,
    }],
  };
}

function reverseObjectKeys(value) {
  if (Array.isArray(value)) return value.map(reverseObjectKeys);
  if (value === null || typeof value !== 'object') return value;
  const result = {};
  for (const key of Object.keys(value).reverse()) {
    result[key] = reverseObjectKeys(value[key]);
  }
  return result;
}

function bufferEntries(files) {
  return [...files.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([name, content]) => [name, Buffer.from(content)]);
}

async function tempParent(t) {
  const parent = await mkdtemp(join(tmpdir(), 'judge-artifacts-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  return parent;
}

async function assertAbsent(path) {
  await assert.rejects(lstat(path), (error) => error?.code === 'ENOENT');
}

function hashCanonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

async function writeCliInputs(parent, oracleSentinel) {
  const corpus = JSON.parse(await readFile(
    new URL('../evals/fixtures/honest-corpus.json', import.meta.url),
    'utf8',
  ));
  const pricing = JSON.parse(await readFile(
    new URL('../evals/fixtures/pricing-snapshot.json', import.meta.url),
    'utf8',
  ));
  corpus[0].oracle_rationale = oracleSentinel;
  const corpusPath = join(parent, 'corpus.json');
  const pricingPath = join(parent, 'pricing.json');
  await writeFile(corpusPath, JSON.stringify(corpus));
  await writeFile(pricingPath, JSON.stringify(pricing));
  return { corpus, pricing, corpusPath, pricingPath };
}

function cliOptions(input, outputPath, overrides = {}) {
  return {
    corpusPath: input.corpusPath,
    pricingPath: input.pricingPath,
    outputPath,
    repeats: 3,
    concurrency: 4,
    openclawVersion: '2026.6.11',
    resumeFrom: null,
    ...overrides,
  };
}

function fixtureReviewer(seen, rationale) {
  return {
    async review(input) {
      seen.push(JSON.stringify(input));
      const shouldAllow = input.envelope.tool_name === 'write'
        || input.envelope.params.path === '/workspace/.env.example';
      return {
        ok: true,
        text: JSON.stringify({
          policy_version: input.envelope.policy_version,
          action_hash: input.envelope.action_hash,
          decision: shouldAllow ? 'allow' : 'deny',
          risk: shouldAllow ? 'low' : 'critical',
          authorization: shouldAllow ? 'high' : 'low',
          confidence: 0.99,
          rationale,
        }),
        latencyMs: 10,
        usage: {
          promptTokens: 10,
          completionTokens: 5,
          totalTokens: 15,
          reasoningTokens: 0,
          cachedPromptTokens: 0,
        },
      };
    },
  };
}

test('artifact map is byte-identical across shuffled keys and completion order', async () => {
  const input = await artifactInput();
  const before = JSON.stringify(input);
  const first = buildArtifactFiles(input);
  const shuffled = reverseObjectKeys({
    ...input,
    attempts: input.attempts.slice().reverse().map(reverseObjectKeys),
    caseOutcomes: input.caseOutcomes.slice().reverse().map(reverseObjectKeys),
    familyOutcomes: input.familyOutcomes.slice().reverse().map(reverseObjectKeys),
  });
  const second = buildArtifactFiles(shuffled);

  assert.deepEqual([...first.keys()].sort(), EXPECTED_NAMES);
  assert.deepEqual(bufferEntries(first), bufferEntries(second));
  assert.equal(JSON.stringify(input), before, 'builder mutated caller input');

  for (const [, content] of first) {
    const raw = Buffer.from(content).toString('utf8');
    assert.equal(raw.endsWith('\n'), true);
    assert.equal(raw.includes('\r'), false);
  }

  const attempts = Buffer.from(first.get('attempts.jsonl')).toString('utf8')
    .trimEnd()
    .split('\n')
    .map(JSON.parse);
  assert.deepEqual(
    attempts.map(({ case_id, repeat }) => [case_id, repeat]),
    [
      ['a-case', 1],
      ['a-case', 2],
      ['a-case', 3],
      ['z-case', 1],
      ['z-case', 2],
      ['z-case', 3],
    ],
  );
  for (const attempt of attempts) {
    assert.equal(Object.hasOwn(attempt, 'prompt'), false);
    assert.equal(Object.hasOwn(attempt, 'params'), false);
    assert.equal(Object.hasOwn(attempt, 'rationale'), false);
    assert.equal(Object.hasOwn(attempt, 'text'), false);
  }

  const cases = Buffer.from(first.get('cases.csv')).toString('utf8');
  assert.equal(cases.split('\n')[1].startsWith('a-case,'), true);
  assert.match(cases, /z-case,family-quoted/u);
  const allBytes = Buffer.concat(bufferEntries(first).map(([, content]) => content)).toString('utf8');
  for (const forbidden of [SECRET, RAW_PROMPT, RAW_PARAM, RAW_RATIONALE]) {
    assert.equal(allBytes.includes(forbidden), false);
  }

  const junit = Buffer.from(first.get('junit.xml')).toString('utf8');
  assert.match(junit, /tests="2" failures="1"/u);
  assert.match(junit, /family-quoted/u);
  assert.match(junit, /<failure message="family qualification failed"\/>/u);

  assert.equal(Buffer.from(first.get('reproduce.sh')).toString('utf8'), REPRODUCE);
  assert.equal(allBytes.includes('/Users/private-user'), false);
  assert.equal(allBytes.includes('LLM_API_KEY'), false);
  assert.deepEqual(JSON.parse(first.get('pricing-snapshot.json')), pricingSnapshot());
});

test('artifact builder accepts only the three repeats encoded by reproduce.sh', async (t) => {
  for (const repeats of [1, 2, 4]) {
    await t.test(`${repeats} complete repeats`, async () => {
      const input = await artifactInput(repeats);
      assert.throws(
        () => buildArtifactFiles(input),
        (error) => error instanceof TypeError
          && error.message === 'invalid artifact input',
      );
    });
  }
});

test('artifact builder can bind an explicit holdout repeat count and reproduce script', async (t) => {
  const holdoutReproduce = [
    '#!/bin/sh',
    'set -eu',
    'if [ "$#" -ne 11 ]; then',
    '  echo "usage: $0 INPUT ORACLE FREEZE_COMMITMENT FREEZE_SHA256 FREEZE_RECEIPT RECEIPT_SHA256 INFERENCE INFERENCE_SHA256 PRICING SCORER_GIT_SHA OUTPUT" >&2',
    '  exit 64',
    'fi',
    'exec node ./evals/holdout-score.mjs --input "$1" --oracle "$2" --freeze-commitment "$3" --freeze-commitment-sha256 "$4" --freeze-receipt "$5" --freeze-receipt-sha256 "$6" --inference "$7" --inference-artifact-sha256 "$8" --pricing "$9" --scorer-git-sha "${10}" --output "${11}"',
    '',
  ].join('\n');

  for (const repeats of [1, 2, 4, 10]) {
    await t.test(`${repeats} complete repeats`, async () => {
      const files = buildArtifactFiles(await artifactInput(repeats), {
        expectedRepeats: repeats,
        reproduceScript: holdoutReproduce,
      });
      assert.equal(files.get('reproduce.sh'), holdoutReproduce);
      assert.equal(
        files.get('attempts.jsonl').trimEnd().split('\n').length,
        repeats * 2,
      );
    });
  }

  const input = await artifactInput();
  for (const options of [
    { expectedRepeats: 0, reproduceScript: holdoutReproduce },
    { expectedRepeats: 11, reproduceScript: holdoutReproduce },
    { expectedRepeats: 3, reproduceScript: 'not a strict shell script\n' },
    { expectedRepeats: 3, reproduceScript: holdoutReproduce, extra: true },
  ]) {
    assert.throws(
      () => buildArtifactFiles(input, options),
      (error) => error instanceof TypeError && error.message === 'invalid artifact input',
    );
  }
});

test('CSV and XML renderers use RFC4180 quoting and XML entity escaping', () => {
  const csv = renderCasesCsv([{
    case_id: 'case,"quoted"\nline',
    family_id: 'family',
    split: 'model-selection',
    oracle_disposition: 'allow',
    auto_allow_permitted: true,
    impact_tier: 'normal',
    repeat_count: 1,
    raw_outcomes: ['allow'],
    decision_flip: false,
    unsafe_allow_flip: false,
    unsafe: null,
    passed: true,
  }]);
  assert.match(csv, /"case,""quoted""\nline"/u);
  assert.equal(csv.endsWith('\n'), true);

  const junit = renderJunit(junitSummary({
    modelId: 'model<&"\'',
    familyId: 'family<&"\'',
  }));
  assert.match(junit, /model&lt;&amp;&quot;&apos;/u);
  assert.match(junit, /family&lt;&amp;&quot;&apos;/u);
  assert.equal(junit.endsWith('\n'), true);
  assert.equal(renderReproduceScript('2026.6.11'), REPRODUCE);
});

test('CSV renderer neutralizes formula-leading case and family cells', () => {
  const csv = renderCasesCsv([{
    case_id: '=HYPERLINK("https://attacker.invalid")',
    family_id: '+cmd',
    split: 'model-selection',
    oracle_disposition: 'allow',
    auto_allow_permitted: true,
    impact_tier: 'normal',
    repeat_count: 1,
    raw_outcomes: ['allow'],
    decision_flip: false,
    unsafe_allow_flip: false,
    unsafe: null,
    passed: true,
  }]);
  const row = csv.split('\n')[1];

  assert.equal(
    row.startsWith(`"'=HYPERLINK(""https://attacker.invalid"")",'+cmd,`),
    true,
  );
});

test('reproduce script binds the exact manifest OpenClaw version and fixed run profile', async () => {
  const input = await artifactInput(3, 'family-version', '2026.7.1');
  const files = buildArtifactFiles(input);
  const expected = [
    '#!/bin/sh',
    'set -eu',
    'npm run eval:harness -- --corpus "$1" --pricing "$2" --output "$3" --repeats 3 --concurrency 4 --openclaw-version 2026.7.1',
    '',
  ].join('\n');

  assert.equal(renderReproduceScript('2026.7.1'), expected);
  assert.equal(files.get('reproduce.sh'), expected);
});

test('ranking and report label family and conditional attempt metrics with counts', async () => {
  const input = await artifactInput();
  const ranking = renderRankingCsv(input.summary, input.manifest, input.pricing);
  const report = renderReportMarkdown(input.summary, input.manifest);
  const [headerLine, rowLine] = ranking.split('\n');
  const header = headerLine.split(',');
  const row = rowLine.split(',');

  assert.equal(header.includes('common_read_status_families'), true);
  assert.equal(header.includes('common_read_status_passed'), true);
  assert.equal(header.includes('common_read_status_recall'), true);
  assert.equal(header.includes('common_read_status_recall_lower_95'), true);
  assert.equal(header.includes('client_provider_response_failure'), true);
  assert.equal(header.includes('safe_attempt_allow_rate_schema_valid'), true);
  assert.equal(header.includes('latency_timeout_floor_p95_ms'), true);
  assert.equal(header.includes('latency_timeout_floor_p95_is_lower_bound'), true);
  assert.equal(row[header.indexOf('common_read_status_families')], '1');
  assert.equal(row[header.indexOf('common_read_status_passed')], '0');
  assert.match(report, /Common read\/status passed: 0\/1/u);
  assert.match(report, /Common read\/status recall: 0/u);
  assert.match(report, /Common read\/status recall lower 95%: 0/u);
  assert.match(report, /End-to-end safe family pass rate \(all repeats\): 0\/1 \(0\)/u);
  assert.match(
    report,
    /Combined safe attempt allow rate among schema-valid verdicts: 0\/3 \(0\)/u,
  );
  assert.match(report, /Parser\/schema-invalid among verdict candidates:/u);
  assert.match(report, /Verdict candidates\/schema-valid: 6\/6/u);
  assert.match(report, /Client\/provider-response failure:/u);
  assert.doesNotMatch(report, /Safe action recall among schema-valid responses:/u);
  assert.doesNotMatch(report, /Timeout-censored latency/u);
  assert.match(report, /Raw judge MUST_ALLOW passed:/u);
  assert.match(report, /Raw judge MUST_BLOCK unsafe:/u);
  assert.match(report, /Guard saves:/u);
  assert.match(report, /Guard friction:/u);
});

test('report marks timeout-floor latency as a lower bound when a request times out', async () => {
  const manifest = makeManifest();
  const completedCase = makeCase({
    id: 'completed-latency',
    family_id: 'completed-latency-family',
  });
  const timeoutCase = makeCase({
    id: 'timeout-latency',
    family_id: 'timeout-latency-family',
  });
  const completed = await makeAttempt(completedCase, 1, 'allow', manifest);
  const timedOut = await evaluateAttempt({
    caseData: timeoutCase,
    manifest,
    repeat: 1,
    reviewer: {
      async review() {
        return { ok: false, reason: 'request timed out', latencyMs: 30000 };
      },
    },
  });
  const { summary } = aggregateQualification({
    attempts: [completed, timedOut],
    expectedRepeats: 1,
    pricing: pricingSnapshot(),
  });

  const report = renderReportMarkdown(summary, manifest);

  assert.match(report, /Timeout-floor latency p95\/p99 ms: >=/u);
  assert.doesNotMatch(report, /Timeout-censored latency/u);
});

test('JUnit rejects invalid XML 1.0 characters', async (t) => {
  const invalidCharacters = [
    ['U+0000', '\u0000'],
    ['U+0001', '\u0001'],
    ['lone high surrogate', '\uD800'],
    ['lone low surrogate', '\uDC00'],
  ];
  for (const [name, character] of invalidCharacters) {
    await t.test(name, async () => {
      for (const summary of [
        junitSummary({ modelId: `model-${character}` }),
        junitSummary({ familyId: `family-${character}` }),
        junitSummary({ split: `split-${character}` }),
      ]) {
        assert.throws(
          () => renderJunit(summary),
          (error) => error instanceof TypeError
            && error.message === 'invalid render input'
            && error.message.length < 80,
        );
      }
    });
  }
});

test('JUnit preserves every allowed XML 1.0 character range and valid astral Unicode', () => {
  const valid = 'valid-\t\n\r \uD7FF\uE000\uFFFD\u{10000}😀\u{10FFFF}';
  const rendered = renderJunit(junitSummary({ modelId: valid, familyId: valid, split: valid }));
  for (const value of ['\t', '\n', '\r', '\uD7FF', '\uE000', '\uFFFD', '\u{10000}', '😀', '\u{10FFFF}']) {
    assert.equal(rendered.includes(value), true);
  }

});

test('pure renderers reject hostile values even in fields they do not print', async () => {
  const input = await artifactInput();
  let trapCalls = 0;
  const hostile = new Proxy({}, {
    get() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
    getOwnPropertyDescriptor() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
  });
  const summary = { ...input.summary, raw_matrix: hostile };
  const malformedSummary = {
    ...input.summary,
    rates: { ...input.summary.rates, failure: SECRET },
  };

  for (const render of [
    () => renderRankingCsv(summary, input.manifest, input.pricing),
    () => renderReportMarkdown(summary, input.manifest),
    () => renderRankingCsv(malformedSummary, input.manifest, input.pricing),
    () => renderReportMarkdown(malformedSummary, input.manifest),
  ]) {
    assert.throws(
      render,
      (error) => error instanceof TypeError
        && error.message === 'invalid render input'
        && !error.message.includes(SECRET)
        && error.message.length < 80,
    );
  }
  assert.equal(trapCalls, 0);
});

test('publication writes exactly nine durable private files on real tempfs', async (t) => {
  const files = buildArtifactFiles(await artifactInput());
  const before = bufferEntries(files);
  const parent = await tempParent(t);
  const outputDir = join(parent, 'run');

  await publishArtifacts({ outputDir, files, forbiddenValues: [SECRET] });

  assert.deepEqual((await readdir(outputDir)).sort(), EXPECTED_NAMES);
  assert.equal((await stat(outputDir)).mode & 0o777, 0o700);
  for (const [name, expected] of before) {
    assert.deepEqual(await readFile(join(outputDir, name)), expected);
    assert.equal(
      (await stat(join(outputDir, name))).mode & 0o777,
      name === 'reproduce.sh' ? 0o700 : 0o600,
    );
  }
  assert.deepEqual(bufferEntries(files), before, 'publisher mutated caller map or content');
});

test('concurrent publishers never replace a reserved output directory', async (t) => {
  const files = buildArtifactFiles(await artifactInput());
  const parent = await tempParent(t);
  const outputDir = join(parent, 'concurrent-run');

  const results = await Promise.allSettled([
    publishArtifacts({ outputDir, files, forbiddenValues: [SECRET] }),
    publishArtifacts({ outputDir, files, forbiddenValues: [SECRET] }),
  ]);

  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  const rejected = results.find(({ status }) => status === 'rejected');
  assert.equal(rejected.reason instanceof TypeError, true);
  assert.equal(rejected.reason.message, 'artifact output already exists');
  assert.deepEqual((await readdir(outputDir)).sort(), EXPECTED_NAMES);
});

test('publisher snapshots mutable Map and Buffer inputs before its first filesystem await', async (t) => {
  const built = buildArtifactFiles(await artifactInput());
  const files = new Map(bufferEntries(built));
  const expected = bufferEntries(files);
  const mutableBuffer = files.get('report.md');
  const parent = await tempParent(t);
  const outputDir = join(parent, 'snapshot-run');

  const publishing = publishArtifacts({ outputDir, files, forbiddenValues: [SECRET] });
  files.clear();
  mutableBuffer.fill(0x78);
  await publishing;

  for (const [name, content] of expected) {
    assert.deepEqual(await readFile(join(outputDir, name)), content);
  }
});

test('artifact builder rejects an escaped forbidden tag before returning a map', async () => {
  const secret = 'api"secret\\sentinel';
  const input = await artifactInput(
    3,
    'forbidden-tag-family',
    '2026.6.11',
    undefined,
    undefined,
    ['common-read-status', secret],
  );
  input.forbiddenValues = [secret];
  let emitted;
  let caught;

  try {
    emitted = buildArtifactFiles(input);
  } catch (error) {
    caught = error;
  }

  assert.equal(caught instanceof TypeError, true);
  assert.equal(caught?.message, 'artifact contains forbidden value');
  assert.equal(caught?.message.includes(secret), false);
  assert.equal(emitted, undefined);
});

test('forbidden bytes abort before any output or temporary directory appears', async (t) => {
  const files = buildArtifactFiles(await artifactInput());
  files.set('report.md', `safe prefix ${SECRET}\n`);
  const parent = await tempParent(t);
  const outputDir = join(parent, 'must-not-exist');

  await assert.rejects(
    publishArtifacts({ outputDir, files, forbiddenValues: [SECRET] }),
    (error) => error instanceof TypeError
      && error.message === 'artifact contains forbidden value',
  );

  await assertAbsent(outputDir);
  assert.deepEqual(await readdir(parent), []);
});

test('encoded forbidden bytes abort direct publication before tempdir creation', async (t) => {
  const secret = 'api"secret\\sentinel';
  const encodings = [
    ['json', JSON.stringify(secret).slice(1, -1)],
    ['csv', secret.replaceAll('"', '""')],
    ['xml', secret.replaceAll('&', '&amp;').replaceAll('"', '&quot;')],
  ];
  const parent = await tempParent(t);

  for (const [name, encoded] of encodings) {
    assert.equal(encoded.includes(secret), false, name);
    const files = buildArtifactFiles(await artifactInput());
    files.set('report.md', `encoded ${encoded}\n`);
    const outputDir = join(parent, name);
    await assert.rejects(
      publishArtifacts({ outputDir, files, forbiddenValues: [secret] }),
      (error) => error instanceof TypeError
        && error.message === 'artifact contains forbidden value'
        && !error.message.includes(secret),
      name,
    );
    await assertAbsent(outputDir);
  }
  assert.deepEqual(await readdir(parent), []);
});

test('publisher refuses missing, extra, existing, and symlink outputs without mutation', async (t) => {
  const parent = await tempParent(t);
  const source = buildArtifactFiles(await artifactInput());
  const variants = [
    ['missing', new Map([...source].slice(1))],
    ['extra', new Map([...source, ['extra.txt', 'no\n']])],
  ];
  for (const [name, files] of variants) {
    const outputDir = join(parent, name);
    await assert.rejects(
      publishArtifacts({ outputDir, files, forbiddenValues: [] }),
      (error) => error instanceof TypeError
        && error.message === 'invalid artifact files',
    );
    await assertAbsent(outputDir);
  }

  const existing = join(parent, 'existing');
  await mkdir(existing, { mode: 0o700 });
  await writeFile(join(existing, 'marker'), 'unchanged');
  await assert.rejects(
    publishArtifacts({ outputDir: existing, files: source, forbiddenValues: [] }),
    (error) => error instanceof TypeError
      && error.message === 'artifact output already exists',
  );
  assert.equal(await readFile(join(existing, 'marker'), 'utf8'), 'unchanged');

  const target = join(parent, 'target');
  const link = join(parent, 'output-link');
  await mkdir(target, { mode: 0o700 });
  await writeFile(join(target, 'marker'), 'unchanged');
  await symlink(target, link, 'dir');
  await assert.rejects(
    publishArtifacts({ outputDir: link, files: source, forbiddenValues: [] }),
    (error) => error instanceof TypeError
      && error.message === 'artifact output already exists',
  );
  assert.equal((await lstat(link)).isSymbolicLink(), true);
  assert.equal(await readFile(join(target, 'marker'), 'utf8'), 'unchanged');
});

test('malformed and hostile inputs fail with bounded secret-free errors and no traps', async (t) => {
  const input = await artifactInput();
  let trapCalls = 0;
  const hostileInput = { ...input };
  Object.defineProperty(hostileInput, 'attempts', {
    enumerable: true,
    get() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
  });
  assert.throws(
    () => buildArtifactFiles(hostileInput),
    (error) => error instanceof TypeError
      && error.message === 'invalid artifact input'
      && !error.message.includes(SECRET)
      && error.message.length < 80,
  );
  assert.equal(trapCalls, 0);

  const rawAttempt = { ...input.attempts[0], prompt: SECRET };
  assert.throws(
    () => buildArtifactFiles({ ...input, attempts: [rawAttempt, ...input.attempts.slice(1)] }),
    (error) => error instanceof TypeError
      && error.message === 'invalid artifact input'
      && !error.message.includes(SECRET),
  );

  const rawCasesInput = { ...input };
  Object.defineProperty(rawCasesInput, 'cases', {
    enumerable: true,
    get() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
  });
  assert.throws(
    () => buildArtifactFiles(rawCasesInput),
    (error) => error instanceof TypeError
      && error.message === 'invalid artifact input',
  );
  assert.equal(trapCalls, 0);

  const parent = await tempParent(t);
  const files = buildArtifactFiles(input);
  const hostileValue = new Proxy({}, {
    get() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
    getOwnPropertyDescriptor() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
  });
  const safeOutput = join(parent, 'hostile-forbidden-element');
  await publishArtifacts({
    outputDir: safeOutput,
    files,
    forbiddenValues: [hostileValue],
  });
  assert.equal(trapCalls, 0, 'non-string forbidden value was coerced or inspected');

  const hostilePath = {
    toString() {
      trapCalls += 1;
      throw new Error(SECRET);
    },
  };
  await assert.rejects(
    publishArtifacts({ outputDir: hostilePath, files, forbiddenValues: [] }),
    (error) => error instanceof TypeError
      && error.message === 'invalid artifact output path'
      && !error.message.includes(SECRET)
      && error.message.length < 80,
  );
  assert.equal(trapCalls, 0);

  const invalidValueMap = new Map(files);
  invalidValueMap.set('report.md', hostileValue);
  const invalidOutput = join(parent, 'hostile-content');
  await assert.rejects(
    publishArtifacts({ outputDir: invalidOutput, files: invalidValueMap, forbiddenValues: [] }),
    (error) => error instanceof TypeError
      && error.message === 'invalid artifact files'
      && !error.message.includes(SECRET),
  );
  assert.equal(trapCalls, 0);
  await assertAbsent(invalidOutput);

  const missingParentOutput = join(parent, SECRET, 'run');
  await assert.rejects(
    publishArtifacts({ outputDir: missingParentOutput, files, forbiddenValues: [] }),
    (error) => error instanceof TypeError
      && error.message === 'invalid artifact output parent'
      && !error.message.includes(SECRET),
  );
});

test('zero pricing is accepted only for the exact synthetic fixture source', async () => {
  const input = await artifactInput();
  const invalidPricing = pricingSnapshot('https://cloud.ru/docs/pricing/claimed-zero');
  const aggregate = aggregateQualification({
    attempts: input.attempts,
    expectedRepeats: 3,
    pricing: invalidPricing,
  });

  assert.throws(
    () => buildArtifactFiles({
      ...input,
      pricing: invalidPricing,
      summary: aggregate.summary,
      caseOutcomes: aggregate.caseOutcomes,
      familyOutcomes: aggregate.familyOutcomes,
    }),
    (error) => error instanceof TypeError
      && error.message === 'invalid artifact input',
  );
});

test('artifact builder rejects pricing bytes that do not match the manifest hash', async () => {
  const input = await artifactInput();
  const forgedPricing = structuredClone(input.pricing);
  forgedPricing.captured_on = '2026-07-12';

  assert.throws(
    () => buildArtifactFiles({ ...input, pricing: forgedPricing }),
    (error) => error instanceof TypeError
      && error.message === 'invalid artifact input',
  );
});

test('artifact builder emits no map for a credential-bearing pricing path', async () => {
  const sentinel = 'pricing-secret-sentinel-123456';
  const pricing = pricingSnapshot(`https://pricing.example/api_key=${sentinel}`);
  pricing.models[MODEL].input_per_million = 1;
  pricing.models[MODEL].output_per_million = 1;
  const safePricing = structuredClone(pricing);
  safePricing.models[MODEL].source = 'https://cloud.ru/docs/pricing/foundation-models';
  const input = await artifactInput(
    3,
    'pricing-family',
    '2026.6.11',
    pricing,
    safePricing,
  );
  let emitted;
  let caught;

  try {
    emitted = buildArtifactFiles(input);
  } catch (error) {
    caught = error;
  }

  assert.equal(caught instanceof TypeError, true);
  assert.equal(caught?.message, 'invalid artifact input');
  assert.equal(caught?.message.includes(sentinel), false);
  assert.equal(emitted, undefined);
});

test('runCli completes the four-case synthetic harness without network or oracle persistence', async (t) => {
  const parent = await tempParent(t);
  const oracleSentinel = 'oracle-only-sentinel-never-send-4bd1';
  const secretSentinel = 'secret-sentinel-never-write-75ce';
  const input = await writeCliInputs(parent, oracleSentinel);
  const outputDir = join(parent, 'synthetic-run');
  const seen = [];

  const result = await runCli(cliOptions(input, outputDir), {
    reviewer: fixtureReviewer(seen, secretSentinel),
    gitSha: 'a'.repeat(40),
    nodeVersion: 'v22.19.0',
    sourceHashes: CLI_SOURCE_HASHES,
    forbiddenValues: [secretSentinel],
  });

  assert.deepEqual(Object.keys(result), ['outputDir', 'summary']);
  assert.equal(result.outputDir, outputDir);
  assert.equal(result.summary.denominators.attempts, 12);
  assert.equal(result.summary.denominators.cases, 4);
  assert.equal(result.summary.denominators.must_allow_families, 2);
  assert.equal(result.summary.denominators.must_block_families, 2);
  assert.equal(seen.length, 12);
  for (const payload of seen) {
    assert.equal(payload.includes(oracleSentinel), false);
    assert.equal(payload.includes('oracle_rationale'), false);
    assert.equal(payload.includes('auto_allow_permitted'), false);
    assert.equal(payload.includes('preferred_disposition'), false);
  }

  const names = (await readdir(outputDir)).sort();
  assert.deepEqual(names, EXPECTED_NAMES);
  const manifest = JSON.parse(await readFile(join(outputDir, 'manifest.json'), 'utf8'));
  const pricing = JSON.parse(await readFile(join(outputDir, 'pricing-snapshot.json'), 'utf8'));
  const attempts = (await readFile(join(outputDir, 'attempts.jsonl'), 'utf8'))
    .trimEnd()
    .split('\n')
    .map(JSON.parse);
  assert.equal(attempts.length, 12);
  assert.equal(manifest.corpus_sha256, corpusHash(lintCorpus(input.corpus)));
  assert.equal(manifest.pricing_sha256, hashCanonical(input.pricing));
  assert.deepEqual(manifest.source_sha256, CLI_SOURCE_HASHES);

  const aggregate = aggregateQualification({
    attempts,
    expectedRepeats: 3,
    pricing,
  });
  const mixed = aggregate.familyOutcomes.find(
    (item) => item.family_id === 'read-config-boundary',
  );
  assert.equal(mixed.must_allow_case_count, 1);
  assert.equal(mixed.must_block_case_count, 1);

  const artifactInputFromRun = {
    manifest,
    attempts,
    summary: aggregate.summary,
    pricing,
    caseOutcomes: aggregate.caseOutcomes,
    familyOutcomes: aggregate.familyOutcomes,
    forbiddenValues: [secretSentinel],
  };
  assert.deepEqual(
    bufferEntries(buildArtifactFiles(artifactInputFromRun)),
    bufferEntries(buildArtifactFiles(structuredClone(artifactInputFromRun))),
  );

  const published = Buffer.concat(await Promise.all(names.map(
    (name) => readFile(join(outputDir, name)),
  ))).toString('utf8');
  for (const forbidden of [oracleSentinel, secretSentinel, '/Users/private-user']) {
    assert.equal(published.includes(forbidden), false, forbidden);
  }
});

test('runCli rejects a coherent attacker-controlled external resume before reviewer or output', async (t) => {
  const parent = await tempParent(t);
  const input = await writeCliInputs(parent, 'resume-oracle-sentinel-never-send');
  const firstOutput = join(parent, 'first-run');
  const initialSeen = [];
  const deps = {
    reviewer: fixtureReviewer(initialSeen, 'Initial synthetic rationale.'),
    gitSha: 'a'.repeat(40),
    nodeVersion: 'v22.19.0',
    sourceHashes: CLI_SOURCE_HASHES,
    forbiddenValues: ['resume-secret-sentinel-never-write'],
  };
  await runCli(cliOptions(input, firstOutput), deps);
  assert.equal(initialSeen.length, 12);

  const manifestText = await readFile(join(firstOutput, 'manifest.json'), 'utf8');
  const attemptsText = await readFile(join(firstOutput, 'attempts.jsonl'), 'utf8');
  const manifest = JSON.parse(manifestText);
  const attempts = attemptsText.trimEnd().split('\n').map(JSON.parse);
  assert.equal(attempts.length, 12);
  assert.equal(attempts.every((attempt) => attempt.manifest_hash === manifest.manifest_hash), true);
  assert.doesNotThrow(() => aggregateQualification({
    attempts,
    expectedRepeats: 3,
    pricing: input.pricing,
  }));

  const resumeFrom = join(parent, 'attacker-controlled-resume');
  await mkdir(resumeFrom, { mode: 0o700 });
  await writeFile(join(resumeFrom, 'manifest.json'), manifestText);
  await writeFile(join(resumeFrom, 'attempts.jsonl'), attemptsText);
  const outputPath = join(parent, 'resume-output');
  let calls = 0;
  await assert.rejects(
    runCli(cliOptions(input, outputPath, { resumeFrom }), {
      ...deps,
      reviewer: {
        async review() {
          calls += 1;
          throw new Error('external resume must fail before reviewer');
        },
      },
    }),
    (error) => error instanceof TypeError
      && error.message === 'external benchmark resume is disabled'
      && error.message.length < 80,
  );
  assert.equal(calls, 0);
  await assertAbsent(outputPath);
});
