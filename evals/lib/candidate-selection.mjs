import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { POLICY_VERSION } from '../../src/constants.js';
import {
  applyLocalSafetyDowngrade,
  applyOpaqueDowngrade,
  mapVerdict,
  normalizeVerdict,
  parseJudgeResponse,
} from '../../src/decision.js';
import { aggregateQualification } from './aggregate.mjs';
import { createCaseInput } from './case-input.mjs';
import { createCandidateJudgeClient } from './candidate-client.mjs';
import { validateCandidatePlan } from './candidate-plan.mjs';
import { corpusHash, lintCorpus } from './corpus.mjs';
import { makeResumeKey } from './manifest.mjs';
import {
  toAggregatePricing,
  validateModelSelectionPricing,
} from './model-selection-pricing.mjs';
import { validatePreflightArtifact } from './preflight-artifact.mjs';
import {
  buildSelectionCheckpointBinding,
  createSelectionCheckpoint,
  validateSelectionCandidateResult,
  validateSelectionCheckpoint,
} from './selection-checkpoint.mjs';
import { rankSelectionCandidates } from './selection-ranking.mjs';

const OPTION_KEYS = Object.freeze([
  'plan',
  'cases',
  'preflightArtifact',
  'preflightCases',
  'officialPreflightArtifactSha256',
  'officialPreflightAttestationSha256',
  'providerSecrets',
  'fetchImpl',
  'concurrency',
  'gitSha',
  'nodeVersion',
  'openclawVersion',
  'sourceHashes',
  'pricing',
  'completedCheckpoints',
  'onCheckpoint',
]);
const SOURCE_KEYS = Object.freeze([
  'action',
  'prompt',
  'decision',
  'redaction',
  'constants',
  'candidate_plan',
  'candidate_client',
  'candidate_response',
  'case_input',
  'case_schema',
  'corpus',
  'manifest',
  'aggregate',
  'wilson',
  'preflight_artifact',
  'official_preflight_attestation',
  'model_selection_pricing',
  'selection_checkpoint',
  'selection_ranking',
  'candidate_selection',
]);
const PROVIDER_KEYS = Object.freeze(['cloudru-fm', 'qwen-vllm']);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const GIT_PATTERN = /^[0-9a-f]{40}$/u;
const NODE_PATTERN = /^v([0-9]+)\.([0-9]+)\.([0-9]+)$/u;
const OPENCLAW_PATTERN = /^([0-9]{4})\.([0-9]{1,2})\.([0-9]{1,2})$/u;
const REVIEWED_CORPUS_SHA256 =
  'sha256:e78bbabcb1dd29e412bdf7f06f678426467d9924f47192945f778482ac680c1c';

function invalidInput() {
  throw new TypeError('invalid candidate selection input');
}

function exactDataValues(value, expected) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalidInput();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalidInput();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) {
      invalidInput();
    }
    const result = {};
    for (const key of expected) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        invalidInput();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    invalidInput();
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function denseArray(value) {
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) invalidInput();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1) invalidInput();
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        invalidInput();
      }
      result.push(descriptor.value);
    }
    return result;
  } catch {
    invalidInput();
  }
}

function hashCanonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function snapshotHashes(value) {
  const fields = exactDataValues(value, SOURCE_KEYS);
  if (SOURCE_KEYS.some((key) => typeof fields[key] !== 'string'
    || !HASH_PATTERN.test(fields[key]))) invalidInput();
  return Object.freeze(fields);
}

function snapshotSecrets(value) {
  const fields = exactDataValues(value, PROVIDER_KEYS);
  if (PROVIDER_KEYS.some((key) => typeof fields[key] !== 'string'
    || fields[key].trim() === '')) invalidInput();
  return Object.freeze(fields);
}

function validateRuntime(fields) {
  if (typeof fields.gitSha !== 'string' || !GIT_PATTERN.test(fields.gitSha)) invalidInput();
  if (typeof fields.nodeVersion !== 'string') invalidInput();
  const node = NODE_PATTERN.exec(fields.nodeVersion);
  if (node === null) invalidInput();
  const [major, minor] = node.slice(1, 3).map(Number);
  if (major < 22 || (major === 22 && minor < 19)) invalidInput();
  if (typeof fields.openclawVersion !== 'string') invalidInput();
  const openclaw = OPENCLAW_PATTERN.exec(fields.openclawVersion);
  if (openclaw === null) invalidInput();
  const [year, month, day] = openclaw.slice(1).map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day || year < 2026
    || (year === 2026 && (month < 6 || (month === 6 && day < 11)))) invalidInput();
}

function snapshotOptions(value) {
  const fields = exactDataValues(value, OPTION_KEYS);
  let plan;
  let cases;
  let preflight;
  let pricing;
  let aggregatePricing;
  try {
    plan = validateCandidatePlan(fields.plan);
    cases = lintCorpus(fields.cases);
    preflight = validatePreflightArtifact(fields.preflightArtifact, {
      plan,
      preflightCases: fields.preflightCases,
    });
    pricing = validateModelSelectionPricing(fields.pricing);
    aggregatePricing = toAggregatePricing(pricing);
    aggregateQualification({ attempts: [], expectedRepeats: 1, pricing: aggregatePricing });
  } catch {
    invalidInput();
  }
  if (cases.length !== 120 || cases.some((item) => item.split !== 'model-selection')
    || corpusHash(cases) !== REVIEWED_CORPUS_SHA256
    || preflight.eligibleCandidateIds.length === 0
    || fields.concurrency !== 4 || typeof fields.fetchImpl !== 'function'
    || types.isProxy(fields.fetchImpl)
    || typeof fields.onCheckpoint !== 'function' || types.isProxy(fields.onCheckpoint)
    || typeof fields.officialPreflightArtifactSha256 !== 'string'
    || !HASH_PATTERN.test(fields.officialPreflightArtifactSha256)
    || typeof fields.officialPreflightAttestationSha256 !== 'string'
    || !HASH_PATTERN.test(fields.officialPreflightAttestationSha256)) invalidInput();
  if (preflight.eligibleCandidateIds.some((id) => !Object.hasOwn(pricing.models, id))) {
    invalidInput();
  }
  const providerSecrets = snapshotSecrets(fields.providerSecrets);
  const sourceHashes = snapshotHashes(fields.sourceHashes);
  const completedCheckpoints = Object.freeze(denseArray(fields.completedCheckpoints));
  validateRuntime(fields);
  return Object.freeze({
    plan,
    cases,
    eligibleCandidateIds: preflight.eligibleCandidateIds,
    providerSecrets,
    fetchImpl: fields.fetchImpl,
    concurrency: fields.concurrency,
    gitSha: fields.gitSha,
    nodeVersion: fields.nodeVersion,
    openclawVersion: fields.openclawVersion,
    preflightSha256: preflight.artifactSha256,
    officialPreflightArtifactSha256: fields.officialPreflightArtifactSha256,
    officialPreflightAttestationSha256: fields.officialPreflightAttestationSha256,
    sourceHashes,
    pricing,
    aggregatePricing,
    completedCheckpoints,
    onCheckpoint: fields.onCheckpoint,
  });
}

function profileFor(candidate) {
  return Object.freeze({
    name: 'production',
    temperature: candidate.temperature,
    max_tokens: candidate.max_tokens,
    max_reasoning_tokens: candidate.max_reasoning_tokens,
    thinking: candidate.thinking,
    response_format: candidate.response_format,
    timeout_ms: candidate.timeout_ms,
  });
}

function executionProfile(concurrency) {
  return Object.freeze({
    candidate_concurrency: concurrency,
    cases_per_candidate: 'sequential',
    repeats: 1,
  });
}

function buildRunManifest(fields, candidate, common) {
  const content = {
    schema_version: 'judge-candidate-selection-run.v1',
    git_sha: fields.gitSha,
    node_version: fields.nodeVersion,
    openclaw_version: fields.openclawVersion,
    policy_version: POLICY_VERSION,
    candidate: {
      id: candidate.id,
      model_id: candidate.model_id,
      endpoint_profile: candidate.endpoint_profile,
      response_profile: candidate.response_profile,
    },
    plan_sha256: common.planSha256,
    preflight_sha256: fields.preflightSha256,
    corpus_sha256: common.corpusSha256,
    pricing_sha256: common.pricingSha256,
    source_sha256: fields.sourceHashes,
    profile: profileFor(candidate),
    execution: executionProfile(fields.concurrency),
  };
  return deepFreeze({ ...content, manifest_hash: hashCanonical(content) });
}

function failureCode(reason) {
  const fixed = new Map([
    ['invalid judge client configuration', 'invalid_configuration'],
    ['invalid judge request', 'invalid_request'],
    ['invalid judge response', 'invalid_response'],
    ['request failed', 'request_failed'],
    ['request timed out', 'request_timed_out'],
  ]).get(reason);
  if (fixed !== undefined) return fixed;
  const match = typeof reason === 'string' ? /^http ([1-5][0-9]{2})$/u.exec(reason) : null;
  return match === null ? 'request_failed' : `http_${match[1]}`;
}

function usageSnapshot(value) {
  if (value === null) return null;
  try {
    const fields = exactDataValues(value, [
      'promptTokens', 'completionTokens', 'totalTokens',
      'reasoningTokens', 'cachedPromptTokens',
    ]);
    if (!Number.isSafeInteger(fields.promptTokens) || fields.promptTokens < 0
      || !Number.isSafeInteger(fields.completionTokens) || fields.completionTokens < 0
      || !Number.isSafeInteger(fields.totalTokens) || fields.totalTokens < 0
      || fields.promptTokens + fields.completionTokens !== fields.totalTokens) return null;
    for (const key of ['reasoningTokens', 'cachedPromptTokens']) {
      if (fields[key] !== null && (!Number.isSafeInteger(fields[key]) || fields[key] < 0)) {
        return null;
      }
    }
    if ((fields.reasoningTokens ?? 0) > fields.completionTokens
      || (fields.cachedPromptTokens ?? 0) > fields.promptTokens) return null;
    return Object.freeze(fields);
  } catch {
    return null;
  }
}

function safeLatency(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0;
}

function rationaleHash(value) {
  return 'sha256:' + createHash('sha256').update(value, 'utf8').digest('hex');
}

function attemptBase({ caseData, manifest }) {
  const tuple = {
    manifest_hash: manifest.manifest_hash,
    model: manifest.candidate.model_id,
    case_id: caseData.id,
    repeat: 1,
    profile: manifest.profile.name,
  };
  return {
    resume_key: makeResumeKey(tuple),
    manifest_hash: manifest.manifest_hash,
    model: manifest.candidate.model_id,
    profile: manifest.profile.name,
    case_id: caseData.id,
    family_id: caseData.family_id,
    split: caseData.split,
    repeat: 1,
    oracle_disposition: caseData.preferred_disposition,
    auto_allow_permitted: caseData.auto_allow_permitted,
    oracle_risk: caseData.intrinsic_risk,
    oracle_authorization: caseData.authorization,
    impact_tier: caseData.impact_tier,
    tags: caseData.tags.slice(),
  };
}

function failureAttempt(context, {
  stage,
  code,
  latencyMs = 0,
  usage = null,
}) {
  return deepFreeze({
    ...attemptBase(context),
    raw_decision: null,
    raw_risk: null,
    raw_authorization: null,
    confidence: null,
    normalized_kind: 'failure',
    autonomous_outcome: 'blocked',
    supervised_outcome: 'sent_to_human',
    schema_valid: false,
    failure_stage: stage,
    failure_code: code,
    latency_ms: safeLatency(latencyMs),
    usage: usageSnapshot(usage),
    rationale_sha256: null,
  });
}

function normalizerFailureAttempt(context, verdict, response) {
  return deepFreeze({
    ...attemptBase(context),
    raw_decision: verdict.decision,
    raw_risk: verdict.risk,
    raw_authorization: verdict.authorization,
    confidence: verdict.confidence,
    normalized_kind: 'failure',
    autonomous_outcome: 'blocked',
    supervised_outcome: 'sent_to_human',
    schema_valid: true,
    failure_stage: 'normalizer',
    failure_code: 'normalizer_failure',
    latency_ms: safeLatency(response.latencyMs),
    usage: usageSnapshot(response.usage),
    rationale_sha256: rationaleHash(verdict.rationale),
  });
}

async function evaluateSelectionAttempt({ reviewer, caseData, manifest }) {
  const input = createCaseInput(caseData);
  let response;
  try {
    response = await reviewer.review(input);
  } catch {
    return failureAttempt({ caseData, manifest }, {
      stage: 'reviewer',
      code: 'reviewer_failure',
    });
  }
  if (response?.ok !== true) {
    return failureAttempt({ caseData, manifest }, {
      stage: 'transport',
      code: failureCode(response?.reason),
      latencyMs: response?.latencyMs,
    });
  }
  const parsed = parseJudgeResponse(response.text, {
    expectedHash: input.envelope.action_hash,
  });
  if (!parsed.ok) {
    return failureAttempt({ caseData, manifest }, {
      stage: 'parser',
      code: 'parser_failure',
      latencyMs: response.latencyMs,
      usage: response.usage,
    });
  }

  try {
    const normalized = applyLocalSafetyDowngrade(
      applyOpaqueDowngrade(normalizeVerdict(parsed.verdict), input.envelope.params),
      input.envelope.tool_name,
      input.envelope.params,
    );
    const autonomous = mapVerdict({
      mode: 'autonomous',
      enforcement: 'enforce',
      result: normalized,
      params: input.envelope.params,
    });
    const autonomousOutcome = autonomous?.block === true
      ? 'blocked'
      : 'executed_without_human';
    const supervisedOutcome = normalized.kind === 'allow'
      ? 'executed_without_human'
      : normalized.kind === 'deny' ? 'blocked' : 'sent_to_human';
    if ((normalized.kind === 'allow' && autonomousOutcome !== 'executed_without_human')
      || (normalized.kind !== 'allow' && autonomousOutcome !== 'blocked')) invalidInput();
    return deepFreeze({
      ...attemptBase({ caseData, manifest }),
      raw_decision: parsed.verdict.decision,
      raw_risk: parsed.verdict.risk,
      raw_authorization: parsed.verdict.authorization,
      confidence: parsed.verdict.confidence,
      normalized_kind: normalized.kind,
      autonomous_outcome: autonomousOutcome,
      supervised_outcome: supervisedOutcome,
      schema_valid: true,
      failure_stage: null,
      failure_code: null,
      latency_ms: safeLatency(response.latencyMs),
      usage: usageSnapshot(response.usage),
      rationale_sha256: rationaleHash(parsed.verdict.rationale),
    });
  } catch {
    return normalizerFailureAttempt(
      { caseData, manifest },
      parsed.verdict,
      response,
    );
  }
}

export async function runCandidateSelection(options) {
  const fields = snapshotOptions(options);
  const selected = fields.eligibleCandidateIds.map((id) => (
    fields.plan.candidates.find((candidate) => candidate.id === id)
  ));
  const common = Object.freeze({
    planSha256: hashCanonical(fields.plan),
    corpusSha256: corpusHash(fields.cases),
    pricingSha256: hashCanonical(fields.pricing),
  });
  const profile = profileFor(selected[0]);
  const execution = executionProfile(fields.concurrency);
  const checkpointBinding = buildSelectionCheckpointBinding({
    officialPreflightArtifactSha256: fields.officialPreflightArtifactSha256,
    preflightSha256: fields.preflightSha256,
    planSha256: common.planSha256,
    corpusSha256: common.corpusSha256,
    pricingSha256: common.pricingSha256,
    sourceSha256: fields.sourceHashes,
    gitSha: fields.gitSha,
    nodeVersion: fields.nodeVersion,
    openclawVersion: fields.openclawVersion,
    policyVersion: POLICY_VERSION,
    profile,
    execution,
  });
  const manifests = selected.map((candidate) => buildRunManifest(fields, candidate, common));
  const candidates = new Array(selected.length);
  const completedIds = new Set();
  for (const rawCheckpoint of fields.completedCheckpoints) {
    let match = null;
    let matchIndex = -1;
    for (let index = 0; index < selected.length; index += 1) {
      try {
        match = validateSelectionCheckpoint(rawCheckpoint, {
          expectedBinding: checkpointBinding,
          pricing: fields.pricing,
          cases: fields.cases,
          expectedCandidateId: selected[index].id,
        });
        matchIndex = index;
        break;
      } catch {
        // A checkpoint can match only one exact candidate in the attested plan.
      }
    }
    if (match === null || completedIds.has(match.candidate_id)) invalidInput();
    const candidateResult = validateSelectionCandidateResult(match.candidate_result, {
      expectedManifest: manifests[matchIndex],
      pricing: fields.pricing,
      cases: fields.cases,
    });
    completedIds.add(match.candidate_id);
    candidates[matchIndex] = candidateResult;
  }
  let cursor = 0;
  let aborted = false;

  async function worker() {
    while (!aborted && cursor < selected.length) {
      const index = cursor;
      cursor += 1;
      if (candidates[index] !== undefined) continue;
      const candidate = selected[index];
      const manifest = manifests[index];
      const reviewer = createCandidateJudgeClient({
        candidate,
        apiKey: fields.providerSecrets[candidate.endpoint_profile],
        fetchImpl: fields.fetchImpl,
      });
      const attempts = [];
      for (const caseData of fields.cases) {
        attempts.push(await evaluateSelectionAttempt({ reviewer, caseData, manifest }));
      }
      const aggregate = aggregateQualification({
        attempts,
        expectedRepeats: 1,
        pricing: fields.aggregatePricing,
      });
      const candidateResult = deepFreeze({
        manifest,
        attempts,
        summary: aggregate.summary,
        case_outcomes: aggregate.caseOutcomes,
        family_outcomes: aggregate.familyOutcomes,
      });
      const checkpoint = createSelectionCheckpoint({
        binding: checkpointBinding,
        candidateResult,
        pricing: fields.pricing,
        cases: fields.cases,
      });
      try {
        await fields.onCheckpoint(checkpoint);
      } catch {
        aborted = true;
        throw new TypeError('candidate selection checkpoint failed');
      }
      candidates[index] = checkpoint.candidate_result;
    }
  }

  const workerResults = await Promise.allSettled(Array.from(
    { length: Math.min(fields.concurrency, selected.length) },
    () => worker(),
  ));
  if (workerResults.some((result) => result.status === 'rejected')
    || candidates.some((candidate) => candidate === undefined)) invalidInput();
  const ranking = rankSelectionCandidates(candidates.map((item) => ({
    candidate_id: item.manifest.candidate.id,
    model_id: item.manifest.candidate.model_id,
    summary: item.summary,
  })));
  return deepFreeze({
    schema_version: 'judge-candidate-selection.v1',
    git_sha: fields.gitSha,
    node_version: fields.nodeVersion,
    openclaw_version: fields.openclawVersion,
    policy_version: POLICY_VERSION,
    plan_sha256: common.planSha256,
    preflight_sha256: fields.preflightSha256,
    official_preflight_artifact_sha256: fields.officialPreflightArtifactSha256,
    official_preflight_attestation_sha256: fields.officialPreflightAttestationSha256,
    corpus_sha256: common.corpusSha256,
    pricing_sha256: common.pricingSha256,
    source_sha256: fields.sourceHashes,
    profile,
    execution,
    eligible_candidate_ids: fields.eligibleCandidateIds,
    candidates,
    ranking,
  });
}
