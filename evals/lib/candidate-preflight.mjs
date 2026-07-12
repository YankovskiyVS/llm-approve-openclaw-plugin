import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { parseJudgeResponse, normalizeVerdict } from '../../src/decision.js';
import { createCaseInput } from './case-input.mjs';
import { createCandidateJudgeClient } from './candidate-client.mjs';
import { validateCandidatePlan } from './candidate-plan.mjs';
import { corpusHash, lintCorpus } from './corpus.mjs';

const OPTION_KEYS = Object.freeze([
  'plan',
  'cases',
  'providerSecrets',
  'fetchImpl',
  'concurrency',
  'gitSha',
  'nodeVersion',
  'openclawVersion',
  'sourceHashes',
]);
const PROVIDER_KEYS = Object.freeze(['cloudru-fm', 'qwen-vllm']);
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
  'preflight',
]);
const ANCHOR_IDS = Object.freeze([
  'ms-c001-p01-allow',
  'ms-c001-p06-allow',
  'ms-c001-p01-block',
  'ms-c001-q04',
  'ms-c001-q08',
  'ms-c001-q06',
]);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const GIT_PATTERN = /^[0-9a-f]{40}$/u;
const NODE_PATTERN = /^v([0-9]+)\.([0-9]+)\.([0-9]+)$/u;
const OPENCLAW_PATTERN = /^([0-9]{4})\.([0-9]{1,2})\.([0-9]{1,2})$/u;

function invalidInput() {
  throw new TypeError('invalid candidate preflight input');
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

function hashCanonical(value) {
  return 'sha256:' + createHash('sha256')
    .update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function snapshotSecrets(value) {
  const fields = exactDataValues(value, PROVIDER_KEYS);
  for (const key of PROVIDER_KEYS) {
    if (typeof fields[key] !== 'string' || fields[key].trim() === '') invalidInput();
  }
  return Object.freeze(fields);
}

function snapshotSourceHashes(value) {
  const fields = exactDataValues(value, SOURCE_KEYS);
  for (const key of SOURCE_KEYS) {
    if (typeof fields[key] !== 'string' || !HASH_PATTERN.test(fields[key])) invalidInput();
  }
  return Object.freeze(fields);
}

function validateNodeVersion(value) {
  if (typeof value !== 'string') invalidInput();
  const match = NODE_PATTERN.exec(value);
  if (match === null) invalidInput();
  const [major, minor] = match.slice(1, 3).map(Number);
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor)
    || major < 22 || (major === 22 && minor < 19)) invalidInput();
}

function validateOpenClawVersion(value) {
  if (typeof value !== 'string') invalidInput();
  const match = OPENCLAW_PATTERN.exec(value);
  if (match === null) invalidInput();
  const [year, month, day] = match.slice(1).map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day || year < 2026
    || (year === 2026 && (month < 6 || (month === 6 && day < 11)))) invalidInput();
}

function snapshotOptions(value) {
  const fields = exactDataValues(value, OPTION_KEYS);
  let plan;
  let cases;
  try {
    plan = validateCandidatePlan(fields.plan);
    cases = lintCorpus(fields.cases);
  } catch {
    invalidInput();
  }
  if (cases.length !== ANCHOR_IDS.length
    || cases.some((item, index) => item.id !== ANCHOR_IDS[index]
      || item.split !== 'model-selection')) invalidInput();
  const providerSecrets = snapshotSecrets(fields.providerSecrets);
  const sourceHashes = snapshotSourceHashes(fields.sourceHashes);
  if (typeof fields.fetchImpl !== 'function' || types.isProxy(fields.fetchImpl)
    || fields.concurrency !== 4
    || typeof fields.gitSha !== 'string' || !GIT_PATTERN.test(fields.gitSha)) invalidInput();
  validateNodeVersion(fields.nodeVersion);
  validateOpenClawVersion(fields.openclawVersion);
  return Object.freeze({
    plan,
    cases,
    providerSecrets,
    fetchImpl: fields.fetchImpl,
    concurrency: fields.concurrency,
    gitSha: fields.gitSha,
    nodeVersion: fields.nodeVersion,
    openclawVersion: fields.openclawVersion,
    sourceHashes,
  });
}

function failureCode(reason) {
  if (reason === 'invalid judge client configuration') return 'invalid_configuration';
  if (reason === 'invalid judge request') return 'invalid_request';
  if (reason === 'invalid judge response') return 'invalid_response';
  if (reason === 'request timed out') return 'request_timed_out';
  if (reason === 'request failed') return 'request_failed';
  const match = typeof reason === 'string' ? /^http ([1-5][0-9]{2})$/u.exec(reason) : null;
  return match === null ? 'request_failed' : `http_${match[1]}`;
}

function rationaleHash(value) {
  return 'sha256:' + createHash('sha256').update(value, 'utf8').digest('hex');
}

function safeLatency(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0;
}

async function runAnchor({ reviewer, caseData }) {
  const input = createCaseInput(caseData);
  const transport = await reviewer.review(input);
  if (transport.ok !== true) {
    const code = failureCode(transport.reason);
    return deepFreeze({
      case_id: caseData.id,
      oracle_disposition: caseData.preferred_disposition,
      transport_status: code === 'invalid_response' ? 'ok' : 'failure',
      schema_valid: false,
      raw_verdict: null,
      normalized_verdict: null,
      oracle_match: false,
      failure_code: code,
      latency_ms: safeLatency(transport.latencyMs),
      usage: null,
      rationale_sha256: null,
    });
  }

  const parsed = parseJudgeResponse(transport.text, {
    expectedHash: input.envelope.action_hash,
  });
  if (!parsed.ok) {
    return deepFreeze({
      case_id: caseData.id,
      oracle_disposition: caseData.preferred_disposition,
      transport_status: 'ok',
      schema_valid: false,
      raw_verdict: null,
      normalized_verdict: null,
      oracle_match: false,
      failure_code: 'invalid_schema',
      latency_ms: safeLatency(transport.latencyMs),
      usage: transport.usage,
      rationale_sha256: null,
    });
  }

  const normalized = normalizeVerdict(parsed.verdict);
  return deepFreeze({
    case_id: caseData.id,
    oracle_disposition: caseData.preferred_disposition,
    transport_status: 'ok',
    schema_valid: true,
    raw_verdict: Object.freeze({
      decision: parsed.verdict.decision,
      risk: parsed.verdict.risk,
      authorization: parsed.verdict.authorization,
      confidence: parsed.verdict.confidence,
    }),
    normalized_verdict: Object.freeze({ kind: normalized.kind }),
    oracle_match: parsed.verdict.decision === caseData.preferred_disposition,
    failure_code: null,
    latency_ms: safeLatency(transport.latencyMs),
    usage: transport.usage,
    rationale_sha256: rationaleHash(parsed.verdict.rationale),
  });
}

function candidateResult(candidate, anchors) {
  const transportOkCount = anchors.filter((item) => item.transport_status === 'ok').length;
  const schemaValidCount = anchors.filter((item) => item.schema_valid).length;
  const oracleMatchCount = anchors.filter((item) => item.oracle_match).length;
  return deepFreeze({
    candidate_id: candidate.id,
    model_id: candidate.model_id,
    endpoint_profile: candidate.endpoint_profile,
    response_profile: candidate.response_profile,
    capability_status: schemaValidCount === anchors.length ? 'pass' : 'fail',
    anchor_count: anchors.length,
    transport_ok_count: transportOkCount,
    schema_valid_count: schemaValidCount,
    oracle_match_count: oracleMatchCount,
    anchors,
  });
}

export async function runCandidatePreflight(options) {
  const fields = snapshotOptions(options);
  const candidates = new Array(fields.plan.candidates.length);
  let cursor = 0;

  async function worker() {
    while (cursor < fields.plan.candidates.length) {
      const index = cursor;
      cursor += 1;
      const candidate = fields.plan.candidates[index];
      const reviewer = createCandidateJudgeClient({
        candidate,
        apiKey: fields.providerSecrets[candidate.endpoint_profile],
        fetchImpl: fields.fetchImpl,
      });
      const anchors = [];
      for (const caseData of fields.cases) {
        anchors.push(await runAnchor({ reviewer, caseData }));
      }
      candidates[index] = candidateResult(candidate, anchors);
    }
  }

  await Promise.all(Array.from(
    { length: Math.min(fields.concurrency, fields.plan.candidates.length) },
    () => worker(),
  ));

  const first = fields.plan.candidates[0];
  return deepFreeze({
    schema_version: 'judge-candidate-preflight.v1',
    git_sha: fields.gitSha,
    node_version: fields.nodeVersion,
    openclaw_version: fields.openclawVersion,
    plan_sha256: hashCanonical(fields.plan),
    corpus_sha256: corpusHash(fields.cases),
    source_sha256: fields.sourceHashes,
    profile: {
      temperature: first.temperature,
      max_tokens: first.max_tokens,
      max_reasoning_tokens: first.max_reasoning_tokens,
      thinking: first.thinking,
      response_format: first.response_format,
      timeout_ms: first.timeout_ms,
    },
    execution: {
      candidate_concurrency: fields.concurrency,
      anchors_per_candidate: 'sequential',
    },
    candidates,
  });
}
