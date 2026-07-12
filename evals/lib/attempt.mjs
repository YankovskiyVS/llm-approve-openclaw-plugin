import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { POLICY_VERSION } from '../../src/constants.js';
import {
  applyLocalSafetyDowngrade,
  applyOpaqueDowngrade,
  mapVerdict,
  normalizeVerdict,
  parseJudgeResponse,
} from '../../src/decision.js';
import { validateCase } from './case-schema.mjs';
import { createCaseInput } from './case-input.mjs';
import { buildManifest, makeResumeKey } from './manifest.mjs';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const HTTP_REASON_PATTERN = /^http ([1-5][0-9]{2})$/u;
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
const MANIFEST_KEYS = Object.freeze([
  'schema_version', 'git_sha', 'node_version', 'openclaw_version',
  'model_id', 'policy_version', 'corpus_sha256', 'pricing_sha256',
  'source_sha256', 'endpoint_origin', 'profile', 'manifest_hash',
]);
const OPTION_KEYS = Object.freeze(['reviewer', 'caseData', 'manifest', 'repeat']);
const DECISIONS = new Set(['allow', 'deny', 'review']);
const RISKS = new Set(['low', 'medium', 'high', 'critical']);
const AUTHORIZATIONS = new Set(['unknown', 'low', 'medium', 'high']);
const NORMALIZED_KINDS = new Set(['allow', 'deny', 'review', 'failure']);
const TRANSPORT_CODES = new Set([
  'invalid_configuration',
  'invalid_request',
  'invalid_response',
  'request_failed',
  'request_timed_out',
]);
const CLIENT_REASON_CODES = new Map([
  ['invalid judge client configuration', 'invalid_configuration'],
  ['invalid judge request', 'invalid_request'],
  ['invalid judge response', 'invalid_response'],
  ['request failed', 'request_failed'],
  ['request timed out', 'request_timed_out'],
]);

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

function dataField(source, key) {
  try {
    if (source === null || typeof source !== 'object' || types.isProxy(source)) {
      return { safe: false, present: false, value: undefined };
    }
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (!descriptor) return { safe: true, present: false, value: undefined };
    if (!Object.hasOwn(descriptor, 'value')) {
      return { safe: false, present: true, value: undefined };
    }
    return { safe: true, present: true, value: descriptor.value };
  } catch {
    return { safe: false, present: false, value: undefined };
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function snapshotManifest(value) {
  const fields = exactDataValues(value, MANIFEST_KEYS, 'invalid attempt manifest');
  const rebuilt = buildManifest({
    schema_version: fields.schema_version,
    git_sha: fields.git_sha,
    node_version: fields.node_version,
    openclaw_version: fields.openclaw_version,
    model_id: fields.model_id,
    policy_version: fields.policy_version,
    corpus_sha256: fields.corpus_sha256,
    pricing_sha256: fields.pricing_sha256,
    source_sha256: fields.source_sha256,
    endpoint_origin: fields.endpoint_origin,
    profile: fields.profile,
  });
  if (fields.policy_version !== POLICY_VERSION
    || fields.manifest_hash !== rebuilt.manifest_hash) {
    throw new TypeError('invalid attempt manifest');
  }
  return rebuilt;
}

export function snapshotAttemptManifest(value) {
  return snapshotManifest(value);
}

function snapshotContext({ caseData, manifest, repeat }) {
  if (!Number.isInteger(repeat) || repeat < 1 || repeat > 10) {
    throw new TypeError('invalid attempt repeat');
  }
  const item = validateCase(caseData);
  const manifestValue = snapshotManifest(manifest);
  const tuple = {
    manifest_hash: manifestValue.manifest_hash,
    model: manifestValue.model_id,
    case_id: item.id,
    repeat,
    profile: manifestValue.profile.name,
  };
  return {
    item,
    manifest: manifestValue,
    repeat,
    resumeKey: makeResumeKey(tuple),
  };
}

export function attemptIdentity({ caseData, manifest, repeat }) {
  const context = snapshotContext({ caseData, manifest, repeat });
  return Object.freeze({
    resume_key: context.resumeKey,
    manifest_hash: context.manifest.manifest_hash,
    model: context.manifest.model_id,
    profile: context.manifest.profile.name,
    case_id: context.item.id,
    repeat: context.repeat,
  });
}

function methodValue(source, name) {
  try {
    if (source === null || (typeof source !== 'object' && typeof source !== 'function')
      || types.isProxy(source)) return null;
    const seen = new Set();
    let current = source;
    while (current !== null && !seen.has(current)) {
      if (types.isProxy(current)) return null;
      seen.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, name);
      if (descriptor) {
        return Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function'
          ? descriptor.value
          : null;
      }
      current = Object.getPrototypeOf(current);
    }
  } catch {
    // Hostile reviewer objects are normalized by the caller.
  }
  return null;
}

function optionalTokenField(source, key) {
  const field = dataField(source, key);
  if (!field.safe) return { valid: false, value: null };
  if (!field.present || field.value === null) return { valid: true, value: null };
  if (!Number.isSafeInteger(field.value) || field.value < 0) {
    return { valid: false, value: null };
  }
  return { valid: true, value: field.value };
}

function sanitizeUsage(value, { exact = false } = {}) {
  try {
    if (value === null) return { valid: true, value: null };
    if (typeof value !== 'object' || Array.isArray(value) || types.isProxy(value)) {
      return { valid: false, value: null };
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      return { valid: false, value: null };
    }
    if (exact) {
      const expected = new Set([
        'promptTokens',
        'completionTokens',
        'totalTokens',
        'reasoningTokens',
        'cachedPromptTokens',
      ]);
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const keys = Reflect.ownKeys(descriptors);
      if (keys.length !== expected.size || keys.some((key) => (
        typeof key !== 'string'
        || !expected.has(key)
        || !descriptors[key].enumerable
        || !Object.hasOwn(descriptors[key], 'value')
      ))) return { valid: false, value: null };
    }

    const prompt = dataField(value, 'promptTokens');
    const completion = dataField(value, 'completionTokens');
    const total = dataField(value, 'totalTokens');
    if (!prompt.safe || !completion.safe || !total.safe
      || !Number.isSafeInteger(prompt.value) || prompt.value < 0
      || !Number.isSafeInteger(completion.value) || completion.value < 0
      || !Number.isSafeInteger(total.value) || total.value < 0
      || prompt.value + completion.value !== total.value) {
      return { valid: false, value: null };
    }

    const reasoning = optionalTokenField(value, 'reasoningTokens');
    const cached = optionalTokenField(value, 'cachedPromptTokens');
    if (!reasoning.valid || !cached.valid
      || (reasoning.value !== null && reasoning.value > completion.value)
      || (cached.value !== null && cached.value > prompt.value)) {
      return { valid: false, value: null };
    }
    return {
      valid: true,
      value: Object.freeze({
        promptTokens: prompt.value,
        completionTokens: completion.value,
        totalTokens: total.value,
        reasoningTokens: reasoning.value,
        cachedPromptTokens: cached.value,
      }),
    };
  } catch {
    return { valid: false, value: null };
  }
}

function safeLatency(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0;
}

function responseSnapshot(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;

    const ok = dataField(value, 'ok');
    if (!ok.safe) return null;
    const latency = dataField(value, 'latencyMs');
    const latencyMs = latency.safe ? safeLatency(latency.value) : 0;

    if (ok.value === true) {
      const text = dataField(value, 'text');
      if (!text.safe) return null;
      const usage = dataField(value, 'usage');
      const usageValue = usage.safe ? sanitizeUsage(usage.value).value : null;
      return { ok: true, text: text.value, latencyMs, usage: usageValue };
    }

    const reason = dataField(value, 'reason');
    if (!reason.safe) return null;
    return {
      ok: false,
      reason: typeof reason.value === 'string' ? reason.value : null,
      latencyMs,
      usage: null,
    };
  } catch {
    return null;
  }
}

function invokeThenable(value, then) {
  return new Promise((resolve, reject) => {
    try {
      then.call(value, resolve, reject);
    } catch (error) {
      reject(error);
    }
  });
}

async function callReviewer(reviewer, input, timeoutMs) {
  const review = methodValue(reviewer, 'review');
  if (review === null) return null;
  const timeoutMarker = Object.freeze({ timeout: true });
  let timer;
  try {
    const deadline = new Promise((resolve) => {
      timer = setTimeout(() => resolve(timeoutMarker), timeoutMs);
    });
    const value = review.call(reviewer, input);
    let pending;
    if (types.isPromise(value)) {
      pending = value;
    } else {
      const then = methodValue(value, 'then');
      if (then === null) return responseSnapshot(value);
      pending = invokeThenable(value, then);
    }

    const settled = await Promise.race([pending, deadline]);
    if (settled === timeoutMarker) {
      return Object.freeze({
        ok: false,
        reason: 'request timed out',
        latencyMs: timeoutMs,
        usage: null,
      });
    }
    return responseSnapshot(settled);
  } catch {
    return null;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function failureCode(reason) {
  const fixed = CLIENT_REASON_CODES.get(reason);
  if (fixed !== undefined) return fixed;
  if (typeof reason === 'string') {
    const match = HTTP_REASON_PATTERN.exec(reason);
    if (match !== null) return `http_${match[1]}`;
  }
  return 'request_failed';
}

function hashRationale(value) {
  return 'sha256:' + createHash('sha256').update(value, 'utf8').digest('hex');
}

function outcomesFor(kind, autonomous) {
  const autonomousOutcome = autonomous?.block === true
    ? 'blocked'
    : 'executed_without_human';
  let supervisedOutcome;
  if (kind === 'allow') supervisedOutcome = 'executed_without_human';
  else if (kind === 'deny') supervisedOutcome = 'blocked';
  else supervisedOutcome = 'sent_to_human';
  return { autonomousOutcome, supervisedOutcome };
}

function buildAttempt(context, {
  verdict = null,
  normalizedKind,
  autonomousOutcome,
  supervisedOutcome,
  schemaValid,
  failureStage = null,
  failureCode = null,
  latencyMs = 0,
  usage = null,
}) {
  const { item, manifest, repeat, resumeKey } = context;
  return deepFreeze({
    resume_key: resumeKey,
    manifest_hash: manifest.manifest_hash,
    model: manifest.model_id,
    profile: manifest.profile.name,
    case_id: item.id,
    family_id: item.family_id,
    split: item.split,
    repeat,
    oracle_disposition: item.preferred_disposition,
    auto_allow_permitted: item.auto_allow_permitted,
    oracle_risk: item.intrinsic_risk,
    oracle_authorization: item.authorization,
    impact_tier: item.impact_tier,
    tags: item.tags.slice(),
    raw_decision: verdict?.decision ?? null,
    raw_risk: verdict?.risk ?? null,
    raw_authorization: verdict?.authorization ?? null,
    confidence: verdict?.confidence ?? null,
    normalized_kind: normalizedKind,
    autonomous_outcome: autonomousOutcome,
    supervised_outcome: supervisedOutcome,
    schema_valid: schemaValid,
    failure_stage: failureStage,
    failure_code: failureCode,
    latency_ms: safeLatency(latencyMs),
    usage,
    rationale_sha256: verdict === null ? null : hashRationale(verdict.rationale),
  });
}

function failureAttempt(context, {
  stage,
  code,
  latencyMs = 0,
  usage = null,
  verdict = null,
  schemaValid = false,
}) {
  return buildAttempt(context, {
    verdict,
    normalizedKind: 'failure',
    autonomousOutcome: 'blocked',
    supervisedOutcome: 'sent_to_human',
    schemaValid,
    failureStage: stage,
    failureCode: code,
    latencyMs,
    usage,
  });
}

function snapshotStringArray(value) {
  try {
    if (!Array.isArray(value) || types.isProxy(value)
      || Object.getOwnPropertySymbols(value).length !== 0
      || Object.getOwnPropertyNames(value).length !== value.length + 1) return null;
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'string') return null;
      result.push(descriptor.value);
    }
    return result;
  } catch {
    return null;
  }
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function validHttpCode(value) {
  return typeof value === 'string' && /^http_[1-5][0-9]{2}$/u.test(value);
}

function failureFieldsAreConsistent(fields) {
  if (fields.failure_stage === null || fields.failure_code === null) {
    return fields.failure_stage === null && fields.failure_code === null
      && fields.schema_valid === true
      && fields.normalized_kind !== 'failure';
  }
  if (fields.normalized_kind !== 'failure') return false;
  if (fields.failure_stage === 'reviewer') {
    return fields.failure_code === 'reviewer_failure' && fields.schema_valid === false;
  }
  if (fields.failure_stage === 'parser') {
    return fields.failure_code === 'parser_failure' && fields.schema_valid === false;
  }
  if (fields.failure_stage === 'normalizer') {
    return fields.failure_code === 'normalizer_failure' && fields.schema_valid === true;
  }
  if (fields.failure_stage === 'transport') {
    return (TRANSPORT_CODES.has(fields.failure_code) || validHttpCode(fields.failure_code))
      && fields.schema_valid === false;
  }
  return false;
}

function verdictFieldsAreConsistent(fields) {
  const rawValues = [
    fields.raw_decision,
    fields.raw_risk,
    fields.raw_authorization,
    fields.confidence,
    fields.rationale_sha256,
  ];
  if (!fields.schema_valid) return rawValues.every((value) => value === null);
  if (!DECISIONS.has(fields.raw_decision)
    || !RISKS.has(fields.raw_risk)
    || !AUTHORIZATIONS.has(fields.raw_authorization)
    || typeof fields.confidence !== 'number'
    || !Number.isFinite(fields.confidence)
    || fields.confidence < 0
    || fields.confidence > 1
    || typeof fields.rationale_sha256 !== 'string'
    || !HASH_PATTERN.test(fields.rationale_sha256)) return false;
  if (fields.normalized_kind === 'failure') return fields.failure_stage === 'normalizer';
  if (fields.raw_decision === 'deny') return fields.normalized_kind === 'deny';
  if (fields.raw_decision === 'review') return fields.normalized_kind === 'review';
  return fields.normalized_kind === 'allow' || fields.normalized_kind === 'review';
}

function outcomeFieldsAreConsistent(fields) {
  if (fields.normalized_kind === 'allow') {
    return fields.autonomous_outcome === 'executed_without_human'
      && fields.supervised_outcome === 'executed_without_human';
  }
  if (fields.normalized_kind === 'deny') {
    return fields.autonomous_outcome === 'blocked'
      && fields.supervised_outcome === 'blocked';
  }
  return fields.autonomous_outcome === 'blocked'
    && fields.supervised_outcome === 'sent_to_human';
}

function productionKindIsConsistent(fields, context) {
  if (!fields.schema_valid || fields.failure_stage === 'normalizer') return true;
  const input = createCaseInput(context.item);
  const verdict = {
    policy_version: POLICY_VERSION,
    action_hash: input.envelope.action_hash,
    decision: fields.raw_decision,
    risk: fields.raw_risk,
    authorization: fields.raw_authorization,
    confidence: fields.confidence,
    rationale: 'Validated resumed rationale hash.',
  };
  const expected = applyLocalSafetyDowngrade(
    applyOpaqueDowngrade(normalizeVerdict(verdict), input.envelope.params),
    input.envelope.tool_name,
    input.envelope.params,
  );
  return expected.kind === fields.normalized_kind;
}

export function snapshotCompletedAttempt(value, { caseData, manifest, repeat }) {
  try {
    const context = snapshotContext({ caseData, manifest, repeat });
    const fields = exactDataValues(value, ATTEMPT_KEYS, 'invalid completed attempt');
    if (fields.failure_stage === 'normalizer') return null;
    const tags = snapshotStringArray(fields.tags);
    const usage = sanitizeUsage(fields.usage, { exact: true });
    if (fields.resume_key !== context.resumeKey
      || fields.manifest_hash !== context.manifest.manifest_hash
      || fields.model !== context.manifest.model_id
      || fields.profile !== context.manifest.profile.name
      || fields.case_id !== context.item.id
      || fields.family_id !== context.item.family_id
      || fields.split !== context.item.split
      || fields.repeat !== context.repeat
      || fields.oracle_disposition !== context.item.preferred_disposition
      || fields.auto_allow_permitted !== context.item.auto_allow_permitted
      || fields.oracle_risk !== context.item.intrinsic_risk
      || fields.oracle_authorization !== context.item.authorization
      || fields.impact_tier !== context.item.impact_tier
      || tags === null
      || !arraysEqual(tags, context.item.tags)
      || !NORMALIZED_KINDS.has(fields.normalized_kind)
      || typeof fields.schema_valid !== 'boolean'
      || typeof fields.latency_ms !== 'number'
      || !Number.isFinite(fields.latency_ms)
      || fields.latency_ms < 0
      || !usage.valid
      || !failureFieldsAreConsistent(fields)
      || !verdictFieldsAreConsistent(fields)
      || !productionKindIsConsistent(fields, context)
      || !outcomeFieldsAreConsistent(fields)) return null;

    if ((fields.failure_stage === 'reviewer' || fields.failure_stage === 'transport')
      && usage.value !== null) return null;

    return deepFreeze({
      resume_key: fields.resume_key,
      manifest_hash: fields.manifest_hash,
      model: fields.model,
      profile: fields.profile,
      case_id: fields.case_id,
      family_id: fields.family_id,
      split: fields.split,
      repeat: fields.repeat,
      oracle_disposition: fields.oracle_disposition,
      auto_allow_permitted: fields.auto_allow_permitted,
      oracle_risk: fields.oracle_risk,
      oracle_authorization: fields.oracle_authorization,
      impact_tier: fields.impact_tier,
      tags,
      raw_decision: fields.raw_decision,
      raw_risk: fields.raw_risk,
      raw_authorization: fields.raw_authorization,
      confidence: fields.confidence,
      normalized_kind: fields.normalized_kind,
      autonomous_outcome: fields.autonomous_outcome,
      supervised_outcome: fields.supervised_outcome,
      schema_valid: fields.schema_valid,
      failure_stage: fields.failure_stage,
      failure_code: fields.failure_code,
      latency_ms: fields.latency_ms,
      usage: usage.value,
      rationale_sha256: fields.rationale_sha256,
    });
  } catch {
    return null;
  }
}

export async function evaluateAttempt(options) {
  const fields = exactDataValues(options, OPTION_KEYS, 'invalid attempt options');
  const context = snapshotContext({
    caseData: fields.caseData,
    manifest: fields.manifest,
    repeat: fields.repeat,
  });
  const input = createCaseInput(context.item);
  const response = await callReviewer(
    fields.reviewer,
    input,
    context.manifest.profile.timeout_ms,
  );
  if (response === null) {
    return failureAttempt(context, { stage: 'reviewer', code: 'reviewer_failure' });
  }
  if (!response.ok) {
    return failureAttempt(context, {
      stage: 'transport',
      code: failureCode(response.reason),
      latencyMs: response.latencyMs,
    });
  }

  const parsed = parseJudgeResponse(response.text, {
    expectedHash: input.envelope.action_hash,
  });
  if (!parsed.ok) {
    return failureAttempt(context, {
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
    if (normalized === null || typeof normalized !== 'object'
      || !NORMALIZED_KINDS.has(normalized.kind) || normalized.kind === 'failure') {
      throw new TypeError('normalizer failure');
    }
    const autonomous = mapVerdict({
      mode: 'autonomous',
      enforcement: 'enforce',
      result: normalized,
      params: input.envelope.params,
    });
    const outcomes = outcomesFor(normalized.kind, autonomous);
    if ((normalized.kind === 'allow' && outcomes.autonomousOutcome !== 'executed_without_human')
      || (normalized.kind !== 'allow' && outcomes.autonomousOutcome !== 'blocked')) {
      throw new TypeError('mapping failure');
    }
    return buildAttempt(context, {
      verdict: parsed.verdict,
      normalizedKind: normalized.kind,
      autonomousOutcome: outcomes.autonomousOutcome,
      supervisedOutcome: outcomes.supervisedOutcome,
      schemaValid: true,
      latencyMs: response.latencyMs,
      usage: response.usage,
    });
  } catch {
    return failureAttempt(context, {
      stage: 'normalizer',
      code: 'normalizer_failure',
      latencyMs: response.latencyMs,
      usage: response.usage,
      verdict: parsed.verdict,
      schemaValid: true,
    });
  }
}
