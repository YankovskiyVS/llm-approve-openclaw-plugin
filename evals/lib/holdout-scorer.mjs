import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { aggregateQualification } from './aggregate.mjs';
import { snapshotInferenceAttempt } from './attempt.mjs';
import { assertProxyFreeTree } from './case-schema.mjs';
import { lintCorpus } from './corpus.mjs';
import {
  holdoutInputHash,
  validateHoldoutInput,
  validateHoldoutOracle,
} from './holdout-contracts.mjs';
import { validateHoldoutInferenceArtifact } from './holdout-runner.mjs';

const OPTION_KEYS = Object.freeze([
  'input',
  'oracle',
  'inferenceArtifact',
  'pricing',
]);

function exactDataValues(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) throw new TypeError('invalid holdout score input');
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('invalid holdout score input');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== OPTION_KEYS.length
      || keys.some((key) => typeof key !== 'string' || !OPTION_KEYS.includes(key))) {
      throw new TypeError('invalid holdout score input');
    }
    const fields = {};
    for (const key of OPTION_KEYS) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError('invalid holdout score input');
      }
      fields[key] = descriptor.value;
    }
    return fields;
  } catch {
    throw new TypeError('invalid holdout score input');
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function pricingHash(value) {
  try {
    assertProxyFreeTree(value, 'holdout pricing');
    return 'sha256:' + createHash('sha256')
      .update(canonicalStringify(value), 'utf8')
      .digest('hex');
  } catch {
    throw new TypeError('invalid holdout pricing');
  }
}

function reconstructCases(input, oracle) {
  if (input.cases.length !== oracle.cases.length) {
    throw new TypeError('holdout input and oracle case IDs do not match');
  }
  const cases = input.cases.map((inputCase, index) => {
    const oracleCase = oracle.cases[index];
    if (inputCase.evaluation_id !== oracleCase.evaluation_id) {
      throw new TypeError('holdout input and oracle case IDs do not match in order');
    }
    return {
      id: inputCase.evaluation_id,
      family_id: oracleCase.family_id,
      split: oracleCase.split,
      language: oracleCase.language,
      trusted_user_request: inputCase.trusted_user_request,
      tool_name: inputCase.tool_name,
      params: inputCase.params,
      auto_allow_permitted: oracleCase.auto_allow_permitted,
      preferred_disposition: oracleCase.preferred_disposition,
      intrinsic_risk: oracleCase.intrinsic_risk,
      authorization: oracleCase.authorization,
      reversibility: oracleCase.reversibility,
      blast_radius: oracleCase.blast_radius,
      provenance: oracleCase.provenance,
      persistence: oracleCase.persistence,
      impact_tier: oracleCase.impact_tier,
      observable_to_judge: true,
      acceptable_conservative_outcomes: oracleCase.acceptable_conservative_outcomes,
      oracle_rationale: oracleCase.oracle_rationale,
      tags: oracleCase.tags,
    };
  });
  return lintCorpus(cases);
}

function assertDocumentBindings(input, oracle, artifact) {
  const inputSha256 = holdoutInputHash(input);
  if (input.holdout_id !== oracle.holdout_id
    || input.holdout_id !== artifact.holdout_id
    || oracle.input_sha256 !== inputSha256
    || artifact.input_sha256 !== inputSha256) {
    throw new TypeError('holdout document binding mismatch');
  }
}

function assertCompleteArtifactOrder(input, artifact) {
  if (artifact.attempts.length !== input.cases.length * artifact.repeats) {
    throw new TypeError('holdout inference cases do not match input');
  }
  for (let caseIndex = 0; caseIndex < input.cases.length; caseIndex += 1) {
    const evaluationId = input.cases[caseIndex].evaluation_id;
    for (let repeat = 1; repeat <= artifact.repeats; repeat += 1) {
      const attempt = artifact.attempts[(caseIndex * artifact.repeats) + repeat - 1];
      if (attempt.evaluation_id !== evaluationId || attempt.repeat !== repeat) {
        throw new TypeError('holdout inference case IDs do not match input in order');
      }
    }
  }
}

function enrichAttempt(attempt, caseData) {
  return {
    resume_key: attempt.resume_key,
    manifest_hash: attempt.manifest_hash,
    model: attempt.model,
    profile: attempt.profile,
    case_id: attempt.evaluation_id,
    family_id: caseData.family_id,
    split: caseData.split,
    repeat: attempt.repeat,
    oracle_disposition: caseData.preferred_disposition,
    auto_allow_permitted: caseData.auto_allow_permitted,
    oracle_risk: caseData.intrinsic_risk,
    oracle_authorization: caseData.authorization,
    impact_tier: caseData.impact_tier,
    tags: caseData.tags.slice(),
    raw_decision: attempt.raw_decision,
    raw_risk: attempt.raw_risk,
    raw_authorization: attempt.raw_authorization,
    confidence: attempt.confidence,
    normalized_kind: attempt.normalized_kind,
    autonomous_outcome: attempt.autonomous_outcome,
    supervised_outcome: attempt.supervised_outcome,
    schema_valid: attempt.schema_valid,
    failure_stage: attempt.failure_stage,
    failure_code: attempt.failure_code,
    latency_ms: attempt.latency_ms,
    usage: attempt.usage,
    rationale_sha256: attempt.rationale_sha256,
  };
}

export function scoreHoldout(options) {
  const fields = exactDataValues(options);
  const input = validateHoldoutInput(fields.input);
  const oracle = validateHoldoutOracle(fields.oracle);
  const artifact = validateHoldoutInferenceArtifact(fields.inferenceArtifact);
  if (pricingHash(fields.pricing) !== artifact.manifest.pricing_sha256) {
    throw new TypeError('holdout pricing does not match inference manifest');
  }
  assertDocumentBindings(input, oracle, artifact);
  const cases = reconstructCases(input, oracle);
  assertCompleteArtifactOrder(input, artifact);

  const caseById = new Map(cases.map((caseData) => [caseData.id, caseData]));
  const attempts = artifact.attempts.map((attempt, index) => {
    const inputCase = input.cases[Math.floor(index / artifact.repeats)];
    const verifiedAttempt = snapshotInferenceAttempt(attempt, {
      inputCase,
      manifest: artifact.manifest,
      repeat: attempt.repeat,
    });
    if (verifiedAttempt === null) {
      throw new TypeError('holdout prediction does not match the production guard');
    }
    const caseData = caseById.get(attempt.evaluation_id);
    if (caseData === undefined) {
      throw new TypeError('holdout inference case ID is absent from input');
    }
    return enrichAttempt(verifiedAttempt, caseData);
  });
  const aggregate = aggregateQualification({
    attempts,
    expectedRepeats: artifact.repeats,
    pricing: fields.pricing,
  });
  return deepFreeze({
    attempts,
    summary: aggregate.summary,
    caseOutcomes: aggregate.caseOutcomes,
    familyOutcomes: aggregate.familyOutcomes,
  });
}
