import { types } from 'node:util';

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
const CASE_OUTCOME_KEYS = Object.freeze([
  'case_id', 'family_id', 'split', 'oracle_disposition',
  'auto_allow_permitted', 'impact_tier', 'repeat_count',
  'raw_outcomes', 'decision_flip', 'unsafe_allow_flip', 'unsafe', 'passed',
]);
const FAMILY_OUTCOME_KEYS = Object.freeze([
  'family_id', 'split', 'must_allow_case_count', 'must_allow_passed',
  'must_block_case_count', 'must_block_unsafe', 'catastrophic_case_count',
  'catastrophic_unsafe', 'qualification_passed',
]);
const SUMMARY_KEYS = Object.freeze([
  'denominators', 'raw_matrix', 'autonomous_matrix', 'supervised_matrix',
  'risk_confusion', 'authorization_confusion', 'confidence_buckets',
  'family', 'raw_family', 'rates', 'bounds', 'latency_ms', 'usage',
]);
const RATE_KEYS = Object.freeze([
  'unsafe_auto_allow', 'safe_action_recall', 'safe_overblock',
  'auto_allow_precision', 'failure', 'transport_failure',
  'client_provider_response_failure', 'schema_invalid', 'timeout',
  'safe_attempt_allow_rate_schema_valid',
  'decision_flip', 'unsafe_allow_flip', 'common_read_status_recall',
]);
const BOUND_KEYS = Object.freeze([
  'unsafe_auto_allow_upper_95', 'safe_action_recall_lower_95',
  'common_read_status_recall_lower_95',
]);
const LATENCY_KEYS = Object.freeze([
  'p50', 'p95', 'p99',
  'timeout_floor_p95', 'timeout_floor_p99',
  'timeout_floor_p95_is_lower_bound', 'timeout_floor_p99_is_lower_bound',
]);
const USAGE_KEYS = Object.freeze([
  'covered_attempts', 'prompt_tokens', 'completion_tokens',
  'reasoning_tokens', 'cached_prompt_tokens', 'cost',
]);
const DENOMINATOR_KEYS = Object.freeze([
  'attempts', 'verdict_candidates_received', 'schema_valid_verdicts',
  'must_allow_schema_valid_attempts', 'cases',
  'must_allow_families', 'must_block_families',
  'catastrophic_families', 'common_read_status_families',
]);
const FAMILY_KEYS = Object.freeze([
  'must_block', 'must_allow', 'catastrophic', 'common_read_status',
]);
const RAW_FAMILY_KEYS = Object.freeze([
  'must_block', 'must_allow', 'gate_saves', 'gate_friction',
]);
const MUST_BLOCK_KEYS = Object.freeze(['total', 'unsafe']);
const MUST_ALLOW_KEYS = Object.freeze(['total', 'passed']);
const AUTONOMOUS_MATRIX_KEYS = Object.freeze(['must_allow', 'must_block']);
const AUTONOMOUS_COHORT_KEYS = Object.freeze(['executed_without_human', 'blocked']);
const MANIFEST_KEYS = Object.freeze([
  'schema_version', 'git_sha', 'node_version', 'openclaw_version',
  'model_id', 'policy_version', 'corpus_sha256', 'pricing_sha256',
  'source_sha256', 'endpoint_origin', 'profile', 'manifest_hash',
]);
const PRICING_KEYS = Object.freeze(['schema_version', 'currency', 'captured_on', 'models']);
const PRICE_KEYS = Object.freeze(['input_per_million', 'output_per_million', 'source']);
const JUNIT_KEYS = Object.freeze(['model_id', 'family_outcomes']);
const OPENCLAW_VERSION_PATTERN = /^[0-9]{4}\.(?:0|[1-9][0-9]?)\.(?:0|[1-9][0-9]?)$/u;

const CASE_COLUMNS = Object.freeze(CASE_OUTCOME_KEYS.slice());
const RANKING_COLUMNS = Object.freeze([
  'model_id',
  'manifest_hash',
  'unsafe_auto_allow',
  'safe_action_recall',
  'common_read_status_families',
  'common_read_status_passed',
  'common_read_status_recall',
  'safe_overblock',
  'auto_allow_precision',
  'unsafe_auto_allow_upper_95',
  'safe_action_recall_lower_95',
  'common_read_status_recall_lower_95',
  'failure',
  'transport_failure',
  'client_provider_response_failure',
  'schema_invalid',
  'timeout',
  'safe_attempt_allow_rate_schema_valid',
  'decision_flip',
  'unsafe_allow_flip',
  'latency_p50_ms',
  'latency_p95_ms',
  'latency_p99_ms',
  'latency_timeout_floor_p95_ms',
  'latency_timeout_floor_p99_ms',
  'latency_timeout_floor_p95_is_lower_bound',
  'latency_timeout_floor_p99_is_lower_bound',
  'covered_attempts',
  'prompt_tokens',
  'completion_tokens',
  'reasoning_tokens',
  'cached_prompt_tokens',
  'cost',
  'currency',
  'pricing_captured_on',
  'input_per_million',
  'output_per_million',
  'pricing_source',
]);

function invalid() {
  throw new TypeError('invalid render input');
}

function compareCodeUnits(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function exactDataValues(value, expected) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalid();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) invalid();
    const result = {};
    for (const key of expected) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    invalid();
  }
}

function dataObjectDescriptors(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalid();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const key of Reflect.ownKeys(descriptors)) {
      const descriptor = descriptors[key];
      if (typeof key !== 'string' || !descriptor.enumerable
        || !Object.hasOwn(descriptor, 'value')) invalid();
    }
    return descriptors;
  } catch {
    invalid();
  }
}

function denseArrayValues(value) {
  try {
    if (types.isProxy(value) || !Array.isArray(value)
      || Object.getPrototypeOf(value) !== Array.prototype) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const length = descriptors.length?.value;
    if (!Number.isSafeInteger(length) || length < 0 || keys.length !== length + 1
      || keys.some((key) => typeof key !== 'string')) invalid();
    const result = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
      result.push(descriptor.value);
    }
    return result;
  } catch {
    invalid();
  }
}

function canonicalJson(value, ancestors = new Set()) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) invalid();
    return JSON.stringify(value);
  }
  if (typeof value !== 'object' || types.isProxy(value) || ancestors.has(value)) invalid();
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return '[' + denseArrayValues(value)
        .map((item) => canonicalJson(item, ancestors))
        .join(',') + ']';
    }
    const descriptors = dataObjectDescriptors(value);
    const keys = Object.keys(descriptors).sort(compareCodeUnits);
    return '{' + keys.map((key) => (
      JSON.stringify(key) + ':' + canonicalJson(descriptors[key].value, ancestors)
    )).join(',') + '}';
  } finally {
    ancestors.delete(value);
  }
}

function safeRender(render) {
  try {
    return render();
  } catch {
    invalid();
  }
}

function requireString(value) {
  if (typeof value !== 'string') invalid();
  return value;
}

function requireInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) invalid();
  return value;
}

function requireRate(value) {
  if (value !== null && (typeof value !== 'number' || !Number.isFinite(value)
    || value < 0 || value > 1)) invalid();
  return value;
}

function requireNonnegativeNumber(value) {
  if (value !== null && (typeof value !== 'number' || !Number.isFinite(value) || value < 0)) {
    invalid();
  }
  return value;
}

function requireBoolean(value) {
  if (typeof value !== 'boolean') invalid();
  return value;
}

function sameNumber(actual, expected) {
  if (actual === null || expected === null) return actual === expected;
  return Math.abs(actual - expected) <= Number.EPSILON * 4;
}

function scalar(value) {
  if (value === null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  invalid();
}

function csvField(value) {
  const scalarText = scalar(value);
  const text = /^\s*[=+\-@]/u.test(scalarText) ? `'${scalarText}` : scalarText;
  if (!/[",\r\n]/u.test(text)) return text;
  return '"' + text.replaceAll('"', '""') + '"';
}

function csvLine(values) {
  return values.map(csvField).join(',');
}

function summarySections(summary) {
  const values = exactDataValues(summary, SUMMARY_KEYS);
  canonicalJson(values);
  const result = {
    values,
    denominators: exactDataValues(values.denominators, DENOMINATOR_KEYS),
    family: exactDataValues(values.family, FAMILY_KEYS),
    rawFamily: exactDataValues(values.raw_family, RAW_FAMILY_KEYS),
    autonomous: exactDataValues(values.autonomous_matrix, AUTONOMOUS_MATRIX_KEYS),
    rates: exactDataValues(values.rates, RATE_KEYS),
    bounds: exactDataValues(values.bounds, BOUND_KEYS),
    latency: exactDataValues(values.latency_ms, LATENCY_KEYS),
    usage: exactDataValues(values.usage, USAGE_KEYS),
  };
  for (const value of Object.values(result.denominators)) requireInteger(value);
  for (const value of Object.values(result.rates)) requireRate(value);
  for (const value of Object.values(result.bounds)) requireRate(value);
  for (const key of [
    'p50', 'p95', 'p99', 'timeout_floor_p95', 'timeout_floor_p99',
  ]) requireNonnegativeNumber(result.latency[key]);
  for (const key of [
    'timeout_floor_p95_is_lower_bound', 'timeout_floor_p99_is_lower_bound',
  ]) requireBoolean(result.latency[key]);
  for (const key of USAGE_KEYS.slice(0, -1)) requireInteger(result.usage[key]);
  requireNonnegativeNumber(result.usage.cost);
  for (const [key, expected] of [
    ['must_block', MUST_BLOCK_KEYS],
    ['must_allow', MUST_ALLOW_KEYS],
    ['catastrophic', MUST_BLOCK_KEYS],
    ['common_read_status', MUST_ALLOW_KEYS],
  ]) {
    const cohort = exactDataValues(result.family[key], expected);
    for (const value of Object.values(cohort)) requireInteger(value);
  }
  for (const [key, expected] of [
    ['must_block', MUST_BLOCK_KEYS],
    ['must_allow', MUST_ALLOW_KEYS],
  ]) {
    const cohort = exactDataValues(result.rawFamily[key], expected);
    for (const value of Object.values(cohort)) requireInteger(value);
  }
  requireInteger(result.rawFamily.gate_saves);
  requireInteger(result.rawFamily.gate_friction);
  for (const cohortName of AUTONOMOUS_MATRIX_KEYS) {
    const cohort = exactDataValues(result.autonomous[cohortName], AUTONOMOUS_COHORT_KEYS);
    for (const value of Object.values(cohort)) requireInteger(value);
    result.autonomous[cohortName] = cohort;
  }
  const conditionalSafeAttempts = result.denominators.must_allow_schema_valid_attempts;
  const conditionalSafeAllows = result.autonomous.must_allow.executed_without_human;
  const conditionalSafeRate = conditionalSafeAttempts === 0
    ? null
    : conditionalSafeAllows / conditionalSafeAttempts;
  if (conditionalSafeAllows > conditionalSafeAttempts
    || !sameNumber(
      result.rates.safe_attempt_allow_rate_schema_valid,
      conditionalSafeRate,
    )) invalid();
  return result;
}

function priceFor(pricing, modelId) {
  const pricingValues = exactDataValues(pricing, PRICING_KEYS);
  const models = dataObjectDescriptors(pricingValues.models);
  const descriptor = models[modelId];
  if (descriptor === undefined) {
    return {
      pricing: pricingValues,
      price: {
        input_per_million: null,
        output_per_million: null,
        source: '',
      },
    };
  }
  return {
    pricing: pricingValues,
    price: exactDataValues(descriptor.value, PRICE_KEYS),
  };
}

function display(value) {
  return value === null ? 'n/a' : scalar(value);
}

function displayRatio(numerator, denominator, ratio) {
  return `${numerator}/${denominator} (${display(ratio)})`;
}

function displayTimeoutFloor(value, isLowerBound) {
  if (value === null) return 'n/a';
  return `${isLowerBound ? '>=' : ''}${scalar(value)}`;
}

function xml(value) {
  const text = requireString(value);
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    const valid = codePoint === 0x09 || codePoint === 0x0a || codePoint === 0x0d
      || (codePoint >= 0x20 && codePoint <= 0xd7ff)
      || (codePoint >= 0xe000 && codePoint <= 0xfffd)
      || (codePoint >= 0x10000 && codePoint <= 0x10ffff);
    if (!valid) invalid();
  }
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

export function renderAttemptsJsonl(attempts) {
  return safeRender(() => {
    const rows = denseArrayValues(attempts).map((value) => {
      const fields = exactDataValues(value, ATTEMPT_KEYS);
      for (const key of ['manifest_hash', 'model', 'profile', 'case_id', 'resume_key']) {
        requireString(fields[key]);
      }
      if (!Number.isSafeInteger(fields.repeat) || fields.repeat < 1) invalid();
      canonicalJson(fields);
      return fields;
    });
    rows.sort((left, right) => {
      for (const key of ['manifest_hash', 'model', 'profile', 'case_id']) {
        const compared = compareCodeUnits(left[key], right[key]);
        if (compared !== 0) return compared;
      }
      if (left.repeat !== right.repeat) return left.repeat - right.repeat;
      return compareCodeUnits(left.resume_key, right.resume_key);
    });
    return rows.map((row) => canonicalJson(row)).join('\n') + (rows.length > 0 ? '\n' : '');
  });
}

export function renderCasesCsv(caseOutcomes) {
  return safeRender(() => {
    const rows = denseArrayValues(caseOutcomes).map((value) => {
      const fields = exactDataValues(value, CASE_OUTCOME_KEYS);
      requireString(fields.case_id);
      requireString(fields.family_id);
      const rawOutcomes = denseArrayValues(fields.raw_outcomes);
      if (rawOutcomes.some((outcome) => typeof outcome !== 'string')) invalid();
      fields.raw_outcomes = canonicalJson(rawOutcomes);
      return fields;
    });
    rows.sort((left, right) => (
      compareCodeUnits(left.case_id, right.case_id)
      || compareCodeUnits(left.family_id, right.family_id)
    ));
    return [
      csvLine(CASE_COLUMNS),
      ...rows.map((row) => csvLine(CASE_COLUMNS.map((column) => row[column]))),
      '',
    ].join('\n');
  });
}

export function renderRankingCsv(summary, manifest, pricing) {
  return safeRender(() => {
    const sections = summarySections(summary);
    const manifestValues = exactDataValues(manifest, MANIFEST_KEYS);
    const modelId = requireString(manifestValues.model_id);
    const priced = priceFor(pricing, modelId);
    const row = {
      model_id: modelId,
      manifest_hash: requireString(manifestValues.manifest_hash),
      unsafe_auto_allow: sections.rates.unsafe_auto_allow,
      safe_action_recall: sections.rates.safe_action_recall,
      common_read_status_families: sections.family.common_read_status.total,
      common_read_status_passed: sections.family.common_read_status.passed,
      common_read_status_recall: sections.rates.common_read_status_recall,
      safe_overblock: sections.rates.safe_overblock,
      auto_allow_precision: sections.rates.auto_allow_precision,
      unsafe_auto_allow_upper_95: sections.bounds.unsafe_auto_allow_upper_95,
      safe_action_recall_lower_95: sections.bounds.safe_action_recall_lower_95,
      common_read_status_recall_lower_95:
        sections.bounds.common_read_status_recall_lower_95,
      failure: sections.rates.failure,
      transport_failure: sections.rates.transport_failure,
      client_provider_response_failure:
        sections.rates.client_provider_response_failure,
      schema_invalid: sections.rates.schema_invalid,
      timeout: sections.rates.timeout,
      safe_attempt_allow_rate_schema_valid:
        sections.rates.safe_attempt_allow_rate_schema_valid,
      decision_flip: sections.rates.decision_flip,
      unsafe_allow_flip: sections.rates.unsafe_allow_flip,
      latency_p50_ms: sections.latency.p50,
      latency_p95_ms: sections.latency.p95,
      latency_p99_ms: sections.latency.p99,
      latency_timeout_floor_p95_ms: sections.latency.timeout_floor_p95,
      latency_timeout_floor_p99_ms: sections.latency.timeout_floor_p99,
      latency_timeout_floor_p95_is_lower_bound:
        sections.latency.timeout_floor_p95_is_lower_bound,
      latency_timeout_floor_p99_is_lower_bound:
        sections.latency.timeout_floor_p99_is_lower_bound,
      covered_attempts: sections.usage.covered_attempts,
      prompt_tokens: sections.usage.prompt_tokens,
      completion_tokens: sections.usage.completion_tokens,
      reasoning_tokens: sections.usage.reasoning_tokens,
      cached_prompt_tokens: sections.usage.cached_prompt_tokens,
      cost: sections.usage.cost,
      currency: priced.pricing.currency,
      pricing_captured_on: priced.pricing.captured_on,
      input_per_million: priced.price.input_per_million,
      output_per_million: priced.price.output_per_million,
      pricing_source: priced.price.source,
    };
    return [
      csvLine(RANKING_COLUMNS),
      csvLine(RANKING_COLUMNS.map((column) => row[column])),
      '',
    ].join('\n');
  });
}

export function renderReportMarkdown(summary, manifest) {
  return safeRender(() => {
    const sections = summarySections(summary);
    const manifestValues = exactDataValues(manifest, MANIFEST_KEYS);
    const mustBlock = exactDataValues(sections.family.must_block, MUST_BLOCK_KEYS);
    const mustAllow = exactDataValues(sections.family.must_allow, MUST_ALLOW_KEYS);
    const catastrophic = exactDataValues(sections.family.catastrophic, MUST_BLOCK_KEYS);
    const commonReadStatus = exactDataValues(
      sections.family.common_read_status,
      MUST_ALLOW_KEYS,
    );
    const rawMustBlock = exactDataValues(sections.rawFamily.must_block, MUST_BLOCK_KEYS);
    const rawMustAllow = exactDataValues(sections.rawFamily.must_allow, MUST_ALLOW_KEYS);
    for (const value of Object.values(sections.denominators)) requireInteger(value);
    for (const value of [
      mustBlock.total, mustBlock.unsafe, mustAllow.total, mustAllow.passed,
      catastrophic.total, catastrophic.unsafe,
      commonReadStatus.total, commonReadStatus.passed,
    ]) requireInteger(value);
    return [
      '# Judge qualification report',
      '',
      `- Model: \`${requireString(manifestValues.model_id)}\``,
      `- Manifest: \`${requireString(manifestValues.manifest_hash)}\``,
      `- Attempts: ${sections.denominators.attempts}`,
      `- Cases: ${sections.denominators.cases}`,
      '',
      '## Family qualification',
      '',
      `- MUST_ALLOW passed: ${mustAllow.passed}/${mustAllow.total}`,
      `- MUST_BLOCK unsafe: ${mustBlock.unsafe}/${mustBlock.total}`,
      `- Catastrophic unsafe: ${catastrophic.unsafe}/${catastrophic.total}`,
      `- Common read/status passed: ${commonReadStatus.passed}/${commonReadStatus.total}`,
      `- Raw judge MUST_ALLOW passed: ${rawMustAllow.passed}/${rawMustAllow.total}`,
      `- Raw judge MUST_BLOCK unsafe: ${rawMustBlock.unsafe}/${rawMustBlock.total}`,
      `- Guard saves: ${sections.rawFamily.gate_saves}`,
      `- Guard friction: ${sections.rawFamily.gate_friction}`,
      '',
      '## Rates and bounds',
      '',
      `- Unsafe auto-allow: ${display(sections.rates.unsafe_auto_allow)}`,
      `- End-to-end safe family pass rate (all repeats): ${displayRatio(mustAllow.passed, mustAllow.total, sections.rates.safe_action_recall)}`,
      `- Combined safe attempt allow rate among schema-valid verdicts: ${displayRatio(sections.autonomous.must_allow.executed_without_human, sections.denominators.must_allow_schema_valid_attempts, sections.rates.safe_attempt_allow_rate_schema_valid)}`,
      `- Common read/status recall: ${display(sections.rates.common_read_status_recall)}`,
      `- Unsafe auto-allow upper 95%: ${display(sections.bounds.unsafe_auto_allow_upper_95)}`,
      `- Safe action recall lower 95%: ${display(sections.bounds.safe_action_recall_lower_95)}`,
      `- Common read/status recall lower 95%: ${display(sections.bounds.common_read_status_recall_lower_95)}`,
      `- Failure: ${display(sections.rates.failure)}`,
      `- Transport failure: ${display(sections.rates.transport_failure)}`,
      `- Client/provider-response failure: ${display(sections.rates.client_provider_response_failure)}`,
      `- Verdict candidates/schema-valid: ${sections.denominators.verdict_candidates_received}/${sections.denominators.schema_valid_verdicts}`,
      `- Parser/schema-invalid among verdict candidates: ${display(sections.rates.schema_invalid)}`,
      `- Timeout: ${display(sections.rates.timeout)}`,
      '',
      '## Runtime',
      '',
      `- Schema-valid verdict latency p50/p95/p99 ms: ${display(sections.latency.p50)} / ${display(sections.latency.p95)} / ${display(sections.latency.p99)}`,
      `- Timeout-floor latency p95/p99 ms: ${displayTimeoutFloor(sections.latency.timeout_floor_p95, sections.latency.timeout_floor_p95_is_lower_bound)} / ${displayTimeoutFloor(sections.latency.timeout_floor_p99, sections.latency.timeout_floor_p99_is_lower_bound)}`,
      `- Usage-covered attempts: ${sections.usage.covered_attempts}`,
      `- Cost: ${display(sections.usage.cost)}`,
      '',
    ].join('\n');
  });
}

export function renderJunit(summary) {
  return safeRender(() => {
    const fields = exactDataValues(summary, JUNIT_KEYS);
    const modelId = requireString(fields.model_id);
    const families = denseArrayValues(fields.family_outcomes).map((value) => {
      const family = exactDataValues(value, FAMILY_OUTCOME_KEYS);
      requireString(family.family_id);
      requireString(family.split);
      if (typeof family.qualification_passed !== 'boolean') invalid();
      return family;
    });
    families.sort((left, right) => (
      compareCodeUnits(left.family_id, right.family_id)
      || compareCodeUnits(left.split, right.split)
    ));
    const failures = families.filter((family) => !family.qualification_passed).length;
    const lines = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      `<testsuite name="judge-qualification" tests="${families.length}" failures="${failures}">`,
      '  <properties>',
      `    <property name="model_id" value="${xml(modelId)}"/>`,
      '  </properties>',
    ];
    for (const family of families) {
      const attributes = `classname="${xml(family.split)}" name="${xml(family.family_id)}"`;
      if (family.qualification_passed) {
        lines.push(`  <testcase ${attributes}/>`);
      } else {
        lines.push(`  <testcase ${attributes}>`);
        lines.push('    <failure message="family qualification failed"/>');
        lines.push('  </testcase>');
      }
    }
    lines.push('</testsuite>', '');
    return lines.join('\n');
  });
}

export function renderReproduceScript(openclawVersion) {
  if (typeof openclawVersion !== 'string'
    || !OPENCLAW_VERSION_PATTERN.test(openclawVersion)) invalid();
  return '#!/bin/sh\n'
    + 'set -eu\n'
    + 'npm run eval:harness -- --corpus "$1" --pricing "$2" --output "$3"'
    + ` --repeats 3 --concurrency 4 --openclaw-version ${openclawVersion}\n`;
}
