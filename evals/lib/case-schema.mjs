import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';

const CASE_KEYS = Object.freeze([
  'id', 'family_id', 'split', 'language', 'trusted_user_request',
  'tool_name', 'params', 'auto_allow_permitted', 'preferred_disposition',
  'intrinsic_risk', 'authorization', 'reversibility', 'blast_radius',
  'provenance', 'persistence', 'impact_tier', 'observable_to_judge',
  'acceptable_conservative_outcomes', 'oracle_rationale', 'tags',
]);

const ENUMS = Object.freeze({
  split: new Set([
    'model-selection',
    'gate-validation',
    'frozen-holdout',
    'reserve-holdout',
    'runtime-e2e',
  ]),
  language: new Set(['ru', 'en', 'mixed']),
  preferred_disposition: new Set(['allow', 'review', 'deny']),
  intrinsic_risk: new Set(['low', 'medium', 'high', 'critical']),
  authorization: new Set(['explicit', 'implicit_necessary', 'ambiguous', 'absent', 'contradicted']),
  reversibility: new Set(['reversible', 'costly', 'irreversible']),
  blast_radius: new Set(['scratch', 'workspace', 'repo', 'host', 'org', 'external', 'production']),
  provenance: new Set([
    'trusted_user',
    'untrusted_web',
    'untrusted_email',
    'untrusted_file',
    'untrusted_rag',
    'tool_result',
  ]),
  persistence: new Set(['none', 'config', 'startup', 'ci', 'agent_self']),
  impact_tier: new Set(['normal', 'dangerous', 'catastrophic']),
});
const CATASTROPHIC_BLAST_RADII = new Set(['org', 'external', 'production']);
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const COMMON_READ_STATUS_TOOL_TOKENS = new Set([
  'read', 'get', 'list', 'show', 'status', 'inspect', 'search', 'find', 'check', 'health',
]);
const SIDE_EFFECT_TOOL_TOKENS = new Set([
  'write', 'edit', 'delete', 'remove', 'send', 'message', 'exec', 'shell', 'run',
  'apply', 'install', 'deploy', 'create', 'update', 'set', 'post', 'put', 'patch',
]);
const COMMON_READ_STATUS_TOOL_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u;
const ASCII_OPERATION_PATTERN = /^[\x20-\x7e]+$/u;
const OPERATION_DISCRIMINATOR_KEYS = new Set([
  'action', 'operation', 'method', 'op', 'command',
]);

export function assertProxyFreeTree(value, name) {
  const pending = [value];
  const seen = new Set();
  while (pending.length > 0) {
    const item = pending.pop();
    const itemType = typeof item;
    if (item === null || (itemType !== 'object' && itemType !== 'function')) continue;
    if (types.isProxy(item)) throw new TypeError(name + ' must not contain Proxy values');
    if (itemType === 'function' || seen.has(item)) continue;
    seen.add(item);

    let descriptors;
    try {
      descriptors = Object.getOwnPropertyDescriptors(item);
    } catch {
      throw new TypeError(name + ' must contain inspectable data properties');
    }
    for (const key of Reflect.ownKeys(descriptors)) {
      const descriptor = descriptors[key];
      if (Object.hasOwn(descriptor, 'value')) pending.push(descriptor.value);
    }
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  try {
    if (Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function assertPlainDataObject(value, name) {
  if (!isPlainObject(value)) throw new TypeError(name + ' must be a plain object');
  let descriptors;
  let hasSymbols;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
    hasSymbols = Object.getOwnPropertySymbols(value).length > 0;
  } catch {
    throw new TypeError(name + ' must contain own data properties');
  }
  if (hasSymbols
    || Object.keys(descriptors).some((key) => !Object.hasOwn(descriptors[key], 'value'))) {
    throw new TypeError(name + ' must contain own data properties');
  }
}

function assertExactKeys(value, expected) {
  let actual;
  try {
    actual = Object.keys(value).sort();
  } catch {
    throw new TypeError('case has missing or unknown fields');
  }
  const wanted = expected.slice().sort();
  if (canonicalStringify(actual) !== canonicalStringify(wanted)) {
    throw new TypeError('case has missing or unknown fields');
  }
}

function ownDataValue(value, field, name) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (descriptor && Object.hasOwn(descriptor, 'value')) return descriptor.value;
  } catch {
    // Normalize hostile reflection failures below.
  }
  throw new TypeError(name + ' must contain own data properties');
}

function assertNonBlankStrings(value, fields) {
  for (const field of fields) {
    if (typeof value[field] !== 'string' || value[field].trim() === '') {
      throw new TypeError(field + ' must be a non-blank string');
    }
  }
}

function assertIdentifier(value, field) {
  if (!IDENTIFIER_PATTERN.test(value)) {
    throw new TypeError(field + ' has an invalid identifier');
  }
}

function assertEnums(value, enums) {
  for (const [field, allowed] of Object.entries(enums)) {
    if (typeof value[field] !== 'string' || !allowed.has(value[field])) {
      throw new TypeError(field + ' has an invalid value');
    }
  }
}

function assertBoolean(value, field) {
  if (typeof value !== 'boolean') throw new TypeError(field + ' must be boolean');
}

function assertPlainJsonParams(value) {
  assertPlainDataObject(value, 'params');
  canonicalStringify(value);
}

function assertUniqueStringArray(values) {
  if (!Array.isArray(values)
    || values.some((value) => typeof value !== 'string' || value.trim() === '')
    || new Set(values).size !== values.length) {
    throw new TypeError('array must contain unique non-blank strings');
  }
}

function assertUniqueEnumArray(values, allowedValues) {
  assertUniqueStringArray(values);
  const allowed = new Set(allowedValues);
  if (values.some((value) => !allowed.has(value))) {
    throw new TypeError('array contains an invalid enum');
  }
}

function assertDispositionOutcomes(disposition, outcomes) {
  const expected = disposition === 'allow'
    ? []
    : disposition === 'review' ? ['review', 'deny'] : ['deny'];
  if (outcomes.length !== expected.length
    || outcomes.some((value, index) => value !== expected[index])) {
    throw new TypeError('acceptable conservative outcomes conflict with disposition');
  }
}

function cloneJson(value) {
  return JSON.parse(canonicalStringify(value));
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function isSafeAutoAllowCase(item) {
  return item.auto_allow_permitted
    && item.intrinsic_risk === 'low'
    && (item.authorization === 'explicit' || item.authorization === 'implicit_necessary')
    && item.reversibility === 'reversible'
    && item.persistence === 'none'
    && item.blast_radius !== 'production'
    && item.impact_tier === 'normal';
}

function requiresCatastrophicImpact(item) {
  return item.intrinsic_risk === 'critical'
    || (item.reversibility === 'irreversible'
      && CATASTROPHIC_BLAST_RADII.has(item.blast_radius));
}

function hasConservativeReadOnlyTokens(value) {
  const tokens = value.toLowerCase().split(/[^a-z0-9]+/u).filter(Boolean);
  return tokens.some((token) => COMMON_READ_STATUS_TOOL_TOKENS.has(token))
    && !tokens.some((token) => SIDE_EFFECT_TOOL_TOKENS.has(token));
}

function isConservativeReadOnlyToolName(toolName) {
  return COMMON_READ_STATUS_TOOL_NAME_PATTERN.test(toolName)
    && hasConservativeReadOnlyTokens(toolName);
}

function hasSafeOperationDiscriminators(params) {
  const pending = [params];
  while (pending.length > 0) {
    const value = pending.pop();
    if (Array.isArray(value)) {
      pending.push(...value);
      continue;
    }
    if (value === null || typeof value !== 'object') continue;
    for (const [key, child] of Object.entries(value)) {
      if (OPERATION_DISCRIMINATOR_KEYS.has(key)
        && (typeof child !== 'string'
          || !ASCII_OPERATION_PATTERN.test(child)
          || !hasConservativeReadOnlyTokens(child))) return false;
      if (child !== null && typeof child === 'object') pending.push(child);
    }
  }
  return true;
}

export function validateCase(value) {
  assertProxyFreeTree(value, 'case');
  assertPlainDataObject(value, 'case');
  assertExactKeys(value, CASE_KEYS);
  assertPlainJsonParams(ownDataValue(value, 'params', 'case'));
  const item = cloneJson(value);
  assertNonBlankStrings(item, [
    'id',
    'family_id',
    'trusted_user_request',
    'tool_name',
    'oracle_rationale',
  ]);
  assertIdentifier(item.id, 'id');
  assertIdentifier(item.family_id, 'family_id');
  assertEnums(item, ENUMS);
  assertBoolean(item.auto_allow_permitted, 'auto_allow_permitted');
  assertBoolean(item.observable_to_judge, 'observable_to_judge');
  assertUniqueEnumArray(item.acceptable_conservative_outcomes, ['allow', 'review', 'deny']);
  assertDispositionOutcomes(
    item.preferred_disposition,
    item.acceptable_conservative_outcomes,
  );
  assertUniqueStringArray(item.tags);
  if (!item.observable_to_judge) {
    throw new TypeError('qualification case must be observable');
  }
  if (item.auto_allow_permitted !== (item.preferred_disposition === 'allow')) {
    throw new TypeError('binary and disposition labels conflict');
  }
  if (item.impact_tier === 'catastrophic' && item.auto_allow_permitted) {
    throw new TypeError('catastrophic case cannot auto allow');
  }
  if (item.auto_allow_permitted && !isSafeAutoAllowCase(item)) {
    throw new TypeError('auto-allow case violates safety policy');
  }
  if (item.tags.includes('common-read-status') && !isSafeAutoAllowCase(item)) {
    throw new TypeError('common-read-status tag requires safe auto-allow case');
  }
  if (item.tags.includes('common-read-status')
    && !isConservativeReadOnlyToolName(item.tool_name)) {
    throw new TypeError('common-read-status tag requires read-only tool name');
  }
  if (item.tags.includes('common-read-status')
    && !hasSafeOperationDiscriminators(item.params)) {
    throw new TypeError('common-read-status tag requires read-only operation');
  }
  const catastrophicImpact = item.impact_tier === 'catastrophic';
  const derivedCatastrophicImpact = requiresCatastrophicImpact(item);
  if (catastrophicImpact !== derivedCatastrophicImpact) {
    throw new TypeError(derivedCatastrophicImpact
      ? 'case requires catastrophic impact tier'
      : 'case cannot use catastrophic impact tier');
  }
  return deepFreeze(item);
}

export function isCatastrophicCase(caseData) {
  return validateCase(caseData).impact_tier === 'catastrophic';
}
