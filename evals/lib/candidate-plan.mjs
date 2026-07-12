import { types } from 'node:util';

export const CANDIDATE_PLAN_URL = new URL(
  '../candidates/candidate-plan.json',
  import.meta.url,
);

const PLAN_KEYS = Object.freeze(['schema_version', 'candidates']);
const CANDIDATE_KEYS = Object.freeze([
  'id',
  'model_id',
  'endpoint_profile',
  'response_profile',
  'temperature',
  'max_tokens',
  'max_reasoning_tokens',
  'thinking',
  'response_format',
  'timeout_ms',
]);

const CANDIDATE_IDENTITIES = Object.freeze([
  Object.freeze(['zai-org/GLM-5.1', 'cloudru-fm', 'openai-content']),
  Object.freeze(['zai-org/GLM-4.7', 'cloudru-fm', 'openai-content']),
  Object.freeze(['zai-org/GLM-5.2', 'cloudru-fm', 'openai-content']),
  Object.freeze(['Qwen/Qwen3.6-35B-A3B', 'cloudru-fm', 'openai-content']),
  Object.freeze(['Qwen/Qwen3.5-397B-A17B', 'cloudru-fm', 'openai-content']),
  Object.freeze(['Qwen/Qwen3-Coder-Next', 'cloudru-fm', 'openai-content']),
  Object.freeze(['qwen36-27b-fp8', 'qwen-vllm', 'vllm-reasoning-final']),
  Object.freeze(['moonshotai/Kimi-K2.6', 'cloudru-fm', 'openai-content']),
  Object.freeze(['deepseek-ai/DeepSeek-V4-Pro', 'cloudru-fm', 'openai-content']),
  Object.freeze(['deepseek-ai/DeepSeek-V4-Flash', 'cloudru-fm', 'openai-content']),
  Object.freeze(['deepseek-ai/DeepSeek-V3.1-Terminus', 'cloudru-fm', 'openai-content']),
  Object.freeze(['deepseek-ai/DeepSeek-V3', 'cloudru-fm', 'openai-content']),
  Object.freeze(['deepseek-ai/DeepSeek-R1-0528', 'cloudru-fm', 'openai-content']),
  Object.freeze(['MiniMaxAI/MiniMax-M3', 'cloudru-fm', 'openai-content']),
  Object.freeze(['MiniMaxAI/MiniMax-M2.5', 'cloudru-fm', 'openai-content']),
  Object.freeze(['MiniMaxAI/MiniMax-M2', 'cloudru-fm', 'openai-content']),
  Object.freeze(['openai/gpt-oss-120b', 'cloudru-fm', 'openai-content']),
  Object.freeze(['openai/gpt-oss-20b', 'cloudru-fm', 'openai-content']),
  Object.freeze(['ai-sage/GigaChat3-10B-A1.8B', 'cloudru-fm', 'openai-content']),
]);

const QUALIFICATION_PROFILE = Object.freeze({
  temperature: 0,
  max_tokens: 256,
  max_reasoning_tokens: 0,
  thinking: false,
  response_format: 'json_object',
  timeout_ms: 5000,
});

function exactDataValues(value, expectedKeys, message) {
  try {
    if (value === null || typeof value !== 'object' || types.isProxy(value)
      || Array.isArray(value)) {
      throw new TypeError(message);
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(message);
    }

    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    if (ownKeys.length !== expectedKeys.length
      || ownKeys.some((key) => typeof key !== 'string')) {
      throw new TypeError(message);
    }

    const result = {};
    for (const key of expectedKeys) {
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

function exactArrayValues(value, expectedLength, message) {
  try {
    if (value === null || typeof value !== 'object' || types.isProxy(value)
      || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
      throw new TypeError(message);
    }

    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    if (ownKeys.length !== expectedLength + 1
      || ownKeys.some((key) => typeof key !== 'string')) {
      throw new TypeError(message);
    }
    const length = descriptors.length;
    if (!length || !Object.hasOwn(length, 'value') || length.value !== expectedLength) {
      throw new TypeError(message);
    }

    const result = [];
    for (let index = 0; index < expectedLength; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError(message);
      }
      result.push(descriptor.value);
    }
    return result;
  } catch {
    throw new TypeError(message);
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function validateCandidateFields(fields, identity) {
  const [modelId, endpointProfile, responseProfile] = identity;

  if (fields.id !== modelId || fields.model_id !== modelId) {
    throw new TypeError('invalid candidate identity');
  }
  if (fields.endpoint_profile !== endpointProfile) {
    throw new TypeError('invalid endpoint profile');
  }
  if (fields.response_profile !== responseProfile) {
    throw new TypeError('invalid response profile');
  }
  for (const [key, value] of Object.entries(QUALIFICATION_PROFILE)) {
    if (!Object.is(fields[key], value)) {
      throw new TypeError('invalid qualification profile');
    }
  }

  return {
    id: fields.id,
    model_id: fields.model_id,
    endpoint_profile: fields.endpoint_profile,
    response_profile: fields.response_profile,
    temperature: fields.temperature,
    max_tokens: fields.max_tokens,
    max_reasoning_tokens: fields.max_reasoning_tokens,
    thinking: fields.thinking,
    response_format: fields.response_format,
    timeout_ms: fields.timeout_ms,
  };
}

export function validateCandidateEntry(input) {
  const fields = exactDataValues(input, CANDIDATE_KEYS, 'invalid candidate fields');
  const identity = CANDIDATE_IDENTITIES.find(([modelId]) => modelId === fields.model_id);
  if (identity === undefined) throw new TypeError('invalid candidate identity');
  return deepFreeze(validateCandidateFields(fields, identity));
}

export function validateCandidatePlan(input) {
  const fields = exactDataValues(input, PLAN_KEYS, 'invalid candidate plan fields');
  if (fields.schema_version !== 'judge-candidate-plan.v1') {
    throw new TypeError('invalid candidate plan version');
  }

  const rawCandidates = exactArrayValues(
    fields.candidates,
    CANDIDATE_IDENTITIES.length,
    'invalid candidate list',
  );
  const candidateFields = rawCandidates.map((candidate) => exactDataValues(
    candidate,
    CANDIDATE_KEYS,
    'invalid candidate fields',
  ));
  const ids = new Set();
  const modelIds = new Set();
  for (const candidate of candidateFields) {
    if (ids.has(candidate.id) || modelIds.has(candidate.model_id)) {
      throw new TypeError('duplicate candidate');
    }
    ids.add(candidate.id);
    modelIds.add(candidate.model_id);
  }
  const candidates = candidateFields.map((candidate, index) => validateCandidateFields(
    candidate,
    CANDIDATE_IDENTITIES[index],
  ));

  return deepFreeze({
    schema_version: fields.schema_version,
    candidates,
  });
}
