import { types } from 'node:util';

export const MODEL_SELECTION_PRICING_URL = new URL(
  '../fixtures/model-selection-pricing.json',
  import.meta.url,
);

const SCHEMA_VERSION = 'judge-model-selection-pricing.v1';
const CAPTURED_ON = '2026-07-12';
const TOKEN_PRICE_SOURCE =
  'https://cloud.ru/products/evolution-ai-factory/catalog-foundation-models';
const TOP_LEVEL_KEYS = Object.freeze([
  'schema_version',
  'currency',
  'captured_on',
  'token_price_source',
  'models',
]);
const TOKEN_PRICE_KEYS = Object.freeze([
  'billing',
  'input_per_million',
  'output_per_million',
]);
const INFRASTRUCTURE_PRICE_KEYS = Object.freeze([
  'billing',
  'per_token_pricing',
  'reason',
]);
const MODEL_PRICES = Object.freeze([
  Object.freeze(['zai-org/GLM-4.7', 549, 793]),
  Object.freeze(['Qwen/Qwen3.6-35B-A3B', 219.6, 329.4]),
  Object.freeze(['Qwen/Qwen3.5-397B-A17B', 915, 1085.8]),
  Object.freeze(['Qwen/Qwen3-Coder-Next', 122, 244]),
  Object.freeze(['deepseek-ai/DeepSeek-V4-Pro', 183, 732]),
]);
const VLLM_MODEL_ID = 'qwen36-27b-fp8';
const MODEL_IDS = Object.freeze([
  ...MODEL_PRICES.slice(0, 4).map(([modelId]) => modelId),
  VLLM_MODEL_ID,
  MODEL_PRICES[4][0],
]);

function invalidPricing() {
  throw new TypeError('invalid model-selection pricing');
}

function exactDataValues(value, expectedKeys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalidPricing();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalidPricing();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    if (ownKeys.length !== expectedKeys.length
      || ownKeys.some((key, index) => key !== expectedKeys[index])) invalidPricing();
    const result = {};
    for (const key of expectedKeys) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        invalidPricing();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    invalidPricing();
  }
}

function validSafeSource(source) {
  if (typeof source !== 'string' || source !== TOKEN_PRICE_SOURCE) return false;
  try {
    const parsed = new URL(source);
    return parsed.protocol === 'https:'
      && parsed.username === ''
      && parsed.password === ''
      && parsed.search === ''
      && parsed.hash === ''
      && parsed.hostname === 'cloud.ru'
      && parsed.href === source;
  } catch {
    return false;
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

export function validateModelSelectionPricing(input) {
  const fields = exactDataValues(input, TOP_LEVEL_KEYS);
  if (fields.schema_version !== SCHEMA_VERSION
    || fields.currency !== 'RUB'
    || fields.captured_on !== CAPTURED_ON
    || !validSafeSource(fields.token_price_source)) invalidPricing();

  const models = exactDataValues(fields.models, MODEL_IDS);
  const canonicalModels = {};
  for (const modelId of MODEL_IDS) {
    if (modelId === VLLM_MODEL_ID) {
      const vllm = exactDataValues(models[VLLM_MODEL_ID], INFRASTRUCTURE_PRICE_KEYS);
      if (vllm.billing !== 'infrastructure'
        || vllm.per_token_pricing !== 'unavailable'
        || vllm.reason !== 'vllm_endpoint_has_no_per_token_price') invalidPricing();
      canonicalModels[VLLM_MODEL_ID] = {
        billing: 'infrastructure',
        per_token_pricing: 'unavailable',
        reason: 'vllm_endpoint_has_no_per_token_price',
      };
      continue;
    }
    const expected = MODEL_PRICES.find(([candidateId]) => candidateId === modelId);
    if (expected === undefined) invalidPricing();
    const [, inputPrice, outputPrice] = expected;
    const price = exactDataValues(models[modelId], TOKEN_PRICE_KEYS);
    if (price.billing !== 'per_token'
      || !Object.is(price.input_per_million, inputPrice)
      || !Object.is(price.output_per_million, outputPrice)) invalidPricing();
    canonicalModels[modelId] = {
      billing: 'per_token',
      input_per_million: inputPrice,
      output_per_million: outputPrice,
    };
  }

  return deepFreeze({
    schema_version: SCHEMA_VERSION,
    currency: 'RUB',
    captured_on: CAPTURED_ON,
    token_price_source: TOKEN_PRICE_SOURCE,
    models: canonicalModels,
  });
}

export function toAggregatePricing(input) {
  const snapshot = validateModelSelectionPricing(input);
  const models = {};
  for (const modelId of MODEL_IDS) {
    if (modelId === VLLM_MODEL_ID) continue;
    const price = snapshot.models[modelId];
    models[modelId] = {
      input_per_million: price.input_per_million,
      output_per_million: price.output_per_million,
      source: snapshot.token_price_source,
    };
  }
  return deepFreeze({
    schema_version: 'judge-pricing.v1',
    currency: snapshot.currency,
    captured_on: snapshot.captured_on,
    models,
  });
}
