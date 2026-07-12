import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { aggregateQualification } from '../evals/lib/aggregate.mjs';
import {
  MODEL_SELECTION_PRICING_URL,
  toAggregatePricing,
  validateModelSelectionPricing,
} from '../evals/lib/model-selection-pricing.mjs';

const SOURCE = 'https://cloud.ru/products/evolution-ai-factory/catalog-foundation-models';
const PRICES = Object.freeze({
  'zai-org/GLM-4.7': Object.freeze([549, 793]),
  'Qwen/Qwen3.6-35B-A3B': Object.freeze([219.6, 329.4]),
  'Qwen/Qwen3.5-397B-A17B': Object.freeze([915, 1085.8]),
  'Qwen/Qwen3-Coder-Next': Object.freeze([122, 244]),
  'deepseek-ai/DeepSeek-V4-Pro': Object.freeze([183, 732]),
});
const ELIGIBLE_IDS = Object.freeze([
  'zai-org/GLM-4.7',
  'Qwen/Qwen3.6-35B-A3B',
  'Qwen/Qwen3.5-397B-A17B',
  'Qwen/Qwen3-Coder-Next',
  'qwen36-27b-fp8',
  'deepseek-ai/DeepSeek-V4-Pro',
]);

function fixture() {
  return JSON.parse(readFileSync(MODEL_SELECTION_PRICING_URL, 'utf8'));
}

test('official selection pricing validates exact eligible prices and converts for aggregate', () => {
  const snapshot = validateModelSelectionPricing(fixture());

  assert.equal(snapshot.schema_version, 'judge-model-selection-pricing.v1');
  assert.equal(snapshot.currency, 'RUB');
  assert.equal(snapshot.captured_on, '2026-07-12');
  assert.equal(snapshot.token_price_source, SOURCE);
  assert.deepEqual(Object.keys(snapshot.models), ELIGIBLE_IDS);
  for (const [modelId, [input, output]] of Object.entries(PRICES)) {
    assert.deepEqual(snapshot.models[modelId], {
      billing: 'per_token',
      input_per_million: input,
      output_per_million: output,
    });
  }
  assert.deepEqual(snapshot.models['qwen36-27b-fp8'], {
    billing: 'infrastructure',
    per_token_pricing: 'unavailable',
    reason: 'vllm_endpoint_has_no_per_token_price',
  });

  const aggregatePricing = toAggregatePricing(snapshot);
  assert.deepEqual(aggregatePricing, {
    schema_version: 'judge-pricing.v1',
    currency: 'RUB',
    captured_on: '2026-07-12',
    models: Object.fromEntries(Object.entries(PRICES).map(([modelId, [input, output]]) => [
      modelId,
      {
        input_per_million: input,
        output_per_million: output,
        source: SOURCE,
      },
    ])),
  });
  assert.doesNotThrow(() => aggregateQualification({
    attempts: [],
    expectedRepeats: 1,
    pricing: aggregatePricing,
  }));
});

test('selection pricing rejects missing, extra, reordered, or changed eligible models', () => {
  const base = fixture();
  const missing = structuredClone(base);
  delete missing.models['zai-org/GLM-4.7'];
  const extra = structuredClone(base);
  extra.models['unknown/model'] = structuredClone(extra.models['zai-org/GLM-4.7']);
  const reordered = structuredClone(base);
  reordered.models = Object.fromEntries(Object.entries(reordered.models).reverse());
  const changed = structuredClone(base);
  changed.models['Qwen/Qwen3.6-35B-A3B'].input_per_million = 219.61;

  for (const value of [missing, extra, reordered, changed]) {
    assert.throws(() => validateModelSelectionPricing(value), /invalid model-selection pricing/u);
  }
});

test('vLLM eligibility must be explicit infrastructure billing with unavailable token price', () => {
  const missing = fixture();
  delete missing.models['qwen36-27b-fp8'];
  const disguisedZero = fixture();
  disguisedZero.models['qwen36-27b-fp8'] = {
    billing: 'per_token',
    input_per_million: 0,
    output_per_million: 0,
  };
  const changedReason = fixture();
  changedReason.models['qwen36-27b-fp8'].reason = 'unknown';

  for (const value of [missing, disguisedZero, changedReason]) {
    assert.throws(() => validateModelSelectionPricing(value), /invalid model-selection pricing/u);
  }
});

test('selection pricing rejects unknown fields, unsafe source, accessors, and proxies without traps', () => {
  const extra = { ...fixture(), extra: true };
  const sourceVariants = [
    'http://cloud.ru/products/evolution-ai-factory/catalog-foundation-models',
    'https://user:pass@cloud.ru/products/evolution-ai-factory/catalog-foundation-models',
    `${SOURCE}?token=secret`,
    `${SOURCE}#prices`,
    '/Users/example/pricing.json',
  ];
  assert.throws(() => validateModelSelectionPricing(extra), /invalid model-selection pricing/u);
  for (const token_price_source of sourceVariants) {
    assert.throws(
      () => validateModelSelectionPricing({ ...fixture(), token_price_source }),
      /invalid model-selection pricing/u,
    );
  }

  const accessor = fixture();
  Object.defineProperty(accessor.models['zai-org/GLM-4.7'], 'input_per_million', {
    enumerable: true,
    get() {
      throw new Error('must not execute');
    },
  });
  assert.throws(() => validateModelSelectionPricing(accessor), /invalid model-selection pricing/u);

  let traps = 0;
  const proxy = new Proxy({}, {
    ownKeys() {
      traps += 1;
      throw new Error('must not execute');
    },
  });
  assert.throws(() => validateModelSelectionPricing(proxy), /invalid model-selection pricing/u);
  assert.equal(traps, 0);
});

test('validated and aggregate snapshots are immutable detached copies', () => {
  const raw = fixture();
  const validated = validateModelSelectionPricing(raw);
  const aggregatePricing = toAggregatePricing(validated);
  raw.models['zai-org/GLM-4.7'].input_per_million = 1;

  assert.equal(validated.models['zai-org/GLM-4.7'].input_per_million, 549);
  assert.throws(() => {
    validated.models['zai-org/GLM-4.7'].input_per_million = 1;
  }, TypeError);
  assert.throws(() => {
    aggregatePricing.models['zai-org/GLM-4.7'].input_per_million = 1;
  }, TypeError);
});
