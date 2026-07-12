import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { aggregateQualification } from '../evals/lib/aggregate.mjs';

const PRICING_URL = new URL('../evals/fixtures/fixed-judge-pricing.json', import.meta.url);

test('fixed judge pricing pins the official Qwen3.5-397B token price', () => {
  const pricing = JSON.parse(readFileSync(PRICING_URL, 'utf8'));

  assert.deepEqual(pricing, {
    schema_version: 'judge-pricing.v1',
    currency: 'RUB',
    captured_on: '2026-07-12',
    models: {
      'Qwen/Qwen3.5-397B-A17B': {
        input_per_million: 915,
        output_per_million: 1085.8,
        source: 'https://cloud.ru/products/evolution-ai-factory/catalog-foundation-models',
      },
    },
  });
  assert.doesNotThrow(() => aggregateQualification({
    attempts: [],
    expectedRepeats: 3,
    pricing,
  }));
});
