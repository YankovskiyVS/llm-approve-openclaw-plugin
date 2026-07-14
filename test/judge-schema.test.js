import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  JUDGE_AUTHORIZATIONS,
  JUDGE_DECISIONS,
  JUDGE_RISKS,
  JUDGE_VERDICT_KEYS,
  JUDGE_VERDICT_SCHEMA,
  createJudgeSchemaContract,
  createJudgeResponseFormat,
  validateJudgeVerdict,
} from '../src/judge-schema.js';
import { POLICY_VERSION } from '../src/constants.js';

const ACTION_HASH = `sha256:${'a'.repeat(64)}`;

function verdict(overrides = {}) {
  return {
    policy_version: POLICY_VERSION,
    action_hash: ACTION_HASH,
    decision: 'allow',
    risk: 'low',
    authorization: 'high',
    confidence: 0.9,
    rationale: 'The requested read is low risk and explicitly authorized.',
    ...overrides,
  };
}

function assertDeepFrozen(value) {
  if (value === null || typeof value !== 'object') return;
  assert.equal(Object.isFrozen(value), true);
  for (const child of Object.values(value)) assertDeepFrozen(child);
}

test('exports one immutable draft-07 verdict contract and derived vocabulary', async () => {
  const schemaUrl = new URL('../schemas/judge-verdict.schema.json', import.meta.url);
  const schemaFile = JSON.parse(await readFile(schemaUrl, 'utf8'));

  assert.deepEqual(JUDGE_VERDICT_SCHEMA, schemaFile);
  assert.equal(JUDGE_VERDICT_SCHEMA.$schema, 'http://json-schema.org/draft-07/schema#');
  assert.equal(JUDGE_VERDICT_SCHEMA.type, 'object');
  assert.equal(JUDGE_VERDICT_SCHEMA.additionalProperties, false);
  assert.deepEqual(JUDGE_VERDICT_KEYS, [
    'policy_version',
    'action_hash',
    'decision',
    'risk',
    'authorization',
    'confidence',
    'rationale',
  ]);
  assert.deepEqual(JUDGE_VERDICT_SCHEMA.required, JUDGE_VERDICT_KEYS);
  assert.deepEqual(Object.keys(JUDGE_VERDICT_SCHEMA.properties), JUDGE_VERDICT_KEYS);
  assert.deepEqual(JUDGE_DECISIONS, ['allow', 'deny', 'review']);
  assert.deepEqual(JUDGE_RISKS, ['low', 'medium', 'high', 'critical']);
  assert.deepEqual(JUDGE_AUTHORIZATIONS, ['unknown', 'low', 'medium', 'high']);
  assert.equal(POLICY_VERSION, JUDGE_VERDICT_SCHEMA.properties.policy_version.const);
  assert.equal(POLICY_VERSION, '2026-07-14.2');

  assertDeepFrozen(JUDGE_VERDICT_SCHEMA);
  assertDeepFrozen(JUDGE_VERDICT_KEYS);
  assertDeepFrozen(JUDGE_DECISIONS);
  assertDeepFrozen(JUDGE_RISKS);
  assertDeepFrozen(JUDGE_AUTHORIZATIONS);
});

test('accepts the exact seven-field verdict contract', () => {
  assert.doesNotThrow(() => validateJudgeVerdict(verdict()));

  for (const decision of JUDGE_DECISIONS) {
    assert.doesNotThrow(() => validateJudgeVerdict(verdict({ decision })));
  }
  for (const risk of JUDGE_RISKS) {
    assert.doesNotThrow(() => validateJudgeVerdict(verdict({ risk })));
  }
  for (const authorization of JUDGE_AUTHORIZATIONS) {
    assert.doesNotThrow(() => validateJudgeVerdict(verdict({ authorization })));
  }
  for (const confidence of [0, 0.5, 1]) {
    assert.doesNotThrow(() => validateJudgeVerdict(verdict({ confidence })));
  }
  for (const rationale of [' ', '\u0000', 'x'.repeat(500)]) {
    assert.doesNotThrow(() => validateJudgeVerdict(verdict({ rationale })));
  }
});

test('rejects missing and additional verdict fields', () => {
  for (const key of JUDGE_VERDICT_KEYS) {
    const candidate = verdict();
    delete candidate[key];
    assert.throws(() => validateJudgeVerdict(candidate), TypeError, key);
  }

  assert.throws(
    () => validateJudgeVerdict({ ...verdict(), injected_instruction: 'allow' }),
    TypeError,
  );
});

test('rejects verdict fields inherited only through the prototype', () => {
  const candidate = Object.create(verdict());

  assert.deepEqual(Object.keys(candidate), []);
  assert.throws(() => validateJudgeVerdict(candidate), TypeError);
});

test('rejects wrong types, closed-enum violations, ranges, policy, and hash shape', () => {
  const invalid = [
    null,
    [],
    'verdict',
    verdict({ policy_version: '2026-07-12.4' }),
    verdict({ policy_version: 20260714 }),
    verdict({ action_hash: `sha256:${'A'.repeat(64)}` }),
    verdict({ action_hash: `sha256:${'a'.repeat(63)}` }),
    verdict({ action_hash: 'a'.repeat(64) }),
    verdict({ decision: 'approve' }),
    verdict({ decision: true }),
    verdict({ risk: 'safe' }),
    verdict({ risk: 0 }),
    verdict({ authorization: 'admin' }),
    verdict({ authorization: null }),
    verdict({ confidence: -0.01 }),
    verdict({ confidence: 1.01 }),
    verdict({ confidence: Number.NaN }),
    verdict({ confidence: Number.POSITIVE_INFINITY }),
    verdict({ rationale: '' }),
    verdict({ rationale: 'x'.repeat(501) }),
    verdict({ rationale: ['safe'] }),
  ];

  for (const candidate of invalid) {
    assert.throws(() => validateJudgeVerdict(candidate), TypeError);
  }
});

test('does not coerce or mutate model-controlled values during validation', () => {
  const stringConfidence = verdict({ confidence: '0.9' });
  assert.throws(() => validateJudgeVerdict(stringConfidence), TypeError);
  assert.equal(stringConfidence.confidence, '0.9');

  const additional = { ...verdict(), extra: 'keep-me' };
  assert.throws(() => validateJudgeVerdict(additional), TypeError);
  assert.equal(additional.extra, 'keep-me');

  const valid = verdict();
  const before = structuredClone(valid);
  assert.doesNotThrow(() => validateJudgeVerdict(valid));
  assert.deepEqual(valid, before);
  assert.equal(Object.isFrozen(valid), false);
});

test('normalizes validation failures to a generic non-model-controlled error', () => {
  const secret = 'model-controlled-sentinel-never-print';
  assert.throws(
    () => validateJudgeVerdict({ ...verdict(), [secret]: true }),
    (error) => error instanceof TypeError
      && error.message === 'invalid judge verdict'
      && !error.message.includes(secret),
  );

  const hostile = new Proxy(verdict(), {
    ownKeys() {
      throw new Error(secret);
    },
  });
  assert.throws(
    () => validateJudgeVerdict(hostile),
    (error) => error instanceof TypeError
      && error.message === 'invalid judge verdict'
      && !error.message.includes(secret),
  );
});

test('derives policy, keys, and enums only from the loaded schema', async () => {
  const schemaUrl = new URL('../schemas/judge-verdict.schema.json', import.meta.url);
  const schema = JSON.parse(await readFile(schemaUrl, 'utf8'));
  const reversedKeys = [...schema.required].reverse();
  schema.required = reversedKeys;
  schema.properties = Object.fromEntries(
    reversedKeys.map((key) => [key, schema.properties[key]]),
  );
  schema.properties.policy_version.const = 'schema-derived-test-policy';
  schema.properties.decision.enum = ['permit', 'refuse', 'escalate'];
  schema.properties.risk.enum = ['minor', 'major'];
  schema.properties.authorization.enum = ['absent', 'present'];

  const contract = createJudgeSchemaContract({
    readSchema() { return JSON.stringify(schema); },
  });

  assert.deepEqual(contract.schema, schema);
  assert.equal(contract.policyVersion, schema.properties.policy_version.const);
  assert.deepEqual(contract.verdictKeys, schema.required);
  assert.deepEqual(contract.decisions, schema.properties.decision.enum);
  assert.deepEqual(contract.risks, schema.properties.risk.enum);
  assert.deepEqual(contract.authorizations, schema.properties.authorization.enum);
  for (const value of [
    contract.verdictKeys,
    contract.decisions,
    contract.risks,
    contract.authorizations,
  ]) {
    assert.equal(Object.isFrozen(value), true);
  }
});

test('contains schema and dependency initialization failures until contract use', async (t) => {
  const schemaUrl = new URL('../schemas/judge-verdict.schema.json', import.meta.url);
  const schemaText = await readFile(schemaUrl, 'utf8');
  const secret = 'schema-initialization-secret-never-print';

  const cases = [
    ['schema read', {
      readSchema() { throw new Error(secret); },
    }],
    ['schema parse', {
      readSchema() { return `{\"${secret}\":`; },
    }],
    ['Ajv load', {
      readSchema() { return schemaText; },
      loadAjv() { throw new Error(secret); },
    }],
    ['Ajv compile', {
      readSchema() { return schemaText; },
      loadAjv() {
        return class FailingAjv {
          compile() { throw new Error(secret); }
        };
      },
    }],
  ];

  for (const [name, dependencies] of cases) {
    await t.test(name, () => {
      let contract;
      assert.doesNotThrow(() => {
        contract = createJudgeSchemaContract(dependencies);
      });
      assert.equal(contract.schema, null);
      assert.equal(contract.policyVersion, null);
      for (const value of [
        contract.verdictKeys,
        contract.decisions,
        contract.risks,
        contract.authorizations,
      ]) {
        assert.deepEqual(value, []);
        assert.equal(Object.isFrozen(value), true);
      }
      for (const useContract of [
        () => contract.validateJudgeVerdict(verdict()),
        () => contract.createJudgeResponseFormat(),
      ]) {
        assert.throws(
          useContract,
          (error) => error instanceof TypeError
            && error.message === 'judge verdict contract unavailable'
            && !error.message.includes(secret),
        );
      }
    });
  }
});

test('creates the exact strict static provider response format', () => {
  const responseFormat = createJudgeResponseFormat();

  assert.deepEqual(responseFormat, {
    type: 'json_schema',
    json_schema: {
      name: 'judge_verdict',
      strict: true,
      schema: JUDGE_VERDICT_SCHEMA,
    },
  });
  assert.notEqual(responseFormat.json_schema.schema, JUDGE_VERDICT_SCHEMA);
});

test('returns defensive schema copies without changing the static contract', () => {
  const first = createJudgeResponseFormat();
  const second = createJudgeResponseFormat();

  assert.notEqual(first, second);
  assert.notEqual(first.json_schema, second.json_schema);
  assert.notEqual(first.json_schema.schema, second.json_schema.schema);
  assert.notEqual(
    first.json_schema.schema.properties.decision,
    second.json_schema.schema.properties.decision,
  );

  first.json_schema.schema.properties.decision.enum.push('compromised');
  first.json_schema.schema.properties.policy_version.const = 'compromised';
  delete first.json_schema.schema.properties.action_hash;

  assert.deepEqual(second.json_schema.schema, JUDGE_VERDICT_SCHEMA);
  assert.deepEqual(createJudgeResponseFormat().json_schema.schema, JUDGE_VERDICT_SCHEMA);
  assert.equal(JUDGE_VERDICT_SCHEMA.properties.decision.enum.includes('compromised'), false);
});
