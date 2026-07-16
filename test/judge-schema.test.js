import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  JUDGE_AUTHORIZATIONS,
  JUDGE_DECISIONS,
  JUDGE_REASON_CODES,
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
  const candidate = {
    policy_version: POLICY_VERSION,
    action_hash: ACTION_HASH,
    decision: 'allow',
    risk: 'low',
    authorization: 'high',
    confidence: 0.9,
    reason_code: 'safe_and_authorized',
    rationale: 'The requested read is low risk and explicitly authorized.',
    ...overrides,
  };
  if (!Object.hasOwn(overrides, 'reason_code') && candidate.decision !== 'allow') {
    candidate.reason_code = 'other_policy_risk';
  }
  return candidate;
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
    'reason_code',
    'rationale',
  ]);
  assert.deepEqual(JUDGE_VERDICT_SCHEMA.required, JUDGE_VERDICT_KEYS);
  assert.deepEqual(Object.keys(JUDGE_VERDICT_SCHEMA.properties), JUDGE_VERDICT_KEYS);
  assert.deepEqual(JUDGE_DECISIONS, ['allow', 'deny', 'review']);
  assert.deepEqual(JUDGE_RISKS, ['low', 'medium', 'high', 'critical']);
  assert.deepEqual(JUDGE_AUTHORIZATIONS, ['unknown', 'low', 'medium', 'high']);
  assert.deepEqual(JUDGE_REASON_CODES, [
    'safe_and_authorized',
    'authorization_missing',
    'out_of_scope',
    'destructive_or_irreversible',
    'sensitive_data',
    'external_side_effect',
    'privilege_or_security_boundary',
    'untrusted_instruction',
    'self_modification',
    'opaque_or_unverifiable',
    'other_policy_risk',
  ]);
  assert.equal(POLICY_VERSION, JUDGE_VERDICT_SCHEMA.properties.policy_version.const);
  assert.equal(POLICY_VERSION, '2026-07-16.1');

  assertDeepFrozen(JUDGE_VERDICT_SCHEMA);
  assertDeepFrozen(JUDGE_VERDICT_KEYS);
  assertDeepFrozen(JUDGE_DECISIONS);
  assertDeepFrozen(JUDGE_RISKS);
  assertDeepFrozen(JUDGE_AUTHORIZATIONS);
  assertDeepFrozen(JUDGE_REASON_CODES);
});

test('accepts the exact eight-field verdict contract', () => {
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
  for (const reason_code of JUDGE_REASON_CODES.slice(1)) {
    assert.doesNotThrow(() => validateJudgeVerdict(verdict({
      decision: 'review',
      reason_code,
    })));
  }
});

test('rejects missing, unknown, and decision-incompatible reason codes', () => {
  const missing = verdict();
  delete missing.reason_code;

  for (const candidate of [
    missing,
    verdict({ reason_code: 'unknown_code' }),
    verdict({ decision: 'allow', reason_code: 'authorization_missing' }),
    verdict({ decision: 'review', reason_code: 'safe_and_authorized' }),
    verdict({ decision: 'deny', reason_code: 'safe_and_authorized' }),
  ]) {
    assert.throws(
      () => validateJudgeVerdict(candidate),
      (error) => error instanceof TypeError && error.message === 'invalid judge verdict',
    );
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
    verdict({ reason_code: null }),
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
  schema.properties.decision.enum = ['review', 'allow', 'deny'];
  schema.properties.risk.enum = ['minor', 'major'];
  schema.properties.authorization.enum = ['absent', 'present'];
  schema.properties.reason_code.enum = ['other_policy_risk', 'safe_and_authorized'];

  const contract = createJudgeSchemaContract({
    readSchema() { return JSON.stringify(schema); },
  });

  assert.deepEqual(contract.schema, schema);
  assert.equal(contract.policyVersion, schema.properties.policy_version.const);
  assert.deepEqual(contract.verdictKeys, schema.required);
  assert.deepEqual(contract.decisions, schema.properties.decision.enum);
  assert.deepEqual(contract.risks, schema.properties.risk.enum);
  assert.deepEqual(contract.authorizations, schema.properties.authorization.enum);
  assert.deepEqual(contract.reasonCodes, schema.properties.reason_code.enum);
  for (const value of [
    contract.verdictKeys,
    contract.decisions,
    contract.risks,
    contract.authorizations,
    contract.reasonCodes,
  ]) {
    assert.equal(Object.isFrozen(value), true);
  }
});

test('decision and reason compatibility is independent from enum order', async () => {
  const schemaUrl = new URL('../schemas/judge-verdict.schema.json', import.meta.url);
  const schema = JSON.parse(await readFile(schemaUrl, 'utf8'));
  schema.properties.decision.enum = ['deny', 'review', 'allow'];
  schema.properties.reason_code.enum = [
    'authorization_missing',
    'safe_and_authorized',
    'other_policy_risk',
  ];
  const contract = createJudgeSchemaContract({
    readSchema() { return JSON.stringify(schema); },
  });

  assert.doesNotThrow(() => contract.validateJudgeVerdict(verdict()));
  assert.doesNotThrow(() => contract.validateJudgeVerdict(verdict({
    decision: 'review',
    reason_code: 'authorization_missing',
  })));
  for (const candidate of [
    verdict({ decision: 'allow', reason_code: 'authorization_missing' }),
    verdict({ decision: 'deny', reason_code: 'safe_and_authorized' }),
  ]) {
    assert.throws(
      () => contract.validateJudgeVerdict(candidate),
      (error) => error instanceof TypeError && error.message === 'invalid judge verdict',
    );
  }
});

test('semantic anchors are required for an available judge contract', async () => {
  const schemaUrl = new URL('../schemas/judge-verdict.schema.json', import.meta.url);
  const original = JSON.parse(await readFile(schemaUrl, 'utf8'));
  for (const mutate of [
    (schema) => { schema.properties.decision.enum = ['deny', 'review']; },
    (schema) => { schema.properties.reason_code.enum = ['other_policy_risk']; },
  ]) {
    const schema = structuredClone(original);
    mutate(schema);
    const contract = createJudgeSchemaContract({
      readSchema() { return JSON.stringify(schema); },
    });
    assert.equal(contract.schema, null);
    assert.throws(
      () => contract.validateJudgeVerdict(verdict()),
      (error) => error instanceof TypeError
        && error.message === 'judge verdict contract unavailable',
    );
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
        contract.reasonCodes,
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
