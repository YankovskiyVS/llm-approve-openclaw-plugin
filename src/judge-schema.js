import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const INVALID_VERDICT_ERROR = 'invalid judge verdict';
const CONTRACT_UNAVAILABLE_ERROR = 'judge verdict contract unavailable';
const schemaUrl = new URL('../schemas/judge-verdict.schema.json', import.meta.url);
const require = createRequire(import.meta.url);

export const JUDGE_POLICY_VERSION = '2026-07-14.1';
export const JUDGE_VERDICT_KEYS = Object.freeze([
  'policy_version',
  'action_hash',
  'decision',
  'risk',
  'authorization',
  'confidence',
  'rationale',
]);
export const JUDGE_DECISIONS = Object.freeze(['allow', 'deny', 'review']);
export const JUDGE_RISKS = Object.freeze(['low', 'medium', 'high', 'critical']);
export const JUDGE_AUTHORIZATIONS = Object.freeze(['unknown', 'low', 'medium', 'high']);

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function sameValues(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function matchesBootstrapVocabulary(schema) {
  try {
    const properties = schema.properties;
    return sameValues(schema.required, JUDGE_VERDICT_KEYS)
      && sameValues(Object.keys(properties), JUDGE_VERDICT_KEYS)
      && properties.policy_version.const === JUDGE_POLICY_VERSION
      && sameValues(properties.decision.enum, JUDGE_DECISIONS)
      && sameValues(properties.risk.enum, JUDGE_RISKS)
      && sameValues(properties.authorization.enum, JUDGE_AUTHORIZATIONS);
  } catch {
    return false;
  }
}

function unavailableContract() {
  function unavailable() {
    throw new TypeError(CONTRACT_UNAVAILABLE_ERROR);
  }
  return Object.freeze({
    schema: null,
    validateJudgeVerdict: unavailable,
    createJudgeResponseFormat: unavailable,
  });
}

function defaultReadSchema() {
  return readFileSync(schemaUrl, 'utf8');
}

function defaultLoadAjv() {
  const loaded = require('ajv');
  return loaded?.default ?? loaded;
}

export function createJudgeSchemaContract(dependencies = {}) {
  try {
    const readSchema = dependencies.readSchema ?? defaultReadSchema;
    const loadAjv = dependencies.loadAjv ?? defaultLoadAjv;
    if (typeof readSchema !== 'function' || typeof loadAjv !== 'function') {
      return unavailableContract();
    }

    const schema = deepFreeze(JSON.parse(readSchema()));
    if (!matchesBootstrapVocabulary(schema)) return unavailableContract();

    const Ajv = loadAjv();
    if (typeof Ajv !== 'function') return unavailableContract();
    const ajv = new Ajv({
      strict: true,
      strictNumbers: true,
      coerceTypes: false,
      useDefaults: false,
      removeAdditional: false,
      ownProperties: true,
    });
    const validate = ajv.compile(schema);
    if (typeof validate !== 'function') return unavailableContract();

    return Object.freeze({
      schema,
      validateJudgeVerdict(value) {
        try {
          if (validate(value)) return;
        } catch {
          // Normalize traps from hostile values just like ordinary schema failures.
        }
        throw new TypeError(INVALID_VERDICT_ERROR);
      },
      createJudgeResponseFormat() {
        return {
          type: 'json_schema',
          json_schema: {
            name: 'judge_verdict',
            strict: true,
            schema: structuredClone(schema),
          },
        };
      },
    });
  } catch {
    return unavailableContract();
  }
}

const defaultContract = createJudgeSchemaContract();

export const JUDGE_VERDICT_SCHEMA = defaultContract.schema;

export function validateJudgeVerdict(value) {
  return defaultContract.validateJudgeVerdict(value);
}

export function createJudgeResponseFormat() {
  return defaultContract.createJudgeResponseFormat();
}
