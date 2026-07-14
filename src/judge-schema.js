import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const INVALID_VERDICT_ERROR = 'invalid judge verdict';
const CONTRACT_UNAVAILABLE_ERROR = 'judge verdict contract unavailable';
const schemaUrl = new URL('../schemas/judge-verdict.schema.json', import.meta.url);
const require = createRequire(import.meta.url);
const EMPTY_VOCABULARY = Object.freeze([]);

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

function frozenStrings(values) {
  if (!Array.isArray(values)
    || values.length === 0
    || values.some((value) => typeof value !== 'string' || value === '')
    || new Set(values).size !== values.length) throw new TypeError(CONTRACT_UNAVAILABLE_ERROR);
  return Object.freeze([...values]);
}

function deriveVocabulary(schema) {
  const properties = schema.properties;
  const verdictKeys = frozenStrings(schema.required);
  if (!sameValues(Object.keys(properties), verdictKeys)) {
    throw new TypeError(CONTRACT_UNAVAILABLE_ERROR);
  }
  const policyVersion = properties.policy_version.const;
  if (typeof policyVersion !== 'string' || policyVersion === '') {
    throw new TypeError(CONTRACT_UNAVAILABLE_ERROR);
  }
  return Object.freeze({
    policyVersion,
    verdictKeys,
    decisions: frozenStrings(properties.decision.enum),
    risks: frozenStrings(properties.risk.enum),
    authorizations: frozenStrings(properties.authorization.enum),
  });
}

function unavailableContract() {
  function unavailable() {
    throw new TypeError(CONTRACT_UNAVAILABLE_ERROR);
  }
  return Object.freeze({
    schema: null,
    policyVersion: null,
    verdictKeys: EMPTY_VOCABULARY,
    decisions: EMPTY_VOCABULARY,
    risks: EMPTY_VOCABULARY,
    authorizations: EMPTY_VOCABULARY,
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
    const vocabulary = deriveVocabulary(schema);

    return Object.freeze({
      schema,
      ...vocabulary,
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
export const JUDGE_POLICY_VERSION = defaultContract.policyVersion;
export const JUDGE_VERDICT_KEYS = defaultContract.verdictKeys;
export const JUDGE_DECISIONS = defaultContract.decisions;
export const JUDGE_RISKS = defaultContract.risks;
export const JUDGE_AUTHORIZATIONS = defaultContract.authorizations;

export function validateJudgeVerdict(value) {
  return defaultContract.validateJudgeVerdict(value);
}

export function createJudgeResponseFormat() {
  return defaultContract.createJudgeResponseFormat();
}
