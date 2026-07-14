import { readFileSync } from 'node:fs';
import Ajv from 'ajv';

const INVALID_VERDICT_ERROR = 'invalid judge verdict';

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const schemaUrl = new URL('../schemas/judge-verdict.schema.json', import.meta.url);
const parsedSchema = JSON.parse(readFileSync(schemaUrl, 'utf8'));

export const JUDGE_VERDICT_SCHEMA = deepFreeze(parsedSchema);
export const JUDGE_VERDICT_KEYS = Object.freeze([...JUDGE_VERDICT_SCHEMA.required]);
export const JUDGE_DECISIONS = Object.freeze([
  ...JUDGE_VERDICT_SCHEMA.properties.decision.enum,
]);
export const JUDGE_RISKS = Object.freeze([
  ...JUDGE_VERDICT_SCHEMA.properties.risk.enum,
]);
export const JUDGE_AUTHORIZATIONS = Object.freeze([
  ...JUDGE_VERDICT_SCHEMA.properties.authorization.enum,
]);

const ajv = new Ajv({
  strict: true,
  strictNumbers: true,
  coerceTypes: false,
  useDefaults: false,
  removeAdditional: false,
});
const validate = ajv.compile(JUDGE_VERDICT_SCHEMA);

export function validateJudgeVerdict(value) {
  try {
    if (validate(value)) return;
  } catch {
    // Normalize traps from hostile values just like ordinary schema failures.
  }
  throw new TypeError(INVALID_VERDICT_ERROR);
}

export function createJudgeResponseFormat() {
  return {
    type: 'json_schema',
    json_schema: {
      name: 'judge_verdict',
      strict: true,
      schema: structuredClone(JUDGE_VERDICT_SCHEMA),
    },
  };
}
