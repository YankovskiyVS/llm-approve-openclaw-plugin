# Strict Structured Judge Output Design

## Status

Approved by the user through the instruction to implement the recommended
approach without adding a Python sidecar.

## Goal

Make the seven-field judge verdict a single, portable JSON Schema contract,
enforce that contract in the Cloud.ru model request, and validate the same
contract locally before any action can be allowed.

## Confirmed provider capability

On 2026-07-14 the fixed Cloud.ru endpoint and model
`Qwen/Qwen3.5-397B-A17B` accepted
`response_format.type=json_schema` with `strict=true`. A second probe used a
prompt that requested a string and an extra property while the schema required
one integer and `additionalProperties=false`; the response was HTTP 200 and
contained only the schema-valid integer. The official Cloud.ru model catalog
also marks this model as supporting Structure Output.

## Boundaries

- Keep the fixed model, profiles, hooks, action hash, local safety guard, and
  fail-closed mappings unchanged.
- Do not add Python or a Pydantic runtime to the Node.js plugin.
- Do not fall back silently to `json_object`; transport incompatibility is a
  judge failure and follows the existing supervised/autonomous fail-closed
  behavior.
- Do not claim that schema validity proves the verdict is semantically safe.
  Existing authorization, risk, confidence, opaque-data, and deterministic
  guard checks remain mandatory.

## Architecture

### Canonical contract

Add `schemas/judge-verdict.schema.json` as the language-neutral source of truth.
It defines exactly these required fields and rejects additional properties:

- `policy_version`: string constant `2026-07-14.1`;
- `action_hash`: lowercase `sha256:` hash pattern;
- `decision`: `allow | deny | review`;
- `risk`: `low | medium | high | critical`;
- `authorization`: `unknown | low | medium | high`;
- `confidence`: finite JSON number from 0 through 1;
- `rationale`: string with length 1 through 500.

Whitespace-only rationale, control characters, and equality with the exact
expected action hash remain semantic checks outside the portable schema.

### Schema module

Add `src/judge-schema.js` to:

- load and defensively freeze the canonical schema;
- compile it once with Ajv in strict, non-coercing, non-mutating mode;
- expose the required key and enum vocabulary derived from the schema;
- validate parsed verdict objects without returning model-controlled error
  text;
- construct a defensive provider response format from the static canonical
  schema.

`POLICY_VERSION` is read from the canonical schema so the schema, prompt,
parser, and provider request cannot carry independent policy literals.

### Runtime flow

1. `judge-client` builds the existing trusted-intent and untrusted-action
   messages.
2. It sends `response_format={type:"json_schema", json_schema:{name,
   strict:true,schema}}` using the static schema so the provider can reuse its
   compiled grammar across requests.
3. `parseJudgeResponse` keeps the raw duplicate-key detector, parses one bare
   object, validates it with Ajv, and applies exact hash plus rationale checks.
4. `plugin` creates a descriptor-safe plain snapshot, validates the snapshot
   with the same schema, freezes it, and only then normalizes the verdict.
5. Any transport, parse, schema, hash, or semantic failure remains a failure:
   autonomous blocks; supervised requests one-call approval with timeout deny;
   shadow only audits.

## Dependency and packaging

Use an exact Ajv 8 dependency. Include `schemas/` in the npm package and keep
the JSON Schema directly consumable by platform teams. Python consumers may
generate a Pydantic model from this artifact, but Python is not part of the
plugin runtime.

## Tests

- Schema accepts exactly one valid verdict and rejects missing, extra, wrong
  type, enum, range, policy, and hash-shape cases.
- Provider response format is `json_schema`, strict, static across actions, and
  defensively copied.
- Judge client sends the exact strict response format.
- Existing duplicate-key, exact-hash, hostile parser, semantic downgrade, and
  fail-closed tests remain green.
- Release tests prove the schema and production dependency ship in the `.tgz`.
- A live Cloud.ru structured-output smoke validates one real seven-field
  response before release.

## Release

Ship as plugin `0.4.0` with policy `2026-07-14.1`. Although the decision rules
and seven fields remain the same, provider-constrained generation can change
model behavior, so old metrics must not be attributed to this release without
a fresh fixed-model qualification run. Update the contract, security,
deployment, R&D, changelog, release artifact, checksums, isolated OpenClaw
runtime smoke, tag, and GitLab branch.
