# Strict Structured Judge Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce the fixed seven-field judge verdict through one packaged JSON Schema at the Cloud.ru API boundary and again inside the Node.js plugin.

**Architecture:** A canonical static JSON Schema becomes the source of contract vocabulary and policy version. Ajv validates parsed snapshots locally, while the same static schema is sent through Cloud.ru `json_schema` Structured Output so provider grammar compilation can be reused. Raw duplicate detection, exact action-hash equality, and semantic safety gates remain separate and fail closed.

**Tech Stack:** Node.js 22.19+, ECMAScript modules, JSON Schema draft-07, Ajv 8, Node test runner, OpenClaw plugin hooks, Cloud.ru OpenAI-compatible Chat Completions API.

## Global Constraints

- Keep model `Qwen/Qwen3.5-397B-A17B` fixed and ship policy `2026-07-14.1`.
- Never fall back from strict `json_schema` to `json_object` at runtime.
- Never add a Python runtime or sidecar to the plugin.
- Never let schema validity bypass exact-hash, risk, authorization, confidence, opaque-data, or deterministic local guard checks.
- Any new failure path must preserve autonomous block and supervised one-call approval with timeout deny.

---

### Task 1: Canonical verdict schema and local validator

**Files:**
- Create: `schemas/judge-verdict.schema.json`
- Create: `src/judge-schema.js`
- Create: `test/judge-schema.test.js`
- Modify: `src/constants.js`
- Modify: `package.json`
- Create: `package-lock.json`

**Interfaces:**
- Produces: `JUDGE_VERDICT_SCHEMA`, `JUDGE_VERDICT_KEYS`, enum arrays,
  `validateJudgeVerdict(value)`, and `createJudgeResponseFormat()`.
- Consumes: the canonical schema only; no plugin runtime state.

- [ ] Write tests proving exact schema acceptance/rejection, non-coercion,
  immutability, generic errors, exact response-format shape, and defensive
  static-schema copies.
- [ ] Run `node --test test/judge-schema.test.js` and confirm RED because the
  module and schema do not exist.
- [ ] Add the draft-07 schema, exact Ajv dependency, schema module, and derive
  `POLICY_VERSION` from the schema.
- [ ] Run `node --test test/judge-schema.test.js` and confirm PASS.

### Task 2: Provider-enforced Structured Output

**Files:**
- Modify: `src/judge-client.js`
- Modify: `src/prompt.js`
- Modify: `test/judge-client.test.js`
- Modify: `test/decision.test.js`

**Interfaces:**
- Consumes: `createJudgeResponseFormat()` and schema-derived key vocabulary.
- Produces: an exact Cloud.ru request using the static schema with
  `type=json_schema` and `strict=true` without fallback.

- [ ] Change tests to require strict `json_schema`, a static schema, local exact
  action-hash binding, and schema-derived prompt vocabulary.
- [ ] Run the focused tests and confirm RED against the current `json_object`
  request.
- [ ] Build the strict static response format with `createJudgeResponseFormat()`;
  keep the envelope hash in the prompt and local exact-equality check, and
  remove the duplicated literal output example from the prompt.
- [ ] Run `node --test test/judge-client.test.js test/decision.test.js` and
  confirm PASS.

### Task 3: Shared local validation and hardened snapshot

**Files:**
- Modify: `src/decision.js`
- Modify: `src/plugin.js`
- Modify: `test/decision.test.js`
- Modify: `test/plugin.test.js`

**Interfaces:**
- Consumes: schema validator and schema-derived keys/enums.
- Produces: duplicate-safe parsing plus a descriptor-safe, schema-validated,
  frozen verdict snapshot.

- [ ] Add tests showing an injected parser cannot exploit schema drift and that
  schema-invalid values always map to existing fail-closed outcomes.
- [ ] Run focused tests and confirm RED for the new shared-validator assertions.
- [ ] Replace duplicated shape/type/enum checks with schema validation while
  preserving duplicate-key, expected-hash, rationale, descriptor, and freeze
  checks.
- [ ] Run `node --test test/judge-schema.test.js test/decision.test.js test/plugin.test.js` and confirm PASS.

### Task 4: Package and integration contract

**Files:**
- Modify: `package.json`
- Modify: `test/release-package.test.js`
- Modify: `CONTRACT.md`
- Modify: `SECURITY.md`
- Modify: `README.md`
- Modify: `DEPLOYMENT.md`
- Modify: `RND.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: canonical schema and new runtime behavior.
- Produces: plugin `0.4.0` package containing `schemas/judge-verdict.schema.json`
  and explicit Structured Output/fail-closed documentation.

- [ ] Update release tests first to require version `0.4.0`, packaged schema,
  Ajv dependency metadata, and policy `2026-07-14.1`.
- [ ] Run release tests and confirm RED against `0.3.0` packaging.
- [ ] Update package metadata and documentation without changing public ENV or
  hook contracts.
- [ ] Run release tests and confirm PASS.

### Task 5: Verification and release publication

**Files:**
- Create: `releases/v0.4.0/*` through the reviewed release builder.
- Modify: Git history and tag only after every verification gate passes.

**Interfaces:**
- Consumes: completed source, tests, docs, and release builder.
- Produces: verified `.tgz`, checksums, evidence, tag `v0.4.0`, and pushed
  `main`.

- [ ] Run `npm test`; require zero failures.
- [ ] Run a live Cloud.ru seven-field strict-schema request with the fixed model;
  require HTTP 200, `finish_reason=stop`, schema validity, and exact action hash.
- [ ] Re-run the frozen fixed-model qualification corpus under policy
  `2026-07-14.1`; do not reuse old safety metrics for the release claim.
- [ ] Run source and packaged runtime smoke in an isolated OpenClaw state;
  require two hooks, no diagnostics, safe allow, deterministic guard block,
  invalid-response fail-closed, and secret-free audit mode `0600`.
- [ ] Build `releases/v0.4.0`, verify all SHA-256 files and archive contents, and
  re-run `npm test` after artifact creation.
- [ ] Review `git diff --check`, secret scans, package file list, and remote
  target.
- [ ] Commit source/docs, commit verified release artifacts, tag `v0.4.0`, push
  `main` and tag, then verify remote refs.
