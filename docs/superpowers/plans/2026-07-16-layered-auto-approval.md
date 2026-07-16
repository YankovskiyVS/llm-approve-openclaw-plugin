# Layered Auto-Approval v0.5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to execute this plan task-by-task.
> Every behavior change follows RED -> GREEN -> focused regression -> review.

**Goal:** Release one OpenClaw plugin that automatically executes only validated
safe actions, returns a bounded actionable tool result for every plugin-controlled
block, and stops repeated bypass attempts within one run.

**Architecture:** `before_tool_call` builds one immutable action snapshot. Narrow
deterministic hard boundaries run before the fixed Qwen judge; a conservative
safe-path is measured in shadow but does not skip Qwen in `0.5.0`. Strict
Structured Output plus local semantic validation produces the decision. Host-owned
feedback templates become OpenClaw `blockReason`; bounded per-run history drives
the judge context and a circuit breaker. Existing sandbox, IAM, native approval,
TOCTOU, redaction, opaque-data and local-guard layers remain in force.

**Tech Stack:** Node.js 22.19+, ECMAScript modules, OpenClaw >=2026.6.11,
Cloud.ru OpenAI-compatible Chat Completions, Qwen/Qwen3.5-397B-A17B, Ajv 8,
JSON Schema draft-07, Node test runner.

## Global constraints

- Source of truth is this repository, not the installed extension or stale
  `openclaw_research/openclaw-llm-action-judge` copy.
- Preserve the existing dirty `0.4.1` hardening delta; never reset, restore, or
  rewrite frozen public benchmark artifacts.
- Ship package `0.5.0` and policy/schema `2026-07-16.1` with the model fixed to
  `Qwen/Qwen3.5-397B-A17B`.
- Keep the existing judge timeout default and bound at 30 seconds; do not regress
  it to 8 seconds.
- `shadow` stays truly observe-only. Hard boundaries and the circuit breaker are
  enforced only in `autonomous` and `supervised`.
- Safe-path is metrics-only in `0.5.0`: every non-hard action still calls Qwen.
- Never expose raw rationale, prompt, params, matched fragments, secrets, model
  output, exception text, hidden reasoning, or internal rule identifiers through
  feedback or audit.
- Feedback is host-generated JSON, one line, strict closed vocabulary, at most
  1024 UTF-8 bytes.
- Fail closed: explicit deny and hard deny block in both enforcing modes;
  review/timeout/invalid block in autonomous and request native one-call approval
  in supervised.
- Circuit breaker thresholds are fixed: 3 consecutive denies or 10 denies among
  the last 50 decisions in the same `runId`. New runs start clean.
- Do not add model `reason_code` to historical persisted eval-attempt schemas in
  this release; publish new qualification artifacts rather than mutating old ones.

---

### Task 0: Review and checkpoint the existing v0.4.1 hardening delta

**Files:** All currently modified tracked files plus `src/intrinsics.js`.

- [ ] Capture current `git status`, base commit, diff statistics, and baseline
  `npm test` result in `.superpowers/sdd/progress.md`.
- [ ] Have an independent reviewer inspect the complete uncommitted delta for
  correctness, scope, secret leakage, artifact truthfulness, and accidental
  regression of autonomous/supervised/shadow behavior.
- [ ] Fix only concrete findings, then run `npm test` and `git diff --check`.
- [ ] Commit the reviewed `0.4.1` delta as its own checkpoint so subsequent task
  commits cannot accidentally absorb unrelated pre-existing changes.

### Task 1: Add the strict reason-code verdict contract

**Files:**
- Modify: `schemas/judge-verdict.schema.json`
- Modify: `src/judge-schema.js`
- Modify: `src/prompt.js`
- Modify: `src/decision.js`
- Modify: `src/plugin.js`
- Modify: `src/audit.js`
- Modify: `test/judge-schema.test.js`
- Modify: `test/decision.test.js`
- Modify: `test/plugin.test.js`
- Modify: `test/audit.test.js`
- Modify: synthetic verdict fixtures under `test/eval-*.test.js`
- Modify: `scripts/package-runtime-smoke.mjs`
- Modify: `test/release-package.test.js`

**Contract:** Export immutable `JUDGE_REASON_CODES`; require `reason_code` as the
eighth exact field. `allow` accepts only `safe_and_authorized`; `review`/`deny`
reject it. Unknown or contradictory codes make the verdict invalid.

- [ ] Write focused schema/parser/injected-parser/audit tests and confirm RED.
- [ ] Add schema-derived vocabulary, shared compatibility validation, prompt
  instructions, defensive plugin snapshot validation, and audit whitelist field.
- [ ] Migrate synthetic judge fixtures using a decision-compatible code without
  changing frozen artifact schemas.
- [ ] Run focused tests, then `npm test`; commit only after review.

### Task 2: Generate safe actionable block feedback

**Files:**
- Create: `src/feedback.js`
- Create: `test/feedback.test.js`
- Modify: `src/decision.js`
- Modify: `src/plugin.js`
- Modify: `src/audit.js`
- Modify: `test/decision.test.js`
- Modify: `test/plugin.test.js`
- Modify: `test/audit.test.js`

**Interface:** `createBlockFeedback(code) -> string` returns immutable,
schema-valid `openclaw.action-gate.feedback.v1` JSON for model and host codes.
Unknown input maps to `invalid_judge_response`. Model-controlled text is never
interpolated.

- [ ] Test every code, exact keys/enums, valid JSON, one-line output, byte bound,
  prototype-pollution inputs, and hostile sentinels from rationale/params/errors.
- [ ] Replace generic `blockReason` with safe feedback for explicit deny, hard
  deny, local/opaque downgrade, judge failure, invalid response and breaker.
- [ ] Include the same safe reason in supervised approval description where the
  native OpenClaw contract permits it.
- [ ] Audit only delivered feedback code/status, never full feedback text.
- [ ] Run focused tests and full suite; commit after review.

### Task 3: Add bounded per-run decision history and circuit breaker

**Files:**
- Create: `src/run-decision-store.js`
- Create: `test/run-decision-store.test.js`
- Modify: `src/plugin.js`
- Modify: `src/audit.js`
- Modify: `test/plugin.test.js`
- Modify: `test/audit.test.js`

**Interface:** A bounded TTL store keyed by trusted `runId` records only tool
family/name, final outcome, risk, authorization and reason code. `allow` resets
the consecutive counter; `review` and technical failure neither reset nor
increment deny counters. Once tripped, a run remains latched until state eviction.

- [ ] Test 3-consecutive and 10-of-50 thresholds, reset rules, new-run isolation,
  eviction/TTL, hostile run IDs, irreversible trip, and absence of
  params/results/rationale.
- [ ] Check breaker both before invoking Qwen and again after the awaited call to
  close the in-flight race; in enforcing modes return `repeated_denials`, while
  shadow records the candidate and still returns no hook mutation.
- [ ] Record the final decision exactly once on every completed plugin path and
  preserve TOCTOU and audit-failure semantics.
- [ ] Run focused tests and full suite; commit after review.

### Task 4: Introduce pre-LLM hard routing and safe-path shadow metrics

**Files:**
- Create: `src/policy-routing.js`
- Create: `test/policy-routing.test.js`
- Modify: `src/decision.js`
- Modify: `src/redact.js`
- Modify: `src/plugin.js`
- Modify: `src/audit.js`
- Modify: `test/decision.test.js`
- Modify: `test/redact.test.js`
- Modify: `test/plugin.test.js`
- Modify: `test/audit.test.js`

**Interface:** Compute one reusable local assessment from the immutable action.
Routing returns `hard_deny` only for exact self-modification, explicit secret to a
known external sink, exact typed security-boundary bypass, or tripped breaker.
Safe candidate is limited to positively proven exact no-side-effect shapes and
never includes read, shell, write, message, network, unknown, opaque, redacted,
truncated or malformed input.

- [ ] Characterize the existing post-LLM guard with parity tests before extracting
  a reusable assessment; preserve every current downgrade result.
- [ ] Add structured redaction provenance without exposing matched values.
- [ ] Test that hard deny skips the client in enforcing modes, cannot be promoted
  by a model, but remains observe-only in shadow.
- [ ] Test that every safe candidate still calls Qwen and that disagreement is
  calculated against the final post-opaque/post-local decision.
- [ ] Add enum-only audit fields `decision_source`, `safe_path_family`,
  `safe_path_candidate`, and `safe_path_disagreement`.
- [ ] Run focused tests and full suite; commit after review.

### Task 5: Supply bounded prior decisions to the judge

**Files:**
- Modify: `src/run-decision-store.js`
- Modify: `src/prompt.js`
- Modify: `src/judge-client.js`
- Modify: `src/plugin.js`
- Modify: `test/run-decision-store.test.js`
- Modify: `test/judge-client.test.js`
- Modify: `test/plugin.test.js`

**Contract:** The judge receives a frozen bounded summary of prior decisions for
the current run. It contains no raw tool output, assistant prose, tool parameters,
prompt text, hidden reasoning or dynamic exception text.

- [ ] Test exact history serialization, byte/item bounds, run isolation, and
  sentinel non-leakage.
- [ ] Bind the history summary into the judge prompt/envelope without weakening
  the current exact action-hash comparison.
- [ ] Keep empty history deterministic for runtime smoke and evaluation clients.
- [ ] Run focused tests and full suite; commit after review.

### Task 6: Extend evaluation and publish truthful v0.5 documentation

**Files:**
- Modify: `evals/lib/*` only where needed for new policy/source metrics
- Modify: relevant `test/eval-*.test.js`
- Modify: `.env.example`
- Modify: `README.md`
- Modify: `CONTRACT.md`
- Modify: `SECURITY.md`
- Modify: `DEPLOYMENT.md`
- Modify: `RND.md`
- Modify: `HOLDOUT.md`
- Modify: `CHANGELOG.md`
- Modify: `package.json`
- Modify: `scripts/build-release.mjs`
- Modify: `scripts/package-runtime-smoke.mjs`
- Modify: `test/release-package.test.js`

- [ ] Add source/shadow-disagreement metrics without rewriting historical public
  artifacts or claiming old scores for the new contract.
- [ ] Document block feedback visible to the worker, both enforcing modes,
  observe-only shadow, fixed breaker thresholds, ENV surface, audit privacy and
  exact install/run commands.
- [ ] Set version `0.5.0`; require all new runtime files/schema/docs in the package.
- [ ] Run eval-focused tests, package tests, `npm pack --dry-run`, full suite and
  secret scans; commit after review.

### Task 7: Qualify package and prove runtime behavior on stock OpenClaw

**Files:**
- Create: verified `releases/v0.5.0/*` using the reviewed builder
- Create: new qualification evidence only; keep historical artifacts immutable

- [ ] Run source and packed-install smoke in isolated OpenClaw state; require two
  hooks, zero diagnostics, autonomous/supervised/shadow behavior, strict feedback,
  breaker and audit file mode `0600`.
- [ ] Run a live strict-schema Cloud.ru request against the fixed Qwen endpoint;
  require HTTP success, exact policy/action hash and locally valid verdict.
- [ ] Run the new family-disjoint qualification corpus and report raw LLM versus
  hybrid FP/FN, dangerous recall, safe recall, failures, latency and token cost.
- [ ] Install the exact packed artifact into the local stock OpenClaw and run an
  interactive E2E proving `deny -> blockReason tool_result -> safer retry`, while
  verifying the blocked tool never executes.
- [ ] Build release checksums/evidence, run `npm test`, `git diff --check`, package
  content checks and repository secret scan one final time.
- [ ] Perform independent final code/security review; fix findings and repeat all
  affected gates.
- [ ] Commit release artifacts, tag `v0.5.0`, push `main` and tag, then verify
  remote refs and publish the exact package/checksum/runtime commands.
