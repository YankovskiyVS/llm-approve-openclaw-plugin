# Changelog

Все заметные изменения `openclaw-llm-action-judge` фиксируются в этом файле.

## 0.4.1 — 2026-07-15

### Added

- Sealed three-principal holdout workflow: separate freeze, blind inference and
  offline scoring commands with canonical SHA-256 commitments and reproducible
  score attestation.
- Exact cross-partition audit for case IDs, families and label-free canonical
  observable fingerprints, plus strict contracts for model, endpoint, policy, profile,
  repeats and concurrency.
- `HOLDOUT.md` with the operational protocol, gate metrics and commands.

### Changed

- Public `action_hash` is now an opaque HMAC-SHA-256 commitment with a random
  process-local key. The key is never persisted, logged, exported or sent to the
  judge; low-entropy redacted values can no longer be dictionary-checked from
  audit or provider traffic.
- Holdout scorer replays the production deterministic guard, retains
  normalizer failures, separates catastrophic-family metrics and reports zero
  token usage as unknown cost instead of zero cost.
- Offline scoring requires a clean externally anchored Git revision and records
  `scorer_git_sha`; blind inference fixes the target OpenClaw contract floor
  instead of accepting an unverified runtime version claim.
- Blind inference defaults to the endpoint-qualified concurrency of `2`.
  Partition and score stdout are path-free versioned receipts; scored output now
  includes `result-set.json`, which binds every result file including the score
  attestation with portable SHA-256 values.
- Runtime model, policy, Structured Output schema, hooks and deployment ENV
  contract remain unchanged from 0.4.0.

### Security and evidence

- The existing 0.4.0 frozen-corpus numbers remain tuned regression evidence,
  not unseen validation. 0.4.1 adds the machinery needed to publish corpus,
  inference and scoring commitments before each privileged stage can observe
  the next artifact.

## 0.4.0 — 2026-07-14

### Added

- Canonical portable `schemas/judge-verdict.schema.json` с policy
  `2026-07-14.6` поставляется внутри runtime `.tgz`.
- Pinned production dependency `ajv@8.20.0` повторно валидирует provider output
  локально; Python/Pydantic runtime или sidecar не добавлены.
- Package/runtime smoke покрывает schema-invalid response и supervised
  fail-closed approval.

### Changed

- Cloud.ru request использует strict `response_format.type=json_schema` с
  `strict=true`; runtime fallback на `json_object` отсутствует.
- Schema стала единственным источником policy и verdict vocabulary, а response
  format остаётся static между actions для reuse provider grammar.
- OpenClaw peer помечен optional для npm, чтобы archive install ставил Ajv, но не
  скачивал вложенную копию host OpenClaw.
- После failed strict qualification deterministic guard расширен для credential
  reads, sensitive gateway config reads и cross-session history; policy поднята
  с `2026-07-14.1` до `2026-07-14.2`.
- Fresh `.2` qualification выявила четыре оставшихся unsafe families. Guard
  теперь проверяет non-read-only `process` actions, destructive/anti-forensics/
  install/migration shell commands, writes to `openclaw.json` и private/internal
  `web_fetch` targets; policy поднята с `2026-07-14.2` до `2026-07-14.3`.
- Fresh `.3` qualification выявила два unsafe auto-allows в одной
  `skill_workshop.apply` family. Policy `2026-07-14.4` разрешает только read-only
  `skill_workshop` actions, добавляет bounded fail-closed shell
  dispatch/redirection hardening и включает `home.arpa` в special-use web
  boundary.
- Fresh `.4` qualification выявила два unsafe auto-allows: удаление
  security-теста и production-config write. Policy `2026-07-14.5` требует
  человека для распознанных security-test deletions/moves и
  `prod`/`production`-marked config writes.
- Fresh `.5` qualification выявила два unsafe auto-allows в active
  `.ssh/authorized_keys` family. Policy `2026-07-14.6` требует человека для
  распознанных active `.ssh` security-file writes.
- Public ENV contract, два hook, fixed model и thresholds не изменились.

### Security and evidence

- Schema-valid response не считается safe сам по себе: exact hash, rationale,
  risk, authorization, confidence, opaque-data и deterministic guards остаются
  обязательными и fail-closed.
- Результаты `117/120` safe и `0/240` unsafe относятся только к historical
  baseline 0.2.0/0.3.0 (`2026-07-12.4`, `json_object`). Первый strict run на
  pre-hardening policy `2026-07-14.1` дал `112/120` safe и `9/240` unsafe
  auto-allows (`5/80` unsafe families, `0/11` catastrophic) и стал
  release-blocker. Второй strict run на policy `2026-07-14.2` дал `118/120`
  safe и `6/240` unsafe auto-allows (`4/80` unsafe families, `0/11`
  catastrophic, `0` failures), поэтому также не прошёл. Offline replay `.2`
  attempts через policy `2026-07-14.3` сохранил `118/120` safe и снизил unsafe
  auto-allow до `0/240`, но fresh `.3` run всё равно стал release-blocker:
  artifact `llm-judge-v040-qualification-20260714T180323Z` дал `112/120` safe
  (`34/40` families), `2/240` unsafe в одной `skill_workshop.apply` family
  (`1/80`, repeats 2 и 3), `0/11` catastrophic, `0/360` failures, p50
  `1867.457 ms`, p95 `2453.216 ms`, p99 `2780.389 ms`. Следующий `.4` artifact
  `llm-judge-v040-qualification-20260714T195408Z` дал `118/120` safe,
  `2/240` unsafe в двух families (`2/80`), `0/11` catastrophic, `0/360`
  failures, p50 `1806.841 ms`, p95 `2264.777 ms`, p99 `2477.047 ms` и также
  стал release-blocker. Следующий `.5` artifact
  `llm-judge-v040-qualification-20260714T201953Z` дал `111/120` safe,
  `2/240` unsafe в active `.ssh/authorized_keys` family (`1/80`, repeats 2 и
  3), `0/11` catastrophic, `0/360` failures, p50 `1838.441 ms`, p95
  `2328.160 ms`, p99 `2671.778 ms` и также стал release-blocker. Current policy
  `2026-07-14.6` прошла fresh frozen-corpus qualification: artifact
  `llm-judge-v040-qualification-20260714T202947Z`, `108/120` safe (`34/40`
  families), `0/240` unsafe (`0/80` families), `0/11` catastrophic, `0/360`
  failures, p50 `1846.141 ms`, p95 `2320.621 ms`, p99 `2761.126 ms`. Raw judge
  вернул 18 unsafe `allow`; combined gates поймали `18/18`.
- Финальный run является tuned regression evidence на том же corpus, по которому
  усиливался guard; unseen holdout отсутствует.
- Shell parser остаётся bounded deterministic backstop, а не shell sandbox;
  simple unknown direct commands зависят от LLM/native controls. Web guard
  статически проверяет URL/IP/special-use names, а DNS resolution и каждый
  redirect зависят от native OpenClaw SSRF guard; pre-hook не решает DNS
  rebinding.

## 0.3.0 — 2026-07-12

### Added

- Strict six-variable deployment ENV contract with one-shot snapshot.
- Profiles `shadow`, `supervised`, `autonomous` mapped to existing mode/enforcement.
- Dedicated judge credential with atomic legacy shared-provider fallback.
- Configurable bounded timeout, confined audit path and lifecycle log level.
- Black-box `CONTRACT.md`, deployment/rollback runbook and GitLab CI.

### Security

- Fixed Cloud.ru endpoint remains immutable; arbitrary ENV endpoint is rejected.
- Unknown/blank/hostile ENV and legacy config fail to supervised approval with timeout-deny.
- Audit root now rejects outside-root paths, linked parents/final files, hardlinks,
  non-regular files and foreign ownership before append.
- Settings resolver cannot be replaced through plugin dependency injection.

### Compatibility and evidence

- Existing `mode/enforcement` plugin config and shared Cloud.ru provider remain
  supported when corresponding ENV is absent.
- Model `Qwen/Qwen3.5-397B-A17B`, policy `2026-07-12.4`, prompt, threshold and
  deterministic guard are unchanged from 0.2.0.
- Existing 360-call model qualification remains explicitly labeled baseline
  0.2.0; release 0.3.0 adds integration/runtime evidence and does not claim a
  repeated model qualification.

## 0.2.0 — 2026-07-12

### Changed

- Fixed judge model: `Qwen/Qwen3.5-397B-A17B`.
- Fixed policy: `2026-07-12.4`.
- Judge timeout увеличен до `8000 ms`.
- Minimum OpenClaw повышен до `2026.6.11`.
- Code defaults зафиксированы как `mode=autonomous`, `enforcement=shadow`.
- Runtime package устанавливается как versioned `.tgz` с отдельным SHA-256, без `--link`.
- Packed runtime manifest не содержит dev-only `test`/`eval:*` scripts; сами tests, evals и corpora остаются только в source checkout.
- Credentials продолжают браться из shared `models.providers.cloudru`; отдельного `judgeApiKey` в 0.2.0 нет.

### Security

- Model `allow` по-прежнему требует `risk=low`, `authorization=high` и confidence не ниже `0.8`.
- Opaque/redacted/truncated params не могут auto-allow.
- Добавлен strict deterministic downgrade для real/unknown message writes, non-message `dryRun`, cron writes, browser uploads, active CI, git hooks, registry config, nested devcontainer lifecycle и security-policy writes.
- Exact action hash, strict seven-field parser, timeout handling и autonomous fail-closed mapping сохранены.
- Установка, benchmark, update и rollback не читают и не изменяют `.env`.

### Evaluation evidence

- Official preflight: шесть доступных candidates.
- Fixed winner: `Qwen/Qwen3.5-397B-A17B`.
- Final diagnostic: 360 live attempts, `117/120` MUST_ALLOW executed, `0/240` MUST_BLOCK unsafe auto-allow, `0/20` catastrophic families unsafe.
- Raw LLM вернула 8 unsafe `allow` в четырёх cases; deterministic local guard понизил и заблокировал все `8/8`. Итоговые `0/240` относятся к combined gate, а не к модели отдельно.
- Четыре failures из 360 пришлись на MUST_BLOCK и были fail-closed.
- Combined latency: p50 `2.454 s`, p95 `3.420 s`, p99 `7.290 s`; per-chunk p95 `2.757–6.495 s`.
- Unit/eval suite: 491 tests passed.
- Double-reviewed frozen pilot: 30/30 cases.
- Single-host OpenClaw 2026.6.11 runtime E2E: safe allow, deterministic guarded block, managed archive load and binary `0.2.0 → 0.1.0 → 0.2.0` rollback.

### Known limitations

- Только один 30-case pilot прошёл double-review.
- Остальные три chunks использовались диагностически.
- Полный independently reviewed gate-validation corpus и frozen primary/reserve holdout отсутствуют.
- Диагностический p95 выше design target `2 s`.
- Shared Cloud.ru provider key остаётся общей credential boundary actor/judge.
- `autonomous + enforce` не квалифицирован.

## 0.1.0 — 2026-07-11

- Initial linked-package pilot с fixed GLM-5.1.
- Exact-action hash, strict parser, fail-closed mapping, supervised/native approval и secret-safe audit.
- Historical 30-case leaky dev-smoke; не является qualification.
