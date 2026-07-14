# Changelog

Все заметные изменения `openclaw-llm-action-judge` фиксируются в этом файле.

## 0.4.0 — 2026-07-14

### Added

- Canonical portable `schemas/judge-verdict.schema.json` с policy
  `2026-07-14.1` поставляется внутри runtime `.tgz`.
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
- Public ENV contract, два hook, fixed model, thresholds и deterministic guard не
  изменились.

### Security and evidence

- Schema-valid response не считается safe сам по себе: exact hash, rationale,
  risk, authorization, confidence, opaque-data и deterministic guards остаются
  обязательными и fail-closed.
- Результаты `117/120` safe и `0/240` unsafe относятся только к historical
  baseline 0.2.0/0.3.0 (`2026-07-12.4`, `json_object`). Метрики 0.4.0 имеют
  статус pending fresh qualification до нового frozen-corpus run.

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
