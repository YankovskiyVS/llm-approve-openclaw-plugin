# OpenClaw LLM Action Judge 0.5.0 — handoff

Готовый black-box комплект для platform-команды:

- `openclaw-llm-action-judge-0.5.0.tgz` — устанавливаемый plugin;
- `openclaw-llm-action-judge-0.5.0-evidence.tar.gz` — санитизированные test и
  stock-runtime proofs; этот архив не устанавливается;
- `.sha256` рядом с каждым архивом и общий `SHA256SUMS`.

Package build source commit:
`c5ced12b020f814042539eb54984bc87881b6d67`.
Release tag: `v0.5.0`.

Runtime SHA-256:
`6d35740ac596b456b4063c5d69cbd68f1a02f31935867b59c3b508ffd5d9581d`.

Evidence SHA-256:
`99524091c0cf0aef9e235cf22a0eb50d7264f14d18da36ddb68a2ca18824c3fe`.

## Что внутри

Плагин сам регистрирует `before_model_resolve` и `before_tool_call` с priority
`-1000`; внешние hook-файлы не нужны. Fixed Qwen проверяет proposed action,
strict `json_schema` и локальный Ajv валидируют ответ, deterministic guard может
только ужесточить allow.

v0.5 добавляет:

- фиксированный безопасный `blockReason` для worker;
- circuit breaker после 3 последовательных deny или 10 deny среди последних 50;
- узкий hard boundary до LLM для exact self-modification, доказанной credential
  exfiltration и отключения judge;
- audit `decision_source` и metrics-only safe-path disagreement.

Safe path не является auto-approve веткой: действие всё равно проходит Qwen и
все локальные проверки.

## Вход deployment

Минимально передайте процессу OpenClaw:

```text
OPENCLAW_JUDGE_API_KEY=<platform-secret>
OPENCLAW_JUDGE_PROFILE=shadow
```

Допустимые optional ENV и точные значения описаны в packed `README.md`,
`CONTRACT.md` и `DEPLOYMENT.md`. Плагин не читает `.env`. Model
`Qwen/Qwen3.5-397B-A17B`, policy `2026-07-16.1`, prompt, schema, threshold и
routing через ENV не меняются.

## Установка

```bash
shasum -a 256 -c SHA256SUMS
openclaw plugins install ./openclaw-llm-action-judge-0.5.0.tgz
openclaw config set plugins.entries.llm-action-judge.hooks.allowConversationAccess true --strict-json
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
```

Добавьте `llm-action-judge` в существующий `plugins.allow`, не удаляя trusted
IDs других plugins. Начните с `shadow`, затем `supervised`; `autonomous`
включайте canary после проверки real traffic и native sandbox.

## Проверено

- source suite 906/906 и package suite 12/12;
- independent review: SPEC PASS, QUALITY PASS;
- exact archive установлен в isolated stock OpenClaw 2026.6.11;
- version 0.5.0, status loaded, imported true, diagnostics `[]`;
- два typed hook с priority -1000;
- isolated gateway health `ok=true`, plugin errors `[]`;
- installed-tarball smoke проверил allow/block/approval/fail-closed и audit 0600;
- immutable historical corpora/releases не изменены;
- реальный `.env` не читался и не менялся.

Новый unseen model holdout и новый live Cloud.ru probe в этом release cycle не
выполнялись. Исторические model-selection/holdout результаты не являются
qualification v0.5.0. Rollback target — package 0.4.1 в соседнем каталоге.
