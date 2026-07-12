# OpenClaw LLM Action Judge 0.3.0 handoff

Готовый пакет для platform-команды:

- `openclaw-llm-action-judge-0.3.0.tgz` — устанавливаемый plugin;
- `openclaw-llm-action-judge-0.3.0-evidence.tar.gz` — baseline R&D и
  санитизированные integration checks; этот архив не устанавливается;
- `.sha256` рядом с каждым архивом — отдельная проверка artifact;
- `SHA256SUMS` — общая проверка handoff-файлов.

Source commit: `a507816f3f06a54126e8c7d8e4594174f7c01052`.
Release tag: `v0.3.0`.

Runtime SHA-256:
`ce3e04e98fc8f5fc4868d291ceb73b49fa5ff07c40e6c5fd0e42cddf4c494d1a`.

Evidence SHA-256:
`a5aa1393a9a1d55c622029fb7a100f7aab4398f21f7184fb4c10c6e67355e57e`.

## Что нужно передать процессу

Обязательные ENV:

```text
OPENCLAW_JUDGE_API_KEY=<platform-secret>
OPENCLAW_JUDGE_PROFILE=shadow
```

Необязательные ENV: `OPENCLAW_JUDGE_BASE_URL`,
`OPENCLAW_JUDGE_TIMEOUT_MS`, `OPENCLAW_JUDGE_AUDIT_PATH`,
`OPENCLAW_JUDGE_LOG_LEVEL`. Полный контракт и допустимые значения находятся в
packed `README.md`, `CONTRACT.md` и `DEPLOYMENT.md`.

Model `Qwen/Qwen3.5-397B-A17B`, policy `2026-07-12.4`, prompt, threshold и
deterministic guard фиксированы внутри plugin и ENV не переопределяются.

## Проверка и установка

Сначала передайте ENV самому managed gateway через platform/service manager.
Plugin не загружает `.env` самостоятельно.

```bash
shasum -a 256 -c SHA256SUMS
openclaw plugins install ./openclaw-llm-action-judge-0.3.0.tgz
openclaw config set plugins.entries.llm-action-judge.hooks.allowConversationAccess true --strict-json
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
openclaw plugins doctor
```

Начальный profile — `shadow`. Переключение на `supervised` или `autonomous`
делается только через durable ENV managed gateway и требует restart/rollout.

## Проверенное состояние

- source tests: 520/520;
- exact runtime archive установлен в изолированный OpenClaw 2026.6.11;
- plugin импортирован, diagnostics пусты;
- зарегистрированы `before_model_resolve` и `before_tool_call`, priority -1000;
- gateway health подтвердил загруженный plugin без plugin errors;
- artifact smoke подтвердил allow, deterministic block, fail-closed approval,
  invalid-ENV fallback и audit mode 0600;
- пользовательская конфигурация OpenClaw и реальный `.env` не изменялись.

Результат 117/120 safe и 0/240 unsafe относится к qualification baseline 0.2.0.
Decision layer 0.3.0 побайтно совпадает с baseline по семи основным файлам;
для 0.3.0 отдельно проверена integration/package boundary. Autonomous profile
не заявлен как production-qualified без rollout qualification на traffic
команды.
