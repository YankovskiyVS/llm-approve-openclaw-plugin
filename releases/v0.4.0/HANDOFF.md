# OpenClaw LLM Action Judge 0.4.0 — handoff

Готовый комплект для platform-команды:

- `openclaw-llm-action-judge-0.4.0.tgz` — устанавливаемый plugin;
- `openclaw-llm-action-judge-0.4.0-evidence.tar.gz` — qualification и
  санитизированные integration proofs; этот архив не устанавливается;
- `.sha256` рядом с каждым архивом — отдельная проверка artifact;
- `SHA256SUMS` — общая проверка всех handoff-файлов.

Runtime source commit:
`1d921d8b639f8eb67b7d728b451c22a241497084`.
Release tag: `v0.4.0`.

Runtime SHA-256:
`7e2533b8d90431fbfb57e4a72812c5fb067882f161bf89d13342024ea75f9633`.

Evidence SHA-256:
`b3fc12b33ebfa18181616d0aa2c5de8e004c87737db40c3138076748713cd94b`.

## Входной deployment contract

Для black-box deployment передайте managed gateway:

```text
OPENCLAW_JUDGE_API_KEY=<platform-secret>
OPENCLAW_JUDGE_PROFILE=shadow
```

Опциональные ENV: `OPENCLAW_JUDGE_BASE_URL`,
`OPENCLAW_JUDGE_TIMEOUT_MS`, `OPENCLAW_JUDGE_AUDIT_PATH`,
`OPENCLAW_JUDGE_LOG_LEVEL`. Допустимые значения находятся в packed
`CONTRACT.md` и `DEPLOYMENT.md`. Plugin не загружает `.env` самостоятельно.

Model `Qwen/Qwen3.5-397B-A17B`, policy `2026-07-14.6`, endpoint, prompt,
Structured Output schema, threshold и deterministic guard фиксированы внутри
plugin и не переопределяются через ENV.

## Проверка и установка

Сначала запишите ENV в durable service/container environment. Затем:

```bash
shasum -a 256 -c SHA256SUMS
openclaw plugins install ./openclaw-llm-action-judge-0.4.0.tgz
openclaw config set plugins.allow '["llm-action-judge"]' --strict-json
openclaw config set plugins.entries.llm-action-judge.hooks.allowConversationAccess true --strict-json
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
openclaw plugins doctor
```

Команда `plugins.allow` выше предназначена для новой выделенной node. Если
allowlist уже существует, добавьте `llm-action-judge`, сохранив trusted ids
других plugins; не заменяйте рабочий список.

Начальный profile — `shadow`. На `supervised` переходите после проверки native
approval route. `autonomous` включайте только после shadow/canary qualification
на реальном traffic команды.

## Проверенное состояние

- source tests: 581/581;
- exact runtime archive установлен в изолированный OpenClaw 2026.6.11;
- plugin status `loaded`, diagnostics пусты;
- зарегистрированы `before_model_resolve` и `before_tool_call`, priority -1000;
- gateway health: `ok=true`, plugin errors пусты, event loop не degraded;
- clean install: Ajv 8.20.0, вложенный OpenClaw не установлен;
- package smoke: safe allow, deterministic block, fail-closed approval,
  schema-invalid и invalid-ENV fail-closed, audit mode 0600 без секретов;
- qualification: 108/120 safe auto-allows, 0/240 unsafe auto-allows,
  0/80 unsafe families, 0/11 catastrophic unsafe, failures 0/360;
- raw judge ошибочно разрешил 18 unsafe attempts; normalization/local guard
  заблокировали все 18/18;
- provider usage отсутствовал во всех ответах, поэтому стоимость этого run по
  artifact не наблюдаема;
- corpus tuned/reviewed; unseen holdout не проводился;
- реальный `.env` не читался и не менялся.

`junit.xml` внутри evidence содержит шесть MUST_ALLOW family failures: это
overblocking безопасных действий, а не пропущенные опасные действия. Полные
границы утверждений, история пяти заблокированных policy-кандидатов и rollback
описаны в evidence и packed `DEPLOYMENT.md`.
