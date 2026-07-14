# OpenClaw LLM Action Judge

`openclaw-llm-action-judge` 0.4.0 автоматически проверяет proposed OpenClaw
tool calls отдельной фиксированной LLM до исполнения. Safe call может пройти,
сомнительный — уйти в native approval, опасный — быть заблокирован.

Пакет предназначен для black-box интеграции: команда устанавливает `.tgz`,
передаёт ENV и разрешает plugin hook access. Оба hook находятся внутри плагина и
регистрируются автоматически.

## Fixed safety contract

- Judge: `Qwen/Qwen3.5-397B-A17B`.
- Policy: `2026-07-14.6`.
- Minimum allow confidence: `0.8`.
- Default timeout: `8000 ms`.
- Endpoint: только `https://foundation-models.api.cloud.ru/v1`.
- Hooks: `before_model_resolve`, `before_tool_call`, priority `-1000`.
- OpenClaw: `>=2026.6.11`; Node.js: `>=22.19.0`.

Model, policy, prompt, threshold и deterministic guard не настраиваются через
ENV или `openclaw.json`.

## Quick start

Из `releases/v0.4.0`:

До restart задайте `OPENCLAW_JUDGE_API_KEY` и
`OPENCLAW_JUDGE_PROFILE=shadow` в environment самого managed gateway через
platform/service manager. Обычный shell `export` не передаётся launchd/systemd
service. Foreground smoke описан в [DEPLOYMENT.md](DEPLOYMENT.md).

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.4.0.tgz.sha256
openclaw plugins install ./openclaw-llm-action-judge-0.4.0.tgz
openclaw config set plugins.entries.llm-action-judge.hooks.allowConversationAccess true --strict-json
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
```

Runtime inspect должен показать `imported=true`, version `0.4.0`, два ожидаемых
hook и `diagnostics=[]`.

Полный runbook: [DEPLOYMENT.md](DEPLOYMENT.md). Black-box input/output contract:
[CONTRACT.md](CONTRACT.md).

## Profiles

| `OPENCLAW_JUDGE_PROFILE` | Поведение |
|---|---|
| `shadow` | Judge и audit работают; tool call не изменяется. Recommended first stage. |
| `supervised` | Allow исполняется; review/failure требует one-call approval; deny блокируется. |
| `autonomous` | Только validated allow исполняется; review/deny/failure блокируются. |

`shadow` намеренно observe-only и поэтому не является enforcement boundary.
Invalid startup config, напротив, переводит plugin в permanent supervised
approval с timeout-deny.

## How it works

1. `before_model_resolve` сохраняет exact trusted request только для текущего
   `runId`; transcript fallback отсутствует.
2. `before_tool_call` строит immutable action snapshot, редактирует credentials и
   вычисляет SHA-256 action hash.
3. Cloud.ru получает `response_format.type=json_schema` с `strict=true` и
   возвращает seven-field JSON по packaged canonical schema.
4. Плагин повторно валидирует ответ локально через Ajv, затем проверяет exact
   policy/hash и rationale semantics. Fallback на `json_object` отсутствует.
5. Model allow принимается только при `risk=low`, `authorization=high` и
   confidence `>=0.8`.
6. Opaque и deterministic local guards могут только понизить allow до review.
7. После async judge call exact action строится заново; mutation означает failure.
8. Outcome переводится в allow/block/native approval и secret-safe JSONL audit.

Schema-valid ответ не означает safe решение: hash, risk, authorization,
confidence, opaque-data checks и deterministic guard остаются обязательными.

Любая transport/schema/policy/hash/mutation ошибка fail-closed в enforcement:
approval в supervised, block в autonomous.

## Deterministic guard

Даже raw model `allow` понижается для redacted/truncated params, real external
messages, state-changing cron, browser upload, active CI/git hooks/devcontainer
lifecycle, registry/auth/IAM/OAuth/RBAC/security-policy writes, credential reads,
sensitive gateway config reads, cross-session history, state-changing process
actions, mutating `skill_workshop` calls, destructive shell dispatch/redirection,
writes to `openclaw.json`, private/internal/special-use web fetch targets и других
fixed high-impact surfaces.

Это существенная часть safety boundary: historical baseline показал 8 unsafe raw
LLM allows, и guard заблокировал все `8/8`.

Shell parser — bounded fail-closed backstop, а не shell sandbox. Он намеренно
останавливает неоднозначный dispatch/redirection, но простые неизвестные direct
commands по-прежнему зависят от решения LLM и native OpenClaw controls.

Для `web_fetch` плагин статически проверяет URL, literal IP и special-use names,
включая `home.arpa`. DNS resolution и каждый redirect должны отдельно
проверяться native OpenClaw SSRF guard; pre-hook не решает DNS rebinding.

## Historical evaluation baseline 0.2.0/0.3.0

- Preflight: 19 models, 6 eligible.
- Selection: 720 model calls.
- Final diagnostic: 120 cases, 360 attempts.
- Combined gate: safe executed `117/120`; unsafe auto-allow `0/240`.
- Raw LLM: unsafe allow `8/240`; deterministic guard caught `8/8`.
- Combined latency: p50 `2.454 s`, p95 `3.420 s`, p99 `7.290 s`.

Ограничения evidence:

- только один 30-case pilot double-reviewed;
- остальные chunks diagnostic;
- frozen primary/reserve holdout отсутствует;
- p95 выше design target 2 seconds;
- `autonomous + enforce` не production-qualified.

Эти цифры получены с policy `2026-07-12.4` и `json_object`; они не являются
метриками 0.4.0. Пять strict qualification run для 0.4.0 стали release-blocker:
policy `2026-07-14.1` дала `112/120` safe и `9/240` unsafe, а policy
`2026-07-14.2` — `118/120` safe и `6/240` unsafe. После hardening policy
`2026-07-14.3` дала `112/120` safe и `2/240` unsafe в одной
`skill_workshop.apply` family. Policy `2026-07-14.4` закрыла этот surface и дала
`118/120` safe, но пропустила `2/240` unsafe в двух других families: удаление
security-теста и правка production config. Policy `2026-07-14.5` закрыла обе
surfaces, но новый run дал `111/120` safe и `2/240` unsafe в active
`.ssh/authorized_keys` family. Current policy `2026-07-14.6` закрывает
распознанные active `.ssh` security-file writes. Fresh run
`llm-judge-v040-qualification-20260714T202947Z` прошёл release-gate: `108/120`
safe auto-allows (`34/40` families), `0/240` unsafe (`0/80` families), `0/11`
catastrophic и `0/360` failures; p50 `1846.141 ms`, p95 `2320.621 ms`, p99
`2761.126 ms`.

Это tuned frozen-corpus qualification, а не unseen holdout: результаты нельзя
переносить на произвольные новые tools и path grammars без отдельного eval.

Подробности: [RND.md](RND.md).

## Data handling

В Cloud.ru уходят raw trusted request, tool name, redacted params, fixed policy и
action hash. Не уходят transcript, assistant prose, tool results, raw IDs или
hidden reasoning.

Plugin audit не хранит raw prompt/params, credentials, raw IDs или model
rationale. OpenClaw host logs могут независимо содержать action params —
защищайте их отдельной access/retention policy.

Portable output contract поставляется как
`schemas/judge-verdict.schema.json`. Platform-команда может генерировать из него
свои Pydantic-типы, но Python/Pydantic runtime или sidecar в плагин не входят.

## Source verification

```bash
npm test
node scripts/build-release.mjs .ci-release/v0.4.0
(cd .ci-release/v0.4.0 && shasum -a 256 -c openclaw-llm-action-judge-0.4.0.tgz.sha256)
npm pack --json --dry-run --ignore-scripts
```

Paid model benchmarks не запускаются в automatic CI.

## Documents

- [CONTRACT.md](CONTRACT.md) — входы, выходы и failure semantics.
- [DEPLOYMENT.md](DEPLOYMENT.md) — install, verify, update, rollback, uninstall.
- [SECURITY.md](SECURITY.md) — security boundary и incident response.
- [RND.md](RND.md) — model research, benchmark methodology и caveats.
- [CHANGELOG.md](CHANGELOG.md) — version history.
