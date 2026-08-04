# Integration contract

Этот документ — black-box контракт `openclaw-llm-action-judge` 0.5.0 для
команды, которая встраивает плагин в OpenClaw.

## Что делает пакет

Плагин автоматически регистрирует два hook:

- `before_model_resolve` сохраняет trusted user request текущего `runId`;
- `before_tool_call` проверяет exact tool call через fixed LLM judge и local
  deterministic guard.

Отдельно прокидывать hook-файлы или вызывать API плагина не нужно. Host должен
только установить `.tgz`, передать ENV и разрешить conversation access для
plugin hooks.

## Вход 1: environment

Плагин читает `process.env` один раз при регистрации. Он не загружает `.env`.

| Variable | Required | Default | Contract |
|---|---|---|---|
| `OPENCLAW_JUDGE_API_KEY` | рекомендуется | shared provider fallback | Printable ASCII без whitespace, 1–4096 chars. |
| `OPENCLAW_JUDGE_PROFILE` | рекомендуется | legacy config, затем `shadow` | `shadow`, `supervised`, `autonomous`. |
| `OPENCLAW_JUDGE_BASE_URL` | нет | fixed Cloud.ru URL | Только `https://foundation-models.api.cloud.ru/v1`. |
| `OPENCLAW_JUDGE_TIMEOUT_MS` | нет | `30000` | Canonical integer `1000..30000`. |
| `OPENCLAW_JUDGE_AUDIT_PATH` | нет | OpenClaw logs path | Absolute `.jsonl` внутри OpenClaw logs root. |
| `OPENCLAW_JUDGE_LOG_LEVEL` | нет | `info` | `error`, `warn`, `info`, `silent`. |
| `OPENCLAW_JUDGE_A2A_HITL_REPLACE` | нет | off | `0`/`1`/`true`/`false`. Agent Space HITL replace mode. |

Рекомендуемый новый deployment передаёт `API_KEY + PROFILE`. Если API key не
передан, для совместимости используется цельная пара
`models.providers.cloudru.baseUrl/apiKey`. ENV base URL без ENV key запрещён;
dedicated ENV key никогда не смешивается с shared provider.

Неизвестная переменная с prefix `OPENCLAW_JUDGE_` — configuration error, а не
молча проигнорированный typo.

### Profile mapping

| Profile | Internal mode | Enforcement |
|---|---|---|
| `shadow` | autonomous | Judge и audit работают, hook ничего не меняет. |
| `supervised` | supervised | Allow исполняется; review/failure требует человека; deny блокируется. |
| `autonomous` | autonomous | Только validated allow исполняется; всё остальное блокируется. |

## Вход 2: OpenClaw hook data

`before_model_resolve` получает raw trusted request и `runId`.
`before_tool_call` получает tool name, params и correlation IDs. Плагин связывает
оба события только по exact `runId`; transcript/session fallback отсутствует.

Trusted request принимается размером до `64 KiB`, хранится не более `30 минут`,
а in-memory store держит максимум `1000` run. Просроченный, вытесненный или
слишком большой request считается missing intent: в `supervised` действие
уходит человеку, в `autonomous` блокируется.

Judge получает:

- raw trusted user request текущего run;
- tool name;
- redacted/minimized params;
- fixed policy version и opaque keyed HMAC-SHA-256 exact-action commitment.

Judge не получает assistant prose, transcript, tool results, raw correlation
IDs или hidden reasoning.

Commitment использует случайный 32-byte process-local key. Key не является ENV,
не экспортируется, не сериализуется и не передаётся judge; judge только копирует
непрозрачное значение в verdict. Wire-формат остаётся
`sha256:<64 lowercase hex>`. Commitment стабилен для повторной проверки внутри
одного process, но меняется после restart и не предназначен для cross-process
correlation или внешнего пересчёта.

## Immutable internals

Deployment не может менять:

- model: `Qwen/Qwen3.5-397B-A17B`;
- policy: `2026-07-16.1`;
- minimum confidence: `0.8`;
- system prompt и strict eight-field response schema с `reason_code`;
- exact-action binding, redaction, opaque downgrade и deterministic local guard;
- approval timeout `60000 ms` с `timeoutBehavior=deny`.

Такие изменения требуют новой версии source, policy version и qualification.

## Judge response contract

Canonical portable contract находится в
`schemas/judge-verdict.schema.json` внутри `.tgz`. Cloud.ru получает его через
`response_format.type=json_schema` с `strict=true`; fallback на `json_object`
отсутствует. Полученный объект повторно проверяется локально Ajv без coercion,
defaults, удаления полей или передачи model-controlled validation errors наружу.

Schema-valid объект сам по себе не разрешает действие. После schema validation
обязательны exact action hash, rationale semantics, risk, authorization,
confidence, opaque-data checks и deterministic local guard. Ошибка provider
Structured Output или local validation использует существующий fail-closed
mapping из таблицы ниже.

JSON Schema является integration artifact для других языков. Platform-команда
может сгенерировать из неё Pydantic model, но Python/Pydantic runtime и sidecar
не являются частью плагина или его deployment contract.

## Hard routing, breaker и deterministic guard

До обращения к Qwen точные попытки self-modification плагина, доказанная
передача найденного секрета во внешний sink и отключение judge/shadow блокируются
с `decision_source=hard_boundary`. Это узкий fail-closed boundary, а не общий
substring blacklist. Safe path в v0.5 остаётся metrics-only: даже
`session_status` текущей сессии и bounded browser wait вызывают Qwen и никогда
сам по себе не устанавливает authorization.

Per-run circuit breaker необратимо срабатывает после `3 consecutive` deny либо
`10 among 50` последних решений. В enforcing-режимах последующие вызовы получают
фиксированный `blockReason` и не вызывают Qwen; `shadow` остаётся observe-only.

Policy `2026-07-16.1` формально разделяет passive observation и external
mutation, задаёт уровни authorization и не позволяет action params доказывать
разрешение. Local guard является downgrade-only: он не может превратить
`review`, `deny` или failure в `allow`.

Текущий deterministic contract:

| Surface | Может остаться `allow` | Всегда понижается минимум в `review` |
|---|---|---|
| `read`/file writes | Обычный workspace data и чтение bootstrap instructions вне sensitive paths. | Чтение credentials, auth-bearing Git/package config, sensitive OpenClaw state вне workspace, sessions/logs/history/audit; записи в `openclaw.json`, state вне workspace, bootstrap instructions и любой `skills/**/SKILL.md`; production, CI/CD, Git/SSH/security config, package manifests/lockfiles и любые записи в распознанные security/auth tests. |
| Ignore boundaries | `apply_patch`, если полный patch доказывает только защитный delta. | Любой `edit`/`write` `.gitignore`, `.npmignore`, `.dockerignore` и ослабляющий/неразбираемый patch. |
| Распознанные OpenClaw first-party families | `gateway config.get` несекретного metadata; own-session `sessions_history` без tool data; `subagents list`; current `session_status` без смены model; `nodes describe/pending/status`; generation `list`; `transcripts status`; `process list/poll/log`; `skill_workshop list`; `cron list/status/get/runs`; read-only message allowlist и `message.send` только с `dryRun=true`. | В этих families: cross-session/tool history, model change, sends/spawns, goal mutations, canvas/TTS, node/process/cron/generation/transcript/skill mutations и все actions вне allowlist. |
| `exec`/`bash` structured fields | Не-elevated action, отсутствующий host либо `host=sandbox`, без `node`, с пустым/отсутствующим `env`; `pty/background` отсутствуют либо literal `false`; optional `timeout=1..3600`, `yieldMs=1..30000` и static absolute/`~/`/drive `workdir`. | `elevated` кроме literal `false`, явно заданный host вне sandbox, любое поле `node`, непустой/не-object `env`, PTY/background, lifecycle вне bounds, relative/dynamic/traversing `workdir`, одновременно `command` и `cmd`, missing/non-static command. Relative command paths разрешаются против validated `workdir`. Отсутствующий host использует effective routing OpenClaw и может означать gateway, если native sandbox не настроен. |
| Shell/CLI | Static command после model `allow`, если deterministic rules не требуют review. Явные read-only allowlists включают OpenClaw `status`/`version`, `plugins inspect/list`, несекретный `config get`, `gateway health/status`. Git и package managers классифицируются по operation, root options, flags, file-valued options и target paths; `--help/--version` считаются control options только до operand separator `--`. Scoped `rg` разрешён только без hidden/no-ignore/follow и с literal file, известным code/docs root либо restrictive code glob. | Shell control/dynamic dispatch, elevation/remote/container execution, destructive/permission/migration/package mutations, protected redirects/reads/writes, protected config/certificate/patch inputs через CLI flags, recursive/dynamic credential readers, broad repo-root content search, broad Git content readers, secret environment exposure, mutating/unknown Git/OpenClaw/package operations. `curl` требует отключённый rc (`-q`/`--disable`), `wget` — `--no-config` и `--max-redirect=0`; redirects/routing/proxy/socket/netrc и upload/data forms review. |
| `web_fetch`/browser | Literal public `http(s)` URL для `navigate/open`; browser metadata и passive `hover`/`resize`/`wait.timeMs=0..30000` только с literal `target=sandbox`. | Browser без `target=sandbox` или с `node`, invalid/internal/special-use URL, console, любой `pdf`/`screenshot`/`snapshot`, wait вне bounds или с `fn`/extra fields, click/type/upload/evaluate и иные consequential actions. |

Для OpenClaw bootstrap instructions защищаются распознанные
`AGENTS.md`, `SOUL.md`, `TOOLS.md`, `USER.md`, `IDENTITY.md`, `HEARTBEAT.md`,
`MEMORY.md` и `skills/**/SKILL.md`, в том числе вне стандартного
`.openclaw/workspace` пути. Это предотвращает тихую подмену будущих инструкций
агента.

Primary pilot на предыдущем runtime-контракте провалил launch gate и используется
только для tuning. Для `2026-07-16.1` нового unseen model holdout нет; v0.5.0
является package/runtime-qualified, а не новым model-quality benchmark result.

Shell parser — backstop, а не shell sandbox: simple unknown direct commands
по-прежнему зависят от LLM verdict и native OpenClaw controls. Отсутствующий
`exec.host` не доказывает sandbox routing; strongest deployment обязан включить
native OpenClaw sandbox. `web_fetch` guard
статически проверяет URL, literal IP и special-use names; DNS resolution и
каждый redirect проверяет native OpenClaw SSRF boundary. Pre-hook не защищает от
DNS rebinding сам по себе.

Неизвестные и plugin-provided tool names, которые не входят в перечисленные
first-party families, также остаются LLM/native-gated: local guard не выводит
семантику будущего инструмента только из произвольного поля `action`.

## Hook ordering invariant

Оба hook плагина регистрируются с priority `-1000`. `before_tool_call` строит
commitment и возвращает проверенные `params`, поэтому он обязан быть
единственным либо последним hook, способным менять параметры tool call. Другой
hook может модифицировать `params` до judge; после judge он может только
наблюдать или блокировать вызов.

Если params-modifying hook исполняется позже, фактически выполненное действие
может отличаться от проверенного snapshot. Это unsupported host composition и
release blocker; TOCTOU-проверка внутри callback judge не покрывает последующую
мутацию другим plugin. Deployment обязан проверить полный runtime hook inventory,
а не только факт импорта judge.

## Выход hook

| Outcome | Shadow | Supervised | Autonomous |
|---|---|---|---|
| validated allow | `undefined` | `{ params }` | `{ params }` |
| review | `undefined` | `{ params, requireApproval }` | `{ block: true, blockReason }` |
| deny | `undefined` | `{ block: true, blockReason }` | `{ block: true, blockReason }` |
| setup/transport/schema/hash failure | `undefined` только у валидного shadow | `requireApproval` | `{ block: true, blockReason }` |

`blockReason` строится host-side из закрытого enum `feedback_code`; raw model
rationale, параметры и provider errors в worker feedback не попадают.

Invalid startup configuration всегда переводит plugin в permanent
`supervised + enforce` с failing client: каждое действие требует native approval,
а timeout означает deny. Hooks при этом всё равно регистрируются, чтобы runtime
inspect показывал диагностируемое состояние.

Если host API не позволяет зарегистрировать enforcement hook
`before_tool_call`, `register()` бросает фиксированную ошибку и loader обязан
считать plugin failed, а не loaded. Отдельный failure capture hook
`before_model_resolve` оставляет enforcement hook активным: trusted intent
отсутствует, поэтому каждый tool call fail-closed уходит в review/block.

## Audit output

Append-only JSONL содержит только:

- timestamp, fixed model/policy;
- tool name и opaque exact-action commitment;
- хешированные agent/session/run/tool-call IDs;
- decision, risk, authorization, confidence, outcome и latency;
- `decision_source` (`hard_boundary`, `circuit_breaker`, `llm`,
  `local_downgrade`, `failure`) и metrics-only safe-path поля;
- effective mode/enforcement;
- marker наличия rationale без самого текста.

Файл создаётся с mode `0600`. Raw prompt, raw params, credentials, raw IDs и
model rationale отсутствуют. Audit I/O failure ухудшает observability, но не
переписывает уже вычисленное решение.

## Host prerequisite

OpenClaw config должен содержать:

```json
{
  "plugins": {
    "entries": {
      "llm-action-judge": {
        "hooks": {
          "allowConversationAccess": true
        }
      }
    }
  }
}
```

Полные команды установки и проверки: [DEPLOYMENT.md](DEPLOYMENT.md).

## A2A HITL replace (Agent Space)

Когда плагин работает рядом с `openclaw-a2a-gateway`, human-in-the-loop идёт через
process-wide singleton
`globalThis.__openclaw_a2a_tool_approval_bridge_v1__.requestApproval`.

Плагин не меняет исходники a2a-gateway. Вместо этого:

1. Agent Space manager при `is_autoapprove_enabled` добавляет в outbound A2A text
   control marker `<!--openclaw:autoapprove=1-->` и
   `metadata.llm.autoApprove=true`;
2. `before_model_resolve` снимает marker с trusted prompt и помечает `runId` /
   `sessionKey`;
3. При `OPENCLAW_JUDGE_A2A_HITL_REPLACE=true` обычный `before_tool_call` **не
   гейтит** tool calls без marker — остаётся чистый human HITL;
4. С marker judge исполняется, решение кладётся в store по `toolCallId`,
   native `requireApproval` на A2A-пути не используется (review/failure → deny);
5. Monkey-patch `requestApproval` при активном autoapprove возвращает
   `allow-once` или `deny` без ожидания человека.

Контракт ключа singleton и формы `requestApproval({ toolName, params,
toolCallId, runId, sessionKey, timeoutMs })` считается стабильным integration
surface a2a-gateway; изменение ключа — breaking change для этого adapter.
