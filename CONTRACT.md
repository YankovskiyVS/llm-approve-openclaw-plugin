# Integration contract

Этот документ — black-box контракт `openclaw-llm-action-judge` 0.4.0 для
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
| `OPENCLAW_JUDGE_TIMEOUT_MS` | нет | `8000` | Canonical integer `1000..30000`. |
| `OPENCLAW_JUDGE_AUDIT_PATH` | нет | OpenClaw logs path | Absolute `.jsonl` внутри OpenClaw logs root. |
| `OPENCLAW_JUDGE_LOG_LEVEL` | нет | `info` | `error`, `warn`, `info`, `silent`. |

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

Judge получает:

- raw trusted user request текущего run;
- tool name;
- redacted/minimized params;
- fixed policy version и SHA-256 exact-action hash.

Judge не получает assistant prose, transcript, tool results, raw correlation
IDs или hidden reasoning.

## Immutable internals

Deployment не может менять:

- model: `Qwen/Qwen3.5-397B-A17B`;
- policy: `2026-07-14.3`;
- minimum confidence: `0.8`;
- system prompt и strict seven-field response schema;
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

## Выход hook

| Outcome | Shadow | Supervised | Autonomous |
|---|---|---|---|
| validated allow | `undefined` | `{ params }` | `{ params }` |
| review | `undefined` | `{ params, requireApproval }` | `{ block: true }` |
| deny | `undefined` | `{ block: true }` | `{ block: true }` |
| setup/transport/schema/hash failure | `undefined` только у валидного shadow | `requireApproval` | `{ block: true }` |

Invalid startup configuration всегда переводит plugin в permanent
`supervised + enforce` с failing client: каждое действие требует native approval,
а timeout означает deny. Hooks при этом всё равно регистрируются, чтобы runtime
inspect показывал диагностируемое состояние.

## Audit output

Append-only JSONL содержит только:

- timestamp, fixed model/policy;
- tool name и exact action hash;
- хешированные agent/session/run/tool-call IDs;
- decision, risk, authorization, confidence, outcome и latency;
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
