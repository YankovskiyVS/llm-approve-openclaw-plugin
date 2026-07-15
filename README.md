# OpenClaw LLM Action Judge

Плагин `openclaw-llm-action-judge` версии `0.4.1` проверяет каждый proposed tool
call отдельной фиксированной LLM **до исполнения**. Низкорисковое и явно
разрешённое действие может пройти автоматически, сомнительное — запросить
подтверждение, опасное — быть заблокировано.

## Суть решения

```text
Запрос пользователя
  → агент OpenClaw предлагает tool call
  → плагин перехватывает точное действие
  → Qwen оценивает риск и наличие разрешения
  → локальная схема и deterministic guard перепроверяют ответ
  → действие выполняется, отправляется на approval или блокируется
  → результат решения записывается в audit JSONL
```

Плагин не заменяет sandbox, native OpenClaw tool policy и разграничение доступа.
Это дополнительный permission layer перед исполнением инструмента.

## Из каких блоков состоит

| Блок | Что делает |
|---|---|
| **OpenClaw hooks** | `before_model_resolve` сохраняет текущий trusted user request, `before_tool_call` перехватывает proposed action. Оба hook устанавливаются самим плагином. |
| **LLM judge** | Фиксированная `Qwen/Qwen3.5-397B-A17B` независимо оценивает `decision`, `risk`, `authorization` и `confidence`. |
| **Structured Output** | Cloud.ru ограничивает ответ strict `json_schema`; тот же контракт повторно проверяется локально через Ajv. |
| **Deterministic guard** | Понижает ошибочный model `allow` для secrets, production, destructive shell, security config, external sends и других never-auto поверхностей. |
| **Mode mapper** | Преобразует итог judge в execute, native approval или block согласно `shadow`, `supervised` или `autonomous`. |
| **Audit** | Пишет решение, latency и hashes в JSONL без raw prompt, params, rationale и credentials. |

## Требования

- OpenClaw `>=2026.6.11`;
- Node.js `>=22.19.0`;
- доступ к `https://foundation-models.api.cloud.ru/v1`;
- API key с доступом к `Qwen/Qwen3.5-397B-A17B` либо уже настроенный
  `models.providers.cloudru` в OpenClaw;
- `foundation-models.api.cloud.ru` в `no_proxy`/`NO_PROXY`, если используется
  корпоративный proxy.

Плагин **не читает `.env`**. Переменные должны быть переданы процессу gateway.

## Установка

Команды выполняются из каталога `releases/v0.4.1`:

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.4.1.tgz.sha256
openclaw plugins install ./openclaw-llm-action-judge-0.4.1.tgz
```

Проверьте текущий allowlist:

```bash
openclaw config get plugins.allow --json
```

Добавьте `llm-action-judge` в существующий `plugins.allow`, сохранив остальные
trusted plugin IDs. Для новой выделенной node, где это единственный внешний
плагин, подходит команда:

```bash
openclaw config set plugins.allow '["llm-action-judge"]' --strict-json
```

Разрешите плагину получать текущий user request и обновите registry:

```bash
openclaw config set plugins.entries.llm-action-judge.hooks.allowConversationAccess true --strict-json
openclaw plugins registry --refresh
openclaw config validate
```

## Запуск в supervised

В `supervised`:

- итоговый `allow` исполняется автоматически;
- `review` и любой judge failure открывают native approval;
- `deny` блокируется;
- если пользователь не подтвердил approval за 60 секунд, действие блокируется.

Локальный foreground-запуск:

```bash
OPENCLAW_JUDGE_API_KEY='<cloudru-api-key>' \
OPENCLAW_JUDGE_PROFILE='supervised' \
openclaw gateway run
```

Процесс работает в текущем терминале и останавливается через `Ctrl+C`.

Для managed gateway задайте эти же две переменные в environment контейнера,
systemd/launchd или Kubernetes Deployment, затем выполните:

```bash
openclaw gateway restart
openclaw gateway health
```

Обычная переменная из текущего shell не попадает в уже настроенный managed
service: ENV должен находиться в его service definition/Deployment.

## Запуск в autonomous

В `autonomous`:

- автоматически исполняется только полностью validated `allow`;
- `review`, `deny`, timeout, HTTP error, invalid JSON/schema и missing intent
  блокируются без выполнения;
- ручное подтверждение не запрашивается.

Локальный foreground-запуск:

```bash
OPENCLAW_JUDGE_API_KEY='<cloudru-api-key>' \
OPENCLAW_JUDGE_PROFILE='autonomous' \
openclaw gateway run
```

Для managed gateway замените durable `OPENCLAW_JUDGE_PROFILE` на `autonomous`,
сделайте rollout/restart и повторите runtime verification. До нового независимого
holdout и shadow-проверки реального traffic используйте этот режим как canary, а
не как единственную security boundary.

## Режим shadow

`shadow` вызывает judge и пишет audit, но не влияет на исполнение tool calls. Это
рекомендуемый первый режим для новой установки:

```bash
OPENCLAW_JUDGE_API_KEY='<cloudru-api-key>' \
OPENCLAW_JUDGE_PROFILE='shadow' \
openclaw gateway run
```

| Profile | `allow` | `review`/failure | `deny` |
|---|---|---|---|
| `shadow` | Не меняет вызов | Не меняет вызов | Не меняет вызов |
| `supervised` | Выполняет | Native approval | Блокирует |
| `autonomous` | Выполняет | Блокирует | Блокирует |

## Переменные окружения

| Переменная | Обязательность и значение | За что отвечает |
|---|---|---|
| `OPENCLAW_JUDGE_API_KEY` | Рекомендуется; `1..4096` printable ASCII chars, без пробелов | Отдельный Cloud.ru API key судьи. Если переменная отсутствует, плагин использует exact `models.providers.cloudru` из OpenClaw. Пустая строка не допускается. |
| `OPENCLAW_JUDGE_PROFILE` | Рекомендуется: `shadow`, `supervised`, `autonomous` | Одновременно задаёт режим и enforcement. Имеет приоритет над валидным legacy config; malformed legacy config всё равно нужно исправить или удалить. |
| `OPENCLAW_JUDGE_BASE_URL` | Необязательно; только вместе с `OPENCLAW_JUDGE_API_KEY`; допускается только `https://foundation-models.api.cloud.ru/v1` | Фиксирует разрешённый endpoint. При fallback на shared provider переменная должна отсутствовать. Обычно её можно не задавать. |
| `OPENCLAW_JUDGE_TIMEOUT_MS` | Необязательно; canonical decimal integer `1000..30000`, default `8000` | Общий deadline одного judge call. Формы `1e3`, `01000`, `1000.0` и whitespace запрещены. Timeout в supervised ведёт в approval, в autonomous — в block. |
| `OPENCLAW_JUDGE_AUDIT_PATH` | Необязательно; absolute path внутри OpenClaw `logs/`, суффикс `.jsonl` | Меняет путь audit-файла. Default: `${OPENCLAW_STATE_DIR:-$HOME/.openclaw}/logs/llm-action-judge.jsonl`. |
| `OPENCLAW_JUDGE_LOG_LEVEL` | Необязательно: `error`, `warn`, `info`, `silent`; default `info` | Управляет operational-логами плагина. На решения judge и JSONL audit не влияет. |

Не создавайте переменные вроде `OPENCLAW_JUDGE_MODEL`,
`OPENCLAW_JUDGE_POLICY` или `OPENCLAW_JUDGE_PROMPT`: неизвестная переменная с
префиксом `OPENCLAW_JUDGE_` считается ошибкой. Model, policy, prompt, threshold и
guard зафиксированы внутри версии плагина.

Любая ошибка конфигурации не останавливает gateway: hooks остаются
зарегистрированы, а plugin переходит в permanent `supervised + enforce` с
failing client. Каждый tool call тогда требует native approval, а audit writer
не работает до исправления конфигурации и restart gateway.

Если `OPENCLAW_JUDGE_PROFILE` не задан, используется legacy config
`plugins.entries.llm-action-judge.config`; его code default —
`mode=autonomous, enforcement=shadow`. Для предсказуемого deployment всегда
задавайте profile явно.

## Как проверить, что всё работает

После запуска выполните:

```bash
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
openclaw plugins doctor
```

Ожидаемый результат:

- gateway отвечает `OK`;
- `imported=true`;
- version `0.4.1`;
- hooks: `before_model_resolve` и `before_tool_call`;
- `diagnostics=[]`.

Открыть интерактивный интерфейс:

```bash
openclaw dashboard
```

Для наглядного smoke используйте только одноразовый тестовый каталог:

1. Попросите агента прочитать обычный несекретный файл — корректный `allow`
   должен пройти во всех enforcement-режимах.
2. Попросите изменить production-marked config или выполнить destructive delete.
   В `supervised` действие не должно выполниться автоматически: ожидается native
   approval или block; после явного approval оно может выполниться. В
   `autonomous` ожидается block.
3. Проверьте, что заблокированное действие не изменило файл.

Смотреть audit в реальном времени:

```bash
tail -f "${OPENCLAW_JUDGE_AUDIT_PATH:-${OPENCLAW_STATE_DIR:-$HOME/.openclaw}/logs/llm-action-judge.jsonl}"
```

Основные поля audit:

- `decision` — raw решение LLM;
- `risk` и `authorization` — оценка риска и наличия разрешения;
- `outcome` — итог после schema validation, confidence threshold и local guard;
- `mode`/`enforcement` — активный режим;
- `latency_ms` — время ответа judge.

Если `decision=allow`, а `outcome=review`, LLM разрешила действие, но локальный
guard не позволил выполнить его автоматически.

## Как проходит один tool call

1. `before_model_resolve` сохраняет exact trusted request только для текущего
   `runId`; предыдущий transcript судье не передаётся.
2. `before_tool_call` создаёт immutable snapshot действия и непрозрачный keyed
   HMAC-SHA-256 commitment.
3. В Cloud.ru уходят user request, tool name, redacted params, fixed policy и
   action hash.
4. Judge возвращает seven-field verdict через strict `json_schema`.
5. Плагин повторно валидирует verdict локально через Ajv, проверяет hash,
   `risk=low`, `authorization=high` и confidence `>=0.8`.
6. Opaque-data и deterministic guards могут только ужесточить решение.
7. Action повторно хешируется после async model call; mutation означает failure.
8. Mode mapper разрешает, запрашивает approval либо блокирует tool call.

32-byte commitment key случайно создаётся внутри Node.js process, не читается из
ENV, не экспортируется, не сохраняется и не передаётся judge. Wire-формат
`sha256:<64 lowercase hex>` сохранён. Значение стабильно в пределах одного
process и меняется после restart, поэтому audit hashes нельзя сопоставлять между
разными запусками gateway.

Schema-valid ответ не означает safe решение: semantic checks и deterministic
guard остаются обязательными. Fallback на `json_object` отсутствует.

## Зафиксированный контракт 0.4.1

- model: `Qwen/Qwen3.5-397B-A17B`;
- policy: `2026-07-14.6`;
- minimum allow confidence: `0.8`;
- default timeout: `8000 ms`;
- endpoint: только `https://foundation-models.api.cloud.ru/v1`;
- hooks priority: `-1000`;
- output: strict `json_schema` + local Ajv validation.

Текущие `108/120` safe и `0/240` combined unsafe относятся к tuned regression
corpus. Raw judge разрешил 18 unsafe attempts, local/semantic guards заблокировали
все 18. Отдельный unseen holdout ещё не проведён, поэтому эти числа нельзя
считать оценкой production FN. Полная методология и ограничения находятся в
[RND.md](RND.md).

## Troubleshooting

- `setup failed`: gateway остаётся в safe supervised fallback. Проверьте spelling
  всех `OPENCLAW_JUDGE_*`, legacy config, API key, exact base URL, timeout и audit
  path, затем перезапустите gateway.
- HTTP `401/403`: key не имеет доступа к fixed judge model либо истёк.
- Timeout: сначала проверьте `no_proxy`/`NO_PROXY` и доступность Cloud.ru.
- Plugin imported, hooks отсутствуют: используйте `--runtime`, выполните registry
  refresh и проверьте `allowConversationAccess=true`.
- Managed gateway не видит ENV: задайте переменные в service manager/Kubernetes,
  а не только в текущем terminal shell.
- Native approval не появляется в supervised: сначала проверьте approval route
  самого OpenClaw; плагин не реализует отдельный UI подтверждения.

Полный update/rollback/uninstall runbook: [DEPLOYMENT.md](DEPLOYMENT.md).

## Документы

- [DEPLOYMENT.md](DEPLOYMENT.md) — managed install, update, rollback, uninstall.
- [CONTRACT.md](CONTRACT.md) — black-box входы, выходы и failure semantics.
- [SECURITY.md](SECURITY.md) — security boundary и incident response.
- [RND.md](RND.md) — исследование моделей, benchmark и его ограничения.
- [HOLDOUT.md](HOLDOUT.md) — sealed primary/reserve protocol без label leakage.
- [CHANGELOG.md](CHANGELOG.md) — история версий.
