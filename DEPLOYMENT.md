# Deployment runbook

## Requirements

- OpenClaw `>=2026.6.11`;
- Node.js `>=22.19.0`;
- доступ к `https://foundation-models.api.cloud.ru/v1`;
- API key с доступом к `Qwen/Qwen3.5-397B-A17B`;
- `foundation-models.api.cloud.ru` в `no_proxy` и `NO_PROXY`, если host работает
  через корпоративный proxy.

Плагин не читает `.env`: platform/service manager должен передать переменные
самому процессу OpenClaw до запуска gateway.

## 1. Verify artifact

Из каталога `releases/v0.3.0`:

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.3.0.tgz.sha256
```

Ожидается `OK`. Не устанавливайте artifact с несовпавшим checksum.

## 2. Pass deployment environment

Для managed gateway значения должны быть записаны в durable environment самого
service manager/platform до restart:

```text
OPENCLAW_JUDGE_API_KEY=<secret-from-platform>
OPENCLAW_JUDGE_PROFILE=shadow
OPENCLAW_JUDGE_BASE_URL=https://foundation-models.api.cloud.ru/v1
OPENCLAW_JUDGE_TIMEOUT_MS=8000
OPENCLAW_JUDGE_LOG_LEVEL=info
```

Типовые варианты: container `env`/Secret в платформе, systemd
`Environment`/`EnvironmentFile`, launchd `EnvironmentVariables` либо штатная
настройка environment вашего gateway service. Обновите service definition и
выполните platform rollout/restart. Обычный shell export перед
`openclaw gateway restart` не передаётся уже установленному managed service.

Для локального foreground gateway smoke можно передать environment тому же
процессу напрямую:

```bash
OPENCLAW_JUDGE_API_KEY='<secret-from-platform>' \
OPENCLAW_JUDGE_PROFILE='shadow' \
openclaw gateway run
```

Этот foreground процесс не переживёт reboot и не заменяет durable service
configuration.

Если задаёте `OPENCLAW_JUDGE_AUDIT_PATH`, он должен заканчиваться `.jsonl` и
находиться внутри `${OPENCLAW_STATE_DIR:-$HOME/.openclaw}/logs`.

## 3. Install and grant hook permission

Следующий restart предполагает, что managed gateway environment уже обновлён по
шагу 2.

```bash
openclaw plugins install ./openclaw-llm-action-judge-0.3.0.tgz
openclaw config set plugins.entries.llm-action-judge.hooks.allowConversationAccess true --strict-json
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
```

Для обновления существующей версии добавьте `--force` к `plugins install`.
Archive install используется без `--link`.

Legacy `mode/enforcement` config можно оставить для rollback compatibility, но
`OPENCLAW_JUDGE_PROFILE` имеет приоритет над валидным legacy config.

## 4. Runtime verification

```bash
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
openclaw plugins doctor
```

Runtime inspect обязан показать:

- `imported=true`;
- version `0.3.0`;
- ровно `before_model_resolve` и `before_tool_call`;
- `diagnostics=[]`.

Metadata-only inspect не доказывает загрузку hooks.

## 5. Operational rollout

1. Начните с `OPENCLAW_JUDGE_PROFILE=shadow`.
2. Проверьте latency/failure и secret-safe audit на реальном traffic.
3. Переключите на `supervised`, если native approval route готов.
4. `autonomous` включайте только после отдельной operational qualification.

После смены profile обновите durable environment service manager/platform,
выполните rollout/restart и повторите runtime verification.
Изменённый timeout не меняет model/policy, но делает опубликованные latency и
failure metrics несопоставимыми с deployment.

## Update

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.3.0.tgz.sha256
openclaw plugins install ./openclaw-llm-action-judge-0.3.0.tgz --force
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
```

Если старая версия подключена через `plugins.load.paths`/`--link`, сначала
посмотрите точный список и удалите только старый judge path. Не удаляйте пути
других plugins.

## Rollback

Пока работает 0.3.0, сначала задайте `OPENCLAW_JUDGE_PROFILE=shadow` в durable
environment service manager/platform, выполните rollout/restart и проверьте
health. Shell-local значение для managed service недостаточно.

До установки 0.2.0 явно зафиксируйте его legacy observe-only config, потому что
эта версия игнорирует `OPENCLAW_JUDGE_*`:

```bash
openclaw config set plugins.entries.llm-action-judge.config '{"mode":"supervised","enforcement":"shadow"}' --strict-json
openclaw config get plugins.entries.llm-action-judge.config --json
openclaw config validate
```

Только затем установите предыдущий проверенный versioned artifact:

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.2.0.tgz.sha256
openclaw plugins install ./openclaw-llm-action-judge-0.2.0.tgz --force
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
openclaw config get plugins.entries.llm-action-judge.config --json
```

Проверьте одновременно runtime version `0.2.0` и exact legacy config
`supervised + shadow`. Версии 0.2.0 также нужен shared
`models.providers.cloudru` config. Rollback не отзывает API key — при incident
с credential выполните отдельную rotation/revocation.

## Uninstall

```bash
openclaw plugins disable llm-action-judge
openclaw plugins uninstall llm-action-judge --force
openclaw config validate
openclaw gateway restart
openclaw gateway health
```

## Troubleshooting

- `setup failed`: проверьте unknown/blank ENV, exact base URL, key grammar,
  timeout и audit path.
- HTTP 401/403: проверьте доступ key к fixed model.
- timeout: endpoint остаётся fail-closed; сначала проверьте proxy/no_proxy и
  latency, не увеличивайте deadline вслепую.
- plugin imported, hooks absent: используйте `--runtime`, refresh registry и
  проверьте `allowConversationAccess`.
- gateway config invalid: выполните `openclaw doctor`, но сначала сохраните
  backup config и просмотрите предлагаемые изменения.
