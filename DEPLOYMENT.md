# Deployment runbook

## Requirements

- OpenClaw `>=2026.4.21`; archive install enforces the same floor through
  `openclaw.install.minHostVersion` and `openclaw.compat.pluginApi`;
- Node.js `>=22.19.0`;
- доступ к `https://foundation-models.api.cloud.ru/v1`;
- API key с доступом к `Qwen/Qwen3.5-397B-A17B`;
- npm registry или internal mirror для установки pinned runtime dependency
  `ajv@8.20.0` из package metadata;
- `foundation-models.api.cloud.ru` в `no_proxy` и `NO_PROXY`, если host работает
  через корпоративный proxy.

Плагин не читает `.env`: platform/service manager должен передать переменные
самому процессу OpenClaw до запуска gateway.

## 1. Verify artifact

Из каталога `releases/v0.5.0`:

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.5.0.tgz.sha256
```

Ожидается `OK`. Не устанавливайте artifact с несовпавшим checksum.

## 2. Pass deployment environment

Для managed gateway значения должны быть записаны в durable environment самого
service manager/platform до restart:

```text
OPENCLAW_JUDGE_API_KEY=<secret-from-platform>
OPENCLAW_JUDGE_PROFILE=shadow
OPENCLAW_JUDGE_BASE_URL=https://foundation-models.api.cloud.ru/v1
OPENCLAW_JUDGE_TIMEOUT_MS=30000
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

До restart добавьте `llm-action-judge` в `plugins.allow`. Если allowlist уже
существует, сохраните все trusted ids других plugins и выполните merge через
platform config management. Не заменяйте рабочий список одной строкой. Для
новой выделенной node, где judge — единственный non-bundled plugin, подходит
следующая команда:

```bash
openclaw plugins install ./openclaw-llm-action-judge-0.5.0.tgz
openclaw config set plugins.allow '["llm-action-judge"]' --strict-json
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
openclaw plugins inspect --all --runtime --json
openclaw plugins doctor
```

Runtime inspect обязан показать:

- запись `plugin.id=llm-action-judge` имеет `plugin.imported=true` и
  `plugin.version=0.5.0`;
- её runtime `typedHooks` содержит ровно
  `{"name":"before_model_resolve","priority":-1000}` и
  `{"name":"before_tool_call","priority":-1000}`;
- `diagnostics=[]`;
- полный inventory не содержит params-modifying `before_tool_call`, который
  исполняется после judge.

Failure регистрации `before_tool_call` теперь abort'ит plugin load. Поэтому
`imported=true`, `diagnostics=[]` и exact `typedHooks` должны выполняться
одновременно; одного успешного archive install недостаточно.

Metadata-only inspect не доказывает загрузку hooks. Оба hook judge имеют priority
`-1000`; независимо от числовой сортировки конкретного host judge должен быть
единственным либо последним hook, которому разрешено менять `params`. Hook после
него может только наблюдать или блокировать. Если порядок или mutation contract
других plugins нельзя доказать, оставьте profile `shadow`.

## 5. Operational rollout

1. Начните с `OPENCLAW_JUDGE_PROFILE=shadow`.
2. Проверьте latency/failure и secret-safe audit на реальном traffic.
3. Переключите на `supervised`, если native approval route готов.
4. `autonomous` включайте только после отдельной operational qualification.

Для strongest isolation включите native OpenClaw sandbox. Плагин разрешает
benign `exec` без явного `host` после judge/guard, а effective routing такого
вызова на установке без sandbox может быть gateway. Browser auto-allow, напротив,
требует literal `target=sandbox` и не полагается на default routing.

После смены profile обновите durable environment service manager/platform,
выполните rollout/restart и повторите runtime verification.
Изменённый timeout не меняет model/policy, но делает опубликованные latency и
failure metrics несопоставимыми с deployment.

## Update

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.5.0.tgz.sha256
openclaw plugins install ./openclaw-llm-action-judge-0.5.0.tgz --force
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect --all --runtime --json
```

Если старая версия подключена через `plugins.load.paths`/`--link`, сначала
посмотрите точный список и удалите только старый judge path. Не удаляйте пути
других plugins.

## Rollback 0.5.0 → 0.4.1

Пока работает 0.5.0, сначала задайте `OPENCLAW_JUDGE_PROFILE=shadow` в durable
environment service manager/platform, выполните rollout/restart и проверьте
health. Shell-local значение для managed service недостаточно.

Затем установите предыдущий проверенный artifact 0.4.1. Он сохраняет public
ENV/profile, hooks, fixed model и strict Structured Output transport, но не
содержит v0.5 worker feedback, circuit breaker и hard routing:

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.4.1.tgz.sha256
openclaw plugins install ./openclaw-llm-action-judge-0.4.1.tgz --force
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect --all --runtime --json
```

Проверьте runtime version `0.4.1`, два hook и `diagnostics=[]`.

### Further rollback 0.4.1 → 0.4.0

Artifact 0.4.0 откатывает policy с `2026-07-15.1` до `2026-07-14.6` и default
judge deadline с `30000 ms` до `8000 ms`. В нём также нет process-local HMAC
action commitment и sealed holdout tooling 0.4.1:

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.4.0.tgz.sha256
openclaw plugins install ./openclaw-llm-action-judge-0.4.0.tgz --force
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect --all --runtime --json
```

Проверьте runtime version `0.4.0`, два hook и `diagnostics=[]`. Rollback не
отзывает API key — при incident с credential выполните отдельную
rotation/revocation.

### Further rollback 0.4.0 → 0.3.0

Artifact 0.3.0 использует тот же public ENV/profile и hook contract,
но policy `2026-07-12.4` и старый `json_object` transport:

```bash
shasum -a 256 -c openclaw-llm-action-judge-0.3.0.tgz.sha256
openclaw plugins install ./openclaw-llm-action-judge-0.3.0.tgz --force
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect --all --runtime --json
```

### Further rollback 0.3.0 → 0.2.0

Перед установкой 0.2.0 явно зафиксируйте его legacy observe-only config, потому
что эта версия игнорирует `OPENCLAW_JUDGE_*`:

```bash
openclaw config set plugins.entries.llm-action-judge.config '{"mode":"supervised","enforcement":"shadow"}' --strict-json
openclaw config get plugins.entries.llm-action-judge.config --json
openclaw config validate
```

Только затем устанавливайте проверенный artifact 0.2.0. Ему также нужен shared
`models.providers.cloudru` config.

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
- warning `plugins.allow is empty`: добавьте `llm-action-judge` к существующему
  allowlist, сохранив trusted ids других plugins.
- HTTP 401/403: проверьте доступ key к fixed model.
- timeout: endpoint остаётся fail-closed; сначала проверьте proxy/no_proxy и
  latency, не увеличивайте deadline вслепую.
- plugin imported, `typedHooks` отсутствуют: используйте
  `plugins inspect --all --runtime --json`, refresh registry и проверьте
  `allowConversationAccess`.
- после judge есть params-modifying hook: измените порядок/контракт plugins либо
  оставьте judge в `shadow`; такой composition не поддерживается для
  enforcement.
- gateway config invalid: выполните `openclaw doctor`, но сначала сохраните
  backup config и просмотрите предлагаемые изменения.
