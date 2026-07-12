# OpenClaw LLM Action Judge: ENV-контракт и standalone handoff

Дата: **12 июля 2026**
Статус: **design approved**

## Цель

Подготовить `openclaw-llm-action-judge` версии `0.3.0` как самостоятельный
репозиторий и устанавливаемый OpenClaw-плагин, который команда разработки может
забрать как black box:

- deployment передаёт небольшой набор environment variables;
- плагин сам регистрирует оба OpenClaw hook;
- модель, policy, prompt, threshold, fail-closed mapping и deterministic guard
  нельзя переопределить снаружи;
- на выходе OpenClaw получает allow, block либо native one-call approval;
- исходники, тесты, R&D evidence, инструкции и versioned release artifact
  публикуются в одном GitLab-репозитории.

Изменение `0.3.0` не меняет production decision contract `0.2.0`: fixed judge
остаётся `Qwen/Qwen3.5-397B-A17B`, policy — `2026-07-12.4`, minimum confidence —
`0.8`, timeout по умолчанию — `8000 ms`.

## Публичный deployment-контракт

Плагин читает значения только из `process.env`; `.env`-файлы он не загружает и
не изменяет.

| Переменная | Обязательность | Default | Назначение |
|---|---|---|---|
| `OPENCLAW_JUDGE_API_KEY` | рекомендуемая; обязательна без shared provider | — | Отдельный credential judge. |
| `OPENCLAW_JUDGE_PROFILE` | рекомендуемая | legacy plugin config, затем `shadow` | Один operational profile. |
| `OPENCLAW_JUDGE_BASE_URL` | нет | `https://foundation-models.api.cloud.ru/v1` | Explicit fixed Cloud.ru base URL для отдельного key. |
| `OPENCLAW_JUDGE_TIMEOUT_MS` | нет | `8000` | Deadline одного judge request, `1000..30000`. |
| `OPENCLAW_JUDGE_AUDIT_PATH` | нет | `${OPENCLAW_STATE_DIR:-~/.openclaw}/logs/llm-action-judge.jsonl` | Путь secret-safe JSONL audit внутри OpenClaw logs root. |
| `OPENCLAW_JUDGE_LOG_LEVEL` | нет | `info` | `error`, `warn`, `info` или `silent`; только lifecycle diagnostics. |

Неизвестная переменная с prefix `OPENCLAW_JUDGE_`, пустое explicit значение,
невалидный enum, timeout вне границ или audit path вне OpenClaw logs root считаются
ошибкой конфигурации. Ошибка не откатывается к более permissive default:
плагин регистрирует hooks, логирует фиксированную secret-free ошибку и работает
через supervised approval с timeout-deny.

ENV snapshot строится один раз во время `register`; последующее изменение
`process.env` не меняет активный gate. API key должен быть непустым printable
ASCII без whitespace/control characters и не длиннее 4096 bytes. Timeout
принимается только как canonical decimal integer без whitespace, exponent и
leading zero.

### Profile mapping

| `OPENCLAW_JUDGE_PROFILE` | Внутренний режим | Поведение |
|---|---|---|
| `shadow` | `autonomous + shadow` | Judge и audit работают, tool call не изменяется. |
| `supervised` | `supervised + enforce` | `review`/failure передаётся человеку, timeout блокирует. |
| `autonomous` | `autonomous + enforce` | Только validated allow исполняется автоматически. |

Если `OPENCLAW_JUDGE_PROFILE` отсутствует, сохраняется совместимость с
`plugins.entries.llm-action-judge.config.mode/enforcement`. Если нет и legacy
config, code default остаётся `autonomous + shadow`.

## Precedence и credential boundary

1. Explicit ENV имеет приоритет над соответствующим legacy plugin config.
2. При наличии `OPENCLAW_JUDGE_API_KEY` judge использует отдельный credential.
   `OPENCLAW_JUDGE_BASE_URL` принимается только как canonical
   `https://foundation-models.api.cloud.ru/v1`; другой origin, port, path,
   userinfo, query и fragment запрещены. Endpoint строится как
   `<base>/chat/completions`, redirect запрещён.
3. Без `OPENCLAW_JUDGE_API_KEY` разрешён backward-compatible fallback на
   `models.providers.cloudru`. Для shared credential допустим только exact
   `https://foundation-models.api.cloud.ru/v1`; ENV base URL в этом случае —
   configuration error.
   При dedicated ENV key shared provider не читается вообще.
4. ENV key, raw prompt, raw params и response body не попадают в lifecycle log
   или plugin audit.

Alternative endpoint можно добавить только в immutable allowlist новой версии
после отдельной квалификации. Это сохраняет credential/data boundary и не даёт
ошибке ENV незаметно отправить Bearer key, raw trusted request и action metadata
на другой host.

## Внутренний runtime flow

Плагин автоматически регистрирует ровно два hook с priority `-1000`:

1. `before_model_resolve` сохраняет raw trusted request только для exact
   `runId`, максимум 64 KiB и максимум на 30 минут.
2. `before_tool_call` формирует immutable action snapshot, редактирует secrets,
   вычисляет SHA-256 action hash и вызывает fixed judge.
3. Ответ принимается только как exact seven-field JSON, совпадающий по policy и
   action hash.
4. Model allow может быть только понижен opaque/local deterministic guard; guard
   никогда не повышает verdict.
5. Перед allow exact action повторно строится и сравнивается после async вызова.
6. Outcome переводится в OpenClaw hook result и пишется в secret-safe audit.

Host обязан один раз выдать hook permission:

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

Hooks не прокидываются отдельными файлами и не устанавливаются вручную: они
находятся внутри plugin entrypoint и регистрируются при загрузке.

## Выходной контракт

| Gate outcome | Shadow | Supervised enforce | Autonomous enforce |
|---|---|---|---|
| validated `allow` | `undefined` | `{ params }` | `{ params }` |
| `review` | `undefined` | `{ params, requireApproval }` | `{ block: true }` |
| `deny` | `undefined` | `{ block: true }` | `{ block: true }` |
| setup/transport/schema/hash failure | `undefined` только при валидном shadow config | `requireApproval`, timeout-deny | `{ block: true }` |

Native approval содержит `pluginId=llm-action-judge`, severity `critical`,
timeout `60000 ms`, `timeoutBehavior=deny`.

## Logging и audit

Lifecycle log содержит только фиксированные сообщения о registration/setup/audit
failure. `LOG_LEVEL` не включает raw per-action logging.

Audit — append-only JSONL с mode `0600`. Explicit path обязан быть normalized
absolute `.jsonl` внутри `${OPENCLAW_STATE_DIR:-~/.openclaw}/logs`; `..`, выход
из root и symlink ancestors запрещены. Final file обязан быть regular file,
принадлежать текущему uid и иметь один hardlink, где эти свойства поддерживаются
ОС. Событие содержит timestamp, fixed model/policy, tool name, action hash,
хешированные correlation IDs, verdict enums, confidence, outcome, latency,
mode и enforcement. Raw prompt, params, identifiers, rationale и credential
отсутствуют.

Audit failure ухудшает observability, но не меняет tool decision.

## Standalone repository и release

Repository root содержит:

- runtime source: `index.js`, `openclaw.plugin.json`, `src/`;
- public docs: `README.md`, `CONTRACT.md`, `DEPLOYMENT.md`, `RND.md`,
  `SECURITY.md`, `CHANGELOG.md`, `LICENSE`, `.env.example`;
- tests/evals и frozen evidence для воспроизводимости;
- `.gitlab-ci.yml` с test, package и checksum verification;
- source-only release builder;
- `releases/v0.3.0/` с `.tgz`, SHA-256, evidence archive и concise handoff manifest.

Runtime `.tgz` содержит только allowlisted production files и public runtime
docs; tests, evals, candidate reviews, CI и build scripts остаются в source.
Реальные secrets, `.env`, absolute host paths и raw logs запрещены release scan.

Evidence archive разделяет неизменённый `qualification-baseline-0.2.0` и новые
`integration-v0.3.0` проверки; переименование старого archive запрещено.

GitLab release point — tag `v0.3.0`. Commit и tag должны соответствовать
checksum опубликованного artifact.

## Проверка перед передачей

Обязательны:

1. полный `npm test`;
2. package allowlist и secret/path scan;
3. сборка release в fresh directory и повторная SHA-256 verification;
4. clean install из exact `.tgz` в полностью изолированном OpenClaw state;
5. runtime inspect: imported, ровно два hooks, diagnostics empty;
6. gateway config validate/health;
7. safe allow, guarded unsafe block и supervised approval mapping;
8. проверка environment precedence и shared-provider fallback;
9. независимый final code/security review;
10. push main и annotated tag только после всех проверок.

Full 360-attempt model qualification не повторяется, потому что `0.3.0` не
меняет fixed model, prompt, policy, parser, normalizer или guard. Existing
benchmark evidence маркируется как qualification baseline `0.2.0`; для `0.3.0`
добавляется integration/runtime evidence. При любом изменении decision layer
нужен новый policy version и новый benchmark.

Изменение timeout сохраняет model/policy qualification, но делает опубликованные
latency/failure метрики несопоставимыми с конкретным deployment.

## Не входит в scope

- Helm chart, Kubernetes manifests и secret manager adapter;
- настройка actor model или общего token budget;
- UI для approval;
- динамический выбор judge model/policy/prompt;
- auto-rotation credentials;
- утверждение, что autonomous enforcement production-qualified.
