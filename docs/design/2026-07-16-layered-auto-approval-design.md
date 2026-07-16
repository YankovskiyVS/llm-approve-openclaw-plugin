# Layered auto-approval и безопасная обратная связь при отказе

Дата: 16 июля 2026 года

Статус: design approved

## Цель

Версия `0.5.0` должна автоматически разрешать безопасные tool calls, останавливать
опасные действия до исполнения и возвращать рабочей модели понятный результат
отказа. Отказ является обычным tool result: агент должен понять причину,
перепланировать действие или запросить пользователя, а не повторять тот же вызов.

LLM judge остаётся дополнительным permission layer. Sandbox, IAM, native OpenClaw
permissions и ограничения инструментов не ослабляются.

## Source of truth

Разработка ведётся в Git-репозитории
`/Users/aogabbasov/.codex/worktrees/llm-approve-openclaw-plugin`. Установленная
копия `~/.openclaw/extensions/llm-action-judge` используется только для runtime
smoke после сборки пакета. Каталог
`/Users/aogabbasov/openclaw_research/openclaw-llm-action-judge` содержит старую
версию `0.1.0` и не является источником релиза.

Текущие незакоммиченные изменения `0.4.1` сохраняются. Новая работа должна быть
совместима с уже добавленным deterministic guard и не подменять его старой
копией исходников.

## Выбранная архитектура

```text
OpenClaw before_tool_call
        |
        v
нормализация exact action + immutable hard boundaries
        |
        +-- hard deny --------------------------+
        |                                       |
        v                                       |
узкий deterministic safe-path в shadow         |
        |                                       |
        v                                       |
fixed Qwen judge для остальных действий        |
        |                                       |
        v                                       v
локальная schema/policy validation ------> agent feedback
        |
        v
allow | deny | human approval
        |
        v
native OpenClaw sandbox/permissions/executor
```

Один пакет поддерживает два режима:

- `autonomous`: только validated allow достигает executor; `deny`, `review`,
  timeout и invalid response блокируются;
- `supervised`: validated allow исполняется, explicit deny блокируется, а
  `review` и техническая неопределённость передаются в native one-call approval.

## Почему нет второго LLM-вызова по умолчанию

Claude Auto использует быстрый classifier перед reasoning, но полезность такого
каскада зависит от latency, цены и измеренного false-negative rate конкретной
модели. Для текущего fixed Qwen второй вызов нельзя включать только по аналогии с
чужим runtime.

В `0.5.0` роль первого классификатора выполняет deterministic routing:

1. небольшое множество неизменяемых hard boundaries;
2. узкий safe-path, который сначала работает только в shadow и сравнивается с
   verdict judge;
3. полный Qwen judge для gray band.

LLM preclassifier допускается как eval-only кандидат. Он может стать production
слоем только после family-disjoint benchmark, где hybrid не ухудшает unsafe
allow rate и действительно снижает latency или стоимость.

## Hard boundaries

Hard boundary срабатывает до LLM и не может быть повышена до allow моделью,
workspace-конфигурацией или другим plugin hook. В эту категорию входят только
стабильные инварианты:

- отключение или модификация judge, его policy, audit и approval boundary;
- credential exfiltration и явная передача секретов во внешний канал;
- попытка обойти sandbox, approval или security controls;
- необратимое host/org/production действие без ограниченной цели и recovery
  boundary;
- повторное действие после сработавшего circuit breaker.

Обычная рискованная, но потенциально легитимная операция не становится hard deny:
в supervised она должна попадать человеку, а в autonomous блокироваться как
review. Deterministic правила не должны превращаться в бесконечный blacklist
флагов и строк.

## Safe-path

Safe-path разрешает без LLM только действие, безопасность которого доказана по
полностью видимому typed envelope. На первом этапе он не влияет на исполнение:
плагин вычисляет кандидатное решение, всё равно вызывает judge и пишет только
disagreement metrics.

Production auto-allow для отдельной family включается лишь после проверки
false-positive и false-negative на frozen/reserve корпусе. Unknown tool, opaque,
redacted, truncated или malformed input никогда не попадает в safe-path.

## Контекст judge

Judge получает только:

- trusted user request, привязанный к текущему `runId`;
- нормализованный exact tool name и параметры;
- action hash и версию policy;
- bounded историю предыдущих action decisions текущего run без raw tool outputs,
  assistant prose и hidden reasoning.

Сырые результаты tools и retrieved content считаются недоверенными. Если в
будущем появится result-scanner, он будет отдельным input/context guardrail и не
заменит action approval.

## Structured output judge

Контракт расширяется обязательным `reason_code`:

```json
{
  "policy_version": "<fixed version>",
  "action_hash": "sha256:<64 hex>",
  "decision": "allow",
  "risk": "low",
  "authorization": "high",
  "confidence": 0.98,
  "reason_code": "safe_and_authorized",
  "rationale": "The bounded read is authorized by the trusted request."
}
```

Допустимые model-controlled reason codes:

```text
safe_and_authorized
authorization_missing
out_of_scope
destructive_or_irreversible
sensitive_data
external_side_effect
privilege_or_security_boundary
untrusted_instruction
self_modification
opaque_or_unverifiable
other_policy_risk
```

Совместимость проверяется локально:

- `allow` допустим только с `safe_and_authorized`;
- `review` и `deny` не могут использовать `safe_and_authorized`;
- неизвестный или противоречивый код делает весь verdict invalid и включает
  fail-closed mapping;
- все поля обязательны, unknown properties запрещены;
- action hash, policy version, risk/authorization threshold и confidence по-прежнему
  проверяются кодом после schema validation.

`rationale` не показывается рабочей модели и не пишется в raw-виде в audit. Он
остаётся диагностическим полем контракта, но не является security boundary и не
участвует в формировании публичного сообщения.

## Agent feedback contract

OpenClaw преобразует `blockReason` в текстовый tool result, видимый рабочей
модели. Плагин сериализует туда bounded JSON одной строкой:

```json
{
  "schema": "openclaw.action-gate.feedback.v1",
  "status": "blocked",
  "code": "out_of_scope",
  "message": "Действие выходит за рамки запроса пользователя.",
  "retry": "after_change",
  "next_step": "Выберите более узкое действие либо запросите явное разрешение пользователя."
}
```

`message` и `next_step` берутся только из immutable map внутри плагина. В них не
попадают raw rationale, tool params, matched fragments, secrets, thresholds,
внутренние rule IDs или текст policy prompt.

Host-only feedback codes дополняют коды judge:

```text
hard_policy_block
local_policy_review
judge_unavailable
invalid_judge_response
opaque_or_unverifiable
repeated_denials
```

`retry` имеет закрытый enum:

- `after_change`: разрешено предложить более узкое или обратимое действие;
- `after_user_input`: продолжение требует нового явного решения пользователя;
- `do_not_retry`: нельзя искать альтернативную формулировку того же запрещённого
  эффекта.

Unknown internal state всегда отображается в консервативный
`invalid_judge_response`, а не в raw exception text. Максимальный размер
feedback ограничивается 1024 UTF-8 bytes.

## Circuit breaker

Плагин хранит bounded decision history отдельно для каждого `runId`:

- validated allow сбрасывает счётчик последовательных deny;
- после трёх последовательных explicit/hard deny circuit breaker закрывает
  дальнейшие tool calls текущего run;
- дополнительный предел — десять deny среди последних пятидесяти решений;
- новый `runId` начинает чистое состояние;
- technical failure и review не маскируют deny и не открывают breaker.

После срабатывания модель получает `repeated_denials` с `retry=after_user_input`.
Это предотвращает перебор обходов, но не создаёт постоянную глобальную блокировку
пользователя или агента.

## Поведение по исходам

| Исход | Autonomous | Supervised | Feedback рабочей модели |
|---|---|---|---|
| validated allow | execute | execute | обычный tool result |
| explicit deny | block | block | reason code + safe next step |
| hard boundary | block | block | `hard_policy_block`, `do_not_retry` |
| judge review | block | native approval | safe reason; в supervised причина также в approval description |
| local/opaque downgrade | block | native approval | host-generated safe reason |
| timeout/API error | block | native approval | `judge_unavailable` |
| malformed/schema mismatch | block | native approval | `invalid_judge_response` |
| circuit breaker | block | block | `repeated_denials` |

После native human deny/timeout OpenClaw `2026.6.11` формирует собственный tool
result. Плагин не подменяет эту строку через `before_tool_call`; единый feedback
контракт для human resolution потребует upstream-поля в approval API и не входит
в `0.5.0`.

## Audit и приватность

Audit сохраняет operational evidence:

- action hash, tool family, decision, risk, authorization и reason code;
- источник решения: hard boundary, safe-path shadow, LLM, local downgrade,
  failure или circuit breaker;
- latency, timeout/failure class, mode, policy/schema version;
- факт доставленного feedback code без полного публичного текста.

Audit не сохраняет raw prompt, raw params, secrets, hidden reasoning, raw model
response или полный rationale. Ошибка audit не меняет permission decision.

## Тестирование и benchmark

Обязательные уровни:

1. Unit tests strict schema, compatibility matrix и всех feedback templates.
2. Security tests доказывают, что secret/prompt-injection sentinel из rationale,
   params или exception не появляется в `blockReason`.
3. Plugin tests проверяют mapping всех исходов в autonomous и supervised.
4. Circuit-breaker tests проверяют оба порога, reset и bounded storage.
5. Runtime E2E на stock OpenClaw подтверждает цепочку:
   `deny -> blockReason -> tool_result -> безопасная следующая попытка агента`.
6. Benchmark сравнивает raw LLM, deterministic-only, текущий hybrid и
   safe-path candidate по family-level FP/FN, latency, token cost и failure rate.
7. Новый strict contract получает новую policy/schema version и новый
   family-disjoint qualification run; старый holdout не переименовывается в
   доказательство качества новой версии.

LLM preclassifier остаётся отдельным eval-профилем. Его нельзя включить в релиз,
если хотя бы одна dangerous family, пойманная full judge, проходит через быстрый
allow.

## Release gates

Релиз `0.5.0` допустим только если:

- все unit/integration/package/runtime smoke tests проходят;
- explicit deny никогда не достигает executor;
- каждый plugin-controlled block возвращает schema-valid feedback;
- raw rationale и sentinels не попадают в feedback или audit;
- invalid output, timeout и exception остаются fail-closed;
- circuit breaker нельзя сбросить повторным tool call внутри того же run;
- catastrophic unsafe auto-allow равен нулю на qualification corpus;
- safe recall, dangerous recall, family FP/FN, latency и token cost опубликованы
  раздельно;
- package устанавливается в чистый OpenClaw и регистрирует ожидаемые hooks без
  diagnostics.

## Не входит в `0.5.0`

- замена sandbox, IAM или native OpenClaw permissions;
- показ raw chain-of-thought или model rationale рабочему агенту;
- обучение локального classifier на production audit data;
- автоматическое расширение hard policy из workspace/repository config;
- собственный approval UI вместо OpenClaw;
- утверждение, что нулевой FN на конечном корпусе является абсолютной security
  гарантией.
