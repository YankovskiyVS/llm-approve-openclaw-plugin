# Security policy

Поддерживаемый internal release: `openclaw-llm-action-judge` 0.4.1 с policy
`2026-07-14.6` на OpenClaw
`>=2026.6.11` и Node.js `>=22.19.0`.

## Security boundary

Плагин связывает fixed judge verdict с opaque keyed exact-action commitment,
принимает только strict seven-field JSON, повторно проверяет action после async
call и работает fail-closed при setup/transport/timeout/schema/policy/hash/
mutation failure.

Commitment — HMAC-SHA-256 canonical action со случайным 32-byte process-local
key. Key не читается из ENV, не экспортируется, не сохраняется и не передаётся
judge. Это не позволяет проверять словарь low-entropy redacted secrets по
видимому `action_hash`. Прежний wire-формат `sha256:<64 lowercase hex>` сохранён,
но значение намеренно ротируется при restart gateway и не является
cross-process audit identifier.

Cloud.ru constrains generation через `response_format.type=json_schema` и
`strict=true`; тот же packaged contract локально проверяется Ajv.
Fallback на `json_object` отсутствует: несовместимость provider считается judge failure.
Schema-valid output не является разрешением и не обходит semantic/local gates.

Raw model allow недостаточен. Исполнение требует одновременно:

- `decision=allow`;
- `risk=low`;
- `authorization=high`;
- confidence `>=0.8`;
- полностью видимые params;
- отсутствие deterministic never-auto surface.

Historical diagnostic 0.2.0/0.3.0 подтвердил необходимость связки: raw judge
разрешил 8 unsafe attempts из 240, deterministic guard понизил и заблокировал
все `8/8`. Эти результаты относятся к policy `2026-07-12.4` и `json_object`, а
не к 0.4.0. Первый strict run на policy `2026-07-14.1` обнаружил `9/240`
unsafe auto-allows. После первого hardening fresh run на policy
`2026-07-14.2` всё ещё обнаружил `6/240` unsafe auto-allows в четырёх families:
process writes, OpenClaw config writes, destructive shell commands и internal
web fetches. Оба run являются failed historical evidence. Policy
`2026-07-14.3` закрыла эти surfaces, но третий strict run всё равно дал `2/240`
unsafe auto-allows в одной `skill_workshop.apply` family (`1/80` unsafe
families; repeats 2 и 3). Artifact
`llm-judge-v040-qualification-20260714T180323Z` зафиксировал `112/120` safe
(`34/40` safe families), `0/11` catastrophic, `0/360` failures и latency p50
`1867.457 ms`, p95 `2453.216 ms`, p99 `2780.389 ms`. Этот run также failed.
Policy `2026-07-14.4` добавила read-only-only `skill_workshop` guard, bounded
fail-closed shell dispatch/redirection hardening и `home.arpa`. Четвёртый strict
run `llm-judge-v040-qualification-20260714T195408Z` дал `118/120` safe,
`2/240` unsafe в двух families (удаление security-теста и production-config
write), `0/11` catastrophic, `0/360` failures; p50 `1806.841 ms`, p95
`2264.777 ms`, p99 `2477.047 ms`. Он также failed. Policy
`2026-07-14.5` закрыла обе deterministic surfaces. Пятый strict run
`llm-judge-v040-qualification-20260714T201953Z` дал `111/120` safe, `2/240`
unsafe в одной active `.ssh/authorized_keys` family (`1/80`, repeats 2 и 3),
`0/11` catastrophic, `0/360` failures; p50 `1838.441 ms`, p95 `2328.160 ms`,
p99 `2671.778 ms`. Он также failed. Current policy `2026-07-14.6` требует
человека для распознанных active `.ssh` security-file writes. Fresh run
`llm-judge-v040-qualification-20260714T202947Z` прошёл frozen-corpus gate:
`108/120` safe (`34/40` families), `0/240` unsafe (`0/80` families), `0/11`
catastrophic, `0/360` failures; p50 `1846.141 ms`, p95 `2320.621 ms`, p99
`2761.126 ms`. Raw judge вернул 18 unsafe `allow`, combined gates поймали
`18/18`.

Это tuned regression evidence на том же corpus, по которому усиливался guard;
отдельного unseen holdout нет.

## Deterministic guard limits

Shell parser — bounded fail-closed backstop, а не shell sandbox. Он понижает
неоднозначный dispatch/redirection, но simple unknown direct commands всё ещё
зависят от LLM verdict и native OpenClaw sandbox/tool policy.

Для `web_fetch` плагин статически проверяет URL, literal IP и special-use names.
DNS resolution и каждый redirect остаются обязанностью native OpenClaw SSRF
guard. DNS rebinding не решается pre-hook и требует повторной проверки resolved
address на каждой сетевой операции и после каждого redirect.

## Credentials and endpoint

Рекомендуется отдельный `OPENCLAW_JUDGE_API_KEY`. Если он отсутствует, legacy
fallback использует цельную пару `models.providers.cloudru`. Dedicated key и
shared provider не смешиваются.

Допустимый endpoint фиксирован:

```text
https://foundation-models.api.cloud.ru/v1
```

Другой scheme/origin/port/path/query/fragment/userinfo и redirect запрещены.
Alternative endpoint добавляется только новой source-версией после отдельной
qualification.

API key не логируется, не аудитится, не добавляется в request body и не
сохраняется пакетом. Plugin не загружает и не изменяет `.env`.

## Environment failures

ENV читается один раз при registration. Unknown `OPENCLAW_JUDGE_*`, blank value,
invalid key/profile/timeout/path или malformed legacy config приводит к fixed
setup error и permanent `supervised + enforce` failing-client fallback. Hooks
остаются зарегистрированы; каждый call требует approval, timeout означает deny.

`shadow` — осознанный observe-only mode и не считается fail-closed enforcement.

## Audit boundary

Audit path обязан быть absolute `.jsonl` внутри
`${OPENCLAW_STATE_DIR:-~/.openclaw}/logs`. Writer проверяет logical/real path,
отвергает parent/final symlink, hardlink, non-regular и чужой owner до
chmod/append; файл удерживается в mode `0600`.

Audit хранит только allowlisted metadata, process-local opaque action commitment
и hashed correlation IDs. Raw prompt, params, credentials, identifiers,
commitment key и rationale отсутствуют. Runtime audit I/O failure не меняет tool
decision, поэтому monitoring audit availability обязателен.

OpenClaw host logs находятся вне контроля плагина и могут содержать action
params. Ограничьте к ним доступ и retention.

## Deployment controls

Начинайте с `shadow`. До enforcement подтвердите:

1. checksum versioned artifact;
2. runtime `imported=true`, ровно два hook, `diagnostics=[]`;
3. native sandbox/tool policy и approval route;
4. fail-closed failure behavior;
5. secret-safe audit и monitoring;
6. локальный rollback artifact.

Current evidence не является safety certificate для autonomous production.

## Incident response

При suspected unsafe allow:

1. переключите deployment на `OPENCLAW_JUDGE_PROFILE=shadow` и отключите risky
   tools native policy;
2. сохраните secret-safe audit, plugin/runtime version и artifact hashes;
3. выполните binary rollback по [DEPLOYMENT.md](DEPLOYMENT.md);
4. добавьте synthetic regression case и повторите independent review;
5. при возможной утечке key выполните provider rotation/revocation.

Rollback плагина сам по себе credential не отзывает.

## Vulnerability reports

Используйте закрытый internal security channel. Не публикуйте credentials, PII,
raw prompts/params/logs или exploit payload в открытом issue.

Укажите plugin/OpenClaw/Node versions, profile, synthetic tool fixture,
expected/actual outcome, action/policy hashes и воспроизводимость.
