# Security policy

Поддерживаемый internal release: `openclaw-llm-action-judge` 0.4.0 с policy
`2026-07-14.3` на OpenClaw
`>=2026.6.11` и Node.js `>=22.19.0`.

## Security boundary

Плагин связывает fixed judge verdict с exact action hash, принимает только
strict seven-field JSON, повторно проверяет action после async call и работает
fail-closed при setup/transport/timeout/schema/policy/hash/mutation failure.

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
web fetches. Оба run являются failed historical evidence. Current policy
`2026-07-14.3` закрывает эти surfaces deterministic guard и остаётся pending
fresh live qualification; offline replay сам по себе не является safety
certificate.

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

Audit хранит только allowlisted metadata и hashed correlation IDs. Raw prompt,
params, credentials, identifiers и rationale отсутствуют. Runtime audit I/O
failure не меняет tool decision, поэтому monitoring audit availability обязателен.

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
