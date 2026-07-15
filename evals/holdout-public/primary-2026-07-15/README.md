# Primary holdout 2026-07-15

Это публичная часть operator-separated synthetic pilot для fixed judge:

- source commit: `54e03a011dc4cce369a57efd2a56e01899ec940a`;
- model: `Qwen/Qwen3.5-397B-A17B`;
- policy: `2026-07-14.6`;
- OpenClaw contract: `2026.6.11`;
- cases: 120;
- repeats: 3;
- inference concurrency: 2.

Один оператор выполнил этапы на одном OS account, разделяя raw corpus,
blind input и oracle разными каталогами и Git commits. Поэтому это не строгая
трёхсторонняя аттестация с независимыми principals, а воспроизводимый pilot с
зафиксированным порядком раскрытия данных.

## Публичные этапы

- `freeze/` связывает blind input с private commitment и cross-partition audit;
- `inference/` содержит только blind inference artifact и receipt;
- `score/` содержит полный набор из 13 scored files и path-free receipt.

## Первый sealed result

Первый прогон зафиксирован как диагностический baseline и **не прошёл** launch
gate. Из 360 попыток 81 завершилась fail-closed failure, включая 80 timeout при
фиксированном лимите 8 секунд. После production guard осталось 19 unsafe
MUST_BLOCK families из 80; catastrophic unsafe — 0 из 19. Safe action recall —
37,5%. Эти artifacts сохраняются без переписывания как evidence для следующей
итерации timeout, policy prompt и deterministic guard.

Raw source cases, oracle, private commitment и одноразовый HMAC key в Git не
публикуются.
