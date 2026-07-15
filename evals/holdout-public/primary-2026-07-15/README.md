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
- `inference/` будет содержать только blind inference artifact и receipt;
- `score/` будет содержать полный набор из 13 scored files и path-free receipt.

Raw source cases, oracle, private commitment и одноразовый HMAC key в Git не
публикуются.
