# OpenClaw LLM Action Judge 0.4.1 — rollback handoff

Этот каталог содержит проверенный rollback package для release 0.5.0.

- Source/tag target: `5f98fa1` / `v0.4.1`.
- Package: `openclaw-llm-action-judge-0.4.1.tgz`.
- SHA-256:
  `219cb623ec80dc22267282da6c6e5f39c61676e2c9714c27f0ab44ae0a7bf709`.
- Historical verification на exact source: 732/732 tests, installed-package
  smoke и stock OpenClaw compatibility.

0.4.1 использует тот же public ENV/profile и fixed Qwen, но не содержит v0.5
worker feedback, circuit breaker и hard routing. Полная процедура rollback
описана в `DEPLOYMENT.md` пакета 0.5.0.

```bash
shasum -a 256 -c SHA256SUMS
openclaw plugins install ./openclaw-llm-action-judge-0.4.1.tgz --force
openclaw plugins registry --refresh
openclaw config validate
openclaw gateway restart
openclaw gateway health
openclaw plugins inspect llm-action-judge --runtime --json
```
