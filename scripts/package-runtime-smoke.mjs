import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [packageRoot, stateDir] = process.argv.slice(2);
if (!packageRoot || !stateDir) {
  process.stderr.write('usage: node scripts/package-runtime-smoke.mjs <package-root> <state-dir>\n');
  process.exitCode = 1;
} else {
  const { createActionJudgePlugin } = await import(
    pathToFileURL(path.resolve(packageRoot, 'index.js')).href
  );
  const auditPath = path.join(stateDir, 'logs', 'integration.jsonl');
  const fixtureKey = 'runtime-smoke-key-v030';
  const rawPrompt = 'runtime smoke trusted prompt';

  function makeHarness({ profile, client, extraEnvironment = {} }) {
    const registrations = [];
    const plugin = createActionJudgePlugin({
      client,
      environment: {
        OPENCLAW_STATE_DIR: stateDir,
        OPENCLAW_JUDGE_API_KEY: fixtureKey,
        OPENCLAW_JUDGE_PROFILE: profile,
        OPENCLAW_JUDGE_AUDIT_PATH: auditPath,
        OPENCLAW_JUDGE_LOG_LEVEL: 'silent',
        ...extraEnvironment,
      },
    });
    plugin.register({
      pluginConfig: {},
      config: { models: { providers: {} } },
      logger: {},
      on(name, handler, options) { registrations.push({ name, handler, options }); },
    });
    return {
      registrations,
      capture: registrations.find(({ name }) => name === 'before_model_resolve').handler,
      gate: registrations.find(({ name }) => name === 'before_tool_call').handler,
    };
  }

  function allowingClient() {
    return {
      calls: 0,
      async review(input) {
        this.calls += 1;
        return {
          ok: true,
          latencyMs: 1,
          text: JSON.stringify({
            policy_version: '2026-07-12.4',
            action_hash: input.envelope.action_hash,
            decision: 'allow',
            risk: 'low',
            authorization: 'high',
            confidence: 0.99,
            rationale: 'Exact synthetic action is authorized for runtime smoke.',
          }),
        };
      },
    };
  }

  async function invoke(harness, { runId, toolName, params }) {
    const toolCallId = `${runId}-call`;
    harness.capture({ prompt: rawPrompt }, { runId });
    return harness.gate(
      { runId, toolCallId, toolName, params },
      { runId, toolCallId, toolName, agentId: 'smoke-agent', sessionKey: 'smoke-session' },
    );
  }

  const safeClient = allowingClient();
  const safeHarness = makeHarness({ profile: 'autonomous', client: safeClient });
  const safeParams = { path: '/workspace/status.txt' };
  const safe = await invoke(safeHarness, {
    runId: 'safe-run',
    toolName: 'read',
    params: safeParams,
  });
  assert.deepEqual(safe, { params: safeParams });

  const guardClient = allowingClient();
  const guardHarness = makeHarness({ profile: 'autonomous', client: guardClient });
  const guarded = await invoke(guardHarness, {
    runId: 'guard-run',
    toolName: 'write',
    params: { path: '.github/workflows/deploy.yml', content: 'name: unsafe-smoke' },
  });
  assert.equal(guarded.block, true);

  const failureHarness = makeHarness({
    profile: 'supervised',
    client: { async review() { return { ok: false, reason: 'request failed', latencyMs: 1 }; } },
  });
  const approval = await invoke(failureHarness, {
    runId: 'approval-run',
    toolName: 'read',
    params: { path: '/workspace/status.txt' },
  });
  assert.equal(approval.requireApproval.timeoutBehavior, 'deny');
  assert.equal(approval.requireApproval.timeoutMs, 60_000);

  const ignoredClient = allowingClient();
  const invalidHarness = makeHarness({
    profile: 'shadow',
    client: ignoredClient,
    extraEnvironment: { OPENCLAW_JUDGE_MODEL: 'forbidden-override' },
  });
  const invalid = await invoke(invalidHarness, {
    runId: 'invalid-run',
    toolName: 'read',
    params: { path: '/workspace/status.txt' },
  });
  assert.equal(ignoredClient.calls, 0);
  assert.equal(invalid.requireApproval.timeoutBehavior, 'deny');

  for (const harness of [safeHarness, guardHarness, failureHarness, invalidHarness]) {
    assert.deepEqual(
      harness.registrations.map(({ name, options }) => ({ name, options })),
      [
        { name: 'before_model_resolve', options: { priority: -1000 } },
        { name: 'before_tool_call', options: { priority: -1000 } },
      ],
    );
  }

  const [audit, stats] = await Promise.all([
    fs.readFile(auditPath, 'utf8'),
    fs.stat(auditPath),
  ]);
  const lines = audit.trimEnd().split('\n').map((line) => JSON.parse(line));
  assert.equal(lines.length, 3);
  assert.equal(stats.mode & 0o777, 0o600);
  assert.equal(audit.includes(fixtureKey), false);
  assert.equal(audit.includes(rawPrompt), false);
  assert.equal(audit.includes('.github/workflows/deploy.yml'), false);

  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    packageVersion: '0.3.0',
    hooks: ['before_model_resolve', 'before_tool_call'],
    safeAllow: true,
    deterministicGuardBlock: true,
    supervisedFailureApproval: true,
    invalidEnvironmentApproval: true,
    invalidEnvironmentClientCalls: ignoredClient.calls,
    auditEvents: lines.length,
    auditMode: '0600',
    auditSecretFree: true,
  }, null, 2)}\n`);
}
