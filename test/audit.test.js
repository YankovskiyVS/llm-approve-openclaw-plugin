import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { computeActionHash } from '../src/action.js';
import { MODEL_ID, PLUGIN_ID, POLICY_VERSION } from '../src/constants.js';
import { buildAuditEvent, createAuditWriter } from '../src/audit.js';

const SECRET = 'SUPER_SECRET_VALUE';
const OMITTED_RATIONALE = '[model rationale omitted]';
const GENERIC_FAILURE = 'LLM action judge audit write failed';
const AUDIT_KEYS = [
  'timestamp',
  'plugin_id',
  'model_id',
  'policy_version',
  'tool_name',
  'action_hash',
  'agent_id_hash',
  'session_key_hash',
  'run_id_hash',
  'tool_call_id_hash',
  'decision',
  'risk',
  'authorization',
  'confidence',
  'reason_code',
  'outcome',
  'latency_ms',
  'mode',
  'enforcement',
  'feedback_code',
  'feedback_status',
  'rationale',
];

function makeAction(overrides = {}) {
  return {
    policy_version: POLICY_VERSION,
    tool_name: 'exec\nstatus',
    params: {
      command: 'deploy',
      prompt: `trusted request ${SECRET}`,
      nested: { token: SECRET },
    },
    agent_id: 'raw-agent-id',
    session_key: 'raw-session-key',
    run_id: 'raw-run-id',
    tool_call_id: 'raw-tool-call-id',
    ...overrides,
  };
}

function makeJudgeResult(overrides = {}) {
  const verdict = {
    policy_version: POLICY_VERSION,
    action_hash: `sha256:${'f'.repeat(64)}`,
    decision: 'allow',
    risk: 'low',
    authorization: 'high',
    confidence: 0.91,
    reason_code: 'safe_and_authorized',
    rationale: `model copied ${SECRET} from the trusted request`,
    ...overrides,
  };
  if (!Object.hasOwn(overrides, 'reason_code') && verdict.decision !== 'allow') {
    verdict.reason_code = 'other_policy_risk';
  }
  return {
    ok: true,
    verdict,
  };
}

function expectedIdHash(field, value) {
  const digest = createHash('sha256')
    .update(`llm-action-judge:audit:${field}\0`, 'utf8')
    .update(value, 'utf8')
    .digest('hex');
  return `sha256:${digest}`;
}

function expectedAuditOpenFlags() {
  const required = [
    fsConstants.O_WRONLY,
    fsConstants.O_APPEND,
    fsConstants.O_CREAT,
    fsConstants.O_NOFOLLOW,
  ];
  assert.equal(required.every(Number.isInteger), true, 'test platform lacks O_NOFOLLOW');
  const nonBlocking = Number.isInteger(fsConstants.O_NONBLOCK) ? fsConstants.O_NONBLOCK : 0;
  return required.reduce((flags, flag) => flags | flag, nonBlocking);
}

async function tempAudit(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'llm-action-judge-audit-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return {
    directory,
    filePath: path.join(directory, 'nested', 'audit.jsonl'),
  };
}

function safeAuditEvent() {
  return buildAuditEvent({
    action: makeAction(),
    judgeResult: makeJudgeResult({ rationale: null }),
    normalized: { kind: 'allow' },
    latencyMs: 1,
    mode: 'supervised',
    enforcement: 'enforce',
  });
}

test('writes one secret-safe whitelisted JSONL event to real tempfs with mode 0600', async (t) => {
  const { filePath } = await tempAudit(t);
  const action = makeAction();
  const event = buildAuditEvent({
    action,
    judgeResult: makeJudgeResult(),
    normalized: { kind: 'allow', reason: `normalized ${SECRET}` },
    latencyMs: 17.25,
    mode: 'supervised',
    enforcement: 'enforce',
    prompt: SECRET,
    params: { password: SECRET },
  });
  const writer = createAuditWriter({ filePath });

  assert.equal(await writer.write(event), true);

  const [raw, stats] = await Promise.all([fs.readFile(filePath, 'utf8'), fs.stat(filePath)]);
  assert.equal(raw.endsWith('\n'), true);
  assert.equal(raw.slice(0, -1).includes('\n'), false, 'JSON contained an unescaped newline');
  assert.equal(raw.includes(SECRET), false);
  for (const rawId of [action.agent_id, action.session_key, action.run_id, action.tool_call_id]) {
    assert.equal(raw.includes(rawId), false, `audit exposed ${rawId}`);
  }

  const parsed = JSON.parse(raw);
  assert.deepEqual(Object.keys(parsed), AUDIT_KEYS);
  assert.match(parsed.timestamp, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.equal(new Date(parsed.timestamp).toISOString(), parsed.timestamp);
  assert.equal(parsed.plugin_id, PLUGIN_ID);
  assert.equal(parsed.model_id, MODEL_ID);
  assert.equal(parsed.policy_version, POLICY_VERSION);
  assert.equal(parsed.tool_name, action.tool_name);
  assert.equal(parsed.action_hash, computeActionHash(action));
  assert.notEqual(parsed.action_hash, makeJudgeResult().verdict.action_hash);
  assert.equal(parsed.agent_id_hash, expectedIdHash('agent_id', action.agent_id));
  assert.equal(parsed.session_key_hash, expectedIdHash('session_key', action.session_key));
  assert.equal(parsed.run_id_hash, expectedIdHash('run_id', action.run_id));
  assert.equal(parsed.tool_call_id_hash, expectedIdHash('tool_call_id', action.tool_call_id));
  assert.equal(new Set([
    parsed.agent_id_hash,
    parsed.session_key_hash,
    parsed.run_id_hash,
    parsed.tool_call_id_hash,
  ]).size, 4, 'correlation ID hash domains were not separated');
  assert.equal(parsed.decision, 'allow');
  assert.equal(parsed.risk, 'low');
  assert.equal(parsed.authorization, 'high');
  assert.equal(parsed.confidence, 0.91);
  assert.equal(parsed.reason_code, 'safe_and_authorized');
  assert.equal(parsed.outcome, 'allow');
  assert.equal(parsed.latency_ms, 17.25);
  assert.equal(parsed.mode, 'supervised');
  assert.equal(parsed.enforcement, 'enforce');
  assert.equal(parsed.feedback_code, null);
  assert.equal(parsed.feedback_status, null);
  assert.equal(parsed.rationale, OMITTED_RATIONALE);
  assert.equal(Object.hasOwn(parsed, 'prompt'), false);
  assert.equal(Object.hasOwn(parsed, 'params'), false);
  assert.equal(stats.mode & 0o777, 0o600);
});

test('corrects an existing audit file from 0644 to 0600 before appending', async (t) => {
  const { directory, filePath } = await tempAudit(t);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, '{}\n', { mode: 0o644 });
  await fs.chmod(filePath, 0o644);
  assert.equal((await fs.stat(filePath)).mode & 0o777, 0o644);

  const writer = createAuditWriter({ filePath });
  const result = await writer.write(buildAuditEvent({
    action: makeAction(),
    judgeResult: makeJudgeResult({ rationale: '' }),
    normalized: { kind: 'review' },
    latencyMs: 1,
    mode: 'autonomous',
    enforcement: 'shadow',
  }));

  assert.equal(result, true);
  assert.equal((await fs.stat(filePath)).mode & 0o777, 0o600);
  assert.equal((await fs.readFile(filePath, 'utf8')).trimEnd().split('\n').length, 2);
  assert.equal(directory.includes('.openclaw'), false, 'test unexpectedly used the default path');
});

test('rejects a final-path symlink without changing its regular-file target', async (t) => {
  const { directory } = await tempAudit(t);
  const auditDirectory = path.join(directory, 'logs');
  const filePath = path.join(auditDirectory, 'audit.jsonl');
  const targetPath = path.join(directory, 'protected-target.txt');
  const targetContent = 'protected target content\n';
  const messages = [];
  await fs.mkdir(auditDirectory, { recursive: true });
  await fs.writeFile(targetPath, targetContent, { mode: 0o644 });
  await fs.chmod(targetPath, 0o644);
  await fs.symlink(targetPath, filePath);
  const before = await fs.stat(targetPath);
  assert.equal(before.isFile(), true);
  assert.equal((await fs.lstat(filePath)).isSymbolicLink(), true);

  const writer = createAuditWriter({
    filePath,
    logger(message) {
      messages.push(message);
    },
  });
  const result = await writer.write(buildAuditEvent({
    action: makeAction(),
    judgeResult: makeJudgeResult({ rationale: null }),
    normalized: { kind: 'allow' },
    latencyMs: 1,
    mode: 'supervised',
    enforcement: 'shadow',
  }));

  const after = await fs.stat(targetPath);
  assert.equal(result, false);
  assert.deepEqual(messages, [GENERIC_FAILURE]);
  assert.equal((await fs.lstat(filePath)).isSymbolicLink(), true);
  assert.equal(await fs.readFile(targetPath, 'utf8'), targetContent);
  assert.equal(after.mode & 0o777, before.mode & 0o777);
});

test('confines a configured audit file to its absolute root', async (t) => {
  const { directory } = await tempAudit(t);
  const rootPath = path.join(directory, 'state', 'logs');
  const filePath = path.join(rootPath, 'nested', 'judge.jsonl');
  const writer = createAuditWriter({ rootPath, filePath });

  assert.equal(await writer.write(safeAuditEvent()), true);
  assert.equal((await fs.stat(filePath)).mode & 0o777, 0o600);
  assert.throws(
    () => createAuditWriter({
      rootPath,
      filePath: path.join(directory, 'outside.jsonl'),
    }),
    (error) => error instanceof TypeError && error.message === 'invalid audit writer options',
  );
});

test('rejects a symlinked parent without writing outside the audit root', async (t) => {
  const { directory } = await tempAudit(t);
  const rootPath = path.join(directory, 'state', 'logs');
  const outsidePath = path.join(directory, 'outside');
  const symlinkPath = path.join(rootPath, 'team');
  const escapedDirectory = path.join(outsidePath, 'new', 'deep');
  const filePath = path.join(symlinkPath, 'new', 'deep', 'judge.jsonl');
  const messages = [];
  await fs.mkdir(rootPath, { recursive: true });
  await fs.mkdir(outsidePath);
  await fs.symlink(outsidePath, symlinkPath);

  const writer = createAuditWriter({
    rootPath,
    filePath,
    logger(message) { messages.push(message); },
  });

  assert.equal(await writer.write(safeAuditEvent()), false);
  assert.deepEqual(messages, [GENERIC_FAILURE]);
  await assert.rejects(fs.stat(escapedDirectory), { code: 'ENOENT' });
  assert.equal((await fs.lstat(symlinkPath)).isSymbolicLink(), true);
});

test('rejects a hardlinked audit file before chmod or append', async (t) => {
  const { directory } = await tempAudit(t);
  const rootPath = path.join(directory, 'state', 'logs');
  const protectedPath = path.join(directory, 'protected.txt');
  const filePath = path.join(rootPath, 'judge.jsonl');
  const original = 'protected hardlink content\n';
  const messages = [];
  await fs.mkdir(rootPath, { recursive: true });
  await fs.writeFile(protectedPath, original, { mode: 0o644 });
  await fs.chmod(protectedPath, 0o644);
  await fs.link(protectedPath, filePath);
  const before = await fs.stat(protectedPath);
  assert.equal(before.nlink, 2);

  const writer = createAuditWriter({
    rootPath,
    filePath,
    logger(message) { messages.push(message); },
  });

  assert.equal(await writer.write(safeAuditEvent()), false);
  assert.deepEqual(messages, [GENERIC_FAILURE]);
  assert.equal(await fs.readFile(protectedPath, 'utf8'), original);
  assert.equal((await fs.stat(protectedPath)).mode & 0o777, before.mode & 0o777);
});

test('buildAuditEvent validates every variable field and emits a bounded failure event', () => {
  const action = makeAction({
    agent_id: null,
    session_key: 42,
    run_id: '',
    tool_call_id: false,
  });
  const event = buildAuditEvent({
    action,
    judgeResult: {
      decision: 'ALLOW',
      risk: 'catastrophic',
      authorization: true,
      confidence: Number.NaN,
      reason_code: SECRET,
      rationale: null,
    },
    normalized: { kind: 'unexpected', reason: SECRET },
    latencyMs: -1,
    mode: 'yolo',
    enforcement: 'silent',
  });

  assert.deepEqual(Object.keys(event), AUDIT_KEYS);
  assert.equal(event.plugin_id, PLUGIN_ID);
  assert.equal(event.model_id, MODEL_ID);
  assert.equal(event.policy_version, POLICY_VERSION);
  assert.equal(event.action_hash, computeActionHash(action));
  assert.equal(event.agent_id_hash, null);
  assert.equal(event.session_key_hash, null);
  assert.equal(event.run_id_hash, null);
  assert.equal(event.tool_call_id_hash, null);
  assert.equal(event.decision, null);
  assert.equal(event.risk, null);
  assert.equal(event.authorization, null);
  assert.equal(event.confidence, null);
  assert.equal(event.reason_code, null);
  assert.equal(event.outcome, 'failure');
  assert.equal(event.latency_ms, null);
  assert.equal(event.mode, null);
  assert.equal(event.enforcement, null);
  assert.equal(event.feedback_code, null);
  assert.equal(event.feedback_status, null);
  assert.equal(event.rationale, null);
  assert.equal(JSON.stringify(event).includes(SECRET), false);
});

test('audit whitelists only a valid reason_code and never leaks model-controlled sentinels', () => {
  const valid = buildAuditEvent({
    action: makeAction(),
    judgeResult: makeJudgeResult({ reason_code: 'authorization_missing' }),
    normalized: { kind: 'review' },
    latencyMs: 1,
    mode: 'supervised',
    enforcement: 'enforce',
  });
  assert.equal(valid.reason_code, 'authorization_missing');

  const invalid = buildAuditEvent({
    action: makeAction(),
    judgeResult: makeJudgeResult({ reason_code: SECRET, rationale: SECRET }),
    normalized: { kind: 'failure', reason: SECRET },
    latencyMs: 1,
    mode: 'autonomous',
    enforcement: 'enforce',
    prompt: SECRET,
    params: { token: SECRET },
  });
  assert.equal(invalid.reason_code, null);
  assert.equal(JSON.stringify(invalid).includes(SECRET), false);
});

test('audit records only closed feedback code and status metadata for enforced outcomes', () => {
  const cases = [
    [{
      judgeResult: makeJudgeResult({
        decision: 'deny',
        risk: 'high',
        authorization: 'low',
        reason_code: 'out_of_scope',
      }),
      normalized: {
        kind: 'deny',
        verdict: makeJudgeResult({
          decision: 'deny',
          risk: 'high',
          authorization: 'low',
          reason_code: 'out_of_scope',
        }).verdict,
      },
      mode: 'autonomous',
      enforcement: 'enforce',
    }, 'out_of_scope', 'blocked'],
    [{
      judgeResult: makeJudgeResult({
        decision: 'review',
        risk: 'medium',
        authorization: 'medium',
        reason_code: 'authorization_missing',
      }),
      normalized: {
        kind: 'review',
        verdict: makeJudgeResult({
          decision: 'review',
          risk: 'medium',
          authorization: 'medium',
          reason_code: 'authorization_missing',
        }).verdict,
      },
      mode: 'supervised',
      enforcement: 'enforce',
    }, 'authorization_missing', 'approval_required'],
    [{
      judgeResult: undefined,
      normalized: { kind: 'failure', feedback_code: 'judge_unavailable', reason: SECRET },
      mode: 'autonomous',
      enforcement: 'enforce',
    }, 'judge_unavailable', 'blocked'],
    [{
      judgeResult: makeJudgeResult(),
      normalized: {
        kind: 'review',
        local_guard: true,
        verdict: makeJudgeResult().verdict,
      },
      mode: 'supervised',
      enforcement: 'enforce',
    }, 'local_policy_review', 'approval_required'],
  ];

  for (const [input, feedbackCode, feedbackStatus] of cases) {
    const event = buildAuditEvent({
      action: makeAction(),
      latencyMs: 1,
      ...input,
      feedback: SECRET,
      blockReason: SECRET,
      approvalDescription: SECRET,
    });
    assert.equal(event.feedback_code, feedbackCode);
    assert.equal(event.feedback_status, feedbackStatus);
    assert.equal(JSON.stringify(event).includes(SECRET), false);
  }
});

test('audit keeps feedback metadata null for allow and shadow outcomes', () => {
  for (const input of [
    {
      judgeResult: makeJudgeResult(),
      normalized: { kind: 'allow', verdict: makeJudgeResult().verdict },
      mode: 'autonomous',
      enforcement: 'enforce',
    },
    {
      judgeResult: makeJudgeResult({
        decision: 'deny',
        reason_code: 'out_of_scope',
      }),
      normalized: {
        kind: 'deny',
        verdict: makeJudgeResult({
          decision: 'deny',
          reason_code: 'out_of_scope',
        }).verdict,
      },
      mode: 'autonomous',
      enforcement: 'shadow',
    },
  ]) {
    const event = buildAuditEvent({ action: makeAction(), latencyMs: 1, ...input });
    assert.equal(event.feedback_code, null);
    assert.equal(event.feedback_status, null);
  }
});

test('buildAuditEvent never evaluates hostile getters or leaks build failures', () => {
  const hostileAction = makeAction();
  Object.defineProperty(hostileAction, 'params', {
    enumerable: true,
    get() {
      throw new Error(`hostile getter ${SECRET}`);
    },
  });
  const hostileInput = {};
  Object.defineProperty(hostileInput, 'judgeResult', {
    enumerable: true,
    get() {
      throw new Error(`top-level getter ${SECRET}`);
    },
  });

  const fromAction = buildAuditEvent({ action: hostileAction });
  const fromInput = buildAuditEvent(hostileInput);

  for (const event of [fromAction, fromInput]) {
    assert.deepEqual(Object.keys(event), AUDIT_KEYS);
    assert.equal(event.action_hash, null);
    assert.equal(event.outcome, 'failure');
    assert.equal(JSON.stringify(event).includes(SECRET), false);
    assert.ok(JSON.stringify(event).length < 1_500, 'safe fallback event was not bounded');
  }
});

test('writer re-applies the whitelist to malicious caller-supplied audit fields', async (t) => {
  const { filePath } = await tempAudit(t);
  const event = buildAuditEvent({
    action: makeAction(),
    judgeResult: makeJudgeResult(),
    normalized: { kind: 'deny' },
    latencyMs: 2,
    mode: 'autonomous',
    enforcement: 'enforce',
  });
  Object.assign(event, {
    prompt: SECRET,
    userPrompt: SECRET,
    params: { secret: SECRET },
    agent_id: `raw-agent-${SECRET}`,
    session_key: `raw-session-${SECRET}`,
    run_id: `raw-run-${SECRET}`,
    tool_call_id: `raw-call-${SECRET}`,
    provider_key: SECRET,
    raw_response: SECRET,
    exception: new Error(SECRET),
    hidden_reasoning: SECRET,
    reason: SECRET,
    unknown: SECRET,
    rationale: `caller replaced rationale with ${SECRET}`,
    feedback_code: SECRET,
    feedback_status: SECRET,
  });

  assert.equal(await createAuditWriter({ filePath }).write(event), true);

  const raw = await fs.readFile(filePath, 'utf8');
  const parsed = JSON.parse(raw);
  assert.deepEqual(Object.keys(parsed), AUDIT_KEYS);
  assert.equal(raw.includes(SECRET), false);
  assert.equal(parsed.rationale, OMITTED_RATIONALE);
  assert.equal(parsed.feedback_code, null);
  assert.equal(parsed.feedback_status, null);
  for (const key of [
    'prompt',
    'userPrompt',
    'params',
    'agent_id',
    'session_key',
    'run_id',
    'tool_call_id',
    'provider_key',
    'raw_response',
    'exception',
    'hidden_reasoning',
    'reason',
    'unknown',
  ]) {
    assert.equal(Object.hasOwn(parsed, key), false, `writer accepted forbidden key ${key}`);
  }
});

test('concurrent writes use independent handles and preserve one JSON object per line', async (t) => {
  const { filePath } = await tempAudit(t);
  const writer = createAuditWriter({ filePath });
  const writes = Array.from({ length: 16 }, (_, index) => writer.write(buildAuditEvent({
    action: makeAction({ run_id: `run-${index}` }),
    judgeResult: makeJudgeResult({ rationale: null }),
    normalized: { kind: index % 2 === 0 ? 'allow' : 'review' },
    latencyMs: index,
    mode: 'supervised',
    enforcement: 'shadow',
  })));

  assert.deepEqual(await Promise.all(writes), Array(16).fill(true));

  const raw = await fs.readFile(filePath, 'utf8');
  assert.equal(raw.endsWith('\n'), true);
  const lines = raw.trimEnd().split('\n');
  assert.equal(lines.length, 16);
  assert.deepEqual(
    lines.map((line) => JSON.parse(line).latency_ms).sort((a, b) => a - b),
    Array.from({ length: 16 }, (_, index) => index),
  );
});

test('writer never throws, closes opened handles, and logs one fixed message per fs failure', async (t) => {
  const safeEvent = buildAuditEvent({
    action: makeAction(),
    judgeResult: makeJudgeResult({ rationale: null }),
    normalized: { kind: 'allow' },
    latencyMs: 1,
    mode: 'supervised',
    enforcement: 'shadow',
  });
  const stages = ['mkdir', 'open', 'stat', 'chmod', 'append', 'close'];

  for (const stage of stages) {
    await t.test(stage, async () => {
      const calls = [];
      const messages = [];
      const fail = (name) => {
        calls.push(name);
        if (stage === name) throw new Error(`${name} failed with ${SECRET}`);
      };
      const handle = {
        async stat() {
          fail('stat');
          return { isFile: () => true };
        },
        async chmod(mode) {
          assert.equal(mode, 0o600);
          fail('chmod');
        },
        async appendFile(line, options) {
          assert.equal(typeof line, 'string');
          assert.equal(line.endsWith('\n'), true);
          assert.deepEqual(options, { encoding: 'utf8' });
          fail('append');
        },
        async close() {
          fail('close');
        },
      };
      const fsImpl = {
        async mkdir(_directory, options) {
          assert.deepEqual(options, { recursive: true, mode: 0o700 });
          fail('mkdir');
        },
        async open(_filePath, flags, mode) {
          assert.equal(flags, expectedAuditOpenFlags());
          assert.equal(mode, 0o600);
          fail('open');
          return handle;
        },
      };
      const writer = createAuditWriter({
        filePath: '/tmp/audit-test-never-created/audit.jsonl',
        fsImpl,
        logger(message) {
          messages.push(message);
        },
      });
      let result;

      await assert.doesNotReject(async () => {
        result = await writer.write(safeEvent);
      });

      assert.equal(result, false);
      assert.deepEqual(messages, [GENERIC_FAILURE]);
      assert.equal(JSON.stringify(messages).includes(SECRET), false);
      const opened = !['mkdir', 'open'].includes(stage);
      assert.equal(calls.filter((call) => call === 'close').length, opened ? 1 : 0);
      if (stage === 'stat') assert.equal(calls.includes('chmod'), false);
      if (stage === 'chmod') assert.equal(calls.includes('append'), false);
      if (stage === 'append') assert.equal(calls.includes('close'), true);
    });
  }
});

test('writer rejects missing or hostile regular-file checks before chmod or append', async (t) => {
  const safeEvent = buildAuditEvent({
    action: makeAction(),
    judgeResult: makeJudgeResult({ rationale: null }),
    normalized: { kind: 'allow' },
    latencyMs: 1,
    mode: 'supervised',
    enforcement: 'shadow',
  });
  const variants = [
    {
      name: 'missing handle.stat',
      install() {},
    },
    {
      name: 'hostile handle.stat getter',
      install(handle, getterCalls) {
        Object.defineProperty(handle, 'stat', {
          get() {
            getterCalls.push('stat');
            throw new Error(`hostile stat getter ${SECRET}`);
          },
        });
      },
    },
    {
      name: 'missing stats.isFile',
      install(handle) {
        handle.stat = async () => ({});
      },
    },
    {
      name: 'hostile stats.isFile getter',
      install(handle, getterCalls) {
        handle.stat = async () => {
          const stats = {};
          Object.defineProperty(stats, 'isFile', {
            get() {
              getterCalls.push('isFile');
              throw new Error(`hostile isFile getter ${SECRET}`);
            },
          });
          return stats;
        };
      },
    },
    {
      name: 'non-regular file',
      install(handle) {
        handle.stat = async () => ({ isFile: () => false });
      },
    },
  ];

  for (const variant of variants) {
    await t.test(variant.name, async () => {
      const getterCalls = [];
      const mutations = [];
      const messages = [];
      let closeCalls = 0;
      const handle = {
        async chmod() {
          mutations.push('chmod');
        },
        async appendFile() {
          mutations.push('append');
        },
        async close() {
          closeCalls += 1;
        },
      };
      variant.install(handle, getterCalls);
      const writer = createAuditWriter({
        filePath: '/tmp/audit-test-never-created/audit.jsonl',
        fsImpl: {
          async mkdir() {},
          async open(_filePath, flags, mode) {
            assert.equal(flags, expectedAuditOpenFlags());
            assert.equal(mode, 0o600);
            return handle;
          },
        },
        logger(message) {
          messages.push(message);
        },
      });

      assert.equal(await writer.write(safeEvent), false);
      assert.deepEqual(messages, [GENERIC_FAILURE]);
      assert.equal(closeCalls, 1);
      assert.deepEqual(mutations, []);
      assert.deepEqual(getterCalls, []);
    });
  }
});

test('writer rejects hostile serialization input safely and ignores a throwing logger', async () => {
  const calls = [];
  const event = {};
  Object.defineProperty(event, 'tool_name', {
    enumerable: true,
    get() {
      throw new Error(`serialize ${SECRET}`);
    },
  });
  Object.defineProperty(event, 'prompt', {
    enumerable: true,
    get() {
      throw new Error(`forbidden ${SECRET}`);
    },
  });
  const writer = createAuditWriter({
    filePath: '/tmp/audit-test-never-created/audit.jsonl',
    fsImpl: {
      async mkdir() {
        calls.push('mkdir');
      },
      async open() {
        calls.push('open');
        throw new Error(SECRET);
      },
    },
    async logger() {
      throw new Error(`logger ${SECRET}`);
    },
  });

  let result;
  await assert.doesNotReject(async () => {
    result = await writer.write(event);
  });
  assert.equal(result, false);
  assert.deepEqual(calls, [], 'writer touched the filesystem after serialization failed');
});

test('createAuditWriter validates explicit dependencies with generic secret-free errors', () => {
  const cases = [
    { filePath: '' },
    { filePath: `bad\0${SECRET}` },
    { filePath: { value: SECRET } },
    { fsImpl: {} },
    { logger: { value: SECRET } },
  ];

  for (const options of cases) {
    assert.throws(
      () => createAuditWriter(options),
      (error) => error instanceof TypeError
        && error.message === 'invalid audit writer options'
        && !error.message.includes(SECRET),
    );
  }
});
