import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const EXPECTED_FILES_FIELD = [
  '.env.example',
  'index.js',
  'openclaw.plugin.json',
  'schemas/',
  'src/',
  'README.md',
  'CONTRACT.md',
  'DEPLOYMENT.md',
  'RND.md',
  'HOLDOUT.md',
  'CHANGELOG.md',
  'SECURITY.md',
  'LICENSE',
];
const EXPECTED_PACKAGE_FILES = [
  '.env.example',
  'CHANGELOG.md',
  'CONTRACT.md',
  'DEPLOYMENT.md',
  'HOLDOUT.md',
  'LICENSE',
  'README.md',
  'RND.md',
  'SECURITY.md',
  'index.js',
  'openclaw.plugin.json',
  'package.json',
  'schemas/judge-verdict.schema.json',
  'src/action.js',
  'src/audit.js',
  'src/config.js',
  'src/constants.js',
  'src/context-store.js',
  'src/decision.js',
  'src/environment.js',
  'src/feedback.js',
  'src/intrinsics.js',
  'src/judge-client.js',
  'src/judge-schema.js',
  'src/plugin.js',
  'src/policy-routing.js',
  'src/prompt.js',
  'src/redact.js',
  'src/run-decision-store.js',
].sort();
const FORBIDDEN_CONTENT = [
  /\/Users\/[^/\s]+\//u,
  /\/home\/[^/\s]+\//u,
  /[A-Za-z]:\\Users\\[^\\\s]+\\/u,
  /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\b(?:sk|rk)_(?:live|prod)_[A-Za-z0-9_-]{12,}\b/u,
  /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/u,
];

async function tempDirectory(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'judge-release-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

async function npmPackDryRun() {
  const { stdout } = await execFileAsync(
    NPM,
    ['pack', '--json', '--dry-run', '--ignore-scripts'],
    { cwd: PACKAGE_ROOT, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
  );
  const result = JSON.parse(stdout);
  assert.equal(result.length, 1);
  return result[0];
}

async function tarEntries(tarballPath) {
  const { stdout } = await execFileAsync(
    'tar',
    ['-tzf', tarballPath],
    { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
  );
  return stdout.trim().split('\n').filter(Boolean);
}

test('package metadata pins the internal 0.5.0 release contract and lean runtime dependencies', async () => {
  const metadata = JSON.parse(await fs.readFile(path.join(PACKAGE_ROOT, 'package.json'), 'utf8'));

  assert.equal(metadata.version, '0.5.0');
  assert.equal(metadata.private, true);
  assert.equal(metadata.license, 'UNLICENSED');
  assert.deepEqual(metadata.repository, {
    type: 'git',
    url: 'git+https://git.sbercloud.tech/ai_transformation/poc-and-eda/llm-approve-openclaw-plugin.git',
  });
  assert.deepEqual(metadata.engines, { node: '>=22.19.0' });
  assert.deepEqual(metadata.dependencies, { ajv: '8.20.0' });
  assert.deepEqual(metadata.peerDependencies, { openclaw: '>=2026.6.11' });
  assert.deepEqual(metadata.peerDependenciesMeta, { openclaw: { optional: true } });
  assert.deepEqual(metadata.openclaw, {
    extensions: ['./index.js'],
    install: { minHostVersion: '>=2026.6.11' },
    compat: { pluginApi: '>=2026.6.11' },
  });
  assert.deepEqual(metadata.files, EXPECTED_FILES_FIELD);
  assert.equal(metadata.scripts.test, 'node --test');
  assert.equal(metadata.scripts['eval:smoke'], 'node evals/dev-smoke.mjs');
  assert.equal(Object.hasOwn(metadata.scripts, 'build:release'), false);
  assert.equal(Object.values(metadata.scripts).some((value) => value.includes('scripts/build-release.mjs')), false);
});

test('npm pack dry-run has the exact reviewed release file set', async () => {
  const packed = await npmPackDryRun();

  assert.equal(packed.filename, 'openclaw-llm-action-judge-0.5.0.tgz');
  assert.deepEqual(packed.files.map((entry) => entry.path).sort(), EXPECTED_PACKAGE_FILES);
  assert.equal(packed.files.some((entry) => /(?:^|\/)(?:evals?|tests?|reviews?)(?:\/|$)/u.test(entry.path)), false);
  assert.equal(packed.files.some((entry) => path.isAbsolute(entry.path) || entry.path.split('/').includes('..')), false);
});

test('release builder publishes one versioned tarball and matching sha256 into a fresh directory', async (t) => {
  const { buildRelease } = await import('../scripts/build-release.mjs');
  const temporary = await tempDirectory(t);
  const outputDir = path.join(temporary, 'release');

  const result = await buildRelease({ packageRoot: PACKAGE_ROOT, outputDir });
  const tarballName = 'openclaw-llm-action-judge-0.5.0.tgz';
  const checksumName = `${tarballName}.sha256`;
  const tarballPath = path.join(outputDir, tarballName);
  const checksumPath = path.join(outputDir, checksumName);

  assert.deepEqual((await fs.readdir(outputDir)).sort(), [checksumName, tarballName].sort());
  assert.deepEqual(result, {
    outputDir,
    tarballPath,
    checksumPath,
    sha256: result.sha256,
    files: EXPECTED_PACKAGE_FILES,
  });
  assert.match(result.sha256, /^[0-9a-f]{64}$/u);

  const tarball = await fs.readFile(tarballPath);
  const digest = createHash('sha256').update(tarball).digest('hex');
  assert.equal(result.sha256, digest);
  assert.equal(await fs.readFile(checksumPath, 'utf8'), `${digest}  ${tarballName}\n`);

  const entries = await tarEntries(tarballPath);
  assert.deepEqual(entries.sort(), EXPECTED_PACKAGE_FILES.map((file) => `package/${file}`).sort());
  assert.equal(entries.some((entry) => path.posix.isAbsolute(entry) || entry.split('/').includes('..')), false);

  const extracted = path.join(temporary, 'extracted');
  await fs.mkdir(extracted);
  await execFileAsync('tar', ['-xzf', tarballPath, '-C', extracted]);
  const runtimeMetadata = JSON.parse(
    await fs.readFile(path.join(extracted, 'package', 'package.json'), 'utf8'),
  );
  assert.equal(Object.hasOwn(runtimeMetadata, 'scripts'), false);
  assert.equal(runtimeMetadata.version, '0.5.0');
  assert.deepEqual(runtimeMetadata.dependencies, { ajv: '8.20.0' });
  assert.deepEqual(runtimeMetadata.peerDependenciesMeta, { openclaw: { optional: true } });
  assert.deepEqual(runtimeMetadata.openclaw, {
    extensions: ['./index.js'],
    install: { minHostVersion: '>=2026.6.11' },
    compat: { pluginApi: '>=2026.6.11' },
  });
  const [sourceSchema, packagedSchema] = await Promise.all([
    fs.readFile(path.join(PACKAGE_ROOT, 'schemas', 'judge-verdict.schema.json'), 'utf8'),
    fs.readFile(
      path.join(extracted, 'package', 'schemas', 'judge-verdict.schema.json'),
      'utf8',
    ),
  ]);
  assert.equal(packagedSchema, sourceSchema);
  const parsedSchema = JSON.parse(packagedSchema);
  assert.equal(parsedSchema.properties.policy_version.const, '2026-07-16.1');
  assert.equal(parsedSchema.required.length, 8);
  assert.deepEqual(parsedSchema.properties.reason_code.enum, [
    'safe_and_authorized',
    'authorization_missing',
    'out_of_scope',
    'destructive_or_irreversible',
    'sensitive_data',
    'external_side_effect',
    'privilege_or_security_boundary',
    'untrusted_instruction',
    'self_modification',
    'opaque_or_unverifiable',
    'other_policy_risk',
  ]);
  assert.equal(parsedSchema.additionalProperties, false);
  for (const file of EXPECTED_PACKAGE_FILES) {
    const content = await fs.readFile(path.join(extracted, 'package', file), 'utf8');
    for (const pattern of FORBIDDEN_CONTENT) {
      assert.doesNotMatch(content, pattern, `${file} contains sensitive release content`);
    }
  }
});

test('environment example exposes only the approved deployment contract', async () => {
  const content = await fs.readFile(path.join(PACKAGE_ROOT, '.env.example'), 'utf8');
  const expectedNames = [
    'OPENCLAW_JUDGE_API_KEY',
    'OPENCLAW_JUDGE_PROFILE',
    'OPENCLAW_JUDGE_BASE_URL',
    'OPENCLAW_JUDGE_TIMEOUT_MS',
    'OPENCLAW_JUDGE_AUDIT_PATH',
    'OPENCLAW_JUDGE_LOG_LEVEL',
  ];
  for (const name of expectedNames) {
    assert.match(content, new RegExp(`^(?:# )?${name}=`, 'mu'));
  }
  assert.match(content, /plugin does not load this file/u);
  assert.match(content, /^OPENCLAW_JUDGE_API_KEY=$/mu);
  assert.match(content, /^# OPENCLAW_JUDGE_AUDIT_PATH=\/absolute\//mu);
  assert.doesNotMatch(content, /OPENCLAW_JUDGE_(?:MODEL|POLICY|PROMPT|MIN_CONFIDENCE)=/u);
});

test('manifest keeps model and policy immutable outside public config', async () => {
  const manifest = JSON.parse(
    await fs.readFile(path.join(PACKAGE_ROOT, 'openclaw.plugin.json'), 'utf8'),
  );
  assert.deepEqual(Object.keys(manifest.configSchema.properties).sort(), ['enforcement', 'mode']);
  assert.equal(JSON.stringify(manifest).includes('Qwen/Qwen3.5-397B-A17B'), false);
  assert.equal(JSON.stringify(manifest).includes('2026-07-16.1'), false);
});

test('runtime smoke pins v0.5 and fails closed for schema-invalid judge output', async (t) => {
  const stateDir = await tempDirectory(t);
  const { buildRelease } = await import('../scripts/build-release.mjs');
  const release = await buildRelease({
    packageRoot: PACKAGE_ROOT,
    outputDir: path.join(stateDir, 'release'),
  });
  const consumerDir = path.join(stateDir, 'consumer');
  const npmCache = path.join(stateDir, 'npm-cache');
  await fs.mkdir(consumerDir);
  await fs.mkdir(npmCache);
  const expectedRuntimeDependencies = {
    ajv: '8.20.0',
    'fast-deep-equal': '3.1.3',
    'fast-uri': '3.1.3',
    'json-schema-traverse': '1.0.0',
    'require-from-string': '2.0.2',
  };
  const localRuntimeDependencies = Object.keys(expectedRuntimeDependencies)
    .map((name) => path.join(PACKAGE_ROOT, 'node_modules', name));
  await execFileAsync(
    NPM,
    [
      'install',
      '--offline',
      '--cache', npmCache,
      '--ignore-scripts',
      '--install-links',
      '--omit=dev',
      '--no-audit',
      '--no-fund',
      '--prefix', consumerDir,
      release.tarballPath,
      ...localRuntimeDependencies,
    ],
    {
      cwd: stateDir,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      env: {
        ...process.env,
        NODE_PATH: '',
        npm_config_cache: npmCache,
        npm_config_offline: 'true',
      },
    },
  );
  const runtimePackageRoot = path.join(
    consumerDir,
    'node_modules',
    'openclaw-llm-action-judge',
  );
  const [installedRoot, canonicalConsumerDir, sourceRoot] = await Promise.all([
    fs.realpath(runtimePackageRoot),
    fs.realpath(consumerDir),
    fs.realpath(PACKAGE_ROOT),
  ]);
  assert.equal(path.dirname(path.dirname(installedRoot)), canonicalConsumerDir);
  assert.notEqual(installedRoot, sourceRoot);
  const installedMetadata = JSON.parse(
    await fs.readFile(path.join(runtimePackageRoot, 'package.json'), 'utf8'),
  );
  assert.equal(installedMetadata.name, 'openclaw-llm-action-judge');
  assert.equal(installedMetadata.version, '0.5.0');
  const canonicalNodeModules = await fs.realpath(path.join(consumerDir, 'node_modules'));
  for (const [name, version] of Object.entries(expectedRuntimeDependencies)) {
    const dependencyRoot = path.join(consumerDir, 'node_modules', name);
    const dependencyStat = await fs.lstat(dependencyRoot);
    assert.equal(dependencyStat.isSymbolicLink(), false, `${name} must not be a symlink`);
    const canonicalDependencyRoot = await fs.realpath(dependencyRoot);
    assert.equal(path.relative(canonicalNodeModules, canonicalDependencyRoot), name);
    const dependencyMetadata = JSON.parse(
      await fs.readFile(path.join(dependencyRoot, 'package.json'), 'utf8'),
    );
    assert.equal(dependencyMetadata.version, version);
  }
  const { stdout } = await execFileAsync(
    process.execPath,
    ['scripts/package-runtime-smoke.mjs', runtimePackageRoot, stateDir],
    {
      cwd: PACKAGE_ROOT,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, NODE_PATH: '' },
    },
  );

  assert.deepEqual(JSON.parse(stdout), {
    schemaVersion: 2,
    packageVersion: '0.5.0',
    hooks: ['before_model_resolve', 'before_tool_call'],
    safeAllow: true,
    deterministicGuardBlock: true,
    supervisedFailureApproval: true,
    invalidSchemaFailureApproval: true,
    invalidEnvironmentApproval: true,
    invalidEnvironmentClientCalls: 0,
    auditEvents: 5,
    auditMode: '0600',
    auditSecretFree: true,
  });
});

test('release docs state the v0.5.0 layered-routing contract and historical evidence boundary', async () => {
  const [readme, contract, security, deployment, rnd, changelog] = await Promise.all([
    fs.readFile(path.join(PACKAGE_ROOT, 'README.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'CONTRACT.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'SECURITY.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'DEPLOYMENT.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'RND.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'CHANGELOG.md'), 'utf8'),
  ]);

  for (const document of [readme, contract, security, deployment, rnd, changelog]) {
    assert.match(document, /0\.5\.0/u);
  }
  for (const document of [readme, contract, security, rnd, changelog]) {
    assert.match(document, /2026-07-16\.1/u);
  }
  for (const document of [readme, rnd, changelog]) assert.match(document, /2026-07-14\.6/u);
  for (const document of [readme, contract, security]) {
    assert.match(document, /json_schema/u);
    assert.match(document, /Ajv/u);
  }
  assert.match(readme, /schema-valid[^\n]*не означает safe/iu);
  assert.match(contract, /schemas\/judge-verdict\.schema\.json/u);
  assert.match(security, /fallback[^\n]*json_object[^\n]*отсутств/iu);
  assert.match(deployment, /releases\/v0\.5\.0/u);
  assert.match(deployment, /0\.5\.0[^\n]*0\.4\.1/u);
  for (const document of [readme, contract, security, changelog]) {
    assert.match(document, /decision_source/u);
    assert.match(document, /3 consecutive[\s\S]*10 among 50/iu);
  }
  for (const document of [readme, contract, changelog]) {
    assert.match(document, /safe path[^\n]*metrics-only/iu);
    assert.match(document, /blockReason/u);
  }
  assert.match(rnd, /Successful sixth strict qualification/iu);
  assert.match(rnd, /2026-07-14\.1[\s\S]*release-blocker/iu);
  assert.match(rnd, /112\/120[\s\S]*9\/240[\s\S]*5\/80[\s\S]*0\/11/iu);
  assert.match(rnd, /p50[\s\S]*1\.912[\s\S]*p95[\s\S]*4\.720[\s\S]*p99[\s\S]*6\.643/iu);
  assert.match(rnd, /2026-07-14\.2[\s\S]*release-blocker/iu);
  assert.match(rnd, /118\/120[\s\S]*6\/240[\s\S]*4\/80[\s\S]*0\/11/iu);
  assert.match(rnd, /p50[\s\S]*1846\.523[\s\S]*p95[\s\S]*2334\.410[\s\S]*p99[\s\S]*2573\.507/iu);
  assert.match(rnd, /2026-07-14\.3[\s\S]*release-blocker/iu);
  assert.match(rnd, /112\/120[\s\S]*2\/240[\s\S]*1\/80[\s\S]*0\/11/iu);
  assert.match(rnd, /p50[\s\S]*1867\.457[\s\S]*p95[\s\S]*2453\.216[\s\S]*p99[\s\S]*2780\.389/iu);
  assert.match(rnd, /2026-07-14\.4[\s\S]*release-blocker/iu);
  assert.match(rnd, /118\/120[\s\S]*2\/240[\s\S]*2\/80[\s\S]*0\/11/iu);
  assert.match(rnd, /p50[\s\S]*1806\.841[\s\S]*p95[\s\S]*2264\.777[\s\S]*p99[\s\S]*2477\.047/iu);
  assert.match(rnd, /2026-07-14\.5[\s\S]*release-blocker/iu);
  assert.match(rnd, /111\/120[\s\S]*2\/240[\s\S]*1\/80[\s\S]*0\/11/iu);
  assert.match(rnd, /p50[\s\S]*1838\.441[\s\S]*p95[\s\S]*2328\.160[\s\S]*p99[\s\S]*2671\.778/iu);
  assert.match(rnd, /108\/120[\s\S]*0\/240[\s\S]*0\/80[\s\S]*0\/11/iu);
  assert.match(rnd, /p50[\s\S]*1846\.141[\s\S]*p95[\s\S]*2320\.621[\s\S]*p99[\s\S]*2761\.126/iu);
  assert.match(rnd, /18\/18/iu);
  assert.match(rnd, /unseen holdout/iu);
  assert.match(security, /DNS resolution[\s\S]*native OpenClaw SSRF/iu);
  assert.match(rnd, /destructive_command_guard/iu);
  assert.match(rnd, /fail-open[\s\S]*default-allow/iu);
  assert.match(rnd, /historical\s+baseline 0\.2\.0\/0\.3\.0/iu);
  assert.match(changelog, /## 0\.4\.0 — 2026-07-14/u);
  assert.match(changelog, /## 0\.4\.1 — 2026-07-15/u);
});

test('deployment docs distinguish managed service ENV and safe legacy rollback', async () => {
  const [readme, deployment] = await Promise.all([
    fs.readFile(path.join(PACKAGE_ROOT, 'README.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'DEPLOYMENT.md'), 'utf8'),
  ]);
  assert.doesNotMatch(readme, /export OPENCLAW_JUDGE_/u);
  assert.doesNotMatch(deployment, /export OPENCLAW_JUDGE_/u);
  assert.match(deployment, /service manager/u);
  assert.match(deployment, /foreground gateway/u);
  assert.match(readme, /plugins\.allow[\s\S]*llm-action-judge/u);
  assert.match(deployment, /plugins\.allow[\s\S]*llm-action-judge/u);
  assert.match(deployment, /сохраните все trusted ids других plugins/u);
  assert.match(
    deployment,
    /config set plugins\.entries\.llm-action-judge\.config '\{"mode":"supervised","enforcement":"shadow"\}' --strict-json/u,
  );
  assert.match(deployment, /config get plugins\.entries\.llm-action-judge\.config --json/u);
});

test('README is operational-first for supervised and autonomous startup', async () => {
  const readme = await fs.readFile(path.join(PACKAGE_ROOT, 'README.md'), 'utf8');

  for (const heading of [
    '## Суть решения',
    '## Из каких блоков состоит',
    '## Установка',
    '## Запуск в supervised',
    '## Запуск в autonomous',
    '## Переменные окружения',
    '## Как проверить, что всё работает',
  ]) {
    assert.match(readme, new RegExp(`^${heading}$`, 'mu'), heading);
  }

  assert.match(
    readme,
    /OPENCLAW_JUDGE_PROFILE='supervised'\s+\\\s*\nopenclaw gateway run/u,
  );
  assert.match(
    readme,
    /OPENCLAW_JUDGE_PROFILE='autonomous'\s+\\\s*\nopenclaw gateway run/u,
  );

  for (const name of [
    'OPENCLAW_JUDGE_API_KEY',
    'OPENCLAW_JUDGE_PROFILE',
    'OPENCLAW_JUDGE_BASE_URL',
    'OPENCLAW_JUDGE_TIMEOUT_MS',
    'OPENCLAW_JUDGE_AUDIT_PATH',
    'OPENCLAW_JUDGE_LOG_LEVEL',
  ]) {
    assert.match(readme, new RegExp('\\| `' + name + '` \\|', 'u'), name);
  }

  for (const block of [
    'OpenClaw hooks',
    'LLM judge',
    'Structured Output',
    'Deterministic guard',
    'Mode mapper',
    'Audit',
  ]) {
    assert.match(readme, new RegExp(`\\*\\*${block}\\*\\*`, 'u'), block);
  }

  assert.match(
    readme,
    /OPENCLAW_JUDGE_BASE_URL[^\n]*только вместе с[^\n]*OPENCLAW_JUDGE_API_KEY/iu,
  );
  assert.match(readme, /приоритет над валидным legacy config/iu);
  assert.match(
    readme,
    /ошибка конфигурации[\s\S]*permanent `supervised \+ enforce`/iu,
  );
  assert.match(
    readme,
    /OPENCLAW_JUDGE_AUDIT_PATH:-\$\{OPENCLAW_STATE_DIR:-\$HOME\/\.openclaw\}/u,
  );
  assert.match(
    readme,
    /В `supervised` действие не должно выполниться автоматически[\s\S]*после явного approval оно может выполниться/iu,
  );
});

test('release builder refuses to replace a pre-existing output directory', async (t) => {
  const { buildRelease } = await import('../scripts/build-release.mjs');
  const temporary = await tempDirectory(t);
  const outputDir = path.join(temporary, 'release');
  const sentinel = path.join(outputDir, 'keep.txt');
  await fs.mkdir(outputDir);
  await fs.writeFile(sentinel, 'keep', 'utf8');

  await assert.rejects(
    buildRelease({ packageRoot: PACKAGE_ROOT, outputDir }),
    /release output already exists/u,
  );
  assert.equal(await fs.readFile(sentinel, 'utf8'), 'keep');
  assert.deepEqual(await fs.readdir(outputDir), ['keep.txt']);
});

test('concurrent release builds publish once without replacing the winner', async (t) => {
  const { buildRelease } = await import('../scripts/build-release.mjs');
  const temporary = await tempDirectory(t);
  const outputDir = path.join(temporary, 'release');

  const results = await Promise.allSettled([
    buildRelease({ packageRoot: PACKAGE_ROOT, outputDir }),
    buildRelease({ packageRoot: PACKAGE_ROOT, outputDir }),
  ]);

  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(results.filter(({ status }) => status === 'rejected').length, 1);
  const entries = await fs.readdir(outputDir);
  assert.deepEqual(entries.sort(), [
    'openclaw-llm-action-judge-0.5.0.tgz',
    'openclaw-llm-action-judge-0.5.0.tgz.sha256',
  ].sort());
});

test('source-only release builder CLI requires one explicit fresh output directory', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, ['scripts/build-release.mjs'], {
      cwd: PACKAGE_ROOT,
      encoding: 'utf8',
    }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /usage: node scripts\/build-release\.mjs <fresh-output-directory>/u);
      return true;
    },
  );
});
