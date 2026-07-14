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
  'CHANGELOG.md',
  'SECURITY.md',
  'LICENSE',
];
const EXPECTED_PACKAGE_FILES = [
  '.env.example',
  'CHANGELOG.md',
  'CONTRACT.md',
  'DEPLOYMENT.md',
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
  'src/judge-client.js',
  'src/judge-schema.js',
  'src/plugin.js',
  'src/prompt.js',
  'src/redact.js',
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
    'npm',
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

test('package metadata pins the internal 0.4.0 release contract and lean runtime dependencies', async () => {
  const metadata = JSON.parse(await fs.readFile(path.join(PACKAGE_ROOT, 'package.json'), 'utf8'));

  assert.equal(metadata.version, '0.4.0');
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
  assert.deepEqual(metadata.files, EXPECTED_FILES_FIELD);
  assert.equal(metadata.scripts.test, 'node --test');
  assert.equal(metadata.scripts['eval:smoke'], 'node evals/dev-smoke.mjs');
  assert.equal(Object.hasOwn(metadata.scripts, 'build:release'), false);
  assert.equal(Object.values(metadata.scripts).some((value) => value.includes('scripts/build-release.mjs')), false);
});

test('npm pack dry-run has the exact reviewed release file set', async () => {
  const packed = await npmPackDryRun();

  assert.equal(packed.filename, 'openclaw-llm-action-judge-0.4.0.tgz');
  assert.deepEqual(packed.files.map((entry) => entry.path).sort(), EXPECTED_PACKAGE_FILES);
  assert.equal(packed.files.some((entry) => /(?:^|\/)(?:evals?|tests?|reviews?)(?:\/|$)/u.test(entry.path)), false);
  assert.equal(packed.files.some((entry) => path.isAbsolute(entry.path) || entry.path.split('/').includes('..')), false);
});

test('release builder publishes one versioned tarball and matching sha256 into a fresh directory', async (t) => {
  const { buildRelease } = await import('../scripts/build-release.mjs');
  const temporary = await tempDirectory(t);
  const outputDir = path.join(temporary, 'release');

  const result = await buildRelease({ packageRoot: PACKAGE_ROOT, outputDir });
  const tarballName = 'openclaw-llm-action-judge-0.4.0.tgz';
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
  assert.equal(runtimeMetadata.version, '0.4.0');
  assert.deepEqual(runtimeMetadata.dependencies, { ajv: '8.20.0' });
  assert.deepEqual(runtimeMetadata.peerDependenciesMeta, { openclaw: { optional: true } });
  const [sourceSchema, packagedSchema] = await Promise.all([
    fs.readFile(path.join(PACKAGE_ROOT, 'schemas', 'judge-verdict.schema.json'), 'utf8'),
    fs.readFile(
      path.join(extracted, 'package', 'schemas', 'judge-verdict.schema.json'),
      'utf8',
    ),
  ]);
  assert.equal(packagedSchema, sourceSchema);
  const parsedSchema = JSON.parse(packagedSchema);
  assert.equal(parsedSchema.properties.policy_version.const, '2026-07-14.2');
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
  for (const name of expectedNames) assert.match(content, new RegExp(`^${name}=`, 'mu'));
  assert.match(content, /plugin does not load this file/u);
  assert.match(content, /^OPENCLAW_JUDGE_API_KEY=$/mu);
  assert.doesNotMatch(content, /OPENCLAW_JUDGE_(?:MODEL|POLICY|PROMPT|MIN_CONFIDENCE)=/u);
});

test('manifest keeps model and policy immutable outside public config', async () => {
  const manifest = JSON.parse(
    await fs.readFile(path.join(PACKAGE_ROOT, 'openclaw.plugin.json'), 'utf8'),
  );
  assert.deepEqual(Object.keys(manifest.configSchema.properties).sort(), ['enforcement', 'mode']);
  assert.equal(JSON.stringify(manifest).includes('Qwen/Qwen3.5-397B-A17B'), false);
  assert.equal(JSON.stringify(manifest).includes('2026-07-14.2'), false);
});

test('runtime smoke pins v0.4 and fails closed for schema-invalid judge output', async (t) => {
  const stateDir = await tempDirectory(t);
  const { stdout } = await execFileAsync(
    process.execPath,
    ['scripts/package-runtime-smoke.mjs', PACKAGE_ROOT, stateDir],
    { cwd: PACKAGE_ROOT, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
  );

  assert.deepEqual(JSON.parse(stdout), {
    schemaVersion: 2,
    packageVersion: '0.4.0',
    hooks: ['before_model_resolve', 'before_tool_call'],
    safeAllow: true,
    deterministicGuardBlock: true,
    supervisedFailureApproval: true,
    invalidSchemaFailureApproval: true,
    invalidEnvironmentApproval: true,
    invalidEnvironmentClientCalls: 0,
    auditEvents: 4,
    auditMode: '0600',
    auditSecretFree: true,
  });
});

test('release docs state the v0.4 structured-output contract and historical evidence boundary', async () => {
  const [readme, contract, security, deployment, rnd, changelog] = await Promise.all([
    fs.readFile(path.join(PACKAGE_ROOT, 'README.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'CONTRACT.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'SECURITY.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'DEPLOYMENT.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'RND.md'), 'utf8'),
    fs.readFile(path.join(PACKAGE_ROOT, 'CHANGELOG.md'), 'utf8'),
  ]);

  for (const document of [readme, contract, security, deployment, rnd, changelog]) {
    assert.match(document, /0\.4\.0/u);
  }
  for (const document of [readme, contract, security, rnd, changelog]) {
    assert.match(document, /2026-07-14\.2/u);
  }
  for (const document of [readme, contract, security]) {
    assert.match(document, /json_schema/u);
    assert.match(document, /Ajv/u);
  }
  assert.match(readme, /schema-valid[^\n]*не означает safe/iu);
  assert.match(contract, /schemas\/judge-verdict\.schema\.json/u);
  assert.match(security, /fallback[^\n]*json_object[^\n]*отсутств/iu);
  assert.match(deployment, /releases\/v0\.4\.0/u);
  assert.match(deployment, /0\.4\.0[^\n]*0\.3\.0/u);
  assert.match(rnd, /pending fresh qualification/iu);
  assert.match(rnd, /2026-07-14\.1[\s\S]*release-blocker/iu);
  assert.match(rnd, /112\/120[\s\S]*9\/240[\s\S]*5\/80[\s\S]*0\/11/iu);
  assert.match(rnd, /p50[\s\S]*1\.912[\s\S]*p95[\s\S]*4\.720[\s\S]*p99[\s\S]*6\.643/iu);
  assert.match(rnd, /destructive_command_guard/iu);
  assert.match(rnd, /fail-open[\s\S]*default-allow/iu);
  assert.match(rnd, /historical baseline 0\.2\.0\/0\.3\.0/iu);
  assert.match(changelog, /## 0\.4\.0 — 2026-07-14/u);
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
  assert.match(
    deployment,
    /config set plugins\.entries\.llm-action-judge\.config '\{"mode":"supervised","enforcement":"shadow"\}' --strict-json/u,
  );
  assert.match(deployment, /config get plugins\.entries\.llm-action-judge\.config --json/u);
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
