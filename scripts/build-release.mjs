import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';

const execFileAsync = promisify(execFile);
const DEFAULT_PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const RELEASE_PACKAGE_FILES = Object.freeze([
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
  'src/prompt.js',
  'src/redact.js',
  'src/run-decision-store.js',
].sort());
const FORBIDDEN_RELEASE_CONTENT = Object.freeze([
  /\/Users\/[^/\s]+\//u,
  /\/home\/[^/\s]+\//u,
  /[A-Za-z]:\\Users\\[^\\\s]+\\/u,
  /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\b(?:sk|rk)_(?:live|prod)_[A-Za-z0-9_-]{12,}\b/u,
  /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/u,
]);

function requiredPath(value, name) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${name} must be a non-empty path`);
  }
  return path.resolve(value);
}

async function pathExists(target) {
  try {
    await fs.lstat(target);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function requireFreshOutput(outputDir) {
  if (await pathExists(outputDir)) throw new Error('release output already exists');
}

async function canonicalReleaseParent(parent) {
  const canonical = await fs.realpath(parent);
  const stat = await fs.lstat(canonical);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('invalid release output parent');
  }
  return canonical;
}

function expectedTarballName(metadata) {
  if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new Error('invalid package metadata');
  }
  if (typeof metadata.name !== 'string' || !metadata.name
    || typeof metadata.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(metadata.version)) {
    throw new Error('invalid package metadata');
  }
  const packageName = metadata.name.startsWith('@')
    ? metadata.name.slice(1).replace('/', '-')
    : metadata.name;
  if (!/^[A-Za-z0-9._-]+$/u.test(packageName)) throw new Error('invalid package metadata');
  return `${packageName}-${metadata.version}.tgz`;
}

async function validateReleaseSources(packageRoot) {
  const prefix = `${packageRoot}${path.sep}`;
  for (const relativePath of RELEASE_PACKAGE_FILES) {
    const sourcePath = path.resolve(packageRoot, relativePath);
    if (!sourcePath.startsWith(prefix)) throw new Error('invalid release file path');

    let stat;
    try {
      stat = await fs.lstat(sourcePath);
    } catch {
      throw new Error(`required release file is missing: ${relativePath}`);
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`required release file is not a regular file: ${relativePath}`);
    }

    const content = await fs.readFile(sourcePath, 'utf8');
    if (FORBIDDEN_RELEASE_CONTENT.some((pattern) => pattern.test(content))) {
      throw new Error(`release safety scan failed: ${relativePath}`);
    }
  }
}

function parsePackResult(stdout, expectedFilename) {
  let result;
  try {
    result = JSON.parse(stdout);
  } catch {
    throw new Error('npm pack returned invalid JSON');
  }
  if (!Array.isArray(result) || result.length !== 1) {
    throw new Error('npm pack returned an unexpected result');
  }

  const packed = result[0];
  if (packed === null || typeof packed !== 'object' || Array.isArray(packed)
    || packed.filename !== expectedFilename
    || path.basename(packed.filename) !== packed.filename
    || !Array.isArray(packed.files)) {
    throw new Error('npm pack returned an unexpected result');
  }

  const files = packed.files.map((entry) => entry?.path);
  if (files.some((entry) => typeof entry !== 'string')
    || new Set(files).size !== files.length
    || files.some((entry) => path.posix.isAbsolute(entry) || entry.split('/').includes('..'))
    || JSON.stringify(files.slice().sort()) !== JSON.stringify(RELEASE_PACKAGE_FILES)) {
    throw new Error('npm pack file set does not match the release allowlist');
  }
  return packed;
}

async function stageRuntimePackage(packageRoot, stagingRoot, metadata) {
  const runtimeRoot = path.join(stagingRoot, 'runtime-package');
  await fs.mkdir(runtimeRoot, { mode: 0o700 });

  for (const relativePath of RELEASE_PACKAGE_FILES) {
    const sourcePath = path.join(packageRoot, relativePath);
    const destinationPath = path.join(runtimeRoot, relativePath);
    await fs.mkdir(path.dirname(destinationPath), { recursive: true, mode: 0o700 });

    if (relativePath === 'package.json') {
      const runtimeMetadata = { ...metadata };
      delete runtimeMetadata.scripts;
      await fs.writeFile(destinationPath, `${JSON.stringify(runtimeMetadata, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o644,
      });
      continue;
    }

    await fs.copyFile(sourcePath, destinationPath);
    await fs.chmod(destinationPath, 0o644);
  }
  return runtimeRoot;
}

async function packToStaging(packageRoot, stagingRoot, expectedFilename) {
  const packDirectory = path.join(stagingRoot, 'pack');
  await fs.mkdir(packDirectory, { mode: 0o700 });
  const { stdout } = await execFileAsync(
    NPM,
    ['pack', '--json', '--ignore-scripts', '--pack-destination', packDirectory],
    {
      cwd: packageRoot,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, npm_config_ignore_scripts: 'true' },
    },
  );
  parsePackResult(stdout, expectedFilename);

  const tarballPath = path.join(packDirectory, expectedFilename);
  const stat = await fs.lstat(tarballPath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('npm pack did not create a regular tarball');
  return tarballPath;
}

export async function buildRelease({ packageRoot = DEFAULT_PACKAGE_ROOT, outputDir } = {}) {
  const root = requiredPath(packageRoot, 'packageRoot');
  const requestedOutput = requiredPath(outputDir, 'outputDir');
  await requireFreshOutput(requestedOutput);

  const requestedParent = path.dirname(requestedOutput);
  await fs.mkdir(requestedParent, { recursive: true, mode: 0o700 });
  const parent = await canonicalReleaseParent(requestedParent);
  const output = path.join(parent, path.basename(requestedOutput));
  await requireFreshOutput(output);
  const lockPath = `${output}.lock`;
  let lock;
  try {
    lock = await fs.open(lockPath, 'wx', 0o600);
  } catch (error) {
    if (error?.code === 'EEXIST') throw new Error('release output is locked by another build');
    throw error;
  }

  let stagingRoot;
  let outputReserved = false;
  let publicationComplete = false;
  const publishedNames = [];
  try {
    await requireFreshOutput(output);
    await validateReleaseSources(root);
    const metadata = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
    const tarballName = expectedTarballName(metadata);
    stagingRoot = await fs.mkdtemp(path.join(parent, '.release-stage-'));
    await fs.chmod(stagingRoot, 0o700);

    const runtimeRoot = await stageRuntimePackage(root, stagingRoot, metadata);
    const packedTarball = await packToStaging(runtimeRoot, stagingRoot, tarballName);
    const tarball = await fs.readFile(packedTarball);
    const sha256 = createHash('sha256').update(tarball).digest('hex');
    const publishDir = path.join(stagingRoot, 'publish');
    await fs.mkdir(publishDir, { mode: 0o700 });
    const stagedTarball = path.join(publishDir, tarballName);
    const checksumName = `${tarballName}.sha256`;
    const stagedChecksum = path.join(publishDir, checksumName);
    await fs.rename(packedTarball, stagedTarball);
    await fs.writeFile(stagedChecksum, `${sha256}  ${tarballName}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o644,
    });
    await fs.chmod(stagedTarball, 0o644);

    try {
      await fs.mkdir(output, { mode: 0o700 });
      outputReserved = true;
    } catch (error) {
      if (error?.code === 'EEXIST') throw new Error('release output already exists');
      throw error;
    }
    for (const name of [tarballName, checksumName]) {
      await fs.link(path.join(publishDir, name), path.join(output, name));
      publishedNames.push(name);
    }
    publicationComplete = true;
    return {
      outputDir: requestedOutput,
      tarballPath: path.join(requestedOutput, tarballName),
      checksumPath: path.join(requestedOutput, checksumName),
      sha256,
      files: RELEASE_PACKAGE_FILES.slice(),
    };
  } finally {
    if (outputReserved && !publicationComplete) {
      for (const name of publishedNames) {
        await fs.rm(path.join(output, name), { force: true }).catch(() => {});
      }
      await fs.rmdir(output).catch(() => {});
    }
    await lock.close().catch(() => {});
    await fs.rm(lockPath, { force: true });
    if (stagingRoot !== undefined) await fs.rm(stagingRoot, { recursive: true, force: true });
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    throw new Error('usage: node scripts/build-release.mjs <fresh-output-directory>');
  }
  const result = await buildRelease({ outputDir: args[0] });
  process.stdout.write(`${JSON.stringify({
    output_dir: result.outputDir,
    tarball: path.basename(result.tarballPath),
    checksum: path.basename(result.checksumPath),
    sha256: result.sha256,
  }, null, 2)}\n`);
}

const invokedPath = process.argv[1] === undefined ? null : pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedPath === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`release build failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  });
}
