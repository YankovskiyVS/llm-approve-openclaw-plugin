import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  parseCandidatePreflightArgs,
  publishCandidatePreflightArtifact,
} from '../evals/lib/candidate-preflight-cli.mjs';

test('preflight CLI accepts one relative fresh output and no ambient model or endpoint flags', () => {
  assert.deepEqual(parseCandidatePreflightArgs(['--output', 'preflight.json']), {
    outputPath: 'preflight.json',
  });
  for (const argv of [
    [],
    ['--output'],
    ['--output', '/tmp/preflight.json'],
    ['--output', '../preflight.json'],
    ['--output', 'linked/subdir/preflight.json'],
    ['--output', 'preflight.txt'],
    ['--output', 'preflight.json', '--model', 'arbitrary/model'],
    ['--endpoint', 'https://evil.invalid'],
    ['--output', 'preflight.json', '--output', 'second.json'],
  ]) {
    assert.throws(() => parseCandidatePreflightArgs(argv), TypeError);
  }
});

test('publisher writes one new private canonical JSON file atomically', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'candidate-preflight-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const outputPath = join(parent, 'preflight.json');
  const artifact = Object.freeze({ schema_version: 'fixture.v1', ok: true });

  await publishCandidatePreflightArtifact({
    outputPath,
    artifact,
    forbiddenValues: ['secret-value-never-write'],
  });

  assert.equal(await readFile(outputPath, 'utf8'), '{"ok":true,"schema_version":"fixture.v1"}\n');
  assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
  await assert.rejects(
    publishCandidatePreflightArtifact({ outputPath, artifact, forbiddenValues: [] }),
    TypeError,
  );
});

test('publisher rejects secrets before creating any output', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'candidate-preflight-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const outputPath = join(parent, 'preflight.json');
  const secret = 'secret-value-never-write';

  await assert.rejects(publishCandidatePreflightArtifact({
    outputPath,
    artifact: { nested: secret },
    forbiddenValues: [secret],
  }), /artifact contains forbidden value/);
  await assert.rejects(stat(outputPath), (error) => error?.code === 'ENOENT');

  const escapedOutput = join(parent, 'escaped.json');
  const escapedSecret = 'secret-"quoted\\value-never-write';
  await assert.rejects(publishCandidatePreflightArtifact({
    outputPath: escapedOutput,
    artifact: { nested: escapedSecret },
    forbiddenValues: [escapedSecret],
  }), /artifact contains forbidden value/);
  await assert.rejects(stat(escapedOutput), (error) => error?.code === 'ENOENT');
});
