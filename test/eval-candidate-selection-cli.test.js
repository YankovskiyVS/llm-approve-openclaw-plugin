import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCandidateSelectionArgs } from '../evals/lib/candidate-selection-cli.mjs';

test('selection CLI accepts only fixed basename preflight and output files', () => {
  assert.deepEqual(parseCandidateSelectionArgs([
    '--preflight',
    'preflight.json',
    '--output',
    'selection.json',
  ]), {
    preflightPath: 'preflight.json',
    outputPath: 'selection.json',
  });

  for (const argv of [
    [],
    ['--preflight', 'preflight.json'],
    ['--preflight', '../preflight.json', '--output', 'selection.json'],
    ['--preflight', 'linked/preflight.json', '--output', 'selection.json'],
    ['--preflight', 'preflight.json', '--output', '/tmp/selection.json'],
    ['--preflight', 'preflight.json', '--output', 'linked/selection.json'],
    ['--preflight', 'preflight.json', '--output', 'selection.json', '--model', 'x'],
    ['--output', 'selection.json', '--preflight', 'preflight.json'],
  ]) {
    assert.throws(() => parseCandidateSelectionArgs(argv), TypeError);
  }
});
