#!/usr/bin/env node

import { fileURLToPath } from 'node:url';
import {
  lintCandidateDirectory,
  lintQualificationChunk,
  readRegularJsonFile,
} from '../lib/corpus-qualification.mjs';

const HELP = `Usage:
  node evals/corpus-v2/corpusctl.mjs lint-candidates --split NAME [--dir PATH]
  node evals/corpus-v2/corpusctl.mjs lint-chunk --split NAME --chunk N --file PATH
`;

function parseOptions(values) {
  const options = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!flag?.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error('arguments');
    }
    const key = flag.slice(2);
    if (!['split', 'dir', 'chunk', 'file'].includes(key)
      || Object.hasOwn(options, key)) throw new Error('arguments');
    options[key] = value;
  }
  return options;
}

function readJson(path) {
  return readRegularJsonFile(path);
}

function defaultPlanPath() {
  return fileURLToPath(new URL('./contracts/generation-plan.json', import.meta.url));
}

function defaultCandidateDirectory(split) {
  return fileURLToPath(new URL(`./candidates/${split}/`, import.meta.url));
}

function run(argv) {
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(HELP);
    return;
  }
  const [command, ...rest] = argv;
  const options = parseOptions(rest);
  if (!options.split) throw new Error('split');
  const plan = readJson(defaultPlanPath());

  if (command === 'lint-candidates') {
    const result = lintCandidateDirectory(
      options.dir ?? defaultCandidateDirectory(options.split),
      { plan, split: options.split },
    );
    process.stdout.write(`${JSON.stringify({
      ok: true,
      split: options.split,
      chunks: result.chunks.length,
      cases: result.cases.length,
    })}\n`);
    return;
  }

  if (command === 'lint-chunk') {
    if (!options.file || !/^[1-9][0-9]*$/u.test(options.chunk ?? '')) {
      throw new Error('chunk');
    }
    const cases = lintQualificationChunk(readJson(options.file), {
      plan,
      split: options.split,
      chunkIndex: Number(options.chunk),
    });
    process.stdout.write(`${JSON.stringify({
      ok: true,
      split: options.split,
      chunk: Number(options.chunk),
      cases: cases.length,
    })}\n`);
    return;
  }

  throw new Error('command');
}

try {
  run(process.argv.slice(2));
} catch {
  process.stderr.write('corpus qualification failed\n');
  process.exitCode = 1;
}
