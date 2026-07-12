import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseConfig } from '../src/config.js';

test('uses autonomous shadow defaults', () => {
  assert.deepEqual(parseConfig(undefined), { mode: 'autonomous', enforcement: 'shadow' });
});

test('rejects unsupported public configuration', () => {
  assert.throws(() => parseConfig({ mode: 'yolo' }), /mode/);
  assert.throws(() => parseConfig({ enforcement: 'silent' }), /enforcement/);
  assert.throws(() => parseConfig({ model: 'other' }), /unknown/);
});

test('exports a minimal OpenClaw plugin entry', async () => {
  const [{ default: plugin }, { PLUGIN_ID }] = await Promise.all([
    import('../index.js'),
    import('../src/constants.js'),
  ]);

  assert.equal(plugin.id, PLUGIN_ID);
  assert.equal(typeof plugin.register, 'function');
});

test('manifest explicitly activates the judge during gateway startup', async () => {
  const manifestUrl = new URL('../openclaw.plugin.json', import.meta.url);
  const manifest = JSON.parse(await readFile(manifestUrl, 'utf8'));

  assert.deepEqual(manifest.activation, { onStartup: true });
});
