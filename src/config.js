const MODES = new Set(['autonomous', 'supervised']);
const ENFORCEMENTS = new Set(['shadow', 'enforce']);

export function parseConfig(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('config must be an object');
  }

  const unknown = Object.keys(value).filter((key) => !['mode', 'enforcement'].includes(key));
  if (unknown.length) throw new Error(`unknown config keys: ${unknown.join(', ')}`);

  const mode = value.mode ?? 'autonomous';
  const enforcement = value.enforcement ?? 'shadow';
  if (!MODES.has(mode)) throw new Error('mode must be autonomous or supervised');
  if (!ENFORCEMENTS.has(enforcement)) throw new Error('enforcement must be shadow or enforce');

  return { mode, enforcement };
}
