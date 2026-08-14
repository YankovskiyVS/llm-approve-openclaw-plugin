/**
 * Normalize OpenClaw agent model ids for Cloud.ru chat/completions.
 * Agent config uses `cloudru/Qwen/...`; the FM API expects `Qwen/...`.
 */
export function normalizeJudgeModelId(value) {
  if (typeof value !== 'string') return undefined;
  let model = value.trim();
  if (!model) return undefined;
  if (model.startsWith('cloudru/')) {
    model = model.slice('cloudru/'.length).trim();
  }
  return model || undefined;
}

/**
 * Pick the first usable model id from hook payloads / config shapes OpenClaw uses.
 */
export function resolveAgentModelId(...candidates) {
  for (const candidate of candidates) {
    if (typeof candidate === 'string') {
      const normalized = normalizeJudgeModelId(candidate);
      if (normalized) return normalized;
      continue;
    }
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      const primary = normalizeJudgeModelId(candidate.primary);
      if (primary) return primary;
      const model = normalizeJudgeModelId(candidate.model);
      if (model) return model;
      const id = normalizeJudgeModelId(candidate.id);
      if (id) return id;
    }
  }
  return undefined;
}
