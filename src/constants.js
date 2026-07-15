import { JUDGE_POLICY_VERSION } from './judge-schema.js';

export const PLUGIN_ID = 'llm-action-judge';
export const MODEL_ID = 'Qwen/Qwen3.5-397B-A17B';
export const POLICY_VERSION = JUDGE_POLICY_VERSION;
export const MIN_CONFIDENCE = 0.8;
export const CLOUDRU_BASE_URL = 'https://foundation-models.api.cloud.ru/v1';
export const JUDGE_TIMEOUT_MS = 8_000;
export const MIN_JUDGE_TIMEOUT_MS = 1_000;
export const MAX_JUDGE_TIMEOUT_MS = 30_000;
export const APPROVAL_TIMEOUT_MS = 60_000;
export const MAX_TRUSTED_PROMPT_BYTES = 64 * 1024;

export function isTrustedUserRequest(value) {
  try {
    return typeof value === 'string'
      && value.trim() !== ''
      && Buffer.byteLength(value, 'utf8') <= MAX_TRUSTED_PROMPT_BYTES;
  } catch {
    return false;
  }
}
