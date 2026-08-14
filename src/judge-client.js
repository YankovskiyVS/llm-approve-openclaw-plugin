import { types } from 'node:util';
import { JUDGE_TIMEOUT_MS, MODEL_ID } from './constants.js';
import { createJudgeResponseFormat } from './judge-schema.js';
import { buildJudgeMessages } from './prompt.js';
import { canonicalStringify } from './action.js';
import { normalizeJudgeModelId } from './model-id.js';
const INVALID_CONFIGURATION = 'invalid judge client configuration';
const INVALID_REQUEST = 'invalid judge request';
const INVALID_RESPONSE = 'invalid judge response';
const REQUEST_FAILED = 'request failed';
const REQUEST_TIMED_OUT = 'request timed out';
const CLOUDRU_ORIGIN = 'https://foundation-models.api.cloud.ru';
const CLOUDRU_API_PATH = '/v1';

function invalidConfiguration() {
  throw new TypeError(INVALID_CONFIGURATION);
}

function monotonicNow() {
  try {
    const value = globalThis.performance?.now();
    if (Number.isFinite(value)) return value;
  } catch {
    // Fall back to the wall clock when the monotonic clock is unavailable.
  }

  try {
    const value = Date.now();
    if (Number.isFinite(value)) return value;
  } catch {
    // A safe result still needs a finite latency when the clock is unavailable.
  }
  return 0;
}

function latencySince(startedAt) {
  const elapsed = monotonicNow() - startedAt;
  return Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : 0;
}

function failure(reason, startedAt) {
  return { ok: false, reason, latencyMs: latencySince(startedAt) };
}

function semanticInputSnapshot(input) {
  const userPrompt = Object.getOwnPropertyDescriptor(input, 'userPrompt');
  const envelope = Object.getOwnPropertyDescriptor(input, 'envelope');
  if (!userPrompt || !Object.hasOwn(userPrompt, 'value')
    || !envelope || !Object.hasOwn(envelope, 'value')) {
    throw new TypeError(INVALID_REQUEST);
  }
  return JSON.parse(canonicalStringify({
    userPrompt: userPrompt.value,
    envelope: envelope.value,
  }));
}

function containsString(value, expected) {
  if (typeof value === 'string') return value.includes(expected);
  if (Array.isArray(value)) return value.some((item) => containsString(item, expected));
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).some(([key, item]) => (
      key.includes(expected) || containsString(item, expected)
    ));
  }
  return false;
}

function normalizeOptions(options) {
  try {
    if (options === null || typeof options !== 'object') return invalidConfiguration();

    const providerConfig = options.providerConfig;
    const fetchImpl = options.fetchImpl === undefined ? globalThis.fetch : options.fetchImpl;
    const timeoutMs = options.timeoutMs === undefined ? JUDGE_TIMEOUT_MS : options.timeoutMs;
    if (providerConfig === null || typeof providerConfig !== 'object') {
      return invalidConfiguration();
    }

    const baseUrl = providerConfig.baseUrl;
    const apiKey = providerConfig.apiKey;
    if (typeof baseUrl !== 'string' || baseUrl.trim() === '') {
      return invalidConfiguration();
    }
    if (typeof apiKey !== 'string' || apiKey.trim() === '') {
      return invalidConfiguration();
    }
    if (typeof fetchImpl !== 'function') return invalidConfiguration();
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) return invalidConfiguration();

    const trimmedBaseUrl = baseUrl.trim();
    const parsed = new URL(trimmedBaseUrl);
    const path = parsed.pathname.replace(/\/+$/u, '');
    if (parsed.protocol !== 'https:'
      || parsed.origin !== CLOUDRU_ORIGIN
      || path !== CLOUDRU_API_PATH
      || parsed.username
      || parsed.password
      || parsed.search
      || parsed.hash) return invalidConfiguration();

    const endpoint = `${CLOUDRU_ORIGIN}${CLOUDRU_API_PATH}/chat/completions`;
    const defaultModelId = normalizeJudgeModelId(options.modelId) || MODEL_ID;
    return { apiKey, endpoint, fetchImpl, timeoutMs, defaultModelId };
  } catch {
    return invalidConfiguration();
  }
}

function responseContent(value, expectedModelId) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) return undefined;
    const model = Object.getOwnPropertyDescriptor(value, 'model');
    if (!model || !Object.hasOwn(model, 'value')
      || typeof model.value !== 'string'
      || model.value !== expectedModelId) {
      return undefined;
    }
    const choices = value.choices;
    if (!Array.isArray(choices) || choices.length === 0) return undefined;

    const choice = choices[0];
    if (choice === null || typeof choice !== 'object' || Array.isArray(choice)) return undefined;
    if (choice.finish_reason !== 'stop') return undefined;

    const message = choice.message;
    if (message === null || typeof message !== 'object' || Array.isArray(message)) {
      return undefined;
    }
    const content = message.content;
    return typeof content === 'string' && content.trim() !== '' ? content : undefined;
  } catch {
    return undefined;
  }
}

function ownDataField(source, key) {
  try {
    if (source === null || typeof source !== 'object' || types.isProxy(source)) {
      return { valid: false, present: false, value: undefined };
    }
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (!descriptor) return { valid: true, present: false, value: undefined };
    if (!Object.hasOwn(descriptor, 'value')) {
      return { valid: false, present: true, value: undefined };
    }
    return { valid: true, present: true, value: descriptor.value };
  } catch {
    return { valid: false, present: false, value: undefined };
  }
}

function ownDataValue(source, key) {
  const field = ownDataField(source, key);
  return field.valid && field.present ? field.value : undefined;
}

function ownDataObject(source, key) {
  const value = ownDataValue(source, key);
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || types.isProxy(value)) return null;
  return value;
}

function nonNegativeInteger(source, key) {
  const value = ownDataValue(source, key);
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function nestedOptionalInteger(source, objectKey, valueKey) {
  const objectField = ownDataField(source, objectKey);
  if (!objectField.valid) return { valid: false, value: null };
  if (!objectField.present) return { valid: true, value: null };

  const nested = objectField.value;
  try {
    if (nested === null || typeof nested !== 'object' || Array.isArray(nested)
      || types.isProxy(nested)) return { valid: false, value: null };
    const prototype = Object.getPrototypeOf(nested);
    if (prototype !== Object.prototype && prototype !== null) {
      return { valid: false, value: null };
    }
  } catch {
    return { valid: false, value: null };
  }

  const valueField = ownDataField(nested, valueKey);
  if (!valueField.valid) return { valid: false, value: null };
  if (!valueField.present) return { valid: true, value: null };
  if (!Number.isSafeInteger(valueField.value) || valueField.value < 0) {
    return { valid: false, value: null };
  }
  return { valid: true, value: valueField.value };
}

function usageSnapshot(responseValue) {
  try {
    const usage = ownDataObject(responseValue, 'usage');
    if (usage === null) return null;
    const promptTokens = nonNegativeInteger(usage, 'prompt_tokens');
    const completionTokens = nonNegativeInteger(usage, 'completion_tokens');
    const totalTokens = nonNegativeInteger(usage, 'total_tokens');
    if (promptTokens === null || completionTokens === null || totalTokens === null
      || promptTokens + completionTokens !== totalTokens) return null;

    const reasoning = nestedOptionalInteger(
      usage,
      'completion_tokens_details',
      'reasoning_tokens',
    );
    const cached = nestedOptionalInteger(
      usage,
      'prompt_tokens_details',
      'cached_tokens',
    );
    if (!reasoning.valid || !cached.valid) return null;
    const reasoningTokens = reasoning.value;
    const cachedPromptTokens = cached.value;
    if ((reasoningTokens !== null && reasoningTokens > completionTokens)
      || (cachedPromptTokens !== null && cachedPromptTokens > promptTokens)) return null;

    return {
      promptTokens,
      completionTokens,
      totalTokens,
      reasoningTokens,
      cachedPromptTokens,
    };
  } catch {
    return null;
  }
}

export function createJudgeClient(options = {}) {
  const { apiKey, endpoint, fetchImpl, timeoutMs, defaultModelId } = normalizeOptions(options);

  async function review(input) {
    const startedAt = monotonicNow();
    let timer;

    try {
      let body;
      let requestedModelId;
      try {
        const semanticInput = semanticInputSnapshot(input);
        const messages = buildJudgeMessages(semanticInput);
        if (containsString(semanticInput, apiKey)) {
          return failure(INVALID_REQUEST, startedAt);
        }
        requestedModelId = normalizeJudgeModelId(
          input && typeof input === 'object' ? input.modelId : undefined,
        ) || defaultModelId || MODEL_ID;
        body = JSON.stringify({
          model: requestedModelId,
          messages,
          temperature: 0,
          max_tokens: 256,
          response_format: createJudgeResponseFormat(),
          chat_template_kwargs: { enable_thinking: false },
        });
        if (body.includes(apiKey)) return failure(INVALID_REQUEST, startedAt);
      } catch {
        return failure(INVALID_REQUEST, startedAt);
      }

      const controller = new AbortController();
      const timeoutMarker = Object.freeze({ timeout: true });
      let timedOut = false;
      const timeout = new Promise((resolve) => {
        timer = setTimeout(() => {
          timedOut = true;
          try {
            controller.abort();
          } catch {
            // Timeout still resolves even if abort itself is unavailable.
          }
          resolve(timeoutMarker);
        }, timeoutMs);
      });

      let response;
      try {
        const request = Promise.resolve().then(() => fetchImpl(endpoint, {
          method: 'POST',
          redirect: 'error',
          headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body,
          signal: controller.signal,
        }));
        response = await Promise.race([request, timeout]);
      } catch {
        return failure(timedOut ? REQUEST_TIMED_OUT : REQUEST_FAILED, startedAt);
      }

      if (response === timeoutMarker) return failure(REQUEST_TIMED_OUT, startedAt);

      let ok;
      try {
        ok = response.ok;
      } catch {
        return failure(REQUEST_FAILED, startedAt);
      }

      if (ok !== true) {
        let status;
        try {
          status = response.status;
        } catch {
          return failure(REQUEST_FAILED, startedAt);
        }
        const reason = Number.isInteger(status) && status >= 100 && status <= 599
          ? `http ${status}`
          : REQUEST_FAILED;
        return failure(reason, startedAt);
      }

      let value;
      try {
        const parse = response.json;
        if (typeof parse !== 'function') return failure(INVALID_RESPONSE, startedAt);
        const parsed = Promise.resolve().then(() => parse.call(response));
        value = await Promise.race([parsed, timeout]);
      } catch {
        return failure(timedOut ? REQUEST_TIMED_OUT : INVALID_RESPONSE, startedAt);
      }

      if (value === timeoutMarker) return failure(REQUEST_TIMED_OUT, startedAt);
      const text = responseContent(value, requestedModelId);
      if (text === undefined) return failure(INVALID_RESPONSE, startedAt);
      if (text.includes(apiKey)) return failure(INVALID_RESPONSE, startedAt);
      return {
        ok: true,
        text,
        latencyMs: latencySince(startedAt),
        usage: usageSnapshot(value),
      };
    } catch {
      return failure(REQUEST_FAILED, startedAt);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  return { review };
}
