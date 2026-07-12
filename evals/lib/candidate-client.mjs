import { types } from 'node:util';
import { canonicalStringify } from '../../src/action.js';
import { buildJudgeMessages } from '../../src/prompt.js';
import { assertProxyFreeTree } from './case-schema.mjs';
import { validateCandidateEntry } from './candidate-plan.mjs';
import { parseCandidateResponse } from './candidate-response.mjs';

const INVALID_CONFIGURATION = 'invalid candidate client configuration';
const INVALID_REQUEST = 'invalid judge request';
const INVALID_RESPONSE = 'invalid judge response';
const REQUEST_FAILED = 'request failed';
const REQUEST_TIMED_OUT = 'request timed out';
const ENDPOINTS = Object.freeze({
  'cloudru-fm': 'https://foundation-models.api.cloud.ru/v1/chat/completions',
  'qwen-vllm': 'https://45a768cf-dd2c-4d96-9a98-7e24ce4866e5.modelrun.inference.cloud.ru/v1/chat/completions',
});

function invalidConfiguration() {
  throw new TypeError(INVALID_CONFIGURATION);
}

function exactDataValues(value, expected) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) invalidConfiguration();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalidConfiguration();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) {
      invalidConfiguration();
    }
    const result = {};
    for (const key of expected) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        invalidConfiguration();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    invalidConfiguration();
  }
}

function snapshotCandidate(value) {
  try {
    return validateCandidateEntry(value);
  } catch {
    invalidConfiguration();
  }
}

function snapshotOptions(value) {
  const fields = exactDataValues(value, ['candidate', 'apiKey', 'fetchImpl']);
  const candidate = snapshotCandidate(fields.candidate);
  if (typeof fields.apiKey !== 'string' || fields.apiKey.trim() === ''
    || typeof fields.fetchImpl !== 'function') invalidConfiguration();
  return Object.freeze({
    candidate,
    apiKey: fields.apiKey,
    fetchImpl: fields.fetchImpl,
    endpoint: ENDPOINTS[candidate.endpoint_profile],
  });
}

function monotonicNow() {
  try {
    const value = globalThis.performance?.now();
    if (Number.isFinite(value)) return value;
  } catch {
    // Fall through to a bounded wall-clock fallback.
  }
  try {
    const value = Date.now();
    if (Number.isFinite(value)) return value;
  } catch {
    // A zero baseline still yields a finite sanitized latency.
  }
  return 0;
}

function latencySince(startedAt) {
  const elapsed = monotonicNow() - startedAt;
  return Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : 0;
}

function failure(reason, startedAt) {
  return Object.freeze({ ok: false, reason, latencyMs: latencySince(startedAt) });
}

function semanticInputSnapshot(input) {
  try {
    if (input === null || typeof input !== 'object' || Array.isArray(input)
      || types.isProxy(input)) throw new TypeError(INVALID_REQUEST);
    const userPrompt = Object.getOwnPropertyDescriptor(input, 'userPrompt');
    const envelope = Object.getOwnPropertyDescriptor(input, 'envelope');
    if (!userPrompt || !userPrompt.enumerable || !Object.hasOwn(userPrompt, 'value')
      || !envelope || !envelope.enumerable || !Object.hasOwn(envelope, 'value')) {
      throw new TypeError(INVALID_REQUEST);
    }
    assertProxyFreeTree(userPrompt.value, 'candidate user prompt');
    assertProxyFreeTree(envelope.value, 'candidate envelope');
    return JSON.parse(canonicalStringify({
      userPrompt: userPrompt.value,
      envelope: envelope.value,
    }));
  } catch {
    throw new TypeError(INVALID_REQUEST);
  }
}

function transportResponseSnapshot(value) {
  try {
    if (value === null || typeof value !== 'object' || types.isProxy(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (types.isProxy(prototype)) return null;

    if (prototype === Object.prototype || prototype === null) {
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const ok = descriptors.ok;
      const status = descriptors.status;
      const json = descriptors.json;
      if (!ok || !Object.hasOwn(ok, 'value')
        || !status || !Object.hasOwn(status, 'value')
        || !json || !Object.hasOwn(json, 'value')
        || typeof json.value !== 'function') return null;
      return Object.freeze({ ok: ok.value, status: status.value, parse: json.value });
    }

    if (typeof globalThis.Response === 'function'
      && prototype === globalThis.Response.prototype) {
      return Object.freeze({
        ok: value.ok,
        status: value.status,
        parse: globalThis.Response.prototype.json,
      });
    }
    return null;
  } catch {
    return null;
  }
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

export function createCandidateJudgeClient(options) {
  const { candidate, apiKey, fetchImpl, endpoint } = snapshotOptions(options);

  async function review(input) {
    const startedAt = monotonicNow();
    let timer;
    try {
      let body;
      try {
        const semanticInput = semanticInputSnapshot(input);
        if (containsString(semanticInput, apiKey)) return failure(INVALID_REQUEST, startedAt);
        body = JSON.stringify({
          model: candidate.model_id,
          messages: buildJudgeMessages(semanticInput),
          temperature: candidate.temperature,
          max_tokens: candidate.max_tokens,
          response_format: { type: candidate.response_format },
          chat_template_kwargs: { enable_thinking: candidate.thinking },
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
            // The deadline still fails closed if abort itself is unavailable.
          }
          resolve(timeoutMarker);
        }, candidate.timeout_ms);
      });

      let response;
      try {
        const issued = fetchImpl(endpoint, {
          method: 'POST',
          redirect: 'error',
          headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body,
          signal: controller.signal,
        });
        if (types.isProxy(issued)) return failure(REQUEST_FAILED, startedAt);
        const request = Promise.resolve(issued);
        response = await Promise.race([request, timeout]);
      } catch {
        return failure(timedOut ? REQUEST_TIMED_OUT : REQUEST_FAILED, startedAt);
      }
      if (response === timeoutMarker) return failure(REQUEST_TIMED_OUT, startedAt);

      const transportResponse = transportResponseSnapshot(response);
      if (transportResponse === null) return failure(REQUEST_FAILED, startedAt);
      if (transportResponse.ok !== true) {
        return failure(
          Number.isInteger(transportResponse.status)
            && transportResponse.status >= 100 && transportResponse.status <= 599
            ? `http ${transportResponse.status}`
            : REQUEST_FAILED,
          startedAt,
        );
      }

      let value;
      try {
        value = await Promise.race([
          Promise.resolve().then(() => transportResponse.parse.call(response)),
          timeout,
        ]);
      } catch {
        return failure(timedOut ? REQUEST_TIMED_OUT : INVALID_RESPONSE, startedAt);
      }
      if (value === timeoutMarker) return failure(REQUEST_TIMED_OUT, startedAt);

      const parsed = parseCandidateResponse(value);
      if (parsed === null || parsed.text.includes(apiKey)) {
        return failure(INVALID_RESPONSE, startedAt);
      }
      return Object.freeze({
        ok: true,
        text: parsed.text,
        latencyMs: latencySince(startedAt),
        usage: parsed.usage,
      });
    } catch {
      return failure(REQUEST_FAILED, startedAt);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  return Object.freeze({ review });
}
