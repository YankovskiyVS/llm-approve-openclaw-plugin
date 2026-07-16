import { createHmac, randomBytes } from 'node:crypto';
import { POLICY_VERSION } from './constants.js';
import { objectPrototypeIsPristine } from './intrinsics.js';
import { redactForJudge } from './redact.js';

const ACTION_HASH_KEY = randomBytes(32);

const CANONICAL_ERROR_MESSAGES = new Set([
  'cannot canonicalize cyclic value',
  'cannot canonicalize unsupported value',
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === null
    || prototype === Object.prototype && objectPrototypeIsPristine();
}

function unsupported() {
  throw new TypeError('cannot canonicalize unsupported value');
}

function canonicalize(value, ancestors) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return unsupported();
    return JSON.stringify(value);
  }
  if (typeof value !== 'object') return unsupported();
  if (ancestors.has(value)) throw new TypeError('cannot canonicalize cyclic value');

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getOwnPropertySymbols(value).length > 0) return unsupported();
      if (Object.getOwnPropertyNames(value).length !== value.length + 1) return unsupported();

      const items = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          return unsupported();
        }
        items.push(canonicalize(descriptor.value, ancestors));
      }
      return `[${items.join(',')}]`;
    }

    if (!isPlainObject(value) || Object.getOwnPropertySymbols(value).length > 0) {
      return unsupported();
    }

    const names = Object.getOwnPropertyNames(value);
    const keys = Object.keys(value);
    if (names.length !== keys.length) return unsupported();

    const descriptors = Object.getOwnPropertyDescriptors(value);
    keys.sort();
    const properties = [];
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!Object.hasOwn(descriptor, 'value')) return unsupported();
      properties.push(`${JSON.stringify(key)}:${canonicalize(descriptor.value, ancestors)}`);
    }
    return `{${properties.join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalStringify(value) {
  try {
    return canonicalize(value, new Set());
  } catch (error) {
    if (error instanceof TypeError && CANONICAL_ERROR_MESSAGES.has(error.message)) throw error;
    throw new TypeError('cannot canonicalize unsupported value');
  }
}

function cloneJson(value) {
  return JSON.parse(canonicalStringify(value));
}

export function createAction({ event, ctx }) {
  const context = ctx ?? {};
  return {
    policy_version: POLICY_VERSION,
    tool_name: event?.toolName ?? null,
    params: cloneJson(event?.params),
    agent_id: context.agentId ?? null,
    session_key: context.sessionKey ?? null,
    run_id: event?.runId ?? context.runId ?? null,
    tool_call_id: event?.toolCallId ?? context.toolCallId ?? null,
  };
}

export function computeActionHash(action) {
  const canonical = canonicalStringify(action);
  const digest = createHmac('sha256', ACTION_HASH_KEY).update(canonical, 'utf8').digest('hex');
  return `sha256:${digest}`;
}

export function createJudgeEnvelope(action) {
  return {
    policy_version: action.policy_version,
    action_hash: computeActionHash(action),
    tool_name: action.tool_name,
    params: redactForJudge(action.params),
  };
}
