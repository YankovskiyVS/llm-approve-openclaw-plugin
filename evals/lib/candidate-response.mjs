import { types } from 'node:util';

const MAX_CONTENT_LENGTH = 4096;

function isPlainObject(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || types.isProxy(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function dataField(source, key) {
  try {
    if (!isPlainObject(source)) return { safe: false, present: false, value: undefined };
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (!descriptor) return { safe: true, present: false, value: undefined };
    if (!Object.hasOwn(descriptor, 'value')) {
      return { safe: false, present: true, value: undefined };
    }
    return { safe: true, present: true, value: descriptor.value };
  } catch {
    return { safe: false, present: false, value: undefined };
  }
}

function singleChoice(value) {
  try {
    if (types.isProxy(value) || !Array.isArray(value)
      || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== 2 || !keys.includes('0') || !keys.includes('length')) return null;
    const item = descriptors['0'];
    const length = descriptors.length;
    if (!item.enumerable || !Object.hasOwn(item, 'value')
      || !Object.hasOwn(length, 'value') || length.value !== 1) return null;
    return item.value;
  } catch {
    return null;
  }
}

function optionalTokenDetail(source, objectKey, valueKey) {
  const object = dataField(source, objectKey);
  if (!object.safe) return { valid: false, value: null };
  if (!object.present) return { valid: true, value: null };
  if (!isPlainObject(object.value)) return { valid: false, value: null };

  const token = dataField(object.value, valueKey);
  if (!token.safe) return { valid: false, value: null };
  if (!token.present) return { valid: true, value: null };
  if (!Number.isSafeInteger(token.value) || token.value < 0) {
    return { valid: false, value: null };
  }
  return { valid: true, value: token.value };
}

function usageSnapshot(value) {
  try {
    if (!isPlainObject(value)) return null;
    const prompt = dataField(value, 'prompt_tokens');
    const completion = dataField(value, 'completion_tokens');
    const total = dataField(value, 'total_tokens');
    if (!prompt.safe || !completion.safe || !total.safe
      || !Number.isSafeInteger(prompt.value) || prompt.value < 0
      || !Number.isSafeInteger(completion.value) || completion.value < 0
      || !Number.isSafeInteger(total.value) || total.value < 0
      || prompt.value + completion.value !== total.value) return null;

    const reasoning = optionalTokenDetail(
      value,
      'completion_tokens_details',
      'reasoning_tokens',
    );
    const cached = optionalTokenDetail(value, 'prompt_tokens_details', 'cached_tokens');
    if (!reasoning.valid || !cached.valid
      || (reasoning.value !== null && reasoning.value > completion.value)
      || (cached.value !== null && cached.value > prompt.value)) return null;

    return Object.freeze({
      promptTokens: prompt.value,
      completionTokens: completion.value,
      totalTokens: total.value,
      reasoningTokens: reasoning.value,
      cachedPromptTokens: cached.value,
    });
  } catch {
    return null;
  }
}

export function parseCandidateResponse(value) {
  try {
    if (!isPlainObject(value)) return null;
    const choices = dataField(value, 'choices');
    if (!choices.safe || !choices.present) return null;
    const choice = singleChoice(choices.value);
    if (!isPlainObject(choice)) return null;

    const finishReason = dataField(choice, 'finish_reason');
    const message = dataField(choice, 'message');
    if (!finishReason.safe || finishReason.value !== 'stop'
      || !message.safe || !message.present || !isPlainObject(message.value)) return null;

    const content = dataField(message.value, 'content');
    if (!content.safe || !content.present || typeof content.value !== 'string'
      || content.value.trim() === '' || content.value.length > MAX_CONTENT_LENGTH) return null;

    const usage = dataField(value, 'usage');
    const sanitizedUsage = usage.safe && usage.present ? usageSnapshot(usage.value) : null;
    return Object.freeze({ text: content.value, usage: sanitizedUsage });
  } catch {
    return null;
  }
}
