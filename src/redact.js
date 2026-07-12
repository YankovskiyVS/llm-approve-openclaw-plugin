const DEFAULT_MAX_STRING_LENGTH = 4096;
const REDACTION_LOOKAHEAD = 256;
const REDACTED = '[REDACTED]';
const TRUNCATED = '[TRUNCATED]';
const PRIVATE_KEY_REDACTED = '[REDACTED PRIVATE KEY]';
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN [^-\r\n]*PRIVATE KEY[^-\r\n]*-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY[^-\r\n]*-----/gi;
const PEM_PRIVATE_KEY_HEADER_PATTERN = /-----BEGIN [^-\r\n]*PRIVATE KEY[^-\r\n]*-----/i;
const BEARER_TOKEN_PATTERN = /\bBearer[ \t]+[^\s"',;]+/gi;
const CREDENTIAL_BINDING_PATTERN = /([\p{L}_][\p{L}\p{N}_.-]{0,127})["']?[ \t]*[:=]/gu;
const CLI_OPTION_PATTERN = /--([A-Za-z_][A-Za-z0-9_-]{0,127})/g;
const SINGLE_DASH_OPTION_PATTERN = /(?:^|\s)-([A-Za-z_][A-Za-z0-9_-]{1,127})/g;
const URI_USERINFO_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^/\s@]*:[^@\s/]+@/i;
const CURL_COMMAND_PATTERN = /(?:^|[\\/\s])curl(?:\.exe)?(?=$|[\s;|&])/i;
const CURL_USER_OPTION_PATTERN = /(?:^|\s)(?:-u(?:(?:[ \t]*=?[ \t]+)|[^ \t;|&]*:[^ \t;|&]+)|--(?:user|proxy-user)(?![A-Za-z0-9_-])(?:[ \t]*=[ \t]*|[ \t]+))/i;
const SECRET_METADATA_SUFFIXES = new Set([
  'file',
  'path',
  'stdin',
  'env',
  'name',
  'field',
  'type',
  'required',
  'enabled',
  'mode',
  'policy',
  'version',
  'count',
  'budget',
  'limit',
  'server',
  'endpoint',
  'url',
  'uri',
  'scheme',
]);
const TOKEN_METADATA_PARTS = new Set([
  'max',
  'min',
  'count',
  'budget',
  'limit',
  'input',
  'output',
  'context',
  'prompt',
  'completion',
  'total',
  'usage',
]);
const SECRET_COMPONENTS = new Set([
  'token',
  'tokens',
  'password',
  'passwd',
  'pwd',
  'secret',
  'credential',
  'credentials',
  'authorization',
  'cookie',
  'пароль',
  'токен',
  'секрет',
  'авторизация',
  'куки',
]);
const COLLAPSED_SECRET_VALUE_PATTERN = /(?:apikey|clientsecret|privatekey|secretaccesskey|password|passwd|secret|credential|credentials|authorization|cookie|accesstoken|refreshtoken|authtoken|idtoken|sessiontoken|token)(?:value|data|pem|text|raw|content|current|json|string|material|bytes)$/u;
const REDACTION_ERROR_MESSAGES = new Set([
  'cannot redact cyclic value',
  'cannot redact unsupported value',
  'maxStringLength must be a non-negative integer',
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isSecretKey(key) {
  return isEmbeddedSecretKey(key);
}

function keyParts(key) {
  return key
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
}

function isEmbeddedSecretKey(key) {
  const parts = keyParts(key);
  if (parts.length === 0) return false;
  const collapsed = parts.join('');
  const finalPart = parts.at(-1);
  if (SECRET_METADATA_SUFFIXES.has(finalPart)
    || [...SECRET_METADATA_SUFFIXES].some((suffix) => collapsed.endsWith(suffix))) {
    return false;
  }

  const hasToken = parts.includes('token')
    || parts.includes('tokens')
    || collapsed.endsWith('token')
    || collapsed.endsWith('tokens');
  const pluralToken = parts.includes('tokens') || collapsed.endsWith('tokens');
  const explicitTokenMetadata = parts.some((part) => (
    part === 'max'
    || part === 'min'
    || part === 'count'
    || part === 'budget'
    || part === 'limit'
    || part === 'usage'
    || part === 'total'
  ));
  if (hasToken
    && (pluralToken || explicitTokenMetadata)
    && parts.every((part) => (
      part === 'token' || part === 'tokens' || TOKEN_METADATA_PARTS.has(part)
    ))) {
    return false;
  }

  if (parts.some((part) => SECRET_COMPONENTS.has(part))) return true;
  if (parts.some((part, index) => part === 'api' && parts[index + 1] === 'key')) return true;
  if (parts.some((part, index) => part === 'private' && parts[index + 1] === 'key')) return true;
  return collapsed.endsWith('apikey')
    || collapsed.endsWith('privatekey')
    || collapsed.endsWith('accesskeyid')
    || collapsed.endsWith('secretaccesskey')
    || collapsed.endsWith('clientsecret')
    || collapsed.endsWith('authorization')
    || collapsed.endsWith('cookie')
    || collapsed.endsWith('password')
    || collapsed.endsWith('passwd')
    || collapsed.endsWith('credential')
    || collapsed.endsWith('credentials')
    || COLLAPSED_SECRET_VALUE_PATTERN.test(collapsed)
    || hasToken;
}

function matchesSecretKey(value, pattern) {
  pattern.lastIndex = 0;
  for (let match = pattern.exec(value); match !== null; match = pattern.exec(value)) {
    if (isEmbeddedSecretKey(match[1])) return true;
  }
  return false;
}

function containsCredentialBinding(value) {
  const normalizedQuotes = value.replace(/["'`]/g, '');
  const normalizedOptions = normalizedQuotes.replace(/\\/g, '');
  if (matchesSecretKey(value, CREDENTIAL_BINDING_PATTERN)
    || matchesSecretKey(normalizedOptions, CLI_OPTION_PATTERN)
    || matchesSecretKey(normalizedOptions, SINGLE_DASH_OPTION_PATTERN)
    || URI_USERINFO_PATTERN.test(value)) return true;

  const curl = CURL_COMMAND_PATTERN.exec(normalizedQuotes);
  CURL_COMMAND_PATTERN.lastIndex = 0;
  if (curl === null) return false;
  const normalizedSuffix = normalizedQuotes
    .slice(curl.index + curl[0].length)
    .replace(/\\/g, '');
  return CURL_USER_OPTION_PATTERN.test(normalizedSuffix);
}

function defineValue(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

function assertDataObject(value) {
  if (!isPlainObject(value) || Object.getOwnPropertySymbols(value).length > 0) {
    throw new TypeError('cannot redact unsupported value');
  }

  const names = Object.getOwnPropertyNames(value);
  const keys = Object.keys(value);
  if (names.length !== keys.length) {
    throw new TypeError('cannot redact unsupported value');
  }

  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of keys) {
    if (!Object.hasOwn(descriptors[key], 'value')) {
      throw new TypeError('cannot redact unsupported value');
    }
  }
  return { keys, descriptors };
}

function isOpaqueString(value) {
  return value.includes(REDACTED)
    || value.includes(PRIVATE_KEY_REDACTED)
    || value.includes(TRUNCATED);
}

function redactEnv(value, maxStringLength) {
  const { keys } = assertDataObject(value);
  if (keys.some((key) => redactString(key, maxStringLength) !== key || isOpaqueString(key))) {
    return REDACTED;
  }
  const result = {};
  for (const key of keys) defineValue(result, key, REDACTED);
  return result;
}

function redactString(value, maxStringLength) {
  const truncated = value.length > maxStringLength;
  const inspectionLimit = maxStringLength + REDACTION_LOOKAHEAD;
  let sanitized = (truncated ? value.slice(0, inspectionLimit) : value)
    .replace(PEM_PRIVATE_KEY_PATTERN, PRIVATE_KEY_REDACTED);
  if (PEM_PRIVATE_KEY_HEADER_PATTERN.test(sanitized)) sanitized = PRIVATE_KEY_REDACTED;
  sanitized = sanitized.replace(BEARER_TOKEN_PATTERN, 'Bearer [REDACTED]');
  if (containsCredentialBinding(sanitized)) return REDACTED;

  if (!truncated && sanitized.length <= maxStringLength) return sanitized;
  return `${sanitized.slice(0, maxStringLength)}${TRUNCATED}`;
}

function redactValue(value, maxStringLength, ancestors) {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return redactString(value, maxStringLength);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('cannot redact unsupported value');
    return value;
  }
  if (typeof value !== 'object') throw new TypeError('cannot redact unsupported value');
  if (ancestors.has(value)) throw new TypeError('cannot redact cyclic value');

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getOwnPropertySymbols(value).length > 0) {
        throw new TypeError('cannot redact unsupported value');
      }

      const ownNames = Object.getOwnPropertyNames(value);
      if (ownNames.length !== value.length + 1) {
        throw new TypeError('cannot redact unsupported value');
      }

      const result = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          throw new TypeError('cannot redact unsupported value');
        }
        result.push(redactValue(descriptor.value, maxStringLength, ancestors));
      }
      return result;
    }

    const { keys, descriptors } = assertDataObject(value);
    if (keys.some((key) => redactString(key, maxStringLength) !== key || isOpaqueString(key))) {
      return REDACTED;
    }
    const result = {};
    for (const key of keys) {
      let redacted;
      if (isSecretKey(key)) {
        redacted = REDACTED;
      } else if (key.toLowerCase() === 'env') {
        redacted = redactEnv(descriptors[key].value, maxStringLength);
      } else {
        redacted = redactValue(descriptors[key].value, maxStringLength, ancestors);
      }
      defineValue(result, key, redacted);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

export function redactForJudge(value, options = {}) {
  try {
    const { maxStringLength = DEFAULT_MAX_STRING_LENGTH } = options;
    if (!Number.isInteger(maxStringLength) || maxStringLength < 0) {
      throw new TypeError('maxStringLength must be a non-negative integer');
    }
    return redactValue(value, maxStringLength, new Set());
  } catch (error) {
    if (error instanceof TypeError && REDACTION_ERROR_MESSAGES.has(error.message)) throw error;
    throw new TypeError('cannot redact unsupported value');
  }
}

function containsOpaqueValue(value, ancestors) {
  if (typeof value === 'string') {
    return isOpaqueString(value);
  }
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return false;
  if (typeof value !== 'object' || ancestors.has(value)) return true;

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getOwnPropertySymbols(value).length > 0
        || Object.getOwnPropertyNames(value).length !== value.length + 1) return true;
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return true;
        if (containsOpaqueValue(descriptor.value, ancestors)) return true;
      }
      return false;
    }

    const { keys, descriptors } = assertDataObject(value);
    return keys.some((key) => containsOpaqueValue(descriptors[key].value, ancestors));
  } catch {
    return true;
  } finally {
    ancestors.delete(value);
  }
}

export function containsOpaqueData(value) {
  return containsOpaqueValue(value, new Set());
}
