import {
  arrayPrototypeIsPristine,
  objectPrototypeIsPristine,
} from './intrinsics.js';

const DEFAULT_MAX_STRING_LENGTH = 4096;
const REDACTION_LOOKAHEAD = 256;
const REDACTED = '[REDACTED]';
const TRUNCATED = '[TRUNCATED]';
const PRIVATE_KEY_REDACTED = '[REDACTED PRIVATE KEY]';
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN [^-\r\n]*PRIVATE KEY[^-\r\n]*-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY[^-\r\n]*-----/gi;
const PEM_PRIVATE_KEY_HEADER_PATTERN = /-----BEGIN [^-\r\n]*PRIVATE KEY[^-\r\n]*-----/i;
const BEARER_TOKEN_PATTERN = /\bBearer[ \t]+(?!(?:\[REDACTED\]|\[TRUNCATED\]|\[REDACTED PRIVATE KEY\])(?=$|[\s"',;]))[^\s"',;]+/gi;
const CREDENTIAL_BINDING_PATTERN = /([\p{L}_][\p{L}\p{N}_.-]{0,127})["']?[ \t]*[:=]/gu;
const CLI_OPTION_PATTERN = /--([A-Za-z_][A-Za-z0-9_-]{0,127})/g;
const SINGLE_DASH_OPTION_PATTERN = /(?:^|\s)-([A-Za-z_][A-Za-z0-9_-]{1,127})/g;
const URI_USERINFO_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^/\s@]*:[^@\s/]+@/i;
const CURL_COMMAND_PATTERN = /(?:^|[\\/\s])curl(?:\.exe)?(?=$|[\s;|&])/i;
const CURL_USER_OPTION_PATTERN = /(?:^|\s)(?:-u(?:(?:[ \t]*=?[ \t]+)|[^ \t;|&]*:[^ \t;|&]+)|--(?:user|proxy-user)(?![A-Za-z0-9_-])(?:[ \t]*=[ \t]*|[ \t]+))/i;
const SERIALIZED_CONTAINER_PATTERN = /^[\u0009\u000a\u000d\u0020]*[\[{]/u;
const OPAQUE_CREDENTIAL_BINDING_ONLY = /^[\t ]*[\p{L}_][\p{L}\p{N}_.-]{0,127}["']?[\t ]*[:=][\t ]*(?:\[REDACTED\]|\[REDACTED PRIVATE KEY\]|\[TRUNCATED\])[\t ]*$/u;
const SECRET_METADATA_SUFFIXES = new Set([
  'file',
  'path',
  'stdin',
  'env',
  'name',
  'field',
  'ref',
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
  'creds',
  'passphrase',
  'authorization',
  'cookie',
  'пароль',
  'токен',
  'секрет',
  'авторизация',
  'куки',
]);
const COLLAPSED_SECRET_VALUE_PATTERN = /(?:apikey|clientsecret|privatekey|secretaccesskey|password|passwd|secret|credential|credentials|authorization|cookie|accesstoken|refreshtoken|authtoken|idtoken|sessiontoken|serviceaccount|token)(?:value|data|pem|text|raw|content|current|json|string|material|bytes)$/u;
const REDACTION_ERROR_MESSAGES = new Set([
  'cannot redact cyclic value',
  'cannot redact unsupported value',
  'maxStringLength must be a non-negative integer',
]);
const TLS_SECRET_FIELDS = new Set(['ca', 'cert', 'key', 'passphrase']);
const CONFIG_WRITE_ACTIONS = new Set(['config.apply', 'config.patch', 'config.set']);

const ARRAY_CONSTRUCTOR = Array;
const BOOLEAN_CONSTRUCTOR = Boolean;
const SET_CONSTRUCTOR = Set;
const OBJECT_PROTOTYPE = Object.prototype;
const ARRAY_PROTOTYPE = Array.prototype;
const STRING_PROTOTYPE = String.prototype;
const SET_PROTOTYPE = Set.prototype;
const REGEXP_PROTOTYPE = RegExp.prototype;
const ARRAY_IS_ARRAY = Array.isArray;
const JSON_PARSE = JSON.parse;
const NUMBER_IS_FINITE = Number.isFinite;
const NUMBER_IS_INTEGER = Number.isInteger;
const OBJECT_DEFINE_PROPERTY = Object.defineProperty;
const OBJECT_FREEZE = Object.freeze;
const OBJECT_GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const OBJECT_GET_OWN_PROPERTY_DESCRIPTORS = Object.getOwnPropertyDescriptors;
const OBJECT_GET_OWN_PROPERTY_NAMES = Object.getOwnPropertyNames;
const OBJECT_GET_OWN_PROPERTY_SYMBOLS = Object.getOwnPropertySymbols;
const OBJECT_GET_PROTOTYPE_OF = Object.getPrototypeOf;
const OBJECT_HAS_OWN = Object.hasOwn;
const OBJECT_KEYS = Object.keys;
const SET_ADD = Set.prototype.add;
const SET_DELETE = Set.prototype.delete;
const SET_HAS = Set.prototype.has;
const SET_ITERATOR = Set.prototype[Symbol.iterator];
const STRING_ENDS_WITH = String.prototype.endsWith;
const STRING_INCLUDES = String.prototype.includes;
const STRING_REPLACE = String.prototype.replace;
const STRING_SLICE = String.prototype.slice;
const STRING_SPLIT = String.prototype.split;
const STRING_TO_LOWER_CASE = String.prototype.toLowerCase;
const REGEXP_EXEC = RegExp.prototype.exec;
const REGEXP_REPLACE = RegExp.prototype[Symbol.replace];
const REGEXP_SPLIT = RegExp.prototype[Symbol.split];
const REGEXP_TEST = RegExp.prototype.test;

function sameDataProperty(owner, key, expected) {
  try {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(owner, key);
    return descriptor !== undefined
      && OBJECT_HAS_OWN(descriptor, 'value')
      && descriptor.value === expected;
  } catch {
    return false;
  }
}

function provenanceRuntimeIsPristine() {
  try {
    return objectPrototypeIsPristine()
      && arrayPrototypeIsPristine()
      && sameDataProperty(SET_PROTOTYPE, 'add', SET_ADD)
      && sameDataProperty(SET_PROTOTYPE, 'delete', SET_DELETE)
      && sameDataProperty(SET_PROTOTYPE, 'has', SET_HAS)
      && sameDataProperty(SET_PROTOTYPE, Symbol.iterator, SET_ITERATOR)
      && sameDataProperty(STRING_PROTOTYPE, 'endsWith', STRING_ENDS_WITH)
      && sameDataProperty(STRING_PROTOTYPE, 'includes', STRING_INCLUDES)
      && sameDataProperty(STRING_PROTOTYPE, 'replace', STRING_REPLACE)
      && sameDataProperty(STRING_PROTOTYPE, 'slice', STRING_SLICE)
      && sameDataProperty(STRING_PROTOTYPE, 'split', STRING_SPLIT)
      && sameDataProperty(STRING_PROTOTYPE, 'toLowerCase', STRING_TO_LOWER_CASE)
      && sameDataProperty(REGEXP_PROTOTYPE, 'exec', REGEXP_EXEC)
      && sameDataProperty(REGEXP_PROTOTYPE, Symbol.replace, REGEXP_REPLACE)
      && sameDataProperty(REGEXP_PROTOTYPE, Symbol.split, REGEXP_SPLIT)
      && sameDataProperty(REGEXP_PROTOTYPE, 'test', REGEXP_TEST)
      && globalThis.Array === ARRAY_CONSTRUCTOR
      && globalThis.Boolean === BOOLEAN_CONSTRUCTOR
      && globalThis.Set === SET_CONSTRUCTOR
      && Array.isArray === ARRAY_IS_ARRAY
      && JSON.parse === JSON_PARSE
      && Number.isFinite === NUMBER_IS_FINITE
      && Number.isInteger === NUMBER_IS_INTEGER
      && Object.defineProperty === OBJECT_DEFINE_PROPERTY
      && Object.freeze === OBJECT_FREEZE
      && Object.getOwnPropertyDescriptor === OBJECT_GET_OWN_PROPERTY_DESCRIPTOR
      && Object.getOwnPropertyDescriptors === OBJECT_GET_OWN_PROPERTY_DESCRIPTORS
      && Object.getOwnPropertyNames === OBJECT_GET_OWN_PROPERTY_NAMES
      && Object.getOwnPropertySymbols === OBJECT_GET_OWN_PROPERTY_SYMBOLS
      && Object.getPrototypeOf === OBJECT_GET_PROTOTYPE_OF
      && Object.hasOwn === OBJECT_HAS_OWN
      && Object.keys === OBJECT_KEYS
      && Object.prototype === OBJECT_PROTOTYPE
      && Array.prototype === ARRAY_PROTOTYPE;
  } catch {
    return false;
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function isSecretBearingKey(key) {
  if (typeof key !== 'string') return false;
  return isEmbeddedSecretKey(key);
}

function keyParts(key) {
  return key
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((part) => part !== '');
}

function isEmbeddedSecretKey(key) {
  const parts = keyParts(key);
  if (parts.length === 0) return false;
  const collapsed = parts.join('');
  const finalPart = parts.at(-1);
  if (collapsed.endsWith('serviceaccount')) return true;
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
    || collapsed.endsWith('encryptkey')
    || collapsed.endsWith('accesskeyid')
    || collapsed.endsWith('secretaccesskey')
    || collapsed.endsWith('clientsecret')
    || collapsed.endsWith('secret')
    || collapsed.endsWith('authorization')
    || collapsed.endsWith('cookie')
    || collapsed.endsWith('password')
    || collapsed.endsWith('passwd')
    || collapsed.endsWith('credential')
    || collapsed.endsWith('credentials')
    || collapsed.endsWith('serviceaccount')
    || COLLAPSED_SECRET_VALUE_PATTERN.test(collapsed)
    || hasToken;
}

function matchesSecretKey(value, pattern) {
  pattern.lastIndex = 0;
  for (let match = pattern.exec(value); match !== null; match = pattern.exec(value)) {
    if (isSecretBearingKey(match[1])) return true;
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

function lowerPath(path) {
  return path.map((part) => typeof part === 'string' ? part.toLowerCase() : part);
}

function isAuthProfilePath(path) {
  const normalized = lowerPath(path);
  return normalized.length >= 2 && normalized.at(-2) === 'profiles';
}

function isAuthProfilesOAuthPath(path) {
  const normalized = lowerPath(path).slice(-2);
  return normalized.length === 2
    && normalized[0] === 'auth-profiles'
    && normalized[1] === 'oauth';
}

function isProviderTlsPath(path) {
  const normalized = lowerPath(path);
  const direct = normalized.slice(-5);
  if (direct.length === 5
    && direct[0] === 'models'
    && direct[1] === 'providers'
    && direct[3] === 'request'
    && direct[4] === 'tls') return true;
  const proxy = normalized.slice(-6);
  return proxy.length === 6
    && proxy[0] === 'models'
    && proxy[1] === 'providers'
    && proxy[3] === 'request'
    && proxy[4] === 'proxy'
    && proxy[5] === 'tls';
}

function isHookMappingPath(path) {
  const normalized = lowerPath(path).slice(-3);
  return normalized.length === 3
    && normalized[0] === 'hooks'
    && normalized[1] === 'mappings'
    && normalized[2] === '[]';
}

function isContextSecretKey(path, key) {
  const normalizedKey = key.toLowerCase();
  if (normalizedKey === 'key' && isAuthProfilePath(path)) return true;
  if (TLS_SECRET_FIELDS.has(normalizedKey) && isProviderTlsPath(path)) return true;
  return normalizedKey === 'sessionkey' && isHookMappingPath(path);
}

function markOpaque(provenance) {
  if (provenance) provenance.opaque = true;
}

function markSecret(provenance) {
  if (provenance) {
    provenance.secret_redacted = true;
    provenance.opaque = true;
  }
}

function markTruncated(provenance) {
  if (provenance) {
    provenance.truncated = true;
    provenance.opaque = true;
  }
}

function mergeProvenance(target, source) {
  if (!target || !source) return;
  if (source.secret_redacted) target.secret_redacted = true;
  if (source.truncated) target.truncated = true;
  if (source.opaque) target.opaque = true;
}

function serializedJsonRequiresRedaction(value, maxStringLength, provenance) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return false;
  }
  if (parsed === null || typeof parsed !== 'object') return false;
  try {
    const nestedProvenance = provenance === undefined ? undefined : {
      secret_redacted: false,
      truncated: false,
      opaque: false,
    };
    const redacted = redactValue(parsed, maxStringLength, new Set(), [], nestedProvenance);
    const requiresRedaction = containsOpaqueValue(redacted, new Set());
    if (requiresRedaction) mergeProvenance(provenance, nestedProvenance);
    return requiresRedaction;
  } catch {
    markOpaque(provenance);
    return true;
  }
}

function redactEnv(value, maxStringLength, provenance) {
  const { keys } = assertDataObject(value);
  if (keys.some((key) => redactString(key, maxStringLength, provenance) !== key
    || isOpaqueString(key))) {
    markOpaque(provenance);
    return REDACTED;
  }
  const result = {};
  for (const key of keys) {
    defineValue(result, key, REDACTED);
    markOpaque(provenance);
    if (isSecretBearingKey(key)) markSecret(provenance);
  }
  return result;
}

function redactString(value, maxStringLength, provenance) {
  if (isOpaqueString(value)) markOpaque(provenance);
  const truncated = value.length > maxStringLength;
  const alreadyTruncated = truncated
    && value.length === maxStringLength + TRUNCATED.length
    && value.endsWith(TRUNCATED);
  if (truncated && !alreadyTruncated) markTruncated(provenance);
  if (truncated && SERIALIZED_CONTAINER_PATTERN.test(value)) return REDACTED;
  const inspectionLimit = maxStringLength + REDACTION_LOOKAHEAD;
  let sanitized = truncated ? value.slice(0, inspectionLimit) : value;
  const pemRedacted = sanitized.replace(PEM_PRIVATE_KEY_PATTERN, PRIVATE_KEY_REDACTED);
  if (pemRedacted !== sanitized) markSecret(provenance);
  sanitized = pemRedacted;
  if (PEM_PRIVATE_KEY_HEADER_PATTERN.test(sanitized)) {
    sanitized = PRIVATE_KEY_REDACTED;
    markSecret(provenance);
  }
  const bearerRedacted = sanitized.replace(BEARER_TOKEN_PATTERN, 'Bearer [REDACTED]');
  if (bearerRedacted !== sanitized) markSecret(provenance);
  sanitized = bearerRedacted;
  if (containsCredentialBinding(sanitized)) {
    if (OPAQUE_CREDENTIAL_BINDING_ONLY.test(sanitized)) markOpaque(provenance);
    else markSecret(provenance);
    return REDACTED;
  }
  if (!truncated
    && serializedJsonRequiresRedaction(sanitized, maxStringLength, provenance)) {
    markOpaque(provenance);
    return REDACTED;
  }

  if (!truncated && sanitized.length <= maxStringLength) return sanitized;
  return `${sanitized.slice(0, maxStringLength)}${TRUNCATED}`;
}

function redactValue(value, maxStringLength, ancestors, path, provenance) {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return redactString(value, maxStringLength, provenance);
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
        result.push(redactValue(
          descriptor.value,
          maxStringLength,
          ancestors,
          [...path, '[]'],
          provenance,
        ));
      }
      return result;
    }

    const { keys, descriptors } = assertDataObject(value);
    if ((isAuthProfilePath(path) && descriptors.type?.value === 'oauth')
      || isAuthProfilesOAuthPath(path)) {
      markSecret(provenance);
      return REDACTED;
    }
    if (keys.some((key) => redactString(key, maxStringLength, provenance) !== key
      || isOpaqueString(key))) {
      markOpaque(provenance);
      return REDACTED;
    }
    const redactRawConfig = CONFIG_WRITE_ACTIONS.has(descriptors.action?.value);
    const redactConfigValue = descriptors.action?.value === 'config.set';
    const result = {};
    for (const key of keys) {
      let redacted;
      if ((key === 'raw' && redactRawConfig)
        || (key === 'value' && redactConfigValue)) {
        redacted = REDACTED;
        markOpaque(provenance);
      } else if (isSecretBearingKey(key) || isContextSecretKey(path, key)) {
        redacted = REDACTED;
        if (containsOpaqueData(descriptors[key].value)) {
          markOpaque(provenance);
        } else {
          markSecret(provenance);
        }
      } else if (key.toLowerCase() === 'env' || key.toLowerCase() === 'headers') {
        redacted = redactEnv(descriptors[key].value, maxStringLength, provenance);
      } else {
        redacted = redactValue(
          descriptors[key].value,
          maxStringLength,
          ancestors,
          [...path, key],
          provenance,
        );
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
    return redactValue(value, maxStringLength, new Set(), []);
  } catch (error) {
    if (error instanceof TypeError && REDACTION_ERROR_MESSAGES.has(error.message)) throw error;
    throw new TypeError('cannot redact unsupported value');
  }
}

export function redactForJudgeWithProvenance(value, options = {}) {
  try {
    if (!provenanceRuntimeIsPristine()) {
      throw new TypeError('cannot redact unsupported value');
    }
    const { maxStringLength = DEFAULT_MAX_STRING_LENGTH } = options;
    if (!Number.isInteger(maxStringLength) || maxStringLength < 0) {
      throw new TypeError('maxStringLength must be a non-negative integer');
    }
    const provenance = {
      secret_redacted: false,
      truncated: false,
      opaque: false,
    };
    const redacted = redactValue(value, maxStringLength, new Set(), [], provenance);
    return Object.freeze({
      value: redacted,
      secret_redacted: provenance.secret_redacted,
      truncated: provenance.truncated,
      opaque: provenance.opaque || containsOpaqueData(redacted),
    });
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
