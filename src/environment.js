import os from 'node:os';
import path from 'node:path';
import { types } from 'node:util';
import { parseConfig } from './config.js';
import {
  CLOUDRU_BASE_URL,
  JUDGE_TIMEOUT_MS,
  MAX_JUDGE_TIMEOUT_MS,
  MIN_JUDGE_TIMEOUT_MS,
} from './constants.js';

const INVALID_CONFIGURATION = 'invalid judge environment configuration';
const JUDGE_PREFIX = 'OPENCLAW_JUDGE_';
const STATE_DIR_NAME = 'OPENCLAW_STATE_DIR';
const ENV_NAMES = Object.freeze({
  apiKey: 'OPENCLAW_JUDGE_API_KEY',
  profile: 'OPENCLAW_JUDGE_PROFILE',
  baseUrl: 'OPENCLAW_JUDGE_BASE_URL',
  timeout: 'OPENCLAW_JUDGE_TIMEOUT_MS',
  auditPath: 'OPENCLAW_JUDGE_AUDIT_PATH',
  logLevel: 'OPENCLAW_JUDGE_LOG_LEVEL',
  a2aHitlReplace: 'OPENCLAW_JUDGE_A2A_HITL_REPLACE',
});
const ALLOWED_JUDGE_NAMES = new Set(Object.values(ENV_NAMES));
const POLICY_ENV_NAMES = new Set([
  ENV_NAMES.profile,
  ENV_NAMES.auditPath,
  STATE_DIR_NAME,
]);
const A2A_HITL_REPLACE_VALUES = new Set(['0', '1', 'true', 'false']);
const PROFILE_CONFIG = Object.freeze({
  shadow: Object.freeze({ mode: 'autonomous', enforcement: 'shadow' }),
  supervised: Object.freeze({ mode: 'supervised', enforcement: 'enforce' }),
  autonomous: Object.freeze({ mode: 'autonomous', enforcement: 'enforce' }),
});
const LOG_LEVELS = new Set(['error', 'warn', 'info', 'silent']);
const PRINTABLE_ASCII = /^[\x21-\x7e]{1,4096}$/u;
const CANONICAL_INTEGER = /^[1-9][0-9]*$/u;

function invalidConfiguration() {
  throw new TypeError(INVALID_CONFIGURATION);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function ownDataValue(source, key) {
  const descriptor = Object.getOwnPropertyDescriptor(source, key);
  if (!descriptor) return { present: false, value: undefined };
  if (!Object.hasOwn(descriptor, 'value')) return invalidConfiguration();
  return { present: true, value: descriptor.value };
}

function snapshotEnvironment(environment) {
  if (!isObject(environment) || types.isProxy(environment)) return invalidConfiguration();
  if (Object.getOwnPropertySymbols(environment).length !== 0) return invalidConfiguration();

  const snapshot = Object.create(null);
  for (const name of Object.getOwnPropertyNames(environment)) {
    if (name.startsWith(JUDGE_PREFIX) && !ALLOWED_JUDGE_NAMES.has(name)) {
      return invalidConfiguration();
    }
    if (!ALLOWED_JUDGE_NAMES.has(name) && name !== STATE_DIR_NAME) continue;
    const field = ownDataValue(environment, name);
    if (!field.present || typeof field.value !== 'string') return invalidConfiguration();
    snapshot[name] = field.value;
  }
  return Object.freeze(snapshot);
}

function snapshotPolicyEnvironment(environment) {
  if (!isObject(environment) || types.isProxy(environment)) return invalidConfiguration();
  if (Object.getOwnPropertySymbols(environment).length !== 0) return invalidConfiguration();
  const snapshot = Object.create(null);
  for (const name of Object.getOwnPropertyNames(environment)) {
    if (!POLICY_ENV_NAMES.has(name)) continue;
    const field = ownDataValue(environment, name);
    if (!field.present || typeof field.value !== 'string') return invalidConfiguration();
    snapshot[name] = field.value;
  }
  return Object.freeze(snapshot);
}

function validatedPluginConfig(pluginConfig) {
  try {
    if (pluginConfig === undefined) {
      const config = parseConfig(undefined);
      return Object.freeze({ mode: config.mode, enforcement: config.enforcement });
    }
    if (!isObject(pluginConfig) || types.isProxy(pluginConfig)
      || Object.getOwnPropertySymbols(pluginConfig).length !== 0) {
      return invalidConfiguration();
    }
    const prototype = Object.getPrototypeOf(pluginConfig);
    if (prototype !== Object.prototype && prototype !== null) return invalidConfiguration();

    const snapshot = {};
    for (const key of Object.getOwnPropertyNames(pluginConfig)) {
      if (key !== 'mode' && key !== 'enforcement') return invalidConfiguration();
      const descriptor = Object.getOwnPropertyDescriptor(pluginConfig, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return invalidConfiguration();
      }
      snapshot[key] = descriptor.value;
    }
    const config = parseConfig(snapshot);
    return Object.freeze({ mode: config.mode, enforcement: config.enforcement });
  } catch {
    return invalidConfiguration();
  }
}

function explicitValue(environment, name) {
  return Object.hasOwn(environment, name) ? environment[name] : undefined;
}

function validApiKey(value) {
  return typeof value === 'string' && PRINTABLE_ASCII.test(value);
}

function providerSnapshot(value) {
  if (!isObject(value) || types.isProxy(value)
    || Object.getOwnPropertySymbols(value).length !== 0) return invalidConfiguration();
  const baseUrl = ownDataValue(value, 'baseUrl');
  const apiKey = ownDataValue(value, 'apiKey');
  if (!baseUrl.present || baseUrl.value !== CLOUDRU_BASE_URL
    || !apiKey.present || !validApiKey(apiKey.value)) return invalidConfiguration();
  return Object.freeze({ baseUrl: CLOUDRU_BASE_URL, apiKey: apiKey.value });
}

function hasParentSegment(value) {
  return value.split(/[\\/]/u).includes('..');
}

function absoluteDirectory(value) {
  if (typeof value !== 'string' || value === '' || value.includes('\0')
    || !path.isAbsolute(value) || hasParentSegment(value)) return invalidConfiguration();
  return path.resolve(value);
}

function resolveAudit(environment, homeDirectory) {
  const stateValue = explicitValue(environment, STATE_DIR_NAME);
  const home = absoluteDirectory(homeDirectory);
  const stateDirectory = stateValue === undefined
    ? path.join(home, '.openclaw')
    : absoluteDirectory(stateValue);
  const auditRoot = path.join(stateDirectory, 'logs');
  const explicitPath = explicitValue(environment, ENV_NAMES.auditPath);
  const auditPath = explicitPath === undefined
    ? path.join(auditRoot, 'llm-action-judge.jsonl')
    : explicitPath;

  if (typeof auditPath !== 'string' || auditPath === '' || auditPath.includes('\0')
    || !path.isAbsolute(auditPath) || hasParentSegment(auditPath)
    || !auditPath.endsWith('.jsonl')) return invalidConfiguration();

  const normalizedPath = path.resolve(auditPath);
  const relative = path.relative(auditRoot, normalizedPath);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)) return invalidConfiguration();
  return Object.freeze({ auditRoot, auditPath: normalizedPath });
}

function resolveTimeout(environment) {
  const value = explicitValue(environment, ENV_NAMES.timeout);
  if (value === undefined) return JUDGE_TIMEOUT_MS;
  if (!CANONICAL_INTEGER.test(value)) return invalidConfiguration();
  const timeoutMs = Number(value);
  if (!Number.isSafeInteger(timeoutMs)
    || timeoutMs < MIN_JUDGE_TIMEOUT_MS
    || timeoutMs > MAX_JUDGE_TIMEOUT_MS) return invalidConfiguration();
  return timeoutMs;
}

function resolveLogLevel(environment) {
  const value = explicitValue(environment, ENV_NAMES.logLevel);
  if (value === undefined) return 'info';
  return LOG_LEVELS.has(value) ? value : invalidConfiguration();
}

function resolveA2AHitlReplace(environment) {
  const value = explicitValue(environment, ENV_NAMES.a2aHitlReplace);
  if (value === undefined) return false;
  if (!A2A_HITL_REPLACE_VALUES.has(value.toLowerCase())) return invalidConfiguration();
  const normalized = value.toLowerCase();
  return normalized === '1' || normalized === 'true';
}

function resolveProvider(environment, getSharedProvider) {
  const apiKey = explicitValue(environment, ENV_NAMES.apiKey);
  const baseUrl = explicitValue(environment, ENV_NAMES.baseUrl);
  if (apiKey !== undefined) {
    if (!validApiKey(apiKey)) return invalidConfiguration();
    if (baseUrl !== undefined && baseUrl !== CLOUDRU_BASE_URL) return invalidConfiguration();
    return Object.freeze({
      providerConfig: Object.freeze({ baseUrl: CLOUDRU_BASE_URL, apiKey }),
      credentialSource: 'environment',
    });
  }
  if (baseUrl !== undefined || typeof getSharedProvider !== 'function'
    || types.isProxy(getSharedProvider)) return invalidConfiguration();
  return Object.freeze({
    providerConfig: providerSnapshot(getSharedProvider()),
    credentialSource: 'shared-provider',
  });
}

export function resolvePolicySettings(options = {}) {
  try {
    if (!isObject(options) || types.isProxy(options)
      || Object.getOwnPropertySymbols(options).length !== 0) return invalidConfiguration();
    const environmentField = ownDataValue(options, 'environment');
    const pluginConfigField = ownDataValue(options, 'pluginConfig');
    const homeField = ownDataValue(options, 'homeDirectory');
    const environment = snapshotPolicyEnvironment(
      environmentField.present ? environmentField.value : process.env,
    );
    const legacyConfig = validatedPluginConfig(
      pluginConfigField.present ? pluginConfigField.value : undefined,
    );
    const profile = explicitValue(environment, ENV_NAMES.profile);
    const config = profile === undefined
      ? legacyConfig
      : (Object.hasOwn(PROFILE_CONFIG, profile) ? PROFILE_CONFIG[profile] : undefined);
    if (config === undefined) return invalidConfiguration();
    const homeDirectory = homeField.present ? homeField.value : os.homedir();
    const audit = resolveAudit(environment, homeDirectory);
    return Object.freeze({
      config: Object.freeze({ mode: config.mode, enforcement: config.enforcement }),
      auditPath: audit.auditPath,
      auditRoot: audit.auditRoot,
    });
  } catch {
    return invalidConfiguration();
  }
}

export function resolveRuntimeSettings(options = {}) {
  try {
    if (!isObject(options) || types.isProxy(options)
      || Object.getOwnPropertySymbols(options).length !== 0) return invalidConfiguration();
    const environmentField = ownDataValue(options, 'environment');
    const pluginConfigField = ownDataValue(options, 'pluginConfig');
    const providerField = ownDataValue(options, 'getSharedProvider');
    const homeField = ownDataValue(options, 'homeDirectory');

    const environment = snapshotEnvironment(
      environmentField.present ? environmentField.value : process.env,
    );
    const legacyConfig = validatedPluginConfig(
      pluginConfigField.present ? pluginConfigField.value : undefined,
    );
    const profile = explicitValue(environment, ENV_NAMES.profile);
    const config = profile === undefined
      ? legacyConfig
      : (Object.hasOwn(PROFILE_CONFIG, profile) ? PROFILE_CONFIG[profile] : undefined);
    if (config === undefined) return invalidConfiguration();

    const provider = resolveProvider(
      environment,
      providerField.present ? providerField.value : undefined,
    );
    const homeDirectory = homeField.present ? homeField.value : os.homedir();
    const audit = resolveAudit(environment, homeDirectory);

    return Object.freeze({
      config: Object.freeze({ mode: config.mode, enforcement: config.enforcement }),
      providerConfig: provider.providerConfig,
      credentialSource: provider.credentialSource,
      timeoutMs: resolveTimeout(environment),
      auditPath: audit.auditPath,
      auditRoot: audit.auditRoot,
      logLevel: resolveLogLevel(environment),
      a2aHitlReplace: resolveA2AHitlReplace(environment),
    });
  } catch {
    return invalidConfiguration();
  }
}
