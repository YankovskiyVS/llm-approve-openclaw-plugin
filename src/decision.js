import { types as utilTypes } from 'node:util';
import { BlockList, isIP } from 'node:net';
import { posix as pathPosix } from 'node:path';
import {
  APPROVAL_TIMEOUT_MS,
  MIN_CONFIDENCE,
  PLUGIN_ID,
  POLICY_VERSION,
} from './constants.js';
import {
  JUDGE_DECISIONS,
  validateJudgeVerdict,
} from './judge-schema.js';
import { containsOpaqueData, isSecretBearingKey } from './redact.js';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const DECISION_SET = new Set(JUDGE_DECISIONS);
const INVALID_RESPONSE_REASON = 'invalid judge response';
const DENY_BLOCK_REASON = 'LLM action judge denied the tool call';
const REVIEW_BLOCK_REASON = 'LLM action judge review required';
const APPROVAL_DESCRIPTION = 'LLM action judge could not safely allow this tool call. Approve this call once to continue.';
const LOCAL_GUARD_REASON = 'local safety guard requires human review';
const INVALID_LOCAL_GUARD_REASON = 'invalid local safety gate input';
const READ_ONLY_CRON_ACTIONS = new Set(['list', 'status', 'get', 'runs']);
const READ_ONLY_PROCESS_ACTIONS = new Set(['list', 'poll', 'log']);
const READ_ONLY_MESSAGE_ACTIONS = new Set([
  'channel-info',
  'channel-list',
  'emoji-list',
  'event-list',
  'list-pins',
  'member-info',
  'reactions',
  'read',
  'role-info',
  'search',
  'thread-list',
  'voice-status',
]);
const FILE_WRITE_TOOLS = new Set(['write', 'edit', 'apply_patch']);
const ACTIVE_REGISTRY_CONFIGS = new Set([
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
]);
const SECURITY_PATH_SEGMENTS = new Set([
  'acl',
  'auth',
  'iam',
  'oauth',
  'rbac',
  'security',
]);
const SECURITY_POLICY_FILE = /^(?:acl|config|permissions|policy|rbac|roles?|rules|scopes|session|settings|token)(?:\.(?:spec|test))?(?:\.(?:c|cc|cpp|cs|go|java|js|jsx|json|kt|kts|php|py|rb|rs|sh|toml|ts|tsx|ya?ml))?$/u;
const DEVCONTAINER_LIFECYCLE_FILE = /^(?:initialize|oncreate|postattach|postcreate|poststart|updatecontent|waitfor)(?:[._-].*)?$/u;
const ACTIVE_GIT_HOOKS = new Set([
  'applypatch-msg',
  'commit-msg',
  'fsmonitor-watchman',
  'p4-changelist',
  'p4-post-changelist',
  'p4-prepare-changelist',
  'p4-pre-submit',
  'post-applypatch',
  'post-checkout',
  'post-commit',
  'post-index-change',
  'post-merge',
  'post-receive',
  'post-rewrite',
  'post-update',
  'pre-applypatch',
  'pre-auto-gc',
  'pre-commit',
  'pre-merge-commit',
  'pre-push',
  'pre-rebase',
  'pre-receive',
  'prepare-commit-msg',
  'proc-receive',
  'push-to-checkout',
  'reference-transaction',
  'sendemail-validate',
  'update',
]);
const PATCH_FILE_HEADER = /^\*\*\* (?:Add|Delete|Update) File: (.+)$/u;
const PATCH_MOVE_HEADER = /^\*\*\* Move to: (.+)$/u;
const LOCAL_ACTION_KEYS = new Set([
  'policy_version',
  'tool_name',
  'params',
  'agent_id',
  'session_key',
  'run_id',
  'tool_call_id',
]);
const INERT_TEMPLATE_NAME = /(?:^|[._-])(?:example|sample|template|tmpl)(?:\.(?:conf|ini|json|toml|ya?ml))?$/u;
const DOCUMENTATION_FILE = /\.(?:adoc|markdown|md|rst)$/u;
const ENV_FILE = /^\.env(?:\..+)?$/u;
const ENVRC_FILE = /^\.envrc(?:\..+)?$/u;
const PRIVATE_KEY_FILE = /^(?:id_(?:dsa|ecdsa|ed25519|rsa)|.*(?:private[._-]?key|privkey).*)$/u;
const PRIVATE_KEY_EXTENSION = /\.(?:jks|key|p12|pfx)$/u;
const PRIVATE_PEM_FILE = /^(?:key|private)\.pem$/u;
const PUBLIC_KEY_FILE = /^(?:id_(?:dsa|ecdsa|ed25519|rsa)(?:-cert)?|.*(?:public[._-]?key|pubkey).*)\.pub$/u;
const CREDENTIAL_NAME = /(?:^|[._-])(?:access[._-]?tokens?|api[._-]?keys?|bearers?|client[._-]?secrets?|cookies?|credentials?|passwords?|passwd|secrets?|tokens?)(?:[._-]|$)/u;
const SENSITIVE_READ_FILES = new Set([
  '.netrc',
  '.npmrc',
  '.pgpass',
  '.pypirc',
  '.yarnrc',
  '.yarnrc.yml',
  'credentials',
  'credentials.json',
  'kubeconfig',
  'service-account.json',
  'service_account.json',
]);
const SENSITIVE_READ_DIRECTORIES = new Set([
  '.direnv',
  '.kube',
  '.ssh',
  'credentials',
  'secrets',
  'vault',
]);
const SAFE_CONFIG_METADATA_COMPONENTS = new Set([
  'apikeypath',
  'baseurl',
  'count',
  'enabled',
  'endpoint',
  'envfile',
  'maxtoken',
  'maxtokens',
  'model',
  'passwordfile',
  'secretpath',
  'thinkingdefault',
  'tokenbudget',
  'tokencount',
  'tokenlimit',
  'tokenusage',
  'timeoutms',
]);
const SHADOW_DATABASE_FILE = /^(?:g?shadow)(?:-|~|\.(?:bak|backup|old|\d+))?$/u;
const MASTER_PASSWD_FILE = /^master\.passwd(?:-|~|\.(?:bak|backup|old|\d+))?$/u;
const SSH_HOST_PRIVATE_KEY = /^ssh_host_[^/]+_key(?:-|~|\.(?:bak|backup|old|\d+))?$/u;
const SSH_HOST_PUBLIC_KEY_PATH = /^\/(?:private\/)?etc\/ssh\/ssh_host_[^/]+_key\.pub$/u;
const KUBERNETES_CREDENTIAL_CONFIG = /^(?:[^/]*admin|bootstrap-kubelet|cluster|controller-manager|kubelet|scheduler)\.conf$/u;
const OPENCLAW_ROOT_CONFIG = /^openclaw\.json(?:~|\.(?:bak(?:\.\d+)?|backup|last-good|old|\d+))?$/u;
const OPENCLAW_AUTH_STORE = /^(?:auth|auth-profiles|auth-state)\.json(?:~|\.(?:bak(?:\.\d+)?|backup|old|\d+))?$/u;
const OPENCLAW_IDENTITY_STORE = /^(?:device|device-auth)\.json(?:~|\.(?:bak(?:\.\d+)?|backup|old|\d+))?$/u;
const OPENCLAW_PAIRING_STORE = /^(?:paired|pending)\.json(?:~|\.(?:bak(?:\.\d+)?|backup|old|\d+))?$/u;
const SHELL_SCAN_MAX_LENGTH = 16_384;
const SHELL_SCAN_MAX_COMMANDS = 128;
const SHELL_SCAN_MAX_TOKENS = 1_024;
const SHELL_INTERPRETERS = new Set([
  'bash',
  'dash',
  'fish',
  'ksh',
  'powershell',
  'pwsh',
  'sh',
  'zsh',
]);
const INLINE_INTERPRETERS = new Set(['node', 'nodejs', 'perl', 'python', 'python3', 'ruby']);
const DELETE_COMMANDS = new Set(['rm', 'rmdir', 'shred', 'unlink']);
const PERMISSION_COMMANDS = new Set(['chgrp', 'chmod', 'chown']);
const INTERNAL_HOST_SUFFIXES = [
  '.internal',
  '.local',
  '.localdomain',
  '.lan',
  '.localhost',
  '.corp',
  '.svc',
];
const INTERNAL_NETWORKS = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]) {
  INTERNAL_NETWORKS.addSubnet(network, prefix, 'ipv4');
  INTERNAL_NETWORKS.addSubnet(`::ffff:${network}`, 96 + prefix, 'ipv6');
}
for (const [network, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
]) INTERNAL_NETWORKS.addSubnet(network, prefix, 'ipv6');

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalidResponse() {
  return { ok: false, reason: INVALID_RESPONSE_REASON };
}

function skipWhitespace(source, index) {
  let next = index;
  while (next < source.length && /[\u0009\u000a\u000d\u0020]/u.test(source[next])) {
    next += 1;
  }
  return next;
}

function scanString(source, index) {
  let next = index + 1;
  while (next < source.length) {
    if (source[next] === '\\') {
      next += 2;
      continue;
    }
    if (source[next] === '"') return next + 1;
    next += 1;
  }
  return -1;
}

function scanTopLevelValue(source, index) {
  let next = index;
  let depth = 0;
  while (next < source.length) {
    const character = source[next];
    if (character === '"') {
      next = scanString(source, next);
      if (next < 0) return -1;
      continue;
    }
    if (character === '{' || character === '[') {
      depth += 1;
    } else if (character === '}' || character === ']') {
      if (character === '}' && depth === 0) return next;
      depth -= 1;
    } else if (character === ',' && depth === 0) {
      return next;
    }
    next += 1;
  }
  return -1;
}

function hasDuplicateTopLevelKeys(source) {
  const seen = new Set();
  let index = skipWhitespace(source, 1);
  if (source[index] === '}') return false;

  while (index < source.length) {
    if (source[index] !== '"') return true;
    const end = scanString(source, index);
    if (end < 0) return true;
    const key = JSON.parse(source.slice(index, end));
    if (seen.has(key)) return true;
    seen.add(key);

    index = skipWhitespace(source, end);
    if (source[index] !== ':') return true;
    index = skipWhitespace(source, index + 1);
    index = scanTopLevelValue(source, index);
    if (index < 0) return true;
    if (source[index] === '}') return false;
    index = skipWhitespace(source, index + 1);
  }
  return true;
}

export function parseJudgeResponse(text, options = {}) {
  try {
    const expectedHash = options?.expectedHash;
    if (typeof text !== 'string' || typeof expectedHash !== 'string') {
      return invalidResponse();
    }
    if (!HASH_PATTERN.test(expectedHash)) return invalidResponse();

    const source = text.trim();
    if (!source.startsWith('{') || !source.endsWith('}')) return invalidResponse();
    if (hasDuplicateTopLevelKeys(source)) return invalidResponse();

    const parsed = JSON.parse(source);
    if (!isPlainObject(parsed)) return invalidResponse();
    validateJudgeVerdict(parsed);
    if (parsed.action_hash !== expectedHash) return invalidResponse();
    if (!parsed.rationale.trim()
      || parsed.rationale.length > 500
      || CONTROL_PATTERN.test(parsed.rationale)) return invalidResponse();

    return { ok: true, verdict: parsed };
  } catch {
    return invalidResponse();
  }
}

export function normalizeVerdict(parsed) {
  if (!isPlainObject(parsed) || !DECISION_SET.has(parsed.decision)) {
    return { kind: 'failure', reason: INVALID_RESPONSE_REASON };
  }

  if (parsed.decision === 'deny' || parsed.decision === 'review') {
    return { kind: parsed.decision, reason: parsed.rationale, verdict: parsed };
  }

  if (parsed.risk === 'low'
    && parsed.authorization === 'high'
    && parsed.confidence >= MIN_CONFIDENCE) {
    return { kind: 'allow', reason: parsed.rationale, verdict: parsed };
  }

  return {
    kind: 'review',
    reason: 'judge allow did not satisfy local safety gate',
    verdict: parsed,
  };
}

export function applyOpaqueDowngrade(result, visibleParams) {
  if (result === null || typeof result !== 'object') {
    return { kind: 'failure', reason: 'invalid judge response' };
  }
  if (result.kind !== 'allow') return result;
  if (!containsOpaqueData(visibleParams)) return result;
  return {
    kind: 'review',
    reason: 'opaque action cannot be auto-approved',
    verdict: result.verdict,
    opaque: true,
  };
}

function ownDataValue(value, key) {
  if (value === null || typeof value !== 'object' || utilTypes.isProxy(value)) {
    return { ok: false };
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return { ok: false };
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) return { ok: false };
  return { ok: true, value: descriptor.value };
}

function shellTokenize(source) {
  if (typeof source !== 'string' || source.trim() === ''
    || source.length > SHELL_SCAN_MAX_LENGTH || source.includes('\0')) return null;
  const commands = [];
  let tokens = [];
  let token = '';
  let tokenStarted = false;
  let quote = null;
  let separatorBefore = null;
  let tokenCount = 0;

  function finishToken() {
    if (!tokenStarted) return true;
    tokenCount += 1;
    if (tokenCount > SHELL_SCAN_MAX_TOKENS) return false;
    tokens.push(token);
    token = '';
    tokenStarted = false;
    return true;
  }

  function finishCommand(separator) {
    if (!finishToken()) return false;
    if (tokens.length > 0) {
      commands.push({ tokens, separatorBefore });
      if (commands.length > SHELL_SCAN_MAX_COMMANDS) return false;
      tokens = [];
    }
    separatorBefore = separator;
    return true;
  }

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (quote === "'") {
      if (character === "'") quote = null;
      else token += character;
      continue;
    }
    if (quote === '"') {
      if (character === '"') {
        quote = null;
      } else if (character === '\\') {
        if (index + 1 >= source.length) return null;
        token += source[index + 1];
        index += 1;
      } else if (character === '`' || (character === '$' && source[index + 1] === '(')) {
        return null;
      } else {
        token += character;
      }
      continue;
    }

    if (character === "'" || character === '"') {
      quote = character;
      tokenStarted = true;
      continue;
    }
    if (character === '\\') {
      if (index + 1 >= source.length) return null;
      tokenStarted = true;
      token += source[index + 1];
      index += 1;
      continue;
    }
    if (character === '#' && !tokenStarted) {
      while (index + 1 < source.length && source[index + 1] !== '\n') index += 1;
      if (!finishCommand(';')) return null;
      continue;
    }
    if (character === '$' && source[index + 1] === '(') {
      if (!finishCommand(';')) return null;
      index += 1;
      continue;
    }
    if (character === '`' || character === '(' || character === ')') {
      if (!finishCommand(';')) return null;
      continue;
    }
    if (character === '&' || character === '|') {
      const doubled = source[index + 1] === character;
      const operator = doubled ? `${character}${character}` : character;
      if (!finishCommand(operator)) return null;
      if (doubled) index += 1;
      continue;
    }
    if (character === ';' || character === '\n') {
      if (!finishCommand(';')) return null;
      continue;
    }
    if (/\s/u.test(character)) {
      if (!finishToken()) return null;
      continue;
    }
    tokenStarted = true;
    token += character;
  }
  if (quote !== null || !finishCommand(null)) return null;
  return commands;
}

function shellBasename(value) {
  const normalized = value.replaceAll('\\', '/');
  const name = normalized.slice(normalized.lastIndexOf('/') + 1).toLowerCase();
  return name.endsWith('.exe') ? name.slice(0, -4) : name;
}

function isShellAssignment(value) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/u.test(value);
}

function skipWrapperOptions(tokens, start, optionsWithValues = new Set()) {
  let index = start;
  while (index < tokens.length && tokens[index].startsWith('-')) {
    const option = tokens[index];
    index += 1;
    if (optionsWithValues.has(option) && index < tokens.length) index += 1;
  }
  return index;
}

function shellCommandView(tokens) {
  let index = 0;
  while (index < tokens.length && isShellAssignment(tokens[index])) index += 1;
  for (let wrappers = 0; wrappers < 8 && index < tokens.length; wrappers += 1) {
    const name = shellBasename(tokens[index]);
    if (name === 'sudo') {
      index = skipWrapperOptions(tokens, index + 1, new Set([
        '-C', '-D', '-g', '-h', '-p', '-r', '-t', '-u',
        '--chdir', '--group', '--host', '--prompt', '--role', '--type', '--user',
      ]));
      continue;
    }
    if (name === 'command' || name === 'builtin' || name === 'nohup') {
      index = skipWrapperOptions(tokens, index + 1);
      continue;
    }
    if (name === 'env') {
      const originalArgs = tokens.slice(index + 1);
      if (originalArgs.includes('--help') || originalArgs.includes('--version')) {
        return { name, args: originalArgs };
      }
      index += 1;
      while (index < tokens.length) {
        if (isShellAssignment(tokens[index])) {
          index += 1;
          continue;
        }
        if (tokens[index] === '-u' || tokens[index] === '--unset') {
          index += 2;
          continue;
        }
        if (tokens[index].startsWith('-')) {
          index += 1;
          continue;
        }
        break;
      }
      if (index >= tokens.length) return { name, args: originalArgs };
      continue;
    }
    return { name, args: tokens.slice(index + 1) };
  }
  return index < tokens.length
    ? { name: shellBasename(tokens[index]), args: tokens.slice(index + 1) }
    : null;
}

function hasHelpOrVersion(args) {
  return args.includes('--help') || args.includes('--version');
}

function shortFlagIncludes(args, letters) {
  return args.some((arg) => (
    /^-[^-]+$/u.test(arg) && [...letters].some((letter) => arg.slice(1).includes(letter))
  ));
}

function firstNonOption(args) {
  return args.find((arg) => !arg.startsWith('-'));
}

function packageInstallCommand(name, args) {
  if ((name === 'python' || name === 'python3') && args[0] === '-m'
    && ['pip', 'pip3'].includes(args[1])) return packageInstallCommand(args[1], args.slice(2));
  if (name === 'uv' && args[0] === 'pip') return packageInstallCommand('pip', args.slice(1));
  const operation = firstNonOption(args);
  if (['pip', 'pip3', 'pipx', 'gem', 'cargo', 'go', 'brew'].includes(name)) {
    return operation === 'install';
  }
  if (['npm', 'pnpm', 'yarn', 'bun'].includes(name)) {
    return ['add', 'ci', 'install'].includes(operation);
  }
  if (['apt', 'apt-get', 'dnf', 'yum', 'zypper'].includes(name)) return operation === 'install';
  if (name === 'apk') return operation === 'add';
  if (name === 'poetry') return operation === 'add' || operation === 'install';
  if (name === 'composer') return operation === 'install' || operation === 'require';
  return ['npx', 'pnpx', 'bunx'].includes(name);
}

function gitCommandRisk(args) {
  let index = 0;
  while (index < args.length && args[index].startsWith('-')) {
    if (['-C', '-c', '--git-dir', '--work-tree', '--namespace'].includes(args[index])) index += 2;
    else index += 1;
  }
  const operation = args[index];
  const operationArgs = args.slice(index + 1);
  if (operation === 'reset') return operationArgs.includes('--hard');
  if (operation === 'clean') {
    return operationArgs.includes('--force') || shortFlagIncludes(operationArgs, 'f');
  }
  if (operation === 'push') {
    return operationArgs.some((arg) => arg === '--force'
      || arg.startsWith('--force-with-lease')) || shortFlagIncludes(operationArgs, 'f');
  }
  if (operation !== 'config') return false;
  if (operationArgs.some((arg) => [
    '--add', '--edit', '--remove-section', '--rename-section', '--replace-all', '--unset',
    '--unset-all',
  ].includes(arg))) return true;
  if (operationArgs.some((arg) => [
    '--get', '--get-all', '--get-regexp', '--get-urlmatch', '--list', '-l', '--show-origin',
  ].includes(arg))) return false;
  const positionals = operationArgs.filter((arg) => !arg.startsWith('-'));
  return positionals.length >= 2;
}

function migrationCommand(name, args) {
  if (name.includes('migrat') || ['dbmate', 'flyway', 'liquibase', 'migrate-mongo'].includes(name)) {
    return true;
  }
  if (name === 'alembic') return args.some((arg) => ['downgrade', 'stamp', 'upgrade'].includes(arg));
  if (['npm', 'pnpm', 'yarn', 'bun'].includes(name)) {
    return args.some((arg) => /migrat/iu.test(arg));
  }
  if (['make', 'task', 'rake', 'rails'].includes(name)) {
    return args.some((arg) => /(?:^|:)migrat/iu.test(arg));
  }
  return (name === 'python' || name === 'python3')
    && args.some((arg) => /manage\.py$/iu.test(arg))
    && args.includes('migrate');
}

function shellSegmentRisk(segment, depth) {
  const view = shellCommandView(segment.tokens);
  if (view === null) return false;
  const { name, args } = view;
  if (segment.separatorBefore === '|' && (SHELL_INTERPRETERS.has(name) || name === 'eval')) {
    return true;
  }
  if (name === 'eval') return true;
  if (SHELL_INTERPRETERS.has(name)) {
    const commandIndex = args.findIndex((arg) => arg === '-c' || arg === '/c'
      || arg === '-command');
    if (commandIndex < 0) return false;
    if (typeof args[commandIndex + 1] !== 'string') return null;
    return shellCommandRisk(args[commandIndex + 1], depth + 1);
  }
  if (INLINE_INTERPRETERS.has(name)
    && args.some((arg) => arg === '-c' || arg === '-e' || arg === '--eval')) return true;
  if (DELETE_COMMANDS.has(name)) return hasHelpOrVersion(args) ? false : true;
  if (name === 'find' && args.includes('-delete')) return true;
  if (name === 'history') {
    return args.includes('--clear') || shortFlagIncludes(args, 'c');
  }
  if (name === ':' && args.some((arg) => arg === '>' || arg === '>>')
    && args.some((arg) => /history/iu.test(arg))) return true;
  if (name === 'truncate' && args.some((arg) => arg === '0')
    && args.some((arg) => /(?:^|[\/])(?:[^\/]*history|logs?)(?:[\/]|$)/iu.test(arg))) return true;
  if (name === 'git' && gitCommandRisk(args)) return true;
  if (packageInstallCommand(name, args)) return true;
  if (name === 'printenv') return !hasHelpOrVersion(args);
  if (name === 'env') return !hasHelpOrVersion(args);
  if (PERMISSION_COMMANDS.has(name)) return hasHelpOrVersion(args) ? false : true;
  return migrationCommand(name, args);
}

function shellCommandRisk(source, depth = 0) {
  if (depth > 3) return null;
  const commands = shellTokenize(source);
  if (commands === null) return null;
  for (const command of commands) {
    const risk = shellSegmentRisk(command, depth);
    if (risk !== false) return risk;
  }
  return false;
}

function isDataOnly(value, ancestors = new Set(), budget = { remaining: 10_000 }) {
  if (value === null) return true;
  if (['string', 'number', 'boolean'].includes(typeof value)) return true;
  if (typeof value !== 'object' || utilTypes.isProxy(value)) return false;
  if (budget.remaining <= 0 || ancestors.has(value)) return false;

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype
    && prototype !== null
    && prototype !== Array.prototype) return false;

  budget.remaining -= 1;
  ancestors.add(value);
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return false;
    if (!isDataOnly(descriptor.value, ancestors, budget)) return false;
  }
  ancestors.delete(value);
  return true;
}

function localReview(result) {
  const verdict = ownDataValue(result, 'verdict');
  if (!verdict.ok || !isDataOnly(verdict.value)) {
    return { kind: 'failure', reason: INVALID_LOCAL_GUARD_REASON };
  }
  return {
    kind: 'review',
    reason: LOCAL_GUARD_REASON,
    verdict: verdict.value,
    local_guard: true,
  };
}

function localActionSnapshot(value, expectedToolName) {
  try {
    if (!isDataOnly(value)) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== LOCAL_ACTION_KEYS.size
      || keys.some((key) => typeof key !== 'string' || !LOCAL_ACTION_KEYS.has(key))) {
      return null;
    }
    for (const key of LOCAL_ACTION_KEYS) {
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return null;
      }
    }
    if (descriptors.policy_version.value !== POLICY_VERSION
      || descriptors.tool_name.value !== expectedToolName
      || !isPlainObject(descriptors.params.value)) return null;
    return Object.freeze({
      params: descriptors.params.value,
      sessionKey: descriptors.session_key.value,
    });
  } catch {
    return null;
  }
}

function pathHasRawTraversal(path) {
  return /(?:^|[\\/])(?:[a-zA-Z]:)?\.\.(?=[\\/]|$)/u.test(path);
}

function pathHasAmbiguousWindowsAlias(path) {
  if (path.startsWith('\\\\?\\') || path.startsWith('\\\\.\\')) return true;
  return path.split(/[\\/]+/u).some((segment) => segment !== '' && /[ .]$/u.test(segment));
}

function pathHasWindowsAlternateDataStream(path) {
  const withoutDrive = /^[a-zA-Z]:/u.test(path) ? path.slice(2) : path;
  return withoutDrive.includes(':');
}

function targetsOpenClawConfigWrite(path) {
  if (typeof path !== 'string' || path.trim() === '') return null;
  if (pathHasRawTraversal(path)
    || pathHasAmbiguousWindowsAlias(path)
    || pathHasWindowsAlternateDataStream(path)) return true;
  const segments = path
    .replaceAll('\\', '/')
    .split('/')
    .filter((segment) => segment !== '')
    .map((segment) => segment.toLowerCase());
  return segments.length > 0 && OPENCLAW_ROOT_CONFIG.test(segments.at(-1));
}

function internalWebFetchUrl(value) {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0
    || value.length > 2_048 || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) return null;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (parsed.username !== '' || parsed.password !== '') return true;
    let hostname = parsed.hostname.toLowerCase();
    if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);
    while (hostname.endsWith('.')) hostname = hostname.slice(0, -1);
    if (hostname === '') return null;
    const version = isIP(hostname);
    if (version !== 0) {
      return INTERNAL_NETWORKS.check(hostname, version === 4 ? 'ipv4' : 'ipv6');
    }
    if (hostname === 'localhost' || hostname === 'metadata' || !hostname.includes('.')) return true;
    return INTERNAL_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
  } catch {
    return null;
  }
}

function normalizeAbsoluteSystemPath(path) {
  const slashPath = path.replaceAll('\\', '/');
  if (!slashPath.startsWith('/')) return null;
  const rooted = `/${slashPath.replace(/^\/+/u, '').replace(/\/{2,}/gu, '/')}`;
  return pathPosix.normalize(rooted).toLowerCase();
}

function targetsSensitiveSystemPath(path) {
  const normalized = normalizeAbsoluteSystemPath(path);
  if (normalized === null) return false;
  const segments = normalized.split('/').filter(Boolean);

  const etcIndex = segments[0] === 'etc'
    ? 0
    : segments[0] === 'private' && segments[1] === 'etc' ? 1 : -1;
  if (etcIndex >= 0) {
    const etcSegments = segments.slice(etcIndex);
    if (etcSegments.length === 2
      && (SHADOW_DATABASE_FILE.test(etcSegments[1])
        || MASTER_PASSWD_FILE.test(etcSegments[1]))) return true;
    if (etcSegments[1] === 'ssh' && SSH_HOST_PRIVATE_KEY.test(etcSegments.at(-1))) return true;
    if (etcSegments[1] === 'ssl' && etcSegments[2] === 'private') return true;
    if (etcSegments[1] === 'kubernetes'
      && KUBERNETES_CREDENTIAL_CONFIG.test(segments.at(-1))) return true;
  }

  const isProcessPath = segments[0] === 'proc'
    && (segments[1] === 'self' || segments[1] === 'thread-self' || /^\d+$/u.test(segments[1]));
  if (!isProcessPath) return false;
  if (['cmdline', 'environ', 'fd', 'mem'].includes(segments[2])) return true;
  return segments[2] === 'root'
    && segments.length > 3
    && targetsSensitiveSystemPath(`/${segments.slice(3).join('/')}`);
}

function isSafeSystemMetadataPath(path) {
  const normalized = normalizeAbsoluteSystemPath(path);
  return normalized === '/etc/passwd'
    || normalized === '/private/etc/passwd'
    || normalized === '/proc/version'
    || (normalized !== null && SSH_HOST_PUBLIC_KEY_PATH.test(normalized));
}

function filenameStem(name) {
  const extensionIndex = name.lastIndexOf('.');
  return extensionIndex > 0 ? name.slice(0, extensionIndex) : name;
}

function targetsOpenClawSecretStore(segments) {
  const stateIndex = segments.lastIndexOf('.openclaw');
  if (stateIndex < 0) return false;
  const relative = segments.slice(stateIndex + 1);
  const name = relative.at(-1);
  if (relative.length === 1 && OPENCLAW_ROOT_CONFIG.test(name)) return true;
  const defaultAuthStore = relative.length === 1
    || (relative[0] === 'agents' && relative.at(-2) === 'agent');
  if (defaultAuthStore && OPENCLAW_AUTH_STORE.test(name)) return true;
  if (relative.at(-2) === 'identity' && OPENCLAW_IDENTITY_STORE.test(name)) return true;
  return (relative.at(-2) === 'devices' || relative.at(-2) === 'nodes')
    && OPENCLAW_PAIRING_STORE.test(name);
}

function targetsCredentialMaterial(path) {
  if (pathHasRawTraversal(path)
    || pathHasAmbiguousWindowsAlias(path)
    || pathHasWindowsAlternateDataStream(path)) return true;
  const segments = path
    .replaceAll('\\', '/')
    .split('/')
    .filter((segment) => segment !== '')
    .map((segment) => segment.toLowerCase());
  if (segments.length === 0) return true;
  const name = segments.at(-1);

  if (INERT_TEMPLATE_NAME.test(name) || PUBLIC_KEY_FILE.test(name)) return false;
  if (isSafeSystemMetadataPath(path)) return false;
  if (ENV_FILE.test(name)
    || ENVRC_FILE.test(name)
    || SENSITIVE_READ_FILES.has(name)
    || PRIVATE_KEY_FILE.test(name)
    || PRIVATE_KEY_EXTENSION.test(name)
    || PRIVATE_PEM_FILE.test(name)) return true;
  if (targetsSensitiveSystemPath(path)) return true;
  if (targetsOpenClawSecretStore(segments)) return true;
  if (segments.at(-2) === '.docker' && name === 'config.json') return true;
  if (segments.at(-2) === '.kube' && name === 'config') return true;
  if (segments.slice(0, -1).some((segment) => SENSITIVE_READ_DIRECTORIES.has(segment))) {
    return true;
  }
  if (DOCUMENTATION_FILE.test(name)) return false;
  if (isSecretBearingKey(filenameStem(name))) return true;
  if (CREDENTIAL_NAME.test(name)) return true;
  return false;
}

function gatewayPathIsSensitive(path) {
  const rawComponents = path
    .split(/[./:\[\]\\]+/u)
    .filter((component) => component !== '');
  if (rawComponents.length < 2 || rawComponents.some(isSecretBearingKey)) return true;
  const components = rawComponents
    .map((component) => component.toLowerCase().replace(/[^a-z0-9]+/gu, ''));
  if (components.some((component) => (
    component === '' || component === 'env' || component === 'headers'
  ))) return true;
  const last = components.at(-1);
  return !SAFE_CONFIG_METADATA_COMPONENTS.has(last);
}

function targetsActiveAutomation(path) {
  if (typeof path !== 'string' || !path) return null;
  const normalized = pathPosix.normalize(
    path.replaceAll('\\', '/').replace(/\/{2,}/gu, '/'),
  );
  const lower = normalized.toLowerCase();
  const name = lower.slice(lower.lastIndexOf('/') + 1);
  if (ACTIVE_REGISTRY_CONFIGS.has(name)) return true;
  if (/(?:^|\/)\.github\/workflows\//u.test(lower)) return /\.ya?ml$/u.test(name);
  if (/(?:^|\/)\.git\/hooks\//u.test(lower)) return ACTIVE_GIT_HOOKS.has(name);
  const devcontainer = /(?:^|\/)\.devcontainer\/(?:[^/]+\/)*([^/]+)$/u.exec(lower);
  if (devcontainer) {
    if (devcontainer[1] === 'devcontainer.json') return true;
    if (!/\.(?:example|sample)$/u.test(devcontainer[1])
      && DEVCONTAINER_LIFECYCLE_FILE.test(devcontainer[1])) return true;
  }
  const segments = lower.split('/');
  if (segments.slice(0, -1).some((segment) => SECURITY_PATH_SEGMENTS.has(segment))
    && SECURITY_POLICY_FILE.test(name)) return true;
  return false;
}

function fileTargets(params, toolName) {
  if (toolName === 'write' || toolName === 'edit') {
    const path = ownDataValue(params, 'path');
    return path.ok && typeof path.value === 'string' ? [path.value] : null;
  }

  const input = ownDataValue(params, 'input');
  if (!input.ok || typeof input.value !== 'string') return null;
  const targets = [];
  for (const line of input.value.split(/\r?\n/u)) {
    const match = PATCH_FILE_HEADER.exec(line) ?? PATCH_MOVE_HEADER.exec(line);
    if (match) targets.push(match[1]);
  }
  return targets.length > 0 ? targets : null;
}

export function applyLocalSafetyDowngrade(result, toolName, visibleParams, localAction) {
  const kind = ownDataValue(result, 'kind');
  if (!kind.ok || typeof kind.value !== 'string') {
    return { kind: 'failure', reason: INVALID_LOCAL_GUARD_REASON };
  }
  if (kind.value !== 'allow') return result;
  if (typeof toolName !== 'string' || !toolName || !isDataOnly(visibleParams)) {
    return localReview(result);
  }
  const action = localActionSnapshot(localAction, toolName);
  if (action === null) return localReview(result);

  if (toolName === 'read') {
    const path = ownDataValue(action.params, 'path');
    if (!path.ok || typeof path.value !== 'string' || path.value.trim() === ''
      || targetsCredentialMaterial(path.value)) return localReview(result);
    return result;
  }

  if (toolName === 'gateway') {
    const actionName = ownDataValue(action.params, 'action');
    const path = ownDataValue(action.params, 'path');
    if (!actionName.ok || actionName.value !== 'config.get'
      || !path.ok || typeof path.value !== 'string' || path.value.trim() === ''
      || gatewayPathIsSensitive(path.value)) return localReview(result);
    return result;
  }

  if (toolName === 'sessions_history') {
    const requestedSession = ownDataValue(action.params, 'sessionKey');
    if (!requestedSession.ok
      || typeof requestedSession.value !== 'string'
      || requestedSession.value.trim() === ''
      || typeof action.sessionKey !== 'string'
      || action.sessionKey.trim() === ''
      || requestedSession.value !== action.sessionKey) return localReview(result);
    return result;
  }

  if (toolName === 'process') {
    const actionName = ownDataValue(action.params, 'action');
    if (!actionName.ok
      || typeof actionName.value !== 'string'
      || !READ_ONLY_PROCESS_ACTIONS.has(actionName.value)) return localReview(result);
    return result;
  }

  if (toolName === 'exec') {
    const command = ownDataValue(action.params, 'command');
    if (!command.ok || shellCommandRisk(command.value) !== false) return localReview(result);
    return result;
  }

  if (toolName === 'web_fetch') {
    const url = ownDataValue(action.params, 'url');
    if (!url.ok || internalWebFetchUrl(url.value) !== false) return localReview(result);
    return result;
  }

  if (toolName === 'message') {
    const actionName = ownDataValue(action.params, 'action');
    if (!actionName.ok || typeof actionName.value !== 'string') return localReview(result);
    if (actionName.value === 'send') {
      const dryRun = ownDataValue(action.params, 'dryRun');
      return dryRun.ok && dryRun.value === true ? result : localReview(result);
    }
    return READ_ONLY_MESSAGE_ACTIONS.has(actionName.value) ? result : localReview(result);
  }

  if (ownDataValue(action.params, 'dryRun').ok) return localReview(result);

  if (toolName === 'cron') {
    const actionName = ownDataValue(action.params, 'action');
    if (!actionName.ok
      || typeof actionName.value !== 'string'
      || !READ_ONLY_CRON_ACTIONS.has(actionName.value)) return localReview(result);
    return result;
  }

  if (toolName === 'browser') {
    const actionName = ownDataValue(action.params, 'action');
    if (!actionName.ok || typeof actionName.value !== 'string' || actionName.value === 'upload') {
      return localReview(result);
    }
    return result;
  }

  if (!FILE_WRITE_TOOLS.has(toolName)) return result;
  const targets = fileTargets(action.params, toolName);
  if (targets === null || targets.some((path) => (
    targetsOpenClawConfigWrite(path) !== false || targetsActiveAutomation(path) !== false
  ))) {
    return localReview(result);
  }
  return result;
}

function approvalSeverity(result) {
  if (result?.opaque === true
    || result?.local_guard === true
    || result?.kind === 'failure'
    || result?.verdict?.risk === 'high'
    || result?.verdict?.risk === 'critical') return 'critical';
  return 'warning';
}

export function mapVerdict({ mode, enforcement, result, params } = {}) {
  if (enforcement === 'shadow') return undefined;

  if (enforcement === 'enforce'
    && (mode === 'autonomous' || mode === 'supervised')
    && result?.kind === 'allow') return { params };

  if (result?.kind === 'deny') {
    return {
      block: true,
      blockReason: DENY_BLOCK_REASON,
    };
  }

  if (enforcement === 'enforce' && mode === 'supervised') {
    return {
      params,
      requireApproval: {
        title: REVIEW_BLOCK_REASON,
        description: APPROVAL_DESCRIPTION,
        severity: approvalSeverity(result),
        timeoutMs: APPROVAL_TIMEOUT_MS,
        timeoutBehavior: 'deny',
        pluginId: PLUGIN_ID,
      },
    };
  }

  return { block: true, blockReason: REVIEW_BLOCK_REASON };
}
