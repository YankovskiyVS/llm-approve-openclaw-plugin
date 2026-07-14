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
const READ_ONLY_SKILL_WORKSHOP_ACTIONS = new Set(['list']);
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
  'cmd',
  'dash',
  'fish',
  'ksh',
  'powershell',
  'pwsh',
  'sh',
  'zsh',
]);
const INLINE_INTERPRETERS = new Set([
  'lua', 'node', 'nodejs', 'perl', 'php', 'python', 'python3', 'ruby',
]);
const DELETE_COMMANDS = new Set(['rm', 'rmdir', 'shred', 'unlink']);
const PERMISSION_COMMANDS = new Set(['chgrp', 'chmod', 'chown']);
const PACKAGE_MANAGER_COMMANDS = new Set([
  'apk', 'apt', 'apt-get', 'brew', 'bun', 'bunx', 'cargo', 'composer', 'dnf', 'gem',
  'go', 'npm', 'npx', 'pip', 'pip3', 'pipx', 'pnpm', 'pnpx', 'poetry', 'uv', 'yarn',
  'yum', 'zypper',
]);
const SHELL_CONTROL_WORDS = new Set([
  '!', '.', 'case', 'coproc', 'do', 'done', 'elif', 'else', 'esac', 'fi', 'for',
  'function', 'if', 'in', 'noglob', 'select', 'source', 'then', 'trap', 'until',
  'while',
]);
const SHELL_WRAPPERS = new Set([
  'builtin', 'busybox', 'command', 'env', 'exec', 'ionice', 'nice', 'nohup',
  'stdbuf', 'sudo', 'time', 'timeout', 'toybox',
]);
const SHELL_REDIRECTIONS = new Set([
  '<', '>', '>>', '<<', '<<<', '<>', '<&', '>&', '&>', '&>>', '>|',
]);
const INTERNAL_HOST_SUFFIXES = [
  '.home.arpa',
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
  let dynamicTokenIndexes = new Set();
  let fdTokenIndexes = new Set();
  let operatorTokenIndexes = new Set();
  let token = '';
  let tokenStarted = false;
  let tokenDynamic = false;
  let tokenQuotedOrEscaped = false;
  let quote = null;
  let separatorBefore = null;
  let tokenCount = 0;

  function finishToken() {
    if (!tokenStarted) return true;
    tokenCount += 1;
    if (tokenCount > SHELL_SCAN_MAX_TOKENS) return false;
    if (tokenDynamic) dynamicTokenIndexes.add(tokens.length);
    tokens.push(token);
    token = '';
    tokenStarted = false;
    tokenDynamic = false;
    tokenQuotedOrEscaped = false;
    return true;
  }

  function finishCommand(separator) {
    if (!finishToken()) return false;
    if (tokens.length > 0) {
      commands.push({
        tokens,
        dynamicTokenIndexes,
        fdTokenIndexes,
        operatorTokenIndexes,
        separatorBefore,
      });
      if (commands.length > SHELL_SCAN_MAX_COMMANDS) return false;
      tokens = [];
      dynamicTokenIndexes = new Set();
      fdTokenIndexes = new Set();
      operatorTokenIndexes = new Set();
    }
    separatorBefore = separator;
    return true;
  }

  function pushOperator(operator) {
    tokenCount += 1;
    if (tokenCount > SHELL_SCAN_MAX_TOKENS) return false;
    operatorTokenIndexes.add(tokens.length);
    tokens.push(operator);
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
        if (source[index + 1] === '\n') {
          index += 1;
          continue;
        }
        if (source[index + 1] === '\r' && source[index + 2] === '\n') {
          index += 2;
          continue;
        }
        token += source[index + 1];
        index += 1;
      } else if (character === '`' || (character === '$' && source[index + 1] === '(')) {
        return null;
      } else if (character === '$') {
        tokenStarted = true;
        tokenDynamic = true;
        token += character;
      } else {
        token += character;
      }
      continue;
    }

    if (character === "'" || character === '"') {
      quote = character;
      tokenStarted = true;
      tokenQuotedOrEscaped = true;
      continue;
    }
    if (character === '\\') {
      if (index + 1 >= source.length) return null;
      if (source[index + 1] === '\n') {
        index += 1;
        continue;
      }
      if (source[index + 1] === '\r' && source[index + 2] === '\n') {
        index += 2;
        continue;
      }
      tokenStarted = true;
      tokenQuotedOrEscaped = true;
      token += source[index + 1];
      index += 1;
      continue;
    }
    if (character === '#' && !tokenStarted) {
      while (index + 1 < source.length && source[index + 1] !== '\n') index += 1;
      if (!finishCommand(';')) return null;
      continue;
    }
    if (character === '`' || (character === '$' && source[index + 1] === '(')
      || character === '(' || character === ')') return null;
    if (character === '$' || character === '*' || character === '?'
      || character === '[' || character === ']' || character === '{'
      || character === '}') {
      tokenStarted = true;
      tokenDynamic = true;
      token += character;
      continue;
    }
    if (character === '|' && source[index + 1] === '&') {
      if (!finishCommand('|&')) return null;
      index += 1;
      continue;
    }
    if (character === '&' && source[index + 1] === '>') {
      if (!finishToken()) return null;
      let operator = '&>';
      index += 1;
      if (source[index + 1] === '>') {
        operator += '>';
        index += 1;
      }
      if (!pushOperator(operator)) return null;
      continue;
    }
    if (character === '<' || character === '>') {
      const fdIndex = tokenStarted && !tokenQuotedOrEscaped && /^\d+$/u.test(token)
        ? tokens.length
        : null;
      if (!finishToken()) return null;
      if (fdIndex !== null) fdTokenIndexes.add(fdIndex);
      let operator = character;
      if (source[index + 1] === '&'
        || (character === '<' && source[index + 1] === '>')
        || (character === '>' && source[index + 1] === '|')) {
        operator += source[index + 1];
        index += 1;
      } else while (source[index + 1] === character && operator.length < 3) {
        operator += character;
        index += 1;
      }
      if (!pushOperator(operator)) return null;
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

function skipShellPrefixes(tokens, start = 0) {
  let index = start;
  while (index < tokens.length) {
    if (isShellAssignment(tokens[index])) {
      index += 1;
      continue;
    }
    if (/^\d+$/u.test(tokens[index]) && SHELL_REDIRECTIONS.has(tokens[index + 1])) {
      index += 3;
      continue;
    }
    if (SHELL_REDIRECTIONS.has(tokens[index])) {
      index += 2;
      continue;
    }
    break;
  }
  return index;
}

function shellCommandView(tokens) {
  let index = skipShellPrefixes(tokens);
  for (let wrappers = 0; wrappers < 8; wrappers += 1) {
    index = skipShellPrefixes(tokens, index);
    if (index >= tokens.length) return null;
    const name = shellBasename(tokens[index]);
    if (name === 'sudo') {
      index = skipWrapperOptions(tokens, index + 1, new Set([
        '-C', '-D', '-R', '-T', '-U', '-a', '-c', '-g', '-h', '-p', '-r', '-t', '-u',
        '--auth-type', '--chdir', '--chroot', '--close-from', '--command-timeout', '--group',
        '--host', '--login-class', '--other-user', '--prompt', '--role', '--type', '--user',
      ]));
      if (index >= tokens.length) return { name, args: [], ambiguous: true, commandIndex: index };
      continue;
    }
    if (name === 'command') {
      const originalArgs = tokens.slice(index + 1);
      if (originalArgs.some((arg) => arg === '-v' || arg === '-V')) {
        return { name, args: originalArgs, commandIndex: index };
      }
      index = skipWrapperOptions(tokens, index + 1);
      continue;
    }
    if (name === 'builtin' || name === 'nohup') {
      index = skipWrapperOptions(tokens, index + 1);
      continue;
    }
    if (name === 'exec') {
      index = skipWrapperOptions(tokens, index + 1, new Set(['-a']));
      if (index >= tokens.length) return { name, args: [], ambiguous: true, commandIndex: index };
      continue;
    }
    if (name === 'time') {
      index = skipWrapperOptions(tokens, index + 1, new Set([
        '-f', '-o', '--format', '--output',
      ]));
      if (index >= tokens.length) return { name, args: [], ambiguous: true, commandIndex: index };
      continue;
    }
    if (name === 'env') {
      const originalArgs = tokens.slice(index + 1);
      if (originalArgs.includes('--help') || originalArgs.includes('--version')) {
        return { name, args: originalArgs, commandIndex: index };
      }
      if (originalArgs.some((arg) => arg === '-S' || arg === '--split-string'
        || arg.startsWith('--split-string='))) {
        return { name, args: originalArgs, ambiguous: true, commandIndex: index };
      }
      index += 1;
      while (index < tokens.length) {
        if (isShellAssignment(tokens[index])) {
          index += 1;
          continue;
        }
        if (['-C', '-P', '-a', '-u', '--argv0', '--chdir', '--unset'].includes(tokens[index])) {
          index += 2;
          continue;
        }
        if (tokens[index] === '--') {
          index += 1;
          break;
        }
        if (/^--(?:argv0|chdir|unset)=/u.test(tokens[index])) {
          index += 1;
          continue;
        }
        if (['-0', '-i', '--debug', '--ignore-environment', '--null'].includes(tokens[index])) {
          index += 1;
          continue;
        }
        if (tokens[index].startsWith('-')) {
          return { name, args: originalArgs, ambiguous: true, commandIndex: index };
        }
        break;
      }
      if (index >= tokens.length) return {
        name, args: originalArgs, ambiguous: true, commandIndex: index,
      };
      continue;
    }
    if (name === 'timeout') {
      index = skipWrapperOptions(tokens, index + 1, new Set([
        '-k', '-s', '--kill-after', '--signal',
      ]));
      if (index >= tokens.length || tokens[index].startsWith('-')) {
        return { name, args: tokens.slice(index), ambiguous: true, commandIndex: index };
      }
      index += 1;
      if (tokens[index] === '--') index += 1;
      if (index >= tokens.length) return { name, args: [], ambiguous: true, commandIndex: index };
      continue;
    }
    if (name === 'nice') {
      index = skipWrapperOptions(tokens, index + 1, new Set(['-n', '--adjustment']));
      if (index >= tokens.length) return { name, args: [], ambiguous: true, commandIndex: index };
      continue;
    }
    if (name === 'ionice') {
      index = skipWrapperOptions(tokens, index + 1, new Set([
        '-c', '-n', '-p', '-P', '-u', '--class', '--classdata', '--pid', '--pgid', '--uid',
      ]));
      if (index >= tokens.length) return { name, args: [], ambiguous: true, commandIndex: index };
      continue;
    }
    if (name === 'stdbuf') {
      index = skipWrapperOptions(tokens, index + 1, new Set([
        '-e', '-i', '-o', '--error', '--input', '--output',
      ]));
      if (index >= tokens.length) return { name, args: [], ambiguous: true, commandIndex: index };
      continue;
    }
    if (name === 'busybox' || name === 'toybox') {
      const originalArgs = tokens.slice(index + 1);
      if (name === 'busybox' && originalArgs.some((arg) => (
        arg === '--install' || arg.startsWith('--install=')
      ))) {
        return { name, args: originalArgs, ambiguous: true, commandIndex: index };
      }
      if (originalArgs[0]?.startsWith('-')) {
        if (hasHelpOrVersion(originalArgs)
          || ['--list', '--list-full', '--show'].includes(originalArgs[0])) {
          return { name, args: originalArgs, commandIndex: index };
        }
        return { name, args: originalArgs, ambiguous: true, commandIndex: index };
      }
      index += 1;
      if (index >= tokens.length) return { name, args: [], ambiguous: true, commandIndex: index };
      continue;
    }
    if (name === 'xargs' || name === 'parallel' || name === 'watch') {
      return { name, args: tokens.slice(index + 1), ambiguous: true, commandIndex: index };
    }
    return { name, args: tokens.slice(index + 1), commandIndex: index };
  }
  if (index >= tokens.length) return null;
  const name = shellBasename(tokens[index]);
  if (SHELL_WRAPPERS.has(name)) {
    return { name, args: tokens.slice(index + 1), ambiguous: true, commandIndex: index };
  }
  return { name, args: tokens.slice(index + 1), commandIndex: index };
}

function hasHelpOrVersion(args) {
  return args.includes('--help') || args.includes('--version');
}

function shortFlagIncludes(args, letters) {
  return args.some((arg) => (
    /^-[^-]+$/u.test(arg) && [...letters].some((letter) => arg.slice(1).includes(letter))
  ));
}

function packageArgsWithoutOptionValues(name, args) {
  const optionsWithValues = new Set();
  if (name === 'npm') {
    for (const option of [
      '-C', '-w', '--cache', '--prefix', '--registry', '--tag', '--userconfig', '--workspace',
    ]) optionsWithValues.add(option);
  }
  if (name === 'pnpm') {
    for (const option of [
      '-C', '-F', '--dir', '--filter', '--global-dir', '--registry', '--virtual-store-dir',
      '--workspace-concurrency',
    ]) optionsWithValues.add(option);
  }
  if (name === 'yarn') {
    for (const option of [
      '--cache-folder', '--cwd', '--modules-folder', '--mutex', '--network-timeout', '--registry',
    ]) optionsWithValues.add(option);
  }
  if (name === 'bun') {
    for (const option of ['--cache-dir', '--cwd', '--filter', '--registry']) {
      optionsWithValues.add(option);
    }
  }
  if (['pip', 'pip3', 'pipx'].includes(name)) {
    for (const option of [
      '--cache-dir', '--cert', '--client-cert', '--extra-index-url', '--index-url', '--proxy',
      '--python', '--retries', '--timeout', '--trusted-host',
    ]) optionsWithValues.add(option);
  }
  if (name === 'go') optionsWithValues.add('-C');
  if (name === 'cargo') {
    for (const option of ['-C', '--config', '--manifest-path', '--target', '--target-dir']) {
      optionsWithValues.add(option);
    }
  }
  if (name === 'apt' || name === 'apt-get') {
    for (const option of ['-c', '-o', '-t', '--config-file', '--option', '--target-release']) {
      optionsWithValues.add(option);
    }
  }
  if (name === 'dnf' || name === 'yum') {
    for (const option of [
      '-c', '--config', '--disableexcludes', '--disablerepo', '--enablerepo', '--installroot',
      '--releasever', '--repo', '--setopt',
    ]) optionsWithValues.add(option);
  }
  if (name === 'zypper') {
    for (const option of ['--config', '--reposd-dir', '--root']) optionsWithValues.add(option);
  }
  const result = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (optionsWithValues.has(arg)) {
      index += 1;
      continue;
    }
    if ([...optionsWithValues].some((option) => arg.startsWith(`${option}=`))) continue;
    result.push(arg);
  }
  return result;
}

function packageInstallCommand(name, args) {
  if (name === 'python' || name === 'python3') {
    const moduleIndex = args.indexOf('-m');
    if (moduleIndex >= 0 && ['pip', 'pip3'].includes(args[moduleIndex + 1])) {
      return packageInstallCommand(args[moduleIndex + 1], args.slice(moduleIndex + 2));
    }
  }
  const uvPipIndex = name === 'uv' ? args.indexOf('pip') : -1;
  if (uvPipIndex >= 0) return packageInstallCommand('pip', args.slice(uvPipIndex + 1));
  const normalizedArgs = packageArgsWithoutOptionValues(name, args)
    .map((arg) => arg.toLowerCase());
  const beforeDoubleDash = normalizedArgs.slice(0, normalizedArgs.indexOf('--') < 0
    ? normalizedArgs.length
    : normalizedArgs.indexOf('--'));
  const firstKnownOperation = (installOperations, safeOperations = []) => {
    const install = new Set(installOperations);
    const safe = new Set(safeOperations);
    let unparsedOption = false;
    for (let index = 0; index < beforeDoubleDash.length; index += 1) {
      const arg = beforeDoubleDash[index];
      if (arg.startsWith('-')) {
        unparsedOption = true;
        continue;
      }
      if (install.has(arg)) return true;
      if (safe.has(arg)) {
        return unparsedOption
          && beforeDoubleDash.slice(index + 1).some((later) => install.has(later));
      }
    }
    return false;
  };
  if (['pip', 'pip3', 'pipx', 'gem', 'cargo', 'go', 'brew'].includes(name)) {
    return firstKnownOperation(['install'], [
      'check', 'config', 'help', 'info', 'list', 'outdated', 'search', 'show', 'version', 'why',
    ]);
  }
  if (['npm', 'pnpm', 'yarn', 'bun'].includes(name)) {
    if ((name === 'yarn' || name === 'bun') && beforeDoubleDash.length === 0) return true;
    return firstKnownOperation(
      ['add', 'ci', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'install'],
      [
        'audit', 'config', 'diff', 'doctor', 'exec', 'help', 'info', 'list', 'ls', 'outdated',
        'run', 'run-script', 'search', 'show', 'test', 'version', 'view', 'why',
      ],
    );
  }
  if (['apt', 'apt-get', 'dnf', 'yum', 'zypper'].includes(name)) {
    return firstKnownOperation(['install'], ['check', 'help', 'info', 'list', 'search', 'show']);
  }
  if (name === 'apk') return firstKnownOperation(['add'], ['info', 'list', 'search', 'version']);
  if (name === 'poetry') return firstKnownOperation(['add', 'install'], ['check', 'show', 'version']);
  if (name === 'composer') return firstKnownOperation(['install', 'require'], ['show', 'validate']);
  return ['npx', 'pnpx', 'bunx'].includes(name);
}

function inlineInterpreterCommand(name, args) {
  return args.some((arg) => (
    arg === '-c'
    || arg === '-e'
    || (name === 'perl' && /^-E(?:.*)$/u.test(arg))
    || (['perl', 'ruby'].includes(name) && /^-[^-]*[eE]/u.test(arg))
    || arg === '--eval'
    || /^-(?:c|e).+/u.test(arg)
    || arg.startsWith('--eval=')
    || ((name === 'node' || name === 'nodejs') && (
      arg === '-p' || arg === '--print' || /^-p.+/u.test(arg) || arg.startsWith('--print=')
    ))
    || (name === 'php' && (
      ['-B', '-E', '-R', '-r', '--process-begin', '--process-code', '--process-end'].includes(arg)
      || /^-[BERr].+/u.test(arg)
      || /^--process-(?:begin|code|end)=/u.test(arg)
    ))
  ));
}

function targetsAuditOrHistoryPath(value) {
  if (typeof value !== 'string') return true;
  const lower = value.replaceAll('\\', '/').toLowerCase();
  return /(?:^|\/)(?:[^/]*(?:audit|history)[^/]*|logs?)(?:\/|$)/u.test(lower);
}

function shellRedirectTargetRisk(target, output) {
  if (typeof target !== 'string' || target === '' || target.startsWith('&')) return true;
  const lower = target.replaceAll('\\', '/').toLowerCase();
  if (!output) return targetsCredentialMaterial(target);
  if (lower === '/dev/null' || lower === 'nul') return false;
  if (targetsAuditOrHistoryPath(lower)
    || /(?:^|\/)\.ssh(?:\/|$)/u.test(lower)
    || /^(?:~\/)?\.(?:bash|zsh|profile)/u.test(lower)
    || /^(?:\/private)?\/(?:etc|var|usr|bin|sbin|system|library)(?:\/|$)/u.test(lower)) {
    return true;
  }
  return targetsCredentialMaterial(target)
    || targetsOpenClawConfigWrite(target) !== false
    || targetsActiveAutomation(target) !== false;
}

function shellRedirectionRisk(segment) {
  const { tokens, dynamicTokenIndexes, operatorTokenIndexes } = segment;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!operatorTokenIndexes.has(index) || !SHELL_REDIRECTIONS.has(token)) continue;
    if (token === '<<' || token === '<<<') return true;
    const target = tokens[index + 1];
    if (dynamicTokenIndexes.has(index + 1)) return true;
    if (token === '>&' || token === '<&') {
      if (typeof target !== 'string' || !/^(?:\d+|-)$/u.test(target)) return true;
      index += 1;
      continue;
    }
    if (shellRedirectTargetRisk(target, token !== '<')) return true;
    index += 1;
  }
  return false;
}

function shellSegmentWithoutRedirections(segment) {
  const tokens = [];
  const dynamicTokenIndexes = new Set();
  for (let index = 0; index < segment.tokens.length; index += 1) {
    if (segment.fdTokenIndexes.has(index)
      && segment.operatorTokenIndexes.has(index + 1)
      && SHELL_REDIRECTIONS.has(segment.tokens[index + 1])) {
      index += 2;
      continue;
    }
    if (segment.operatorTokenIndexes.has(index)
      && SHELL_REDIRECTIONS.has(segment.tokens[index])) {
      index += 1;
      continue;
    }
    if (segment.dynamicTokenIndexes.has(index)) dynamicTokenIndexes.add(tokens.length);
    tokens.push(segment.tokens[index]);
  }
  return { ...segment, tokens, dynamicTokenIndexes };
}

function gitCommandRisk(args) {
  if (args.some((arg) => /^--config-env=alias\./iu.test(arg)
    || /^-calias\./iu.test(arg))) return true;
  let index = 0;
  while (index < args.length && args[index].startsWith('-')) {
    if (args[index] === '-c') {
      if (typeof args[index + 1] !== 'string'
        || args[index + 1].toLowerCase().startsWith('alias.')) return true;
      index += 2;
    } else if (['-C', '--git-dir', '--work-tree', '--namespace'].includes(args[index])) index += 2;
    else index += 1;
  }
  const operation = args[index];
  const operationArgs = args.slice(index + 1);
  if (operation === 'reset') return operationArgs.includes('--hard');
  if (operation === 'clean') {
    return operationArgs.includes('--force') || shortFlagIncludes(operationArgs, 'f');
  }
  if (operation === 'push') {
    return operationArgs.some((arg) => arg === '--delete' || arg === '--force'
      || arg === '--mirror' || arg === '--prune'
      || arg.startsWith('--force-with-lease') || arg.startsWith('+') || arg.startsWith(':'))
      || shortFlagIncludes(operationArgs, 'f');
  }
  if (operation === 'restore') return true;
  if (operation === 'checkout') {
    return operationArgs.includes('--') || operationArgs.includes('--force')
      || shortFlagIncludes(operationArgs, 'Bf');
  }
  if (operation === 'switch') {
    return operationArgs.includes('--discard-changes') || operationArgs.includes('--force-create')
      || operationArgs.includes('--force')
      || operationArgs.some((arg) => arg.startsWith('--force-create='))
      || shortFlagIncludes(operationArgs, 'Cf');
  }
  if (operation === 'branch') {
    return operationArgs.includes('--force')
      || shortFlagIncludes(operationArgs, 'DMf')
      || (operationArgs.includes('--delete') && operationArgs.includes('--force'));
  }
  if (operation === 'stash') return operationArgs.some((arg) => ['clear', 'drop'].includes(arg));
  if (operation !== 'config') return false;
  if (operationArgs.some((arg) => [
    '-e', '--add', '--edit', '--remove-section', '--rename-section', '--replace-all', '--unset',
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
    const end = args.indexOf('--');
    const scoped = args.slice(0, end < 0 ? args.length : end);
    const runIndex = scoped.findIndex((arg) => arg === 'run' || arg === 'run-script');
    const target = runIndex >= 0 ? scoped[runIndex + 1] : (
      name === 'npm' ? null : scoped.find((arg) => !arg.startsWith('-'))
    );
    return typeof target === 'string'
      && !/^(?:check|lint|test)(?::|$)/iu.test(target)
      && /(?:^|:)migrat(?:e|ion)(?:[-:]|$)/iu.test(target);
  }
  if (['make', 'task', 'rake', 'rails'].includes(name)) {
    const target = args.find((arg) => !arg.startsWith('-'));
    return typeof target === 'string'
      && !/^(?:check|lint|test)(?::|$)/iu.test(target)
      && /(?:^|:)migrat(?:e|ion)(?:[-:]|$)/iu.test(target);
  }
  return (name === 'python' || name === 'python3')
    && args.some((arg) => /manage\.py$/iu.test(arg))
    && args.includes('migrate');
}

function shellSegmentRisk(segment, depth) {
  if (shellRedirectionRisk(segment)) return true;
  const parsedSegment = shellSegmentWithoutRedirections(segment);
  const view = shellCommandView(parsedSegment.tokens);
  if (view === null) return false;
  const {
    name, args, ambiguous = false, commandIndex,
  } = view;
  if (ambiguous || parsedSegment.dynamicTokenIndexes.has(commandIndex)) return true;
  const hasDynamicArgs = [...parsedSegment.dynamicTokenIndexes]
    .some((index) => index > commandIndex);
  if (SHELL_CONTROL_WORDS.has(name)) return true;
  if (segment.separatorBefore?.startsWith('|')
    && (SHELL_INTERPRETERS.has(name) || INLINE_INTERPRETERS.has(name) || name === 'eval')) {
    return true;
  }
  if (name === 'eval') return true;
  if (SHELL_INTERPRETERS.has(name)) {
    if (hasDynamicArgs) return true;
    if ([...segment.operatorTokenIndexes].some((index) => (
      ['<', '<&', '<>'].includes(segment.tokens[index])
    ))) {
      return true;
    }
    if (name === 'cmd') return args.some((arg) => /^\/(?:c|k)/iu.test(arg));
    if (name === 'powershell' || name === 'pwsh') {
      return args.some((arg) => /^(?:-|\/)(?:c|command|commandwithargs|cwa|e|ec|enc|encodedcommand)$/iu.test(arg)
        || /^(?:-|\/)(?:c|command|commandwithargs|cwa|e|ec|enc|encodedcommand)[:=]/iu.test(arg));
    }
    if (name === 'fish' && args.some((arg) => (
      /^-[^-]*C/u.test(arg) || arg === '--init-command' || arg.startsWith('--init-command=')
    ))) return true;
    return args.some((arg) => /^-[^-]*c[^-]*$/u.test(arg) || arg === '--command');
  }
  if (INLINE_INTERPRETERS.has(name)
    && (hasDynamicArgs || inlineInterpreterCommand(name, args))) return true;
  if (['awk', 'gawk', 'mawk', 'nawk'].includes(name)
    && (hasDynamicArgs || args.some((arg) => /\bsystem\s*\(/iu.test(arg)))) return true;
  if (DELETE_COMMANDS.has(name)) return hasHelpOrVersion(args) ? false : true;
  if (name === 'find' && args.some((arg) => [
    '-delete', '-exec', '-execdir', '-ok', '-okdir',
  ].includes(arg))) return true;
  if (name === 'find' && hasDynamicArgs) return true;
  if (name === 'history') {
    const historyPrefixes = parsedSegment.tokens.slice(0, commandIndex);
    const historyLimitOverride = historyPrefixes
      .some((token) => /^(?:HISTSIZE|HISTFILESIZE)=/iu.test(token));
    return hasDynamicArgs || args.includes('--clear') || shortFlagIncludes(args, 'cd')
      || (historyLimitOverride && shortFlagIncludes(args, 'w'));
  }
  if (name === ':' && args.some((arg) => arg === '>' || arg === '>>')
    && args.some((arg) => /history/iu.test(arg))) return true;
  if (name === 'truncate') {
    const zeroSize = args.some((arg, index) => (
      /^(?:0+)(?:[bBkKmMgGtTpPeEzZyY](?:i?B)?)?$/u.test(arg)
      && (args[index - 1] === '-s' || args[index - 1] === '--size')
    )) || args.some((arg) => /^-s0+(?:[bBkKmMgGtTpPeEzZyY](?:i?B)?)?$/u.test(arg)
      || /^--size=0+(?:[bBkKmMgGtTpPeEzZyY](?:i?B)?)?$/u.test(arg));
    if (zeroSize && args.some(targetsAuditOrHistoryPath)) return true;
  }
  if (hasDynamicArgs && ['cp', 'dd', 'tee', 'truncate'].includes(name)) return true;
  if (name === 'cp') {
    const positionals = args.filter((arg) => !arg.startsWith('-'));
    if (positionals.length >= 2 && targetsAuditOrHistoryPath(positionals.at(-1))) return true;
  }
  if (name === 'dd'
    && args.some((arg) => arg.startsWith('of=') && targetsAuditOrHistoryPath(arg.slice(3)))) {
    return true;
  }
  if (name === 'tee' && args.some((arg) => !arg.startsWith('-')
    && targetsAuditOrHistoryPath(arg))) return true;
  const hasGitConfigOverride = name === 'git'
    && parsedSegment.tokens.slice(0, commandIndex)
      .some((token) => /^GIT_CONFIG_[A-Za-z0-9_]*=/u.test(token));
  if (name === 'git' && (hasDynamicArgs || hasGitConfigOverride || gitCommandRisk(args))) {
    return true;
  }
  if (hasDynamicArgs && (
    name === 'alembic' || name.includes('migrat')
    || ['dbmate', 'flyway', 'liquibase', 'make', 'rake', 'rails', 'task'].includes(name)
  )) return true;
  if (hasDynamicArgs && PACKAGE_MANAGER_COMMANDS.has(name)) return true;
  if (hasDynamicArgs && (
    PERMISSION_COMMANDS.has(name) || name === 'truncate' || packageInstallCommand(name, args)
  )) return true;
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
    if (hostname === 'localhost' || hostname === 'metadata' || hostname === 'home.arpa'
      || !hostname.includes('.')) return true;
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

  if (toolName === 'skill_workshop') {
    const actionName = ownDataValue(action.params, 'action');
    if (!actionName.ok
      || typeof actionName.value !== 'string'
      || !READ_ONLY_SKILL_WORKSHOP_ACTIONS.has(actionName.value)) return localReview(result);
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
