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
import {
  createApprovalDescription,
  createBlockFeedback,
  feedbackRequiresBlock,
  selectFeedbackCode,
} from './feedback.js';
import { containsOpaqueData, isSecretBearingKey } from './redact.js';
import { objectPrototypeIsPristine } from './intrinsics.js';
import { classifySafePathShape } from './policy-routing.js';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const DECISION_SET = new Set(JUDGE_DECISIONS);
const INVALID_RESPONSE_REASON = 'invalid judge response';
const REVIEW_BLOCK_REASON = 'LLM action judge review required';
const LOCAL_GUARD_REASON = 'local safety guard requires human review';
const INVALID_LOCAL_GUARD_REASON = 'invalid local safety gate input';
const READ_ONLY_CRON_ACTIONS = new Set(['list', 'status', 'get', 'runs']);
const READ_ONLY_PROCESS_ACTIONS = new Set(['list', 'poll', 'log']);
const READ_ONLY_SKILL_WORKSHOP_ACTIONS = new Set(['list']);
const READ_ONLY_NODE_ACTIONS = new Set(['describe', 'pending', 'status']);
const GENERATION_TOOL_NAMES = new Set([
  'image_generate', 'music_generate', 'video_generate',
]);
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
const LOW_RISK_BROWSER_ACTIONS = new Set([
  'console',
  'doctor',
  'focus',
  'navigate',
  'open',
  'profiles',
  'status',
  'tabs',
]);
const LOW_RISK_BROWSER_ACT_KINDS = new Set(['hover', 'resize', 'wait']);
const BROWSER_URL_ACTIONS = new Set(['navigate', 'open']);
const BROWSER_CAPTURE_ACTIONS = new Set(['pdf', 'screenshot', 'snapshot']);
const BROWSER_WAIT_REQUEST_KEYS = new Set(['kind', 'timeMs']);
const BROWSER_WAIT_NESTED_PARAM_KEYS = new Set(['action', 'profile', 'request', 'target']);
const BROWSER_WAIT_LEGACY_PARAM_KEYS = new Set(['action', 'kind', 'profile', 'target', 'timeMs']);
const BROWSER_MAX_WAIT_MS = 30_000;
const FILE_WRITE_TOOLS = new Set(['write', 'edit', 'apply_patch']);
const PACKAGE_MANIFEST_FILES = new Set([
  '.pnpmfile.cjs',
  '.pypirc',
  'build.gradle',
  'build.gradle.kts',
  'bunfig.toml',
  'bun.lock',
  'bun.lockb',
  'cartfile',
  'cartfile.resolved',
  'cargo.lock',
  'cargo.toml',
  'composer.json',
  'composer.lock',
  'conan.lock',
  'conanfile.py',
  'conanfile.txt',
  'deno.json',
  'deno.jsonc',
  'deno.lock',
  'directory.build.props',
  'directory.build.targets',
  'directory.packages.props',
  'environment.yaml',
  'environment.yml',
  'gemfile',
  'gemfile.lock',
  'gems.locked',
  'gems.rb',
  'go.mod',
  'go.sum',
  'go.work',
  'go.work.sum',
  'gradle.properties',
  'gradle.lockfile',
  'init.gradle',
  'init.gradle.kts',
  'manifest.in',
  'mix.exs',
  'mix.lock',
  'npm-shrinkwrap.json',
  'package-lock.json',
  'package.resolved',
  'package.swift',
  'package.json',
  'packages.lock.json',
  'paket.dependencies',
  'paket.lock',
  'pipfile',
  'pipfile.lock',
  'pip.conf',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  'podfile',
  'podfile.lock',
  'poetry.lock',
  'pom.xml',
  'pyproject.toml',
  'pubspec.lock',
  'pubspec.yaml',
  'setup.cfg',
  'setup.py',
  'settings.gradle',
  'settings.gradle.kts',
  'uv.lock',
  'vcpkg-configuration.json',
  'vcpkg.json',
  'yarn.lock',
]);
const PACKAGE_MANIFEST_PATTERN = /^(?:(?:requirements|constraints)(?:[-_.][a-z0-9][a-z0-9._-]*)?\.(?:in|txt)|.+\.(?:csproj|fsproj|gemspec|podspec|vbproj))$/u;
const PACKAGE_MANIFEST_PATH_SUFFIXES = new Set([
  '.bundle/config',
  '.cargo/config',
  '.cargo/config.toml',
  '.cargo/credentials',
  '.cargo/credentials.toml',
  '.m2/settings.xml',
  '.mvn/extensions.xml',
  '.mvn/maven.config',
  'gradle/libs.versions.toml',
  'vendor/modules.txt',
]);
const PACKAGE_BOUNDARY_FILES = new Set(['.dockerignore', '.gitignore', '.npmignore']);
const ACTIVE_REGISTRY_CONFIGS = new Set([
  '.curlrc',
  '.gitconfig',
  '.npmrc',
  '.wgetrc',
  '.yarnrc',
  '.yarnrc.yml',
]);
const ACTIVE_AUTOMATION_FILES = new Set([
  '.drone.yml',
  '.gitattributes',
  '.gitlab-ci.yml',
  '.gitmodules',
  '.woodpecker.yml',
  'azure-pipelines.yml',
  'bitbucket-pipelines.yml',
  'jenkinsfile',
]);
const ACTIVE_AUTOMATION_PATH_SUFFIXES = new Set([
  '.buildkite/pipeline.yml',
  '.circleci/config.yml',
  '.git/config',
  '.git/info/attributes',
  '.git/info/exclude',
  '.config/git/config',
]);
const STARTUP_BASENAMES = new Set([
  '.bash_login', '.bash_profile', '.bashrc', '.pam_environment', '.profile',
  '.xinitrc', '.xprofile', '.zlogin', '.zprofile', '.zshenv', '.zshrc',
  'microsoft.powershell_profile.ps1', 'profile.ps1',
]);
const SECURITY_PATH_SEGMENTS = new Set([
  'acl',
  'auth',
  'authorization',
  'authz',
  'iam',
  'oauth',
  'rbac',
  'security',
]);
const SECURITY_POLICY_FILE = /^(?:acl|config|permissions|policy|rbac|roles?|rules|scopes|session|settings|token)(?:\.(?:spec|test))?(?:\.(?:c|cc|cpp|cs|go|java|js|jsx|json|kt|kts|php|py|rb|rs|sh|toml|ts|tsx|ya?ml))?$/u;
const SECURITY_NAME_MARKER = /(?:^|[._-])(?:acl|access[._-]?control|auth|authentication|authorization|authz|iam|oauth|permissions?|rbac|security)(?=[._-]|$)/u;
const TEST_NAME_MARKER = /(?:^|[._-])(?:spec|test)(?=[._-]|$)/u;
const TEST_PATH_MARKER = /(?:^|[._-])(?:__tests__|specs?|tests?)(?=[._-]|$)/u;
const COMPACT_SECURITY_TEST_NAME = /^(?:(?:specs?|tests?)(?:acl|accesscontrol|auth|authentication|authorization|authz|iam|oauth|permissions?|rbac|security)|(?:acl|accesscontrol|auth|authentication|authorization|authz|iam|oauth|permissions?|rbac|security)(?:specs?|tests?))$/u;
const PRODUCTION_NAME_MARKER = /(?:^|[._-])(?:prod|production)(?=[._-]|$)/u;
const DATA_CONFIG_EXTENSION = /\.(?:cfg|conf|config|env|hcl|ini|json|json5|jsonc|properties|tf|tfvars|toml|xml|ya?ml)$/u;
const CODE_CONFIG_EXTENSION = /\.(?:cjs|gradle|groovy|js|kts|mjs|php|py|rb|ts)$/u;
const ACTIVE_CONFIG_BASENAME = /^(?:config|settings|values)$/u;
const SSH_SECURITY_FILE = /^(?:authorized_keys2?|config|environment|known_hosts|rc)$/u;
const CONFIG_NAME_MARKER = /(?:^|[._-])(?:config|settings|values)(?=[._-]|$)/u;
const CONFIG_PATH_MARKER = /^(?:config|configs|configuration|deploy|deployment|deployments|env|environment|environments|helm|infra|k8s|kubernetes)$/u;
const NAMED_PRODUCTION_CONFIG = /^(?:app|application|config|settings|values)(?:[._-][a-z0-9-]+)*[._-](?:prod|production)$/u;
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
const PATCH_ADD_HEADER = /^\*\*\* Add File: (.+)$/u;
const PATCH_DELETE_HEADER = /^\*\*\* Delete File: (.+)$/u;
const PATCH_UPDATE_HEADER = /^\*\*\* Update File: (.+)$/u;
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
const INERT_TEMPLATE_NAME = /(?:^|[._-])(?:example|sample|template|tmpl)(?:\.(?:cfg|cjs|conf|config|env|hcl|ini|js|json|json5|jsonc|mjs|properties|py|rb|tfvars|toml|ts|xml|ya?ml))?$/u;
const DOCUMENTATION_FILE = /\.(?:adoc|markdown|md|rst)$/u;
const ENV_FILE = /^\.env(?:\..+)?$/u;
const ENVRC_FILE = /^\.envrc(?:\..+)?$/u;
const PRIVATE_KEY_FILE = /^(?:id_(?:dsa|ecdsa|ed25519|rsa)|.*(?:private[._-]?key|privkey).*)$/u;
const PRIVATE_KEY_EXTENSION = /\.(?:jks|key|p12|pfx)$/u;
const PRIVATE_PEM_FILE = /^(?:key|private)\.pem$/u;
const PUBLIC_KEY_FILE = /^(?:id_(?:dsa|ecdsa|ed25519|rsa)(?:-cert)?|.*(?:public[._-]?key|pubkey).*)\.pub$/u;
const CREDENTIAL_NAME = /(?:^|[._-])(?:access[._-]?tokens?|api[._-]?keys?|bearers?|client[._-]?secrets?|cookies?|credentials?|passwords?|passwd|secrets?|tokens?)(?:[._-]|$)/u;
const SENSITIVE_READ_FILES = new Set([
  '.curlrc',
  '.gitconfig',
  '.netrc',
  '.npmrc',
  '.pgpass',
  '.pypirc',
  '.yarnrc',
  '.yarnrc.yml',
  '.wgetrc',
  'credentials',
  'credentials.json',
  'gradle.properties',
  'kubeconfig',
  'nuget.config',
  'pip.conf',
  'pip.ini',
  'service-account.json',
  'service_account.json',
]);
const SENSITIVE_READ_PATH_SUFFIXES = new Set([
  '.bundle/config',
  '.config/git/config',
  '.git/config',
  '.m2/settings-security.xml',
  '.m2/settings.xml',
]);
const SENSITIVE_READ_DIRECTORIES = new Set([
  '.aws',
  '.azure',
  '.direnv',
  '.docker',
  '.gnupg',
  '.kube',
  '.ssh',
  'credentials',
  'secrets',
  'vault',
]);
const OPENCLAW_WORKSPACE_BOOTSTRAP_FILES = new Set([
  'agents.md',
  'heartbeat.md',
  'identity.md',
  'memory.md',
  'soul.md',
  'tools.md',
  'user.md',
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
const EXECUTION_DISPATCHERS = new Set([
  'chroot', 'doas', 'firejail', 'ltrace', 'nsenter', 'proot', 'runuser', 'scp',
  'script', 'setsid', 'sftp', 'ssh', 'strace', 'su', 'systemd-run', 'unshare',
]);
const CONTAINER_DISPATCHERS = new Set(['docker', 'podman']);
const DANGEROUS_EXEC_ENV_NAME = /^(?:ALL_PROXY|BASH_ENV|BASH_FUNC_.+|CDPATH|CLASSPATH|CURL_HOME|EDITOR|ENV|FPATH|GIT_.+|GRADLE_OPTS|HOME|HTTPS?_PROXY|IFS|JAVA_OPTS|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|LD_.+|LESSOPEN|MANPAGER|MAVEN_OPTS|NODE_OPTIONS|NODE_PATH|NO_PROXY|OPENCLAW_.+|PAGER|PATH|PERL5LIB|PERL5OPT|PHPRC|PHP_INI_SCAN_DIR|PROMPT_COMMAND|PYTHONBREAKPOINT|PYTHONHOME|PYTHONINSPECT|PYTHONPATH|PYTHONSTARTUP|RIPGREP_CONFIG_PATH|RUBYLIB|RUBYOPT|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|SHELLOPTS|SSH_ASKPASS|VISUAL|WGETRC|XDG_(?:CONFIG|DATA|STATE)_HOME|ZDOTDIR|_JAVA_OPTIONS)$/u;
const SAFE_ENV_METADATA_NAMES = new Set([
  'MAX_TOKENS', 'TOKEN_BUDGET', 'TOKEN_COUNT', 'TOKEN_LIMIT', 'TOKEN_USAGE',
]);
const CREDENTIAL_READER_COMMANDS = new Set([
  '7z', 'age', 'ar', 'awk', 'base64', 'bsdtar', 'bunzip2', 'bzip2', 'cat', 'cut', 'egrep', 'fgrep',
  'file', 'gawk', 'gpg', 'gpg2', 'grep', 'gunzip', 'gzip', 'head', 'hexdump', 'jq',
  'jar', 'less', 'mawk', 'more', 'nawk', 'od', 'openssl', 'rg', 'scp', 'sed', 'sftp',
  'sort', 'strings', 'tail', 'tar', 'uniq', 'unxz', 'unzip', 'unzstd', 'wc', 'xxd', 'xz',
  'yq', 'zip', 'zstd',
]);
const CREDENTIAL_QUERY_READER_COMMANDS = new Set([
  'awk', 'egrep', 'fgrep', 'gawk', 'grep', 'jq', 'mawk', 'nawk', 'rg', 'sed', 'yq',
]);
const PACKAGE_MANAGER_COMMANDS = new Set([
  'apk', 'apt', 'apt-get', 'brew', 'bun', 'bundle', 'bundler', 'bunx', 'cargo',
  'composer', 'conda', 'corepack', 'dart', 'deno', 'dnf', 'dotnet', 'flutter', 'gem',
  'go', 'gradle', 'gradlew', 'mamba', 'micromamba', 'mix', 'mvn', 'mvnw', 'npm',
  'npx', 'nuget', 'pip', 'pip3', 'pipenv', 'pipx', 'pnpm', 'pnpx', 'pod', 'poetry',
  'swift', 'uv', 'uvx', 'yarn', 'yarnpkg', 'yum', 'zypper',
]);
const SHELL_CONTROL_WORDS = new Set([
  '!', '.', 'case', 'cd', 'coproc', 'do', 'done', 'elif', 'else', 'esac', 'fi',
  'for', 'function', 'if', 'in', 'noglob', 'popd', 'pushd', 'select', 'source',
  'then', 'trap', 'until', 'while',
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
  const rawName = normalized.slice(normalized.lastIndexOf('/') + 1).toLowerCase();
  const name = /\.(?:cmd|exe)$/u.test(rawName) ? rawName.slice(0, -4) : rawName;
  if (name === 'py' || name === 'pyw'
    || /^python(?:[23](?:\.\d+)*)?[tw]?$/u.test(name)
    || /^pypy(?:3(?:\.\d+)*)?[w]?$/u.test(name)) return 'python3';
  if (/^pip3(?:\.\d+)+$/u.test(name)) return 'pip3';
  if (/^php\d+(?:\.\d+)*$/u.test(name)) return 'php';
  if (/^ruby\d+(?:\.\d+)*$/u.test(name)) return 'ruby';
  if (/^perl\d+(?:\.\d+)*$/u.test(name)) return 'perl';
  if (/^lua\d+(?:\.\d+)*$/u.test(name)) return 'lua';
  if (/^node(?:js)?\d+(?:\.\d+)*$/u.test(name)) return 'node';
  if (/^bash\d+(?:\.\d+)*$/u.test(name)) return 'bash';
  if (/^zsh\d+(?:\.\d+)*$/u.test(name)) return 'zsh';
  if (name === 'pwsh-preview') return 'pwsh';
  if (name === 'powershell-preview') return 'powershell';
  return name;
}

function isShellAssignment(value) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/u.test(value);
}

function dangerousShellAssignment(value) {
  if (!isShellAssignment(value)) return false;
  const name = value.slice(0, value.indexOf('=')).toUpperCase();
  return DANGEROUS_EXEC_ENV_NAME.test(name) || /^DYLD_/u.test(name);
}

function secretEnvironmentReference(value) {
  if (typeof value !== 'string') return false;
  if (/\$\{!/u.test(value)) return true;
  const names = [];
  for (const match of value.matchAll(/\$(?:\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|([A-Za-z_][A-Za-z0-9_]*))/gu)) {
    names.push(match[1] ?? match[2]);
  }
  for (const match of value.matchAll(/\$env:([A-Za-z_][A-Za-z0-9_]*)/giu)) {
    names.push(match[1]);
  }
  return names.some((name) => {
    const normalized = name.toUpperCase();
    return !SAFE_ENV_METADATA_NAMES.has(normalized) && isSecretBearingKey(normalized);
  });
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
      const originalArgs = tokens.slice(index + 1);
      return {
        name,
        args: originalArgs,
        ambiguous: !(originalArgs.length === 1 && hasHelpOrVersion(originalArgs)),
        commandIndex: index,
      };
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
      const originalArgs = tokens.slice(index + 1);
      if (originalArgs.some((arg) => arg === '-o' || arg === '--output'
        || /^-o.+/u.test(arg) || arg.startsWith('--output='))) {
        return { name, args: originalArgs, ambiguous: true, commandIndex: index };
      }
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
        || arg.startsWith('--split-string=')
        || arg === '-C' || arg === '-P' || arg === '--chdir'
        || arg.startsWith('--chdir='))) {
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
  const separatorIndex = args.indexOf('--');
  const optionScope = separatorIndex < 0 ? args : args.slice(0, separatorIndex);
  return optionScope.includes('--help') || optionScope.includes('--version');
}

function shortFlagIncludes(args, letters) {
  return args.some((arg) => (
    /^-[^-]+$/u.test(arg) && [...letters].some((letter) => arg.slice(1).includes(letter))
  ));
}

function packageOptionsWithValues(name) {
  const optionsWithValues = new Set();
  if (name === 'npm') {
    for (const option of [
      '-C', '-w', '--cache', '--loglevel', '--prefix', '--registry', '--tag', '--userconfig',
      '--workspace',
    ]) optionsWithValues.add(option);
  }
  if (name === 'pnpm') {
    for (const option of [
      '-C', '-F', '--dir', '--filter', '--global-dir', '--registry', '--virtual-store-dir',
      '--reporter', '--workspace-concurrency',
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
  if (name === 'uv') {
    for (const option of [
      '--cache-dir', '--color', '--config-file', '--default-index', '--directory',
      '--extra-index-url', '--find-links', '--index', '--index-url', '--keyring-provider',
      '--project', '--python',
    ]) optionsWithValues.add(option);
  }
  if (name === 'poetry') {
    for (const option of ['-C', '-P', '--cache-dir', '--directory', '--project']) {
      optionsWithValues.add(option);
    }
  }
  if (['bundle', 'bundler'].includes(name)) optionsWithValues.add('--gemfile');
  if (name === 'composer') {
    for (const option of ['-d', '--working-dir']) optionsWithValues.add(option);
  }
  if (['conda', 'mamba', 'micromamba'].includes(name)) {
    for (const option of [
      '-c', '-n', '-p', '--channel', '--name', '--prefix', '--rc-file', '--root-prefix',
    ]) optionsWithValues.add(option);
  }
  if (name === 'gradle' || name === 'gradlew') {
    for (const option of [
      '-I', '-b', '-g', '-p', '--build-file', '--gradle-user-home', '--init-script',
      '--project-dir', '--settings-file',
    ]) optionsWithValues.add(option);
  }
  if (name === 'mvn' || name === 'mvnw') {
    for (const option of [
      '-f', '-gs', '-pl', '-s', '-t', '--file', '--global-settings', '--projects',
      '--settings', '--toolchains',
    ]) optionsWithValues.add(option);
  }
  if (name === 'swift') {
    for (const option of ['--package-path', '--scratch-path']) optionsWithValues.add(option);
  }
  if (name === 'deno') {
    for (const option of ['--config', '--import-map']) optionsWithValues.add(option);
  }
  return optionsWithValues;
}

function packageRootOptionAmbiguityRisk(name, args) {
  const optionsWithValues = packageOptionsWithValues(name);
  const knownFlags = new Set([
    '--ansi', '--debug', '--help', '--no-ansi', '--no-color', '--no-interaction', '--offline',
    '--quiet', '--silent', '--verbose', '--version', '-V', '-h', '-q', '-v',
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--' || !arg.startsWith('-')) return false;
    if (optionsWithValues.has(arg)) {
      const value = args[index + 1];
      if (typeof value !== 'string' || value === '' || value.startsWith('-')) return true;
      index += 1;
      continue;
    }
    if ([...optionsWithValues].some((option) => arg.startsWith(`${option}=`))) continue;
    if (knownFlags.has(arg) || arg.includes('=')) continue;
    const remainingPositionals = args.slice(index + 1)
      .filter((value) => value !== '--' && !value.startsWith('-'));
    if (remainingPositionals.length >= 2) return true;
  }
  return false;
}

function packageArgsWithoutOptionValues(name, args) {
  const optionsWithValues = packageOptionsWithValues(name);
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

function pythonModuleInvocation(args) {
  for (let index = 0; index < args.length; index += 1) {
    const match = /^-[3bBdEiIOPqRsStuvx]*m(.*)$/u.exec(args[index]);
    if (!match) continue;
    const attached = match[1];
    const module = attached || args[index + 1];
    return {
      found: true,
      module,
      args: args.slice(index + (attached ? 1 : 2)),
    };
  }
  return { found: false, module: undefined, args: [] };
}

function packageMutationCommand(inputName, args) {
  const name = inputName === 'yarnpkg' ? 'yarn' : inputName;
  if (name === 'python' || name === 'python3') {
    const invocation = pythonModuleInvocation(args);
    if (invocation.found && ['pip', 'pip3'].includes(invocation.module)) {
      return packageMutationCommand(invocation.module, invocation.args);
    }
  }
  if (PACKAGE_MANAGER_COMMANDS.has(name) && packageRootOptionAmbiguityRisk(name, args)) {
    return true;
  }
  const uvPipIndex = name === 'uv' ? args.indexOf('pip') : -1;
  if (uvPipIndex >= 0) return packageMutationCommand('pip', args.slice(uvPipIndex + 1));
  if (name === 'corepack') {
    const targetIndex = args.findIndex((arg) => [
      'npm', 'pnpm', 'yarn', 'yarnpkg',
    ].includes(arg.toLowerCase()));
    if (targetIndex >= 0) {
      return packageMutationCommand(args[targetIndex].toLowerCase(), args.slice(targetIndex + 1));
    }
    if (args.length === 0
      || args.every((arg) => ['-h', '--help', '--version'].includes(arg))) return false;
    return true;
  }
  if (['npx', 'pnpx', 'bunx', 'uvx'].includes(name)) {
    return args.length > 0
      && !args.every((arg) => ['-h', '--help', '--version'].includes(arg));
  }
  const normalizedArgs = packageArgsWithoutOptionValues(name, args)
    .map((arg) => arg.toLowerCase());
  const firstDoubleDash = normalizedArgs.indexOf('--');
  const prefixHasOperation = firstDoubleDash >= 0
    && normalizedArgs.slice(0, firstDoubleDash).some((arg) => !arg.startsWith('-'));
  const commandArgs = firstDoubleDash >= 0 && !prefixHasOperation
    ? normalizedArgs.slice(firstDoubleDash + 1)
    : normalizedArgs;
  const doubleDashIndex = commandArgs.indexOf('--');
  const beforeDoubleDash = commandArgs.slice(0, doubleDashIndex < 0
    ? commandArgs.length
    : doubleDashIndex);
  const afterDoubleDash = doubleDashIndex < 0 ? [] : commandArgs.slice(doubleDashIndex + 1);
  const positionals = beforeDoubleDash.filter((arg) => !arg.startsWith('-'));
  const operation = positionals[0];
  const operationArgs = [
    ...positionals.slice(1),
    ...afterDoubleDash.filter((arg) => !arg.startsWith('-')),
  ];
  const hasOption = (...options) => [...beforeDoubleDash, ...afterDoubleDash]
    .some((arg) => options.includes(arg));
  const managerHelp = beforeDoubleDash
    .some((arg) => ['-h', '--help', '--version'].includes(arg));
  const classifyKnown = (mutating, inspecting, emptyRisk = false) => {
    if (operation === undefined) return managerHelp ? false : emptyRisk;
    if (mutating.includes(operation)) return managerHelp ? false : true;
    if (inspecting.includes(operation)) return false;
    return true;
  };

  if (['pip', 'pip3'].includes(name)) {
    if (operation === 'config') {
      if (managerHelp) return false;
      if (['get', 'list'].includes(operationArgs[0]) || operationArgs.length === 0) return false;
      return true;
    }
    if (operation === 'cache') {
      if (managerHelp) return false;
      return !['dir', 'info', 'list'].includes(operationArgs[0]);
    }
    return classifyKnown(
      ['download', 'install', 'lock', 'uninstall', 'wheel'],
      [
        'check', 'debug', 'freeze', 'hash', 'help', 'index', 'info', 'inspect', 'list',
        'outdated', 'search', 'show', 'version', 'why',
      ],
    );
  }
  if (name === 'pipx') {
    if (['run', 'runpip'].includes(operation)) {
      return operationArgs.length > 0 || !managerHelp;
    }
    return classifyKnown([
      'inject', 'install', 'reinstall', 'reinstall-all', 'uninstall', 'uninstall-all', 'upgrade',
      'upgrade-all',
    ], ['environment', 'help', 'list']);
  }
  if (name === 'gem') {
    if (operation === 'check') return hasOption('--repair') && !managerHelp;
    if (operation === 'sources') {
      if (managerHelp) return false;
      return !hasOption('--list', '-l');
    }
    if (operation === 'owner') {
      if (managerHelp) return false;
      return !hasOption('--show');
    }
    if (operation === 'cert') {
      if (managerHelp) return false;
      return !hasOption('--list', '-l');
    }
    return classifyKnown(
      [
        'build', 'cleanup', 'fetch', 'i', 'install', 'pristine', 'push', 'uninstall', 'update',
        'yank',
      ],
      [
        'contents', 'dependency', 'environment', 'help', 'info', 'list', 'outdated', 'search',
        'specification', 'which',
      ],
    );
  }
  if (name === 'cargo') {
    if (['bench', 'run', 'test'].includes(operation)) {
      return operationArgs.length > 0 || !managerHelp;
    }
    if (operation === 'metadata') return managerHelp ? false : !hasOption('--no-deps');
    if (operation === 'fmt') {
      return managerHelp ? false : !afterDoubleDash.includes('--check');
    }
    if (operation === 'tree') {
      return managerHelp ? false : !(hasOption('--locked') && hasOption('--offline'));
    }
    return classifyKnown(
      [
        'add', 'bench', 'build', 'check', 'clean', 'clippy', 'doc', 'fetch', 'fix',
        'generate-lockfile', 'init', 'install', 'new', 'remove', 'run', 'test', 'uninstall',
        'update', 'vendor',
      ],
      [
        'help', 'locate-project', 'pkgid', 'read-manifest', 'search', 'verify-project', 'version',
      ],
    );
  }
  if (name === 'go') {
    if (operation === 'run') return operationArgs.length > 0 || !managerHelp;
    if (operation === 'mod') {
      if (managerHelp) return false;
      const subcommand = operationArgs[0];
      if (subcommand === 'tidy' && hasOption('-diff')) return false;
      if (subcommand === 'edit' && hasOption('-json', '-print')) return false;
      if (['graph', 'verify', 'why'].includes(subcommand)) return false;
      return true;
    }
    if (operation === 'work') {
      if (managerHelp) return false;
      const subcommand = operationArgs[0];
      if (subcommand === 'edit' && hasOption('-json', '-print')) return false;
      return true;
    }
    if (operation === 'env') return managerHelp ? false : hasOption('-u', '-w');
    if (operation === 'list') return managerHelp ? false : hasOption('-mod=mod');
    return classifyKnown(
      ['build', 'clean', 'fix', 'fmt', 'generate', 'get', 'install', 'run', 'test'],
      ['doc', 'help', 'version', 'vet'],
    );
  }
  if (name === 'brew') {
    return classifyKnown(
      [
        'autoremove', 'cleanup', 'install', 'link', 'pin', 'reinstall', 'tap', 'uninstall',
        'unlink', 'unpin', 'untap', 'update', 'upgrade',
      ],
      ['config', 'deps', 'doctor', 'help', 'info', 'list', 'outdated', 'search'],
    );
  }
  if (name === 'npm') {
    if (['run', 'run-script'].includes(operation)) {
      const target = operationArgs[0];
      if (managerHelp && typeof target === 'string') return true;
      return typeof target === 'string' && !/^(?:check|lint|test)(?::|$)/u.test(target);
    }
    if (operation === 'test') return managerHelp;
    if (operation === 'exec') return operationArgs.length > 0 || !managerHelp;
    if (['create', 'init'].includes(operation)) return managerHelp ? operationArgs.length > 0 : true;
    if (['restart', 'start', 'stop'].includes(operation)) return true;
    if (operation === 'audit') {
      return managerHelp ? false : operationArgs.includes('fix') || hasOption('--fix');
    }
    if (operation === 'pkg') {
      if (managerHelp || operationArgs.length === 0 || operationArgs[0] === 'get') return false;
      return true;
    }
    if (operation === 'config') {
      if (managerHelp || operationArgs.length === 0
        || ['get', 'list'].includes(operationArgs[0])) return false;
      return true;
    }
    if (operation === 'version') {
      return managerHelp ? false : operationArgs.length > 0;
    }
    return classifyKnown(
      [
        'add', 'ci', 'cit', 'create', 'ddp', 'dedupe', 'edit', 'exec', 'explore', 'i', 'in',
        'init', 'ins', 'inst', 'insta', 'install', 'install-ci-test', 'install-test', 'it', 'link',
        'ln', 'pack', 'prune', 'publish', 'r', 'rb', 'rebuild', 'remove', 'restart', 'rm',
        'shrinkwrap', 'start', 'stop', 'un', 'uninstall', 'unlink', 'up', 'update', 'upgrade',
      ],
      [
        'completion', 'diff', 'doctor', 'explain', 'find-dupes', 'fund', 'get', 'help',
        'help-search', 'info', 'la', 'list', 'll', 'ls', 'outdated', 'ping', 'prefix', 'query',
        'root', 'sbom', 'search', 'show', 'view', 'whoami', 'why',
      ],
    );
  }
  if (name === 'pnpm') {
    if (['create', 'dlx', 'exec', 'run'].includes(operation)) {
      return operationArgs.length > 0 || !managerHelp;
    }
    if (operation === 'audit') return managerHelp ? false : hasOption('--fix');
    if (['config', 'c'].includes(operation)) {
      if (managerHelp || operationArgs.length === 0
        || ['get', 'list'].includes(operationArgs[0])) return false;
      return true;
    }
    if (operation === 'dedupe') return managerHelp ? false : !hasOption('--check');
    if (operation === 'env') {
      if (managerHelp) return false;
      return !['list', 'ls'].includes(operationArgs[0]);
    }
    if (operation === 'store') {
      if (managerHelp) return false;
      return !['path', 'status'].includes(operationArgs[0]);
    }
    if (operation === 'cache') {
      if (managerHelp) return false;
      return !['list', 'view'].includes(operationArgs[0]);
    }
    return classifyKnown(
      [
        'add', 'approve-builds', 'create', 'deploy', 'dlx', 'exec', 'i', 'import', 'init',
        'install', 'install-test', 'it', 'link', 'ln', 'pack', 'patch', 'patch-commit',
        'patch-remove', 'prune', 'publish', 'rb', 'rebuild', 'remove', 'rm', 'run', 'setup',
        'unlink', 'up', 'update',
      ],
      [
        'bin', 'cat-file', 'cat-index', 'doctor', 'find-hash', 'help', 'ignored-builds',
        'licenses', 'list', 'ls', 'outdated', 'root', 'why',
      ],
    );
  }
  if (name === 'yarn') {
    if (['create', 'dlx', 'exec', 'node', 'run'].includes(operation)) {
      return operationArgs.length > 0 || !managerHelp;
    }
    if (operation === 'config') {
      if (managerHelp || operationArgs.length === 0
        || ['get', 'list'].includes(operationArgs[0])) return false;
      return true;
    }
    if (operation === 'constraints') return managerHelp ? false : hasOption('--fix');
    if (operation === 'dedupe') return managerHelp ? false : !hasOption('--check');
    if (operation === 'patch-commit') {
      return managerHelp ? false : hasOption('--save', '-s');
    }
    if (operation === 'version') {
      if (managerHelp || operationArgs[0] === 'check') return false;
      return true;
    }
    if (operation === 'workspace') {
      if (managerHelp) return operationArgs.length >= 2;
      if (operationArgs.length < 2) return true;
      return packageMutationCommand('yarn', operationArgs.slice(1));
    }
    if (operation === 'workspaces') {
      if (operationArgs[0] === 'list') return false;
      if (managerHelp) return operationArgs.length > 1;
      return true;
    }
    if (operation === 'npm') {
      if (managerHelp) return false;
      if (['audit', 'info', 'whoami'].includes(operationArgs[0])) return false;
      return !(operationArgs[0] === 'tag' && operationArgs[1] === 'list');
    }
    if (operation === 'plugin') {
      if (managerHelp || ['check', 'list', 'runtime'].includes(operationArgs[0])) return false;
      return true;
    }
    if (operation === 'cache') {
      if (managerHelp || ['dir', 'list'].includes(operationArgs[0])) return false;
      return true;
    }
    if (operation === 'global') {
      if (managerHelp || ['bin', 'dir'].includes(operationArgs[0])) return false;
      return true;
    }
    if (operation === 'policies') return managerHelp ? false : true;
    return classifyKnown(
      [
        'add', 'autoclean', 'create', 'dlx', 'exec', 'import', 'init', 'install', 'link', 'node',
        'pack', 'patch', 'publish', 'rebuild', 'remove', 'run', 'set', 'unlink', 'unplug', 'up',
        'upgrade',
      ],
      [
        'audit', 'bin', 'check', 'explain', 'generate-lock-entry', 'help', 'info', 'licenses',
        'list', 'outdated', 'versions', 'why',
      ],
      true,
    );
  }
  if (name === 'bun') {
    if (operation === 'pm') {
      if (managerHelp) return false;
      const subcommand = operationArgs[0];
      const nested = operationArgs.slice(1);
      if (subcommand === 'pkg') return !(['get'].includes(nested[0]) || nested.length === 0);
      if (subcommand === 'version') return nested.length > 0;
      if (subcommand === 'cache') return nested[0] === 'rm';
      if ([
        'bin', 'cache', 'default-trusted', 'hash', 'hash-print', 'hash-string', 'list', 'ls',
        'pkg', 'scan', 'untrusted', 'version', 'view', 'whoami', 'why',
      ].includes(subcommand)) return false;
      return true;
    }
    if (['create', 'exec', 'run', 'test', 'x'].includes(operation)) {
      return operationArgs.length > 0 || !managerHelp;
    }
    if (['add', 'a', 'install', 'i'].includes(operation) && hasOption('--dry-run')) return false;
    return classifyKnown(
      [
        'a', 'add', 'c', 'create', 'exec', 'i', 'init', 'install', 'link', 'patch',
        'patch-commit', 'publish', 'r', 'remove', 'rm', 'unlink', 'update', 'upgrade',
      ],
      ['audit', 'help', 'info', 'outdated', 'why'],
      true,
    );
  }
  if (['apt', 'apt-get', 'dnf', 'yum', 'zypper'].includes(name)) {
    return classifyKnown(
      [
        'autoremove', 'clean', 'dist-upgrade', 'downgrade', 'install', 'reinstall', 'remove',
        'update', 'upgrade',
      ],
      ['check', 'help', 'info', 'list', 'search', 'show'],
    );
  }
  if (name === 'apk') {
    return classifyKnown(
      ['add', 'cache', 'del', 'fix', 'update', 'upgrade'],
      ['audit', 'help', 'info', 'list', 'search', 'version'],
    );
  }
  if (name === 'poetry') {
    if (operation === 'run') return operationArgs.length > 0 || !managerHelp;
    if (operation === 'shell') return !managerHelp;
    if (operation === 'config') {
      if (managerHelp || hasOption('--list') || operationArgs.length <= 1) return false;
      return true;
    }
    if (operation === 'source') {
      if (managerHelp || operationArgs[0] === 'show') return false;
      return true;
    }
    if (operation === 'env') {
      if (managerHelp || ['info', 'list'].includes(operationArgs[0])) return false;
      return true;
    }
    if (operation === 'version') return managerHelp ? false : operationArgs.length > 0;
    return classifyKnown(
      [
        'add', 'init', 'install', 'lock', 'remove', 'self', 'sync', 'update',
      ],
      ['check', 'debug', 'help', 'search', 'show'],
    );
  }
  if (name === 'bundle' || name === 'bundler') {
    if (operation === 'exec') return operationArgs.length > 0 || !managerHelp;
    if (operation === 'config') {
      if (managerHelp || operationArgs.length === 0
        || ['get', 'list'].includes(operationArgs[0])) return false;
      return true;
    }
    return classifyKnown(
      [
        'add', 'cache', 'clean', 'exec', 'init', 'install', 'lock', 'open', 'remove', 'update',
      ],
      ['check', 'help', 'info', 'list', 'outdated', 'platform', 'show', 'version'],
    );
  }
  if (name === 'pipenv') {
    if (hasOption('--clear', '--rm')) return true;
    if (operation === undefined && hasOption('--py', '--support', '--venv', '--where')) return false;
    if (operation === 'run') return operationArgs.length > 0 || !managerHelp;
    if (operation === 'shell') return !managerHelp;
    return classifyKnown(
      ['clean', 'install', 'lock', 'open', 'run', 'shell', 'sync', 'uninstall', 'update'],
      ['check', 'graph', 'help', 'requirements', 'scripts', 'version'],
    );
  }
  if (['conda', 'mamba', 'micromamba'].includes(name)) {
    if (operation === 'run') return operationArgs.length > 0 || !managerHelp;
    if (operation === 'config') {
      if (managerHelp || hasOption('--get', '--show', '--show-sources')) return false;
      return true;
    }
    if (operation === 'env') {
      if (managerHelp || operationArgs[0] === 'list') return false;
      if (operationArgs[0] === 'config'
        && operationArgs[1] === 'vars'
        && operationArgs[2] === 'list') return false;
      return true;
    }
    return classifyKnown(
      [
        'clean', 'create', 'install', 'package', 'remove', 'rename', 'run', 'uninstall', 'update',
        'upgrade',
      ],
      ['compare', 'help', 'info', 'list', 'notices', 'search'],
    );
  }
  if (name === 'gradle' || name === 'gradlew') {
    return classifyKnown([], [
      'buildenvironment', 'components', 'dependencies', 'dependencyinsight', 'help', 'model',
      'outgoingvariants', 'projects', 'properties', 'resolvableconfigurations', 'tasks',
    ]);
  }
  if (name === 'mvn' || name === 'mvnw') {
    if (operation?.startsWith('help:') || operation === 'dependency:tree') return false;
    return classifyKnown([], ['help']);
  }
  if (name === 'pod') {
    return classifyKnown(
      ['cache', 'deintegrate', 'env', 'init', 'install', 'ipc', 'lib', 'repo', 'setup', 'trunk', 'update'],
      ['help', 'list', 'outdated', 'search'],
    );
  }
  if (name === 'swift') {
    if (operation === 'package') {
      if (managerHelp || ['describe', 'dump-package', 'show-dependencies'].includes(operationArgs[0])) {
        return false;
      }
      if (operationArgs[0] === 'tools-version') return operationArgs.length > 1;
      return true;
    }
    if (operation === 'run') return operationArgs.length > 0 || !managerHelp;
    return classifyKnown(['build', 'test'], ['help', 'version']);
  }
  if (name === 'nuget') {
    if (operation === 'locals') return managerHelp ? false : !hasOption('-list');
    if (operation === 'sources') {
      if (managerHelp || ['list'].includes(operationArgs[0])) return false;
      return true;
    }
    return classifyKnown(
      ['add', 'delete', 'init', 'install', 'push', 'restore', 'setapikey', 'update'],
      ['help', 'list', 'search', 'spec', 'verify'],
    );
  }
  if (name === 'composer') {
    if (['exec', 'run-script'].includes(operation)) {
      return operationArgs.length > 0 || !managerHelp;
    }
    if (operation === 'config') {
      if (managerHelp || hasOption('--list', '-l') || operationArgs.length <= 1) return false;
      return true;
    }
    if (['repo', 'repository'].includes(operation)) {
      if (managerHelp || operationArgs[0] === 'list') return false;
      return true;
    }
    return classifyKnown(
      [
        'bump', 'clear-cache', 'create-project', 'dump-autoload', 'exec', 'init', 'install',
        'reinstall', 'remove', 'require', 'run-script', 'update',
      ],
      [
        'audit', 'diagnose', 'fund', 'help', 'licenses', 'outdated', 'show', 'status',
        'validate', 'why',
      ],
    );
  }
  if (name === 'deno') {
    if (['run', 'task', 'test'].includes(operation)) {
      return operationArgs.length > 0 || !managerHelp;
    }
    if (operation === 'fmt') return managerHelp ? false : !hasOption('--check');
    return classifyKnown(
      ['add', 'cache', 'install', 'remove', 'run', 'task', 'test', 'uninstall'],
      ['check', 'doc', 'help', 'info', 'lint'],
    );
  }
  if (name === 'mix') {
    if (managerHelp || ['deps', 'deps.tree', 'help'].includes(operation)) return false;
    return operation !== undefined;
  }
  if (name === 'dart' || name === 'flutter') {
    const pubIndex = positionals.indexOf('pub');
    if (managerHelp) return false;
    if (pubIndex < 0) return operation === undefined ? false : true;
    return !['deps', 'outdated'].includes(positionals[pubIndex + 1]);
  }
  if (name === 'dotnet') {
    if (['run', 'test'].includes(operation)) {
      return operationArgs.length > 0 || !managerHelp;
    }
    return classifyKnown(
      ['add', 'build', 'clean', 'format', 'new', 'remove', 'restore', 'run', 'test', 'tool', 'workload'],
      ['help', 'list', 'nuget', 'sdk-check'],
    );
  }
  if (name === 'uv') {
    return classifyKnown([], ['help', 'version']);
  }
  return false;
}

function inlineInterpreterCommand(name, args) {
  return args.some((arg) => (
    arg === '-c'
    || arg === '-e'
    || (name === 'perl' && /^-E(?:.*)$/u.test(arg))
    || (['perl', 'ruby'].includes(name) && /^-[^-]*[eE]/u.test(arg))
    || arg === '--eval'
    || /^-(?:c|e).+/u.test(arg)
    || (name === 'python3' && /^-[3bBdEiIOPqRsStuvx]*c.*$/u.test(arg))
    || arg.startsWith('--eval=')
    || ((name === 'node' || name === 'nodejs') && (
      arg === '-p' || arg === '--print' || /^-p.+/u.test(arg) || arg.startsWith('--print=')
    ))
    || (name === 'php' && (
      ['-B', '-E', '-R', '-r', '--process-begin', '--process-code', '--process-end'].includes(arg)
      || /^-[BERr].+/u.test(arg)
      || /^-[CenqH]*[BERr].*$/u.test(arg)
      || arg === '--run'
      || arg.startsWith('--run=')
      || /^--process-(?:begin|code|end)=/u.test(arg)
    ))
  ));
}

function targetsAuditOrHistoryPath(value) {
  if (typeof value !== 'string') return true;
  const lower = value.replaceAll('\\', '/').toLowerCase();
  return /(?:^|\/)(?:[^/]*(?:audit|history)[^/]*|logs?)(?:\/|$)/u.test(lower);
}

function targetsAuditOrHistoryWrite(value) {
  const normalized = normalizedFilePath(value);
  if (normalized === null) return true;
  const segments = normalized.split('/').filter(Boolean);
  const name = segments.at(-1);
  const parents = segments.slice(0, -1);
  if (parents.some((segment) => /^(?:audit(?:-logs?)?s?|logs?)$/u.test(segment))) {
    return true;
  }
  if (/^\.(?:bash|fish|sh|zsh)_history$/u.test(name) || name === 'history') return true;
  return /(?:^|[._-])(?:audit|history)(?:[._-]|$)/u.test(filenameStem(name))
    && /\.(?:db|json|jsonl|log|ndjson|sqlite|sqlite3)$/u.test(name);
}

function normalizedShellWorkdir(value) {
  if (typeof value !== 'string' || value.trim() === '' || value !== value.trim()
    || CONTROL_PATTERN.test(value)
    || /[$`*?\[\]{}()]/u.test(value)
    || pathHasRawTraversal(value)
    || pathHasAmbiguousWindowsAlias(value)
    || pathHasWindowsAlternateDataStream(value)) return null;
  const slashPath = value.replaceAll('\\', '/');
  if (slashPath !== '~' && !slashPath.startsWith('~/')
    && !slashPath.startsWith('/') && !/^[a-zA-Z]:\//u.test(slashPath)) return null;
  return pathPosix.normalize(slashPath);
}

function resolveShellPath(value, workdir) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  const slashPath = value.replaceAll('\\', '/');
  if (slashPath === '~' || slashPath.startsWith('~/')
    || slashPath.startsWith('/') || /^[a-zA-Z]:\//u.test(slashPath)) return slashPath;
  if (workdir === undefined) return slashPath;
  const normalizedWorkdir = normalizedShellWorkdir(workdir);
  return normalizedWorkdir === null ? null : pathPosix.join(normalizedWorkdir, slashPath);
}

function targetsShellProtectedWritePath(value, workdir, includePackageBoundary = true) {
  const resolved = resolveShellPath(value, workdir);
  return resolved === null || targetsProtectedWritePath(resolved, includePackageBoundary);
}

function targetsShellProtectedReadPath(value, workdir) {
  const resolved = resolveShellPath(value, workdir);
  return resolved === null || targetsProtectedReadPath(resolved);
}

function shellRedirectTargetRisk(target, output, workdir) {
  if (typeof target !== 'string' || target === '' || target.startsWith('&')) return true;
  const lower = target.replaceAll('\\', '/').toLowerCase();
  if (!output) return targetsShellProtectedReadPath(target, workdir);
  if (lower === '/dev/null' || lower === 'nul') return false;
  if (targetsAuditOrHistoryPath(lower)
    || /(?:^|\/)\.ssh(?:\/|$)/u.test(lower)
    || /^(?:~\/)?\.(?:bash|zsh|profile)/u.test(lower)
    || /^(?:\/private)?\/(?:etc|var|usr|bin|sbin|system|library)(?:\/|$)/u.test(lower)) {
    return true;
  }
  return targetsShellProtectedWritePath(target, workdir);
}

function shellRedirectionRisk(segment, workdir) {
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
    if (shellRedirectTargetRisk(target, token !== '<', workdir)) return true;
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

function gitCommandRisk(args, workdir) {
  if (args.some((arg) => arg === '-c' || /^-c.+/u.test(arg)
    || arg === '--config-env' || arg.startsWith('--config-env='))) return true;
  const rootOptionsWithValues = new Set(['-C', '--git-dir', '--namespace', '--work-tree']);
  const rootPathOptions = new Set(['-C', '--git-dir', '--work-tree']);
  const rootFlags = new Set([
    '--bare', '--glob-pathspecs', '--icase-pathspecs', '--literal-pathspecs',
    '--no-literal-pathspecs', '--no-optional-locks', '--no-pager', '--no-replace-objects',
    '--noglob-pathspecs', '--paginate', '-p',
  ]);
  let index = 0;
  while (index < args.length && args[index].startsWith('-')) {
    const arg = args[index];
    if (arg === '--') {
      index += 1;
      break;
    }
    const inlineRootOption = /^(--git-dir|--namespace|--work-tree)=(.*)$/u.exec(arg);
    if (inlineRootOption) {
      if (inlineRootOption[2] === ''
        || rootPathOptions.has(inlineRootOption[1])
          && targetsShellProtectedReadPath(inlineRootOption[2], workdir)) return true;
      index += 1;
      continue;
    }
    if (rootOptionsWithValues.has(arg)) {
      const value = args[index + 1];
      if (typeof value !== 'string' || value === '' || value.startsWith('-')
        || rootPathOptions.has(arg) && targetsShellProtectedReadPath(value, workdir)) return true;
      index += 2;
      continue;
    }
    if (!rootFlags.has(arg) && !['--help', '--version'].includes(arg)) return true;
    index += 1;
  }
  const operation = args[index];
  const operationArgs = args.slice(index + 1);
  if (operation === undefined || ['help', 'version'].includes(operation)) return false;
  if (operationArgs.some((arg) => arg === '--ext-diff'
    || arg === '--filters'
    || arg === '--open-files-in-pager'
    || arg === '--textconv'
    || arg.startsWith('--open-files-in-pager='))) return true;
  for (let outputIndex = 0; outputIndex < operationArgs.length; outputIndex += 1) {
    const arg = operationArgs[outputIndex];
    if (arg === '--output') {
      if (targetsShellProtectedWritePath(operationArgs[outputIndex + 1], workdir)) return true;
      outputIndex += 1;
    } else if (arg.startsWith('--output=')
      && targetsShellProtectedWritePath(arg.slice('--output='.length), workdir)) return true;
  }
  const separatorIndex = operationArgs.indexOf('--');
  const explicitPaths = separatorIndex >= 0 ? operationArgs.slice(separatorIndex + 1) : [];
  const objectPaths = operationArgs
    .filter((arg) => !arg.startsWith('-') && arg.includes(':'))
    .map((arg) => arg.slice(arg.indexOf(':') + 1));
  if ([...explicitPaths, ...objectPaths]
    .some((path) => targetsShellProtectedReadPath(path, workdir))) return true;
  const protectedGitOptionValue = (options) => {
    for (let optionIndex = 0; optionIndex < operationArgs.length; optionIndex += 1) {
      const arg = operationArgs[optionIndex];
      if (options.has(arg)) {
        const value = operationArgs[optionIndex + 1];
        if (value !== '-' && targetsShellProtectedReadPath(value, workdir)) return true;
        optionIndex += 1;
        continue;
      }
      for (const option of options) {
        const attached = option.startsWith('--')
          ? arg.startsWith(`${option}=`) ? arg.slice(option.length + 1) : null
          : arg.startsWith(option) && arg.length > option.length
            ? arg.slice(option.length).replace(/^=/u, '')
            : null;
        if (attached !== null && attached !== '-'
          && targetsShellProtectedReadPath(attached, workdir)) return true;
      }
    }
    return false;
  };
  if (operation === 'blame'
    && protectedGitOptionValue(new Set(['-S', '--contents', '--ignore-revs-file']))) return true;
  if (operation === 'grep'
    && protectedGitOptionValue(new Set(['-f', '--file']))) return true;
  const knownBuiltin = [
    'add', 'am', 'apply', 'archive', 'bisect', 'blame', 'branch', 'bundle', 'cat-file',
    'check-attr', 'check-ignore', 'check-mailmap', 'checkout', 'cherry-pick', 'clean',
    'clone', 'commit', 'config', 'count-objects', 'describe', 'diff', 'fetch', 'for-each-ref',
    'format-patch', 'grep', 'hash-object', 'init', 'log', 'ls-files', 'ls-tree', 'merge',
    'merge-base', 'mv', 'name-rev', 'notes', 'pull', 'push', 'rebase', 'remote', 'reset',
    'restore', 'revert', 'rev-list', 'rev-parse', 'rm', 'shortlog', 'show', 'show-branch',
    'show-ref', 'stash', 'status', 'submodule', 'switch', 'tag', 'var', 'whatchanged',
    'worktree',
  ];
  if (hasHelpOrVersion(args) && knownBuiltin.includes(operation)) return false;
  if (operation === 'diff') {
    if (explicitPaths.length > 0) return false;
    return !operationArgs.some((arg) => (
      ['--compact-summary', '--name-only', '--name-status', '--numstat', '--raw',
        '--shortstat', '--stat', '--summary'].includes(arg)
      || arg.startsWith('--dirstat')
      || arg.startsWith('--stat=')
    ));
  }
  if (operation === 'log') {
    const patchRequested = operationArgs.some((arg) => (
      ['-p', '--full-diff', '--patch'].includes(arg)
      || arg.startsWith('--color-words')
      || arg.startsWith('--word-diff')
    ));
    return patchRequested && explicitPaths.length === 0;
  }
  if (operation === 'show') {
    if (explicitPaths.length > 0 || objectPaths.length > 0) return false;
    return !operationArgs.some((arg) => (
      ['-s', '--compact-summary', '--name-only', '--name-status', '--no-patch', '--numstat',
        '--raw', '--shortstat', '--stat', '--summary'].includes(arg)
      || arg.startsWith('--dirstat')
      || arg.startsWith('--stat=')
    ));
  }
  if (operation === 'cat-file') {
    if (operationArgs.some((arg) => (
      ['-p', '--batch', '--batch-command'].includes(arg)
      || arg.startsWith('--batch=')
      || arg.startsWith('--batch-command=')
    ))) return true;
    if (objectPaths.length > 0) return false;
    return !operationArgs.some((arg) => (
      ['-e', '-s', '-t', '--batch-check'].includes(arg)
      || arg.startsWith('--batch-check=')
    ));
  }
  if (operation === 'grep') return explicitPaths.length === 0;
  if (operation === 'blame') {
    const inferredPath = separatorIndex >= 0
      ? explicitPaths.at(-1)
      : operationArgs.filter((arg) => !arg.startsWith('-')).at(-1);
    return typeof inferredPath !== 'string'
      || targetsShellProtectedReadPath(inferredPath, workdir);
  }
  if (operation === 'apply') {
    if (operationArgs.some((arg) => !arg.startsWith('-')
      && targetsShellProtectedReadPath(arg, workdir))) return true;
    if (operationArgs.some((arg) => (
      arg === '--apply'
      || arg === '--3way'
      || arg === '-3'
      || arg === '--build-fake-ancestor'
      || arg.startsWith('--build-fake-ancestor=')
    ))) return true;
    return !operationArgs.some((arg) => [
      '--check', '--numstat', '--stat', '--summary',
    ].includes(arg));
  }
  if (operation === 'branch') {
    if (operationArgs.some((arg) => arg === '--force'
      || /^-[^-]*[dDmMf]/u.test(arg)
      || ['--copy', '--delete', '--edit-description', '--move', '--set-upstream-to', '--unset-upstream'].includes(arg))) {
      return true;
    }
    const positionals = operationArgs.filter((arg) => !arg.startsWith('-'));
    if (positionals.length === 0) return false;
    return !operationArgs.some((arg) => [
      '--all', '--contains', '--format', '--list', '--merged', '--no-contains', '--no-merged',
      '--points-at', '--remotes', '--show-current', '--sort', '-a', '-l', '-r',
    ].includes(arg));
  }
  if (operation === 'tag') {
    if (operationArgs.some((arg) => arg === '--delete' || /^-[^-]*[dFsu]/u.test(arg)
      || ['--annotate', '--force', '--sign'].includes(arg))) return true;
    const positionals = operationArgs.filter((arg) => !arg.startsWith('-'));
    return positionals.length > 0
      && !operationArgs.some((arg) => ['--contains', '--list', '--merged', '--no-contains', '--no-merged', '--points-at', '-l'].includes(arg));
  }
  if (operation === 'remote') {
    if (operationArgs.includes('-v') || operationArgs.includes('--verbose')) return true;
    const subcommand = operationArgs.find((arg) => !arg.startsWith('-'));
    return subcommand !== undefined;
  }
  if (operation === 'stash') {
    const subcommand = operationArgs.find((arg) => !arg.startsWith('-'));
    return !['list', 'show'].includes(subcommand);
  }
  if (operation === 'notes') {
    const subcommand = operationArgs.find((arg) => !arg.startsWith('-'));
    return !['get-ref', 'list', 'show'].includes(subcommand);
  }
  if (operation === 'worktree') {
    const subcommand = operationArgs.find((arg) => !arg.startsWith('-'));
    return subcommand !== 'list';
  }
  if (operation === 'submodule') {
    const subcommand = operationArgs.find((arg) => !arg.startsWith('-'));
    return !['status', 'summary'].includes(subcommand);
  }
  if (operation === 'hash-object') {
    if (operationArgs.includes('-w') || operationArgs.includes('--write')) return true;
    const inputPaths = [];
    for (let pathIndex = 0; pathIndex < operationArgs.length; pathIndex += 1) {
      const arg = operationArgs[pathIndex];
      if (['-t', '--path'].includes(arg)) {
        pathIndex += 1;
        continue;
      }
      if (arg.startsWith('--path=') || arg.startsWith('-')) continue;
      inputPaths.push(arg);
    }
    return inputPaths.some((path) => targetsShellProtectedReadPath(path, workdir));
  }
  if (operation === 'config') {
    if (protectedGitOptionValue(new Set(['-f', '--file']))) return true;
    const configArgs = [];
    for (let configIndex = 0; configIndex < operationArgs.length; configIndex += 1) {
      const arg = operationArgs[configIndex];
      if (arg === '-f' || arg === '--file') {
        const value = operationArgs[configIndex + 1];
        if (typeof value !== 'string' || value === '') return true;
        configIndex += 1;
        continue;
      }
      if (arg.startsWith('--file=') || /^-f.?/u.test(arg) && arg.length > 2) {
        const value = arg.startsWith('--file=')
          ? arg.slice('--file='.length)
          : arg.slice(2).replace(/^=/u, '');
        if (value === '') return true;
        continue;
      }
      configArgs.push(arg);
    }
    if (configArgs.some((arg) => [
      '-e', '--add', '--edit', '--remove-section', '--rename-section', '--replace-all', '--unset',
      '--unset-all',
    ].includes(arg))) return true;
    if (configArgs.some((arg) => [
      '--get-regexp', '--get-urlmatch', '--list', '--show-origin', '-l',
    ].includes(arg))) return true;
    if (configArgs.some((arg) => ['--get', '--get-all'].includes(arg))) {
      const key = configArgs.find((arg) => !arg.startsWith('-'));
      return typeof key !== 'string' || isSecretBearingKey(key)
        || /(?:authorization|credential|cookie|extraheader|password|proxy|secret|token)/iu.test(key);
    }
    const positionals = configArgs.filter((arg) => !arg.startsWith('-'));
    if (positionals.length === 1) {
      return isSecretBearingKey(positionals[0])
        || /(?:authorization|credential|cookie|extraheader|password|proxy|secret|token)/iu
          .test(positionals[0]);
    }
    return positionals.length >= 2;
  }
  return ![
    'blame', 'cat-file', 'check-attr', 'check-ignore', 'check-mailmap', 'count-objects',
    'describe', 'diff', 'for-each-ref', 'grep', 'log', 'ls-files', 'ls-tree', 'merge-base',
    'name-rev', 'rev-list', 'rev-parse', 'shortlog', 'show', 'show-branch', 'show-ref', 'status',
    'var', 'whatchanged',
  ].includes(operation);
}

function openClawCommandRisk(args) {
  if (args.length === 1 && hasHelpOrVersion(args)) return false;
  const optionsWithValues = new Set(['--container', '--log-level', '--profile']);
  const flags = new Set(['--dev', '--help', '--no-color', '--version', '-V', '-h']);
  let index = 0;
  while (index < args.length && args[index].startsWith('-')) {
    const arg = args[index];
    if (arg === '--') {
      index += 1;
      break;
    }
    const inlineOption = /^(--container|--log-level|--profile)=(.*)$/u.exec(arg);
    if (inlineOption) {
      if (inlineOption[2] === '') return true;
      index += 1;
      continue;
    }
    if (optionsWithValues.has(arg)) {
      const value = args[index + 1];
      if (typeof value !== 'string' || value === '' || value.startsWith('-')) return true;
      index += 2;
      continue;
    }
    if (!flags.has(arg)) return true;
    index += 1;
  }
  const operation = args[index];
  const operationArgs = args.slice(index + 1);
  if (operation === undefined || ['status', 'version'].includes(operation)) return false;
  if (operation === 'plugins') {
    return !['inspect', 'list'].includes(operationArgs[0]);
  }
  if (operation === 'config') {
    if (operationArgs[0] !== 'get'
      || typeof operationArgs[1] !== 'string'
      || operationArgs[1].startsWith('-')) return true;
    return gatewayPathIsSensitive(operationArgs[1]);
  }
  if (operation === 'gateway') return !['health', 'status'].includes(operationArgs[0]);
  return true;
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

function environmentDumpCommandRisk(name, args) {
  if (name === 'set') return args.length === 0;
  if (name === 'export') {
    return args.length === 0 || shortFlagIncludes(args, 'p') || args.includes('--print');
  }
  if (name === 'declare' || name === 'typeset') {
    if (args.length === 0 || shortFlagIncludes(args, 'p')) return true;
    const hasAssignment = args.some((arg) => isShellAssignment(arg));
    return !hasAssignment
      && shortFlagIncludes(args, 'x')
      && args.every((arg) => arg.startsWith('-'));
  }
  return false;
}

function environmentIntrospectionCommandRisk(name, args) {
  if (name === 'ps') {
    if (hasHelpOrVersion(args)) return false;
    return args.some((arg) => /^-[^-]*E/u.test(arg)
      || /^-[^-]+$/u.test(arg)
        && arg.includes('e') && [...arg].filter((character) => character === 'w').length >= 2
      || !arg.startsWith('-')
        && /^[a-z]+$/iu.test(arg) && arg.toLowerCase().includes('e'));
  }
  const operation = args.find((arg) => !arg.startsWith('-'));
  if (name === 'systemctl') {
    return ['import-environment', 'set-environment', 'show-environment', 'unset-environment']
      .includes(operation);
  }
  if (name === 'launchctl') {
    return ['getenv', 'setenv', 'unsetenv'].includes(operation);
  }
  return false;
}

function executionDispatcherRisk(name, args) {
  if (EXECUTION_DISPATCHERS.has(name)) {
    return !(args.length === 1 && (hasHelpOrVersion(args) || args[0] === '-V'));
  }
  if (!CONTAINER_DISPATCHERS.has(name)) return false;
  if (args.length === 1 && hasHelpOrVersion(args)) return false;
  const operation = args.find((arg) => !arg.startsWith('-'));
  return !['images', 'info', 'ps', 'version'].includes(operation);
}

function remoteOutputBasename(url, fallback = 'index.html') {
  try {
    const parsed = new URL(url);
    const rawName = parsed.pathname.slice(parsed.pathname.lastIndexOf('/') + 1);
    if (rawName === '') return fallback;
    try {
      return decodeURIComponent(rawName);
    } catch {
      return rawName;
    }
  } catch {
    return null;
  }
}

function networkTransferCommandRisk(name, args, hasDynamicArgs, workdir) {
  if (name !== 'curl' && name !== 'wget') return false;
  if (args.length === 1 && hasHelpOrVersion(args)) return false;
  if (hasDynamicArgs) return true;
  if (name === 'curl' && !(args[0] === '--disable' || /^-q/u.test(args[0] ?? ''))) {
    return true;
  }
  if (name === 'wget' && args[0] !== '--no-config') return true;

  const urls = args.filter((arg) => /^https?:\/\//iu.test(arg));
  if (urls.length === 0 || urls.some((url) => internalWebFetchUrl(url) !== false)) return true;

  if (name === 'curl' && args.some((arg) => (
    /^-[^-]*[Lnx]/u.test(arg)
    || /^(?:--(?:abstract-unix-socket|connect-to|doh-url|expand-(?:data|form|header|url)|interface|location|location-trusted|netrc|netrc-optional|preproxy|proxy|resolve|socks4|socks4a|socks5|socks5-hostname|unix-socket|url-query|variable))(?:=|$)/u.test(arg)
  ))) return true;
  if (name === 'wget') {
    if (args.some((arg) => arg === '-e' || /^-e.+/u.test(arg)
      || arg === '--execute' || arg.startsWith('--execute='))) return true;
    const boundedRedirects = args.some((arg, index) => arg === '--max-redirect=0'
      || arg === '--max-redirect' && args[index + 1] === '0');
    if (!boundedRedirects) return true;
  }

  const mutatingFlags = name === 'curl'
    ? /^(?:-[A-Za-z]*[TdbFHuXKcD].*|--(?:aws-sigv4|cert|config|cookie|cookie-jar|data(?:-ascii|-binary|-raw|-urlencode)?|dump-header|form|string|form-string|header|json|key|netrc-file|oauth2-bearer|output-dir|proxy-cert|proxy-header|proxy-key|proxy-user|request|upload-file|user)(?:=|$))/u
    : /^(?:-[iP].*|--(?:body-data|body-file|certificate|config|directory-prefix|header|input-file|load-cookies|method|password|post-data|post-file|private-key|proxy-password|proxy-user|upload-file|user)(?:=|$))/u;
  if (args.some((arg) => mutatingFlags.test(arg))) return true;

  if (name === 'curl') {
    const remoteName = args.some((arg) => arg === '--remote-name'
      || arg === '--remote-name-all' || /^-[^-]*O/u.test(arg));
    const headerName = args.some((arg) => arg === '--remote-header-name'
      || /^-[^-]*J/u.test(arg));
    if (headerName) return true;
    if (remoteName && urls.some((url) => {
      const output = remoteOutputBasename(url);
      return output === null || targetsShellProtectedWritePath(output, workdir);
    })) return true;
  } else {
    const explicitDocument = args.some((arg) => arg === '-O'
      || arg === '--output-document' || /^-[^-]*O.*$/u.test(arg)
      || arg.startsWith('--output-document='));
    const noDownload = args.some((arg) => arg === '--spider');
    if (!explicitDocument && !noDownload && urls.some((url) => {
      const output = remoteOutputBasename(url);
      return output === null || targetsShellProtectedWritePath(output, workdir);
    })) return true;
  }

  if (name === 'curl' && args.some((arg) => (
    arg === '--trace' || arg === '--trace-ascii' || arg === '--stderr'
    || arg.startsWith('--trace=') || arg.startsWith('--trace-ascii=')
    || arg.startsWith('--stderr=')
  ))) return true;

  const pathOutputFlags = name === 'curl'
    ? new Set(['--etag-save'])
    : new Set(['-a', '-o', '--append-output', '--output-file']);
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const shortOutput = name === 'curl'
      ? /^-[^-]*?o(.*)$/u.exec(arg)
      : /^-[^-]*?[ao](.*)$/u.exec(arg);
    if (shortOutput) {
      const output = shortOutput[1] || args[index + 1];
      if (targetsShellProtectedWritePath(output, workdir)) return true;
      if (shortOutput[1] === '') index += 1;
      continue;
    }
    if (pathOutputFlags.has(arg)) {
      if (targetsShellProtectedWritePath(args[index + 1], workdir)) return true;
      index += 1;
      continue;
    }
    const inlinePath = name === 'curl'
      ? /^--etag-save=(.+)$/u.exec(arg)?.[1]
      : /^(?:-a|-o)(.+)$/u.exec(arg)?.[1]
        ?? /^--(?:append-output|output-file)=(.+)$/u.exec(arg)?.[1];
    if (inlinePath && targetsShellProtectedWritePath(inlinePath, workdir)) return true;
  }

  if (name === 'curl') {
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index];
      let format;
      if (arg === '-w' || arg === '--write-out') {
        format = args[index + 1];
        index += 1;
      } else {
        format = /^(?:-w|--write-out=)(.+)$/u.exec(arg)?.[1];
      }
      if (typeof format !== 'string') continue;
      const outputs = [...format.matchAll(/%output\{([^}]+)\}/gu)];
      if (outputs.some((match) => targetsShellProtectedWritePath(match[1], workdir))) return true;
    }
  }

  const outputFlags = name === 'curl' ? new Set(['-o', '--output']) : new Set(['-O', '--output-document']);
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (outputFlags.has(arg)) {
      if (targetsShellProtectedWritePath(args[index + 1], workdir)) return true;
      index += 1;
      continue;
    }
    const inlineOutput = name === 'curl'
      ? /^(?:-[^-]*?o(.+)|--output=(.+))$/u.exec(arg)
      : /^(?:-[^-]*?O(.+)|--output-document=(.+))$/u.exec(arg);
    const outputPath = inlineOutput?.[1] ?? inlineOutput?.[2];
    if (outputPath && targetsShellProtectedWritePath(outputPath, workdir)) return true;
  }
  return false;
}

function embeddedReaderProgramRisk(name, args) {
  if (name === 'rg') {
    return args.some((arg) => ['--hostname-bin', '--pre'].includes(arg)
      || arg.startsWith('--hostname-bin=') || arg.startsWith('--pre='));
  }
  if (['awk', 'gawk', 'mawk', 'nawk'].includes(name)) {
    if (args.some((arg) => arg === '-f' || arg === '--file'
      || arg.startsWith('--file=') || /^-f.+/u.test(arg))) return true;
    if (name === 'gawk' && args.some((arg) => arg === '-E' || arg === '--exec'
      || arg.startsWith('--exec=') || /^-E.+/u.test(arg))) return true;
    if (name === 'mawk' && args.some((arg, index) => (
      arg === '-W' && /^exec(?:=|$)/u.test(args[index + 1] ?? '')
      || /^-Wexec(?:=|$)/u.test(arg)
    ))) return true;
    return args.some((arg) => typeof arg === 'string' && (
      /\bsystem\s*\(/iu.test(arg)
      || /\bgetline\b[^;\n]*</iu.test(arg)
      || /\|\s*getline\b/iu.test(arg)
      || /\b(?:print|printf)\b[^;\n]*(?:>>?|\|)/iu.test(arg)
    ));
  }
  if (name !== 'sed') return false;
  if (args.some((arg) => arg === '-f' || arg === '--file'
    || arg.startsWith('--file='))) return true;
  const scripts = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '-e' || arg === '--expression') {
      scripts.push(args[index + 1]);
      index += 1;
      continue;
    }
    if (arg.startsWith('--expression=')) {
      scripts.push(arg.slice('--expression='.length));
      continue;
    }
    if (!/^-[^-]/u.test(arg)) continue;
    const cluster = arg.slice(1);
    for (let optionIndex = 0; optionIndex < cluster.length; optionIndex += 1) {
      const option = cluster[optionIndex];
      if (option === 'f') return true;
      if (option === 'e') {
        const attached = cluster.slice(optionIndex + 1);
        scripts.push(attached || args[index + 1]);
        if (!attached) index += 1;
        break;
      }
      if (option === 'i' || option === 'l') break;
      if (!['E', 'H', 'a', 'n', 'r', 's', 'u', 'z'].includes(option)) break;
    }
  }
  return [...args, ...scripts].some((arg) => typeof arg === 'string' && (
    /(?:^|[;{}\n])\s*(?:[0-9$]+(?:,[0-9$]+)?\s*)?(?:e|r|R|w|W)(?:\s|$)/u.test(arg)
    || /s(.).*\1.*\1[a-zA-Z]*[ewW][a-zA-Z]*(?:\s|$)/u.test(arg)
  ));
}

function untrustedExecutablePath(value) {
  if (typeof value !== 'string') return true;
  const normalized = value.replaceAll('\\', '/');
  if (!normalized.includes('/')) return false;
  if (pathHasRawTraversal(normalized)) return true;
  return !/^(?:\/(?:bin|sbin|usr\/bin|usr\/sbin|opt\/homebrew\/bin)\/[^/]+|[a-zA-Z]:\/Windows\/System32\/[^/]+)$/iu
    .test(normalized);
}

function interpreterVersionOnly(name, args) {
  if (name === 'php' && args.includes('--version')
    && args.every((arg) => arg === '-n' || arg === '--version')) return true;
  if (args.length !== 1) return false;
  if (hasHelpOrVersion(args)) return true;
  if (['node', 'nodejs', 'perl', 'php', 'ruby'].includes(name)) return args[0] === '-v';
  if (name === 'python' || name === 'python3') return args[0] === '-V';
  return name === 'lua' && args[0] === '-v';
}

function tarArchiveTarget(args) {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '-f' || arg === '--file') return args[index + 1] ?? null;
    if (arg.startsWith('--file=')) return arg.slice('--file='.length);
    const short = /^-[^-]*f(.*)$/u.exec(arg);
    if (short) return short[1] || args[index + 1] || null;
  }
  return null;
}

function archiveOrCompressorCommandRisk(name, args, workdir) {
  if (name === 'tar' || name === 'bsdtar') {
    if (args.some((arg) => arg === '--checkpoint-action'
      || arg.startsWith('--checkpoint-action=')
      || arg === '--remove-files'
      || arg === '--to-command'
      || arg.startsWith('--to-command=')
      || arg === '--use-compress-program'
      || arg.startsWith('--use-compress-program=')
      || arg === '-I' || /^-I.+/u.test(arg))) return true;
    if (args.some((arg) => ['--extract', '--get'].includes(arg)
      || /^-[^-]*x/u.test(arg))) return true;
    const createsArchive = args.some((arg) => [
      '--append', '--concatenate', '--create', '--update',
    ].includes(arg) || /^-[^-]*[cAru]/u.test(arg));
    const archive = tarArchiveTarget(args);
    return createsArchive && (archive === null
      || targetsShellProtectedWritePath(archive, workdir));
  }
  if (name === 'zip') {
    if (hasHelpOrVersion(args)) return false;
    if (args.some((arg) => arg === '-TT' || arg === '--unzip-command'
      || arg.startsWith('--unzip-command='))) return true;
    const archive = args.find((arg) => !arg.startsWith('-'));
    return typeof archive !== 'string'
      || targetsShellProtectedWritePath(archive, workdir);
  }
  if (name === 'jar') {
    if (hasHelpOrVersion(args)) return false;
    const operationIndex = args.findIndex((arg) => !arg.startsWith('--'));
    const operation = args[operationIndex] ?? '';
    if (operation.includes('x') || args.includes('--extract')) return true;
    const mutates = /[cu]/u.test(operation)
      || args.some((arg) => arg === '--create' || arg === '--update');
    if (!mutates) return false;
    let archive = null;
    const fileIndex = args.findIndex((arg) => arg === '--file' || arg === '-f');
    if (fileIndex >= 0) archive = args[fileIndex + 1] ?? null;
    const inlineFile = args.find((arg) => arg.startsWith('--file='));
    if (inlineFile) archive = inlineFile.slice('--file='.length);
    if (archive === null && operation.includes('f')) archive = args[operationIndex + 1] ?? null;
    return archive !== null && targetsShellProtectedWritePath(archive, workdir);
  }
  if (name === 'ar') {
    if (hasHelpOrVersion(args)) return false;
    if (args.some((arg) => arg === '--plugin' || arg.startsWith('--plugin='))) return true;
    const operationIndex = args.findIndex((arg) => /^-?[a-zA-Z]+$/u.test(arg));
    const operation = (args[operationIndex] ?? '').replace(/^-+/u, '');
    if (args.includes('-M') || operation.includes('x')) return true;
    if (!/[dmpqrs]/u.test(operation)) return false;
    const archive = args[operationIndex + 1];
    return typeof archive !== 'string'
      || targetsShellProtectedWritePath(archive, workdir);
  }
  if (name === '7z') {
    if (hasHelpOrVersion(args)) return false;
    const operation = args.find((arg) => !arg.startsWith('-'))?.toLowerCase();
    return ['a', 'd', 'e', 'u', 'x'].includes(operation);
  }
  if (name === 'unzip') {
    if (hasHelpOrVersion(args)) return false;
    return !args.some((arg) => ['-l', '-t', '-Z'].includes(arg));
  }
  if (['bunzip2', 'bzip2', 'gunzip', 'gzip', 'unxz', 'unzstd', 'xz', 'zstd'].includes(name)) {
    if (hasHelpOrVersion(args)) return false;
    return !args.some((arg) => arg === '--stdout' || /^-[^-]*c/u.test(arg));
  }
  return false;
}

function processControlCommandRisk(name, args) {
  if (['halt', 'kill', 'killall', 'pkill', 'poweroff', 'reboot', 'shutdown'].includes(name)) {
    return !hasHelpOrVersion(args);
  }
  const operation = args.find((arg) => !arg.startsWith('-'));
  if (name === 'service') return operation !== undefined && args.at(-1) !== 'status';
  if (name === 'systemctl') {
    if (operation === 'cat' || operation === 'show') return true;
    if (operation === 'show' && args.some((arg, index) => (
      /^(?:Environment|EnvironmentFiles)$/iu.test(arg)
      && ['-p', '--property'].includes(args[index - 1])
      || /^--property=(?:Environment|EnvironmentFiles)$/iu.test(arg)
    ))) return true;
    return operation !== undefined && ![
      'cat', 'get-default', 'is-active', 'is-enabled', 'is-failed', 'list-dependencies',
      'list-jobs', 'list-sockets', 'list-timers', 'list-unit-files', 'list-units', 'show',
      'status',
    ].includes(operation);
  }
  if (name === 'launchctl') return operation !== undefined && operation !== 'list';
  return false;
}

function packageCredentialInspectionRisk(inputName, args) {
  const name = inputName === 'yarnpkg' ? 'yarn' : inputName;
  if (name === 'python' || name === 'python3') {
    const invocation = pythonModuleInvocation(args);
    return invocation.found && ['pip', 'pip3'].includes(invocation.module)
      ? packageCredentialInspectionRisk(invocation.module, invocation.args)
      : false;
  }
  const normalized = args.map((arg) => arg.toLowerCase());
  if (name === 'poetry' && normalized.includes('config')
    && normalized.includes('--list')) return true;
  if (name === 'composer' && normalized.includes('config')
    && normalized.some((arg) => ['-l', '--list'].includes(arg))) return true;
  if (['bundle', 'bundler'].includes(name) && normalized.includes('config')
    && normalized.includes('list')) return true;
  if (['conda', 'mamba', 'micromamba'].includes(name) && normalized.includes('config')
    && normalized.some((arg) => ['--get', '--show', '--show-sources'].includes(arg))) return true;
  if (name === 'gem' && normalized.includes('sources')
    && normalized.some((arg) => ['-l', '--list'].includes(arg))) return true;
  if (!['bun', 'npm', 'pip', 'pip3', 'pnpm', 'yarn'].includes(name)) return false;
  const scoped = packageArgsWithoutOptionValues(name, args).filter((arg) => arg !== '--');
  const configIndex = scoped.findIndex((arg) => arg === 'config' || arg === 'c');
  if (configIndex < 0) return false;
  const operation = scoped[configIndex + 1];
  if (['list', 'ls'].includes(operation)) return true;
  if (operation !== 'get') return false;
  if (name === 'pip' || name === 'pip3') return true;
  const key = scoped[configIndex + 2];
  return typeof key !== 'string' || isSecretBearingKey(key)
    || /(?:_auth|authorization|credential|password|secret|token)/iu.test(key);
}

function packageSensitiveFileOptionRisk(inputName, args, workdir) {
  const name = inputName === 'yarnpkg' ? 'yarn' : inputName;
  if (name === 'python' || name === 'python3') {
    const invocation = pythonModuleInvocation(args);
    return invocation.found && ['pip', 'pip3'].includes(invocation.module)
      ? packageSensitiveFileOptionRisk(invocation.module, invocation.args, workdir)
      : false;
  }
  const alwaysReview = new Map([
    ['npm', ['--userconfig']],
    ['pip', ['--client-cert', '--python']],
    ['pip3', ['--client-cert', '--python']],
    ['bundle', ['--gemfile']],
    ['bundler', ['--gemfile']],
    ['cargo', ['--config']],
    ['uv', ['--config-file']],
    ['conda', ['--rc-file']],
    ['mamba', ['--rc-file']],
    ['micromamba', ['--rc-file']],
    ['gradle', ['-I', '-b', '-c', '-g', '-p', '--build-file', '--gradle-user-home', '--include-build', '--init-script', '--project-dir', '--settings-file']],
    ['gradlew', ['-I', '-b', '-c', '-g', '-p', '--build-file', '--gradle-user-home', '--include-build', '--init-script', '--project-dir', '--settings-file']],
    ['mvn', ['-f', '-gs', '-s', '-t', '--file', '--global-settings', '--settings', '--toolchains']],
    ['mvnw', ['-f', '-gs', '-s', '-t', '--file', '--global-settings', '--settings', '--toolchains']],
  ]);
  const sensitiveOptions = alwaysReview.get(name) ?? [];
  for (const arg of args) {
    if (sensitiveOptions.some((option) => (
      arg === option
      || option.startsWith('--') && arg.startsWith(`${option}=`)
      || !option.startsWith('--') && arg.startsWith(option) && arg.length > option.length
    ))) return true;
  }
  if (['mvn', 'mvnw'].includes(name) && args.some((arg, index) => (
    /^-Dmaven\.ext\.class\.path(?:=|$)/u.test(arg)
    || arg === '-D' && /^maven\.ext\.class\.path(?:=|$)/u.test(args[index + 1] ?? '')
  ))) return true;
  if (name === 'cargo') {
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index];
      if (arg === '--manifest-path') {
        if (targetsShellProtectedReadPath(args[index + 1], workdir)) return true;
        index += 1;
      } else if (arg.startsWith('--manifest-path=')
        && targetsShellProtectedReadPath(arg.slice('--manifest-path='.length), workdir)) {
        return true;
      }
    }
  }
  return false;
}

function readerFileOptionRisk(name, args, workdir) {
  const protectedOptions = new Set(['-f', '--file']);
  const perCommand = new Map([
    ['bsdtar', ['-X', '--exclude-from']],
    ['egrep', ['--exclude-from']],
    ['fgrep', ['--exclude-from']],
    ['grep', ['--exclude-from']],
    ['rg', ['--ignore-file']],
    ['tar', ['-X', '--exclude-from']],
  ]);
  for (const option of perCommand.get(name) ?? []) protectedOptions.add(option);

  const indirectOptions = new Set(
    name === 'tar' || name === 'bsdtar'
      ? ['-T', '--files-from']
      : name === 'head' || name === 'sort'
        ? ['--files0-from']
        : [],
  );
  const options = [...new Set([...protectedOptions, ...indirectOptions])]
    .sort((left, right) => right.length - left.length);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    for (const option of options) {
      let value;
      if (arg === option) {
        value = args[index + 1];
      } else if (option.startsWith('--') && arg.startsWith(`${option}=`)) {
        value = arg.slice(option.length + 1);
      } else if (!option.startsWith('--') && arg.startsWith(option)
        && arg.length > option.length) {
        value = arg.slice(option.length).replace(/^=/u, '');
      } else {
        continue;
      }
      if (indirectOptions.has(option)) return true;
      if (targetsShellProtectedReadPath(value, workdir)) return true;
    }
  }
  return false;
}

function credentialReaderWriteRisk(name, args, workdir) {
  if (name === 'less' && args.some((arg) => (
    arg.startsWith('+')
    || arg === '-k'
    || /^-k.+/u.test(arg)
    || arg === '--lesskey-file'
    || arg.startsWith('--lesskey-file=')
  ))) return true;
  if (name === 'sort' && args.some((arg) => (
    arg === '--compress-program' || arg.startsWith('--compress-program=')
  ))) return true;
  const outputOptions = new Map([
    ['age', ['-o', '--output']],
    ['base64', ['-o', '--output']],
    ['gpg', ['-o', '--attribute-file', '--logger-file', '--output', '--status-file']],
    ['gpg2', ['-o', '--attribute-file', '--logger-file', '--output', '--status-file']],
    ['less', ['-o', '-O', '--log-file', '--LOG-FILE']],
    ['openssl', ['-out', '--out', '-certout', '-keyout', '-writerand']],
    ['tar', ['-g', '--listed-incremental']],
  ]).get(name) ?? [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    for (const option of outputOptions) {
      let value;
      if (arg === option) {
        value = args[index + 1];
      } else if (option.startsWith('--') && arg.startsWith(`${option}=`)) {
        value = arg.slice(option.length + 1);
      } else if (!option.startsWith('--') && arg.startsWith(option)
        && arg.length > option.length) {
        value = arg.slice(option.length).replace(/^=/u, '');
      } else {
        continue;
      }
      if (targetsShellProtectedWritePath(value, workdir)) return true;
    }
  }
  if (name === 'xxd') {
    const positionals = args.filter((arg) => arg === '-' || !arg.startsWith('-'));
    if (positionals.length >= 2
      && targetsShellProtectedWritePath(positionals.at(-1), workdir)) return true;
  }
  if (name === 'uniq') {
    const positionals = args.filter((arg) => arg === '-' || !arg.startsWith('-'));
    if (positionals.length >= 2
      && targetsShellProtectedWritePath(positionals.at(-1), workdir)) return true;
  }
  return false;
}

function shellSegmentRisk(segment, depth, workdir) {
  if (shellRedirectionRisk(segment, workdir)) return true;
  const parsedSegment = shellSegmentWithoutRedirections(segment);
  const view = shellCommandView(parsedSegment.tokens);
  if (view === null) return false;
  const {
    name, args, ambiguous = false, commandIndex,
  } = view;
  if (ambiguous || parsedSegment.dynamicTokenIndexes.has(commandIndex)) return true;
  if (untrustedExecutablePath(parsedSegment.tokens[commandIndex])) return true;
  const hasDynamicArgs = [...parsedSegment.dynamicTokenIndexes]
    .some((index) => index > commandIndex);
  if (parsedSegment.tokens.some(dangerousShellAssignment)) return true;
  if ([...parsedSegment.dynamicTokenIndexes]
    .some((index) => secretEnvironmentReference(parsedSegment.tokens[index]))) return true;
  const hasInputRedirection = [...segment.operatorTokenIndexes]
    .some((index) => ['<', '<&', '<>'].includes(segment.tokens[index]));
  if (SHELL_CONTROL_WORDS.has(name)) return true;
  if (segment.separatorBefore?.startsWith('|')
    && (SHELL_INTERPRETERS.has(name) || INLINE_INTERPRETERS.has(name) || name === 'eval')) {
    return true;
  }
  if (name === 'eval') return true;
  if ((SHELL_INTERPRETERS.has(name) || INLINE_INTERPRETERS.has(name))
    && hasInputRedirection) return true;
  if (SHELL_INTERPRETERS.has(name)) {
    if (args.length === 1 && hasHelpOrVersion(args)) return false;
    if (hasDynamicArgs) return true;
    if (name === 'cmd') return true;
    if (name === 'powershell' || name === 'pwsh') {
      if (args.some((arg) => {
        const option = /^(?:--?|\/)([a-z]+)(?::|=|$)/iu.exec(arg)?.[1]?.toLowerCase();
        return typeof option === 'string' && (
          option === 'cwa'
          || option === 'commandwithargs'
          || 'command'.startsWith(option)
          || option === 'ec'
          || 'encodedcommand'.startsWith(option)
        );
      })) return true;
      return true;
    }
    if (name === 'fish' && args.some((arg) => (
      /^-[^-]*C/u.test(arg) || arg === '--init-command' || arg.startsWith('--init-command=')
    ))) return true;
    if (args.some((arg) => /^-[^-]*c[^-]*$/u.test(arg) || arg === '--command')) return true;
    return true;
  }
  if (name === 'python' || name === 'python3') {
    const invocation = pythonModuleInvocation(args);
    if (invocation.found && !['pip', 'pip3'].includes(invocation.module)) return true;
  }
  if (INLINE_INTERPRETERS.has(name)) {
    if (interpreterVersionOnly(name, args)) return false;
    if (hasDynamicArgs || inlineInterpreterCommand(name, args)) return true;
    const invocation = name === 'python' || name === 'python3'
      ? pythonModuleInvocation(args)
      : { found: false, module: undefined };
    if (!(invocation.found && ['pip', 'pip3'].includes(invocation.module))) return true;
  }
  if (['awk', 'gawk', 'mawk', 'nawk'].includes(name) && hasDynamicArgs) return true;
  if (embeddedReaderProgramRisk(name, args)) return true;
  if (DELETE_COMMANDS.has(name)) return hasHelpOrVersion(args) ? false : true;
  if (name === 'find' && args.some((arg) => [
    '-delete', '-exec', '-execdir', '-ok', '-okdir',
  ].includes(arg))) return true;
  if (name === 'find') {
    for (let index = 0; index < args.length; index += 1) {
      if (!['-fprint', '-fprintf'].includes(args[index])) continue;
      if (targetsShellProtectedWritePath(args[index + 1], workdir)) return true;
      index += args[index] === '-fprintf' ? 2 : 1;
    }
  }
  if (name === 'find' && hasDynamicArgs) return true;
  if (name === 'history') {
    return hasHelpOrVersion(args) ? false : true;
  }
  if (name === 'fc') return hasHelpOrVersion(args) ? false : true;
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
  const targetsProtectedReadArgument = (arg) => typeof arg === 'string'
    && !arg.startsWith('-')
    && targetsShellProtectedReadPath(arg, workdir);
  if (CREDENTIAL_READER_COMMANDS.has(name)) {
    if (hasDynamicArgs) return true;
    if (readerFileOptionRisk(name, args, workdir)
      || credentialReaderWriteRisk(name, args, workdir)) return true;
    if (['egrep', 'fgrep', 'grep'].includes(name) && args.some((arg) => (
      arg === '--recursive' || /^-[^-]*[rR]/u.test(arg)
    ))) return true;
    if (name === 'rg' && args.some((arg) => (
      ['--follow', '--hidden', '--no-ignore'].includes(arg)
      || arg.startsWith('--no-ignore-')
      || /^-[^-]*[Lu]/u.test(arg)
    ))) return true;
    const positionals = args.filter((arg) => !arg.startsWith('-'));
    const possiblePaths = CREDENTIAL_QUERY_READER_COMMANDS.has(name)
      ? name === 'rg' && args.includes('--files') ? positionals : positionals.slice(1)
      : args;
    if (name === 'rg' && !args.includes('--files')) {
      const globPatterns = [];
      const parsedPositionals = [];
      const optionsWithValues = new Set(['-e', '-f', '-g', '-t', '-T', '--file', '--glob',
        '--iglob', '--ignore-file', '--regexp', '--type', '--type-not']);
      for (let argIndex = 0; argIndex < args.length; argIndex += 1) {
        const arg = args[argIndex];
        if (optionsWithValues.has(arg)) {
          const value = args[argIndex + 1];
          if (['-g', '--glob', '--iglob'].includes(arg) && typeof value === 'string') {
            globPatterns.push(value);
          }
          argIndex += 1;
          continue;
        }
        const inlineGlob = /^(?:-g|--glob=|--iglob=)(.+)$/u.exec(arg)?.[1];
        if (inlineGlob) {
          globPatterns.push(inlineGlob);
          continue;
        }
        if (!arg.startsWith('-')) parsedPositionals.push(arg);
      }
      const roots = parsedPositionals.slice(1);
      const broadRoot = roots.length === 0 || roots.some((root) => {
        const basename = root.replaceAll('\\', '/').split('/').filter(Boolean).at(-1) ?? '';
        return root === '.' || root.endsWith('/') || !basename.includes('.');
      });
      const scopedCodeRoots = roots.length > 0 && roots.every((root) => (
        /^(?:\.\/)?(?:app|docs|lib|src|test|tests)(?:\/[a-zA-Z0-9][a-zA-Z0-9._-]*)*\/?$/u
          .test(root)
      ));
      const restrictiveGlobs = globPatterns.length > 0 && globPatterns.every((glob) => (
        glob.startsWith('!')
        || /^(?:\*\*\/)?\*\.(?:c|cc|cpp|css|go|h|hpp|html?|java|js|jsx|kt|md|mjs|php|py|rb|rs|rst|sh|swift|ts|tsx)$/iu.test(glob)
      )) && globPatterns.some((glob) => !glob.startsWith('!'));
      if (broadRoot && !restrictiveGlobs && !scopedCodeRoots) return true;
    }
    if (possiblePaths.some((arg) => targetsProtectedReadArgument(arg)
      || typeof arg === 'string' && /[$\u007b\u007d]/u.test(arg))) return true;
  }
  const sedInPlace = name === 'sed' && args.some((arg) => (
    arg === '-i' || arg === '-I' || arg === '--in-place'
      || /^-[EHanrsuz]*[iI]/u.test(arg)
      || arg.startsWith('--in-place=')
  ));
  if (sedInPlace && (hasDynamicArgs || args.some((arg) => (
    typeof arg === 'string' && !arg.startsWith('-')
      && targetsShellProtectedWritePath(arg, workdir)
  )))) return true;
  const yqInPlace = name === 'yq' && args.some((arg) => (
    arg === '-i' || arg === '--inplace' || arg === '--in-place'
  ));
  if (yqInPlace && (hasDynamicArgs || args.some((arg) => (
    typeof arg === 'string' && !arg.startsWith('-')
      && targetsShellProtectedWritePath(arg, workdir)
  )))) return true;
  if (name === 'patch') {
    return hasHelpOrVersion(args) || args.includes('--dry-run')
      || args.includes('--check') || args.includes('-C') ? false : true;
  }
  if (hasDynamicArgs && [
    'cp', 'dd', 'install', 'ln', 'mv', 'rsync', 'tee', 'truncate',
  ].includes(name)) return true;
  const explicitTargetDirectory = args.findIndex((arg) => arg === '-t'
    || arg === '--target-directory');
  const inlineTargetDirectory = args.find((arg) => arg.startsWith('--target-directory='));
  const positionalArgs = args.filter((arg) => !arg.startsWith('-'));
  const destination = explicitTargetDirectory >= 0
    ? args[explicitTargetDirectory + 1]
    : inlineTargetDirectory?.slice('--target-directory='.length) ?? positionalArgs.at(-1);
  if (['cp', 'install', 'rsync'].includes(name)
    && targetsShellProtectedWritePath(destination, workdir)) return true;
  if (['cp', 'install', 'rsync'].includes(name)
    && args.some(targetsProtectedReadArgument)) return true;
  if (['ln', 'mv', 'tee', 'truncate'].includes(name)
    && args.some((arg) => typeof arg === 'string'
      && !arg.startsWith('-') && targetsShellProtectedWritePath(arg, workdir))) return true;
  if (name === 'cp') {
    const positionals = args.filter((arg) => !arg.startsWith('-'));
    if (positionals.length >= 2 && targetsAuditOrHistoryPath(positionals.at(-1))) return true;
  }
  if (name === 'dd'
    && args.some((arg) => arg.startsWith('of=') && targetsAuditOrHistoryPath(arg.slice(3)))) {
    return true;
  }
  if (name === 'dd'
    && args.some((arg) => arg.startsWith('of=')
      && targetsShellProtectedWritePath(arg.slice(3), workdir))) {
    return true;
  }
  if (name === 'dd'
    && args.some((arg) => arg.startsWith('if=')
      && targetsShellProtectedReadPath(arg.slice(3), workdir))) return true;
  if (name === 'tee' && args.some((arg) => !arg.startsWith('-')
    && targetsAuditOrHistoryPath(arg))) return true;
  if (name === 'sort') {
    for (let index = 0; index < args.length; index += 1) {
      if (args[index] === '-o' || args[index] === '--output') {
        if (targetsShellProtectedWritePath(args[index + 1], workdir)) return true;
        index += 1;
      } else if (args[index].startsWith('--output=')
        && targetsShellProtectedWritePath(args[index].slice('--output='.length), workdir)) {
        return true;
      } else if (/^-o.+/u.test(args[index])
        && targetsShellProtectedWritePath(args[index].slice(2), workdir)) {
        return true;
      }
    }
  }
  const hasGitConfigOverride = name === 'git'
    && parsedSegment.tokens.slice(0, commandIndex)
      .some((token) => /^GIT_CONFIG_[A-Za-z0-9_]*=/u.test(token));
  if (name === 'git' && (hasDynamicArgs || hasGitConfigOverride || gitCommandRisk(args, workdir))) {
    return true;
  }
  if (name === 'openclaw' && (hasDynamicArgs || openClawCommandRisk(args))) return true;
  if (hasDynamicArgs && (
    name === 'alembic' || name.includes('migrat')
    || ['dbmate', 'flyway', 'liquibase', 'make', 'rake', 'rails', 'task'].includes(name)
  )) return true;
  if (hasDynamicArgs && PACKAGE_MANAGER_COMMANDS.has(name)) return true;
  if (packageSensitiveFileOptionRisk(name, args, workdir)) return true;
  if (hasDynamicArgs && (
    PERMISSION_COMMANDS.has(name) || name === 'truncate' || packageMutationCommand(name, args)
  )) return true;
  if (packageMutationCommand(name, args)) return true;
  if (packageCredentialInspectionRisk(name, args)) return true;
  if (environmentDumpCommandRisk(name, args)) return true;
  if (environmentIntrospectionCommandRisk(name, args)) return true;
  if (processControlCommandRisk(name, args)) return true;
  if (executionDispatcherRisk(name, args)) return true;
  if (archiveOrCompressorCommandRisk(name, args, workdir)) return true;
  if (networkTransferCommandRisk(name, args, hasDynamicArgs, workdir)) return true;
  if (name === 'printenv') return !hasHelpOrVersion(args);
  if (name === 'env') return !hasHelpOrVersion(args);
  if (PERMISSION_COMMANDS.has(name)) return hasHelpOrVersion(args) ? false : true;
  return migrationCommand(name, args);
}

function shellCommandRisk(source, depth = 0, workdir) {
  if (depth > 3) return null;
  const commands = shellTokenize(source);
  if (commands === null) return null;
  for (const command of commands) {
    const risk = shellSegmentRisk(command, depth, workdir);
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
  if (prototype === Object.prototype && !objectPrototypeIsPristine()) return false;

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

function targetsOpenClawInstruction(relative) {
  if (relative.length === 1
    && OPENCLAW_WORKSPACE_BOOTSTRAP_FILES.has(relative[0])) return true;
  return relative[0] === 'skills' && relative.at(-1) === 'skill.md';
}

function targetsOpenClawStateWrite(path) {
  const normalized = normalizedFilePath(path);
  if (normalized === null) return true;
  const segments = normalized.split('/').filter(Boolean);
  if (OPENCLAW_WORKSPACE_BOOTSTRAP_FILES.has(segments.at(-1))) return true;
  if (segments.includes('skills') && segments.at(-1) === 'skill.md') return true;
  const stateIndex = segments.lastIndexOf('.openclaw');
  if (stateIndex >= 0) {
    const relative = segments.slice(stateIndex + 1);
    if (relative[0] !== 'workspace') return true;
    const workspaceRelative = relative.slice(1);
    return workspaceRelative.length === 0 || targetsOpenClawInstruction(workspaceRelative);
  }

  const slashPath = path.replaceAll('\\', '/');
  const isRelative = !slashPath.startsWith('/')
    && !slashPath.startsWith('~/')
    && !/^[a-zA-Z]:\//u.test(slashPath);
  if (isRelative && targetsOpenClawInstruction(segments)) return true;
  const workspaceIndex = segments[0] === 'workspace'
    ? 0
    : /^[a-z]:$/u.test(segments[0]) && segments[1] === 'workspace' ? 1 : -1;
  return workspaceIndex >= 0
    && targetsOpenClawInstruction(segments.slice(workspaceIndex + 1));
}

function targetsOpenClawSensitiveStateRead(path) {
  const normalized = normalizedFilePath(path);
  if (normalized === null) return true;
  const segments = normalized.split('/').filter(Boolean);
  const stateIndex = segments.lastIndexOf('.openclaw');
  if (stateIndex < 0) return false;
  const relative = segments.slice(stateIndex + 1);
  if (relative[0] === 'workspace' || targetsOpenClawInstruction(relative)) return false;
  return true;
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
  const normalizedPath = segments.join('/');

  if (INERT_TEMPLATE_NAME.test(name) || PUBLIC_KEY_FILE.test(name)) return false;
  if (isSafeSystemMetadataPath(path)) return false;
  if (ENV_FILE.test(name)
    || ENVRC_FILE.test(name)
    || SENSITIVE_READ_FILES.has(name)
    || PRIVATE_KEY_FILE.test(name)
    || PRIVATE_KEY_EXTENSION.test(name)
    || PRIVATE_PEM_FILE.test(name)) return true;
  if ([...SENSITIVE_READ_PATH_SUFFIXES]
    .some((suffix) => normalizedPath === suffix || normalizedPath.endsWith(`/${suffix}`))) {
    return true;
  }
  if (targetsSensitiveSystemPath(path)) return true;
  if (targetsOpenClawSecretStore(segments)) return true;
  if (segments.at(-2) === '.docker' && name === 'config.json') return true;
  if (segments.at(-2) === '.kube' && name === 'config') return true;
  if (segments.some((segment) => SENSITIVE_READ_DIRECTORIES.has(segment))) {
    return true;
  }
  if (segments.some((segment, index) => segment === '.config'
    && segments[index + 1] === 'gcloud')) return true;
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
  if (ACTIVE_AUTOMATION_FILES.has(name)) return true;
  if ([...ACTIVE_AUTOMATION_PATH_SUFFIXES]
    .some((suffix) => lower === suffix || lower.endsWith(`/${suffix}`))) return true;
  if (/(?:^|\/)\.github\/workflows\//u.test(lower)) return /\.ya?ml$/u.test(name);
  if (/(?:^|\/)\.git\/hooks\//u.test(lower)) return ACTIVE_GIT_HOOKS.has(name);
  const devcontainer = /(?:^|\/)\.devcontainer\/(?:[^/]+\/)*([^/]+)$/u.exec(lower);
  if (devcontainer) {
    if (devcontainer[1] === 'devcontainer.json') return true;
    if (!/\.(?:example|sample)$/u.test(devcontainer[1])
      && DEVCONTAINER_LIFECYCLE_FILE.test(devcontainer[1])) return true;
  }
  const segments = lower.split('/').filter((segment) => segment !== '');
  if (!INERT_TEMPLATE_NAME.test(name)
    && segments.slice(0, -1).includes('.ssh')
    && SSH_SECURITY_FILE.test(name)) return true;
  if (segments.slice(0, -1).some((segment) => SECURITY_PATH_SEGMENTS.has(segment))
    && SECURITY_POLICY_FILE.test(name)) return true;
  if (!INERT_TEMPLATE_NAME.test(name)) {
    const parents = segments.slice(0, -1);
    const stem = filenameStem(name);
    const productionName = PRODUCTION_NAME_MARKER.test(name);
    const productionParent = parents.some((segment) => PRODUCTION_NAME_MARKER.test(segment));
    const configContext = parents.some((segment) => CONFIG_PATH_MARKER.test(segment));
    const testContext = TEST_NAME_MARKER.test(stem)
      || parents.some((segment) => TEST_PATH_MARKER.test(segment));
    const dataConfig = DATA_CONFIG_EXTENSION.test(name);
    const codeConfig = CODE_CONFIG_EXTENSION.test(name);
    const namedConfig = (NAMED_PRODUCTION_CONFIG.test(stem)
      || NAMED_PRODUCTION_CONFIG.test(name)
      || CONFIG_NAME_MARKER.test(stem)) && productionName;
    if (ENV_FILE.test(name)
      || !testContext && namedConfig
      || !testContext && productionName && (dataConfig || codeConfig && configContext)
      || !testContext && productionParent
        && (dataConfig || ACTIVE_CONFIG_BASENAME.test(stem))
      || configContext && (productionName || productionParent)
        && (dataConfig || codeConfig || ACTIVE_CONFIG_BASENAME.test(stem))) return true;
  }
  return false;
}

function targetsSecurityTest(path) {
  if (typeof path !== 'string' || !path) return null;
  const normalized = pathPosix.normalize(
    path.replaceAll('\\', '/').replace(/\/{2,}/gu, '/'),
  );
  const segments = normalized.split('/').filter((segment) => segment !== '');
  const stem = filenameStem(segments.at(-1));
  const splitIdentifier = (value) => value
    .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/gu, '$1_$2')
    .toLowerCase();
  const markedStem = splitIdentifier(stem);
  const parents = segments.slice(0, -1).map(splitIdentifier);
  const compactStem = markedStem.replace(/[._-]/gu, '');
  return COMPACT_SECURITY_TEST_NAME.test(compactStem)
    || (TEST_NAME_MARKER.test(markedStem)
      || parents.some((segment) => TEST_PATH_MARKER.test(segment)))
      && (SECURITY_NAME_MARKER.test(markedStem)
        || parents.some((segment) => SECURITY_NAME_MARKER.test(segment)));
}

function targetsStartupPersistence(path) {
  const normalized = normalizedFilePath(path);
  if (normalized === null) return true;
  const segments = normalized.split('/').filter(Boolean);
  const name = segments.at(-1);
  if (STARTUP_BASENAMES.has(name)) return true;
  const joined = segments.join('/');
  if (joined.endsWith('.config/fish/config.fish')
    || /(?:^|\/)\.config\/fish\/conf\.d\/[^/]+\.fish$/u.test(joined)) return true;
  if (/(?:^|\/)library\/(?:launchagents|launchdaemons)\/[^/]+\.plist$/u.test(joined)) {
    return true;
  }
  if (/(?:^|\/)(?:\.config|\.local\/share)\/systemd\/user\/[^/]+\.(?:path|service|socket|target|timer)$/u
    .test(joined)) return true;
  if (/(?:^|\/)\.config\/autostart\/[^/]+\.desktop$/u.test(joined)) return true;
  return /(?:^|\/)appdata\/roaming\/microsoft\/windows\/start menu\/programs\/startup\//u
    .test(joined);
}

function patchRemovesSecurityTest(params) {
  const input = ownDataValue(params, 'input');
  if (!input.ok || typeof input.value !== 'string') return null;
  let updatedPath = null;
  for (const line of input.value.split(/\r?\n/u)) {
    const structuralLine = line;
    const deleted = PATCH_DELETE_HEADER.exec(structuralLine);
    if (deleted && targetsSecurityTest(deleted[1]) !== false) return true;
    const updated = PATCH_UPDATE_HEADER.exec(structuralLine);
    if (updated) {
      updatedPath = updated[1];
      continue;
    }
    if (PATCH_FILE_HEADER.test(structuralLine)) {
      updatedPath = null;
      continue;
    }
    if (PATCH_MOVE_HEADER.test(structuralLine)
      && updatedPath !== null
      && targetsSecurityTest(updatedPath) !== false) return true;
  }
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
    const structuralLine = line;
    const match = PATCH_FILE_HEADER.exec(structuralLine)
      ?? PATCH_MOVE_HEADER.exec(structuralLine);
    if (match) targets.push(match[1]);
  }
  return targets.length > 0 ? targets : null;
}

function normalizedFilePath(path) {
  if (typeof path !== 'string' || path.trim() === ''
    || pathHasRawTraversal(path)
    || pathHasAmbiguousWindowsAlias(path)
    || pathHasWindowsAlternateDataStream(path)) return null;
  return pathPosix.normalize(path.replaceAll('\\', '/')).toLowerCase();
}

function normalizedFileName(path) {
  const normalized = normalizedFilePath(path);
  return normalized === null ? null : normalized.slice(normalized.lastIndexOf('/') + 1);
}

function targetsPrivilegedSystemWrite(path) {
  const normalized = normalizedFilePath(path);
  if (normalized === null) return true;
  return /^(?:\/(?:private\/)?(?:bin|etc|library|sbin|system|usr|var)(?:\/|$)|[a-z]:\/(?:program files(?: \(x86\))?|programdata|windows)(?:\/|$))/u
    .test(normalized);
}

function targetsPackageManifest(path) {
  const normalized = normalizedFilePath(path);
  if (normalized === null) return true;
  const segments = normalized.split('/').filter(Boolean);
  const name = segments.at(-1);
  const joined = segments.join('/');
  return name === null
    || PACKAGE_MANIFEST_FILES.has(name)
    || PACKAGE_MANIFEST_PATTERN.test(name)
    || [...PACKAGE_MANIFEST_PATH_SUFFIXES]
      .some((suffix) => joined === suffix || joined.endsWith(`/${suffix}`))
    || segments.includes('requirements') && /\.(?:in|txt)$/u.test(name);
}

function targetsPackageBoundary(path) {
  const name = normalizedFileName(path);
  return name === null
    || PACKAGE_BOUNDARY_FILES.has(name)
    || name.endsWith('.dockerignore');
}

function targetsProtectedWritePath(path, includePackageBoundary = true) {
  if (typeof path !== 'string' || path.trim() === '') return true;
  return targetsCredentialMaterial(path)
    || targetsPrivilegedSystemWrite(path)
    || targetsOpenClawConfigWrite(path) !== false
    || targetsOpenClawStateWrite(path) !== false
    || targetsAuditOrHistoryWrite(path)
    || targetsActiveAutomation(path) !== false
    || targetsStartupPersistence(path) !== false
    || targetsPackageManifest(path) !== false
    || includePackageBoundary && targetsPackageBoundary(path) !== false
    || targetsSecurityTest(path) !== false;
}

function targetsProtectedReadPath(path) {
  if (typeof path !== 'string' || path.trim() === '') return true;
  return targetsCredentialMaterial(path)
    || targetsOpenClawSensitiveStateRead(path) !== false
    || targetsAuditOrHistoryWrite(path);
}

function patchRemovesPackageBoundary(params) {
  const input = ownDataValue(params, 'input');
  if (!input.ok || typeof input.value !== 'string') return null;
  let boundaryPath = null;
  for (const line of input.value.split(/\r?\n/u)) {
    const structuralLine = line;
    const deleted = PATCH_DELETE_HEADER.exec(structuralLine);
    if (deleted) {
      if (targetsPackageBoundary(deleted[1])) return true;
      boundaryPath = null;
      continue;
    }
    const updated = PATCH_UPDATE_HEADER.exec(structuralLine);
    if (updated) {
      boundaryPath = targetsPackageBoundary(updated[1]) ? updated[1] : null;
      continue;
    }
    const added = PATCH_ADD_HEADER.exec(structuralLine);
    if (added) {
      boundaryPath = targetsPackageBoundary(added[1]) ? added[1] : null;
      continue;
    }
    const fileHeader = PATCH_FILE_HEADER.exec(structuralLine);
    if (fileHeader) {
      boundaryPath = null;
      continue;
    }
    const moved = PATCH_MOVE_HEADER.exec(structuralLine);
    if (moved && (boundaryPath !== null || targetsPackageBoundary(moved[1]))) return true;
    if (boundaryPath === null) continue;
    if (line.startsWith('-')) {
      const removed = line.slice(1);
      if (removed !== '' && !removed.startsWith('#') && !removed.startsWith('!')) {
        return true;
      }
    }
    if (line.startsWith('+')) {
      const addedRule = line.slice(1);
      if (addedRule.startsWith('!')
        || normalizedFileName(boundaryPath) === '.dockerignore'
          && addedRule.trimStart().startsWith('!')) return true;
    }
  }
  return false;
}

function editWeakensPackageBoundary(params) {
  const path = ownDataValue(params, 'path');
  if (!path.ok || !targetsPackageBoundary(path.value)) return false;
  // Edit receives only replacement fragments, not the complete ordered rule file.
  // Whitespace and rule order are semantic, so monotonic safety cannot be proven here.
  return true;
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
  const safePathFamily = classifySafePathShape({
    tool_name: toolName,
    params: action.params,
    session_key: action.sessionKey,
  });
  if (safePathFamily !== null) return result;

  if (toolName === 'read') {
    const path = ownDataValue(action.params, 'path');
    if (!path.ok || typeof path.value !== 'string' || path.value.trim() === ''
      || targetsProtectedReadPath(path.value)) return localReview(result);
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
    const includeTools = ownDataValue(action.params, 'includeTools');
    if (!requestedSession.ok
      || typeof requestedSession.value !== 'string'
      || requestedSession.value.trim() === ''
      || typeof action.sessionKey !== 'string'
      || action.sessionKey.trim() === ''
      || requestedSession.value !== action.sessionKey
      || includeTools.ok && includeTools.value !== false) return localReview(result);
    return result;
  }

  if (toolName === 'sessions_send' || toolName === 'sessions_spawn'
    || toolName === 'create_goal' || toolName === 'update_goal'
    || toolName === 'canvas' || toolName === 'tts') return localReview(result);

  if (toolName === 'subagents') {
    const actionName = ownDataValue(action.params, 'action');
    return actionName.ok && actionName.value === 'list' ? result : localReview(result);
  }

  if (toolName === 'session_status') {
    const model = ownDataValue(action.params, 'model');
    if (model.ok) {
      return localReview(result);
    }
    const requestedSession = ownDataValue(action.params, 'sessionKey');
    if (requestedSession.ok
      && requestedSession.value !== 'current'
      && requestedSession.value !== action.sessionKey) return localReview(result);
    return result;
  }

  if (toolName === 'nodes') {
    const actionName = ownDataValue(action.params, 'action');
    return actionName.ok && typeof actionName.value === 'string'
      && READ_ONLY_NODE_ACTIONS.has(actionName.value)
      ? result
      : localReview(result);
  }

  if (GENERATION_TOOL_NAMES.has(toolName)) {
    const actionName = ownDataValue(action.params, 'action');
    return actionName.ok && actionName.value === 'list' ? result : localReview(result);
  }

  if (toolName === 'transcripts') {
    const actionName = ownDataValue(action.params, 'action');
    return actionName.ok && actionName.value === 'status' ? result : localReview(result);
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

  if (toolName === 'exec' || toolName === 'bash') {
    const elevated = ownDataValue(action.params, 'elevated');
    if (elevated.ok && elevated.value !== false) return localReview(result);
    const host = ownDataValue(action.params, 'host');
    if (host.ok && host.value !== 'sandbox') return localReview(result);
    if (ownDataValue(action.params, 'node').ok) return localReview(result);
    const pty = ownDataValue(action.params, 'pty');
    if (pty.ok && pty.value !== false) return localReview(result);
    const background = ownDataValue(action.params, 'background');
    if (background.ok && background.value !== false) return localReview(result);
    const timeout = ownDataValue(action.params, 'timeout');
    if (timeout.ok && (!Number.isInteger(timeout.value)
      || timeout.value < 1 || timeout.value > 3_600)) return localReview(result);
    const yieldMs = ownDataValue(action.params, 'yieldMs');
    if (yieldMs.ok && (!Number.isInteger(yieldMs.value)
      || yieldMs.value < 1 || yieldMs.value > 30_000)) return localReview(result);
    const environment = ownDataValue(action.params, 'env');
    if (environment.ok
      && (!isPlainObject(environment.value) || Object.keys(environment.value).length > 0)) {
      return localReview(result);
    }
    const requestedWorkdir = ownDataValue(action.params, 'workdir');
    const workdir = requestedWorkdir.ok
      ? normalizedShellWorkdir(requestedWorkdir.value)
      : undefined;
    if (requestedWorkdir.ok && workdir === null) return localReview(result);
    const command = ownDataValue(action.params, 'command');
    const legacyCommand = ownDataValue(action.params, 'cmd');
    if (command.ok && legacyCommand.ok) return localReview(result);
    const cmd = command.ok ? command : legacyCommand;
    if (!cmd.ok || shellCommandRisk(cmd.value, 0, workdir) !== false) {
      return localReview(result);
    }
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
    if (!actionName.ok || typeof actionName.value !== 'string') {
      return localReview(result);
    }
    const browserTarget = ownDataValue(action.params, 'target');
    if (!browserTarget.ok || browserTarget.value !== 'sandbox') return localReview(result);
    if (ownDataValue(action.params, 'node').ok) return localReview(result);
    if (BROWSER_CAPTURE_ACTIONS.has(actionName.value)) return localReview(result);
    if (BROWSER_URL_ACTIONS.has(actionName.value)) {
      const targetUrl = ownDataValue(action.params, 'targetUrl');
      const url = targetUrl.ok ? targetUrl : ownDataValue(action.params, 'url');
      return url.ok && internalWebFetchUrl(url.value) === false
        ? result
        : localReview(result);
    }
    if (actionName.value === 'console') return localReview(result);
    if (actionName.value !== 'act') {
      return LOW_RISK_BROWSER_ACTIONS.has(actionName.value) ? result : localReview(result);
    }
    const request = ownDataValue(action.params, 'request');
    const actKind = request.ok
      ? ownDataValue(request.value, 'kind')
      : ownDataValue(action.params, 'kind');
    if (actKind.ok && actKind.value === 'wait') {
      const waitParams = request.ok ? request.value : action.params;
      const waitKeys = Reflect.ownKeys(waitParams);
      const allowedWaitKeys = request.ok
        ? BROWSER_WAIT_REQUEST_KEYS
        : BROWSER_WAIT_LEGACY_PARAM_KEYS;
      const outerKeys = Reflect.ownKeys(action.params);
      const allowedOuterKeys = request.ok
        ? BROWSER_WAIT_NESTED_PARAM_KEYS
        : BROWSER_WAIT_LEGACY_PARAM_KEYS;
      const timeMs = ownDataValue(waitParams, 'timeMs');
      if (!timeMs.ok
        || !Number.isInteger(timeMs.value)
        || timeMs.value < 0
        || timeMs.value > BROWSER_MAX_WAIT_MS
        || waitKeys.some((key) => typeof key !== 'string' || !allowedWaitKeys.has(key))
        || outerKeys.some((key) => typeof key !== 'string' || !allowedOuterKeys.has(key))) {
        return localReview(result);
      }
    }
    return actKind.ok
      && typeof actKind.value === 'string'
      && LOW_RISK_BROWSER_ACT_KINDS.has(actKind.value)
      ? result
      : localReview(result);
  }

  if (!FILE_WRITE_TOOLS.has(toolName)) return result;
  const targets = fileTargets(action.params, toolName);
  const securityTestRemoval = toolName === 'apply_patch'
    ? patchRemovesSecurityTest(action.params)
    : false;
  let packageBoundaryRemoval = false;
  if (toolName === 'apply_patch') {
    packageBoundaryRemoval = patchRemovesPackageBoundary(action.params);
  } else if (toolName === 'edit') {
    packageBoundaryRemoval = editWeakensPackageBoundary(action.params);
  } else if (toolName === 'write') {
    packageBoundaryRemoval = targets?.some(targetsPackageBoundary);
  }
  if (targets === null
    || securityTestRemoval !== false
    || packageBoundaryRemoval !== false
    || targets.some((path) => targetsProtectedWritePath(path, false))) {
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

  const feedbackCode = selectFeedbackCode(result);

  if (enforcement === 'enforce'
    && (mode === 'autonomous' || mode === 'supervised')
    && result?.kind === 'allow'
    && feedbackCode === null) return { params };

  if (result?.kind === 'allow'
    || result?.kind === 'deny'
    || feedbackRequiresBlock(feedbackCode)) {
    return {
      block: true,
      blockReason: createBlockFeedback(feedbackCode),
    };
  }

  if (enforcement === 'enforce' && mode === 'supervised') {
    return {
      params,
      requireApproval: {
        title: REVIEW_BLOCK_REASON,
        description: createApprovalDescription(feedbackCode),
        severity: approvalSeverity(result),
        timeoutMs: APPROVAL_TIMEOUT_MS,
        timeoutBehavior: 'deny',
        pluginId: PLUGIN_ID,
      },
    };
  }

  return { block: true, blockReason: createBlockFeedback(feedbackCode) };
}
