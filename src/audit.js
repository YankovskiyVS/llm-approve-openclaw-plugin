import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { computeActionHash } from './action.js';
import { MODEL_ID, PLUGIN_ID, POLICY_VERSION } from './constants.js';
import { JUDGE_REASON_CODES } from './judge-schema.js';
import {
  FEEDBACK_CODES,
  FEEDBACK_STATUSES,
  feedbackRequiresBlock,
  selectFeedbackCode,
  selectFeedbackOutcome,
} from './feedback.js';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const DECISIONS = new Set(['allow', 'deny', 'review']);
const RISKS = new Set(['low', 'medium', 'high', 'critical']);
const AUTHORIZATIONS = new Set(['unknown', 'low', 'medium', 'high']);
const REASON_CODES = new Set(JUDGE_REASON_CODES);
const OUTCOMES = new Set(['allow', 'deny', 'review', 'failure']);
const MODES = new Set(['autonomous', 'supervised']);
const ENFORCEMENTS = new Set(['shadow', 'enforce']);
const CLOSED_FEEDBACK_CODES = new Set(FEEDBACK_CODES);
const CLOSED_FEEDBACK_STATUSES = new Set(FEEDBACK_STATUSES);
const MODEL_FEEDBACK_CODES = new Set(
  JUDGE_REASON_CODES.filter((code) => code !== 'safe_and_authorized'),
);
const OMITTED_RATIONALE = '[model rationale omitted]';
const WRITE_FAILED_MESSAGE = 'LLM action judge audit write failed';
const INVALID_WRITER_OPTIONS = 'invalid audit writer options';
const MAX_TOOL_NAME_LENGTH = 256;

function auditOpenFlags() {
  const required = [
    fsConstants.O_WRONLY,
    fsConstants.O_APPEND,
    fsConstants.O_CREAT,
    fsConstants.O_NOFOLLOW,
  ];
  if (!required.every(Number.isInteger)) return null;
  const nonBlocking = Number.isInteger(fsConstants.O_NONBLOCK) ? fsConstants.O_NONBLOCK : 0;
  return required.reduce((flags, flag) => flags | flag, nonBlocking);
}

const AUDIT_OPEN_FLAGS = auditOpenFlags();

function currentTimestamp() {
  try {
    return new Date().toISOString();
  } catch {
    return '1970-01-01T00:00:00.000Z';
  }
}

function emptyAuditEvent() {
  return {
    timestamp: currentTimestamp(),
    plugin_id: PLUGIN_ID,
    model_id: MODEL_ID,
    policy_version: POLICY_VERSION,
    tool_name: null,
    action_hash: null,
    agent_id_hash: null,
    session_key_hash: null,
    run_id_hash: null,
    tool_call_id_hash: null,
    decision: null,
    risk: null,
    authorization: null,
    confidence: null,
    reason_code: null,
    outcome: 'failure',
    latency_ms: null,
    mode: null,
    enforcement: null,
    feedback_code: null,
    feedback_status: null,
    rationale: null,
  };
}

function ownDataValue(source, key) {
  if (source === null || typeof source !== 'object') return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(source, key);
  if (!descriptor) return undefined;
  if (!Object.hasOwn(descriptor, 'value')) {
    throw new TypeError('unsupported audit input');
  }
  return descriptor.value;
}

function validToolName(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= MAX_TOOL_NAME_LENGTH
    ? value
    : null;
}

function validEnum(value, allowed) {
  return typeof value === 'string' && allowed.has(value) ? value : null;
}

function validConfidence(value) {
  return typeof value === 'number'
    && Number.isFinite(value)
    && value >= 0
    && value <= 1
    ? value
    : null;
}

function validLatency(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? value
    : null;
}

function validHash(value) {
  return typeof value === 'string' && HASH_PATTERN.test(value) ? value : null;
}

function validTimestamp(value) {
  if (typeof value !== 'string') return null;
  try {
    return new Date(value).toISOString() === value ? value : null;
  } catch {
    return null;
  }
}

function rationaleIndicator(value) {
  return typeof value === 'string' && value.length > 0 ? OMITTED_RATIONALE : null;
}

function hashCorrelationId(field, value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  const digest = createHash('sha256')
    .update(`llm-action-judge:audit:${field}\0`, 'utf8')
    .update(value, 'utf8')
    .digest('hex');
  return `sha256:${digest}`;
}

function judgeVerdict(judgeResult) {
  if (judgeResult === null || typeof judgeResult !== 'object') return null;
  const nested = ownDataValue(judgeResult, 'verdict');
  return nested !== null && typeof nested === 'object' ? nested : judgeResult;
}

function feedbackMetadata(normalized, outcome, mode, enforcement) {
  if (enforcement !== 'enforce') return { code: null, status: null };
  if (outcome === 'allow') return { code: null, status: null };
  if (outcome !== 'deny' && outcome !== 'review' && outcome !== 'failure') {
    return { code: null, status: null };
  }
  const code = selectFeedbackCode(normalized);
  if (!CLOSED_FEEDBACK_CODES.has(code)) return { code: null, status: null };
  if (outcome === 'deny' || feedbackRequiresBlock(code)) return { code, status: 'blocked' };
  if (mode === 'autonomous') return { code, status: 'blocked' };
  if (mode === 'supervised') return { code, status: 'approval_required' };
  return { code: null, status: null };
}

function sanitizeFeedbackMetadata(code, status, outcome, mode, enforcement) {
  if (enforcement !== 'enforce' || outcome === 'allow') return { code: null, status: null };
  if (!CLOSED_FEEDBACK_CODES.has(code) || !CLOSED_FEEDBACK_STATUSES.has(status)) {
    return { code: null, status: null };
  }
  const codeMatchesOutcome = outcome === 'deny'
    || (feedbackRequiresBlock(code)
      ? outcome === 'review' || outcome === 'failure'
      : code === 'local_policy_review'
        ? outcome === 'review'
        : code === 'judge_unavailable' || code === 'invalid_judge_response'
          ? outcome === 'failure'
          : MODEL_FEEDBACK_CODES.has(code) && outcome === 'review');
  if (!codeMatchesOutcome) return { code: null, status: null };
  let expectedStatus = null;
  if (outcome === 'deny' || feedbackRequiresBlock(code)) {
    expectedStatus = 'blocked';
  } else if (outcome === 'review' || outcome === 'failure') {
    if (mode === 'autonomous') expectedStatus = 'blocked';
    if (mode === 'supervised') expectedStatus = 'approval_required';
  }
  return status === expectedStatus
    ? { code, status }
    : { code: null, status: null };
}

export function buildAuditEvent(input = {}) {
  try {
    if (input === null || typeof input !== 'object') return emptyAuditEvent();

    const action = ownDataValue(input, 'action');
    const judgeResult = judgeVerdict(ownDataValue(input, 'judgeResult'));
    const normalized = ownDataValue(input, 'normalized');
    const event = emptyAuditEvent();

    event.tool_name = validToolName(ownDataValue(action, 'tool_name'));
    event.action_hash = computeActionHash(action);
    event.agent_id_hash = hashCorrelationId('agent_id', ownDataValue(action, 'agent_id'));
    event.session_key_hash = hashCorrelationId('session_key', ownDataValue(action, 'session_key'));
    event.run_id_hash = hashCorrelationId('run_id', ownDataValue(action, 'run_id'));
    event.tool_call_id_hash = hashCorrelationId(
      'tool_call_id',
      ownDataValue(action, 'tool_call_id'),
    );
    event.decision = validEnum(ownDataValue(judgeResult, 'decision'), DECISIONS);
    event.risk = validEnum(ownDataValue(judgeResult, 'risk'), RISKS);
    event.authorization = validEnum(
      ownDataValue(judgeResult, 'authorization'),
      AUTHORIZATIONS,
    );
    event.confidence = validConfidence(ownDataValue(judgeResult, 'confidence'));
    event.reason_code = validEnum(ownDataValue(judgeResult, 'reason_code'), REASON_CODES);
    event.outcome = validEnum(selectFeedbackOutcome(normalized), OUTCOMES) ?? 'failure';
    event.latency_ms = validLatency(ownDataValue(input, 'latencyMs'));
    event.mode = validEnum(ownDataValue(input, 'mode'), MODES);
    event.enforcement = validEnum(ownDataValue(input, 'enforcement'), ENFORCEMENTS);
    const feedback = feedbackMetadata(
      normalized,
      event.outcome,
      event.mode,
      event.enforcement,
    );
    event.feedback_code = feedback.code;
    event.feedback_status = feedback.status;
    event.rationale = rationaleIndicator(ownDataValue(judgeResult, 'rationale'));

    return event;
  } catch {
    return emptyAuditEvent();
  }
}

function sanitizeAuditEvent(input) {
  if (input === null || typeof input !== 'object') {
    throw new TypeError('unsupported audit event');
  }

  const event = emptyAuditEvent();
  event.timestamp = validTimestamp(ownDataValue(input, 'timestamp')) ?? event.timestamp;
  event.tool_name = validToolName(ownDataValue(input, 'tool_name'));
  event.action_hash = validHash(ownDataValue(input, 'action_hash'));
  event.agent_id_hash = validHash(ownDataValue(input, 'agent_id_hash'));
  event.session_key_hash = validHash(ownDataValue(input, 'session_key_hash'));
  event.run_id_hash = validHash(ownDataValue(input, 'run_id_hash'));
  event.tool_call_id_hash = validHash(ownDataValue(input, 'tool_call_id_hash'));
  event.decision = validEnum(ownDataValue(input, 'decision'), DECISIONS);
  event.risk = validEnum(ownDataValue(input, 'risk'), RISKS);
  event.authorization = validEnum(
    ownDataValue(input, 'authorization'),
    AUTHORIZATIONS,
  );
  event.confidence = validConfidence(ownDataValue(input, 'confidence'));
  event.reason_code = validEnum(ownDataValue(input, 'reason_code'), REASON_CODES);
  event.outcome = validEnum(ownDataValue(input, 'outcome'), OUTCOMES) ?? 'failure';
  event.latency_ms = validLatency(ownDataValue(input, 'latency_ms'));
  event.mode = validEnum(ownDataValue(input, 'mode'), MODES);
  event.enforcement = validEnum(ownDataValue(input, 'enforcement'), ENFORCEMENTS);
  const feedbackCode = validEnum(
    ownDataValue(input, 'feedback_code'),
    CLOSED_FEEDBACK_CODES,
  );
  const feedbackStatus = validEnum(
    ownDataValue(input, 'feedback_status'),
    CLOSED_FEEDBACK_STATUSES,
  );
  const feedback = sanitizeFeedbackMetadata(
    feedbackCode,
    feedbackStatus,
    event.outcome,
    event.mode,
    event.enforcement,
  );
  event.feedback_code = feedback.code;
  event.feedback_status = feedback.status;
  event.rationale = rationaleIndicator(ownDataValue(input, 'rationale'));
  return event;
}

function methodValue(source, name) {
  if ((source === null || typeof source !== 'object') && typeof source !== 'function') {
    return null;
  }

  const seen = new Set();
  let current = source;
  while (current !== null && !seen.has(current)) {
    seen.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) {
      return Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function'
        ? descriptor.value
        : null;
    }
    current = Object.getPrototypeOf(current);
  }
  return null;
}

function invalidWriterOptions() {
  throw new TypeError(INVALID_WRITER_OPTIONS);
}

function pathIsInside(rootPath, targetPath, allowRoot = true) {
  const relative = path.relative(rootPath, targetPath);
  if (relative === '') return allowRoot;
  return relative !== '..'
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function writerOptions(options) {
  try {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      return invalidWriterOptions();
    }

    const explicitPath = ownDataValue(options, 'filePath');
    const filePath = explicitPath === undefined
      ? path.join(os.homedir(), '.openclaw', 'logs', 'llm-action-judge.jsonl')
      : explicitPath;
    if (typeof filePath !== 'string' || filePath.trim() === '' || filePath.includes('\0')) {
      return invalidWriterOptions();
    }

    const explicitRoot = ownDataValue(options, 'rootPath');
    let rootPath = null;
    if (explicitRoot !== undefined) {
      rootPath = explicitRoot;
      if (typeof explicitRoot !== 'string' || explicitRoot.trim() === ''
        || explicitRoot.includes('\0') || !path.isAbsolute(explicitRoot)
        || path.resolve(explicitRoot) !== explicitRoot || !path.isAbsolute(filePath)
        || path.resolve(filePath) !== filePath
        || !pathIsInside(rootPath, filePath, false)) {
        return invalidWriterOptions();
      }
    }

    const explicitFs = ownDataValue(options, 'fsImpl');
    const fsImpl = explicitFs === undefined ? fsPromises : explicitFs;
    const mkdir = methodValue(fsImpl, 'mkdir');
    const open = methodValue(fsImpl, 'open');
    if (!mkdir || !open) return invalidWriterOptions();
    const realpath = rootPath === null ? null : methodValue(fsImpl, 'realpath');
    const lstat = rootPath === null ? null : methodValue(fsImpl, 'lstat');
    if (rootPath !== null && (!realpath || !lstat)) return invalidWriterOptions();

    const explicitLogger = ownDataValue(options, 'logger');
    let notify = null;
    if (explicitLogger !== undefined) {
      if (typeof explicitLogger === 'function') {
        notify = explicitLogger;
      } else {
        const error = methodValue(explicitLogger, 'error');
        if (!error) return invalidWriterOptions();
        notify = (message) => error.call(explicitLogger, message);
      }
    }

    return { filePath, rootPath, fsImpl, mkdir, open, realpath, lstat, notify };
  } catch {
    return invalidWriterOptions();
  }
}

function notifyFailure(notify) {
  if (!notify) return;
  try {
    Promise.resolve(notify(WRITE_FAILED_MESSAGE)).catch(() => {});
  } catch {
    // Audit logging must never affect the tool decision, including logger failures.
  }
}

async function requireDirectory(lstat, fsImpl, directory) {
  const stats = await lstat.call(fsImpl, directory);
  const isDirectory = methodValue(stats, 'isDirectory');
  const isSymbolicLink = methodValue(stats, 'isSymbolicLink');
  if (!isDirectory || !isSymbolicLink
    || isDirectory.call(stats) !== true
    || isSymbolicLink.call(stats) !== false) {
    throw new TypeError('invalid audit directory');
  }
}

async function requireOrCreateDirectory(lstat, mkdir, fsImpl, directory) {
  try {
    await requireDirectory(lstat, fsImpl, directory);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    await mkdir.call(fsImpl, directory, { recursive: false, mode: 0o700 });
    await requireDirectory(lstat, fsImpl, directory);
  }
}

async function prepareConfinedParent(options) {
  const {
    filePath,
    rootPath,
    fsImpl,
    mkdir,
    realpath,
    lstat,
  } = options;
  const parentPath = path.dirname(filePath);
  await mkdir.call(fsImpl, rootPath, { recursive: true, mode: 0o700 });
  await requireDirectory(lstat, fsImpl, rootPath);

  const relativeParent = path.relative(rootPath, parentPath);
  let current = rootPath;
  if (relativeParent !== '') {
    for (const segment of relativeParent.split(path.sep)) {
      current = path.join(current, segment);
      await requireOrCreateDirectory(lstat, mkdir, fsImpl, current);
    }
  }

  const [realRoot, realParent] = await Promise.all([
    realpath.call(fsImpl, rootPath),
    realpath.call(fsImpl, parentPath),
  ]);
  if (typeof realRoot !== 'string' || typeof realParent !== 'string'
    || !pathIsInside(realRoot, realParent, true)) {
    throw new TypeError('invalid audit directory');
  }
}

export function createAuditWriter(options = {}) {
  const normalizedOptions = writerOptions(options);
  const {
    filePath,
    rootPath,
    fsImpl,
    mkdir,
    open,
    notify,
  } = normalizedOptions;

  async function write(input) {
    let handle;
    let failed = false;

    try {
      const line = `${JSON.stringify(sanitizeAuditEvent(input))}\n`;
      if (AUDIT_OPEN_FLAGS === null) throw new TypeError('secure audit open unsupported');
      if (rootPath === null) {
        await mkdir.call(fsImpl, path.dirname(filePath), { recursive: true, mode: 0o700 });
      } else {
        await prepareConfinedParent(normalizedOptions);
      }
      handle = await open.call(fsImpl, filePath, AUDIT_OPEN_FLAGS, 0o600);

      const stat = methodValue(handle, 'stat');
      if (!stat) throw new TypeError('invalid audit file handle');
      const stats = await stat.call(handle);
      const isFile = methodValue(stats, 'isFile');
      if (!isFile || isFile.call(stats) !== true) {
        throw new TypeError('invalid audit file type');
      }
      const nlink = ownDataValue(stats, 'nlink');
      if (Number.isInteger(nlink) && nlink !== 1) {
        throw new TypeError('invalid audit file links');
      }
      const uid = ownDataValue(stats, 'uid');
      if (Number.isInteger(uid) && typeof process.getuid === 'function'
        && uid !== process.getuid()) {
        throw new TypeError('invalid audit file owner');
      }
      const chmod = methodValue(handle, 'chmod');
      const appendFile = methodValue(handle, 'appendFile');
      if (!chmod || !appendFile) throw new TypeError('invalid audit file handle');

      await chmod.call(handle, 0o600);
      await appendFile.call(handle, line, { encoding: 'utf8' });
    } catch {
      failed = true;
    } finally {
      if (handle !== undefined && handle !== null) {
        try {
          const close = methodValue(handle, 'close');
          if (!close) throw new TypeError('invalid audit file handle');
          await close.call(handle);
        } catch {
          failed = true;
        }
      }
    }

    if (failed) notifyFailure(notify);
    return !failed;
  }

  return { write };
}
