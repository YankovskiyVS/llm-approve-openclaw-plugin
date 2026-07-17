import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { computeActionHash } from './action.js';
import { MODEL_ID, PLUGIN_ID, POLICY_VERSION } from './constants.js';
import {
  JUDGE_REASON_CODES,
  JUDGE_VERDICT_KEYS,
  validateJudgeVerdict,
} from './judge-schema.js';
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
const DECISION_SOURCES = new Set([
  'hard_boundary',
  'circuit_breaker',
  'llm',
  'local_downgrade',
  'failure',
]);
const SAFE_PATH_FAMILIES = new Set(['session_status_current', 'browser_wait']);
const CLOSED_FEEDBACK_CODES = new Set(FEEDBACK_CODES);
const CLOSED_FEEDBACK_STATUSES = new Set(FEEDBACK_STATUSES);
const MODEL_FEEDBACK_CODES = new Set(
  JUDGE_REASON_CODES.filter((code) => code !== 'safe_and_authorized'),
);
const OMITTED_RATIONALE = '[model rationale omitted]';
const WRITE_FAILED_MESSAGE = 'LLM action judge audit write failed';
const INVALID_WRITER_OPTIONS = 'invalid audit writer options';
const MAX_TOOL_NAME_LENGTH = 256;
const SAFE_REASON_CODE = 'safe_and_authorized';
const LOCAL_FEEDBACK_CODES = new Set(['local_policy_review', 'opaque_or_unverifiable']);
const FAILURE_FEEDBACK_CODES = new Set(['judge_unavailable', 'invalid_judge_response']);

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
    decision_source: 'failure',
    safe_path_candidate: false,
    safe_path_family: null,
    safe_path_disagreement: null,
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

function rawJudgeSnapshot(judgeResult, expectedActionHash) {
  if (judgeResult === undefined || judgeResult === null) {
    return { present: false, valid: true, verdict: null };
  }
  try {
    const verdict = judgeVerdict(judgeResult);
    if (verdict === null || typeof verdict !== 'object' || utilTypes.isProxy(verdict)) {
      return { present: true, valid: false, verdict: null };
    }
    const prototype = Object.getPrototypeOf(verdict);
    if (prototype !== Object.prototype && prototype !== null) {
      return { present: true, valid: false, verdict: null };
    }
    const keys = Reflect.ownKeys(verdict);
    if (keys.length !== JUDGE_VERDICT_KEYS.length
      || keys.some((key) => typeof key !== 'string' || !JUDGE_VERDICT_KEYS.includes(key))) {
      return { present: true, valid: false, verdict: null };
    }
    const snapshot = {};
    for (const key of JUDGE_VERDICT_KEYS) {
      const descriptor = Object.getOwnPropertyDescriptor(verdict, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return { present: true, valid: false, verdict: null };
      }
      snapshot[key] = descriptor.value;
    }
    validateJudgeVerdict(snapshot);
    if (snapshot.action_hash !== expectedActionHash
      || typeof snapshot.rationale !== 'string'
      || snapshot.rationale.trim() === '') {
      return { present: true, valid: false, verdict: null };
    }
    return { present: true, valid: true, verdict: snapshot };
  } catch {
    return { present: true, valid: false, verdict: null };
  }
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

function inferredDecisionSource(normalized, outcome) {
  const code = selectFeedbackCode(normalized);
  if (code === 'hard_policy_block') return 'hard_boundary';
  if (code === 'repeated_denials') return 'circuit_breaker';
  if (outcome === 'failure') return 'failure';
  if (ownDataValue(normalized, 'local_guard') === true
    || ownDataValue(normalized, 'opaque') === true) return 'local_downgrade';
  return 'llm';
}

function judgeTupleState(event) {
  const values = [
    event.decision,
    event.risk,
    event.authorization,
    event.confidence,
    event.reason_code,
  ];
  if (values.every((value) => value === null) && event.rationale === null) return 'absent';
  const complete = DECISIONS.has(event.decision)
    && RISKS.has(event.risk)
    && AUTHORIZATIONS.has(event.authorization)
    && validConfidence(event.confidence) !== null
    && REASON_CODES.has(event.reason_code)
    && event.rationale === OMITTED_RATIONALE
    && ((event.decision === 'allow') === (event.reason_code === SAFE_REASON_CODE));
  return complete ? 'complete' : 'invalid';
}

function expectedFeedbackStatus(mode, outcome, code) {
  if (outcome === 'deny' || feedbackRequiresBlock(code)) return 'blocked';
  if (outcome === 'review' || outcome === 'failure') {
    return mode === 'autonomous' ? 'blocked' : 'approval_required';
  }
  return null;
}

function feedbackSemanticsValid(event) {
  if (event.enforcement === 'shadow') {
    return event.feedback_code === null && event.feedback_status === null;
  }
  if (event.enforcement !== 'enforce') return false;

  let validCode = false;
  if (event.decision_source === 'hard_boundary') {
    validCode = event.feedback_code === 'hard_policy_block';
  } else if (event.decision_source === 'circuit_breaker') {
    validCode = event.feedback_code === 'repeated_denials';
  } else if (event.decision_source === 'local_downgrade') {
    validCode = LOCAL_FEEDBACK_CODES.has(event.feedback_code);
  } else if (event.decision_source === 'failure') {
    validCode = FAILURE_FEEDBACK_CODES.has(event.feedback_code);
  } else if (event.outcome === 'allow') {
    return event.feedback_code === null && event.feedback_status === null;
  } else {
    validCode = MODEL_FEEDBACK_CODES.has(event.feedback_code)
      && event.feedback_code === event.reason_code;
  }
  return validCode
    && event.feedback_status === expectedFeedbackStatus(
      event.mode,
      event.outcome,
      event.feedback_code,
    );
}

function safePathSemanticsValid(event) {
  if (event.safe_path_candidate === false) {
    return event.safe_path_family === null && event.safe_path_disagreement === null;
  }
  if (event.safe_path_candidate !== true
    || !SAFE_PATH_FAMILIES.has(event.safe_path_family)
    || typeof event.safe_path_disagreement !== 'boolean'
    || event.decision_source === 'hard_boundary') return false;
  return event.decision_source === 'circuit_breaker'
    || event.safe_path_disagreement === (event.outcome !== 'allow');
}

function auditSemanticsValid(event, rawJudgeContractValid = true) {
  if (!rawJudgeContractValid) return false;
  const tupleState = judgeTupleState(event);
  if (tupleState === 'invalid') return false;

  const fallback = event.mode === null && event.enforcement === null;
  if (fallback) {
    return event.decision_source === 'failure'
      && event.outcome === 'failure'
      && tupleState === 'absent'
      && event.feedback_code === null
      && event.feedback_status === null
      && safePathSemanticsValid(event);
  }
  if (!MODES.has(event.mode) || !ENFORCEMENTS.has(event.enforcement)) return false;

  let sourceValid = false;
  if (event.decision_source === 'hard_boundary') {
    sourceValid = event.outcome === 'deny';
  } else if (event.decision_source === 'circuit_breaker') {
    sourceValid = event.outcome === 'deny';
  } else if (event.decision_source === 'local_downgrade') {
    sourceValid = event.outcome === 'review'
      && tupleState === 'complete'
      && event.decision === 'allow';
  } else if (event.decision_source === 'failure') {
    sourceValid = event.outcome === 'failure';
  } else if (event.decision_source === 'llm') {
    sourceValid = tupleState === 'complete' && event.decision === event.outcome;
  }
  return sourceValid && feedbackSemanticsValid(event) && safePathSemanticsValid(event);
}

function collapseSemanticFailure(event) {
  event.decision = null;
  event.risk = null;
  event.authorization = null;
  event.confidence = null;
  event.reason_code = null;
  event.outcome = 'failure';
  event.decision_source = 'failure';
  event.safe_path_candidate = false;
  event.safe_path_family = null;
  event.safe_path_disagreement = null;
  event.rationale = null;
  if (MODES.has(event.mode) && ENFORCEMENTS.has(event.enforcement)) {
    if (event.enforcement === 'enforce') {
      event.feedback_code = 'invalid_judge_response';
      event.feedback_status = expectedFeedbackStatus(
        event.mode,
        event.outcome,
        event.feedback_code,
      );
    } else {
      event.feedback_code = null;
      event.feedback_status = null;
    }
  } else {
    event.mode = null;
    event.enforcement = null;
    event.feedback_code = null;
    event.feedback_status = null;
  }
  return event;
}

export function buildAuditEvent(input = {}) {
  try {
    if (input === null || typeof input !== 'object') return emptyAuditEvent();

    const action = ownDataValue(input, 'action');
    const rawJudgeInput = ownDataValue(input, 'judgeResult');
    const normalized = ownDataValue(input, 'normalized');
    const event = emptyAuditEvent();

    event.tool_name = validToolName(ownDataValue(action, 'tool_name'));
    event.action_hash = action === null || typeof action !== 'object'
      ? null
      : computeActionHash(action);
    event.agent_id_hash = hashCorrelationId('agent_id', ownDataValue(action, 'agent_id'));
    event.session_key_hash = hashCorrelationId('session_key', ownDataValue(action, 'session_key'));
    event.run_id_hash = hashCorrelationId('run_id', ownDataValue(action, 'run_id'));
    event.tool_call_id_hash = hashCorrelationId(
      'tool_call_id',
      ownDataValue(action, 'tool_call_id'),
    );
    const rawJudge = rawJudgeSnapshot(rawJudgeInput, event.action_hash);
    const judgeResult = rawJudge.verdict;
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
    const explicitSource = ownDataValue(input, 'decisionSource');
    const source = explicitSource === undefined
      ? inferredDecisionSource(normalized, event.outcome)
      : validEnum(explicitSource, DECISION_SOURCES);
    const explicitCandidate = ownDataValue(input, 'safePathCandidate');
    const candidate = explicitCandidate === undefined ? false : explicitCandidate;
    const explicitFamily = ownDataValue(input, 'safePathFamily');
    const family = explicitFamily === undefined ? null : explicitFamily;
    const explicitDisagreement = ownDataValue(input, 'safePathDisagreement');
    const disagreement = explicitDisagreement === undefined ? null : explicitDisagreement;
    event.decision_source = source;
    event.safe_path_candidate = candidate;
    event.safe_path_family = family;
    event.safe_path_disagreement = disagreement;
    event.rationale = rationaleIndicator(ownDataValue(judgeResult, 'rationale'));

    if (!auditSemanticsValid(event, rawJudge.valid)) collapseSemanticFailure(event);

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
  event.feedback_code = feedbackCode;
  event.feedback_status = feedbackStatus;
  event.decision_source = validEnum(
    ownDataValue(input, 'decision_source'),
    DECISION_SOURCES,
  );
  event.safe_path_candidate = ownDataValue(input, 'safe_path_candidate');
  event.safe_path_family = validEnum(
    ownDataValue(input, 'safe_path_family'),
    SAFE_PATH_FAMILIES,
  );
  event.safe_path_disagreement = ownDataValue(input, 'safe_path_disagreement');
  event.rationale = rationaleIndicator(ownDataValue(input, 'rationale'));
  if (!auditSemanticsValid(event)) collapseSemanticFailure(event);
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
