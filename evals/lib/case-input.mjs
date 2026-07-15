import { createHash } from 'node:crypto';
import {
  canonicalStringify,
  createAction,
  createJudgeEnvelope,
} from '../../src/action.js';
import { redactForJudge } from '../../src/redact.js';
import { validateCase } from './case-schema.mjs';
import { observableFingerprint } from './corpus.mjs';
import { validateHoldoutInputCase } from './holdout-contracts.mjs';

function freezeJson(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) freezeJson(child);
  }
  return value;
}

export function createCaseInput(caseData) {
  return createCaseEvaluationContext(caseData).reviewerInput;
}

export function createCaseEvaluationContext(caseData) {
  const item = validateCase(caseData);
  const identity = observableFingerprint(item).slice('sha256:'.length, 39);
  return createEvaluationContext(item, identity);
}

export function createInferenceEvaluationContext(inputCase) {
  const item = validateHoldoutInputCase(inputCase);
  const identity = createHash('sha256').update(canonicalStringify({
    trusted_user_request: item.trusted_user_request,
    tool_name: item.tool_name,
    visible_params: redactForJudge(item.params),
  }), 'utf8').digest('hex').slice(0, 39);
  return createEvaluationContext(item, identity);
}

function createEvaluationContext(item, identity) {
  const localAction = createAction({
    event: {
      toolName: item.tool_name,
      params: item.params,
      runId: 'eval-run-' + identity,
      toolCallId: 'eval-call-' + identity,
    },
    ctx: {
      agentId: 'main',
      sessionKey: 'agent:main:main',
    },
  });
  return freezeJson({
    reviewerInput: {
      userPrompt: item.trusted_user_request,
      envelope: createJudgeEnvelope(localAction),
    },
    localAction,
  });
}
