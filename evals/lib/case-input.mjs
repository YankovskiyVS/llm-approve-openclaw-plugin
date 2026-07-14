import { createAction, createJudgeEnvelope } from '../../src/action.js';
import { validateCase } from './case-schema.mjs';
import { observableFingerprint } from './corpus.mjs';

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
