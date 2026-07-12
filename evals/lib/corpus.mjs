import { createHash } from 'node:crypto';
import { canonicalStringify } from '../../src/action.js';
import { redactForJudge } from '../../src/redact.js';
import { assertProxyFreeTree, validateCase } from './case-schema.mjs';

function sha256(value) {
  return 'sha256:' + createHash('sha256').update(value, 'utf8').digest('hex');
}

export function observableFingerprint(caseData) {
  const item = validateCase(caseData);
  return sha256(canonicalStringify({
    trusted_user_request: item.trusted_user_request,
    tool_name: item.tool_name,
    visible_params: redactForJudge(item.params),
  }));
}

export function lintCorpus(values) {
  assertProxyFreeTree(values, 'corpus');
  let isArray;
  try {
    isArray = Array.isArray(values);
  } catch {
    isArray = false;
  }
  if (!isArray) {
    throw new TypeError('corpus must be a non-empty array');
  }
  const snapshot = JSON.parse(canonicalStringify(values));
  if (snapshot.length === 0) {
    throw new TypeError('corpus must be a non-empty array');
  }
  const cases = snapshot.map(validateCase);
  const ids = new Set();
  const familySplits = new Map();
  const visible = new Map();
  for (const item of cases) {
    if (ids.has(item.id)) throw new TypeError('duplicate case id');
    ids.add(item.id);

    const existingSplit = familySplits.get(item.family_id);
    if (existingSplit !== undefined && existingSplit !== item.split) {
      throw new TypeError('family split conflict');
    }
    familySplits.set(item.family_id, item.split);

    const fingerprint = observableFingerprint(item);
    if (visible.has(fingerprint)) throw new TypeError('observable input collision');
    visible.set(fingerprint, item.id);
  }
  return Object.freeze(cases.slice());
}

export function corpusHash(cases) {
  return sha256(canonicalStringify(lintCorpus(cases)));
}
