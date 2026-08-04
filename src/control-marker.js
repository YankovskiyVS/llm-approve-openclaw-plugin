/**
 * Outbound-only control marker used by agent-space-manager when
 * `is_autoapprove_enabled` is true. A2A gateway only forwards message text into
 * OpenClaw agent RPC, so this marker is the activation signal that does not
 * require a2a-gateway changes. It is stripped before the trusted prompt is
 * stored for the judge.
 */
export const AUTOAPPROVE_CONTROL_MARKER = '<!--openclaw:autoapprove=1-->';

const MARKER_PATTERN = /(?:^|\n)\s*<!--\s*openclaw:autoapprove\s*=\s*1\s*-->\s*(?:\n|$)/iu;

/**
 * @param {unknown} prompt
 * @returns {{ enabled: boolean, stripped: string }}
 */
export function extractAutoApproveMarker(prompt) {
  if (typeof prompt !== 'string') {
    return { enabled: false, stripped: typeof prompt === 'string' ? prompt : '' };
  }
  const enabled = MARKER_PATTERN.test(prompt) || prompt.includes(AUTOAPPROVE_CONTROL_MARKER);
  if (!enabled) {
    return { enabled: false, stripped: prompt };
  }
  const stripped = prompt
    .replace(MARKER_PATTERN, '\n')
    .split(AUTOAPPROVE_CONTROL_MARKER)
    .join('')
    .replace(/^\n+/u, '')
    .replace(/\n{3,}/gu, '\n\n')
    .trimStart();
  return { enabled: true, stripped };
}

/**
 * Prefix used by manager when building the outbound A2A text payload only.
 * @returns {string}
 */
export function autoApproveOutboundPrefix() {
  return `\n\n${AUTOAPPROVE_CONTROL_MARKER}\n`;
}
