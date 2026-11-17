import type { Writable } from 'node:stream';
import type { BrowserError, ErrorCode } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';

const diagnosticLines = Object.freeze({
  protocol_failure: 'arbol-browser mcp: protocol_failure\n',
  connection_closed: 'arbol-browser mcp: connection_closed\n',
  attachment_failed: 'arbol-browser mcp: attachment_failed\n',
  runtime_lost: 'arbol-browser mcp: runtime_lost\n',
  invalid_runtime_result: 'arbol-browser mcp: invalid_runtime_result\n',
  request_cancelled: 'arbol-browser mcp: request_cancelled\n',
});
export type McpDiagnosticEvent = keyof typeof diagnosticLines;
export type McpDiagnostics = (event: McpDiagnosticEvent) => void;
/** Only compile-time fixed labels can be emitted. SDK exceptions, validation
 * errors and abort reasons may contain full bodies and are never accepted. */
export function createMcpDiagnostics(output: Writable): McpDiagnostics {
  output.on('error', () => {});
  return event => {
    const line = Object.hasOwn(diagnosticLines, event) ? diagnosticLines[event] : undefined;
    if (!line || output.destroyed || output.writableEnded || output.writableLength + Buffer.byteLength(line) > 4096) return;
    try { output.write(line, () => {}); } catch { /* diagnostics cannot retain or disclose failed output */ }
  };
}
const publicMessages: Record<ErrorCode, string> = {
  invalid_input: 'Invalid browser input.',
  profile_not_found: 'The selected profile does not exist.',
  profile_unavailable: 'The selected profile is unavailable.',
  browser_unavailable: 'The browser connection is unavailable.',
  tab_not_found: 'The tab is unavailable.',
  control_refused: 'The operation is not admitted under current browser control.',
  control_changed: 'Browser control has changed.',
  stale_snapshot: 'The snapshot or original target is no longer current.',
  snapshot_truncated: 'A complete snapshot is unavailable within the bounds.',
  navigation_failed: 'The navigation did not complete.',
  unsupported: 'The operation is unavailable in browser contract 1.',
  internal: 'The browser operation could not complete.',
};
/** Preserve only validated closed status/outcome facts from the trusted host.
 * Free-form engine/provider messages never become page-data side channels. */
export function redactedBrowserError(detail: BrowserError): BrowserError {
  if (!validator('browser.BrowserError')(detail)) return { code: 'internal', message: publicMessages.internal, retryable: false };
  return { code: detail.code, message: publicMessages[detail.code], retryable: detail.retryable,
    remedy: detail.code === 'tab_not_found' ? 'Inspect the tabs shared with this attachment.' :
      detail.code === 'control_refused' ? 'Finish or cancel outstanding work; use Take control if needed, then inspect fresh state.' :
      'Inspect fresh browser state before deciding on another request; do not replay an uncertain action.',
    ...(detail.action === undefined ? {} : { action: detail.action }),
    ...(detail.dispatchOutcome === undefined ? {} : { dispatchOutcome: detail.dispatchOutcome }),
    ...(detail.controller === undefined ? {} : { controller: detail.controller }),
    ...(detail.controlGeneration === undefined ? {} : { controlGeneration: detail.controlGeneration }) };
}
