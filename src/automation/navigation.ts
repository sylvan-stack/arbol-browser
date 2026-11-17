import type { Contract } from '../contracts/generated.js';
import { invalidInput } from '../contracts/errors.js';
import type { ActionExecution } from '../host/actions.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import type { HostDocument } from '../host/documents.js';
import { staleSnapshot } from '../host/authority.js';

/** Explicit absolute network URL only. WHATWG's scheme guessing/backslash
 * repair must not silently broaden the accepted tool contract. */
export function agentURL(value: string, previous?: string): string {
  if (Array.from(value).length > 8192 || /[\u0000-\u0020\u007f\uD800-\uDFFF\\]/u.test(value)) throw invalidInput();
  if (value === 'about:blank') return value;
  if (!/^https?:\/\//i.test(value)) throw invalidInput();
  let parsed: URL; try { parsed = new URL(value); } catch { throw invalidInput(); }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password ||
      (previous?.toLowerCase().startsWith('https:') && parsed.protocol === 'http:')) throw invalidInput();
  return parsed.href;
}
/** Policy state belongs to one literal page's actual top-level navigation.
 * It is independent from action completion and supplies no causal successor. */
export class AgentNavigationPolicy {
  private initialHTTPS = false;
  private redirects = 0;
  start(address: string, previous: string): string {
    const safe = agentURL(address, previous);
    this.initialHTTPS = safe.startsWith('https:'); this.redirects = 0; return safe;
  }
  redirect(address: string): string {
    if (++this.redirects > 20) throw invalidInput();
    return agentURL(address, this.initialHTTPS ? 'https:' : undefined);
  }
}
export async function navigateTrusted(inspection: SnapshotInspection, execution: ActionExecution,
  input: Contract<'browser.NavigateInput'>): Promise<Contract<'browser.ActionResult'>> {
  const guard = inspection.guard(execution, true), { stamp } = execution;
  guard();
  if (!execution.action || input.tab !== stamp.target.id || input.controlGeneration !== stamp.generation) throw staleSnapshot();
  inspection.authority.requireSnapshot(input.snapshot, stamp);
  const address = agentURL(input.url, inspection.documents.lastSafeURL(stamp.target)); guard();
  // HostDocuments owns the actual issued slot, loader/frame correlation, commit,
  // DOMContentLoaded and readiness. Missing same-document loader proof refuses.
  const current = await inspection.documents.navigateAction(execution, address);
  inspection.authority.assertHealthy(); inspection.documents.assertCurrent(stamp.target, current);
  if (execution.signal.aborted || performance.now() >= execution.deadline || !current.ready) throw staleSnapshot();
  execution.settle({ action: execution.action, operation: 'browser_navigate', original: stamp.document,
    current, delivered: true, quiescent: true, command: execution.command });
  return navigationResult(inspection, execution, current);
}
function navigationResult(inspection: SnapshotInspection, execution: ActionExecution, current: HostDocument): Contract<'browser.ActionResult'> {
  const stamp = inspection.authority.capture(execution.stamp.target, execution.stamp.attachment.id, execution.stamp.generation, true);
  if (stamp.document !== current || !execution.action) throw staleSnapshot();
  return { tab: stamp.target.id, action: execution.action, status: 'completed', controlGeneration: stamp.generation,
    navigation: current.navigation, pageAvailability: current.availability, inputReady: current.ready };
}
