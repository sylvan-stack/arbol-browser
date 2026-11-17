import type { Contract } from '../contracts/generated.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import { owningQueue, type ActionExecution } from '../host/actions.js';
import { staleSnapshot } from '../host/authority.js';

const failed = new WeakSet<ActionExecution>();
/** This validates a result only AFTER operation-specific genuine settlement.
 * It never creates an action, receipt, navigation continuation or completion. */
export function settledResult(inspection: SnapshotInspection, execution: ActionExecution,
  result: Contract<'browser.ActionResult'>): Contract<'browser.ActionResult'> {
  const queue = owningQueue(execution);
  if (queue.authority !== inspection.authority) throw staleSnapshot();
  const stamp = queue.settledStamp(execution); inspection.authority.assertHealthy();
  inspection.documents.assertCurrent(stamp.target, stamp.document);
  if (!execution.action || result.action !== execution.action || result.tab !== stamp.target.id || result.status !== 'completed' ||
      result.controlGeneration !== stamp.generation || result.navigation !== stamp.document.navigation ||
      result.pageAvailability !== stamp.document.availability || result.inputReady !== stamp.document.ready ||
      result.openedTabs !== undefined) throw staleSnapshot();
  inspection.authority.check(stamp, true); return result;
}
/** One-shot failure contribution into the already bound real health/ownership
 * chain. Existing protected cancel/disconnect/Take/Close remain authoritative.
 * No fake up/drop/composition commit, second queue or successor-page cleanup. */
export function retireUnsettled(inspection: SnapshotInspection, execution: ActionExecution, request: string): void {
  if (failed.has(execution)) return;
  const queue = owningQueue(execution), stamp = execution.stamp;
  if (queue.authority !== inspection.authority) throw staleSnapshot();
  const state = queue.status(stamp.attachment.id, request);
  if (!state?.mutation || state.target !== stamp.target || state.action !== execution.action || state.dispatchOutcome !== 'outcome_unknown') return;
  failed.add(execution); inspection.authority.assertHealthy();
  const original = stamp.document.page;
  if (inspection.authority.wasClosed(stamp.target) || stamp.target.page !== original || original.retirement()) return;
  // HostDocuments validates the literal original PageSurface and its own
  // current record before invoking RendererHealth -> protected Handoff.
  inspection.documents.failPage(stamp.target, original, 'unavailable', 'action_settlement_unavailable');
}
