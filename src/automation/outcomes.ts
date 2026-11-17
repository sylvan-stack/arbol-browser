import type { Contract } from '../contracts/generated.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import { owningQueue, type ActionExecution } from '../host/actions.js';
import { staleSnapshot } from '../host/authority.js';

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
