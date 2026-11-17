import type { ActionExecution } from '../host/actions.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import type { OriginalNode } from '../content/references.js';
import type { InspectionFrame } from '../host/readiness.js';
import { staleSnapshot } from '../host/authority.js';

export interface ActionTarget extends OriginalNode {
  readonly execution: ActionExecution;
  readonly inspection: SnapshotInspection;
  readonly snapshot: string;
  readonly ref: string;
  guard(): void;
  revalidate(): Promise<void>;
}
/** Read preparation cannot allocate an issued command or a continuation. The
 * existing ownership host remains the only snapshot and mutation authority. */
export async function admitTarget(inspection: SnapshotInspection, execution: ActionExecution,
  input: { tab: string; controlGeneration: number; snapshot: string; ref: string }, editing = false): Promise<ActionTarget> {
  const check = inspection.guard(execution, true), stamp = execution.stamp;
  check();
  if (!execution.action || input.tab !== stamp.target.id || input.controlGeneration !== stamp.generation) throw staleSnapshot();
  inspection.authority.requireSnapshot(input.snapshot, stamp);
  const original = await inspection.resolve(input.snapshot, input.ref, execution, editing); check();
  const guard = () => {
    check(); inspection.authority.requireSnapshot(input.snapshot, stamp);
    inspection.readiness.assertInspection(original.frame, check);
    if (original.frame.receipt !== stamp.document || original.frame.receipt.page !== stamp.target.page) throw staleSnapshot();
  };
  guard();
  return Object.freeze({ ...original, execution, inspection, snapshot: input.snapshot, ref: input.ref, guard,
    async revalidate() {
      guard(); const current = await inspection.resolve(input.snapshot, input.ref, execution, editing); guard();
      if (current.backend !== original.backend || current.signature !== original.signature ||
          current.frame.receipt !== original.frame.receipt || current.frame.frameId !== original.frame.frameId ||
          current.frame.session !== original.frame.session || current.frame.physical !== original.frame.physical) throw staleSnapshot();
    } });
}

export interface InterceptionAcknowledgement {
  readonly action: string;
  readonly frame: InspectionFrame;
  assertCurrent(): void;
}
/** Every action obtains its own actual acknowledgement, including after Return.
 * It is retained through genuine queue drain/retirement; only PageReadiness's
 * existing guarded leaveAgentMode may disable interception. */
export async function interceptInput(target: ActionTarget): Promise<InterceptionAcknowledgement> {
  const { execution, frame, inspection } = target, stamp = execution.stamp;
  target.guard();
  const page = frame.receipt.page, channel = frame.receipt.channel, physical = frame.physical;
  const reply = await inspection.readiness.command(page, target.guard, 'Input.setInterceptDrags', { enabled: true }, frame.session);
  target.guard();
  if (!reply || typeof reply !== 'object' || Array.isArray(reply) || Object.keys(reply).length) throw staleSnapshot();
  return Object.freeze({ action: execution.action!, frame, assertCurrent() {
    target.guard();
    if (execution.stamp !== stamp || stamp.target.page !== page || frame.receipt.channel !== channel || frame.physical !== physical ||
        stamp.document !== frame.receipt || !execution.action) throw staleSnapshot();
  } });
}
