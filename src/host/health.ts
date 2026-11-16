import { performance } from 'node:perf_hooks';
import { BrowserFailure } from '../contracts/errors.js';
import { TabAuthority, staleSnapshot } from './authority.js';
import type { DocumentEvent, DocumentFault, HostDocument, HostDocuments } from './documents.js';
import type { PageReadiness } from './readiness.js';
import type { PageSurface } from './windows.js';
import { refused, type TabTarget } from './tabs.js';

export type HealthPhase = 'loading' | 'ready' | 'recovering' | 'unresponsive' | 'crashed' | 'unavailable' | 'closed';
export interface FailureObservation {
  readonly availability: DocumentFault['availability']; readonly reason: string; readonly at: number;
}
export interface RecoveryError { readonly reason: string; readonly at: number }
export interface HealthStatus {
  readonly phase: HealthPhase;
  readonly originalFailure?: FailureObservation;
  readonly currentFailure?: FailureObservation;
  readonly recoveryError?: RecoveryError;
  readonly failures: readonly FailureObservation[];
  readonly recoveryErrors: readonly RecoveryError[];
  readonly intentionalTerminations: readonly RecoveryError[];
  readonly affectedTabs: readonly string[];
}
export interface RecoveryAttempt {
  readonly target: TabTarget; readonly original: PageSurface; readonly generation: number;
}
interface AttemptState { record: HealthRecord; active: boolean; stopping: boolean; affected: Set<string> }
interface Heartbeat {
  readonly receipt: HostDocument; readonly page: PageSurface; readonly revision: number; readonly deadline: number;
  active: boolean; timer?: ReturnType<typeof setTimeout>;
}
interface HealthRecord {
  target: TabTarget; page: PageSurface; phase: HealthPhase; revision: number; receipt?: HostDocument;
  interval: ReturnType<typeof setInterval>; pending?: Heartbeat; attempt?: RecoveryAttempt;
  original?: FailureObservation; fault?: FailureObservation; recoveryError?: RecoveryError;
  failures: FailureObservation[]; recoveryErrors: RecoveryError[]; intentional: RecoveryError[]; affected: Set<string>;
}
/** Host health runs in user/private mode too. No controller, load event,
 * responsive label or new document can clear its latched fault. */
export class RendererHealth {
  private readonly records = new Map<TabTarget, HealthRecord>();
  private readonly attempts = new WeakMap<RecoveryAttempt, AttemptState>();
  private readonly unsubscribe: () => void;
  private closed = false;
  constructor(readonly documents: HostDocuments, readonly readiness: PageReadiness, readonly owner: TabAuthority,
    readonly release: (fault: DocumentFault) => Promise<void>) {
    if (owner.documents !== documents || readiness.documents !== documents) throw refused('control_refused');
    this.unsubscribe = documents.subscribe(event => this.event(event));
  }
  private increment(record: HealthRecord): void {
    if (record.revision >= Number.MAX_SAFE_INTEGER) return this.owner.exhausted(); record.revision++;
  }
  private record(target: TabTarget, page: PageSurface): HealthRecord {
    let record = this.records.get(target);
    if (!record) {
      record = { target, page, phase: 'loading', revision: 1,
        interval: setInterval(() => { if (record) this.pulse(record); }, 500),
        failures: [], recoveryErrors: [], intentional: [], affected: new Set() };
      this.records.set(target, record);
    }
    return record;
  }
  private cancelHeartbeat(record: HealthRecord): void {
    const pending = record.pending;
    if (!pending) return;
    pending.active = false; delete record.pending; if (pending.timer) clearTimeout(pending.timer);
  }
  private event(event: DocumentEvent): void {
    if (this.closed || this.owner.wasClosed(event.target)) {
      const record = this.records.get(event.target); if (record) this.close(record); return;
    }
    const record = this.record(event.target, event.page);
    // A retired old producer cannot overwrite the fresh logical binding.
    if (event.target.page !== event.page) return;
    if (record.page !== event.page) { record.page = event.page; this.increment(record); }
    if (event.kind === 'suspect') { this.pulse(record); return; }
    this.increment(record);
    if (event.receipt) record.receipt = event.receipt;
    record.phase = record.attempt ? 'recovering' : record.fault?.availability ??
      (event.kind === 'closed' ? 'unavailable' : event.kind === 'ready' && event.receipt?.ready ? 'ready' : 'loading');
    // Keep one actual pending heartbeat through a supersession until its
    // response/deadline, so navigation never creates a second pending challenge.
  }
  private current(record: HealthRecord, pending: Heartbeat): boolean {
    if (this.closed || !pending.active || record.pending !== pending || record.phase !== 'ready' || record.attempt ||
        record.revision !== pending.revision || record.page !== pending.page || record.target.page !== pending.page ||
        record.receipt !== pending.receipt || this.owner.wasClosed(record.target)) return false;
    try { return this.documents.current(record.target) === pending.receipt && pending.receipt.ready && pending.receipt.availability === 'ready'; }
    catch { this.owner.assertHealthy(); return false; }
  }
  private pulse(record: HealthRecord): void {
    if (this.closed || record.phase !== 'ready' || record.pending || record.attempt || !record.receipt || this.owner.wasClosed(record.target)) return;
    const pending: Heartbeat = { receipt: record.receipt, page: record.page, revision: record.revision,
      deadline: performance.now() + 1000, active: true };
    record.pending = pending;
    const expire = (reason: string) => {
      const current = this.current(record, pending);
      pending.active = false; if (record.pending === pending) delete record.pending; if (pending.timer) clearTimeout(pending.timer);
      if (current) this.documents.failPage(record.target, pending.page, 'unresponsive', reason);
    };
    const guard = () => {
      this.owner.assertHealthy();
      if (!this.current(record, pending) || performance.now() >= pending.deadline) throw staleSnapshot();
    };
    pending.timer = setTimeout(() => expire('heartbeat_timeout'), 1000);
    void this.readiness.ping(pending.receipt, guard).then(() => {
      if (performance.now() >= pending.deadline) { expire('heartbeat_timeout'); return; }
      // Stale phase/channel/receipt success has no current-health effect.
      pending.active = false; if (record.pending === pending) delete record.pending; if (pending.timer) clearTimeout(pending.timer);
    }, error => {
      if (performance.now() >= pending.deadline) { expire('heartbeat_timeout'); return; }
      if (error instanceof BrowserFailure) {
        // An actual guard refused a superseded job, not a failed renderer reply.
        pending.active = false; if (record.pending === pending) delete record.pending; if (pending.timer) clearTimeout(pending.timer);
        this.owner.assertHealthy(); return;
      }
      expire('heartbeat_failed');
    }).catch(() => this.owner.exhausted());
  }
  /** Called synchronously by the genuine document producer after poisoning its
   * receipt, including when no current renderer/frame remains accessible. */
  failed(fault: DocumentFault): void {
    if (this.closed || this.owner.wasClosed(fault.target)) return;
    this.documents.assertFault(fault.target, fault);
    const record = this.record(fault.target, fault.page), attempt = record.attempt && this.attempts.get(record.attempt);
    this.cancelHeartbeat(record); this.increment(record);
    if (attempt?.active && attempt.stopping && record.attempt?.original === fault.page) {
      record.intentional.push(Object.freeze({ reason: fault.reason, at: performance.now() }));
      record.phase = 'recovering'; return; // original fault remains separate from intentional stop
    }
    const observed = Object.freeze({ availability: fault.availability, reason: fault.reason, at: performance.now() });
    record.failures.push(observed); record.original ??= observed;
    if (record.fault?.availability !== 'crashed' || observed.availability === 'crashed') record.fault = observed;
    record.phase = record.attempt ? 'recovering' : record.fault.availability;
    // The actual owner closes visibility/input and begins its real bounded
    // release before this method returns. A label-only callback is not enough.
    const released = this.release(fault);
    if (!this.owner.wasClosed(fault.target)) {
      const state = this.owner.state(fault.target);
      if (state.controller.kind !== 'user' || state.inputReady) return this.owner.exhausted();
    }
    void released.catch(() => {
      if (!this.owner.wasClosed(fault.target) && fault.target.page === fault.page && !record.attempt) return this.owner.exhausted();
    }).catch(() => {});
  }
  status(target: TabTarget): HealthStatus {
    const record = this.records.get(target);
    if (!record) throw refused('tab_not_found');
    return Object.freeze({ phase: record.phase, ...(record.original ? { originalFailure: record.original } : {}),
      ...(record.fault ? { currentFailure: record.fault } : {}), ...(record.recoveryError ? { recoveryError: record.recoveryError } : {}),
      failures: Object.freeze([...record.failures]), recoveryErrors: Object.freeze([...record.recoveryErrors]),
      intentionalTerminations: Object.freeze([...record.intentional]), affectedTabs: Object.freeze([...record.affected]) });
  }
  recovering(target: TabTarget): boolean { return Boolean(this.records.get(target)?.attempt); }
  beginRecovery(target: TabTarget, original: PageSurface, generation: number): RecoveryAttempt {
    if (this.closed || this.owner.wasClosed(target)) throw refused('control_changed');
    const state = this.owner.expected(target, generation), record = this.record(target, original);
    if (record.attempt || state.controller.kind !== 'user' || state.handoff !== 'idle' || state.inputReady || target.page !== original)
      throw refused('control_refused');
    const attempt = Object.freeze({ target, original, generation });
    this.attempts.set(attempt, { record, active: true, stopping: false, affected: new Set() });
    record.attempt = attempt; record.phase = 'recovering'; this.cancelHeartbeat(record); this.increment(record); return attempt;
  }
  assertAttempt(attempt: RecoveryAttempt): void {
    const value = this.attempts.get(attempt);
    if (!value?.active || value.record.attempt !== attempt || this.closed || this.owner.wasClosed(attempt.target)) throw staleSnapshot();
    const state = this.owner.expected(attempt.target, attempt.generation);
    if (state.controller.kind !== 'user' || state.handoff !== 'idle') throw staleSnapshot();
  }
  stopping(attempt: RecoveryAttempt): void { this.assertAttempt(attempt); this.attempts.get(attempt)!.stopping = true; }
  replaced(attempt: RecoveryAttempt, page: PageSurface): void {
    this.assertAttempt(attempt);
    if (attempt.target.page !== page || page === attempt.original || page.session !== attempt.original.session) throw staleSnapshot();
    const value = this.attempts.get(attempt)!; value.stopping = false; value.record.page = page; this.increment(value.record);
  }
  affected(attempt: RecoveryAttempt, target: TabTarget, fault: DocumentFault): void {
    this.assertAttempt(attempt); this.documents.assertFault(target, fault);
    if (target === attempt.target || target.page !== fault.page) return;
    const value = this.attempts.get(attempt)!; value.affected.add(target.id); value.record.affected.add(target.id);
  }
  affectedTabs(attempt: RecoveryAttempt): readonly string[] {
    const value = this.attempts.get(attempt); if (!value) throw staleSnapshot(); return Object.freeze([...value.affected]);
  }
  completeRecovery(attempt: RecoveryAttempt, receipt: HostDocument): void {
    this.assertAttempt(attempt); this.documents.assertCurrent(attempt.target, receipt);
    const value = this.attempts.get(attempt)!, state = this.owner.state(attempt.target);
    if (receipt.page === attempt.original || receipt.page !== attempt.target.page || !receipt.ready || receipt.availability !== 'ready' ||
        !state.inputReady || state.controller.kind !== 'user' || state.pageAvailability !== 'ready' || receipt.page.binding().blocked)
      throw staleSnapshot();
    value.active = false; delete value.record.attempt; delete value.record.fault; delete value.record.recoveryError;
    value.record.receipt = receipt; value.record.phase = 'ready'; this.increment(value.record);
  }
  failRecovery(attempt: RecoveryAttempt, reason: string): void {
    const value = this.attempts.get(attempt);
    if (!value?.active || value.record.attempt !== attempt) return;
    value.active = false; delete value.record.attempt;
    const error = Object.freeze({ reason, at: performance.now() }); value.record.recoveryError = error; value.record.recoveryErrors.push(error);
    value.record.phase = this.owner.wasClosed(attempt.target) ? 'closed' : value.record.fault?.availability ?? 'unavailable';
    this.increment(value.record);
  }
  private close(record: HealthRecord): void {
    record.phase = 'closed'; this.cancelHeartbeat(record); clearInterval(record.interval); this.increment(record);
    if (record.attempt) { const attempt = this.attempts.get(record.attempt); if (attempt) attempt.active = false; delete record.attempt; }
    if (this.records.get(record.target) === record) this.records.delete(record.target);
  }
  closeAll(): void {
    if (this.closed) return; this.closed = true; this.unsubscribe(); for (const record of this.records.values()) this.close(record);
  }
}
