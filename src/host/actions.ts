import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, type ErrorCode } from '../contracts/errors.js';
import { TabAuthority, type AuthorityStamp, type DocumentReceipt, type Invalidation } from './authority.js';
import type { HandoffOperations } from './handoff.js';
import { refused, type TabTarget } from './tabs.js';

export type Sequence = 'pointer' | 'drag' | 'composition' | 'key' | 'wheel';
/** A real operation-specific settlement producer must supply these observations.
 * It must prove trusted delivery and balanced sequences (including scroll/drop
 * presentation settlement); command acknowledgement alone cannot produce this. */
export interface OperationSettlement {
  readonly action: string;
  readonly operation: string;
  readonly original: DocumentReceipt;
  readonly current: DocumentReceipt;
  readonly delivered: true;
  readonly quiescent: true;
}
export interface ActionExecution {
  readonly action: string | undefined;
  readonly stamp: AuthorityStamp;
  readonly signal: AbortSignal;
  readonly deadline: number;
  /** Every actual engine command is admitted here immediately before issue. */
  dispatch<T>(command: () => Promise<T>): Promise<T>;
  beginSequence(sequence: Sequence): void;
  settle(proof: OperationSettlement): void;
}
export interface ActionCompletion<T> { readonly value: T; readonly action?: string; readonly stamp: AuthorityStamp }
interface Task {
  stamp: AuthorityStamp; operation: string; mutation: boolean; screenshot: boolean; snapshot?: string;
  action?: string; controller: AbortController; deadline: number;
  dispatched: boolean; settled: boolean; retired: boolean; started: boolean; workDone: boolean; countedRead: boolean;
  resultStamp?: AuthorityStamp;
  sequences: Set<Sequence>; issued: Set<Promise<void>>; safe: Promise<void>; safeResolve(): void;
  start(): void; reject(error: unknown): void; cleanup(): void;
}
interface Slot { active?: Task; waiting: Task[] }
/** One profile-wide owner for real mutation queues and original issued work. */
export class ActionQueue implements HandoffOperations {
  private readonly slots = new Map<TabTarget, Slot>();
  private readonly tasks = new Set<Task>();
  private readonly interrupted = new Map<TabTarget, Task | undefined>();
  private reads = 0;
  private screenshots = 0;
  constructor(readonly authority: TabAuthority,
    readonly leaveAgentMode: HandoffOperations['leaveAgentMode']) {
    authority.onInvalidate(event => this.invalidate(event));
  }
  private failure(task: Task, code: ErrorCode = 'control_changed'): BrowserFailure {
    return new BrowserFailure({ code, message: 'The browser operation cannot complete under its original authority.', retryable: true,
      remedy: 'Inspect fresh browser state before deciding on another action.',
      ...(task.action ? { action: task.action, dispatchOutcome: task.settled ? 'completed' : task.dispatched ? 'outcome_unknown' : 'not_dispatched' } : {}) });
  }
  private check(task: Task): void {
    this.authority.check(task.stamp, task.mutation);
    if (task.retired || task.controller.signal.aborted || performance.now() >= task.deadline) throw this.failure(task, 'control_refused');
    if (task.mutation) this.authority.requireSnapshot(task.snapshot!, task.stamp);
  }
  private safe(task: Task): void {
    if (task.retired || (task.workDone && task.issued.size === 0 && task.sequences.size === 0 && (!task.dispatched || !task.mutation || task.settled))) {
      task.safeResolve(); this.tasks.delete(task);
    }
  }
  run<T>(stamp: AuthorityStamp, operation: string, options: { mutation: boolean; screenshot?: boolean; snapshot?: string;
    deadline: number; signal: AbortSignal }, work: (execution: ActionExecution) => Promise<T>): Promise<ActionCompletion<T>> {
    this.authority.check(stamp, options.mutation);
    if (options.mutation) {
      if (!options.snapshot) throw refused('control_refused'); this.authority.requireSnapshot(options.snapshot, stamp);
    } else if (this.reads >= 4 || (options.screenshot && this.screenshots >= 1)) throw refused('control_refused');
    if (options.signal.aborted || performance.now() >= options.deadline) throw refused('control_refused');
    let slot = this.slots.get(stamp.target);
    if (options.mutation && slot?.active && slot.waiting.length >= 4) throw refused('control_refused');
    if (options.mutation && !slot) { slot = { waiting: [] }; this.slots.set(stamp.target, slot); }
    let resolve!: (result: ActionCompletion<T>) => void, reject!: (error: unknown) => void, safeResolve!: () => void;
    const result = new Promise<ActionCompletion<T>>((yes, no) => { resolve = yes; reject = no; });
    const safe = new Promise<void>(yes => { safeResolve = yes; });
    const task: Task = { stamp, operation, mutation: options.mutation, screenshot: options.screenshot ?? false,
      ...(options.snapshot ? { snapshot: options.snapshot } : {}), ...(options.mutation ? { action: this.authority.opaque('act') } : {}),
      controller: new AbortController(), deadline: options.deadline, dispatched: false, settled: false, retired: false,
      started: false, workDone: false, countedRead: false, sequences: new Set(), issued: new Set(), safe, safeResolve, reject,
      cleanup: () => options.signal.removeEventListener('abort', abort),
      start: () => { void execute(); } };
    this.tasks.add(task);
    const abort = () => this.cancelTask(task, 'control_refused');
    options.signal.addEventListener('abort', abort, { once: true });
    const execution: ActionExecution = Object.freeze({ action: task.action, stamp, signal: task.controller.signal, deadline: task.deadline,
      dispatch: <U>(command: () => Promise<U>): Promise<U> => {
        this.check(task);
        // Publish an issued slot before the command can synchronously reenter.
        let issuedResolve!: () => void;
        const issued = new Promise<void>(yes => { issuedResolve = yes; }); task.issued.add(issued); task.dispatched = true;
        let promise: Promise<U>;
        try { promise = Promise.resolve(command()); }
        catch (error) { promise = Promise.reject(error); }
        return promise.finally(() => { task.issued.delete(issued); issuedResolve(); this.safe(task); });
      },
      beginSequence: (sequence: Sequence) => { this.check(task); if (!task.mutation || task.sequences.has(sequence)) throw this.failure(task);
        task.sequences.add(sequence); },
      settle: (proof: OperationSettlement) => {
        if (!task.mutation || task.retired || !task.dispatched || task.issued.size !== 0 || proof.action !== task.action ||
            proof.operation !== operation || proof.original !== stamp.document || !proof.delivered || !proof.quiescent)
          throw this.failure(task, 'control_refused');
        this.authority.assertHealthy(); this.authority.documents.assertCurrent(stamp.target, proof.current);
        task.settled = true; task.sequences.clear();
        // Navigation may legitimately replace the original document. It cannot
        // replace recipient/grant/generation authority; no old action is issued
        // against the new document by this context.
        try {
          const current = this.authority.capture(stamp.target, stamp.attachment.id, stamp.generation, true);
          if (current.attachment !== stamp.attachment || current.recipientEpoch !== stamp.recipientEpoch || current.document !== proof.current)
            throw this.failure(task);
          task.resultStamp = current;
        } catch { /* Genuine old work may settle during private Take; no result lease. */ }
        this.safe(task);
      },
    });
    const execute = async () => {
      task.started = true;
      try {
        this.check(task);
        if (!task.mutation) { task.countedRead = true; ++this.reads; if (task.screenshot) ++this.screenshots; }
        const value = await work(execution);
        if (task.mutation && (!task.settled || task.issued.size || task.sequences.size)) throw this.failure(task, 'control_refused');
        const finalStamp = task.resultStamp ?? stamp; this.authority.check(finalStamp, task.mutation);
        if (task.controller.signal.aborted || task.retired || performance.now() >= task.deadline) throw this.failure(task, 'control_refused');
        resolve({ value, stamp: finalStamp, ...(task.action ? { action: task.action } : {}) });
      } catch (error) {
        const code = error instanceof BrowserFailure ? error.detail.code : 'internal'; reject(this.failure(task, code));
      } finally {
        task.workDone = true; task.cleanup(); this.safe(task);
        if (!task.mutation) { if (task.countedRead) { --this.reads; if (task.screenshot) --this.screenshots; } }
        else {
          const current = this.slots.get(stamp.target);
          if (current?.active === task) {
            // Unsafe orphaned continuations keep the slot occupied until actual
            // settlement/retirement; never dispatch a successor on wrapper exit.
            void task.safe.then(() => {
              if (current.active !== task) return;
              delete current.active; const next = current.waiting.shift();
              if (next) { current.active = next; next.start(); }
              else this.slots.delete(stamp.target);
            });
          }
        }
      }
    };
    if (task.mutation) { if (slot!.active) slot!.waiting.push(task); else { slot!.active = task; task.start(); } }
    else task.start();
    return result;
  }
  private cancelTask(task: Task, code: ErrorCode): void {
    const error = this.failure(task, code);
    if (!task.started) {
      const waiting = this.slots.get(task.stamp.target)?.waiting;
      const index = waiting?.indexOf(task) ?? -1; if (index >= 0) waiting!.splice(index, 1);
      task.workDone = true;
      task.cleanup();
    }
    // Reject/close authority before abort listeners can reenter engine providers.
    task.reject(error); task.controller.abort(); this.safe(task);
  }
  private invalidate(event: Invalidation): void {
    for (const task of [...this.tasks]) if (task.stamp.target === event.target &&
        (event.recipient === undefined || task.stamp.attachment.id === event.recipient)) this.cancelTask(task, 'control_changed');
  }
  stop(target: TabTarget): void {
    const current = [...this.tasks].find(task => task.stamp.target === target && task.mutation && task.dispatched);
    this.interrupted.set(target, current);
    this.invalidate({ target });
  }
  unsafe(target: TabTarget): boolean {
    return [...this.tasks].some(task => task.stamp.target === target && !task.retired &&
      (task.issued.size !== 0 || task.sequences.size !== 0 || (task.dispatched && task.mutation && !task.settled) || (task.started && !task.workDone)));
  }
  async drain(target: TabTarget, _deadline: number): Promise<Contract<'browser.SettledAction'> | undefined> {
    await Promise.all([...this.tasks].filter(task => task.stamp.target === target).map(task => task.safe));
    return this.outcome(target);
  }
  outcome(target: TabTarget): Contract<'browser.SettledAction'> | undefined {
    const task = this.interrupted.get(target);
    return task?.action ? { action: task.action, status: task.settled ? 'completed' : task.dispatched ? 'outcome_unknown' : 'not_dispatched' } : undefined;
  }
  retired(target: TabTarget): void {
    for (const task of [...this.tasks]) if (task.stamp.target === target) { task.retired = true; this.cancelTask(task, 'control_changed'); }
    this.slots.delete(target); this.interrupted.delete(target);
  }
}
