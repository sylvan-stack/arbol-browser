import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, type ErrorCode } from '../contracts/errors.js';
import { TabAuthority, type AuthorityStamp, type DocumentReceipt, type Invalidation, type NavigationContinuation } from './authority.js';
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
  readonly command: number;
}
export interface ActionExecution {
  readonly action: string | undefined;
  readonly stamp: AuthorityStamp;
  readonly signal: AbortSignal;
  readonly deadline: number;
  readonly command: number;
  readonly navigation: NavigationContinuation | undefined;
  /** Every actual engine command is admitted here immediately before issue. */
  dispatch<T>(command: () => Promise<T>): Promise<T>;
  beginSequence(sequence: Sequence): void;
  settle(proof: OperationSettlement): void;
}
export interface ActionCompletion<T> { readonly value: T; readonly action?: string; readonly stamp: AuthorityStamp }
interface Task {
  stamp: AuthorityStamp; request: string; operation: string; mutation: boolean; screenshot: boolean; snapshot?: string;
  action?: string; controller: AbortController; deadline: number;
  dispatched: boolean; settled: boolean; retired: boolean; started: boolean; workDone: boolean; countedRead: boolean;
  resultStamp?: AuthorityStamp;
  navigation?: NavigationContinuation;
  command: number; terminal: boolean;
  sequences: Set<Sequence>; issued: Set<Promise<void>>; safe: Promise<void>; safeResolve(): void;
  start(): void; reject(error: unknown): void; cleanup(): void;
}
interface Slot { active?: Task; waiting: Task[] }
interface Preparation {
  target: TabTarget; generation: number; controller: AbortController; completion: Promise<void>; retired: boolean;
}
export interface IssuedNavigation {
  readonly token: NavigationContinuation;
  readonly command: number;
  readonly operation: string;
  assertCurrent(): void;
}
const issuedExecutions = new WeakMap<ActionExecution, (authority: TabAuthority) => IssuedNavigation>();
/** Private host adapter proof of an actual ActionQueue-issued command. */
export function issuedNavigation(execution: ActionExecution, authority: TabAuthority): IssuedNavigation {
  const current = issuedExecutions.get(execution);
  if (!current) throw refused('control_refused'); return current(authority);
}
/** One profile-wide owner for real mutation queues and original issued work. */
export class ActionQueue implements HandoffOperations {
  private readonly slots = new Map<TabTarget, Slot>();
  private readonly tasks = new Set<Task>();
  private readonly interrupted = new WeakMap<TabTarget, Task | undefined>();
  private readonly preparations = new Set<Preparation>();
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
    if (task.terminal || task.retired || task.controller.signal.aborted || performance.now() >= task.deadline) throw this.failure(task, 'control_refused');
    if (task.mutation) this.authority.requireSnapshot(task.snapshot!, task.stamp);
  }
  private safe(task: Task): void {
    if (task.retired || (task.workDone && task.issued.size === 0 && task.sequences.size === 0 && (!task.dispatched || !task.mutation || task.settled))) {
      task.safeResolve(); this.tasks.delete(task);
    }
  }
  run<T>(stamp: AuthorityStamp, operation: string, options: { request: string; mutation: boolean; screenshot?: boolean; snapshot?: string;
    deadline: number; signal: AbortSignal }, work: (execution: ActionExecution) => Promise<T>): Promise<ActionCompletion<T>> {
    this.authority.check(stamp, options.mutation);
    if ([...this.tasks].some(task => task.stamp.attachment === stamp.attachment && task.request === options.request))
      throw refused('control_refused');
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
    const task: Task = { stamp, request: options.request, operation, mutation: options.mutation, screenshot: options.screenshot ?? false,
      ...(options.snapshot ? { snapshot: options.snapshot } : {}), ...(options.mutation ? { action: this.authority.opaque('act') } : {}),
      controller: new AbortController(), deadline: options.deadline, dispatched: false, settled: false, retired: false,
      started: false, workDone: false, countedRead: false, command: 0, terminal: false,
      sequences: new Set(), issued: new Set(), safe, safeResolve, reject,
      cleanup: () => options.signal.removeEventListener('abort', abort),
      start: () => { void execute(); } };
    this.tasks.add(task);
    const abort = () => this.cancelTask(task, 'control_refused');
    options.signal.addEventListener('abort', abort, { once: true });
    const execution: ActionExecution = Object.freeze({ action: task.action, stamp, signal: task.controller.signal, deadline: task.deadline,
      get command() { return task.command; }, get navigation() { return task.navigation; },
      dispatch: <U>(command: () => Promise<U>): Promise<U> => {
        this.check(task);
        if (task.command >= Number.MAX_SAFE_INTEGER) return this.authority.exhausted();
        ++task.command;
        if (task.mutation && !task.navigation) task.navigation = this.authority.beginContinuation(stamp, task.action!, operation);
        // Publish an issued slot before the command can synchronously reenter.
        let issuedResolve!: () => void;
        const issued = new Promise<void>(yes => { issuedResolve = yes; }); task.issued.add(issued); task.dispatched = true;
        let promise: Promise<U>;
        try {
          if (task.navigation) this.authority.issuedNavigation(task.navigation, task.command);
          promise = Promise.resolve(command());
        }
        catch (error) { promise = Promise.reject(error); }
        return promise.finally(() => { task.issued.delete(issued); issuedResolve(); this.safe(task); });
      },
      beginSequence: (sequence: Sequence) => { this.check(task); if (!task.mutation || task.sequences.has(sequence)) throw this.failure(task);
        task.sequences.add(sequence); },
      settle: (proof: OperationSettlement) => {
        if (!task.mutation || task.terminal || !task.started || task.workDone || task.retired) throw this.failure(task, 'control_refused');
        task.terminal = true;
        if (!task.dispatched ||
            !task.navigation || task.issued.size !== 0 || proof.action !== task.action || proof.command !== task.command ||
            task.command < 1 || performance.now() >= task.deadline || proof.operation !== operation ||
            proof.original !== stamp.document || !proof.delivered || !proof.quiescent)
          throw this.failure(task, 'control_refused');
        // Terminal before providers can reenter; failed/late proof never sets
        // settled and can neither issue more input nor retry this attestation.
        const current = this.authority.settleContinuation(task.navigation, proof.original, proof.current);
        if (performance.now() >= task.deadline || task.retired) throw this.failure(task, 'control_refused');
        if (current) task.resultStamp = current;
        task.settled = true; task.sequences.clear();
        this.safe(task);
      },
    });
    issuedExecutions.set(execution, authority => {
      if (authority !== this.authority || !task.navigation || !task.started || task.terminal || task.retired ||
          task.workDone || task.issued.size !== 1 || task.controller.signal.aborted || performance.now() >= task.deadline)
        throw this.failure(task, 'control_refused');
      const token = task.navigation, command = task.command;
      const assertCurrent = () => {
        if (task.retired || task.terminal || task.workDone || task.controller.signal.aborted ||
            task.command !== command || task.issued.size !== 1 || performance.now() >= task.deadline) throw this.failure(task);
        authority.assertNavigationCommand(token, command);
      };
      assertCurrent(); return Object.freeze({ token, command, operation: task.operation, assertCurrent });
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
        (event.recipient === undefined || task.stamp.attachment.id === event.recipient)) {
      // Only the already-issued exact navigation keeps a result/settlement
      // continuation. Its raw dispatch remains fenced to the original stamp.
      if (event.continuation && task.navigation === event.continuation && task.started && task.dispatched && !task.terminal && !task.retired) continue;
      this.cancelTask(task, 'control_changed');
    }
    for (const preparation of this.preparations) if (preparation.target === event.target &&
        (this.authority.wasClosed(event.target) || this.authority.state(event.target).generation !== preparation.generation))
      preparation.controller.abort();
  }
  /** Real initial/readiness work is tracked even before a content stamp exists.
   * The document producer additionally fences its own physical epoch/job on
   * every continuation, including navigation it initiated itself. */
  prepare(target: TabTarget, generation: number, work: (signal: AbortSignal, assertCurrent: () => void) => Promise<void>): Promise<void> {
    this.authority.expected(target, generation);
    if ([...this.preparations].some(value => value.target === target)) throw refused('control_refused');
    let resolve!: () => void, reject!: (error: unknown) => void;
    const completion = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
    const preparation: Preparation = { target, generation, controller: new AbortController(), completion, retired: false };
    this.preparations.add(preparation);
    const assertCurrent = () => {
      this.authority.expected(target, generation);
      if (preparation.retired || preparation.controller.signal.aborted || !this.preparations.has(preparation) || target.page.retirement())
        throw refused('control_changed');
    };
    void (async () => { assertCurrent(); await work(preparation.controller.signal, assertCurrent); assertCurrent(); })()
      .then(resolve, reject).finally(() => { this.preparations.delete(preparation); }).catch(() => {});
    return completion;
  }
  status(recipient: string, request: string): Readonly<{ target: TabTarget; mutation: boolean; action?: string;
    dispatchOutcome: Contract<'browser.Outcome'> }> | undefined {
    const task = [...this.tasks].find(task => task.stamp.attachment.id === recipient && task.request === request);
    return task ? Object.freeze({ target: task.stamp.target, mutation: task.mutation,
      ...(task.action ? { action: task.action } : {}),
      dispatchOutcome: task.settled ? 'completed' : task.dispatched ? 'outcome_unknown' : 'not_dispatched' }) : undefined;
  }
  cancel(recipient: string, request: string): void {
    const task = [...this.tasks].find(task => task.stamp.attachment.id === recipient && task.request === request);
    if (task) this.cancelTask(task, 'control_refused');
  }
  stop(target: TabTarget): void {
    const current = [...this.tasks].find(task => task.stamp.target === target && task.mutation && task.dispatched);
    this.interrupted.set(target, current);
    this.invalidate({ target });
  }
  unsafe(target: TabTarget): boolean {
    return [...this.preparations].some(value => value.target === target && !value.retired) ||
      [...this.tasks].some(task => task.stamp.target === target && !task.retired &&
      (task.issued.size !== 0 || task.sequences.size !== 0 || (task.dispatched && task.mutation && !task.settled) || (task.started && !task.workDone)));
  }
  async drain(target: TabTarget, _deadline: number): Promise<Contract<'browser.SettledAction'> | undefined> {
    await Promise.all([...this.tasks].filter(task => task.stamp.target === target).map(task => task.safe).concat(
      [...this.preparations].filter(value => value.target === target).map(value => value.completion.catch(() => {}))));
    return this.outcome(target);
  }
  outcome(target: TabTarget): Contract<'browser.SettledAction'> | undefined {
    const task = this.interrupted.get(target);
    return task?.action ? { action: task.action, status: task.settled ? 'completed' : task.dispatched ? 'outcome_unknown' : 'not_dispatched' } : undefined;
  }
  retired(target: TabTarget): void {
    for (const task of [...this.tasks]) if (task.stamp.target === target) { task.retired = true; this.cancelTask(task, 'control_changed'); }
    this.slots.delete(target); this.interrupted.delete(target);
    for (const preparation of [...this.preparations]) if (preparation.target === target) {
      preparation.retired = true; this.preparations.delete(preparation); preparation.controller.abort();
    }
  }
}
