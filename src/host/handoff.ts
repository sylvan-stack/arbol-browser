import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { bindingKey } from '../native/retirement.js';
import { TabAuthority, type DocumentReceipt } from './authority.js';
import { refused, type TabState, type TabTarget } from './tabs.js';
import { assertPageRetirement } from './windows.js';

export interface HandoffResult { readonly state: TabState; readonly settledAction?: Contract<'browser.SettledAction'> }
/** Actual admitted engine work and unfinished sequence tracking, supplied by
 * the action owner. A resolved CDP call is never a balanced-sequence receipt. */
export interface HandoffOperations {
  stop(target: TabTarget): void;
  drain(target: TabTarget, deadline: number): Promise<Contract<'browser.SettledAction'> | undefined>;
  unsafe(target: TabTarget): boolean;
  outcome(target: TabTarget): Contract<'browser.SettledAction'> | undefined;
  /** Disable agent drag interception only after genuine command/sequence drain. */
  leaveAgentMode(target: TabTarget, document: DocumentReceipt, deadline: number): Promise<void>;
  retired(target: TabTarget): void;
}
interface PendingTake { expected: number; promise: Promise<HandoffResult> }
/** A local wait expiring says nothing about the original operation's safety. */
export async function bounded<T>(deadline: number, work: () => Promise<T>): Promise<T> {
  if (performance.now() >= deadline) throw refused('control_refused');
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([work(), new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(refused('control_refused')), Math.max(1, deadline - performance.now()));
    })]);
    if (performance.now() >= deadline) throw refused('control_refused'); return result;
  } finally { if (timer) clearTimeout(timer); }
}
/** The one host Take path. No default operation, native or readiness provider. */
export class HandoffController {
  private readonly pending = new Map<TabTarget, PendingTake>();
  constructor(readonly authority: TabAuthority, readonly operations: HandoffOperations,
    readonly selected: (target: TabTarget) => boolean) {}
  private synchronous(operation: () => void): void {
    try { const result: unknown = operation(); if (result !== undefined) return this.authority.exhausted(); }
    catch { return this.authority.exhausted(); }
  }
  /** Exact full native acknowledgement; all failures retain the real fatal path. */
  private mark(target: TabTarget, blocked: boolean): void {
    target.page.window.guardRetirementTransition(() => {
      const before = target.page.binding(), after = target.page.setNativeBlocked(blocked);
      if (before.retired || after.retired || after.id !== before.id || after.nonce !== before.nonce ||
          after.webContentsId !== before.webContentsId || after.webContentsId !== target.page.view.webContents.id ||
          after.revision !== before.revision + 1 || after.blocked !== blocked) return this.authority.exhausted();
    });
  }
  private async superseded(target: TabTarget): Promise<never> {
    const receipt = target.page.retirement();
    try {
      if (!this.authority.wasClosed(target) || !receipt) return this.authority.exhausted();
      assertPageRetirement(target.page, receipt);
      await bounded(performance.now() + 1000, () => receipt.completion);
      assertPageRetirement(target.page, receipt);
      if (receipt.phase !== 'retired') return this.authority.exhausted();
      this.synchronous(() => this.operations.retired(target));
    } catch { return this.authority.exhausted(); }
    // This is genuine same-original Close, not a successful old Take reply.
    throw refused('control_changed');
  }
  take(target: TabTarget, expected: number): Promise<HandoffResult> {
    this.authority.assertAdmission();
    if (this.authority.wasClosed(target)) throw refused('tab_not_found');
    const existing = this.pending.get(target);
    if (existing) {
      if (expected !== existing.expected && expected !== existing.expected + 1) throw refused('control_changed');
      return existing.promise;
    }
    const before = this.authority.expected(target, expected);
    if (before.controller.kind !== 'agent' || before.handoff !== 'idle') throw refused('control_refused');
    let resolve!: (value: HandoffResult) => void, reject!: (error: unknown) => void;
    const promise = new Promise<HandoffResult>((yes, no) => { resolve = yes; reject = no; });
    // Record before invalidators, native calls or state publication can reenter.
    this.pending.set(target, { expected, promise });
    try {
      this.authority.beginTake(target, expected);
      this.synchronous(() => this.operations.stop(target));
      if (!this.authority.wasClosed(target)) this.mark(target, true);
      this.authority.changed();
      void this.finish(target, performance.now() + 1000).then(resolve, reject).finally(() => {
        if (this.pending.get(target)?.promise === promise) this.pending.delete(target);
      }).catch(() => {});
    } catch (error) { this.pending.delete(target); reject(error); }
    return promise;
  }
  private async finish(target: TabTarget, deadline: number): Promise<HandoffResult> {
    let settledAction: Contract<'browser.SettledAction'> | undefined;
    let readyDocument: DocumentReceipt | undefined;
    try {
      settledAction = await bounded(deadline, () => this.operations.drain(target, deadline));
      if (!this.authority.wasClosed(target) && !this.operations.unsafe(target) && !target.page.retirement()) {
        const document = this.authority.document(target);
        await bounded(deadline, () => this.operations.leaveAgentMode(target, document, deadline));
        this.authority.documents.assertCurrent(target, document);
        if (!this.operations.unsafe(target) && this.authority.document(target) === document) readyDocument = document;
      }
    } catch { this.authority.assertHealthy(); }
    if (this.authority.wasClosed(target)) return this.superseded(target);
    this.authority.assertAdmission();
    if (readyDocument && !this.operations.unsafe(target) && !target.page.retirement()) {
      this.authority.documents.assertCurrent(target, readyDocument);
      this.mark(target, false);
      this.authority.finishTake(target, true, false);
    } else {
      const known = this.operations.outcome(target);
      if (known) settledAction = { action: known.action, status: known.status === 'not_dispatched' ? 'not_dispatched' : 'outcome_unknown' };
      try {
        await bounded(performance.now() + 1000, () => target.page.retire());
        const receipt = target.page.retirement();
        if (!receipt) return this.authority.exhausted();
        assertPageRetirement(target.page, receipt);
        if (receipt.phase !== 'retired') return this.authority.exhausted();
        this.synchronous(() => this.operations.retired(target));
      } catch { return this.authority.exhausted(); }
      if (this.authority.wasClosed(target)) return this.superseded(target);
      this.authority.finishTake(target, false, true);
    }
    this.authority.changed();
    if (this.authority.wasClosed(target)) return this.superseded(target);
    return { state: this.authority.state(target), ...(settledAction ? { settledAction } : {}) };
  }
  release(target: TabTarget, recipient: string, expected: number): Promise<HandoffResult> {
    this.authority.owner(target, recipient, expected); return this.take(target, expected);
  }
  /** Entire native check/mark/controller commit executes without yielding to an
   * OS input event. Refused busy interaction stays intact and is never queued. */
  returnControl(target: TabTarget, recipient: string, expected: number): HandoffResult {
    const state = this.authority.expected(target, expected);
    const attachment = this.authority.attachment(recipient);
    if (!this.selected(target) || state.controller.kind !== 'user' || state.handoff !== 'idle' ||
        !state.visibleTo.includes(recipient) || !state.inputReady || state.pageAvailability !== 'ready' ||
        this.operations.unsafe(target) || target.page.retirement()) throw refused('control_refused');
    const document = this.authority.document(target);
    const before = target.page.binding();
    if (before.blocked || before.retired) return this.authority.exhausted();
    const interaction = this.authority.boundary.native.ownership.interactionState(bindingKey(before));
    if (interaction.busy || interaction.buttons || interaction.pressedButtons || interaction.wheel || interaction.momentum ||
        interaction.htmlSource || interaction.htmlTarget || interaction.marked)
      throw refused('control_refused', 'Finish or cancel the current interaction, then Return control.');
    // Providers may check facts; none can schedule a deferred grant. Recheck
    // selection, recipient and document immediately before the native commit.
    this.authority.documents.assertCurrent(target, document);
    this.authority.expected(target, expected);
    if (!this.selected(target) || this.authority.attachment(recipient) !== attachment ||
        !this.authority.state(target).visibleTo.includes(recipient)) throw refused('control_changed');
    this.mark(target, true);
    this.authority.publishReturn(target, recipient, expected, document);
    this.authority.changed();
    const after = this.authority.owner(target, recipient, expected + 1);
    if (after.handoff !== 'idle' || this.authority.document(target) !== document) throw refused('control_changed');
    return { state: after };
  }
}
