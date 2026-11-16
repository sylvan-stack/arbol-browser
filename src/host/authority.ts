import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import type { NativeFailureBoundary } from '../runtime/bootstrap.js';
import { assertCandidateTrust } from '../native/manifest.js';
import type { PageSurface } from './windows.js';
import { refused, type TabState, type TabTarget } from './tabs.js';

/** Supplied by the current-document producer (ABR-11), never a renderer claim.
 * Identity objects denote actual original renderer/document/frame lifetimes.
 * Navigation, including same-document navigation, must replace this receipt. */
export interface DocumentReceipt {
  readonly page: PageSurface;
  readonly renderer: object;
  readonly document: object;
  readonly frame: object;
  readonly epoch: number;
  readonly navigation: string;
  readonly availability: Contract<'browser.Availability'>;
  readonly ready: boolean;
}
export interface DocumentAuthority {
  current(target: TabTarget): DocumentReceipt;
  assertCurrent(target: TabTarget, receipt: DocumentReceipt): void;
  /** The real producer fences every command and continuation to this job and
   * its current physical document/readiness epoch, including own navigation. */
  prepare(target: TabTarget, url: string, context: { readonly signal: AbortSignal; assertCurrent(): void }): Promise<void>;
  /** Prove this physical navigation is the expected successor of this exact
   * already-issued action. An unrelated navigation cannot claim its ticket. */
  assertSuccessor(target: TabTarget, original: DocumentReceipt, successor: DocumentReceipt,
    action: string, operation: string): void;
}
export interface NavigationContinuation { readonly target: TabTarget; readonly action: string }
interface ContinuationState {
  stamp: AuthorityStamp; operation: string; valid: boolean; used: boolean; successor?: DocumentReceipt; successorEpoch?: number;
}
export interface AuthorityStamp {
  readonly target: TabTarget;
  readonly attachment: Readonly<Contract<'browser.ClientIdentity'>>;
  readonly generation: number;
  readonly epoch: number;
  readonly recipientEpoch: number;
  readonly document: DocumentReceipt;
}
export interface Invalidation {
  readonly target: TabTarget;
  /** Absent means every recipient and every operation on the tab. */
  readonly recipient?: string;
  readonly continuation?: NavigationContinuation;
}
interface Entry {
  target: TabTarget;
  generation: number;
  epoch: number;
  controller: Contract<'browser.ShellController'>;
  grants: Set<string>;
  recipients: Map<string, number>;
  handoff: 'idle' | 'taking';
  ready: boolean;
  availability: Contract<'browser.Availability'>;
  document?: DocumentReceipt;
  closed: boolean;
  retired: boolean;
}
interface Connection { identity: Readonly<Contract<'browser.ClientIdentity'>>; signal: AbortSignal }
interface Snapshot { stamp: AuthorityStamp; expires: number; delivered: boolean }
/** Host-private state only. No renderer, adapter or label is an authority token. */
export class TabAuthority {
  private readonly entries = new Map<TabTarget, Entry>();
  private readonly ids = new Map<string, TabTarget>();
  private readonly connections = new Map<string, Connection>();
  private readonly issued = new Set<string>();
  private readonly listeners = new Set<() => void>();
  private readonly invalidators = new Set<(event: Invalidation) => void>();
  private readonly snapshots = new Map<string, Snapshot>();
  private readonly closedTargets = new WeakSet<TabTarget>();
  private readonly continuations = new WeakMap<NavigationContinuation, ContinuationState>();
  private readonly activeContinuations = new Map<TabTarget, NavigationContinuation>();
  private sealed = false;
  constructor(readonly boundary: NativeFailureBoundary, readonly documents: DocumentAuthority) {
    assertCandidateTrust(boundary.native.trust); this.assertHealthy();
  }
  assertHealthy(): void {
    this.boundary.fatal.assertHealthy(); this.boundary.native.assertIntegrity();
  }
  assertAdmission(): void { this.assertHealthy(); if (this.sealed) throw unavailable('browser'); }
  exhausted(): never { this.sealed = true; return this.boundary.fatal.fail('native_boundary_unavailable'); }
  private increment(value: number): number {
    if (!Number.isSafeInteger(value) || value < 0 || value >= Number.MAX_SAFE_INTEGER) return this.exhausted();
    return value + 1;
  }
  opaque(prefix: 'act' | 'snap' | 'ref'): string {
    this.assertAdmission();
    const id = `${prefix}_${randomBytes(16).toString('base64url')}`;
    if (this.issued.size >= 1000000 || this.issued.has(id)) return this.exhausted();
    this.issued.add(id); return id;
  }
  /** Called once by authenticated transport hello; reconnect must use a new id. */
  connect(identity: Readonly<Contract<'browser.ClientIdentity'>>, signal: AbortSignal): void {
    this.assertAdmission();
    if (!validator('browser.ClientIdentity')(identity) || signal.aborted || this.issued.has(identity.id) ||
        this.connections.size >= 32) throw refused('control_refused');
    if (this.issued.size >= 1000000) return this.exhausted();
    this.issued.add(identity.id); this.connections.set(identity.id, { identity, signal }); this.changed();
  }
  connected(id: string): boolean { const value = this.connections.get(id); return Boolean(value && !value.signal.aborted && !this.sealed); }
  attachment(id: string): Readonly<Contract<'browser.ClientIdentity'>> {
    this.assertAdmission(); const value = this.connections.get(id);
    if (!value || !this.connected(id)) throw unavailable('browser'); return value.identity;
  }
  attachments(): readonly Contract<'browser.ClientIdentity'>[] {
    this.assertAdmission(); return [...this.connections.values()].filter(value => this.connected(value.identity.id)).map(value => ({ ...value.identity }));
  }
  /** Removes connection identity first. Caller immediately revokes every returned tab. */
  detach(id: string): readonly TabTarget[] {
    const targets = this.targets().filter(target => this.entry(target).grants.has(id));
    this.connections.delete(id); return targets;
  }
  targets(): readonly TabTarget[] { return [...this.entries.values()].filter(entry => !entry.closed).map(entry => entry.target); }
  private entry(target: TabTarget): Entry {
    const entry = this.entries.get(target);
    if (!entry || this.ids.get(target.id) !== target) throw refused('tab_not_found'); return entry;
  }
  target(id: string): TabTarget {
    this.assertAdmission(); const target = this.ids.get(id);
    if (!target || this.entry(target).closed) throw refused('tab_not_found'); return target;
  }
  register(target: TabTarget, initial: TabState): void {
    this.assertAdmission();
    if (this.entries.has(target) || this.ids.has(target.id) || this.issued.has(target.id) || !validator('browser.ShellTab')(initial) ||
        initial.tab !== target.id || initial.generation !== 1 || initial.handoff !== 'idle' || initial.inputReady ||
        initial.pageAvailability !== 'unavailable' || this.entries.size >= 64) return this.exhausted();
    const binding = target.page.binding();
    if (!binding.blocked || binding.retired || binding.webContentsId !== target.page.view.webContents.id) return this.exhausted();
    const grants = new Set(initial.visibleTo);
    if (initial.controller.kind === 'user' ? grants.size !== 0 : !grants.has(initial.controller.client) || [...grants].some(id => !this.connected(id)))
      return this.exhausted();
    this.issued.add(target.id); this.ids.set(target.id, target);
    this.entries.set(target, { target, generation: 1, epoch: 1, controller: { ...initial.controller }, grants,
      recipients: new Map(), handoff: 'idle', ready: false, availability: 'unavailable', closed: false, retired: false });
  }
  state(target: TabTarget): TabState {
    this.assertHealthy(); const entry = this.entry(target);
    return Object.freeze({ tab: target.id, generation: entry.generation, controller: Object.freeze({ ...entry.controller }),
      visibleTo: Object.freeze([...entry.grants].filter(id => this.connected(id))) as unknown as string[],
      handoff: entry.handoff, inputReady: !entry.closed && entry.ready && entry.handoff === 'idle',
      observationSuspended: entry.controller.kind === 'user', pageAvailability: entry.availability,
      ...(entry.document ? { navigation: entry.document.navigation } : {}) });
  }
  expected(target: TabTarget, expected: number): TabState {
    this.assertAdmission(); const entry = this.entry(target);
    if (entry.closed) throw refused('tab_not_found');
    if (entry.generation !== expected) throw refused('control_changed'); return this.state(target);
  }
  visible(target: TabTarget, recipient: string): TabState {
    this.assertAdmission(); const entry = this.entry(target);
    if (entry.closed || !this.connected(recipient) || !entry.grants.has(recipient)) throw refused('tab_not_found'); return this.state(target);
  }
  owner(target: TabTarget, recipient: string, generation: number): TabState {
    this.visible(target, recipient); const state = this.expected(target, generation);
    if (state.controller.kind !== 'agent' || state.controller.client !== recipient) throw refused('control_refused');
    return state;
  }
  subscribe(listener: () => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  onInvalidate(invalidate: (event: Invalidation) => void): () => void {
    this.invalidators.add(invalidate); return () => { this.invalidators.delete(invalidate); };
  }
  changed(): void {
    this.assertHealthy();
    try { for (const listener of this.listeners) { const result: unknown = listener(); if (result !== undefined) return this.exhausted(); } }
    catch { return this.exhausted(); }
  }
  /** This function and all registered invalidators must actually return void. */
  invalidate(target: TabTarget, recipient?: string, continuation?: NavigationContinuation): void {
    const entry = this.entry(target);
    const active = this.activeContinuations.get(target);
    if (active && active !== continuation && (recipient === undefined || this.continuations.get(active)?.stamp.attachment.id === recipient)) {
      this.continuations.get(active)!.valid = false; this.activeContinuations.delete(target);
    }
    if (recipient === undefined) entry.epoch = this.increment(entry.epoch);
    else entry.recipients.set(recipient, this.increment(entry.recipients.get(recipient) ?? 0));
    for (const [id, snapshot] of this.snapshots)
      if (snapshot.stamp.target === target && (recipient === undefined || snapshot.stamp.attachment.id === recipient)) this.snapshots.delete(id);
    try {
      const event = Object.freeze({ target, ...(recipient === undefined ? {} : { recipient }), ...(continuation ? { continuation } : {}) });
      for (const invalidate of this.invalidators) { const result: unknown = invalidate(event); if (result !== undefined) return this.exhausted(); }
    } catch { return this.exhausted(); }
  }
  grant(target: TabTarget, recipient: string, expected: number): void {
    const state = this.expected(target, expected); this.attachment(recipient);
    if (state.controller.kind !== 'user' || state.handoff !== 'idle') throw refused('control_refused');
    this.entry(target).grants.add(recipient);
  }
  revoke(target: TabTarget, recipient: string): void {
    this.entry(target).grants.delete(recipient); this.invalidate(target, recipient);
  }
  beginTake(target: TabTarget, expected: number): void {
    this.expected(target, expected); const entry = this.entry(target);
    if (entry.handoff !== 'idle' || entry.controller.kind !== 'agent') throw refused('control_refused');
    entry.generation = this.increment(entry.generation); entry.controller = { kind: 'user' };
    entry.ready = false; entry.handoff = 'taking'; this.invalidate(target);
  }
  finishTake(target: TabTarget, ready: boolean, retired: boolean): void {
    const entry = this.entry(target);
    if (entry.closed || entry.controller.kind !== 'user' || entry.handoff !== 'taking') return this.exhausted();
    entry.retired = retired; entry.ready = ready && !retired; entry.handoff = 'idle';
    if (retired) { entry.availability = 'unavailable'; delete entry.document; }
  }
  publishReturn(target: TabTarget, recipient: string, expected: number, document: DocumentReceipt): void {
    const state = this.expected(target, expected); this.attachment(recipient); this.documents.assertCurrent(target, document);
    if (state.controller.kind !== 'user' || state.handoff !== 'idle' || !state.visibleTo.includes(recipient) || !document.ready)
      throw refused('control_refused');
    const entry = this.entry(target); entry.generation = this.increment(entry.generation);
    entry.controller = { kind: 'agent', client: recipient, label: this.attachment(recipient).label };
    entry.document = document; entry.ready = true; entry.availability = 'ready'; this.invalidate(target);
  }
  /** Close visibility synchronously before ABR-9 starts actual native retirement. */
  closeTab(target: TabTarget): void {
    const entry = this.entry(target); if (entry.closed) return;
    this.closedTargets.add(target);
    entry.closed = true; entry.ready = false; entry.grants.clear(); entry.generation = this.increment(entry.generation);
    entry.controller = { kind: 'user' }; this.invalidate(target);
  }
  removed(target: TabTarget): void {
    const entry = this.entry(target); if (!entry.closed) return this.exhausted();
    this.entries.delete(target); this.ids.delete(target.id);
  }
  /** Retained exact identity, including after the registry removes its record. */
  wasClosed(target: TabTarget): boolean { return this.closedTargets.has(target); }
  closeAdmission(): void {
    this.sealed = true;
    for (const entry of this.entries.values()) this.closeTab(entry.target);
    this.connections.clear();
  }
  document(target: TabTarget, requireReady = true): DocumentReceipt {
    this.assertAdmission(); const entry = this.entry(target);
    if (entry.closed || entry.retired) throw refused('control_refused');
    const receipt = this.documents.current(target); this.documents.assertCurrent(target, receipt);
    if (receipt.page !== target.page || !Number.isSafeInteger(receipt.epoch) || receipt.epoch < 1 ||
        !validator('browser.NavigationId')(receipt.navigation)) return this.exhausted();
    if (requireReady && (!receipt.ready || receipt.availability !== 'ready')) throw refused('control_refused');
    return receipt;
  }
  refreshDocument(target: TabTarget): DocumentReceipt {
    const receipt = this.document(target, false), entry = this.entry(target);
    if (entry.document !== receipt) { entry.ready = false; this.invalidate(target); entry.document = receipt; }
    if (!receipt.ready) entry.ready = false;
    entry.availability = receipt.availability; return receipt;
  }
  beginContinuation(stamp: AuthorityStamp, action: string, operation: string): NavigationContinuation {
    this.check(stamp, true);
    if (!this.issued.has(action) || !validator('browser.ActionId')(action) || this.activeContinuations.has(stamp.target))
      throw refused('control_refused');
    const token = Object.freeze({ target: stamp.target, action });
    this.continuations.set(token, { stamp, operation, valid: true, used: false });
    this.activeContinuations.set(stamp.target, token); return token;
  }
  /** Called only by the real document producer at the exact expected navigation
   * boundary. Default refreshDocument revokes every operation, including this. */
  acceptNavigation(token: NavigationContinuation, successor: DocumentReceipt): void {
    const record = this.continuations.get(token), entry = this.entry(token.target);
    if (!record || !record.valid || record.used || this.activeContinuations.get(token.target) !== token) throw staleSnapshot();
    const stamp = record.stamp;
    this.owner(token.target, stamp.attachment.id, stamp.generation);
    if (this.attachment(stamp.attachment.id) !== stamp.attachment || entry.epoch !== stamp.epoch ||
        (entry.recipients.get(stamp.attachment.id) ?? 0) !== stamp.recipientEpoch || entry.document !== stamp.document ||
        successor.page !== token.target.page || successor === stamp.document || successor.document === stamp.document.document ||
        successor.epoch <= stamp.document.epoch || successor.navigation === stamp.document.navigation) throw staleSnapshot();
    const proof: unknown = this.documents.assertSuccessor(token.target, stamp.document, successor, token.action, record.operation);
    if (proof !== undefined) return this.exhausted();
    this.documents.assertCurrent(token.target, successor);
    if (this.documents.current(token.target) !== successor) throw staleSnapshot();
    this.owner(token.target, stamp.attachment.id, stamp.generation);
    if (!record.valid || record.used || this.activeContinuations.get(token.target) !== token || entry.epoch !== stamp.epoch ||
        (entry.recipients.get(stamp.attachment.id) ?? 0) !== stamp.recipientEpoch || entry.document !== stamp.document ||
        this.attachment(stamp.attachment.id) !== stamp.attachment) throw staleSnapshot();
    // Consume before any invalidation callback reenters; no second successor.
    record.used = true; record.successor = successor;
    entry.ready = false; entry.document = successor; entry.availability = successor.availability;
    this.invalidate(token.target, undefined, token); record.successorEpoch = entry.epoch;
  }
  /** Physical settlement may be known after Take, but it never renews lost
   * authority. A successor must have been authenticated before invalidation. */
  settleContinuation(token: NavigationContinuation, original: DocumentReceipt, current: DocumentReceipt): AuthorityStamp | undefined {
    const record = this.continuations.get(token);
    if (!record || record.stamp.document !== original || current !== (record.successor ?? original)) throw staleSnapshot();
    this.assertHealthy(); this.documents.assertCurrent(token.target, current);
    let result: AuthorityStamp | undefined;
    try {
      if (!record.valid || this.activeContinuations.get(token.target) !== token) throw staleSnapshot();
      const stamp = this.capture(token.target, record.stamp.attachment.id, record.stamp.generation, true);
      if (stamp.attachment !== record.stamp.attachment || stamp.recipientEpoch !== record.stamp.recipientEpoch || stamp.document !== current ||
          stamp.epoch !== (record.successorEpoch ?? record.stamp.epoch)) throw staleSnapshot();
      result = stamp;
    } catch { /* No result lease; actual balanced old work can still drain. */ }
    record.valid = false;
    if (this.activeContinuations.get(token.target) === token) this.activeContinuations.delete(token.target);
    return result;
  }
  /** Only the verified native/readiness adapter may publish initial readiness. */
  prepared(target: TabTarget, receipt: DocumentReceipt): void {
    this.documents.assertCurrent(target, receipt); const entry = this.entry(target);
    if (receipt !== this.document(target) || entry.closed || entry.handoff !== 'idle') throw refused('control_changed');
    entry.document = receipt; entry.ready = true; entry.availability = 'ready';
  }
  capture(target: TabTarget, recipient: string, generation?: number, mutation = false): AuthorityStamp {
    const state = this.visible(target, recipient);
    if (generation !== undefined && state.generation !== generation) throw refused('control_changed');
    if (mutation) this.owner(target, recipient, generation ?? state.generation);
    if (state.controller.kind !== 'agent' || state.handoff !== 'idle' || !state.inputReady) throw refused('control_refused');
    const document = this.document(target), entry = this.entry(target);
    if (entry.document !== document) throw staleSnapshot();
    const binding = target.page.binding();
    if (!binding.blocked || binding.retired || binding.webContentsId !== target.page.view.webContents.id) return this.exhausted();
    return Object.freeze({ target, attachment: this.attachment(recipient), generation: state.generation,
      epoch: entry.epoch, recipientEpoch: entry.recipients.get(recipient) ?? 0, document });
  }
  check(stamp: AuthorityStamp, mutation = false): void {
    const current = this.capture(stamp.target, stamp.attachment.id, stamp.generation, mutation);
    if (current.attachment !== stamp.attachment || current.epoch !== stamp.epoch || current.recipientEpoch !== stamp.recipientEpoch ||
        current.document !== stamp.document) throw staleSnapshot();
  }
  /** References are issued by later inspection ports; their snapshot marker is
   * admitted here and activated only at the actual final transport commitment. */
  reserveSnapshot(stamp: AuthorityStamp): string {
    this.check(stamp); const id = this.opaque('snap');
    for (const [key, value] of this.snapshots) if (value.expires <= performance.now()) this.snapshots.delete(key);
    const own = [...this.snapshots].filter(([, value]) => value.stamp.attachment.id === stamp.attachment.id);
    while (own.length >= 8) this.snapshots.delete(own.shift()![0]);
    this.snapshots.set(id, { stamp, expires: performance.now() + 300000, delivered: false }); return id;
  }
  commitSnapshot(id: string, stamp: AuthorityStamp): void {
    this.check(stamp); const snapshot = this.snapshots.get(id);
    if (!snapshot || snapshot.stamp !== stamp || snapshot.expires <= performance.now()) throw staleSnapshot(); snapshot.delivered = true;
  }
  requireSnapshot(id: string, stamp: AuthorityStamp): void {
    this.check(stamp, true); const snapshot = this.snapshots.get(id);
    if (!snapshot || !snapshot.delivered || snapshot.expires <= performance.now()) throw staleSnapshot();
    this.check(snapshot.stamp, true);
    if (snapshot.stamp.attachment !== stamp.attachment || snapshot.stamp.target !== stamp.target || snapshot.stamp.document !== stamp.document ||
        snapshot.stamp.epoch !== stamp.epoch || snapshot.stamp.recipientEpoch !== stamp.recipientEpoch) throw staleSnapshot();
  }
}
export function staleSnapshot(): BrowserFailure {
  return new BrowserFailure({ code: 'stale_snapshot', message: 'The page reference is no longer current.', retryable: true,
    remedy: 'Take a fresh snapshot before another page action.' });
}
