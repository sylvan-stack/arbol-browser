import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { setTimeout as pause } from 'node:timers/promises';
import type { Contract } from '../contracts/generated.js';
import { bindingKey } from '../native/retirement.js';
import { TabAuthority, type DocumentReceipt } from './authority.js';
import { refused, userURL, assertTabRegistry, type TabLifecycle, type TabRegistry, type TabState, type TabTarget } from './tabs.js';
import { assertPageRetirement, assertPageSurface, assertWindowHost, type PageRetirement, type PageSurface, type WindowHost } from './windows.js';
import { ActionQueue, type ActionExecution } from './actions.js';
import { DeliveryAuthority, responseBytes, type DeliveryProof } from './delivery.js';
import { createSharing } from './sharing.js';
import { projectAgentTabs } from './projections.js';
import { assertShellRegistration, type ShellAuthority, type ShellRegistration } from './shell-ipc.js';
import { assertNativeFailureBoundary, type NativeFailureBoundary } from '../runtime/bootstrap.js';
import { assertHostLifecycle, type HostControlPort, type HostLifecycle } from '../runtime/lifecycle.js';
import type { ConnectionContext, ProtectedDispatchPort, Request, ControlFrameKind } from '../runtime/transport.js';
import { BrowserFailure, unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';

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
interface PendingTake { expected: number; promise: Promise<HandoffResult>; page: PageSurface }
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
  private readonly notified = new WeakMap<PageSurface, PageRetirement>();
  private readonly retirementWaits = new WeakMap<PageSurface, { deadline: number; receipt?: PageRetirement; complete: boolean }>();
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
      // The real native wrapper already checked its mark acknowledgement before
      // shield/presentation callbacks. A genuine same-target Close may now have
      // advanced that binding again; its exact destruction proof governs next.
      if (this.authority.wasClosed(target)) return;
      if (before.retired || after.retired || after.id !== before.id || after.nonce !== before.nonce ||
          after.webContentsId !== before.webContentsId || after.webContentsId !== target.page.view.webContents.id ||
          after.revision !== before.revision + 1 || after.blocked !== blocked) return this.authority.exhausted();
    });
  }
  private original(target: TabTarget): PageSurface {
    const page = this.pending.get(target)?.page;
    if (!page || page !== target.page) return this.authority.exhausted(); return page;
  }
  private async waitRetirement(target: TabTarget, page: PageSurface): Promise<PageRetirement> {
    let wait = this.retirementWaits.get(page);
    if (!wait) { wait = { deadline: performance.now() + 1000, complete: false }; this.retirementWaits.set(page, wait); }
    try {
      if (page !== target.page) return this.authority.exhausted();
      if (wait.complete && wait.receipt) { assertPageRetirement(page, wait.receipt); return wait.receipt; }
      // Logical close is synchronous; registry/native start may follow an
      // awaited instance phase or all-window preparation. Absence is no proof.
      let receipt = page.retirement();
      while (!receipt) {
        if (!this.authority.wasClosed(target) || performance.now() >= wait.deadline) return this.authority.exhausted();
        await pause(Math.max(1, Math.min(10, wait.deadline - performance.now())));
        if (page !== target.page) return this.authority.exhausted(); receipt = page.retirement();
      }
      assertPageRetirement(page, receipt);
      if (wait.receipt && wait.receipt !== receipt) return this.authority.exhausted(); wait.receipt = receipt;
      await bounded(wait.deadline, () => receipt.completion);
      assertPageRetirement(page, receipt);
      if (page !== target.page || receipt.phase !== 'retired') return this.authority.exhausted();
      wait.complete = true; return receipt;
    } catch { return this.authority.exhausted(); }
  }
  /** Registry removal and Take share this once-only genuine settlement. */
  retired(target: TabTarget): void {
    const receipt = target.page.retirement();
    try {
      if (!receipt) return this.authority.exhausted();
      assertPageRetirement(target.page, receipt);
      if (receipt.phase !== 'retired') return this.authority.exhausted();
      const previous = this.notified.get(target.page);
      if (previous) { if (previous !== receipt) return this.authority.exhausted(); return; }
      this.notified.set(target.page, receipt); // before callback reentry
      this.synchronous(() => this.operations.retired(target));
    } catch { return this.authority.exhausted(); }
  }
  private async superseded(target: TabTarget): Promise<never> {
    try {
      if (!this.authority.wasClosed(target)) return this.authority.exhausted();
      await this.waitRetirement(target, this.original(target)); this.retired(target);
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
    this.pending.set(target, { expected, promise, page: target.page });
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
    const page = this.original(target);
    let settledAction: Contract<'browser.SettledAction'> | undefined;
    let readyDocument: DocumentReceipt | undefined;
    try {
      settledAction = await bounded(deadline, () => this.operations.drain(target, deadline));
      if (!this.authority.wasClosed(target) && !this.operations.unsafe(target) && !target.page.retirement()) {
        const document = this.authority.document(target);
        await bounded(deadline, () => this.operations.leaveAgentMode(target, document, deadline));
        this.authority.assertDocument(target, document);
        if (!this.operations.unsafe(target) && this.authority.document(target) === document) readyDocument = document;
      }
    } catch { this.authority.assertHealthy(); }
    this.original(target);
    if (this.authority.wasClosed(target)) return this.superseded(target);
    this.authority.assertAdmission();
    if (readyDocument && !this.operations.unsafe(target) && !target.page.retirement()) {
      this.authority.assertDocument(target, readyDocument);
      if (this.authority.wasClosed(target)) return this.superseded(target);
      this.original(target);
      if (this.operations.unsafe(target) || page.retirement()) return this.authority.exhausted();
      this.mark(target, false);
      if (this.authority.wasClosed(target)) return this.superseded(target);
      this.authority.finishTake(target, true, false, readyDocument);
    } else {
      const known = this.operations.outcome(target);
      if (known) settledAction = { ...known };
      try {
        // Start the one exact retirement before awaiting its existing receipt.
        // Repeated/superseding callers share the same wait and deadline.
        if (!this.retirementWaits.has(page)) this.retirementWaits.set(page, { deadline: performance.now() + 1000, complete: false });
        const kickoff = page.retire(); void kickoff.catch(() => {}); // canonical receipt below owns proof/failure
        await this.waitRetirement(target, page); this.retired(target);
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
  /** Cleanup, unlike an old public Take reply, may join a verified Close that
   * superseded this exact target without making normal close profile-fatal. */
  settleOwnership(target: TabTarget, expected: number): Promise<void> {
    const page = target.page;
    const closed = async () => { await this.waitRetirement(target, page); this.retired(target); };
    if (this.authority.wasClosed(target)) return closed();
    let pending: Promise<HandoffResult>;
    try { pending = this.take(target, expected); }
    catch (error) { if (this.authority.wasClosed(target)) return closed(); throw error; }
    return pending.then(() => {}, error => {
      if (this.authority.wasClosed(target)) return closed(); throw error;
    });
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
    this.authority.assertDocument(target, document);
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

type AgentRequest = Contract<'wire.ToolRequest'>;
type UserRequest = Extract<Contract<'browser.ShellRequest'>, { method: 'user_navigate' | 'back' | 'forward' | 'reload' }>;
export interface HostJob {
  readonly signal: AbortSignal;
  readonly deadline: number;
  assertCurrent(): void;
}
/** These are real main-process producers, not successful placeholders. ABR-11
 * supplies physical readiness/recovery; Tools supplies classified inspection
 * and operation-specific trusted input/settlement. Every asynchronous provider
 * must call the supplied guard before each engine issue or host mutation. */
export interface OwnershipOperations {
  info(): Contract<'browser.BrowserInfo'>;
  agent(request: AgentRequest, execution: ActionExecution, inspectionIdentity?: string): Promise<unknown>;
  user(request: UserRequest, target: TabTarget, job: HostJob): Promise<void>;
  recover(target: TabTarget, expected: number, job: { readonly deadline: number; assertCurrent(): void }): Promise<void>;
  invalidate(target: TabTarget, recipient?: string): void;
  leaveAgentMode(target: TabTarget, document: DocumentReceipt, deadline: number,
    job: { readonly generation: number; assertCurrent(): void }): Promise<void>;
}
export interface OwnershipHost {
  readonly authority: TabAuthority;
  readonly lifecycle: TabLifecycle;
  readonly shell: ShellAuthority;
  readonly control: HostControlPort;
  readonly dispatch: ProtectedDispatchPort;
  bind(tabs: TabRegistry, host: WindowHost, registration: ShellRegistration): void;
  bindRuntime(runtime: HostLifecycle): void;
  runEnd(attachment: string): void;
  healthFailure(target: TabTarget): Promise<void>;
}
interface PendingOpen { action: string; recipient: string; request: string; targets: Set<TabTarget>; cancelled: boolean }
interface StagedProof { proof: DeliveryProof; invalidated: boolean; listDigest?: string }
/** Closed canonical contribution. This does not launch, install, choose a
 * profile, construct an EngineAuthority or qualify/open ordinary entry. */
export function createOwnershipHost(boundary: NativeFailureBoundary, documents: import('./authority.js').DocumentAuthority,
  operations: OwnershipOperations): OwnershipHost {
  assertNativeFailureBoundary(boundary);
  for (const method of ['current', 'assertCurrent', 'prepare', 'assertSuccessor'] as const)
    if (typeof documents[method] !== 'function') throw unavailable('browser');
  for (const method of ['info', 'agent', 'user', 'recover', 'invalidate', 'leaveAgentMode'] as const)
    if (typeof operations[method] !== 'function') throw unavailable('browser');
  const authority = new TabAuthority(boundary, documents);
  let phase: 'prepared' | 'live' | 'closed' = 'prepared';
  let registry: TabRegistry | undefined, runtime: HostLifecycle | undefined, opening: PendingOpen | undefined, everBound = false;
  const windows = new Map<WindowHost, ShellRegistration>();
  const contexts = new Map<string, ConnectionContext>(), attempted = new WeakSet<ConnectionContext>();
  const disconnected = new WeakSet<ConnectionContext>(), cleanups = new Map<string, Promise<void>>();
  const initial = new Map<TabTarget, { page: PageSurface; closed: boolean }>();
  const opens = new Map<ConnectionContext, Map<string, PendingOpen>>();
  const requests = new Map<ConnectionContext, Map<string, Request>>();
  const staged = new Map<ConnectionContext, Map<string, StagedProof>>();
  const hash = (value: Uint8Array) => createHash('sha256').update(value).digest('hex');
  const tabs = () => { if (!registry) throw unavailable('browser'); assertTabRegistry(registry); return registry; };
  const prepared = () => { assertNativeFailureBoundary(boundary); if (phase === 'closed') throw unavailable('browser'); };
  const live = () => { prepared(); if (phase !== 'live' || !runtime || runtime.phase !== 'ready') throw unavailable('browser'); };
  const synchronous = (work: () => void) => {
    try { const returned: unknown = work(); if (returned !== undefined) return authority.exhausted(); }
    catch { return authority.exhausted(); }
  };
  const queue = new ActionQueue(authority, async (target, document, deadline) => {
    const generation = authority.state(target).generation;
    const assertCurrent = () => {
      authority.expected(target, generation); authority.assertDocument(target, document);
      if (target.page !== document.page || target.page.retirement() || performance.now() >= deadline) throw refused('control_changed');
    };
    assertCurrent(); await operations.leaveAgentMode(target, document, deadline, { generation, assertCurrent }); assertCurrent();
  });
  const handoff = new HandoffController(authority, queue, target => tabs().selected(target.page.window) === target);
  const sharing = createSharing(authority, handoff), delivery = new DeliveryAuthority(authority, tabs);
  authority.onInvalidate(event => {
    for (const [context, records] of staged) for (const record of records.values()) {
      const proof = record.proof;
      if ((event.recipient === undefined || context.attachment?.id === event.recipient) &&
          (proof.kind === 'tabs' || ('stamp' in proof && proof.stamp.target === event.target) ||
          ((proof.kind === 'release' || proof.kind === 'close') && proof.receipt.target === event.target))) record.invalidated = true;
    }
  });
  authority.onInvalidate(event => operations.invalidate(event.target, event.recipient));
  const windowForOpen = () => {
    const host = [...windows.keys()].find(value => !value.window.isDestroyed());
    if (!host) throw unavailable('browser'); assertWindowHost(host); return host;
  };
  const client = (context: ConnectionContext): string => {
    delivery.assertContext(context);
    if (context.endpoint !== 'agent' || !context.attachment) throw unavailable('browser'); return context.attachment.id;
  };
  const authorize = (context: ConnectionContext, request: Request) => {
    live(); delivery.assertContext(context);
    if (context.endpoint === 'management') {
      if (!validator('wire.ManagementRequest')(request) || context.attachment) throw unavailable('browser'); return;
    }
    if (!validator('wire.ToolRequest')(request) || request.method !== 'tool') throw unavailable('browser');
    const recipient = client(context), params = request.params;
    if (['browser_info', 'browser_tabs_list', 'browser_tab_open'].includes(params.name)) return;
    const args = params.arguments;
    if (!('tab' in args) || !('controlGeneration' in args)) throw refused('tab_not_found');
    const target = authority.target(args.tab); authority.visible(target, recipient); authority.expected(target, args.controlGeneration);
    if (params.name === 'browser_release' || params.name === 'browser_tab_close') { authority.owner(target, recipient, args.controlGeneration); return; }
    const mutation = !['browser_snapshot', 'browser_screenshot'].includes(params.name);
    const stamp = authority.capture(target, recipient, args.controlGeneration, mutation);
    if (mutation) {
      if (!('snapshot' in args)) throw refused('control_refused'); authority.requireSnapshot(args.snapshot, stamp);
    } else {
      if (params.name === 'browser_screenshot' && 'snapshot' in args) authority.requireSnapshot(args.snapshot, stamp, false);
      if ('root' in args && args.root) authority.requireSnapshot(args.root.snapshot, stamp, false);
    }
  };
  const markPrepared = (target: TabTarget, generation: number, receipt: DocumentReceipt) => {
    const beforeState = authority.expected(target, generation); authority.assertDocument(target, receipt);
    if (!receipt.ready || receipt.availability !== 'ready') throw refused('control_refused');
    if (beforeState.controller.kind === 'agent') authority.owner(target, beforeState.controller.client, generation);
    target.page.window.guardRetirementTransition(() => {
      const before = target.page.binding(), blocked = beforeState.controller.kind === 'agent', after = target.page.setNativeBlocked(blocked);
      if (authority.wasClosed(target)) return;
      if (after.id !== before.id || after.nonce !== before.nonce || after.webContentsId !== before.webContentsId ||
          after.webContentsId !== target.page.view.webContents.id || after.revision !== before.revision + 1 || after.retired || after.blocked !== blocked)
        return authority.exhausted();
    });
    authority.expected(target, generation); authority.assertDocument(target, receipt);
    authority.prepared(target, receipt);
  };
  const lifecycle = Object.freeze<TabLifecycle>({
    assertAdmission: live, connected: id => authority.connected(id),
    register(target, state) {
      assertPageSurface(target.page);
      if (initial.has(target) || authority.knowsTarget(target)) return authority.exhausted();
      initial.set(target, { page: target.page, closed: false });
      live(); authority.register(target, state); initial.delete(target);
      if (opening && state.controller.kind === 'agent' && state.controller.client === opening.recipient) opening.targets.add(target);
    },
    state: target => authority.state(target),
    invalidate(target): void {
      if (authority.knowsTarget(target)) { authority.closeTab(target); return; }
      const pending = initial.get(target);
      if (!pending || pending.page !== target.page) return authority.exhausted();
      const binding = target.page.binding();
      if (!binding.blocked || binding.retired || binding.webContentsId !== target.page.view.webContents.id) return authority.exhausted();
      pending.closed = true; synchronous(() => operations.invalidate(target));
    },
    removed(target) {
      handoff.retired(target);
      if (authority.knowsTarget(target)) { authority.removed(target); return; }
      const pending = initial.get(target);
      if (!pending?.closed || pending.page !== target.page) return authority.exhausted(); initial.delete(target);
    },
    async prepare(target, url) {
      live(); const generation = authority.state(target).generation;
      await queue.prepare(target, generation, async (signal, assertCurrent) => {
        await documents.prepare(target, url, { signal, assertCurrent }); assertCurrent();
        const receipt = authority.refreshDocument(target); markPrepared(target, generation, receipt);
      });
    },
    changed: () => authority.changed(), exhausted: () => authority.exhausted(),
  });
  const disconnect = (id: string): void => {
    const context = contexts.get(id);
    if (!context && !authority.connected(id)) return;
    if (context && disconnected.has(context)) return;
    if (context) {
      disconnected.add(context); delivery.disconnect(context);
      for (const record of opens.get(context)?.values() ?? []) record.cancelled = true;
      opens.delete(context); contexts.delete(id);
      requests.delete(context);
      staged.delete(context);
    }
    const targets = authority.detach(id), pending: Promise<unknown>[] = [];
    // Identity is gone before native/abort callbacks; all grants and references
    // are synchronously closed before asynchronous settlement is joined.
    for (const target of targets) {
      const state = authority.state(target);
      if (state.controller.kind === 'agent' && state.controller.client === id) pending.push(handoff.settleOwnership(target, state.generation));
      authority.revoke(target, id);
    }
    const cleanup = Promise.all(pending).then(() => {}); void cleanup.catch(() => {}); cleanups.set(id, cleanup); authority.changed();
  };
  const control = Object.freeze<HostControlPort>({
    assertPrepared() {
      prepared(); if (!registry || windows.size === 0) throw unavailable('browser');
      for (const [host, registration] of windows) { assertWindowHost(host); registration.assertLoaded(); }
    },
    openAdmission() {
      prepared(); if (phase !== 'prepared' || !runtime || runtime.phase !== 'ready' || !registry || windows.size === 0) throw unavailable('browser');
      phase = 'live';
      for (const [host, registration] of windows) { live(); assertShellRegistration(registration, host); registration.show(); }
    },
    closeAdmission() { phase = 'closed'; authority.closeAdmission(); }, disconnect,
    async settleDisconnect(id, deadline) {
      const cleanup = cleanups.get(id); if (cleanup) { await bounded(deadline, () => cleanup); if (cleanups.get(id) === cleanup) cleanups.delete(id); }
    },
    async retireAll(deadline) {
      if (!registry) {
        if (windows.size !== 0 || initial.size !== 0) return authority.exhausted(); return;
      }
      const actualRegistry = tabs();
      await bounded(deadline, () => Promise.all([...windows.keys()].map(host => actualRegistry.closeWindow(host))).then(() => {}));
    },
    windowCount: () => [...windows.keys()].filter(host => !host.window.isDestroyed()).length,
  });
  const userJob = async (request: UserRequest, target: TabTarget) => {
    const generation = request.params.controlGeneration, deadline = performance.now() + (request.method === 'user_navigate' ? 15000 : 5000);
    if (request.method === 'user_navigate') userURL(request.params.url);
    let active = true;
    try {
      await bounded(deadline, () => queue.prepare(target, generation, async (signal, guard) => {
        const assertCurrent = () => {
          guard(); const state = authority.expected(target, generation);
          if (!active || performance.now() >= deadline || state.controller.kind !== 'user' || state.handoff !== 'idle') throw refused('control_changed');
        };
        await operations.user(request, target, { signal, deadline, assertCurrent }); assertCurrent();
        const receipt = authority.refreshDocument(target); if (receipt.ready) markPrepared(target, generation, receipt);
      }));
      authority.changed(); return { state: authority.state(target) };
    } finally { active = false; }
  };
  const shell = Object.freeze<ShellAuthority>({
    assertReady: prepared, assertOperational: live, attachments: () => authority.attachments(),
    subscribe: changed => authority.subscribe(changed), exhausted: () => authority.exhausted(),
    execute(request, target): Promise<HandoffResult> {
      live();
      if (!('tab' in request.params) || !('controlGeneration' in request.params) || request.params.tab !== target.id ||
          tabs().get(target.id) !== target || tabs().selected(target.page.window) !== target) throw refused('control_refused');
      const generation = request.params.controlGeneration;
      if (request.method === 'take') return handoff.take(target, generation);
      const state = authority.expected(target, generation);
      switch (request.method) {
        case 'share': return Promise.resolve(sharing.share(target, request.params.client, generation));
        case 'stop_sharing': return sharing.stopSharing(target, request.params.client, generation);
        case 'return': return Promise.resolve(handoff.returnControl(target, request.params.client, generation));
        case 'user_navigate': case 'back': case 'forward': case 'reload':
          if (state.controller.kind !== 'user' || state.handoff !== 'idle') throw refused('control_refused');
          return userJob(request, target);
        case 'recover': {
          if (state.controller.kind !== 'user' || state.handoff !== 'idle') throw refused('control_refused');
          const original = target.page, deadline = performance.now() + 8000; let active = true;
          const assertCurrent = () => {
            live(); if (!active || performance.now() >= deadline || authority.wasClosed(target)) throw refused('control_changed');
          };
          return bounded(deadline, () => operations.recover(target, generation, { deadline, assertCurrent })).then(() => {
            assertCurrent(); const after = authority.expected(target, generation + 1), document = authority.document(target);
            if (after.controller.kind !== 'user' || after.handoff !== 'idle' || !after.inputReady || document.page === original ||
                target.page.binding().blocked) throw refused('control_refused');
            authority.changed(); return { state: after };
          }).finally(() => { active = false; });
        }
        default: throw refused('control_refused');
      }
    },
  });
  const noteFailure = (context: ConnectionContext, request: Request, error: unknown) => {
    if (phase !== 'live' || context.signal.aborted || (context.attachment && !authority.connected(context.attachment.id))) return;
    if (error instanceof BrowserFailure && error.detail.action && error.detail.dispatchOutcome)
      delivery.noteOutcome(context, request, { action: error.detail.action, dispatchOutcome: error.detail.dispatchOutcome });
  };
  const dispatch = Object.freeze<ProtectedDispatchPort>({
    enroll(context) {
      live(); if (attempted.has(context)) throw unavailable('browser'); attempted.add(context);
      if (context.attachment) contexts.set(context.attachment.id, context);
      opens.set(context, new Map()); requests.set(context, new Map()); staged.set(context, new Map()); delivery.enroll(context);
      if (context.attachment && contexts.get(context.attachment.id) !== context) throw unavailable('browser');
    },
    authorize,
    async execute(context, request, deadline, signal) {
      authorize(context, request);
      const active = requests.get(context); if (!active) throw unavailable('browser'); active.set(request.id, request);
      try {
        let value: unknown, proof: DeliveryProof;
        if (request.method !== 'tool') {
          // Actual management producer is the owned registry/lifecycle, never a
          // fabricated provider acknowledgement or agent-accessible close.
          if (request.method === 'close') { await runtime!.close(); throw unavailable('browser'); }
          const host = windowForOpen();
          if (request.params.url !== undefined || tabs().all().length === 0)
            await tabs().openUser(host, userURL(request.params.url ?? 'about:blank'));
          live();
          host.window.show();
          const info = operations.info();
          value = { profile: info.profile, instance: info.instance, process: process.pid, alreadyRunning: true };
          proof = { kind: 'management', method: 'open' };
        } else {
          const recipient = client(context), params = request.params;
          if (params.name === 'browser_info') { value = operations.info(); proof = { kind: 'info' }; }
          else if (params.name === 'browser_tabs_list') {
            value = projectAgentTabs(tabs(), recipient, id => authority.connected(id)); proof = { kind: 'tabs', recipient };
          } else if (params.name === 'browser_tab_open') {
            const record: PendingOpen = { action: authority.opaque('act'), recipient, request: request.id, targets: new Set(), cancelled: false };
            opens.get(context)!.set(request.id, record); delivery.noteOutcome(context, request, { action: record.action, dispatchOutcome: 'not_dispatched' });
            let pending: Promise<TabTarget>;
            const previous = opening; opening = record;
            try { pending = tabs().openAgent(windowForOpen(), recipient, context.attachment!.label, userURL(params.arguments.url ?? 'about:blank')); }
            finally { opening = previous; }
            if (record.targets.size) delivery.noteOutcome(context, request, { action: record.action, dispatchOutcome: 'outcome_unknown' });
            const target = await pending;
            if (record.cancelled || signal.aborted || performance.now() >= deadline || !record.targets.has(target)) throw new BrowserFailure({
              code: 'control_refused', message: 'The open request no longer has authority.', retryable: true,
              action: record.action, dispatchOutcome: 'outcome_unknown' });
            const stamp = authority.capture(target, recipient, 1, true), receipt = authority.completedOpen(target, recipient, request.id, record.action);
            const tab = projectAgentTabs(tabs(), recipient, id => authority.connected(id)).tabs.find(tab => tab.tab === target.id);
            if (!tab || tab.controller !== 'agent') throw refused('control_changed');
            value = { action: record.action, status: 'completed', tab }; proof = { kind: 'opened', stamp, receipt };
            delivery.noteOutcome(context, request, { action: record.action, dispatchOutcome: 'completed' });
          } else {
            const args = params.arguments;
            if (!('tab' in args) || !('controlGeneration' in args)) throw refused('tab_not_found');
            const target = authority.target(args.tab), generation = args.controlGeneration;
            if (params.name === 'browser_release' || params.name === 'browser_tab_close') {
              const action = authority.opaque('act'); authority.owner(target, recipient, generation);
              delivery.noteOutcome(context, request, { action, dispatchOutcome: 'outcome_unknown' });
              if (params.name === 'browser_release') {
                const result = await handoff.release(target, recipient, generation);
                delivery.noteOutcome(context, request, { action, dispatchOutcome: 'completed' });
                const receipt = authority.completedRelease(target, recipient, request.id, action, generation);
                const tab: Contract<'browser.PrivateTab'> = { tab: target.id, controller: 'user', controlGeneration: result.state.generation,
                  observationSuspended: true, inputReady: false, pageAvailability: result.state.pageAvailability };
                value = { action, status: 'completed', tab, ...(result.settledAction ? { settledAction: result.settledAction } : {}) };
                proof = { kind: 'release', receipt };
              } else {
                await tabs().closeAgent(recipient, target.id, generation);
                delivery.noteOutcome(context, request, { action, dispatchOutcome: 'completed' });
                const receipt = authority.completedClose(target, recipient, request.id, action, generation);
                value = { action, status: 'completed', tab: target.id, closed: true }; proof = { kind: 'close', receipt };
              }
            } else {
              const mutation = !['browser_snapshot', 'browser_screenshot'].includes(params.name), stamp = authority.capture(target, recipient, generation, mutation);
              let inspectionIdentity: string | undefined;
              const result = await queue.run(stamp, params.name, { request: request.id, mutation,
                screenshot: params.name === 'browser_screenshot', ...('snapshot' in args ? { snapshot: args.snapshot } : {}), deadline, signal }, async execution => {
                if (params.name === 'browser_snapshot') inspectionIdentity = authority.reserveSnapshot(stamp);
                if (params.name === 'browser_screenshot' && 'snapshot' in args) inspectionIdentity = args.snapshot;
                const end = mutation ? tabs().beginPopupAction(target, generation) : () => {};
                try { return await operations.agent(request, execution, inspectionIdentity); } finally { end(); }
              });
              value = result.value;
              if (result.action) {
                delivery.noteOutcome(context, request, { action: result.action, dispatchOutcome: 'completed' });
                proof = { kind: 'action', stamp: result.stamp, action: result.action };
              } else {
                if (!inspectionIdentity) throw unavailable('browser');
                proof = { kind: params.name === 'browser_snapshot' ? 'snapshot' : 'screenshot', stamp: result.stamp, identity: inspectionIdentity };
              }
            }
          }
        }
        if (signal.aborted || performance.now() >= deadline) throw refused('control_refused');
        delivery.stage(context, request, value, proof);
        const records = staged.get(context); if (!records) throw unavailable('browser');
        records.set(request.id, { proof, invalidated: false, ...(proof.kind === 'tabs' ? { listDigest: hash(responseBytes(request.id, true, value)) } : {}) });
        return value;
      } catch (error) {
        noteFailure(context, request, error);
        const recipient = context.attachment?.id;
        const status = recipient ? queue.status(recipient, request.id) : undefined;
        if (status?.mutation && status.dispatchOutcome === 'outcome_unknown' && !authority.wasClosed(status.target) && phase === 'live') {
          const state = authority.state(status.target);
          if (state.controller.kind === 'agent' && state.controller.client === recipient && state.handoff === 'idle')
            void handoff.take(status.target, state.generation).catch(() => {});
        }
        throw error;
      }
    },
    guardControl(context, kind: ControlFrameKind, bytes) {
      live(); delivery.assertContext(context);
      const value: unknown = JSON.parse(Buffer.from(bytes).toString('utf8'));
      if (kind === 'hello') {
        if (!validator('wire.HelloResult')(value) || value.result.attachment?.id !== context.attachment?.id ||
            value.result.attachment?.label !== context.attachment?.label) throw unavailable('browser');
      } else if (kind === 'ping') { if (!validator('wire.Ping')(value)) throw unavailable('browser'); }
      else {
        if (!validator('wire.Response')(value) || !value.ok) throw unavailable('browser');
        if (kind === 'pong' ? Object.keys(value.result).length !== 0 : !validator('wire.CancelResult')(value.result)) throw unavailable('browser');
      }
      delivery.assertContext(context);
    },
    commitResponse: (context, request, success, bytes) => success ? delivery.commit(context, request, bytes) : delivery.commitFailure(context, request, bytes),
    redactedFailure(context, request, error) {
      let mapped = error;
      const record = staged.get(context)?.get(request.id);
      if (record && error instanceof BrowserFailure && error.detail.code === 'browser_unavailable' && request.method === 'tool') {
        const recipient = client(context), proof = record.proof;
        try {
          if ('stamp' in proof) {
            authority.visible(proof.stamp.target, recipient);
            authority.expected(proof.stamp.target, proof.stamp.generation);
            authority.check(proof.stamp, proof.kind === 'action' || proof.kind === 'opened');
            if (record.invalidated) throw refused('control_changed');
          } else if (proof.kind === 'release' && record.invalidated) {
            authority.visible(proof.receipt.target, recipient);
            authority.verifyTransition(proof.receipt, 'release', recipient, request.id, proof.receipt.target.id, proof.receipt.fromGeneration);
            throw refused('control_changed');
          } else if (proof.kind === 'tabs') {
            const current = projectAgentTabs(tabs(), recipient, id => authority.connected(id));
            if (record.invalidated || hash(responseBytes(request.id, true, current)) !== record.listDigest) throw refused('control_changed');
          }
        } catch (current) {
          if (current instanceof BrowserFailure && ['tab_not_found', 'control_changed', 'stale_snapshot', 'control_refused'].includes(current.detail.code)) mapped = current;
          else throw current;
        }
      }
      return delivery.redactedFailure(context, request, mapped);
    },
    forget(context, request) {
      delivery.forget(context, request); opens.get(context)?.delete(request.id); requests.get(context)?.delete(request.id); staged.get(context)?.delete(request.id);
    },
    disconnect(context) {
      delivery.disconnect(context);
      if (context.attachment) {
        if (runtime) runtime.disconnect(context); else disconnect(context.attachment.id);
      }
      opens.delete(context);
      requests.delete(context);
      staged.delete(context);
    },
    cancel(context, request) {
      live(); delivery.assertContext(context);
      if (context.endpoint === 'management') return; // lookup ACK is not cancellation/rollback proof
      const recipient = client(context), status = queue.status(recipient, request), open = opens.get(context)?.get(request);
      if (open) {
        open.cancelled = true;
        for (const target of open.targets) if (authority.knowsTarget(target) && !authority.wasClosed(target)) {
          const state = authority.state(target);
          if (state.controller.kind === 'agent' && state.controller.client === recipient) void handoff.take(target, state.generation).catch(() => {});
          authority.revoke(target, recipient);
        }
        authority.changed();
      }
      if (status) {
        const original = requests.get(context)?.get(request);
        if (!original) return authority.exhausted();
        if (status.action) delivery.noteOutcome(context, original, { action: status.action, dispatchOutcome: status.dispatchOutcome });
        queue.cancel(recipient, request);
        if (status.mutation && status.dispatchOutcome === 'outcome_unknown' && !authority.wasClosed(status.target)) {
          const state = authority.state(status.target);
          if (state.controller.kind === 'agent' && state.controller.client === recipient)
            void handoff.take(status.target, state.generation).catch(() => {});
        }
      }
    },
    fatal() { phase = 'closed'; return boundary.fatal.fail('native_boundary_unavailable'); },
  });
  return Object.freeze<OwnershipHost>({ authority, lifecycle, shell, control, dispatch,
    bind(registryValue, host, registration) {
      prepared(); assertTabRegistry(registryValue); assertWindowHost(host); assertShellRegistration(registration, host);
      if ((registry && registry !== registryValue) || windows.has(host)) throw unavailable('browser');
      registry = registryValue; everBound = true; windows.set(host, registration);
      host.window.once('closed', () => { windows.delete(host); runtime?.lastWindowClosed(); });
    },
    bindRuntime(value) {
      prepared(); assertHostLifecycle(value);
      if (runtime || value.phase !== 'starting') throw unavailable('browser'); runtime = value;
      if (everBound && control.windowCount() === 0) runtime.lastWindowClosed();
    },
    runEnd(id) { const context = contexts.get(id); if (context && runtime) runtime.disconnect(context); else disconnect(id); },
    async healthFailure(target) {
      live(); const state = authority.state(target); authority.refreshDocument(target);
      if (state.controller.kind === 'agent') await handoff.take(target, state.generation);
      else { authority.invalidate(target); authority.changed(); }
    },
  });
}
