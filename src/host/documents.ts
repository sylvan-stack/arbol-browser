import { webContents, webFrameMain, type WebFrameMain, type WebContents } from 'electron';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, unavailable } from '../contracts/errors.js';
import { assertNativeFailureBoundary, type NativeFailureBoundary } from '../runtime/bootstrap.js';
import { TabAuthority, staleSnapshot, type DocumentAuthority, type DocumentReceipt } from './authority.js';
import { issuedNavigation, type ActionExecution, type IssuedNavigation } from './actions.js';
import { assertPageSurface, type PageSurface } from './windows.js';
import { refused, userURL, type TabTarget } from './tabs.js';

export interface PhysicalFrame {
  readonly handle: WebFrameMain;
  readonly process: number;
  readonly osProcess: number;
  readonly routing: number;
  readonly token: string;
  readonly node: number;
}
export interface HostDocument extends DocumentReceipt {
  readonly binding: PageSurface['identity'];
  readonly frame: PhysicalFrame;
  readonly renderer: Readonly<{ process: number; osProcess: number }>;
  readonly frames: readonly PhysicalFrame[];
  readonly channel: object;
}
export interface DocumentFault {
  readonly target: TabTarget;
  readonly page: PageSurface;
  readonly availability: 'unresponsive' | 'crashed' | 'unavailable';
  readonly reason: string;
}
/** Real implementation is supplied by readiness.ts. No successful fallback. */
export interface DocumentPreparation {
  channel(page: PageSurface): object;
  barrier(receipt: HostDocument, deadline: number, assertCurrent: () => void): Promise<void>;
  ping(receipt: HostDocument, assertCurrent: () => void): Promise<void>;
  command(page: PageSurface, assertCurrent: () => void, method: string, params?: object): Promise<unknown>;
  close(page: PageSurface): void;
}
export interface DocumentEvent {
  readonly target: TabTarget;
  readonly page: PageSurface;
  readonly kind: 'changed' | 'ready' | 'closed' | 'suspect';
  readonly receipt?: HostDocument;
}
/** Ordinary selection can supersede a presentation job without a renderer fault. */
export class PresentationSuperseded extends Error {}
export function presentationCategory(page: PageSurface): string {
  const host = page.window;
  return `${host.selected() === page}:${page.view.getVisible()}:${host.window.isVisible() && !host.window.isMinimized()}`;
}
interface EpochState { valid: boolean; ready: boolean; availability: Contract<'browser.Availability'> }
interface Job { active: boolean; controller: AbortController }
interface Ticket {
  issued: IssuedNavigation; original: HostDocument; execution: ActionExecution; candidate?: HostDocument; commits: number; starts: number;
}
interface PageRecord {
  target: TabTarget; page: PageSurface; contents: WebContents; use: object; channel: object; closed: boolean;
  current?: HostDocument; state?: EpochState; barrier?: Job; load?: Job; ticket?: Ticket;
  committed: boolean; mainDOM: boolean; lastSafeURL: string; startHTTPS: boolean; redirects: number;
  fault?: DocumentFault; stopped?: Readonly<{ page: PageSurface; renderer: HostDocument['renderer']; reason: string }>;
  listeners: (() => void)[];
  presentation: string;
  presentationPending?: boolean;
  barrierDeadline?: number;
}
function navigationFailed(): BrowserFailure {
  return new BrowserFailure({ code: 'navigation_failed', message: 'The page did not complete its current navigation.', retryable: true,
    remedy: 'Read the current page state before another explicit navigation or recovery.' });
}
function sameFrame(a: PhysicalFrame, b: PhysicalFrame): boolean {
  return a.handle === b.handle && a.process === b.process && a.osProcess === b.osProcess && a.routing === b.routing &&
    a.token === b.token && a.node === b.node;
}
/** WebFrameMain can change its underlying RFH in place. Copy every physical
 * identity; the wrapper itself and a URL are insufficient lifetime evidence. */
export function physicalFrames(page: PageSurface): readonly PhysicalFrame[] {
  const contents = page.view.webContents;
  if (page.retirement() || !contents || contents.isDestroyed() || contents.isCrashed()) throw staleSnapshot();
  const main = contents.mainFrame, frames = main.framesInSubtree;
  if (!frames.length || !frames.includes(main)) throw staleSnapshot();
  return Object.freeze(frames.map(handle => {
    if (handle.isDestroyed() || handle.detached || webContents.fromFrame(handle) !== contents ||
        (handle !== main && handle.top !== main)) throw staleSnapshot();
    const value = Object.freeze({ handle, process: handle.processId, osProcess: handle.osProcessId,
      routing: handle.routingId, token: handle.frameToken, node: handle.frameTreeNodeId });
    if (value.process < 0 || value.osProcess <= 0 || value.routing < 0 || !value.token || value.node < 0 ||
        webFrameMain.fromFrameToken(value.process, value.token) !== handle) throw staleSnapshot();
    return value;
  }));
}
/** Canonical main-process producer. bind must receive actual ownership and the
 * real preparation adapter before any page can be watched or prepared. */
export class HostDocuments implements DocumentAuthority {
  private owner?: TabAuthority;
  private preparation?: DocumentPreparation;
  private onFault?: (fault: DocumentFault) => void;
  private readonly records = new Map<TabTarget, PageRecord>();
  private readonly receipts = new WeakMap<DocumentReceipt, { record: PageRecord; state: EpochState }>();
  private readonly faults = new WeakMap<DocumentFault, PageRecord>();
  private readonly epochs = new WeakMap<TabTarget, number>();
  private readonly issued = new Set<string>();
  private readonly subscribers = new Set<(event: DocumentEvent) => void>();
  private readonly successors = new WeakMap<DocumentReceipt, Ticket>();
  constructor(readonly boundary: NativeFailureBoundary) { assertNativeFailureBoundary(boundary); }
  bind(owner: TabAuthority, preparation: DocumentPreparation, onFault: (fault: DocumentFault) => void): void {
    if (this.owner || owner.documents !== this) throw unavailable('browser');
    assertNativeFailureBoundary(this.boundary);
    this.owner = owner; this.preparation = preparation; this.onFault = onFault;
  }
  private authority(): TabAuthority { if (!this.owner || !this.preparation || !this.onFault) throw unavailable('browser'); return this.owner; }
  private synchronous(work: () => void): void {
    try { const value: unknown = work(); if (value !== undefined) return this.boundary.fatal.fail('native_boundary_unavailable'); }
    catch { return this.boundary.fatal.fail('native_boundary_unavailable'); }
  }
  subscribe(receive: (event: DocumentEvent) => void): () => void {
    this.subscribers.add(receive); return () => { this.subscribers.delete(receive); };
  }
  private emit(record: PageRecord, kind: DocumentEvent['kind']): void {
    const event = Object.freeze({ target: record.target, page: record.page, kind,
      ...(record.current ? { receipt: record.current } : {}) });
    for (const receive of this.subscribers) this.synchronous(() => receive(event));
  }
  private isOriginal(record: PageRecord): boolean {
    return !record.closed && this.records.get(record.target) === record && record.target.page === record.page;
  }
  private alive(record: PageRecord): boolean {
    return this.isOriginal(record) && !record.page.retirement() && !record.contents.isDestroyed();
  }
  private poisonEpoch(record: PageRecord): readonly Job[] {
    // Reentrant AbortSignal listeners are notified only after authority closes.
    if (record.state) { record.state.ready = false; record.state.availability = record.fault?.availability ?? 'unavailable'; }
    const jobs = record.barrier ? [record.barrier] : [];
    for (const job of jobs) job.active = false;
    delete record.barrier; return jobs;
  }
  private abortJobs(jobs: readonly Job[]): void { for (const job of jobs) job.controller.abort(); }
  private suspend(record: PageRecord, preserve = false): void {
    const jobs = this.poisonEpoch(record);
    if (!preserve) { delete record.ticket; this.authority().suspendDocument(record.target); }
    this.abortJobs(jobs);
    this.emit(record, 'changed'); this.authority().changed();
  }
  private capture(record: PageRecord): HostDocument {
    const frames = physicalFrames(record.page), frame = frames.find(value => value.handle.parent === null);
    if (!frame) throw staleSnapshot();
    if (record.state) { record.state.valid = false; record.state.ready = false; record.state.availability = 'unavailable'; }
    const epoch = (this.epochs.get(record.target) ?? 0) + 1;
    if (!Number.isSafeInteger(epoch)) return this.authority().exhausted(); this.epochs.set(record.target, epoch);
    const navigation = `nav_${randomBytes(16).toString('base64url')}`;
    if (this.issued.size >= 1000000 || this.issued.has(navigation)) return this.authority().exhausted(); this.issued.add(navigation);
    const state: EpochState = { valid: true, ready: false, availability: record.fault?.availability ?? 'unavailable' };
    delete record.barrierDeadline; // A genuinely new logical document owns a new bounded barrier.
    const receipt: HostDocument = Object.freeze({ page: record.page, binding: record.page.identity, frame, frames,
      renderer: Object.freeze({ process: frame.process, osProcess: frame.osProcess }), document: Object.freeze({}),
      epoch, navigation, channel: record.channel,
      get availability() { return state.availability; }, get ready() { return state.valid && state.ready; } });
    this.receipts.set(receipt, { record, state }); record.current = receipt; record.state = state; return receipt;
  }
  private frameEvent(record: PageRecord, process: number, routing: number): boolean {
    if (!this.alive(record)) return false;
    const frame = webFrameMain.fromId(process, routing);
    return Boolean(frame && !frame.isDestroyed() && !frame.detached && webContents.fromFrame(frame) === record.page.view.webContents &&
      record.page.view.webContents.mainFrame.framesInSubtree.includes(frame));
  }
  watch(target: TabTarget): void {
    this.authority(); assertPageSurface(target.page);
    const previous = this.records.get(target);
    if (previous?.page === target.page && !previous.closed) return;
    if (previous) this.close(target, previous.page);
    const page = target.page, contents = page.view.webContents;
    const record: PageRecord = { target, page, contents, use: Object.freeze({}), channel: this.preparation!.channel(page), closed: false,
      committed: false, mainDOM: false, lastSafeURL: previous?.lastSafeURL ?? 'about:blank', startHTTPS: false, redirects: 0,
      listeners: [], presentation: presentationCategory(page) };
    this.records.set(target, record);
    const on = <K extends string>(name: K, receive: (...args: any[]) => void) => {
      contents.on(name as never, receive); record.listeners.push(() => contents.removeListener(name as never, receive));
    };
    const committed = (process: number, routing: number, main: boolean, address: string, sameDocument: boolean) => {
      if (!this.frameEvent(record, process, routing) || record.fault) return;
      let safe: string; try { safe = userURL(address); } catch { this.failPage(target, page, 'unavailable', 'navigation_policy'); return; }
      const jobs = this.poisonEpoch(record);
      if (main) { record.committed = true; if (sameDocument) record.mainDOM = true; record.lastSafeURL = safe; }
      const receipt = this.capture(record), ticket = record.ticket;
      if (ticket && !sameDocument && ticket.commits === 0) {
        if (main) { ticket.commits++; ticket.candidate = receipt; }
      }
      else { delete record.ticket; this.authority().suspendDocument(target); this.authority().refreshDocument(target); }
      this.abortJobs(jobs);
      this.emit(record, 'changed'); this.authority().changed();
      if (!record.ticket) this.schedule(record);
    };
    on('did-start-navigation', (details: Electron.Event<Electron.WebContentsDidStartNavigationEventParams>) => {
      if (!this.alive(record) || record.fault) return;
      // A frame-bearing event must belong to this exact WebContents, including OOPIFs.
      if (details.frame && webContents.fromFrame(details.frame) !== contents) return;
      if (details.isMainFrame) {
        record.startHTTPS = details.url.startsWith('https:'); record.redirects = 0;
        if (!details.isSameDocument) { record.committed = false; record.mainDOM = false; }
      }
      const ticket = record.ticket;
      const preserve = Boolean(!details.isSameDocument && ticket && ticket.commits === 0 &&
        (details.isMainFrame ? ++ticket.starts === 1 : details.frame && webContents.fromFrame(details.frame) === contents));
      this.suspend(record, preserve);
    });
    on('did-frame-navigate', (_event: unknown, address: string, _code: number, _text: string, main: boolean, process: number, routing: number) =>
      committed(process, routing, main, address, false));
    on('did-navigate-in-page', (_event: unknown, address: string, main: boolean, process: number, routing: number) =>
      committed(process, routing, main, address, true));
    on('dom-ready', () => {
      if (!this.alive(record) || record.fault || !record.committed) return;
      record.mainDOM = true; this.schedule(record);
    });
    on('frame-created', (_event: unknown, details: Electron.FrameCreatedDetails) => {
      const frame = details.frame;
      if (!this.alive(record) || !frame || frame.isDestroyed() || frame.detached || webContents.fromFrame(frame) !== contents) return;
      // A new child/RFH is a reference boundary. Its wrapper may later retarget.
      const preserve = Boolean(record.ticket && record.ticket.commits === 0);
      this.suspend(record, preserve); try { this.capture(record); } catch { return; }
      this.schedule(record);
    });
    on('will-redirect', (event: Electron.Event, address: string) => {
      if (!this.alive(record)) { event.preventDefault(); return; }
      try {
        const safe = userURL(address), state = this.authority().state(target);
        if (state.controller.kind === 'agent' && (++record.redirects > 20 || (record.startHTTPS && safe.startsWith('http:')))) throw navigationFailed();
      } catch { event.preventDefault(); this.failPage(target, page, 'unavailable', 'navigation_policy'); }
    });
    on('did-fail-load', (_event: unknown, code: number, _description: string, _address: string, main: boolean, process: number, routing: number) => {
      if (!main || code === -3 || !this.alive(record) || !this.frameEvent(record, process, routing)) return;
      this.failPage(target, page, 'unavailable', 'navigation_failed');
    });
    on('render-process-gone', (_event: unknown, details: Electron.RenderProcessGoneDetails) => {
      if (!this.alive(record)) return;
      // The pinned event is asynchronous and has no renderer id. Authenticate
      // actual current crash state; a late event cannot poison a new live RFH.
      if (!contents.isCrashed()) return;
      if (record.current) record.stopped = Object.freeze({ page, renderer: record.current.renderer, reason: details.reason });
      this.failPage(target, page, 'crashed', details.reason);
    });
    on('unresponsive', () => {
      // This event has no renderer/epoch identity. Ask the one owned heartbeat
      // job for a fresh challenge, never treat a delayed label as authority.
      if (this.alive(record) && !contents.isCrashed()) this.emit(record, 'suspect');
    });
    on('destroyed', () => { if (this.isOriginal(record)) this.close(target, page); });
    try { this.capture(record); } catch { /* New view has no document yet; never mint readiness. */ }
    this.emit(record, 'changed');
  }
  current(target: TabTarget): HostDocument {
    const record = this.records.get(target);
    if (!record || !this.alive(record) || record.fault) throw staleSnapshot();
    if (!record.page.window.presentationStable()) throw staleSnapshot();
    if (record.current) {
      const frames = physicalFrames(record.page), before = record.current.frames;
      if (frames.length !== before.length || frames.some((value, index) => !before[index] || !sameFrame(value, before[index]!))) {
        // A stale heartbeat/read can race the quarantined native commit. It
        // gets no document, but cannot claim or revoke that command's result.
        if (record.ticket) throw staleSnapshot();
        this.suspend(record); this.capture(record); this.schedule(record);
      }
    }
    if (!record.current) throw staleSnapshot(); return record.current;
  }
  assertCurrent(target: TabTarget, receipt: DocumentReceipt): void {
    const value = this.receipts.get(receipt), record = value?.record;
    if (!value || !record || record.target !== target || !value.state.valid || this.current(target) !== receipt ||
        record.channel !== (receipt as HostDocument).channel) throw staleSnapshot();
    const binding = record.page.binding();
    if (binding.retired || binding.id !== record.page.identity.id || binding.nonce !== record.page.identity.nonce ||
        binding.webContentsId !== record.page.identity.webContentsId) return this.authority().exhausted();
  }
  private schedule(record: PageRecord): void {
    if (!this.alive(record) || record.fault || !record.current || !record.committed || !record.mainDOM || record.ticket || record.barrier) return;
    const receipt = record.current, generation = this.authority().state(record.target).generation;
    const job: Job = { active: true, controller: new AbortController() }; record.barrier = job;
    const deadline = record.barrierDeadline ?? performance.now() + 2000;
    record.barrierDeadline = deadline;
    const guard = () => {
      if (!job.active || job.controller.signal.aborted || record.barrier !== job || performance.now() >= deadline || record.fault)
        throw staleSnapshot();
      this.authority().expected(record.target, generation); this.assertCurrent(record.target, receipt);
    };
    void this.preparation!.barrier(receipt, deadline, guard).then(() => {
      if (!job.active || record.barrier !== job) return;
      try { guard(); } catch { job.active = false; if (record.barrier === job) delete record.barrier; return; }
      job.active = false; delete record.barrier;
      record.state!.ready = true; record.state!.availability = 'ready';
      this.emit(record, 'ready'); // actual ownership adapter performs the checked native policy publication
    }, error => {
      const current = job.active && record.barrier === job && this.alive(record) && record.current === receipt;
      job.active = false; if (record.barrier === job) delete record.barrier;
      if (error instanceof PresentationSuperseded) return;
      if (current) {
        try { this.authority().expected(record.target, generation); } catch { return; }
        this.failPage(record.target, record.page, 'unavailable', 'readiness_failed');
      }
    }).catch(() => this.boundary.fatal.fail('native_boundary_unavailable'));
  }
  async prepare(target: TabTarget, address: string, context: { readonly signal: AbortSignal; assertCurrent(): void }): Promise<void> {
    this.watch(target); const record = this.records.get(target)!;
    const deadline = performance.now() + 15000;
    await this.navigateUser(target, address, { ...context, deadline });
  }
  async navigateUser(target: TabTarget, address: string | 'back' | 'forward' | 'reload',
    context: { readonly signal: AbortSignal; readonly deadline: number; assertCurrent(): void }): Promise<void> {
    const record = this.records.get(target);
    if (!record || !this.alive(record) || record.fault || record.load) throw refused('control_refused');
    const job: Job = { active: true, controller: new AbortController() }; record.load = job;
    const guard = () => {
      const result: unknown = context.assertCurrent(); if (result !== undefined) return this.authority().exhausted();
      if (!job.active || context.signal.aborted || record.load !== job || !this.alive(record) || record.fault ||
          performance.now() >= context.deadline) throw navigationFailed();
    };
    let unsubscribe = () => {}, abort = () => {}, timer: ReturnType<typeof setTimeout> | undefined;
    try {
      guard(); this.suspend(record); guard();
      const complete = new Promise<void>((resolve, reject) => {
        unsubscribe = this.subscribe(event => {
          if (event.target !== target || event.page !== record.page) return;
          try { guard(); if (event.kind === 'ready') resolve(); } catch (error) { reject(error); }
        });
        timer = setTimeout(() => { job.active = false; reject(navigationFailed()); }, Math.max(1, context.deadline - performance.now()));
        abort = () => { job.active = false; reject(refused('control_changed')); };
        context.signal.addEventListener('abort', abort, { once: true });
      });
      void complete.catch(() => {});
      const contents = record.contents;
      guard();
      if (address === 'back' || address === 'forward') {
        const history = contents.navigationHistory;
        if (address === 'back' ? !history.canGoBack() : !history.canGoForward()) throw navigationFailed();
        if (address === 'back') history.goBack(); else history.goForward();
      } else if (address === 'reload') contents.reload();
      else {
        const loading = contents.loadURL(userURL(address));
        void loading.catch(() => { if (job.active && this.alive(record) && record.load === job) this.failPage(target, record.page, 'unavailable', 'navigation_failed'); });
      }
      await complete; guard(); this.assertCurrent(target, this.current(target));
    } finally {
      job.active = false; if (record.load === job) delete record.load; unsubscribe(); if (timer) clearTimeout(timer);
      context.signal.removeEventListener('abort', abort);
    }
  }
  /** Later Tools can call this real producer only with the actual issued
   * ActionExecution. A missing loader id (same-document Page.navigate) refuses
   * causal successor proof while the actual commit still invalidates identity. */
  async navigateAction(execution: ActionExecution, address: string): Promise<HostDocument> {
    const owner = this.authority(), target = execution.stamp.target, record = this.records.get(target);
    const original = this.current(target); this.assertCurrent(target, original); address = userURL(address);
    if (!record || record.ticket || execution.stamp.document !== original) throw staleSnapshot();
    return execution.dispatch(async () => {
      const issued = issuedNavigation(execution, owner), ticket: Ticket = { issued, original, execution, commits: 0, starts: 0 };
      issued.assertCurrent(); record.ticket = ticket; const jobs = this.poisonEpoch(record);
      owner.provisionalNavigation(issued.token, issued.command);
      this.abortJobs(jobs);
      const guard = () => { issued.assertCurrent(); if (!this.alive(record) || record.ticket !== ticket || record.fault) throw staleSnapshot(); };
      try {
        guard();
        const result = await this.preparation!.command(record.page, guard, 'Page.navigate', { url: address }) as { frameId?: string; loaderId?: string; errorText?: string; isDownload?: boolean };
        guard();
        if (!result.loaderId || !result.frameId || result.errorText || result.isDownload)
          throw navigationFailed();
        // Pinned transport can deliver the response before or after the native
        // commit. Keep the same genuine issued slot until both are available.
        await this.waitCandidate(record, ticket, guard);
        const candidate = ticket.candidate;
        if (!candidate || ticket.commits !== 1) throw navigationFailed();
        const tree = await this.preparation!.command(record.page, guard, 'Page.getFrameTree') as { frameTree?: { frame?: { id?: string; loaderId?: string } } };
        guard(); this.assertCurrent(target, candidate);
        if (tree.frameTree?.frame?.id !== result.frameId || tree.frameTree?.frame?.loaderId !== result.loaderId) throw staleSnapshot();
        this.successors.set(candidate, ticket); owner.acceptNavigation(issued.token, candidate);
        delete record.ticket; this.schedule(record);
        await this.waitReady(target, candidate, execution.signal, execution.deadline, () => issued.assertCurrent());
        return candidate;
      } catch (error) {
        if (record.ticket === ticket) { delete record.ticket; this.suspend(record); }
        throw error;
      }
    });
  }
  private async waitCandidate(record: PageRecord, ticket: Ticket, guard: () => void): Promise<void> {
    let remove = () => {}, timer: ReturnType<typeof setTimeout> | undefined;
    try {
      guard(); if (ticket.candidate) return;
      await new Promise<void>((resolve, reject) => {
        const inspect = () => {
          try { guard(); if (ticket.candidate && ticket.commits === 1) resolve(); } catch (error) { reject(error); }
        };
        remove = this.subscribe(event => { if (event.target === record.target) inspect(); });
        timer = setTimeout(() => reject(staleSnapshot()), Math.max(1, ticket.execution.deadline - performance.now())); inspect();
      });
      guard();
    } finally { remove(); if (timer) clearTimeout(timer); }
  }
  async waitReady(target: TabTarget, receipt: HostDocument, signal: AbortSignal, deadline: number, assertJob: () => void): Promise<void> {
    let remove = () => {}, abort = () => {}, timer: ReturnType<typeof setTimeout> | undefined;
    const check = () => {
      const result: unknown = assertJob(); if (result !== undefined) return this.authority().exhausted();
      if (signal.aborted || performance.now() >= deadline) throw staleSnapshot(); this.assertCurrent(target, receipt);
    };
    try {
      check(); if (receipt.ready) return;
      await new Promise<void>((resolve, reject) => {
        const inspect = () => { try { check(); if (receipt.ready) resolve(); } catch (error) { reject(error); } };
        remove = this.subscribe(event => { if (event.target === target) inspect(); });
        abort = () => reject(staleSnapshot()); signal.addEventListener('abort', abort, { once: true });
        timer = setTimeout(() => reject(staleSnapshot()), Math.max(1, deadline - performance.now())); inspect();
      });
      check();
    } finally { remove(); signal.removeEventListener('abort', abort); if (timer) clearTimeout(timer); }
  }
  assertSuccessor(target: TabTarget, original: DocumentReceipt, successor: DocumentReceipt, action: string, operation: string): void {
    const ticket = this.successors.get(successor);
    if (!ticket || ticket.original !== original || ticket.candidate !== successor || ticket.execution.action !== action ||
        ticket.issued.operation !== operation || ticket.execution.stamp.target !== target || ticket.commits !== 1) throw staleSnapshot();
    ticket.issued.assertCurrent(); this.assertCurrent(target, successor);
  }
  failPage(target: TabTarget, page: PageSurface, availability: DocumentFault['availability'], reason: string): DocumentFault | undefined {
    const record = this.records.get(target);
    if (!record || record.page !== page || !this.isOriginal(record)) return;
    if (record.fault?.availability === 'crashed' || (record.fault && availability !== 'crashed')) return record.fault;
    const fault = Object.freeze({ target, page, availability, reason }); record.fault = fault; this.faults.set(fault, record);
    const jobs = [...this.poisonEpoch(record), ...(record.load ? [record.load] : [])];
    for (const job of jobs) job.active = false;
    delete record.ticket;
    // No live-frame access is needed to poison a genuinely vanished original.
    this.synchronous(() => this.onFault!(fault)); this.abortJobs(jobs); this.emit(record, 'changed'); return fault;
  }
  assertFault(target: TabTarget, fault: DocumentFault): void {
    const record = this.faults.get(fault);
    if (!record || record.target !== target || record.page !== fault.page || record.fault !== fault || !this.isOriginal(record)) throw staleSnapshot();
  }
  target(receipt: HostDocument): TabTarget {
    const value = this.receipts.get(receipt); if (!value) throw staleSnapshot();
    this.assertCurrent(value.record.target, receipt); return value.record.target;
  }
  channelLost(page: PageSurface, channel: object): void {
    for (const record of this.records.values()) if (record.page === page && record.channel === channel && this.alive(record))
      this.failPage(record.target, page, 'unavailable', 'debugger_detached');
  }
  fencePresentation(page: PageSurface): void {
    for (const record of this.records.values()) if (record.page === page && this.alive(record) && !record.fault) {
      // Only a completed real proof can open a fresh presentation budget.
      // Repeated in-flight category changes retain the original absolute time.
      if (record.state?.ready) delete record.barrierDeadline;
      record.presentationPending = true;
      const jobs = this.poisonEpoch(record);
      if (!record.ticket) this.authority().suspendDocument(record.target);
      this.abortJobs(jobs); // no changed/state publication inside placement
    }
  }
  presentationChanged(page: PageSurface): void {
    for (const record of this.records.values()) if (record.page === page && this.alive(record) && !record.fault && record.presentationPending) {
      record.presentationPending = false; record.presentation = presentationCategory(page);
      this.emit(record, 'changed'); this.authority().changed(); this.schedule(record);
    }
  }
  failure(target: TabTarget): DocumentFault | undefined { return this.records.get(target)?.fault; }
  lastSafeURL(target: TabTarget): string { const record = this.records.get(target); if (!record) throw staleSnapshot(); return record.lastSafeURL; }
  stopped(target: TabTarget, page: PageSurface): PageRecord['stopped'] {
    const record = this.records.get(target); return record?.page === page ? record.stopped : undefined;
  }
  close(target: TabTarget, page: PageSurface): void {
    const record = this.records.get(target); if (!record || record.page !== page || record.closed) return;
    record.closed = true;
    const jobs = [...this.poisonEpoch(record), ...(record.load ? [record.load] : [])];
    for (const job of jobs) job.active = false;
    if (record.state) record.state.valid = false; delete record.ticket;
    this.abortJobs(jobs);
    for (const remove of record.listeners.splice(0)) remove();
    this.preparation!.close(page); this.emit(record, 'closed');
  }
  closeAll(): void { for (const record of this.records.values()) this.close(record.target, record.page); }
}
