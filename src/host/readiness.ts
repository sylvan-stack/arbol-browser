import type { Debugger, WebContents } from 'electron';
import { performance } from 'node:perf_hooks';
import { assertNativeFailureBoundary, type NativeFailureBoundary } from '../runtime/bootstrap.js';
import { unavailable } from '../contracts/errors.js';
import { bindingKey } from '../native/retirement.js';
import type { DocumentReceipt } from './authority.js';
import type { HostDocuments, HostDocument, DocumentPreparation, PhysicalFrame } from './documents.js';
import { PresentationSuperseded, presentationCategory } from './documents.js';
import { staleSnapshot } from './authority.js';
import { assertPageSurface, type PageSurface } from './windows.js';
import type { TabTarget } from './tabs.js';

export type InspectionMethod = 'Page.getFrameTree' | 'Accessibility.enable' | 'Accessibility.getFullAXTree' |
  'Accessibility.getPartialAXTree' | 'DOMSnapshot.captureSnapshot' | 'DOM.describeNode' | 'DOM.resolveNode' |
  'DOM.getBoxModel' | 'DOM.getNodeForLocation' | 'Page.getLayoutMetrics' | 'Page.captureScreenshot' |
  'Page.setWebLifecycleState' | 'Animation.getPlaybackRate' | 'Animation.setPlaybackRate';
export interface InspectionFrame {
  readonly receipt: HostDocument;
  readonly frameId: string;
  readonly session: string | undefined;
  readonly physical: PhysicalFrame | undefined;
}
export interface InspectionObservation {
  readonly epoch: number;
  readonly sessions: number;
  readonly unknownActivity: boolean;
  readonly resources: number;
  readonly animations: number;
}
interface ChildSession { targetId: string; parent: string | undefined }
interface Channel {
  readonly page: PageSurface;
  readonly contents: WebContents;
  readonly debugger: Debugger;
  readonly identity: object;
  active: boolean;
  interception: 'unknown' | 'enabled' | 'disabled';
  interceptionInFlight?: object;
  inspection?: Promise<void>;
  epoch: number;
  unknownActivity: boolean;
  sessions: Map<string, ChildSession>;
  observers: Set<() => void>;
  resources: Set<string>;
  animations: Set<string>;
  surface?: object;
}
function emptyAck(value: unknown): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length) throw staleSnapshot();
}
/** The supported host's sole per-physical-page CDP owner, never a TCP endpoint,
 * renderer capability or default Tools implementation. */
export class PageReadiness implements DocumentPreparation {
  private readonly channels = new WeakMap<PageSurface, Channel>();
  constructor(readonly boundary: NativeFailureBoundary, readonly documents: HostDocuments) {
    assertNativeFailureBoundary(boundary); if (documents.boundary !== boundary) throw unavailable('browser');
  }
  private native(): void { assertNativeFailureBoundary(this.boundary); }
  private synchronous(assertCurrent: () => void): void {
    const result: unknown = assertCurrent(); if (result !== undefined) return this.boundary.fatal.fail('native_boundary_unavailable');
  }
  channel(page: PageSurface): object {
    this.native(); assertPageSurface(page);
    const existing = this.channels.get(page);
    if (existing) { this.assertChannel(existing); return existing.identity; }
    if (page.retirement()) throw staleSnapshot();
    const contents = page.view.webContents, debugger_ = contents.debugger;
    if (contents.isDestroyed() || debugger_.isAttached()) throw unavailable('browser');
    const channel: Channel = { page, contents, debugger: debugger_, identity: Object.freeze({}), active: true, interception: 'unknown', epoch: 0, unknownActivity: false, sessions: new Map(), observers: new Set(), resources: new Set(), animations: new Set() };
    this.channels.set(page, channel);
    debugger_.on('message', (_event, method, params, sessionId) => {
      if (!channel.active || this.channels.get(page) !== channel) return;
      if (!/^(Target|Page|DOM|Animation|Network|Runtime)\./.test(method)) return;
      if (++channel.epoch >= Number.MAX_SAFE_INTEGER) return this.boundary.fatal.fail('native_boundary_unavailable');
      if (method === 'Target.attachedToTarget') {
        const child = params as { sessionId?: string; targetInfo?: { type?: string; targetId?: string } };
        if (child.sessionId && child.targetInfo?.type === 'iframe' && child.targetInfo.targetId && channel.sessions.size < 256)
          channel.sessions.set(child.sessionId, { targetId: child.targetInfo.targetId, parent: sessionId || undefined });
        else channel.unknownActivity = true;
      } else if (method === 'Target.detachedFromTarget') {
        const child = params as { sessionId?: string };
        if (child.sessionId) channel.sessions.delete(child.sessionId); else channel.unknownActivity = true;
      }
      // Events are invalidations, never proof that pixels/geometry settled.
      if (sessionId && !channel.sessions.has(sessionId)) channel.unknownActivity = true;
      const data = params as { requestId?: string; id?: string; animation?: { id?: string } };
      if (method === 'Network.requestWillBeSent' && data.requestId) channel.resources.add(data.requestId);
      if (['Network.loadingFinished', 'Network.loadingFailed'].includes(method) && data.requestId) channel.resources.delete(data.requestId);
      if (/^Network\.(webSocket|webTransport|eventSource)/.test(method)) channel.unknownActivity = true;
      if (method === 'Animation.animationCreated' && data.id) channel.animations.add(data.id);
      if (method === 'Animation.animationStarted' && data.animation?.id) channel.animations.add(data.animation.id);
      if (method === 'Animation.animationCanceled' && data.id) channel.animations.delete(data.id);
      if (channel.resources.size > 4096 || channel.animations.size > 4096) {
        channel.resources.clear(); channel.animations.clear(); channel.unknownActivity = true;
      }
      for (const notify of channel.observers) notify();
    });
    debugger_.on('detach', () => {
      if (!channel.active) return;
      channel.active = false;
      this.documents.channelLost(page, channel.identity); // literal original page/channel, never target.page
    });
    try { debugger_.attach('1.3'); this.assertChannel(channel); }
    catch (error) { channel.active = false; throw error; }
    return channel.identity;
  }
  private assertChannel(channel: Channel): void {
    this.native();
    if (!channel.active || this.channels.get(channel.page) !== channel || channel.page.retirement() ||
        channel.contents.isDestroyed() || !channel.debugger.isAttached()) throw staleSnapshot();
    const binding = channel.page.binding();
    if (binding.id !== channel.page.identity.id || binding.nonce !== channel.page.identity.nonce ||
        binding.webContentsId !== channel.contents.id || binding.retired) return this.boundary.fatal.fail('native_boundary_unavailable');
  }
  private owned(page: PageSurface): Channel {
    const channel = this.channels.get(page); if (!channel) throw staleSnapshot(); this.assertChannel(channel); return channel;
  }
  /** Host-only callers retain original page/job guards. Result data does not
   * carry authority and is checked again after the actual channel response. */
  async command(page: PageSurface, assertCurrent: () => void, method: string, params?: object, session?: string): Promise<unknown> {
    const channel = this.owned(page);
    const check = () => { this.synchronous(assertCurrent); this.assertChannel(channel); };
    check(); if (session !== undefined && !channel.sessions.has(session)) throw staleSnapshot();
    if (channel.interceptionInFlight) throw staleSnapshot();
    const intercept = method === 'Input.setInterceptDrags', token = Object.freeze({});
    const enabled = (params as { enabled?: unknown } | undefined)?.enabled;
    if (intercept) {
      if (typeof enabled !== 'boolean') throw staleSnapshot();
      // The engine may apply this before a stale/failed reply. Never retain a
      // prior disabled acknowledgement across an ambiguous opposite effect.
      channel.interception = 'unknown'; channel.interceptionInFlight = token;
    }
    try {
      check(); const result: unknown = await channel.debugger.sendCommand(method, params, session); check();
      if (intercept) {
        if (channel.interceptionInFlight !== token) throw staleSnapshot(); emptyAck(result);
        channel.interception = enabled ? 'enabled' : 'disabled';
      }
      return result;
    } finally { if (channel.interceptionInFlight === token) delete channel.interceptionInFlight; }
  }
  private readonly inspectionFrames = new WeakSet<InspectionFrame>();
  /** The debugger is attached to this literal WebContents. Its root is the
   * original owned main frame; CDP child IDs are never Electron frame tokens.
   * Until a child has a physical correlation it is unavailable, even if its
   * URL/name, process or sampled image happens to match. */
  async inspection(receipt: HostDocument, assertCurrent: () => void): Promise<readonly InspectionFrame[]> {
    const channel = this.owned(receipt.page);
    const guard = () => { this.synchronous(assertCurrent); this.documents.target(receipt); this.assertChannel(channel);
      if (receipt.channel !== channel.identity) throw staleSnapshot(); };
    guard();
    if (!channel.inspection) {
      const setup = (async () => {
      for (const method of ['Page.enable', 'DOM.enable', 'Animation.enable', 'Network.enable'])
        emptyAck(await this.command(receipt.page, guard, method));
      emptyAck(await this.command(receipt.page, guard, 'Target.setAutoAttach',
        { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }));
      emptyAck(await this.command(receipt.page, guard, 'Page.setLifecycleEventsEnabled', { enabled: true }));
      })();
      channel.inspection = setup;
      // Only this failed attempt is cleared. Current callers still share the
      // same in-flight work and each caller keeps its own exact receipt guard.
      void setup.catch(() => { if (channel.inspection === setup) delete channel.inspection; });
    }
    await channel.inspection; guard();
    // Re-populate after navigation too; a prior document's mirror is no proof.
    // Data remains private; classification uses its own fresh DOMSnapshot.
    await this.command(receipt.page, guard, 'DOM.getDocument', { depth: -1, pierce: true });
    const result = await this.command(receipt.page, guard, 'Page.getFrameTree') as {
      frameTree?: { frame?: { id?: string }; childFrames?: unknown[] } };
    guard(); const root = result.frameTree?.frame?.id;
    if (!root || receipt.page.view.webContents.mainFrame !== receipt.frame.handle || receipt.frame.handle.parent !== null) throw staleSnapshot();
    const frames: InspectionFrame[] = [];
    const add = (frameId: string, session: string | undefined, physical: PhysicalFrame | undefined) => {
      const frame = Object.freeze({ receipt, frameId, session, physical }); this.inspectionFrames.add(frame); frames.push(frame);
    };
    add(root, undefined, receipt.frame);
    // Keep the flattened routing map distinct from physical authority. Unknown
    // same-process children are represented by the physical census below too.
    for (const [session, child] of channel.sessions) {
      // Target ids are not frame ids either. Query that flattened session's
      // own tree; the result is routing metadata, never physical authority.
      const tree = await this.command(receipt.page, guard, 'Page.getFrameTree', undefined, session) as {
        frameTree?: { frame?: { id?: string } } };
      guard(); if (channel.sessions.get(session) !== child) throw staleSnapshot();
      add(tree.frameTree?.frame?.id ?? '', session, undefined);
    }
    for (const physical of receipt.frames) if (physical !== receipt.frame) add('', undefined, undefined);
    return Object.freeze(frames);
  }
  assertInspection(frame: InspectionFrame, assertCurrent: () => void): void {
    this.synchronous(assertCurrent); this.documents.target(frame.receipt);
    const channel = this.owned(frame.receipt.page);
    if (!this.inspectionFrames.has(frame) || frame.receipt.channel !== channel.identity || !frame.physical ||
        !frame.receipt.frames.includes(frame.physical) || frame.physical !== frame.receipt.frame || frame.session !== undefined)
      throw staleSnapshot();
  }
  async inspect(frame: InspectionFrame, assertCurrent: () => void, method: InspectionMethod, params?: object): Promise<unknown> {
    const guard = () => this.assertInspection(frame, assertCurrent);
    guard(); const value = await this.command(frame.receipt.page, guard, method, params, frame.session); guard(); return value;
  }
  observation(receipt: HostDocument): InspectionObservation {
    this.documents.target(receipt); const channel = this.owned(receipt.page);
    if (channel.identity !== receipt.channel) throw staleSnapshot();
    return Object.freeze({ epoch: channel.epoch, sessions: channel.sessions.size, unknownActivity: channel.unknownActivity,
      resources: channel.resources.size, animations: channel.animations.size });
  }
  observeInspection(receipt: HostDocument, notify: () => void): () => void {
    this.documents.target(receipt); const channel = this.owned(receipt.page);
    if (channel.identity !== receipt.channel) throw staleSnapshot();
    channel.observers.add(notify); return () => { channel.observers.delete(notify); };
  }
  /** A real compositor observation, scoped to the original page. This is an
   * invalidation epoch only: it is not a layout-coupled screenshot token. */
  watchSurface(receipt: HostDocument, guard: () => void): {
    sample(): Readonly<{ epoch: number; width: number; height: number }>;
    close(): void;
  } {
    const channel = this.owned(receipt.page); this.synchronous(guard); this.documents.target(receipt);
    if (channel.surface || channel.identity !== receipt.channel) throw staleSnapshot();
    const token = Object.freeze({}); channel.surface = token;
    let epoch = 0, width = 0, height = 0, valid = true;
    try {
      channel.contents.beginFrameSubscription(true, image => {
        if (channel.surface !== token || !channel.active) return;
        try {
          this.documents.target(receipt); this.assertChannel(channel);
          const size = image.getSize();
          if (image.isEmpty() || size.width <= 0 || size.height <= 0 || ++epoch >= Number.MAX_SAFE_INTEGER) valid = false;
          width = size.width; height = size.height;
        } catch { valid = false; }
      });
    } catch (error) { if (channel.surface === token) delete channel.surface; throw error; }
    return Object.freeze({ sample: () => {
      this.synchronous(guard); this.documents.target(receipt); this.assertChannel(channel);
      if (!valid || channel.surface !== token || epoch < 1) throw staleSnapshot();
      return Object.freeze({ epoch, width, height });
    }, close: () => {
      if (channel.surface !== token) return;
      delete channel.surface; valid = false;
      if (!channel.contents.isDestroyed()) channel.contents.endFrameSubscription();
    } });
  }
  private async deadline<T>(deadline: number, assertCurrent: () => void, work: (check: () => void) => Promise<T>): Promise<T> {
    let active = true, timer: ReturnType<typeof setTimeout> | undefined;
    const check = () => {
      if (!active || performance.now() >= deadline) throw staleSnapshot(); this.synchronous(assertCurrent);
    };
    try {
      check(); const running = work(check);
      return await Promise.race([running, new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { active = false; reject(staleSnapshot()); }, Math.max(1, deadline - performance.now()));
      })]);
    } finally { active = false; if (timer) clearTimeout(timer); }
  }
  async ping(receipt: HostDocument, assertCurrent: () => void): Promise<void> {
    const channel = this.owned(receipt.page);
    const check = () => {
      this.synchronous(assertCurrent); this.assertChannel(channel); this.documents.target(receipt);
      if (channel.identity !== receipt.channel) throw staleSnapshot();
    };
    check();
    // A literal expression proves service of the actual frame execution queue;
    // no website function, page-supplied boolean or privileged IPC is trusted.
    await Promise.all(receipt.frames.map(async frame => {
      check(); const result = await frame.handle.executeJavaScript('0', false); check();
      if (result !== 0) throw staleSnapshot();
    }));
    check();
  }
  private async observe(receipt: HostDocument, check: () => void): Promise<void> {
    const page = receipt.page, channel = this.owned(page), host = page.window;
    const category = presentationCategory(page), selected = host.selected() === page, visible = page.view.getVisible();
    const presented = selected && visible && host.window.isVisible() && !host.window.isMinimized();
    const guard = () => {
      check(); this.documents.target(receipt); this.assertChannel(channel);
      if (channel.identity !== receipt.channel) throw staleSnapshot();
      if (presentationCategory(page) !== category) throw new PresentationSuperseded();
    };
    guard();
    if (presented) {
      const before = page.binding(); page.restorePresentation(); const after = page.binding(); guard();
      if (before.id !== after.id || before.nonce !== after.nonce || before.revision !== after.revision ||
          before.blocked !== after.blocked || after.retired) return this.boundary.fatal.fail('native_boundary_unavailable');
    } else if (!selected && visible) throw staleSnapshot(); // Never expose an inactive view to repair it.
    emptyAck(await this.command(page, guard, 'Emulation.setFocusEmulationEnabled', { enabled: true }));
    if (channel.interception === 'unknown')
      await this.command(page, guard, 'Input.setInterceptDrags', { enabled: false });
    guard(); await this.ping(receipt, guard); guard();
    // A separate isolated world cannot use a website-replaced RAF/readiness
    // function. Native DOM events schedule this; actual current DOM readiness
    // and two frame callbacks independently confirm the current document.
    const result: unknown = await channel.contents.executeJavaScriptInIsolatedWorld(999, [{ code:
      'new Promise((resolve,reject)=>{if(document.readyState==="loading"){reject(new Error("loading"));return;}requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(0)));})' }], false);
    guard(); if (result !== 0) throw staleSnapshot();
    const image = await channel.contents.capturePage(undefined, { stayHidden: true, stayAwake: false });
    guard(); const size = image.getSize();
    if (image.isEmpty() || size.width <= 0 || size.height <= 0) throw staleSnapshot();
    // Native policy/readiness remain separate. This queries the exact owned
    // binding; it neither fabricates quiescence nor unlocks an active gesture.
    const binding = page.binding();
    this.boundary.native.ownership.interactionState(bindingKey(binding)); guard();
  }
  async barrier(receipt: HostDocument, deadline: number, assertCurrent: () => void): Promise<void> {
    await this.deadline(Math.min(deadline, performance.now() + 2000), assertCurrent, async check => {
      for (;;) {
        try { await this.observe(receipt, check); return; }
        catch (error) {
          if (!(error instanceof PresentationSuperseded)) throw error;
          check(); // A fresh category observation stays inside this same 2 s job.
        }
      }
    });
  }
  async leaveAgentMode(target: TabTarget, document: DocumentReceipt, deadline: number, assertCurrent: () => void): Promise<void> {
    await this.deadline(deadline, assertCurrent, async check => {
      this.documents.assertCurrent(target, document);
      const receipt = document as HostDocument, channel = this.owned(receipt.page);
      const guard = () => { check(); this.documents.assertCurrent(target, receipt); this.assertChannel(channel);
        if (receipt.channel !== channel.identity) throw staleSnapshot(); };
      guard();
      // disabled is retained only after a real acknowledgement on this channel.
      if (channel.interception !== 'disabled') await this.command(receipt.page, guard, 'Input.setInterceptDrags', { enabled: false });
      guard();
    });
  }
  close(page: PageSurface): void {
    const channel = this.channels.get(page); if (!channel || !channel.active) return;
    channel.active = false; // before detach callbacks can reenter
    if (!channel.contents.isDestroyed() && channel.debugger.isAttached()) channel.debugger.detach();
  }
}
