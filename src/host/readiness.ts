import type { Debugger, WebContents } from 'electron';
import { performance } from 'node:perf_hooks';
import { assertNativeFailureBoundary, type NativeFailureBoundary } from '../runtime/bootstrap.js';
import { unavailable } from '../contracts/errors.js';
import { bindingKey } from '../native/retirement.js';
import type { DocumentReceipt } from './authority.js';
import type { HostDocuments, HostDocument, DocumentPreparation, PhysicalFrame } from './documents.js';
import { PresentationSuperseded, presentationCategory, physicalFrames } from './documents.js';
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
export interface ActionDragData {
  readonly items: readonly Readonly<{ mimeType: string; data: string; title?: string; baseURL?: string }>[];
  readonly dragOperationsMask: number;
}
/** Closed host-private projections. No arbitrary debugger event or renderer
 * object crosses this port. Context identity still needs action-side matching. */
export type ActionEvent =
  | Readonly<{ kind: 'context'; id: number; unique: string; name: string; frame: string; default: boolean }>
  | Readonly<{ kind: 'destroyed'; id: number; unique: string }>
  | Readonly<{ kind: 'cleared' | 'lost' }>
  | Readonly<{ kind: 'binding'; name: string; payload: string; context: number }>
  | Readonly<{ kind: 'drag'; data: ActionDragData }>;
interface ActionObserver { session: string | undefined; frame: InspectionFrame; check(): void;
  receive(event: ActionEvent): void; close(): void }
type FrameScalars = Readonly<Pick<PhysicalFrame, 'process' | 'osProcess' | 'routing' | 'token' | 'node'>>;
interface PassiveContext {
  readonly id: number; readonly unique: string; readonly physical: FrameScalars;
}
interface ActionWorld {
  readonly name: string; frame: string; session: string | undefined; physical: FrameScalars; context?: PassiveContext;
}
function frameScalars(frame: PhysicalFrame): FrameScalars {
  return Object.freeze({ process: frame.process, osProcess: frame.osProcess, routing: frame.routing, token: frame.token, node: frame.node });
}
function samePhysical(a: FrameScalars, b: FrameScalars): boolean {
  return a.process === b.process && a.osProcess === b.osProcess && a.routing === b.routing && a.token === b.token && a.node === b.node;
}
function actionEvent(method: string, raw: unknown): ActionEvent | undefined {
  if (!['Runtime.executionContextCreated', 'Runtime.executionContextDestroyed', 'Runtime.executionContextsCleared',
    'Runtime.bindingCalled', 'Input.dragIntercepted'].includes(method)) return;
  const data = raw as any;
  const string = (value: unknown, limit: number): value is string => typeof value === 'string' && value.length <= limit;
  const id = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0;
  if (method === 'Runtime.executionContextsCleared') return Object.freeze({ kind: 'cleared' });
  if (method === 'Runtime.executionContextCreated') {
    const c = data?.context;
    if (id(c?.id) && string(c.uniqueId, 256) && c.uniqueId && string(c.name, 128) &&
        string(c.auxData?.frameId, 256) && typeof c.auxData?.isDefault === 'boolean')
      return Object.freeze({ kind: 'context', id: c.id, unique: c.uniqueId, name: c.name,
        frame: c.auxData.frameId, default: c.auxData.isDefault });
  } else if (method === 'Runtime.executionContextDestroyed') {
    if (id(data?.executionContextId) && string(data.executionContextUniqueId, 256))
      return Object.freeze({ kind: 'destroyed', id: data.executionContextId, unique: data.executionContextUniqueId });
  } else if (method === 'Runtime.bindingCalled') {
    if (string(data?.name, 128) && string(data.payload, 2048) && id(data.executionContextId))
      return Object.freeze({ kind: 'binding', name: data.name, payload: data.payload, context: data.executionContextId });
  } else {
    const drag = data?.data;
    if (drag && Array.isArray(drag.items) && drag.items.length <= 16 &&
        Number.isSafeInteger(drag.dragOperationsMask) && drag.dragOperationsMask >= 0 && drag.dragOperationsMask <= 31 &&
        (drag.files === undefined || (Array.isArray(drag.files) && drag.files.length === 0))) {
      let bytes = 0; const items: ActionDragData['items'][number][] = [];
      for (const item of drag.items) {
        if (!string(item?.mimeType, 128) || !string(item.data, 65536) ||
            (item.title !== undefined && !string(item.title, 4096)) || (item.baseURL !== undefined && !string(item.baseURL, 8192)) ||
            (bytes += Buffer.byteLength(item.data, 'utf8') + Buffer.byteLength(item.title ?? '', 'utf8') + Buffer.byteLength(item.baseURL ?? '', 'utf8')) > 65536)
          return Object.freeze({ kind: 'lost' });
        items.push(Object.freeze({ mimeType: item.mimeType, data: item.data,
          ...(item.title !== undefined ? { title: item.title } : {}), ...(item.baseURL !== undefined ? { baseURL: item.baseURL } : {}) }));
      }
      return Object.freeze({ kind: 'drag', data: Object.freeze({ items: Object.freeze(items), dragOperationsMask: drag.dragOperationsMask }) });
    }
  }
  return Object.freeze({ kind: 'lost' });
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
  actionObservers: Set<ActionObserver>;
  actionWorld?: ActionWorld;
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
    documents.subscribe(event => {
      const channel = this.channels.get(event.page); if (!channel) return;
      if (event.kind === 'changed' || event.kind === 'closed') {
        // Logical renewal always expires action listeners/receipts. Only a
        // scalar physical/context identity can survive same-document renewal.
        for (const observer of [...channel.actionObservers]) observer.close();
        const world = channel.actionWorld;
        if (world && (event.kind === 'closed' || !event.receipt || !samePhysical(world.context?.physical ?? world.physical, event.receipt.frame)))
          delete world.context;
      }
    });
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
    const channel: Channel = { page, contents, debugger: debugger_, identity: Object.freeze({}), active: true, interception: 'unknown', epoch: 0, unknownActivity: false, sessions: new Map(), observers: new Set(), resources: new Set(), animations: new Set(), actionObservers: new Set() };
    this.channels.set(page, channel);
    debugger_.on('message', (_event, method, params, sessionId) => {
      if (!channel.active || this.channels.get(page) !== channel) return;
      if (channel.actionObservers.size || (channel.actionWorld && ['Runtime.executionContextCreated',
        'Runtime.executionContextDestroyed', 'Runtime.executionContextsCleared'].includes(method))) {
        const projected = actionEvent(method, params);
        if (projected) this.contextEvent(channel, sessionId || undefined, projected);
        if (projected) for (const observer of [...channel.actionObservers]) {
          if (observer.session !== (sessionId || undefined)) continue;
          try {
            observer.check();
            if (projected.kind !== 'context' || projected.frame === observer.frame.frameId) observer.receive(projected);
          } catch { observer.close(); }
        }
      }
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
      if (channel.actionWorld) delete channel.actionWorld.context;
      for (const observer of [...channel.actionObservers]) observer.close();
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
  /** Ephemeral original-action notifications on the already attached debugger.
   * No implicit attach, generic event route or guessed child identity exists. */
  observeActions(frame: InspectionFrame, guard: () => void, signal: AbortSignal, receive: (event: ActionEvent) => void): () => void {
    this.assertInspection(frame, guard); const channel = this.owned(frame.receipt.page);
    if (signal.aborted || channel.actionObservers.size >= 8 || channel.identity !== frame.receipt.channel) throw staleSnapshot();
    let active = true;
    const remove = () => { if (!active) return; active = false; channel.actionObservers.delete(observer); signal.removeEventListener('abort', remove); };
    const observer: ActionObserver = { frame, session: frame.session,
      check: () => { if (!active) throw staleSnapshot(); this.assertInspection(frame, guard);
        if (this.owned(frame.receipt.page) !== channel) throw staleSnapshot(); },
      receive, close: () => { if (!active) return; remove(); try { receive(Object.freeze({ kind: 'lost' })); } catch { /* closed original scope */ } } };
    channel.actionObservers.add(observer); signal.addEventListener('abort', remove, { once: true });
    return remove;
  }
  /** Register only the one fixed private world. Passive state has no document
   * lease, action listener, arbitrary payload or second event history. */
  registerActionWorld(frame: InspectionFrame, guard: () => void, name: string): void {
    this.assertInspection(frame, guard);
    if (!/^arbol_action_[0-9a-f]{32}$/.test(name) || !frame.physical || frame.session !== undefined || frame.physical !== frame.receipt.frame) throw staleSnapshot();
    const channel = this.owned(frame.receipt.page), physical = frameScalars(frame.physical);
    const current = channel.actionWorld;
    if (current) {
      if (current.name !== name) throw staleSnapshot();
      if (current.frame !== frame.frameId || current.session !== frame.session ||
          !samePhysical(current.context?.physical ?? current.physical, physical)) delete current.context;
      current.frame = frame.frameId; current.session = frame.session; current.physical = physical;
    } else channel.actionWorld = { name, frame: frame.frameId, session: frame.session, physical };
  }
  private contextEvent(channel: Channel, session: string | undefined, event: ActionEvent): void {
    const world = channel.actionWorld; if (!world || world.session !== session) return;
    if (event.kind === 'cleared' || event.kind === 'lost' || (event.kind === 'destroyed' &&
        (world.context?.id === event.id || world.context?.unique === event.unique))) delete world.context;
    else if (event.kind === 'context' && event.name === world.name && event.frame === world.frame && !event.default) {
      try {
        this.assertChannel(channel);
        const root = physicalFrames(channel.page).find(frame => frame.handle === channel.contents.mainFrame);
        if (!root) throw staleSnapshot();
        // Numeric ids are routing only. The next action must also obtain a
        // fresh exact-frame createIsolatedWorld ack and use this unique id.
        world.context = Object.freeze({ id: event.id, unique: event.unique, physical: frameScalars(root) });
      } catch { delete world.context; }
    }
  }
  actionContext(frame: InspectionFrame, guard: () => void, name: string): Readonly<{ id: number; unique: string }> {
    this.assertInspection(frame, guard); const channel = this.owned(frame.receipt.page), world = channel.actionWorld;
    const context = world?.context;
    if (!world || world.name !== name || world.frame !== frame.frameId || world.session !== frame.session ||
        !context || !frame.physical || !samePhysical(context.physical, frame.physical)) throw staleSnapshot();
    return Object.freeze({ id: context.id, unique: context.unique });
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
    if (channel.actionWorld) delete channel.actionWorld.context;
    for (const observer of [...channel.actionObservers]) observer.close();
    if (!channel.contents.isDestroyed() && channel.debugger.isAttached()) channel.debugger.detach();
  }
}
