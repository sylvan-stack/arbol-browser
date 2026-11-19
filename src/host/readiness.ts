import type { Debugger, WebContents } from 'electron';
import { createHash, randomBytes } from 'node:crypto';
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
  readonly loaderId: string;
  readonly parent: InspectionFrame | undefined;
  readonly ownerBackend: number | undefined;
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
export interface MutationBracket { check(): Promise<void>; close(): Promise<void> }
interface ContentContext { readonly id: number; readonly unique: string; gone: boolean }
interface ContentWorld { readonly name: string; readonly physical: FrameScalars; context?: ContentContext; readonly notifications: Set<() => void>; readonly active: Set<object> }
interface DefaultContext { readonly id: number; readonly unique: string; readonly frame: string }
interface DebuggerOwner { events: number; readonly limit: number; bad: boolean; readonly done: Promise<void>; finish(): void }
interface ChildSession {
  readonly targetId: string; readonly parent: string | undefined;
  readonly contexts: Map<string, DefaultContext>; readonly worlds: Map<string, ContentWorld>; detached: boolean; prepared?: Promise<void>; debuggerOwner?: DebuggerOwner;
}
interface FrameRoute { readonly id: string; readonly loader: string; readonly parent: string | undefined }
interface FrameGraph {
  readonly epoch: number; readonly signature: string; readonly frames: ReadonlyMap<string, FrameRoute>;
  readonly sessions: ReadonlyMap<string | undefined, ChildSession>;
  readonly local: ReadonlyMap<string | undefined, ReadonlyMap<string, FrameRoute>>;
}
interface FrameSeal { readonly channel: Channel; readonly graph: FrameGraph; readonly context: DefaultContext | undefined }
interface FrameChallenge {
  readonly hash: string; matches: number; failed: boolean;
  readonly observed: Promise<void>; notify(): void;
  match?: { readonly session: string | undefined; readonly context: DefaultContext };
}
interface Channel {
  readonly page: PageSurface;
  readonly contents: WebContents;
  readonly debugger: Debugger;
  readonly identity: object;
  active: boolean;
  poisoned?: boolean;
  detached: boolean;
  graphEpoch: number;
  readonly root: ChildSession;
  proof?: Promise<void>;
  challenge?: FrameChallenge;
  interception: 'unknown' | 'enabled' | 'disabled';
  interceptionInFlight?: object;
  epoch: number;
  unknownActivity: boolean;
  sessions: Map<string, ChildSession>;
  observers: Set<() => void>;
  resources: Set<string>;
  animations: Set<string>;
  actionObservers: Set<ActionObserver>;
  actionWorld?: ActionWorld;
  surface?: object;
  viewportWork?: Promise<unknown>;
  viewportOverride?: true;
}
function emptyAck(value: unknown): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length) throw staleSnapshot();
}
/** Isolated native DOM objects only. Every open-shadow scope is latched before
 * AX reads, but composition inside every shadow host is still excluded by DOM
 * classification: manual slot assignment has no complete mutation signal. */
const mutationProgram = `(() => {
  'use strict'; let dirty=false, live=true;
  const scopes=[], hosts=[], roots=[];
  const observe=root=>{const observer=new MutationObserver(()=>{dirty=true;});
    observer.observe(root,{subtree:true,attributes:true,childList:true,characterData:true});scopes.push(observer);};
  observe(document);
  const inventory=(watch)=>{
    const foundHosts=[],foundRoots=[],queue=[document];let count=0;
    for(let index=0;index<queue.length;index++){
      const root=queue[index],walker=document.createTreeWalker(root,NodeFilter.SHOW_ELEMENT);
      for(let node=walker.nextNode();node;node=walker.nextNode()){
        if(++count>100000)throw Error('bound');
        const shadow=node.shadowRoot;
        if(shadow){if(foundRoots.length>=256)throw Error('bound');foundHosts.push(node);foundRoots.push(shadow);queue.push(shadow);if(watch)observe(shadow);}
      }
    }
    return {hosts:foundHosts,roots:foundRoots};
  };
  try{const initial=inventory(true);hosts.push(...initial.hosts);roots.push(...initial.roots);}
  catch{for(const observer of scopes)observer.disconnect();throw Error('scope');}
  return Object.freeze({
    check(){if(!live)return false;
      for(const observer of scopes)if(observer.takeRecords().length)dirty=true;
      let current;try{current=inventory(false);}catch{return false;}
      if(current.hosts.length!==hosts.length||current.roots.length!==roots.length)return false;
      for(let i=0;i<hosts.length;i++)if(current.hosts[i]!==hosts[i]||current.roots[i]!==roots[i]||!hosts[i].isConnected)return false;
      for(const observer of scopes)if(observer.takeRecords().length)dirty=true;
      return !dirty;
    },
    close(){live=false;for(const observer of scopes)observer.disconnect();scopes.length=0;hosts.length=0;roots.length=0;return true;}
  });
})()`;
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
    const channel: Channel = { page, contents, debugger: debugger_, identity: Object.freeze({}), active: true, detached: false, graphEpoch: 0, root: { targetId: '', parent: undefined, contexts: new Map(), worlds: new Map(), detached: false }, interception: 'unknown', epoch: 0, unknownActivity: false, sessions: new Map(), observers: new Set(), resources: new Set(), animations: new Set(), actionObservers: new Set() };
    this.channels.set(page, channel);
    debugger_.on('message', (_event, method, params, sessionId) => {
      if (!channel.active || this.channels.get(page) !== channel) return;
      this.frameEvent(channel, sessionId || undefined, method, params);
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
      channel.detached = true; channel.root.detached = true;
      for (const state of channel.sessions.values()) state.detached = true;
      if (channel.challenge) channel.challenge.failed = true;
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
    if (!channel.active || channel.poisoned || this.channels.get(channel.page) !== channel || channel.page.retirement() ||
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
    if (method.startsWith('Debugger.') || method === 'Runtime.disable') throw staleSnapshot();
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
  private readonly inspectionFrames = new WeakMap<InspectionFrame, FrameSeal>();
  private state(channel: Channel, session: string | undefined): ChildSession {
    const state = session === undefined ? channel.root : channel.sessions.get(session);
    if (!state || state.detached) throw staleSnapshot(); return state;
  }
  /** Only fixed scalar engine fields survive this listener. In particular no
   * URL, source, stack, script text or arbitrary event object is retained. */
  private frameEvent(channel: Channel, session: string | undefined, method: string, raw: unknown): void {
    const data = raw as any;
    const scalar = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 256;
    const changed = () => {
      if (++channel.graphEpoch >= Number.MAX_SAFE_INTEGER) return this.boundary.fatal.fail('native_boundary_unavailable');
    };
    if (method === 'Target.attachedToTarget') {
      changed();
      if (!scalar(data?.sessionId) || !scalar(data?.targetInfo?.targetId) || data.targetInfo.type !== 'iframe' ||
          channel.sessions.has(data.sessionId) || channel.sessions.size >= 255 || (session && !channel.sessions.has(session))) {
        channel.unknownActivity = true; if (channel.challenge) channel.challenge.failed = true; return;
      }
      channel.sessions.set(data.sessionId, { targetId: data.targetInfo.targetId, parent: session,
        contexts: new Map(), worlds: new Map(), detached: false }); return;
    }
    if (method === 'Target.detachedFromTarget') {
      changed(); const state = channel.sessions.get(data?.sessionId);
      if (!state || state.parent !== session) { channel.unknownActivity = true; return; }
      state.detached = true; channel.sessions.delete(data.sessionId); return;
    }
    if (['Page.frameAttached', 'Page.frameDetached', 'Page.frameNavigated', 'Page.navigatedWithinDocument'].includes(method)) changed();
    const state = session === undefined ? channel.root : channel.sessions.get(session);
    if (!state) { if (channel.challenge) channel.challenge.failed = true; return; }
    if (method === 'Runtime.executionContextsCleared') {
      state.contexts.clear(); changed();
      for (const world of state.worlds.values()) { if (world.context) world.context.gone = true; delete world.context; for (const notify of world.notifications) notify(); }
    }
    if (method === 'Runtime.executionContextDestroyed') for (const world of state.worlds.values()) {
      if (world.context && (world.context.id === data?.executionContextId || world.context.unique === data?.executionContextUniqueId)) {
        world.context.gone = true; delete world.context; for (const notify of world.notifications) notify();
      }
    }
    if (method === 'Runtime.executionContextCreated' && data?.context?.auxData?.isDefault === false) {
      const c = data.context, world = state.worlds.get(c.auxData.frameId);
      if (world && c.name === world.name && scalar(c.uniqueId) && Number.isSafeInteger(c.id) && c.id > 0) {
        if (world.context && (world.context.id !== c.id || world.context.unique !== c.uniqueId)) world.context.gone = true;
        world.context = { id: c.id, unique: c.uniqueId, gone: false }; for (const notify of world.notifications) notify();
      }
    }
    if (method === 'Runtime.executionContextDestroyed') {
      for (const [frame, context] of state.contexts) if (context.id === data?.executionContextId || context.unique === data?.executionContextUniqueId) {
        state.contexts.delete(frame); changed();
      }
    }
    if (method === 'Runtime.executionContextCreated' && data?.context?.auxData?.isDefault === true) {
      const c = data.context, frame = c.auxData.frameId;
      if (!scalar(frame) || !scalar(c.uniqueId) || !Number.isSafeInteger(c.id) || c.id <= 0) {
        state.contexts.clear(); channel.unknownActivity = true; changed(); return;
      }
      const old = state.contexts.get(frame);
      if (old?.id !== c.id || old?.unique !== c.uniqueId) {
        let count = channel.root.contexts.size;
        for (const child of channel.sessions.values()) count += child.contexts.size;
        if (!old && count >= 256) { channel.unknownActivity = true; return; }
        state.contexts.set(frame, Object.freeze({ id: c.id, unique: c.uniqueId, frame })); changed();
      }
    }
    const owner = state.debuggerOwner;
    if (!owner) return;
    if (method === 'Debugger.paused') owner.bad = true;
    if (method !== 'Debugger.scriptParsed') return;
    // enable enumerates existing live scripts even with a zero source cache.
    if (++owner.events > owner.limit) { owner.bad = true; channel.challenge?.notify(); return; }
    const pending = channel.challenge;
    if (!pending || data?.hash !== pending.hash) return;
    if (++pending.matches !== 1) { pending.failed = true; pending.notify(); return; }
    const aux = data.executionContextAuxData;
    const context = scalar(aux?.frameId) ? state.contexts.get(aux.frameId) : undefined;
    if (!context || aux?.isDefault !== true || context.id !== data.executionContextId || owner.bad) { pending.failed = true; pending.notify(); return; }
    pending.match = Object.freeze({ session, context }); pending.notify();
  }
  private async prepareInspection(channel: Channel, session: string | undefined, guard: () => void): Promise<void> {
    const state = this.state(channel, session);
    if (!state.prepared) {
      const setup = (async () => {
        for (const method of ['Page.enable', 'DOM.enable', 'Runtime.enable', 'Animation.enable', 'Network.enable'])
          emptyAck(await this.command(channel.page, guard, method, undefined, session));
        emptyAck(await this.command(channel.page, guard, 'Target.setAutoAttach',
          { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, session));
        emptyAck(await this.command(channel.page, guard, 'Page.setLifecycleEventsEnabled', { enabled: true }, session));
      })();
      state.prepared = setup;
      void setup.catch(() => { if (state.prepared === setup) delete state.prepared; });
    }
    await state.prepared; guard();
    if (this.state(channel, session) !== state) throw staleSnapshot();
  }
  private sessionGraph(channel: Channel): Map<string | undefined, ChildSession> {
    const sessions = new Map<string | undefined, ChildSession>([[undefined, channel.root]]);
    for (const [id, state] of channel.sessions) {
      if (state.detached || (state.parent !== undefined && !channel.sessions.has(state.parent))) throw staleSnapshot();
      const seen = new Set<string>([id]); let parent = state.parent;
      while (parent !== undefined) {
        if (seen.has(parent) || seen.size > 256) throw staleSnapshot(); seen.add(parent);
        parent = channel.sessions.get(parent)!.parent;
      }
      sessions.set(id, state);
    }
    return sessions;
  }
  private sameSessions(channel: Channel, sessions: ReadonlyMap<string | undefined, ChildSession>): void {
    const live = this.sessionGraph(channel);
    if (live.size !== sessions.size || [...sessions].some(([id, state]) => live.get(id) !== state)) throw staleSnapshot();
  }
  private async frameGraph(channel: Channel, guard: () => void): Promise<FrameGraph> {
    guard(); const epoch = channel.graphEpoch, sessions = this.sessionGraph(channel);
    const frames = new Map<string, FrameRoute>(), local = new Map<string | undefined, Map<string, FrameRoute>>();
    let work = 0;
    for (const [session] of sessions) {
      const value = await this.command(channel.page, guard, 'Page.getFrameTree', undefined, session) as { frameTree?: unknown };
      const nodes = new Map<string, FrameRoute>(); local.set(session, nodes);
      const visit = (raw: any, parent: string | undefined, depth: number) => {
        if (++work > 65536 || depth > 32 || nodes.size >= 256) throw staleSnapshot();
        const f = raw?.frame;
        const scalar = (x: unknown): x is string => typeof x === 'string' && x.length > 0 && x.length <= 256;
        if (!scalar(f?.id) || !scalar(f.loaderId) || (f.parentId !== undefined && !scalar(f.parentId)) || nodes.has(f.id)) throw staleSnapshot();
        const lineage = parent ?? f.parentId;
        if (parent !== undefined && f.parentId !== undefined && f.parentId !== parent) throw staleSnapshot();
        const known = frames.get(f.id);
        if (known && (known.loader !== f.loaderId || (lineage !== undefined && known.parent !== lineage))) throw staleSnapshot();
        const frame: FrameRoute = known ?? Object.freeze({ id: f.id, loader: f.loaderId, parent: lineage });
        nodes.set(f.id, frame); frames.set(f.id, frame);
        if (frames.size > 256 || (raw.childFrames !== undefined && (!Array.isArray(raw.childFrames) || raw.childFrames.length > 256))) throw staleSnapshot();
        for (const child of raw.childFrames ?? []) visit(child, f.id, depth + 1);
      };
      visit(value.frameTree, undefined, 1);
    }
    guard(); this.sameSessions(channel, sessions); if (channel.graphEpoch !== epoch) throw staleSnapshot();
    const roots = [...local.get(undefined)!.values()].filter(frame => frame.parent === undefined);
    if (roots.length !== 1 || [...frames.values()].some(frame => frame.parent !== undefined && !frames.has(frame.parent))) throw staleSnapshot();
    const signature = JSON.stringify([...local].map(([id, nodes]) => [id, sessions.get(id)!.targetId, sessions.get(id)!.parent,
      [...nodes.values()].map(f => [f.id, f.loader, f.parent])]));
    return { epoch, sessions, local, frames, signature };
  }
  /** This guard is deliberately independent of the expired logical read. It
   * permits only disable on the literal original channel and original target
   * attachment; it confers no authority for document work or retargeting. */
  private originalDebugger(channel: Channel, session: string | undefined, state: ChildSession): 'live' | 'detached' {
    this.native();
    if (channel.contents.isDestroyed() || channel.detached || state.detached) return 'detached';
    if (this.channels.get(channel.page) !== channel || channel.contents.debugger !== channel.debugger || !channel.debugger.isAttached() ||
        (session === undefined ? channel.root !== state : channel.sessions.get(session) !== state)) throw staleSnapshot();
    return 'live';
  }
  private async disableDebugger(channel: Channel, session: string | undefined, state: ChildSession, owner: DebuggerOwner): Promise<void> {
    let clean = false;
    try {
      if (this.originalDebugger(channel, session, state) === 'detached') clean = true;
      else {
        await this.deadline(performance.now() + 2000, () => {
          if (state.debuggerOwner !== owner) throw staleSnapshot();
          this.originalDebugger(channel, session, state);
        }, async check => {
          check();
          // No Runtime.disable: the original passive action world is retained.
          const value = await channel.debugger.sendCommand('Debugger.disable', undefined, session);
          check(); emptyAck(value); clean = true;
        });
      }
    } catch {
      try { clean = this.originalDebugger(channel, session, state) === 'detached'; } catch { /* unresolved original */ }
    }
    if (clean) { if (state.debuggerOwner === owner) delete state.debuggerOwner; owner.finish(); return; }
    owner.bad = true; channel.poisoned = true;
    this.documents.channelLost(channel.page, channel.identity);
    // This is the canonical idempotent original-surface retirement, never a
    // lookup through a target that may now designate a replacement page.
    void channel.page.retire().catch(() => this.boundary.fatal.fail('native_retirement_unavailable'));
    // Retain the owner forever unless this exact attachment really detaches.
    throw staleSnapshot();
  }
  /** The physical main frame is bound by the original WebContents debugger.
   * Each child is correlated by its own original RFH executing only this nonce
   * literal in the default main world, and by V8's UTF-16LE source hash. */
  async inspection(receipt: HostDocument, assertCurrent: () => void): Promise<readonly InspectionFrame[]> {
    const channel = this.owned(receipt.page), deadline = performance.now() + 5000;
    const guard = () => { this.synchronous(assertCurrent); this.documents.target(receipt); this.assertChannel(channel);
      if (receipt.channel !== channel.identity) throw staleSnapshot(); };
    guard();
    while (channel.proof) await this.deadline(deadline, guard, async () => { await channel.proof; });
    guard();
    let finish = () => {};
    const token = new Promise<void>(resolve => { finish = resolve; }); channel.proof = token;
    const activated: [string | undefined, ChildSession, DebuggerOwner][] = [];
    try {
      return await this.deadline(deadline, guard, async check => {
        await this.prepareInspection(channel, undefined, check);
        // Auto-attach is recursive only after each actual flattened child has
        // itself enabled it. Bound all rounds and keep object identity.
        const prepared = new Set<ChildSession>([channel.root]);
        for (let round = 0; round < 256; round++) {
          const next = [...this.sessionGraph(channel)].find(([, state]) => !prepared.has(state));
          if (!next) break;
          await this.prepareInspection(channel, next[0], check); prepared.add(next[1]);
        }
        const graph = await this.frameGraph(channel, check);
        const root = [...graph.local.get(undefined)!.values()].find(f => f.parent === undefined)!;
        const routes = new Map<PhysicalFrame, { route: FrameRoute; session: string | undefined; context: DefaultContext | undefined }>();
        routes.set(receipt.frame, { route: root, session: undefined, context: undefined });
        if (receipt.frames.length > 1) {
          for (const [session, state] of graph.sessions) {
            check();
            if (state.debuggerOwner) throw staleSnapshot();
            let done = () => {};
            const owner: DebuggerOwner = { events: 0, limit: Math.min(4096, Math.floor(16384 / graph.sessions.size)), bad: false, done: new Promise<void>(resolve => { done = resolve; }), finish: () => done() };
            state.debuggerOwner = owner; activated.push([session, state, owner]);
            // The observer is installed above before enable can enumerate live
            // scripts. A genuine skip receipt closes the debugger-statement gap.
            check(); emptyAck(await channel.debugger.sendCommand('Debugger.setSkipAllPauses', { skip: true }, session)); check();
            emptyAck(await channel.debugger.sendCommand('Debugger.setBreakpointsActive', { active: false }, session)); check();
            const enabled = await channel.debugger.sendCommand('Debugger.enable', { maxScriptsCacheSize: 0 }, session); check();
            if (!enabled || typeof enabled !== 'object' || typeof (enabled as { debuggerId?: unknown }).debuggerId !== 'string' || owner.bad) throw staleSnapshot();
          }
          const used = new Set<string>([root.id]);
          for (const physical of receipt.frames) if (physical !== receipt.frame) {
            check();
            if (channel.graphEpoch !== graph.epoch || activated.some(([, , owner]) => owner.bad)) throw staleSnapshot();
            const source = `void 0/*arbol-frame-${randomBytes(16).toString('hex')}*/`;
            let notify = () => {};
            const pending: FrameChallenge = { hash: createHash('sha256').update(Buffer.from(source, 'utf16le')).digest('hex'), matches: 0, failed: false,
              observed: new Promise<void>(resolve => { notify = resolve; }), notify: () => notify() };
            channel.challenge = pending;
            try {
              const result: unknown = await physical.handle.executeJavaScript(source, false); check();
              // RFH execution replies and CDP script notifications use distinct
              // channels. Require both genuine receipts without ordering them.
              if (!pending.match && !pending.failed) await this.deadline(Math.min(deadline, performance.now() + 250), check,
                async () => { await pending.observed; });
              check();
              const match = pending.match;
              if (result !== undefined || pending.failed || pending.matches !== 1 || !match || used.has(match.context.frame)) continue;
              const state = this.state(channel, match.session), route = graph.local.get(match.session)?.get(match.context.frame);
              if (!route || state.contexts.get(route.id) !== match.context) continue;
              routes.set(physical, { route, session: match.session, context: match.context }); used.add(route.id);
            } catch (error) { check(); /* This physical child remains unavailable. */ }
            finally { if (channel.challenge === pending) delete channel.challenge; }
          }
        }
        check(); if (activated.some(([, , owner]) => owner.bad)) throw staleSnapshot();
        const after = await this.frameGraph(channel, check);
        if (after.signature !== graph.signature || after.epoch !== graph.epoch) throw staleSnapshot();
        const frames: InspectionFrame[] = [], byPhysical = new Map<PhysicalFrame['handle'], InspectionFrame>();
        const pending = [...receipt.frames];
        for (let round = 0; pending.length && round < 256; round++) {
          const index = pending.findIndex(physical => physical.parent === null || byPhysical.has(physical.parent));
          if (index < 0) break;
          const physical = pending.splice(index, 1)[0]!, binding = routes.get(physical);
          const parent = physical.parent === null ? undefined : byPhysical.get(physical.parent);
          if (!binding || (physical !== receipt.frame && (!parent?.physical || binding.route.parent !== parent.frameId))) continue;
          const state = this.state(channel, binding.session);
          if (binding.context && state.contexts.get(binding.route.id) !== binding.context) throw staleSnapshot();
          let ownerBackend: number | undefined;
          if (parent) {
            // DOM ownership is queried on the actual parent's route. Flattened
            // target parentage is checked separately by the original graph.
            const value = await this.command(receipt.page, check, 'DOM.getFrameOwner', { frameId: binding.route.id }, parent.session) as { backendNodeId?: number };
            if (!Number.isSafeInteger(value.backendNodeId) || value.backendNodeId! <= 0) continue;
            ownerBackend = value.backendNodeId;
          }
          const frame: InspectionFrame = Object.freeze({ receipt, physical, frameId: binding.route.id, loaderId: binding.route.loader,
            session: binding.session, parent, ownerBackend });
          this.inspectionFrames.set(frame, { channel, graph, context: binding.context }); frames.push(frame); byPhysical.set(physical.handle, frame);
        }
        if (frames[0]?.physical !== receipt.frame) throw staleSnapshot();
        for (const physical of receipt.frames) if (!byPhysical.has(physical.handle)) {
          const parent = physical.parent === null ? undefined : byPhysical.get(physical.parent);
          frames.push(Object.freeze({ receipt, physical: undefined, frameId: '', loaderId: '', session: undefined, parent, ownerBackend: undefined }));
        }
        check(); const final = await this.frameGraph(channel, check);
        if (final.signature !== graph.signature || final.epoch !== graph.epoch) throw staleSnapshot();
        for (const frame of frames) if (frame.physical) this.assertInspection(frame, check);
        return Object.freeze(frames);
      });
    } finally {
      delete channel.challenge;
      // Cleanup owns the actual attachment after read timeout, Take, navigation
      // or cancellation. Neither its lock nor its disable follows target.page.
      const cleaned = await Promise.allSettled(activated.map(([session, state, owner]) => this.disableDebugger(channel, session, state, owner)));
      if (channel.proof === token) delete channel.proof; finish();
      if (cleaned.some(result => result.status === 'rejected')) throw staleSnapshot();
    }
  }
  assertInspection(frame: InspectionFrame, assertCurrent: () => void): void {
    this.synchronous(assertCurrent); this.documents.target(frame.receipt);
    const seal = this.inspectionFrames.get(frame), channel = this.owned(frame.receipt.page);
    if (!seal || seal.channel !== channel || frame.receipt.channel !== channel.identity || !frame.physical ||
        !frame.receipt.frames.includes(frame.physical) || channel.graphEpoch !== seal.graph.epoch) throw staleSnapshot();
    this.sameSessions(channel, seal.graph.sessions);
    const state = this.state(channel, frame.session);
    if (seal.context && state.contexts.get(frame.frameId) !== seal.context) throw staleSnapshot();
    if (frame.parent && (frame.physical.parent !== frame.parent.physical?.handle || frame.ownerBackend === undefined)) throw staleSnapshot();
  }
  async verifyInspection(frames: readonly InspectionFrame[], guard: () => void): Promise<void> {
    const frame = frames.find(value => value.physical); if (!frame) throw staleSnapshot();
    this.assertInspection(frame, guard); const seal = this.inspectionFrames.get(frame)!;
    const graph = await this.frameGraph(seal.channel, () => this.assertInspection(frame, guard));
    if (graph.signature !== seal.graph.signature) throw staleSnapshot();
    for (const value of frames) if (value.physical) this.assertInspection(value, guard);
  }
  /** One fixed original-frame mutation latch, with its group reserved before
   * any evaluation (including possible exception-object allocation). Cleanup
   * never reuses the read guard or a replacement context/document. */
  async mutationBracket(frame: InspectionFrame, guard: () => void): Promise<MutationBracket> {
    this.assertInspection(frame, guard);
    const channel = this.owned(frame.receipt.page), state = this.state(channel, frame.session), physical = frame.physical!;
    let world = state.worlds.get(frame.frameId);
    if (world && !samePhysical(world.physical, physical)) {
      if (world.active.size) throw staleSnapshot(); state.worlds.delete(frame.frameId); world = undefined;
    }
    if (!world) {
      if (state.worlds.size >= 256) throw staleSnapshot();
      world = { name: `arbol_content_${randomBytes(16).toString('hex')}`, physical: frameScalars(physical), notifications: new Set(), active: new Set() };
      state.worlds.set(frame.frameId, world);
    }
    const originalWorld = world;
    if (world.active.size >= 4) throw staleSnapshot();
    const token = Object.freeze({}), key = `arbol_observer_${randomBytes(16).toString('hex')}`, group = `arbol-content-${randomBytes(16).toString('hex')}`;
    world.active.add(token);
    let context: ContentContext | undefined, installed = false, closed = false, closing: Promise<void> | undefined;
    const expiry = performance.now() + 5000; let timer: ReturnType<typeof setTimeout> | undefined;
    const current = () => {
      this.assertInspection(frame, guard);
      if (closed || performance.now() >= expiry || !originalWorld.active.has(token) || state.worlds.get(frame.frameId) !== originalWorld ||
          (context && (context.gone || originalWorld.context !== context))) throw staleSnapshot();
    };
    const boolean = (value: unknown) => {
      const raw = value as { result?: { type?: string; value?: unknown }; exceptionDetails?: unknown };
      if (raw?.exceptionDetails || raw?.result?.type !== 'boolean' || raw.result.value !== true) throw staleSnapshot();
    };
    const evaluate = async (expression: string) => {
      current(); if (!context) throw staleSnapshot();
      const unique = context.unique;
      const result = await this.deadline(Math.min(expiry, performance.now() + 1000), current, check =>
        this.command(frame.receipt.page, check, 'Runtime.evaluate', { expression, uniqueContextId: unique,
          objectGroup: group, returnByValue: true, awaitPromise: false, includeCommandLineAPI: false }, frame.session));
      current(); boolean(result);
    };
    const close = (): Promise<void> => {
      if (closing) return closing;
      let readable = true; try { current(); } catch { readable = false; }
      let contentClean = readable;
      closed = true; if (timer) clearTimeout(timer);
      closing = (async () => {
        let clean = false;
        const exact = () => {
          if (this.originalDebugger(channel, frame.session, state) === 'detached') return 'detached';
          if (!originalWorld.active.has(token)) throw staleSnapshot(); return 'live';
        };
        try {
          if (exact() === 'detached') clean = true;
          else await this.deadline(performance.now() + 2000, () => { exact(); }, async check => {
            let observerClean = !installed || Boolean(context?.gone);
            if (context?.gone) contentClean = false;
            try {
              if (installed && context && !context.gone) {
                check();
                const value = await channel.debugger.sendCommand('Runtime.evaluate', {
                  expression: `(() => {const value=globalThis["${key}"];if(!value)return false;const valid=${readable ? 'value.check()' : 'false'};const ok=value.close();delete globalThis["${key}"];return ok===true?valid:null;})()`,
                  uniqueContextId: context.unique, objectGroup: group, returnByValue: true, awaitPromise: false, includeCommandLineAPI: false }, frame.session);
                check();
                const result = value as { result?: { type?: string; value?: unknown }; exceptionDetails?: unknown };
                if (result?.exceptionDetails || result?.result?.type !== 'boolean' || typeof result.result.value !== 'boolean') throw staleSnapshot();
                contentClean = contentClean && result.result.value; observerClean = true;
              }
            } finally {
              check(); emptyAck(await channel.debugger.sendCommand('Runtime.releaseObjectGroup', { objectGroup: group }, frame.session)); check();
            }
            if (!observerClean) throw staleSnapshot(); clean = true;
          });
        } catch { try { clean = exact() === 'detached'; } catch { /* unresolved exact original */ } }
        if (!clean) {
          channel.poisoned = true; this.documents.channelLost(channel.page, channel.identity);
          void channel.page.retire().catch(() => this.boundary.fatal.fail('native_retirement_unavailable'));
          throw staleSnapshot();
        }
        originalWorld.active.delete(token);
        if (!contentClean) throw staleSnapshot();
      })();
      return closing;
    };
    timer = setTimeout(() => { void close().catch(() => {}); }, Math.max(1, expiry - performance.now()));
    let notify = () => {};
    try {
      const created = new Promise<void>(resolve => { notify = resolve; }); originalWorld.notifications.add(notify);
      const value = await this.deadline(Math.min(expiry, performance.now() + 1000), current, check =>
        this.command(frame.receipt.page, check, 'Page.createIsolatedWorld', {
          frameId: frame.frameId, worldName: originalWorld.name, grantUniveralAccess: false }, frame.session)) as { executionContextId?: number };
      if (!originalWorld.context) await this.deadline(performance.now() + 1000, current, async () => { await created; });
      context = originalWorld.context;
      if (!context || context.gone || value.executionContextId !== context.id) throw staleSnapshot();
      current(); installed = true; // before an applied command can lose its reply
      await evaluate(`(() => {if(Object.prototype.hasOwnProperty.call(globalThis,"${key}"))return false;globalThis["${key}"]=${mutationProgram};return true;})()`);
      await evaluate(`globalThis["${key}"].check()`);
      return Object.freeze({ check: () => evaluate(`globalThis["${key}"].check()`), close });
    } catch (error) { await close(); throw error; }
    finally { originalWorld.notifications.delete(notify); }
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
    if (frame.physical !== frame.receipt.frame || frame.session !== undefined) throw staleSnapshot();
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
  private async readinessViewport(channel: Channel, check: () => void, size?: { width: number; height: number }): Promise<void> {
    // A superseded readiness job can still have a command on this channel.
    // Let its real reply settle before applying or clearing the newer viewport.
    while (channel.viewportWork) {
      await channel.viewportWork.catch(() => {});
      check();
    }
    if (!size && !channel.viewportOverride) return;
    if (size) channel.viewportOverride = true; // the engine can apply the command before the reply is checked
    const work = size
      ? this.command(channel.page, check, 'Emulation.setDeviceMetricsOverride', { ...size, deviceScaleFactor: 0, mobile: false })
      : this.command(channel.page, check, 'Emulation.clearDeviceMetricsOverride');
    channel.viewportWork = work;
    try {
      emptyAck(await work); check();
      if (!size) delete channel.viewportOverride;
    } finally { delete channel.viewportWork; }
  }
  private async observe(receipt: HostDocument, check: () => void): Promise<void> {
    const page = receipt.page, channel = this.owned(page), host = page.window;
    const category = presentationCategory(page), selected = host.selected() === page, visible = page.view.getVisible();
    const presented = selected && visible && host.window.isVisible() && !host.window.isMinimized();
    const guard = () => {
      check(); this.documents.target(receipt); this.assertChannel(channel);
      if (channel.identity !== receipt.channel) throw staleSnapshot();
      if (presentationCategory(page) !== category || (host.selected() === page) !== selected || page.view.getVisible() !== visible)
        throw new PresentationSuperseded();
    };
    guard();
    if (!selected && visible) throw staleSnapshot(); // Never expose an inactive view to repair it.
    const { width, height } = page.view.getBounds();
    if (!presented && (![width, height].every(value => Number.isSafeInteger(value) && value > 0))) throw staleSnapshot();
    await this.readinessViewport(channel, guard, presented ? undefined : { width, height });
    guard();
    if (presented) {
      const before = page.binding(); page.restorePresentation(); const after = page.binding(); guard();
      if (before.id !== after.id || before.nonce !== after.nonce || before.revision !== after.revision ||
          before.blocked !== after.blocked || after.retired) return this.boundary.fatal.fail('native_boundary_unavailable');
    }
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
    if (presented) {
      const image = await channel.contents.capturePage(undefined, { stayHidden: true, stayAwake: false });
      guard(); const size = image.getSize();
      if (image.isEmpty() || size.width <= 0 || size.height <= 0) throw staleSnapshot();
    } else {
      type Viewport = { clientWidth?: number; clientHeight?: number };
      const metrics = await this.command(page, guard, 'Page.getLayoutMetrics') as {
        cssLayoutViewport?: Viewport; cssVisualViewport?: Viewport & { scale?: number };
      } | undefined;
      const layout = metrics?.cssLayoutViewport, visual = metrics?.cssVisualViewport;
      if (![layout?.clientWidth, layout?.clientHeight, visual?.clientWidth, visual?.clientHeight, visual?.scale]
        .every(value => typeof value === 'number' && Number.isFinite(value) && value > 0)) throw staleSnapshot();
    }
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
