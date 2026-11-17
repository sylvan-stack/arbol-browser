import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { ActionEvent, ActionDragData } from '../host/readiness.js';
import type { HostDocument } from '../host/documents.js';
import type { ActionTarget, InterceptionAcknowledgement } from './admission.js';
import type { TargetPoint } from './targets.js';
import { staleSnapshot } from '../host/authority.js';

interface Context { readonly receipt: HostDocument; readonly id: number; readonly unique: string }
interface Registration {
  readonly world: string; readonly binding: string;
  failed: boolean; setup?: Promise<void>; context?: Context; active?: object;
}
const registrations = new WeakMap<object, Registration>();
const opaque = () => randomBytes(16).toString('hex');
function acknowledgement(value: unknown): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length) throw staleSnapshot();
}
interface EventReceipt { readonly type: string; readonly token: string; readonly target: 'source' | 'other'; readonly serial: number; readonly key?: string }
export interface IssuedInput { readonly token: string; readonly command: number }
interface MonitorState { connected: boolean; pointer: boolean; captures: number; keys: number; composing: boolean; bad: boolean }
export const physicalKeys = Object.freeze({
  Enter: ['Enter', 'Enter', 13], Tab: ['Tab', 'Tab', 9], Escape: ['Escape', 'Escape', 27],
  Backspace: ['Backspace', 'Backspace', 8], Delete: ['Delete', 'Delete', 46],
  ArrowLeft: ['ArrowLeft', 'ArrowLeft', 37], ArrowRight: ['ArrowRight', 'ArrowRight', 39],
  ArrowUp: ['ArrowUp', 'ArrowUp', 38], ArrowDown: ['ArrowDown', 'ArrowDown', 40],
  Home: ['Home', 'Home', 36], End: ['End', 'End', 35], PageUp: ['PageUp', 'PageUp', 33], PageDown: ['PageDown', 'PageDown', 34],
  Space: [' ', 'Space', 32], A: ['a', 'KeyA', 65], Shift: ['Shift', 'ShiftLeft', 16], Meta: ['Meta', 'MetaLeft', 91],
} as const);
export type PhysicalKey = keyof typeof physicalKeys;
export interface KeyStroke { readonly key: PhysicalKey; readonly down: IssuedInput; readonly up: IssuedInput }

/** Fixed host program, never caller script. The reusable world starts inert;
 * this function arms bounded listeners on exactly one resolved original node.
 * No name/value/text/URL or page-provided completion is exported. */
const installMonitor = `function(action,binding){
  'use strict'; const source=this, doc=source.ownerDocument||source;
  if(!source.isConnected||doc!==document)throw Error('target');
  const notify=globalThis[binding]; if(typeof notify!=='function')throw Error('binding');
  let token='',serial=0,live=true,pointer=false,composing=false,bad=false,expected;
  const captures=new Set(),keys=new Set();
  const allowedKeys=['Enter','Tab','Escape','Backspace','Delete','ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End','PageUp','PageDown',' ','a','A','Shift','Meta'];
  const types=['pointerdown','pointerup','pointercancel','gotpointercapture','lostpointercapture','mousedown','mouseup','click','keydown','keyup','beforeinput','input','compositionstart','compositionend','wheel'];
  const receive=e=>{
    if(!live||!e.isTrusted)return;
    const original=e.composedPath()[0]===source||(e.type==='wheel'&&e.composedPath().includes(source));
    if(!original&&!['pointerup','pointercancel','lostpointercapture','mouseup','keyup'].includes(e.type))return;
    if(!token||++serial>128){bad=true;return;}
    if(e.type==='pointerdown')pointer=true;
    if(e.type==='pointerup'||e.type==='pointercancel')pointer=false;
    if(e.type==='gotpointercapture'){if(captures.size>=16)bad=true;else captures.add(e.pointerId);}
    if(e.type==='lostpointercapture')captures.delete(e.pointerId);
    if(e.type==='pointercancel')bad=true;
    if(e.type==='compositionstart')composing=true;
    if(e.type==='compositionend')composing=false;
    let key;
    if(e.type==='keydown'||e.type==='keyup'){
      if(!allowedKeys.includes(e.key)){bad=true;return;}key=e.key==='A'?'a':e.key;
      if(e.type==='keydown'){if(keys.has(e.code)||keys.size>=4)bad=true;keys.add(e.code);}
      else{if(!keys.has(e.code))bad=true;keys.delete(e.code);}
    }
    notify(JSON.stringify({action,token,serial,type:e.type,target:original?'source':'other',...(key===undefined?{}:{key})}));
  };
  for(const type of types)doc.addEventListener(type,receive,true);
  return Object.freeze({
    arm(next){if(!live||typeof next!=='string'||next.length!==32||!source.isConnected)throw Error('arm');token=next;return true;},
    state(){return {connected:source.isConnected&&(source===doc||source.ownerDocument===doc),pointer,captures:captures.size,keys:keys.size,composing,bad};},
    contains(node){return source.isConnected&&node&&node.isConnected&&source.contains(node);},
    offset(){const scroller=source===doc?doc.scrollingElement:source;
      if(!scroller||!scroller.isConnected)throw Error('scroll');return {x:scroller.scrollLeft,y:scroller.scrollTop};},
    focused(){return source.isConnected&&(source.getRootNode().activeElement===source||doc.activeElement===source);},
    prepareText(text,mode){
      if(!this.focused()||typeof text!=='string'||text.length>20000||!['replace','append'].includes(mode))return false;
      const value=('value' in source)?source.value:source.textContent;
      if(typeof value!=='string'||value.length>65536)return false;
      expected=mode==='replace'?text:value+text;return true;
    },
    accepted(){
      if(!this.focused()||typeof expected!=='string'||composing)return false;
      return (('value' in source)?source.value:source.textContent)===expected;
    },
    async frame(){await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return this.state();},
    close(){live=false;token='';expected=undefined;for(const type of types)doc.removeEventListener(type,receive,true);captures.clear();keys.clear();return true;}
  });
}`;
const armMonitor = 'function(token){return this.arm(token);}';
const frameMonitor = 'function(){return this.frame();}';
const closeMonitor = 'function(){return this.close();}';

/** Authentic original-world events plus actual issued commands, never a site
 * success flag. One instance occupies the existing tab mutation execution. */
export class TrustedObservation {
  private readonly scope = Object.freeze({});
  private readonly group = `arbol-action-${opaque()}`;
  private readonly events: EventReceipt[] = [];
  private readonly issued = new Map<string, number>();
  private readonly pending = new Set<string>();
  private remove = () => {};
  private monitor?: string;
  private context?: Context;
  private signature?: string;
  private invalid = false;
  private closed = false;
  private serial = 0;
  private cleanup?: Promise<void>;
  private dragData?: ActionDragData;
  private constructor(readonly target: ActionTarget, readonly operation: string,
    private readonly interception: InterceptionAcknowledgement, private readonly registration: Registration) {}

  static async open(target: ActionTarget, operation: string, interception: InterceptionAcknowledgement): Promise<TrustedObservation> {
    target.guard(); interception.assertCurrent();
    const channel = target.frame.receipt.channel;
    let registration = registrations.get(channel);
    if (!registration) {
      registration = { world: `arbol_action_${opaque()}`, binding: `arbol_event_${opaque()}`, failed: false };
      registrations.set(channel, registration);
    }
    if (registration.failed || registration.active) throw staleSnapshot();
    const observation = new TrustedObservation(target, operation, interception, registration);
    registration.active = observation.scope;
    try { await observation.install(); return observation; }
    catch (error) { await observation.close(); throw error; }
  }
  private receive(event: ActionEvent): void {
    if (this.closed) return;
    const registration = this.registration, receipt = this.target.frame.receipt;
    if (event.kind === 'context') {
      if (event.name !== registration.world || event.default || event.frame !== this.target.frame.frameId) return;
      const context = Object.freeze({ receipt, id: event.id, unique: event.unique });
      if (this.context && (this.context.id !== context.id || this.context.unique !== context.unique)) this.invalid = true;
      registration.context = context;
    } else if (event.kind === 'cleared' || event.kind === 'lost' || (event.kind === 'destroyed' &&
        (event.id === registration.context?.id || event.unique === registration.context?.unique))) {
      if (this.context) this.invalid = true;
      delete registration.context;
    } else if (event.kind === 'binding') {
      if (event.name !== registration.binding) return;
      if (!this.context || event.context !== this.context.id) { this.invalid = true; return; }
      let data: any; try { data = JSON.parse(event.payload); } catch { this.invalid = true; return; }
      if (data?.action !== this.target.execution.action || typeof data.token !== 'string' || !this.issued.has(data.token) ||
          !Number.isSafeInteger(data.serial) || data.serial !== this.serial + 1 || data.serial > 128 ||
          !['pointerdown', 'pointerup', 'pointercancel', 'gotpointercapture', 'lostpointercapture', 'mousedown', 'mouseup', 'click', 'keydown', 'keyup',
            'beforeinput', 'input', 'compositionstart', 'compositionend', 'wheel'].includes(data.type) ||
          !['source', 'other'].includes(data.target) || this.events.length >= 128) { this.invalid = true; return; }
      this.serial = data.serial;
      if (['keydown', 'keyup'].includes(data.type) && !Object.values(physicalKeys).some(key => key[0] === data.key)) { this.invalid = true; return; }
      this.events.push(Object.freeze({ type: data.type, token: data.token, serial: data.serial, target: data.target,
        ...(data.key !== undefined ? { key: data.key } : {}) }));
    } else if (event.kind === 'drag') {
      // Until the drag leaf installs its exact action path, unexpected HTML
      // continuation cannot be mistaken for a settled primary click.
      this.dragData = event.data; this.invalid = true;
    }
  }
  guard = (): void => {
    this.target.guard(); this.interception.assertCurrent();
    if (this.closed || this.invalid || this.registration.failed || this.registration.active !== this.scope ||
        !this.context || this.registration.context?.unique !== this.context.unique ||
        this.registration.context.id !== this.context.id || this.context.receipt !== this.target.frame.receipt) throw staleSnapshot();
  };
  private command(method: string, params?: object, guard = this.guard): Promise<unknown> {
    return this.target.inspection.readiness.command(this.target.frame.receipt.page, guard, method, params, this.target.frame.session);
  }
  private async install(): Promise<void> {
    const { target, registration } = this;
    const initial = () => { target.guard(); if (this.closed || registration.active !== this.scope || registration.failed) throw staleSnapshot(); };
    this.remove = target.inspection.readiness.observeActions(target.frame, initial, target.execution.signal, event => this.receive(event));
    target.execution.signal.addEventListener('abort', this.abort, { once: true });
    if (!registration.setup) {
      const setup = (async () => {
        acknowledgement(await this.command('Runtime.enable', undefined, initial)); initial();
        acknowledgement(await this.command('Runtime.addBinding', { name: registration.binding, executionContextName: registration.world }, initial)); initial();
        const result = await this.command('Page.addScriptToEvaluateOnNewDocument', { source: 'void 0;', worldName: registration.world,
          includeCommandLineAPI: false, runImmediately: true }, initial) as { identifier?: string };
        initial(); if (!result.identifier || result.identifier.length > 256) throw staleSnapshot();
      })();
      registration.setup = setup;
      void setup.catch(() => { registration.failed = true; });
    }
    await registration.setup; initial();
    const world = await this.command('Page.createIsolatedWorld', { frameId: target.frame.frameId, worldName: registration.world,
      grantUniveralAccess: false }, initial) as { executionContextId?: number };
    initial(); const context = registration.context;
    if (!context || context.receipt !== target.frame.receipt || world.executionContextId !== context.id) throw staleSnapshot();
    this.context = context; this.guard();
    const classified = await target.inspection.fields.classify(target.frame, this.guard); this.guard();
    const field = classified.nodes.get(target.backend);
    if (!field || field.sensitive || field.unavailable) throw staleSnapshot(); this.signature = field.signature;
    const resolved = await this.command('DOM.resolveNode', { backendNodeId: target.backend, executionContextId: context.id,
      objectGroup: this.group }) as { object?: { objectId?: string } };
    this.guard(); if (!resolved.object?.objectId) throw staleSnapshot();
    const result = await this.command('Runtime.callFunctionOn', { uniqueContextId: context.unique,
      functionDeclaration: `function(source,action,binding){return (${installMonitor}).call(source,action,binding);}`,
      arguments: [{ objectId: resolved.object.objectId }, { value: target.execution.action }, { value: registration.binding }],
      objectGroup: this.group, silent: true, returnByValue: false, userGesture: false }) as {
        result?: { objectId?: string }; exceptionDetails?: unknown };
    this.guard(); if (result.exceptionDetails || !result.result?.objectId) throw staleSnapshot();
    this.monitor = result.result.objectId;
  }
  private readonly abort = () => { void this.close().catch(() => {}); };
  private async call(functionDeclaration: string, args: readonly object[] = [], awaitPromise = false): Promise<unknown> {
    this.guard(); if (!this.monitor) throw staleSnapshot();
    const result = await this.command('Runtime.callFunctionOn', { uniqueContextId: this.context!.unique,
      functionDeclaration: `function(monitor,...args){return (${functionDeclaration}).apply(monitor,args);}`,
      arguments: [{ objectId: this.monitor }, ...args], silent: true, returnByValue: true, userGesture: false, awaitPromise }) as { result?: { value?: unknown }; exceptionDetails?: unknown };
    this.guard(); if (result.exceptionDetails || !result.result) throw staleSnapshot(); return result.result.value;
  }
  private async issue(method: string, params: object): Promise<IssuedInput> {
    this.guard();
    const classified = await this.target.inspection.fields.classify(this.target.frame, this.guard); this.guard();
    const field = classified.nodes.get(this.target.backend);
    if (!field || field.sensitive || field.unavailable || field.signature !== this.signature) throw staleSnapshot();
    const token = opaque();
    if (this.issued.size >= 32 || await this.call(armMonitor, [{ value: token }]) !== true) throw staleSnapshot();
    this.guard();
    let command = 0;
    await this.target.execution.dispatch(() => {
      // The real command number is read only after ActionQueue reserves issue.
      this.guard(); command = this.target.execution.command; this.issued.set(token, command); this.pending.add(token);
      return this.command(method, params);
    }).then(result => {
      this.guard();
      if (!result || typeof result !== 'object' || Array.isArray(result) || Object.keys(result).length) throw staleSnapshot();
      this.pending.delete(token);
    });
    this.guard(); return Object.freeze({ token, command });
  }
  mouse(type: 'mousePressed' | 'mouseReleased', point: TargetPoint): Promise<IssuedInput> {
    if (![point.x, point.y].every(value => Number.isFinite(value) && value >= 0 && value <= 100000)) throw staleSnapshot();
    return this.issue('Input.dispatchMouseEvent', { type, x: point.x, y: point.y, button: 'left',
      buttons: type === 'mousePressed' ? 1 : 0, clickCount: 1, modifiers: 0, pointerType: 'mouse' });
  }
  async focus(): Promise<void> {
    await this.issue('DOM.focus', { backendNodeId: this.target.backend }); this.guard();
    if (await this.call('function(){return this.focused();}') !== true) throw staleSnapshot();
  }
  key(key: PhysicalKey, type: 'keyDown' | 'keyUp', modifiers: 0 | 4 | 8): Promise<IssuedInput> {
    if (!Object.hasOwn(physicalKeys, key) || ![0, 4, 8].includes(modifiers)) throw staleSnapshot();
    const [name, code, virtual] = physicalKeys[key];
    return this.issue('Input.dispatchKeyEvent', { type, modifiers, key: name, code, windowsVirtualKeyCode: virtual,
      autoRepeat: false, isSystemKey: false, ...(key === 'Shift' || key === 'Meta' ? { location: 1 } : {}),
      ...(type === 'keyDown' && key === 'Enter' ? { text: '\r', unmodifiedText: '\r' } : {}),
      ...(type === 'keyDown' && key === 'Space' ? { text: ' ', unmodifiedText: ' ' } : {}),
      ...(type === 'keyDown' && key === 'A' && modifiers === 4 ? { commands: ['selectAll'] } : {}) });
  }
  async prepareText(text: string, mode: 'replace' | 'append'): Promise<void> {
    if (await this.call('function(text,mode){return this.prepareText(text,mode);}', [{ value: text }, { value: mode }]) !== true) throw staleSnapshot();
  }
  /** Fixed native editor command, not a DOM selection/value setter. */
  appendSelection(): Promise<IssuedInput> {
    return this.issue('Input.dispatchKeyEvent', { type: 'keyDown', key: 'End', code: 'End', windowsVirtualKeyCode: 35,
      modifiers: 0, autoRepeat: false, isSystemKey: false, commands: ['moveToEndOfDocument'] });
  }
  insertText(text: string): Promise<IssuedInput> { return this.issue('Input.insertText', { text }); }
  async covers(backend: number): Promise<boolean> {
    this.guard();
    const resolved = await this.command('DOM.resolveNode', { backendNodeId: backend, executionContextId: this.context!.id,
      objectGroup: this.group }) as { object?: { objectId?: string } };
    this.guard(); if (!resolved.object?.objectId) throw staleSnapshot();
    return await this.call('function(node){return this.contains(node);}', [{ objectId: resolved.object.objectId }]) === true;
  }
  scroll(point: TargetPoint, deltaX: number, deltaY: number): Promise<IssuedInput> {
    if (![deltaX, deltaY].every(value => Number.isInteger(value) && Math.abs(value) <= 2000) || (!deltaX && !deltaY) ||
        ![point.x, point.y].every(value => Number.isFinite(value) && value >= 0 && value <= 100000)) throw staleSnapshot();
    return this.issue('Input.synthesizeScrollGesture', { x: point.x, y: point.y, xDistance: -deltaX, yDistance: -deltaY,
      preventFling: true, speed: 800, gestureSourceType: 'mouse', repeatCount: 0 });
  }
  private async offset(): Promise<Readonly<{ x: number; y: number }>> {
    const value = await this.call('function(){return this.offset();}') as { x?: number; y?: number };
    if (!Number.isFinite(value?.x) || !Number.isFinite(value?.y)) throw staleSnapshot();
    return Object.freeze({ x: value.x!, y: value.y! });
  }
  private async presentedOffset(): Promise<Readonly<{ x: number; y: number; time: number }>> {
    await this.balanced(); const before = await this.offset(); this.guard();
    // An actual compositor capture is used only as a current presentation
    // barrier. No pixels are compared, delivered, cached or persisted, and this
    // grants no public screenshot proof. It supplements genuine gesture/wheel
    // settlement; equal offsets or images alone can never complete the action.
    let frame: { data?: string } | undefined = await this.command('Page.captureScreenshot',
      { format: 'png', fromSurface: true, captureBeyondViewport: false }) as { data?: string };
    try {
      this.guard();
      if (typeof frame.data !== 'string' || frame.data.length < 32 || frame.data.length > 12 * 1024 * 1024 ||
          !Buffer.from(frame.data.slice(0, 32), 'base64').subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) throw staleSnapshot();
    } finally { frame = undefined; }
    const after = await this.offset(); this.guard();
    if (before.x !== after.x || before.y !== after.y) throw staleSnapshot();
    return Object.freeze({ ...after, time: performance.now() });
  }
  private seen(type: string, issued: IssuedInput, target: EventReceipt['target'] = 'source'): boolean {
    return this.issued.get(issued.token) === issued.command && this.events.some(event => event.type === type && event.token === issued.token && event.target === target);
  }
  private async balanced(): Promise<void> {
    const state = await this.call(frameMonitor, [], true) as MonitorState;
    this.guard();
    if (!state || !state.connected || state.pointer !== false || state.captures !== 0 || state.keys !== 0 || state.composing !== false ||
        state.bad !== false || this.pending.size) throw staleSnapshot();
  }
  private checkStrokes(strokes: readonly KeyStroke[], allowTabTransfer: boolean): void {
    this.guard();
    for (const stroke of strokes) {
      const name = physicalKeys[stroke.key][0];
      if (!this.events.some(event => event.type === 'keydown' && event.target === 'source' && event.token === stroke.down.token && event.key === name) ||
          !this.events.some(event => event.type === 'keyup' && (event.target === 'source' || allowTabTransfer) && event.token === stroke.up.token && event.key === name) ||
          this.issued.get(stroke.down.token) !== stroke.down.command || this.issued.get(stroke.up.token) !== stroke.up.command) throw staleSnapshot();
    }
  }
  async settleKeys(strokes: readonly KeyStroke[], allowTabTransfer: boolean): Promise<void> {
    await this.balanced(); this.checkStrokes(strokes, allowTabTransfer);
    const last = strokes.at(-1)?.up.command, { execution } = this.target;
    if (!last || last !== execution.command) throw staleSnapshot();
    execution.settle({ action: execution.action!, operation: this.operation, original: execution.stamp.document,
      current: this.target.frame.receipt, delivered: true, quiescent: true, command: last });
  }
  async settleText(strokes: readonly KeyStroke[], insertion: IssuedInput): Promise<void> {
    await this.balanced(); this.checkStrokes(strokes, false);
    if (!this.seen('beforeinput', insertion) || !this.seen('input', insertion) ||
        insertion.command !== this.target.execution.command || await this.call('function(){return this.accepted();}') !== true) throw staleSnapshot();
    this.guard(); const { execution } = this.target;
    execution.settle({ action: execution.action!, operation: this.operation, original: execution.stamp.document,
      current: this.target.frame.receipt, delivered: true, quiescent: true, command: insertion.command });
  }
  async settleScroll(gesture: IssuedInput): Promise<void> {
    this.guard();
    if (!this.seen('wheel', gesture) || this.pending.size || gesture.command !== this.target.execution.command) throw staleSnapshot();
    let previous = await this.presentedOffset();
    for (;;) {
      const current = await this.presentedOffset(); this.guard();
      if (current.time - previous.time >= 16 && current.x === previous.x && current.y === previous.y) break;
      if (current.x !== previous.x || current.y !== previous.y) previous = current;
    }
    await this.balanced(); this.guard(); const { execution } = this.target;
    execution.settle({ action: execution.action!, operation: this.operation, original: execution.stamp.document,
      current: this.target.frame.receipt, delivered: true, quiescent: true, command: gesture.command });
  }
  async settleClick(press: IssuedInput, release: IssuedInput): Promise<void> {
    await this.balanced(); this.guard();
    if (!this.seen('pointerdown', press) || !this.seen('mousedown', press) || !this.seen('pointerup', release) ||
        !this.seen('mouseup', release) || !this.seen('click', release) || release.command !== this.target.execution.command) throw staleSnapshot();
    const { execution } = this.target;
    execution.settle({ action: execution.action!, operation: this.operation, original: execution.stamp.document,
      current: this.target.frame.receipt, delivered: true, quiescent: true, command: release.command });
  }
  /** Cleanup only deactivates this exact isolated monitor. It cannot issue an
   * input, unlock native policy, settle a sequence or touch a successor world. */
  close(): Promise<void> {
    if (this.cleanup) return this.cleanup;
    this.closed = true; this.remove(); this.target.execution.signal.removeEventListener('abort', this.abort);
    this.events.length = 0; delete this.dragData;
    this.cleanup = (async () => {
      const { target, registration } = this;
      const cleanupGuard = () => {
        target.inspection.authority.assertHealthy();
        target.inspection.documents.assertCurrent(target.execution.stamp.target, target.frame.receipt);
        target.inspection.readiness.assertInspection(target.frame, () => {});
        if (registration.active !== this.scope || !this.context || registration.context?.unique !== this.context.unique) throw staleSnapshot();
      };
      try {
        if (this.monitor && this.context) {
          cleanupGuard();
          const result = await this.command('Runtime.callFunctionOn', { uniqueContextId: this.context.unique,
            functionDeclaration: `function(monitor){return (${closeMonitor}).call(monitor);}`, arguments: [{ objectId: this.monitor }],
            returnByValue: true, silent: true, userGesture: false }, cleanupGuard) as { result?: { value?: unknown }; exceptionDetails?: unknown };
          cleanupGuard(); if (result.exceptionDetails || result.result?.value !== true) throw staleSnapshot();
          await this.command('Runtime.releaseObjectGroup', { objectGroup: this.group }, cleanupGuard); cleanupGuard();
        }
      } catch {
        // A failed cleanup on a surviving original context must not accumulate
        // listeners/objects on the next action. New documents start inert.
        if (registration.context?.receipt === target.frame.receipt) registration.failed = true;
      } finally {
        if (registration.active === this.scope) delete registration.active;
        this.issued.clear(); this.pending.clear(); delete this.monitor;
      }
    })();
    return this.cleanup;
  }
}
