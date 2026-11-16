import type { Debugger, WebContents } from 'electron';
import { performance } from 'node:perf_hooks';
import { assertNativeFailureBoundary, type NativeFailureBoundary } from '../runtime/bootstrap.js';
import { unavailable } from '../contracts/errors.js';
import { bindingKey } from '../native/retirement.js';
import type { DocumentReceipt } from './authority.js';
import type { HostDocuments, HostDocument, DocumentPreparation } from './documents.js';
import { PresentationSuperseded, presentationCategory } from './documents.js';
import { staleSnapshot } from './authority.js';
import { assertPageSurface, type PageSurface } from './windows.js';
import type { TabTarget } from './tabs.js';

interface Channel {
  readonly page: PageSurface;
  readonly contents: WebContents;
  readonly debugger: Debugger;
  readonly identity: object;
  active: boolean;
  interception: 'unknown' | 'enabled' | 'disabled';
  interceptionInFlight?: object;
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
    const channel: Channel = { page, contents, debugger: debugger_, identity: Object.freeze({}), active: true, interception: 'unknown' };
    this.channels.set(page, channel);
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
  async command(page: PageSurface, assertCurrent: () => void, method: string, params?: object): Promise<unknown> {
    const channel = this.owned(page);
    const check = () => { this.synchronous(assertCurrent); this.assertChannel(channel); };
    check(); if (channel.interceptionInFlight) throw staleSnapshot();
    const intercept = method === 'Input.setInterceptDrags', token = Object.freeze({});
    const enabled = (params as { enabled?: unknown } | undefined)?.enabled;
    if (intercept) {
      if (typeof enabled !== 'boolean') throw staleSnapshot();
      // The engine may apply this before a stale/failed reply. Never retain a
      // prior disabled acknowledgement across an ambiguous opposite effect.
      channel.interception = 'unknown'; channel.interceptionInFlight = token;
    }
    try {
      check(); const result: unknown = await channel.debugger.sendCommand(method, params); check();
      if (intercept) {
        if (channel.interceptionInFlight !== token) throw staleSnapshot(); emptyAck(result);
        channel.interception = enabled ? 'enabled' : 'disabled';
      }
      return result;
    } finally { if (channel.interceptionInFlight === token) delete channel.interceptionInFlight; }
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
