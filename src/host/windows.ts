import { consumeArmedHostSnapshot, type ArmedHostSnapshot } from '../runtime/custody.js';
import { BaseWindow, WebContentsView, View, type Input, type Session } from 'electron';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import type { ProfileSessions } from '../profiles/session.js';
import type { NativeFailureBoundary } from '../runtime/bootstrap.js';
import type { Binding } from '../native/api.js';
import { bindingKey } from '../native/retirement.js';
import { assertCandidateTrust } from '../native/manifest.js';
import { unavailable } from '../contracts/errors.js';

/** Resolved only in the physical lib/host graph, never relative to a bundled entry. */
export const shellURL = new URL('../shell/index.html', import.meta.url).href;
const preloadPath = fileURLToPath(new URL('../shell/preload.cjs', import.meta.url));
// Keep these native offsets aligned with the trusted shell stylesheet.
const toolbarHeight = 48;
const sidebarWidth = (width: number) => width < 720 ? 168 : 216;
export interface PageSurface {
  readonly view: WebContentsView;
  readonly window: WindowHost;
  readonly session: Session;
  readonly identity: Readonly<Pick<Binding, 'id' | 'nonce' | 'webContentsId'>>;
  binding(): Binding;
  setNativeBlocked(blocked: boolean): Binding;
  restorePresentation(): void;
  /** Presentation restores never change input policy. */
  present(selected: boolean): void;
  /** Authentic original retirement; never inferred from a missing native view. */
  retirement(): PageRetirement | undefined;
  retire(): Promise<void>;
}
export interface PageRetirement {
  readonly page: PageSurface;
  readonly completion: Promise<void>;
  readonly phase: 'retiring' | 'retired' | 'failed';
}
export interface WindowHost {
  readonly window: BaseWindow;
  readonly shell: WebContentsView;
  readonly origin: string;
  createPage(): PageSurface;
  assertHealthy(): void;
  isActiveProfile(): boolean;
  hasForegroundWork(): boolean;
  select(page: PageSurface, commit?: () => void): void;
  /** Physical selection, independent of a logical tab retaining a retired page. */
  selected(): PageSurface | undefined;
  clearSelection(page: PageSurface, commit?: () => void): void;
  owns(page: PageSurface): boolean;
  presentationStable(): boolean;
  onPresentation(fence: (pages: readonly PageSurface[]) => void, changed: (pages: readonly PageSurface[]) => void): () => void;
  onTabChromeChange(changed: () => void): () => void;
  onClosed(closed: () => void): void;
  guardRetirementTransition(operation: () => void): void;
  close(): Promise<void>;
}
const hosts = new WeakSet<object>(), surfaces = new WeakSet<object>();
interface ProfilePlacement {
  refresh(): void;
  changed(): void;
  canSwitch(): boolean;
  requestClose(): void;
}
interface BrowserFrame {
  readonly window: BaseWindow;
  readonly profiles: Map<WindowHost, ProfilePlacement>;
  active: WindowHost | undefined;
  switching: boolean;
  closing: boolean;
}
const browserFrames = new WeakMap<NativeFailureBoundary, BrowserFrame>();
const profileFrames = new WeakMap<WindowHost, BrowserFrame>();
const retirementRecords = new WeakMap<PageSurface, PageRetirement>();
function browserFrame(boundary: NativeFailureBoundary): BrowserFrame {
  const existing = browserFrames.get(boundary);
  if (existing) {
    if (existing.closing || existing.window.isDestroyed()) throw unavailable('browser');
    return existing;
  }
  const window = new BaseWindow({ width: 1120, height: 800, minWidth: 560, minHeight: 480,
    title: 'Arbol Browser', titleBarStyle: 'hidden', trafficLightPosition: { x: 14, y: 16 }, show: false });
  const frame: BrowserFrame = { window, profiles: new Map(), active: undefined, switching: false, closing: false };
  browserFrames.set(boundary, frame);
  window.on('close', event => {
    event.preventDefault();
    if (frame.closing) return;
    frame.closing = true;
    for (const profile of frame.profiles.values()) profile.requestClose();
  });
  return frame;
}
/** Both profiles must already have been admitted in this exact native window.
 * The caller owns profile authentication and the owner-initiated switch. */
export function selectWindowProfile(source: WindowHost, destination: WindowHost): void {
  assertWindowHost(source); assertWindowHost(destination);
  const frame = profileFrames.get(source);
  const oldProfile = frame?.profiles.get(source), newProfile = frame?.profiles.get(destination);
  if (!frame || frame !== profileFrames.get(destination) || frame.closing || frame.switching ||
      frame.active !== source || !oldProfile?.canSwitch() || !newProfile?.canSwitch())
    throw unavailable('browser');
  if (source === destination) return;
  const focused = frame.window.isFocused();
  frame.switching = true;
  try {
    frame.active = undefined;
    oldProfile.refresh();
    frame.active = destination;
    newProfile.refresh();
  } finally { frame.switching = false; }
  if (focused && frame.window.isFocused()) destination.shell.webContents.focus();
  newProfile.changed();
}
export function assertPageRetirement(page: PageSurface, receipt: PageRetirement): void {
  if (!surfaces.has(page) || retirementRecords.get(page) !== receipt || receipt.page !== page || receipt.phase === 'failed')
    throw unavailable('browser');
}
export function assertWindowHost(host: WindowHost): void {
  if (!hosts.has(host) || host.window.isDestroyed()) throw unavailable('browser');
}
export function assertPageSurface(page: PageSurface): void {
  if (!surfaces.has(page)) throw unavailable('browser');
  assertWindowHost(page.window);
}
function clipboardShortcut(input: Input): boolean {
  const key = input.key.toLowerCase();
  return input.meta && !input.alt && !input.control && !input.shift && (key === 'c' || key === 'x');
}

function preferences(session: Session) {
  return { session, sandbox: true, contextIsolation: true, nodeIntegration: false,
    nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false, webSecurity: true,
    allowRunningInsecureContent: false, webviewTag: false, navigateOnDragDrop: false,
    backgroundThrottling: false, devTools: false } as const;
}
/** Main-process contribution only. The installed boundary is supplied by bootstrap;
 * this creates no EngineAuthority and no document/input readiness. */
export function createWindowHost(sessions: ProfileSessions, boundary: NativeFailureBoundary,
  onCloseRequested: () => void, proof?: ArmedHostSnapshot, existingHost?: WindowHost): WindowHost {
  if (proof) consumeArmedHostSnapshot(proof, boundary.native.trust, 'window', onCloseRequested);
  else assertCandidateTrust(boundary.native.trust);
  boundary.fatal.assertHealthy(); boundary.native.assertIntegrity();
  if (sessions.website === sessions.shell || sessions.shell.getStoragePath() !== null ||
      sessions.website.getStoragePath() === null || realpathSync(preloadPath) !== preloadPath ||
      realpathSync(fileURLToPath(shellURL)) !== fileURLToPath(shellURL)) throw unavailable('browser');
  if (existingHost) assertWindowHost(existingHost);
  const frame = existingHost ? profileFrames.get(existingHost) : browserFrame(boundary);
  if (!frame || frame !== browserFrames.get(boundary) || frame.closing) throw unavailable('browser');
  const { window } = frame;
  const shell = new WebContentsView({ webPreferences: { ...preferences(sessions.shell), preload: preloadPath } });
  shell.setVisible(false);
  let shellBinding = boundary.native.ownership.bind(window.getNativeWindowHandle(), shell.webContents.id,
    () => { window.contentView.addChildView(shell); });
  // Chromium shell roots have no implicit native bypass. Only this bound shell is enabled.
  shellBinding = boundary.native.ownership.mark(bindingKey(shellBinding), false);
  if (shellBinding.blocked || shellBinding.retired) return boundary.fatal.fail('native_boundary_unavailable');
  shell.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  shell.webContents.on('before-input-event', (event, input) => {
    if (clipboardShortcut(input)) event.preventDefault();
  });
  shell.webContents.on('will-navigate', event => event.preventDefault());
  shell.webContents.on('will-frame-navigate', event => event.preventDefault());
  shell.webContents.on('will-attach-webview', event => event.preventDefault());
  const pages = new Set<PageSurface>();
  let selected: PageSurface | undefined, closing = false;
  let placementDepth = 0, placementVersion = 0;
  const pendingPresentation = new Set<PageSurface>(), categories = new Map<PageSurface, string>();
  const observers = new Set<{ fence: (pages: readonly PageSurface[]) => void; changed: (pages: readonly PageSurface[]) => void }>();
  const chromeObservers = new Set<() => void>();
  const closedObservers = new Set<() => void>();
  const active = () => frame.active === host;
  const category = (page: PageSurface) => {
    const foreground = active() && selected === page, visible = page.view.getVisible();
    if (!foreground && visible) return 'invalid';
    return foreground && visible && window.isVisible() && !window.isMinimized() ? 'presented' : 'hidden';
  };
  const synchronous = (work: () => void) => {
    const result: unknown = work(); if (result !== undefined) return boundary.fatal.fail('native_retirement_unavailable');
  };
  const observe = (work: () => void) => {
    try { synchronous(work); } catch { return boundary.fatal.fail('native_retirement_unavailable'); }
  };
  const presentSelection = (next: PageSurface | undefined, owns = () => true, targets: Iterable<PageSurface> = pages) => {
    for (const page of targets) if (!page.retirement()) {
      if (!owns()) throw unavailable('browser'); page.present(active() && page === next);
      if (!owns()) throw unavailable('browser');
    }
  };
  const selectPhysical = (next: PageSurface | undefined, commit: () => void = () => {}, explicit?: readonly PageSurface[]) => {
    if (placementVersion >= Number.MAX_SAFE_INTEGER) return boundary.fatal.fail('native_retirement_unavailable');
    const previous = selected, version = ++placementVersion;
    const affected = Object.freeze(explicit ?? (previous === next ? [] : [previous, next].filter((page): page is PageSurface => Boolean(page))));
    placementDepth++;
    for (const page of affected) pendingPresentation.add(page);
    try {
      for (const observer of observers) observe(() => observer.fence(affected));
      if (version !== placementVersion) throw unavailable('browser');
      selected = next;
      presentSelection(next, () => version === placementVersion, explicit);
      if (version !== placementVersion) throw unavailable('browser');
      synchronous(commit); // actual registry selection/binding co-commit, while publication is deferred
      if (version !== placementVersion) throw unavailable('browser');
    }
    catch (error) {
      if (version === placementVersion) selected = previous;
      // A newer genuine Close/selection owns both maps. Reconcile its actual
      // placement, never clear it by selecting the retired original.
      const winner = placementVersion;
      try { presentSelection(selected, () => placementVersion === winner); }
      catch { return boundary.fatal.fail('native_retirement_unavailable'); }
      throw error;
    } finally {
      placementDepth--;
      if (placementDepth === 0) {
        const affected = Object.freeze([...pendingPresentation]); pendingPresentation.clear();
        for (const page of affected) if (pages.has(page) && !page.retirement()) categories.set(page, category(page));
        for (const observer of observers) observe(() => observer.changed(affected));
      }
    }
  };
  const layout = () => {
    if (closing || window.isDestroyed()) return;
    try {
      const { width, height } = window.getContentBounds();
      shell.setBounds({ x: 0, y: 0, width, height });
      presentSelection(selected);
    } catch { return boundary.fatal.fail('native_retirement_unavailable'); }
  };
  const host: WindowHost = Object.freeze({ window, shell, origin: shellURL,
    assertHealthy() { assertWindowHost(host); boundary.fatal.assertHealthy(); boundary.native.assertIntegrity(); },
    isActiveProfile: active,
    // An attached AppKit sheet can be key while its parent window is disabled.
    hasForegroundWork: () => active() && !window.isDestroyed() && (window.isFocused() || !window.isEnabled()),
    createPage(): PageSurface {
      assertWindowHost(host); boundary.fatal.assertHealthy(); boundary.native.assertIntegrity();
      if (closing) throw unavailable('browser');
      const view = new WebContentsView({ webPreferences: { ...preferences(sessions.website), disableHtmlFullscreenWindowResize: true } });
      view.setVisible(false);
      let current = boundary.native.ownership.bind(window.getNativeWindowHandle(), view.webContents.id,
        () => { window.contentView.addChildView(view); });
      let retired = false;
      const shield = new View();
      shield.setBackgroundColor('#00000000');
      shield.setVisible(false);
      window.contentView.addChildView(shield);
      view.webContents.on('before-input-event', (event, input) => {
        if (retired || current.blocked || clipboardShortcut(input)) event.preventDefault();
      });
      view.webContents.on('will-attach-webview', event => event.preventDefault());
      // The default popup route never permits Electron to create/retarget a window.
      view.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
      const identity = Object.freeze({ id: current.id, nonce: current.nonce, webContentsId: current.webContentsId });
      const page: PageSurface = Object.freeze({ view, window: host, session: sessions.website, identity,
        binding() { if (retired) throw unavailable('browser');
          current = boundary.native.ownership.bindingInfo(bindingKey(current)); return current; },
        setNativeBlocked(blocked: boolean) {
          if (retired) throw unavailable('browser');
          current = boundary.native.ownership.mark(bindingKey(current), blocked);
          shield.setVisible(active() && selected === page && current.blocked); return current;
        },
        restorePresentation() {
          // restore unhides native subviews. It is never a background probe.
          if (retired || selected !== page || !view.getVisible() || !window.isVisible() || window.isMinimized()) throw unavailable('browser');
          current = boundary.native.ownership.restore(bindingKey(current));
        },
        present(active: boolean) {
          if (retired) return;
          const { width, height } = window.getContentBounds();
          const x = sidebarWidth(width);
          view.setVisible(active);
          // Website and hit-test shield cover only the content beside the shell controls.
          view.setBounds({ x, y: toolbarHeight, width: Math.max(0, width - x), height: Math.max(0, height - toolbarHeight) });
          shield.setBounds(view.getBounds()); shield.setVisible(active && current.blocked);
        },
        retirement: () => retirementRecords.get(page),
        retire() {
          const existing = retirementRecords.get(page);
          if (existing) { assertPageRetirement(page, existing); return existing.completion; }
          if (retired) return boundary.fatal.fail('native_retirement_unavailable');
          let resolve!: () => void, reject!: (reason: unknown) => void;
          let phase: PageRetirement['phase'] = 'retiring';
          const completion = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
          const receipt: PageRetirement = Object.freeze({ page, completion, get phase() { return phase; } });
          // Publish the exact join handle before native/callback reentry. No
          // second mark/detach/close may be issued against this original page.
          retirementRecords.set(page, receipt); retired = true;
          void (async () => {
            current = await boundary.retire(bindingKey(current), window.contentView, view);
            window.contentView.removeChildView(shield);
            if (selected === page) selectPhysical(undefined);
            pages.delete(page); categories.delete(page);
            phase = 'retired';
          })().then(resolve, error => {
            phase = 'failed'; reject(error);
            return boundary.fatal.fail('native_retirement_unavailable');
          });
          return completion;
        },
      });
      // Keep Electron's actual modal only for the selected foreground user page.
      // The capability provider can install stricter document checks around this listener.
      const contents = view.webContents, emitter = contents as unknown as EventEmitter;
      const chromeChanged = () => { if (!closing && !retired) for (const changed of chromeObservers) changed(); };
      contents.on('page-title-updated', chromeChanged);
      contents.on('did-navigate', chromeChanged);
      contents.on('did-navigate-in-page', chromeChanged);
      const raw = EventEmitter.prototype.rawListeners.call(emitter, '-run-dialog');
      const listeners = EventEmitter.prototype.listeners.call(emitter, '-run-dialog');
      type DialogReply = (accepted: boolean, value: string) => void;
      const stock = raw[0] as ((info: unknown, reply: DialogReply) => unknown) | undefined;
      if (raw.length !== 1 || listeners.length !== 1 || stock !== listeners[0] || typeof stock !== 'function')
        return boundary.fatal.fail('native_boundary_unavailable');
      const dialog = async (info: unknown, reply: DialogReply) => {
        if (typeof reply !== 'function') return boundary.fatal.fail('native_boundary_unavailable');
      if (closing || retired || !active() || selected !== page || window.isDestroyed() || !window.isFocused() ||
            !view.getVisible() || page.binding().blocked) return reply(false, '');
        return Reflect.apply(stock, contents, [info, reply]);
      };
      EventEmitter.prototype.removeListener.call(emitter, '-run-dialog', stock);
      EventEmitter.prototype.on.call(emitter, '-run-dialog', dialog);
      const installed = EventEmitter.prototype.rawListeners.call(emitter, '-run-dialog');
      if (installed.length !== 1 || installed[0] !== dialog) return boundary.fatal.fail('native_boundary_unavailable');
      surfaces.add(page); pages.add(page); page.present(false); categories.set(page, category(page)); return page;
    },
    select(page: PageSurface, commit: () => void = () => {}) {
      assertPageSurface(page);
      if (closing || page.window !== host) throw unavailable('browser');
      const retired = page.retirement();
      if (retired) {
        assertPageRetirement(page, retired);
        // The logical tab may still be selected, but never its retired surface.
        selectPhysical(undefined, commit); return;
      }
      if (!pages.has(page)) throw unavailable('browser');
      selectPhysical(page, commit);
    },
    selected() { assertWindowHost(host); return selected; },
    owns(page: PageSurface) { return page.window === host && pages.has(page) && !page.retirement(); },
    presentationStable: () => !closing && !frame.switching && placementDepth === 0,
    onPresentation(fence: (pages: readonly PageSurface[]) => void, changed: (pages: readonly PageSurface[]) => void) {
      assertWindowHost(host); const observer = { fence, changed }; observers.add(observer);
      return () => { observers.delete(observer); };
    },
    onTabChromeChange(changed: () => void) {
      assertWindowHost(host); chromeObservers.add(changed);
      return () => { chromeObservers.delete(changed); };
    },
    onClosed(closed: () => void) {
      assertWindowHost(host); closedObservers.add(closed);
    },
    clearSelection(page: PageSurface, commit: () => void = () => {}) {
      assertPageSurface(page);
      const retirement = page.retirement();
      if (page.window !== host || (!pages.has(page) && !retirement)) throw unavailable('browser');
      if (retirement) observe(() => assertPageRetirement(page, retirement));
      const before = placementVersion;
      try {
        if (selected === page) selectPhysical(undefined, commit);
        else synchronous(commit);
      }
      catch {
        // A proven newer placement owns its consistent selection. The stale
        // retiring caller must not clear it or claim a physical failure.
        if (selected !== page && placementVersion > before + 1) return;
        return boundary.fatal.fail('native_retirement_unavailable');
      }
    },
    guardRetirementTransition(operation: () => void) {
      try {
        assertWindowHost(host); boundary.fatal.assertHealthy(); boundary.native.assertIntegrity();
        const result: unknown = operation();
        if (result !== undefined) return boundary.fatal.fail('native_retirement_unavailable');
        boundary.fatal.assertHealthy(); boundary.native.assertIntegrity();
      } catch { return boundary.fatal.fail('native_retirement_unavailable'); }
    },
    async close() {
      if (closing) throw unavailable('browser'); closing = true;
      await Promise.all([...pages].map(page => page.retire()));
      await boundary.retire(bindingKey(shellBinding), window.contentView, shell);
      window.removeListener('resize', layout);
      window.removeListener('show', windowPresentation); window.removeListener('hide', windowPresentation);
      window.removeListener('minimize', windowPresentation); window.removeListener('restore', windowPresentation);
      hosts.delete(host); profileFrames.delete(host); frame.profiles.delete(host);
      if (frame.active === host) {
        frame.active = frame.closing ? undefined : frame.profiles.keys().next().value;
        const next = frame.active && frame.profiles.get(frame.active);
        if (next) { next.refresh(); next.changed(); }
      }
      if (!frame.profiles.size) window.destroy();
      for (const closed of closedObservers) observe(closed);
      closedObservers.clear();
    },
  });
  const windowPresentation = () => {
    if (closing || window.isDestroyed()) return;
    const affected = [...pages].filter(page => !page.retirement() && categories.get(page) !== category(page));
    if (affected.length) selectPhysical(selected, () => {}, affected);
  };
  const refresh = () => {
    try {
      const affected = [...pages].filter(page => !page.retirement() && (page === selected || page.view.getVisible()));
      selectPhysical(selected, () => { shell.setVisible(active()); }, affected);
    } catch { return boundary.fatal.fail('native_retirement_unavailable'); }
  };
  hosts.add(host); profileFrames.set(host, frame);
  frame.profiles.set(host, { refresh, canSwitch: () => !closing && placementDepth === 0 && window.isEnabled(),
    requestClose: () => { if (!closing) onCloseRequested(); },
    changed: () => { for (const changed of chromeObservers) changed(); } });
  frame.active ??= host;
  window.on('resize', layout);
  window.on('show', windowPresentation); window.on('hide', windowPresentation);
  window.on('minimize', windowPresentation); window.on('restore', windowPresentation);
  layout(); refresh(); return host;
}
