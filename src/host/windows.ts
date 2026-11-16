import { BaseWindow, WebContentsView, View, type Session } from 'electron';
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
  select(page: PageSurface): void;
  /** Physical selection, independent of a logical tab retaining a retired page. */
  selected(): PageSurface | undefined;
  clearSelection(page: PageSurface): void;
  guardRetirementTransition(operation: () => void): void;
  close(): Promise<void>;
}
const hosts = new WeakSet<object>(), surfaces = new WeakSet<object>();
const retirementRecords = new WeakMap<PageSurface, PageRetirement>();
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
function preferences(session: Session) {
  return { session, sandbox: true, contextIsolation: true, nodeIntegration: false,
    nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false, webSecurity: true,
    allowRunningInsecureContent: false, webviewTag: false, navigateOnDragDrop: false,
    backgroundThrottling: false, devTools: false } as const;
}
/** Main-process contribution only. The installed boundary is supplied by bootstrap;
 * this creates no EngineAuthority and no document/input readiness. */
export function createWindowHost(sessions: ProfileSessions, boundary: NativeFailureBoundary,
  onCloseRequested: () => void): WindowHost {
  assertCandidateTrust(boundary.native.trust); boundary.fatal.assertHealthy(); boundary.native.assertIntegrity();
  if (sessions.website === sessions.shell || sessions.shell.getStoragePath() !== null ||
      sessions.website.getStoragePath() === null || realpathSync(preloadPath) !== preloadPath ||
      realpathSync(fileURLToPath(shellURL)) !== fileURLToPath(shellURL)) throw unavailable('browser');
  const window = new BaseWindow({ width: 1120, height: 800, minWidth: 560, minHeight: 480,
    title: 'Arbol Browser', show: false });
  const shell = new WebContentsView({ webPreferences: { ...preferences(sessions.shell), preload: preloadPath } });
  let shellBinding = boundary.native.ownership.bind(window.getNativeWindowHandle(), shell.webContents.id,
    () => { window.contentView.addChildView(shell); });
  // Chromium shell roots have no implicit native bypass. Only this bound shell is enabled.
  shellBinding = boundary.native.ownership.mark(bindingKey(shellBinding), false);
  if (shellBinding.blocked || shellBinding.retired) return boundary.fatal.fail('native_boundary_unavailable');
  shell.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  shell.webContents.on('will-navigate', event => event.preventDefault());
  shell.webContents.on('will-frame-navigate', event => event.preventDefault());
  shell.webContents.on('will-attach-webview', event => event.preventDefault());
  const pages = new Set<PageSurface>();
  let selected: PageSurface | undefined, closing = false;
  const presentSelection = (next: PageSurface | undefined) => {
    for (const page of pages) if (!page.retirement()) page.present(page === next);
  };
  const selectPhysical = (next: PageSurface | undefined) => {
    const previous = selected;
    try { presentSelection(next); }
    catch (error) {
      try { presentSelection(previous); }
      catch { return boundary.fatal.fail('native_retirement_unavailable'); }
      throw error;
    }
    selected = next;
  };
  const layout = () => {
    if (closing || window.isDestroyed()) return;
    try {
      const { width, height } = window.getContentBounds();
      shell.setBounds({ x: 0, y: 0, width, height: Math.min(272, height) });
      presentSelection(selected);
    } catch { return boundary.fatal.fail('native_retirement_unavailable'); }
  };
  const host: WindowHost = Object.freeze({ window, shell, origin: shellURL,
    assertHealthy() { assertWindowHost(host); boundary.fatal.assertHealthy(); boundary.native.assertIntegrity(); },
    createPage(): PageSurface {
      assertWindowHost(host); boundary.fatal.assertHealthy(); boundary.native.assertIntegrity();
      if (closing) throw unavailable('browser');
      const view = new WebContentsView({ webPreferences: preferences(sessions.website) });
      let current = boundary.native.ownership.bind(window.getNativeWindowHandle(), view.webContents.id,
        () => { window.contentView.addChildView(view); });
      let retired = false;
      const shield = new View();
      shield.setBackgroundColor('#00000000');
      window.contentView.addChildView(shield);
      view.webContents.on('before-input-event', (event) => {
        if (retired || current.blocked) event.preventDefault();
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
          shield.setVisible(selected === page && current.blocked); return current;
        },
        restorePresentation() {
          // restore unhides native subviews. It is never a background probe.
          if (retired || selected !== page || !view.getVisible() || !window.isVisible()) throw unavailable('browser');
          current = boundary.native.ownership.restore(bindingKey(current));
        },
        present(active: boolean) {
          if (retired) return;
          const { width, height } = window.getContentBounds();
          view.setVisible(active);
          view.setBounds({ x: 0, y: 272, width, height: Math.max(0, height - 272) });
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
            pages.delete(page); if (selected === page) selected = undefined;
            phase = 'retired';
          })().then(resolve, error => {
            phase = 'failed'; reject(error);
            return boundary.fatal.fail('native_retirement_unavailable');
          });
          return completion;
        },
      });
      surfaces.add(page); pages.add(page); page.present(false); return page;
    },
    select(page: PageSurface) {
      assertPageSurface(page);
      if (closing || page.window !== host) throw unavailable('browser');
      const retired = page.retirement();
      if (retired) {
        assertPageRetirement(page, retired);
        // The logical tab may still be selected, but never its retired surface.
        selectPhysical(undefined); return;
      }
      if (!pages.has(page)) throw unavailable('browser');
      selectPhysical(page);
    },
    selected() { assertWindowHost(host); return selected; },
    clearSelection(page: PageSurface) {
      assertPageSurface(page);
      const retirement = page.retirement();
      if (page.window !== host || (!pages.has(page) && !retirement)) throw unavailable('browser');
      try {
        if (retirement) assertPageRetirement(page, retirement);
        if (selected === page) selectPhysical(undefined);
      }
      catch { return boundary.fatal.fail('native_retirement_unavailable'); }
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
      window.destroy(); hosts.delete(host);
    },
  });
  hosts.add(host);
  window.on('resize', layout);
  window.on('close', event => { event.preventDefault(); if (!closing) onCloseRequested(); });
  layout(); return host;
}
