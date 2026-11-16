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
  binding(): Binding;
  setNativeBlocked(blocked: boolean): Binding;
  restorePresentation(): void;
  /** Presentation restores never change input policy. */
  present(selected: boolean): void;
  retire(): Promise<void>;
}
export interface WindowHost {
  readonly window: BaseWindow;
  readonly shell: WebContentsView;
  readonly origin: string;
  createPage(): PageSurface;
  assertHealthy(): void;
  select(page: PageSurface): void;
  close(): Promise<void>;
}
const hosts = new WeakSet<object>(), surfaces = new WeakSet<object>();
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
  const layout = () => {
    const { width, height } = window.getContentBounds();
    shell.setBounds({ x: 0, y: 0, width, height: Math.min(272, height) });
    for (const page of pages) page.present(page === selected);
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
      const page: PageSurface = Object.freeze({ view, window: host,
        binding() { if (retired) throw unavailable('browser');
          current = boundary.native.ownership.bindingInfo(bindingKey(current)); return current; },
        setNativeBlocked(blocked: boolean) {
          if (retired) throw unavailable('browser');
          current = boundary.native.ownership.mark(bindingKey(current), blocked);
          shield.setVisible(selected === page && current.blocked); return current;
        },
        restorePresentation() {
          if (retired) throw unavailable('browser');
          current = boundary.native.ownership.restore(bindingKey(current));
        },
        present(active: boolean) {
          if (retired) return;
          const { width, height } = window.getContentBounds();
          view.setVisible(active);
          view.setBounds({ x: 0, y: 272, width, height: Math.max(0, height - 272) });
          shield.setBounds(view.getBounds()); shield.setVisible(active && current.blocked);
        },
        async retire() {
          if (retired) throw unavailable('browser');
          retired = true;
          current = await boundary.retire(bindingKey(current), window.contentView, view);
          window.contentView.removeChildView(shield);
          pages.delete(page); if (selected === page) selected = undefined;
        },
      });
      surfaces.add(page); pages.add(page); page.present(false); return page;
    },
    select(page: PageSurface) {
      assertPageSurface(page);
      if (closing || page.window !== host || !pages.has(page)) throw unavailable('browser');
      selected = page; layout();
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
