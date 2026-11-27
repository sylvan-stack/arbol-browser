import { setTimeout as pause } from 'node:timers/promises';
import { app, ipcMain, type IpcMainInvokeEvent, type WebContents } from 'electron';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { invalidInput, publicFailure, unavailable } from '../contracts/errors.js';
import { assertHostCustody, assertSharedProfileRuntime, type HostCustody, type SharedProfileRuntime } from '../runtime/custody.js';
import type { ProfileSnapshot } from '../profiles/records.js';
import type { PlatformPort } from '../runtime/platform.js';
import { createProfileNavigation, readSubscriptionHome, rememberSubscriptionHome, type ProfileNavigation } from './profile-navigation.js';
import { bindProfilePresentation } from './presentation.js';
import { assertWindowHost, selectWindowProfile, shellURL, type WindowHost } from './windows.js';
import { assertTabRegistry, refused, userURL, type TabRegistry, type TabTarget } from './tabs.js';

type Request = Contract<'browser.ShellRequest'>;
type Event = Contract<'browser.ShellEvent'>;
type Result = Contract<'browser.ShellSuccess'> | Contract<'browser.ShellFailure'>;
type State = Contract<'browser.ShellTab'>;
/** Required authoritative ABR-10/11 services, never renderer claims or a default stub.
 * execute owns atomic native/generation/settlement semantics, including reply fencing. */
export interface ShellAuthority {
  assertReady(): void;
  assertOperational(): void;
  attachments(): readonly Contract<'browser.ClientIdentity'>[];
  execute(request: Request, target: TabTarget): Promise<{ state: State; settledAction?: Contract<'browser.SettledAction'> }>;
  subscribe(changed: () => void): () => void;
  exhausted(): never;
}
export interface ShellRegistration {
  /** The only supported loader; handlers and the initial projection already exist. */
  load(): Promise<void>;
  assertLoaded(): void;
  setRuntimeReady(isReady: () => boolean): void;
  offerPresentation(): void;
  offerForegroundPresentation(deadline: number, mayShowEmpty: () => boolean): Promise<void>;
  show(deadline: number, signal: AbortSignal, raiseWindow?: boolean, guard?: () => void): Promise<void>;
  foregroundShell(deadline: number, signal: AbortSignal, guard: () => void): Promise<boolean>;
  foreground(target: TabTarget, deadline: number, signal: AbortSignal, guard: () => void,
    ready: () => boolean, shellRaised?: boolean): Promise<void>;
  subscriptionHome(): Promise<string | undefined>;
  rememberSubscriptionHome(url: string): Promise<void>;
  publish(): void;
  dispose(): void;
}
interface Registration {
  host: WindowHost;
  authority: ShellAuthority;
  snapshot(): Event;
  dispatch(request: Request): Promise<Result>;
  profiles?: ProfileNavigation;
}
const registrations = new WeakMap<ShellRegistration, Registration>();
const senders = new Map<WebContents, Registration>();
type NativePresentation = {
  readonly state: string;
  readonly platform: PlatformPort;
  readonly profiles: Map<WindowHost, {
    readonly id: string;
    readonly instance: string;
    ready(): boolean;
    assertRetained(): void;
    sidebarTabs(): NonNullable<Event['profileTabs']>[number]['tabs'];
    assertTab(id: string): void;
    selectTab(id: string): void;
    publish(): void;
    canYield(ownerSwitch: boolean): boolean;
    openHome(): void;
  }>;
  readonly value: ReturnType<typeof bindProfilePresentation>;
};
const nativePresentations = new WeakMap<WindowHost['window'], NativePresentation>();
let installed = false;
const requestShape = validator('browser.ShellRequest'), eventShape = validator('browser.ShellEvent');
const successShape = validator('browser.ShellSuccess'), failureShape = validator('browser.ShellFailure');
function tabChrome(target: TabTarget): NonNullable<Event['tabChrome']>[number] {
  const contents = target.page.view.webContents;
  const empty = { title: '', back: false, forward: false };
  if (target.page.retirement() || contents.isDestroyed() || contents.isCrashed()) return empty;
  const title = contents.getTitle(), address = contents.getURL();
  const displayTitle = title && title !== address && title !== 'about:blank' ? title : URL.parse(address)?.hostname ?? '';
  return {
    title: [...displayTitle.replace(/[\p{Cc}\p{Cf}\p{Cs}]/gu, '')].slice(0, 160).join('').trim(),
    back: contents.navigationHistory.canGoBack(),
    forward: contents.navigationHistory.canGoForward(),
  };
}
function authenticated(event: IpcMainInvokeEvent): Registration {
  const current = senders.get(event.sender);
  if (!current) throw unavailable('browser');
  const { host, authority } = current;
  assertWindowHost(host); host.assertHealthy(); authority.assertReady();
  const contents = host.shell.webContents, frame = event.senderFrame;
  if (!host.presentationStable()) throw refused('control_refused');
  // file: origins serialize as null. Exact canonical URL and actual frame object are mandatory.
  if (contents.isDestroyed() || event.sender !== contents || !frame || frame !== contents.mainFrame || frame.parent !== null ||
      frame.url !== shellURL || contents.getURL() !== shellURL || host.origin !== shellURL ||
      !host.window.contentView.children.includes(host.shell)) throw unavailable('browser');
  return current;
}
function installTransport() {
  if (installed) return;
  // No request-supplied identity, role, sender or channel is accepted.
  ipcMain.handle('browser-shell:request', async (event, raw: unknown) => {
    const current = authenticated(event); // before inspecting privileged parameters
    if (!current.host.isActiveProfile()) throw refused('control_refused');
    if (!requestShape(raw)) throw invalidInput();
    let size: number;
    try { size = Buffer.byteLength(JSON.stringify(raw), 'utf8'); } catch { throw invalidInput(); }
    if (size > 1048576) throw invalidInput();
    const result = await current.dispatch(raw as Request);
    // Closing destroys the original sender; every other asynchronous reply is fenced again.
    if ((raw as Request).method !== 'close_window') {
      if (authenticated(event) !== current || !current.host.isActiveProfile()) throw unavailable('browser');
    }
    return result;
  });
  // Transport snapshot only: the exact ShellEvent, no additional renderer capability/data endpoint.
  ipcMain.handle('browser-shell:state', (event, ...args: unknown[]) => {
    const current = authenticated(event);
    if (args.length) throw invalidInput();
    return current.snapshot();
  });
  ipcMain.handle('browser-shell:profiles', async (event, request: unknown) => {
    const current = authenticated(event);
    if (!current.profiles) return null;
    let firstCheck = true;
    const check = () => {
      if (!firstCheck && authenticated(event) !== current) throw unavailable('browser');
      firstCheck = false;
      current.authority.assertOperational();
    };
    try {
      const isFocused = () => current.host.isActiveProfile() && current.host.window.isFocused();
      if ((request as { method?: unknown } | null)?.method !== 'list' && !isFocused()) throw refused('control_refused');
      const state = await current.profiles(request, check, isFocused);
      if (authenticated(event) !== current) throw unavailable('browser');
      return state;
    } catch (error) {
      if (authenticated(event) !== current) throw unavailable('browser');
      return { error: publicFailure(error).detail.message };
    }
  });
  installed = true;
}
export function assertShellRegistration(value: ShellRegistration, host: WindowHost): void {
  const current = registrations.get(value);
  if (!current || current.host !== host || senders.get(host.shell.webContents) !== current) throw unavailable('browser');
  host.assertHealthy(); current.authority.assertReady();
}
/** Called only by trusted main-process assembly with a real authority. No fallback is supplied. */
export interface ShellProfileSource {
  readonly custody: HostCustody;
  readonly platform: PlatformPort;
  readonly shared?: Readonly<{
    runtime?: SharedProfileRuntime;
    openInWindow(source: WindowHost, profile: ProfileSnapshot, deadline: number): Promise<void>;
    prepareInWindow(source: WindowHost, profiles: readonly ProfileSnapshot[]): void;
  }>;
}
export function registerShellIPC(host: WindowHost, tabs: TabRegistry, authority: ShellAuthority,
  profileSource?: ShellProfileSource): ShellRegistration {
  assertWindowHost(host); assertTabRegistry(tabs); host.assertHealthy(); authority.assertReady();
  if (senders.has(host.shell.webContents)) throw unavailable('browser');
  const shared = profileSource?.shared;
  if (shared?.runtime && (assertSharedProfileRuntime(shared.runtime) !== profileSource?.custody ||
      host.shell.webContents.session !== shared.runtime.sessions.shell)) throw unavailable('profile');
  const installedProfile = profileSource?.custody.host.identity.layout.scope === 'installed'
    ? (shared?.runtime?.instance ?? profileSource.custody.instance).owner.profile : undefined;
  let openingHome: Promise<void> | undefined;
  let revision = 0, loaded = false, prepared = false, disposed = false;
  let lastSidebarTabs: string | null = null;
  let runtimeReady = () => false;
  const ids = new Set<string>();
  const snapshot = (): Event => {
    host.assertHealthy(); authority.assertReady();
    if (disposed || revision >= Number.MAX_SAFE_INTEGER) return authority.exhausted();
    const selected = tabs.selected(host);
    const targets = tabs.all().filter(target => target.page.window === host);
    // Send real selection first and keep the owner-only chrome aligned with that same order.
    const ordered = selected && targets.includes(selected) ? [selected, ...targets.filter(target => target !== selected)] : targets;
    const value: Event = { ui: 1, event: 'state', revision: ++revision,
      tabs: ordered.map(target => structuredClone(tabs.state(target))),
      tabChrome: ordered.map(tabChrome),
      ...(nativePresentation ? { profileTabs: [...nativePresentation.profiles.values()]
        .flatMap(member => member.ready() ? [{ id: member.id, instance: member.instance, tabs: member.sidebarTabs() }] : []) } : {}),
      ...(profiles && runtimeReady() ? { profileNavigationReady: true as const } : {}),
      attachments: authority.attachments().map(entry => ({ id: entry.id, label: entry.label })) };
    if (!eventShape(value)) throw unavailable('browser');
    return value;
  };
  let nativePresentation: NativePresentation | undefined;
  if (profileSource?.custody.host.identity.layout.scope === 'installed') {
    const { platform } = profileSource;
    const state = profileSource.custody.host.policy.stateRoot;
    nativePresentation = nativePresentations.get(host.window);
    if (!nativePresentation) {
      const profiles: NativePresentation['profiles'] = new Map();
      const value = bindProfilePresentation(host.window, state, platform, ownerSwitch => {
        for (const [member, profile] of profiles) if (member.isActiveProfile()) return profile.canYield(ownerSwitch);
        return false;
      });
      nativePresentation = { state, platform, profiles, value };
      nativePresentations.set(host.window, nativePresentation);
    }
    if (nativePresentation.state !== state || nativePresentation.platform !== platform) throw unavailable('browser');
    const { id, instance } = (shared?.runtime?.instance ?? profileSource.custody.instance).owner.profile.record;
    if ([...nativePresentation.profiles.values()].some(profile => profile.id === id)) throw unavailable('browser');
    nativePresentation.profiles.set(host, { id, instance,
      ready: () => runtimeReady() && prepared && !disposed,
      assertRetained() {
        if (shared?.runtime) assertSharedProfileRuntime(shared.runtime);
        else assertHostCustody(profileSource.custody);
      },
      sidebarTabs: () => tabs.all().filter(target => target.page.window === host)
        .slice(0, 7).map(target => ({ id: target.id, title: tabChrome(target).title })),
      assertTab(id) {
        if (tabs.get(id).page.window !== host) throw refused('tab_not_found');
      },
      selectTab(id) {
        if (tabs.selected(host)?.id !== id) tabs.select(host, id);
      },
      publish: () => registration.publish(),
      canYield: ownerSwitch =>
        !host.window.isDestroyed() && host.window.isEnabled() && (ownerSwitch || !host.window.isFocused()) &&
        tabs.all().filter(target => target.page.window === host).every(target => tabs.state(target).handoff === 'idle'),
      openHome() {
        if (!installedProfile || openingHome || tabs.all().length !== 0) return;
        openingHome = readSubscriptionHome(installedProfile).then(async home => {
          if (!home || !host.isActiveProfile() || tabs.all().length !== 0) return;
          assertPresentable();
          await tabs.openUser(host, home);
        }).catch(() => {}).finally(() => { openingHome = undefined; });
      },
    });
  }
  const presentation = nativePresentation?.value;
  const profiles = profileSource && nativePresentation && createProfileNavigation(profileSource.custody, profileSource.platform,
    nativePresentation.value.yieldForSwitch, (id, instance, tab) => {
      const members = nativePresentation.profiles;
      const source = members.get(host);
      if (!host.isActiveProfile() || !host.window.isFocused() || !source?.canYield(true)) throw refused('control_refused');
      for (const [target, profile] of members) {
        if (profile.id !== id) continue;
        if (profile.instance !== instance) throw refused('control_refused');
        if (!profile.ready()) return false;
        profile.assertRetained();
        if (tab !== undefined) profile.assertTab(tab);
        selectWindowProfile(host, target);
        if (tab !== undefined) {
          try {
            profile.selectTab(tab);
          } catch (error) {
            if (target.isActiveProfile() && source.ready() && profile.canYield(true)) selectWindowProfile(target, host);
            throw error;
          }
        }
        profile.openHome();
        return true;
      }
      return false;
    }, shared && { ...(shared.runtime ? { runtime: shared.runtime } : {}),
      isReady: (id, instance) => [...nativePresentation.profiles.values()]
        .some(member => member.id === id && member.instance === instance),
      prepareInWindow: profiles => shared.prepareInWindow(host, profiles),
      openInWindow: (profile, deadline) => shared.openInWindow(host, profile, deadline) });
  const assertPresentable = () => { registration.assertLoaded(); authority.assertOperational(); };
  const current: Registration = { host, authority, snapshot, ...(profiles ? { profiles } : {}),
    async dispatch(request): Promise<Result> {
      host.assertHealthy(); authority.assertReady();
      if (ids.has(request.id) || ids.size >= 65536) throw refused('control_refused', 'Reopen the browser window to establish a fresh shell connection.');
      ids.add(request.id);
      try {
        let state: State | null = null, settledAction: Contract<'browser.SettledAction'> | undefined;
        if (request.method === 'new_tab') {
          const target = await tabs.openUser(host, userURL(request.params.url ?? 'about:blank'));
          state = tabs.state(target);
        } else if (request.method === 'select') {
          state = tabs.state(tabs.select(host, request.params.tab));
        } else if (request.method === 'close_window') {
          if (shared) await new Promise<void>(resolve => {
            host.window.once('closed', () => resolve());
            host.window.close();
          });
          else await tabs.closeWindow(host);
        } else {
          const target = tabs.get(request.params.tab);
          if (target.page.window !== host) throw refused('tab_not_found');
          const before = tabs.state(target);
          // Take coalescing belongs to the authority, which can identify its exact running transition.
          if (before.generation !== request.params.controlGeneration && request.method !== 'take') throw refused('control_changed');
          if (request.method === 'close_tab') await tabs.closeUser(host, target.id, before.generation);
          else {
            if (tabs.selected(host) !== target) throw refused('control_refused');
            if (['share', 'return', 'user_navigate', 'back', 'forward', 'reload', 'recover'].includes(request.method) &&
                (before.controller.kind !== 'user' || before.handoff !== 'idle')) throw refused('control_refused', 'Take control before using this action.');
            const recipient = 'client' in request.params ? request.params.client : undefined;
            if (recipient && !authority.attachments().some(entry => entry.id === recipient)) throw refused('control_refused');
            if (request.method === 'user_navigate') userURL(request.params.url);
            const result = await authority.execute(request, target);
            state = result.state; settledAction = result.settledAction;
            if (state.tab !== target.id || tabs.state(target).generation !== state.generation) throw refused('control_changed');
          }
        }
        const reply: Contract<'browser.ShellSuccess'> = { ui: 1, id: request.id, ok: true, state,
          ...(settledAction ? { settledAction } : {}) };
        if (!successShape(reply)) throw unavailable('browser');
        if (request.method !== 'close_window') { host.assertHealthy(); authority.assertReady(); registration.publish(); }
        return reply;
      } catch (error) {
        host.assertHealthy(); authority.assertReady();
        const reply: Contract<'browser.ShellFailure'> = { ui: 1, id: request.id, ok: false, error: publicFailure(error).detail };
        if (!failureShape(reply)) throw unavailable('browser'); return reply;
      }
    },
  };
  const registration: ShellRegistration = Object.freeze({
    async load() {
      assertShellRegistration(registration, host);
      if (loaded) throw unavailable('browser'); loaded = true;
      snapshot(); // initial authority/projection must validate before any load
      await host.shell.webContents.loadURL(shellURL);
      await host.shell.webContents.setVisualZoomLevelLimits(1, 1);
      host.shell.webContents.setZoomFactor(1);
      assertShellRegistration(registration, host);
      registration.publish(); prepared = true;
    },
    assertLoaded() {
      assertShellRegistration(registration, host);
      if (!prepared || disposed || host.shell.webContents.getURL() !== shellURL) throw unavailable('browser');
    },
    setRuntimeReady(isReady: () => boolean) {
      assertPresentable();
      runtimeReady = isReady;
      registration.publish();
    },
    offerPresentation() {
      assertPresentable();
      if (!host.isActiveProfile()) return;
      if (presentation) { presentation.offer(); return; }
      if (!host.window.isVisible()) host.window.showInactive();
    },
    async offerForegroundPresentation(deadline: number, mayShowEmpty: () => boolean) {
      assertPresentable();
      if (!host.isActiveProfile()) return;
      if (presentation) { await presentation.offerForeground(deadline, assertPresentable, mayShowEmpty); return; }
      if (mayShowEmpty()) registration.offerPresentation();
    },
    async show(deadline: number, signal: AbortSignal, raiseWindow = false, guard?: () => void) {
      const check = () => { assertPresentable(); guard?.(); };
      check();
      if (presentation) await presentation.show(deadline, signal, check, raiseWindow);
      else if (!host.window.isVisible()) host.window.showInactive();
      check();
      if (!shared || !nativePresentation || host.isActiveProfile() || signal.aborted ||
          performance.now() >= deadline || !nativePresentation.profiles.get(host)?.ready()) return;
      for (const [source, member] of nativePresentation.profiles) {
        if (!source.isActiveProfile() || !member.ready() || !member.canYield(false)) continue;
        selectWindowProfile(source, host);
        break;
      }
    },
    async foregroundShell(deadline: number, signal: AbortSignal, guard: () => void) {
      const check = () => {
        guard();
        assertPresentable();
        if (!runtimeReady() || host.window.isDestroyed() || !host.window.isEnabled())
          throw unavailable('browser');
      };
      if (!presentation) throw unavailable('browser');
      // Use the existing native frame. The account check still gates any
      // change to its selected profile, selected tab or website URL.
      await presentation.show(deadline, signal, check);
      check();
      app.focus({ steal: true });
      host.window.focus();
      const focusDeadline = Math.min(deadline, performance.now() + 150);
      while (!host.window.isFocused() && performance.now() < focusDeadline) {
        await pause(15, undefined, { signal });
        check();
      }
      return host.window.isFocused();
    },
    async foreground(target: TabTarget, deadline: number, signal: AbortSignal, guard: () => void,
      ready: () => boolean, shellRaised = false) {
      assertPresentable();
      if (!nativePresentation || !runtimeReady() || host.window.isDestroyed() ||
          !host.window.isEnabled()) throw unavailable('browser');
      const member = nativePresentation.profiles.get(host);
      if (!member?.ready() || !member.canYield(true)) throw unavailable('profile');
      const source = [...nativePresentation.profiles].find(([member]) => member.isActiveProfile());
      if (!source?.[1].ready() || !source[1].canYield(true)) throw unavailable('profile');
      guard();
      const previous = tabs.selected(host);
      const assertSelected = () => {
        guard();
        if (!host.isActiveProfile() || tabs.selected(host) !== target || !member.ready() || !member.canYield(true))
          throw unavailable('profile');
      };
      try {
        // Prepare the admitted selection in the target scope before revealing it.
        if (previous !== target) tabs.select(host, target.id);
        if (source[0] !== host) selectWindowProfile(source[0], host);
        if (!shellRaised) await registration.show(deadline, signal, false, assertSelected);
        // Placement temporarily fences the same document. Keep its identity
        // pinned while the native readiness check settles in its new position.
        assertSelected();
        while (!ready()) {
          if (shellRaised && (!host.window.isVisible() || host.window.isMinimized())) return;
          await pause(15, undefined, { signal });
          assertSelected();
        }
        if (!shellRaised) {
          if (!host.window.isVisible() || host.window.isMinimized()) throw unavailable('browser');
          app.focus({ steal: true });
          host.window.focus();
        }
      } catch (error) {
        // A later selection owns the window if it changed while presentation waited.
        try {
          if (host.isActiveProfile() && tabs.selected(host) === target && member.canYield(true)) {
            if (source[0] !== host && source[1].ready() && source[1].canYield(true)) selectWindowProfile(host, source[0]);
            if ((source[0] === host || source[0].isActiveProfile()) && previous && previous !== target &&
                tabs.selected(host) === target && tabs.get(previous.id) === previous)
              tabs.select(host, previous.id);
          }
        } catch { /* Keep the original presentation failure. */ }
        throw error;
      }
    },
    async subscriptionHome() {
      if (installedProfile) return readSubscriptionHome(installedProfile);
      return undefined;
    },
    async rememberSubscriptionHome(url: string) {
      if (!installedProfile) throw unavailable('profile');
      await rememberSubscriptionHome(installedProfile, url);
    },
    publish() {
      if (!host.presentationStable()) return; // a real placement co-commit will notify the consistent state
      assertShellRegistration(registration, host);
      const value = snapshot();
      if (loaded && host.shell.webContents.getURL() === shellURL) host.shell.webContents.send('browser-shell:state', value);
      const member = nativePresentation?.profiles.get(host);
      const sidebarTabs = member?.ready() ? JSON.stringify(member.sidebarTabs()) : null;
      if (sidebarTabs !== lastSidebarTabs) {
        lastSidebarTabs = sidebarTabs;
        if (!host.isActiveProfile()) {
          const current = [...(nativePresentation?.profiles ?? [])].find(([view, profile]) =>
            view.isActiveProfile() && profile.ready());
          current?.[1].publish();
        }
      }
    },
    dispose() {
      if (disposed) return; disposed = true;
      unsubscribe(); unsubscribePresentation(); unsubscribeChrome(); clearTimeout(chromeTimer);
      nativePresentation?.profiles.delete(host);
      senders.delete(host.shell.webContents); registrations.delete(registration);
    },
  });
  installTransport(); senders.set(host.shell.webContents, current); registrations.set(registration, current);
  let unsubscribe: () => void = () => {};
  let unsubscribePresentation: () => void = () => {};
  let unsubscribeChrome: () => void = () => {};
  let chromeTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    snapshot();
    unsubscribe = authority.subscribe(() => registration.publish());
    unsubscribePresentation = host.onPresentation(() => {}, () => { if (!disposed) registration.publish(); });
    unsubscribeChrome = host.onTabChromeChange(() => {
      if (!prepared || disposed || !runtimeReady() || chromeTimer) return;
      chromeTimer = setTimeout(() => {
        chromeTimer = undefined;
        if (!disposed && runtimeReady()) registration.publish();
      }, 100);
    });
    host.shell.webContents.once('destroyed', () => registration.dispose());
    return registration;
  } catch (error) { registration.dispose(); throw error; }
}
