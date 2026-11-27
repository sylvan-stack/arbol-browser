import { app, Menu, nativeImage, webContents } from 'electron';
import { resolve, join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { configureProfileSession, type SessionBinding, type ProfileSessions, type ProfileApp } from '../profiles/session.js';
import { prepareEngine, type EngineAuthority, type EngineTransaction } from '../profiles/compatibility.js';
import { acquireInstance, runtimeLocation, assertTime, type InstanceOwner, type PreviousExit, type RuntimeRecord } from './instance.js';
import { readJson, readProfile, type ProfileSnapshot } from '../profiles/records.js';
import { profilePaths } from '../profiles/paths.js';
import { consumeSelection, type BuildSelection } from './selection.js';
import { validator } from '../contracts/schema.js';
import { unavailable } from '../contracts/errors.js';
import { adoptHostBuildLease, assertAdoptedBuildContinuity, captureHostBuild, terminateCapturedHostBuild, type CapturedHostBuild, type BuildLease } from './build-lease.js';
import { assertVerifiedHostMetadata, assertHostEngineAuthority, installedImagePath, type VerifiedHost } from './authorities.js';
import { claimedHostAttempt } from './process.js';
import { noteHostStartup, prepareHostCustody, prepareSharedProfileRuntime, assertSharedProfileRuntime,
  abortUnadmittedHost, type HostCustody, type SharedProfileRuntime } from './custody.js';
import type { NativeBoundaryPreparation, NativeFailureBoundary, NativeShellPort, TrustedShellIntegration } from './bootstrap.js';
import type { NativeWatchdog } from '../native/watchdog.js';
import type { OwnerLease } from '../profiles/locking.js';
import type { PlatformPort, PriorMarkerExpectation } from './platform.js';
import type { HostLifecycle, SharedProfileLifecycle } from './lifecycle.js';
import type { ProductionExitAuthority } from './exit.js';
import type { TransportServer } from './transport.js';
import type { RendererControl } from '../host/recovery.js';
import type { WindowHost } from '../host/windows.js';
import { retainInstalledResidence } from './resident.js';

export interface HostRequest { readonly request: string; readonly profile: ProfileSnapshot; readonly selection: BuildSelection }
export async function consumeHostRequest(args: readonly string[], packagedBuild: string, directory: string): Promise<HostRequest> {
  if (args.length !== 2 || args[0] !== '--arbol-host-request' || !args[1]) throw unavailable('browser');
  const { value } = await readJson(args[1], 16384);
  const input = value as Record<string, unknown>;
  if (!input || Object.keys(input).sort().join(',') !== 'format,profile,profileInstance,request,selection' || input.format !== 1 ||
      !validator('browser.RequestId')(input.request) || typeof input.profile !== 'string') throw unavailable('browser');
  const selectionInput = input.selection as Record<string, unknown>;
  if (!selectionInput || Object.keys(selectionInput).sort().join(',') !== 'build,directory,explicit,guard') throw unavailable('browser');
  const selection = consumeSelection(packagedBuild, directory,
    { ARBOL_BROWSER_SELECTION: JSON.stringify({ format: 1, ...selectionInput }) });
  const paths = profilePaths(basename(input.profile), dirname(dirname(input.profile)));
  if (paths.root !== input.profile) throw unavailable('browser');
  const profile = await readProfile(paths);
  if (input.profileInstance !== profile.record.instance) throw unavailable('browser');
  const location = await runtimeLocation(profile);
  if (!location || args[1] !== join(location.leaf, `launch-${input.request}.json`)) throw unavailable('browser');
  await location.assert();
  return Object.freeze({ request: input.request, profile, selection });
}
export interface HostPreviousExit extends PreviousExit {
  /** Read only the independent outside-profile terminal/activation journal at
   * this stage. Actual engine.json validation follows Native enrollment. */
  priorExpectation(profile: ProfileSnapshot, previous: RuntimeRecord | undefined,
    owner: OwnerLease, build: BuildLease, deadline: number): Promise<PriorMarkerExpectation>;
}
export interface OwnedHost {
  readonly instance: InstanceOwner;
  readonly buildGuard: BuildLease;
  readonly custody: HostCustody;
  readonly watchdog: NativeWatchdog;
  installNative(effects: import('../native/fatal.js').FatalEffects, deadline: number): Promise<import('./bootstrap.js').NativeFailureBoundary>;
}
const ownedHosts = new WeakSet<object>();
/** Membership only: callers must still validate the exact preparation tuple. */
export function isOwnedHost(host: unknown): host is OwnedHost {
  return typeof host === 'object' && host !== null && ownedHosts.has(host);
}
export function assertOwnedHost(host: OwnedHost): void {
  if (!ownedHosts.has(host)) throw unavailable('browser'); host.custody.assertRetained();
}
/** Genuine pre-ready ownership only: no compatibility read, dirty marker,
 * setPath, Session or shell access precedes retained Native acknowledgement. */
export async function prepareOwnedHost(actualApp: ProfileApp, request: HostRequest, host: VerifiedHost,
  native: NativeBoundaryPreparation, previousExit: HostPreviousExit, deadline: number, capture?: CapturedHostBuild): Promise<OwnedHost | null> {
  if (process.type !== 'browser' || actualApp.isReady()) throw unavailable('browser');
  const bootstrapURL = new URL('./bootstrap.js', import.meta.url).href;
  const bootstrap = await import(bootstrapURL) as typeof import('./bootstrap.js');
  bootstrap.assertNativeBoundaryPreparation(native);
  const platform = native.platform;
  assertVerifiedHostMetadata(host, deadline);
  if (native.trust.bundle !== host.signed.bundle || native.trust.snapshotDigest !== host.signed.snapshotDigest ||
      request.selection.build !== host.identity.layout.build || request.selection.directory !== host.identity.layout.buildRoot)
    throw unavailable('browser');
  const location = await runtimeLocation(request.profile);
  if (!location) throw unavailable('browser');
  // This adopts, rather than releases/reopens, the original outer description.
  const buildGuard = await adoptHostBuildLease(host, platform, join(location.leaf, `launch-${request.request}.json`), deadline, capture);
  const assertAdmission = async (mutation = true) => {
    assertTime(deadline); if (actualApp.isReady()) throw unavailable('browser');
    await claimedHostAttempt(request.profile, host, platform, request.request, deadline);
    if (mutation) await buildGuard.assert();
    else await assertAdoptedBuildContinuity(buildGuard, host, deadline);
    assertTime(deadline);
  };
  const assertContinuity = () => assertAdmission(false);
  let instance: InstanceOwner | null = null, custody: HostCustody | undefined;
  let prior: PriorMarkerExpectation | undefined;
  const previousShutdown: PreviousExit = {
    async assertExited(profile, previous, owner) {
      if (!owner || prior) throw unavailable('browser');
      // Capture the native prior-marker expectation during the same original
      // Owner lease that proves the last process has exited. Acquisition
      // rechecks the runtime before publishing; enrollment still validates
      // the actual marker and its bound shutdown evidence.
      prior = await previousExit.priorExpectation(profile, previous, owner, buildGuard,
        Math.min(deadline, performance.now() + 10000));
    },
  };
  try {
    instance = await acquireInstance(request.profile, platform, request.selection.build, previousShutdown, deadline,
      { assertAdmission, assertContinuity, failed: owner => abortUnadmittedHost(owner, buildGuard, platform) });
    // The losing original still owns the genuine inherited Build, and must
    // publish terminal-only no-use before exact self exit. No invented Owner.
    if (!instance) return abortUnadmittedHost(undefined, buildGuard, platform);
    await assertContinuity(); await instance.owner.assert();
    if (!prior) throw unavailable('browser');
    custody = await prepareHostCustody(host, instance, buildGuard, platform, request.request, prior, deadline);
    const watchdog = await custody.arm(native, deadline);
    custody.assertRetained(); assertTime(deadline);
    if (actualApp.isReady()) return custody.terminate();
    const retainedCustody = custody;
    const owned: OwnedHost = Object.freeze({ instance, buildGuard, custody, watchdog,
      installNative(effects: import('../native/fatal.js').FatalEffects, limit: number) {
        retainedCustody.assertRetained();
        return bootstrap.installNativeBoundary(native, watchdog, effects, retainedCustody, Math.min(deadline, limit));
      },
    });
    ownedHosts.add(owned); return owned;
  } catch {
    if (custody) return custody.terminate();
    return abortUnadmittedHost(instance?.owner, buildGuard, platform);
  }
}

export interface HostPreparation extends OwnedHost {
  readonly instance: InstanceOwner; readonly engine: EngineTransaction; readonly binding: SessionBinding;
  readonly buildGuard: BuildLease;
}
/** Called with the real app in the entry's awaited pre-ready phase. Ownership
 * and Build guards already belong to this host. No page authority is created. */
export async function prepareHost(actualApp: ProfileApp, owned: OwnedHost, authority: EngineAuthority): Promise<HostPreparation> {
  assertOwnedHost(owned); assertHostEngineAuthority(authority);
  const { instance, buildGuard, custody } = owned;
  if (actualApp.isReady()) return custody.terminate();
  try {
    noteHostStartup(custody, 'owned-lease-policy');
    await instance.owner.assert(); custody.assertRetained();
    if (authority.build !== instance.record.build) return custody.terminate();
    const engine = await prepareEngine(instance.owner, authority, stage => noteHostStartup(custody, stage));
    custody.assertRetained(); custody.assertMarker();
    noteHostStartup(custody, 'host-session-configure-before');
    const binding = await configureProfileSession(actualApp, engine, custody, custody.host.identity.layout.scope === 'installed');
    noteHostStartup(custody, 'host-session-configure-after');
    if (actualApp.isReady()) return custody.terminate();
    const prepared: HostPreparation = Object.freeze({ ...owned, engine, binding });
    ownedHosts.add(prepared); return prepared;
  } catch { return custody.terminate(); }
}
export async function bindHostSessions(prepared: HostPreparation, deadline: number): Promise<ProfileSessions> {
  assertOwnedHost(prepared);
  const { instance, custody, buildGuard } = prepared;
  const starting = instance.record;
  const assertStarting = () => {
    assertTime(deadline);
    if (starting.phase !== 'starting' || instance.record !== starting ||
        custody.instance !== instance || custody.build !== buildGuard) return custody.terminate();
    custody.assertRetained();
  };
  assertStarting();
  await instance.owner.assert();
  assertStarting();
  await assertAdoptedBuildContinuity(buildGuard, custody.host, deadline);
  assertStarting();
  return prepared.binding.bindActual();
}
interface ActualHostAssembly {
  closed: boolean;
  control?: RendererControl;
  shell?: TrustedShellIntegration;
  transport?: TransportServer;
  runtime?: HostLifecycle;
  additional?: AdditionalProfiles;
  residence?: Awaited<ReturnType<typeof retainInstalledResidence>>;
}
function installApplicationMenu(): () => void {
  const zoomPage = (change?: number) => {
    const page = webContents.getFocusedWebContents();
    if (page && !page.isDestroyed() && page.session.getStoragePath() !== null)
      page.setZoomLevel(change === undefined ? 0 : page.getZoomLevel() + change);
  };
  const menu = Menu.buildFromTemplate([
    { role: 'appMenu' },
    { role: 'fileMenu' },
    { label: 'Edit', submenu: [
      { role: 'undo' }, { role: 'redo' }, { type: 'separator' },
      { id: 'disabled-copy', label: 'Copy', enabled: false },
      { id: 'disabled-cut', label: 'Cut', enabled: false },
      { role: 'paste' }, { role: 'pasteAndMatchStyle' }, { role: 'selectAll' },
    ] },
    { label: 'View', submenu: [
      { label: 'Actual Size', accelerator: 'CmdOrCtrl+0', click: () => zoomPage() },
      { label: 'Zoom In', accelerator: 'CmdOrCtrl+Plus', click: () => zoomPage(0.5) },
      { label: 'Zoom Out', accelerator: 'CmdOrCtrl+-', click: () => zoomPage(-0.5) },
      { type: 'separator' }, { role: 'togglefullscreen' },
    ] },
    { role: 'windowMenu' },
  ]);
  Menu.setApplicationMenu(menu);
  const assertInstalled = () => {
    if (Menu.getApplicationMenu() !== menu) throw unavailable('browser');
    for (const id of ['disabled-copy', 'disabled-cut']) {
      const item = menu.getMenuItemById(id);
      if (!item || item.enabled || item.role || item.accelerator) throw unavailable('browser');
    }
  };
  assertInstalled();
  return assertInstalled;
}

function usageFor(transports: typeof import('./transport.js'), platform: PlatformPort, instance: InstanceOwner,
  guard: () => void, control: RendererControl, shell: TrustedShellIntegration,
  currentLifecycle: () => HostLifecycle | undefined,
  otherActiveHandoff: () => boolean): NonNullable<Parameters<typeof transports.listenProtectedTransport>[4]> {
  return async (params, deadline, signal) => {
    const runtime = currentLifecycle();
    if (!runtime) return { status: 'dashboard_unavailable' };
    const current = instance.record;
    const { SeqoyaPageRefusal } = await import('../host/seqoya-page.js');
    const { captureSeqoyaUsage } = await import('../host/seqoya-usage.js');
    const ownerBusy = () => otherActiveHandoff() || hasHandoff(control, shell);
    const assertCurrent = () => { runtime.assertAdmission(); guard(); };
    try {
      assertCurrent();
      await transports.admitSeqoyaCapture(platform, current, params, deadline, 'claim', signal);
      assertCurrent();
      if (instance.record !== current) return { status: 'dashboard_unavailable' };
      const reading = await captureSeqoyaUsage(shell.host, params.provider, deadline, signal, ownerBusy);
      assertCurrent();
      if (instance.record !== current || signal.aborted || shell.host.window.isFocused() || !shell.host.window.isEnabled() || ownerBusy())
        return { status: 'deferred' };
      return { status: 'read', reading };
    } catch (error) {
      return { status: error instanceof SeqoyaPageRefusal ? error.code : 'dashboard_unavailable' };
    }
  };
}
function hasHandoff(control: RendererControl, shell: TrustedShellIntegration): boolean {
  return shell.tabs.all().some(tab => control.ownership.lifecycle.state(tab).handoff !== 'idle');
}

interface AdditionalProfiles {
  openInWindow(source: WindowHost, target: ProfileSnapshot, deadline: number): Promise<void>;
  admit: NonNullable<Parameters<typeof import('./transport.js').listenProtectedTransport>[6]>;
  bindPrimary(scope: LogicalProfile): void;
  primaryActive(): boolean;
  activeHandoff(): boolean;
  fence(): void;
  retire(deadline: number): Promise<void>;
}
interface LogicalProfile {
  instance: InstanceOwner;
  runtime: HostLifecycle;
  control: RendererControl;
  shell: TrustedShellIntegration;
  transport: TransportServer;
  flush(): Promise<void>;
  phase: 'active' | 'closing' | 'dormant';
  retirement?: Promise<void>;
}
function additionalProfiles(custody: HostCustody, state: ActualHostAssembly, boundary: NativeFailureBoundary,
  port: NativeShellPort, platform: PlatformPort, exits: ProductionExitAuthority,
  bootstrap: typeof import('./bootstrap.js'), lifecycle: typeof import('./lifecycle.js'),
  transports: typeof import('./transport.js')): AdditionalProfiles {
  type Entry = { instance: string; opening?: Promise<LogicalProfile>; runtime?: SharedProfileLifecycle; scope?: LogicalProfile };
  const profiles = new Map<string, Entry>();
  let primary: LogicalProfile | undefined;
  let closing = false;
  const activeHandoff = () => [...profiles.values()].some(({ scope }) =>
    scope?.phase === 'active' && scope.shell.host.isActiveProfile() && hasHandoff(scope.control, scope.shell));
  const assertCurrent = (source: WindowHost, deadline: number) => {
    assertTime(deadline);
    if (closing || state.closed || source.window !== state.shell?.host.window || !state.runtime) throw unavailable('profile');
    state.runtime.assertAdmission(); custody.assertRetained(); source.assertHealthy();
  };
  async function openProfile(source: WindowHost, target: ProfileSnapshot, deadline: number, signal?: AbortSignal): Promise<RuntimeRecord> {
    const assertOpeningCurrent = () => {
      assertCurrent(source, deadline);
      if (signal?.aborted) throw unavailable('profile');
    };
    assertOpeningCurrent();
    const { id, instance } = target.record;
    if (target.paths.state !== custody.host.policy.stateRoot) throw unavailable('profile');
    if (id === custody.instance.record.profile) {
      if (!primary || instance !== primary.instance.record.profileInstance) throw unavailable('profile');
      return activate(primary, assertOpeningCurrent);
    }
    let entry = profiles.get(id);
    if (!entry) { entry = { instance }; profiles.set(id, entry); }
    if (entry.instance !== instance) throw unavailable('profile');
    entry.opening ??= openEntry(entry, source, target, deadline, assertOpeningCurrent).catch(error => {
      delete entry.opening;
      throw error;
    });
    return activate(await entry.opening, assertOpeningCurrent);
  }
  async function openInWindow(source: WindowHost, target: ProfileSnapshot, deadline: number): Promise<void> {
    await openProfile(source, target, deadline);
  }
  async function openEntry(entry: Entry, source: WindowHost, target: ProfileSnapshot, deadline: number,
    assertOpeningCurrent: () => void): Promise<LogicalProfile> {
    let profile: SharedProfileRuntime | undefined, shell: TrustedShellIntegration | undefined, transport: TransportServer | undefined;
    try {
      const prepared = profile = await prepareSharedProfileRuntime(app, custody, target, exits, deadline);
      assertOpeningCurrent();
      const control = await bootstrap.prepareSharedRendererControl(boundary, prepared, deadline);
      assertOpeningCurrent();
      shell = await bootstrap.integrateSharedProfileShell(port, prepared, source, control.ownership.lifecycle,
        control.ownership.shell, openInWindow, deadline);
      assertOpeningCurrent();
      control.bind(shell.tabs, shell.host, shell.registration);
      const { instance } = prepared;
      transport = await transports.listenProtectedTransport(instance.location, instance.record, platform, control.ownership.dispatch,
        usageFor(transports, platform, instance, () => { assertSharedProfileRuntime(prepared); },
          control, shell, () => entry.runtime, () => {
            const primary = state.shell, primaryControl = state.control;
            return activeHandoff() || !!(primary && primaryControl && primary.host.isActiveProfile() && hasHandoff(primaryControl, primary));
          }), prepared);
      const runtime = entry.runtime = lifecycle.createSharedProfileLifecycle(prepared, transport, control.ownership.control, deadline);
      control.ownership.bindRuntime(runtime);
      assertOpeningCurrent();
      await shell.registration.load();
      assertOpeningCurrent();
      await runtime.ready();
      assertCurrent(source, deadline);
      const scope: LogicalProfile = { instance, runtime, control, shell, transport, phase: 'active',
        flush: () => prepared.sessions.flushStorage() };
      shell.registration.setRuntimeReady(() => scope.phase === 'active' && runtime.phase === 'ready' && !closing && !state.closed);
      entry.scope = scope;
      return scope;
    } catch (error) {
      if (entry.runtime) await entry.runtime.close();
      else {
        transport?.closeAdmission();
        await Promise.allSettled([
          shell && shell.tabs.closeWindow(shell.host),
          transport?.close(),
          profile?.instance.phase('closing'),
          profile?.sessions.flushStorage(),
        ]);
      }
      if (!profile) profiles.delete(target.record.id);
      throw error;
    }
  }
  async function activate(scope: LogicalProfile, guard: () => void): Promise<RuntimeRecord> {
    if (scope.retirement) await scope.retirement;
    guard(); scope.runtime.assertAdmission();
    if (scope.phase === 'dormant') {
      void transports.setProfileTraffic(scope.transport, true);
      scope.phase = 'active';
      scope.shell.registration.publish();
    }
    if (scope.phase !== 'active') throw unavailable('profile');
    return scope.instance.record;
  }
  async function closeProfile(scope: LogicalProfile, guard: () => void, deadline: number):
    ReturnType<AdditionalProfiles['admit']> {
    if (scope.retirement) await scope.retirement;
    guard(); scope.runtime.assertAdmission();
    if (scope.phase === 'dormant') return { result: 'dormant' };
    if (scope.phase !== 'active' || scope.shell.host.hasForegroundWork()) throw unavailable('profile');
    const { selectWindowProfile } = await import('../host/windows.js');
    guard();
    if (scope.phase !== 'active' || scope.shell.host.hasForegroundWork() ||
        [...profiles.values()].some(entry => entry.opening && !entry.scope && entry.runtime?.phase !== 'fatal')) throw unavailable('profile');
    const peers = [primary, ...[...profiles.values()].map(entry => entry.scope)]
      .filter((peer): peer is LogicalProfile => !!peer && peer !== scope && peer.phase === 'active');
    const next = peers[0];
    if (!next) {
      const runtime = state.runtime;
      if (!runtime) throw unavailable('profile');
      closing = true;
      return { result: 'exiting', afterReply: () => {
        setImmediate(() => { void runtime.close().catch(() => {}); });
      } };
    }
    if (scope.shell.host.isActiveProfile()) selectWindowProfile(scope.shell.host, next.shell.host);
    const retire = scope.control.ownership.control.retireProfileTabs;
    if (!retire) throw unavailable('profile');
    scope.phase = 'closing';
    const draining = transports.setProfileTraffic(scope.transport, false);
    scope.retirement = (async () => {
      await Promise.all([retire(deadline), draining]);
      await scope.flush();
      scope.runtime.assertAdmission();
      await scope.instance.owner.assert();
      scope.phase = 'dormant';
      scope.shell.registration.publish();
    })();
    await scope.retirement;
    delete scope.retirement;
    guard();
    return { result: 'closed' };
  }
  return Object.freeze({
    openInWindow,
    bindPrimary(scope: LogicalProfile) {
      if (primary || scope.instance !== custody.instance || scope.runtime !== state.runtime || scope.shell !== state.shell) throw unavailable('profile');
      primary = scope;
    },
    primaryActive: () => primary?.phase === 'active' && !closing,
    activeHandoff,
    async admit(scope: Parameters<AdditionalProfiles['admit']>[0], deadline: number, signal: AbortSignal):
      ReturnType<AdditionalProfiles['admit']> {
      const source = state.shell?.host;
      if (!source || signal.aborted) throw unavailable('profile');
      assertCurrent(source, deadline);
      const target = await readProfile(profilePaths(scope.profile, custody.host.policy.stateRoot));
      if (target.record.instance !== scope.profileInstance) throw unavailable('profile');
      if (scope.operation === 'open') return { result: await openProfile(source, target, deadline, signal) };
      const selected = scope.profile === custody.instance.record.profile ? primary : profiles.get(scope.profile)?.scope;
      if (!selected) return { result: 'dormant' };
      if (selected.instance.record.profileInstance !== scope.profileInstance) throw unavailable('profile');
      const guard = () => {
        assertCurrent(source, deadline);
        if (signal.aborted) throw unavailable('profile');
      };
      guard();
      if (scope.operation === 'close') return closeProfile(selected, guard, deadline);
      selected.runtime.assertAdmission();
      if (selected.phase === 'closing') throw unavailable('profile');
      return { result: selected.phase === 'dormant' ? 'dormant' : selected.instance.record };
    },
    fence() {
      closing = true;
      for (const entry of profiles.values()) entry.runtime?.fence();
    },
    async retire(deadline: number) {
      await Promise.allSettled([...profiles.values()].map(entry => entry.opening));
      await Promise.all([...profiles.values()].map(entry => entry.runtime?.retire(deadline)));
    },
  });
}

/** Actual canonical ABR-11 control, hidden shell and protected transport.
 * Bind every owner/window/registration before load, then publish native ready. */
async function assembleAfterReady(prepared: HostPreparation, sessions: ProfileSessions,
  boundary: import('./bootstrap.js').NativeFailureBoundary, request: HostRequest,
  state: ActualHostAssembly, deadline: number, platform: import('./platform.js').PlatformPort,
  assertMenuInstalled: () => void, showEmptyWhenReady: boolean, exits: ProductionExitAuthority): Promise<void> {
  assertOwnedHost(prepared); assertTime(deadline);
  const bootstrapURL = new URL('./bootstrap.js', import.meta.url).href;
  const lifecycleURL = new URL('./lifecycle.js', import.meta.url).href;
  const transportURL = new URL('./transport.js', import.meta.url).href;
  const sessionsURL = new URL('../profiles/session.js', import.meta.url).href;
  const bootstrap = await import(bootstrapURL) as typeof import('./bootstrap.js');
  const lifecycle = await import(lifecycleURL) as typeof import('./lifecycle.js');
  const transports = await import(transportURL) as typeof import('./transport.js');
  const sessionModule = await import(sessionsURL) as typeof import('../profiles/session.js');
  const current = () => {
    assertTime(deadline); prepared.custody.assertRetained();
    if (state.closed) return prepared.custody.terminate();
    assertMenuInstalled();
  };
  try {
    current(); sessionModule.assertProductionSessions(sessions, prepared.custody);
    noteHostStartup(prepared.custody, 'host-control-prepare-before');
    const control = await bootstrap.prepareRendererControl(boundary, prepared, request.selection, sessions, deadline);
    noteHostStartup(prepared.custody, 'host-control-prepare-after');
    state.control = control; current();
    noteHostStartup(prepared.custody, 'host-shell-port-before');
    const port = await bootstrap.prepareNativeShellPort(boundary);
    noteHostStartup(prepared.custody, 'host-shell-port-after'); current();
    const group = state.residence ?
      additionalProfiles(prepared.custody, state, boundary, port, platform, exits, bootstrap, lifecycle, transports) : undefined;
    if (group) state.additional = group;
    noteHostStartup(prepared.custody, 'host-shell-integrate-before');
    const shell = await bootstrap.integrateTrustedShell(port, prepared, request.selection, sessions,
      control.ownership.lifecycle, control.ownership.shell, deadline, group?.openInWindow);
    noteHostStartup(prepared.custody, 'host-shell-integrate-after');
    state.shell = shell; current();
    // Genuine physical shell is still hidden and empty. No load/show precedes
    // real controller/window/registration binding in the accepted graph.
    noteHostStartup(prepared.custody, 'host-control-bind-before');
    control.bind(shell.tabs, shell.host, shell.registration);
    noteHostStartup(prepared.custody, 'host-control-bind-after');
    noteHostStartup(prepared.custody, 'host-listeners-before');
    const transport = await transports.listenProtectedTransport(prepared.instance.location, prepared.instance.record, platform,
      control.ownership.dispatch, usageFor(transports, platform, prepared.instance,
        () => prepared.custody.assertRetained(), control, shell, () => state.runtime, () => group?.activeHandoff() === true),
      undefined, group?.admit);
    noteHostStartup(prepared.custody, 'host-listeners-after');
    state.transport = transport; current();
    const shutdown = sessionModule.productionSessionShutdown(sessions, prepared.custody);
    const native = bootstrap.createNativeLifetime(boundary, prepared, request.selection, () => shutdown.quit());
    noteHostStartup(prepared.custody, 'host-lifecycle-bind-before');
    const runtime = lifecycle.createHostLifecycle(prepared, sessions, transport, control.ownership.control, native, deadline, platform, group);
    state.runtime = runtime; control.ownership.bindRuntime(runtime);
    group?.bindPrimary({ instance: prepared.instance, runtime, control, shell, transport, phase: 'active', async flush() {
      sessionModule.assertProductionSessions(sessions, prepared.custody);
      runtime.assertAdmission();
      sessions.website.flushStorageData();
      await sessions.website.cookies.flushStore();
      sessionModule.assertProductionSessions(sessions, prepared.custody);
      runtime.assertAdmission();
    } });
    noteHostStartup(prepared.custody, 'host-lifecycle-bind-after');
    app.on('before-quit', event => {
      if (shutdown.isQuitting()) return;
      event.preventDefault(); void runtime.close().catch(() => {});
    });
    app.on('window-all-closed', () => runtime.lastWindowClosed());
    noteHostStartup(prepared.custody, 'host-shell-load-before');
    await shell.registration.load();
    noteHostStartup(prepared.custody, 'host-shell-load-after'); current(); shell.registration.assertLoaded();
    noteHostStartup(prepared.custody, 'host-lifecycle-ready-before');
    await runtime.ready();
    noteHostStartup(prepared.custody, 'host-lifecycle-ready-after'); current();
    shell.registration.setRuntimeReady(() => runtime.phase === 'ready' && !state.closed && (!group || group.primaryActive()));
    if (showEmptyWhenReady && shell.tabs.all().length === 0) {
      runtime.assertAdmission();
      await shell.registration.offerForegroundPresentation(deadline, () => {
        runtime.assertAdmission();
        return shell.tabs.all().length === 0;
      });
    }
  } catch {
    if (state.runtime?.phase === 'closing') return; // actual bounded native shutdown already owns abandonment
    state.closed = true; return boundary.fatal.fail('native_boundary_unavailable');
  }
}
let entryAttempted = false;
/** The thin packaged entry explicitly awaits ONLY this authenticated pre-ready
 * phase. It never waits for app.whenReady during ESM module evaluation. */
export async function runHostEntry(): Promise<void> {
  if (entryAttempted || process.type !== 'browser' || app.isReady()) throw unavailable('browser');
  entryAttempted = true;
  const localBudget = performance.now() + 60000;
  let capture: CapturedHostBuild | undefined, owned: OwnedHost | null = null;
  let boundary: import('./bootstrap.js').NativeFailureBoundary | undefined;
  const state: ActualHostAssembly = { closed: false };
  try {
    // Only the fixed entry's physical layout and exact outer argument precede
    // native capture. Never read the profile request or learn policy from it.
    const payload = resolve(fileURLToPath(new URL('../../', import.meta.url)));
    const bundle = dirname(dirname(dirname(payload))), parent = dirname(bundle);
    const buildRoot = basename(parent) === 'app' ? dirname(parent) : parent;
    const selectionURL = new URL('./selection.js', import.meta.url).href;
    const selections = await import(selectionURL) as typeof import('./selection.js');
    const layout = selections.packagedLayout(basename(buildRoot), payload), argv = [...process.argv];
    const selection: BuildSelection = Object.freeze({ build: layout.build, directory: layout.buildRoot, guard: layout.guard, explicit: true });
    const showEmptyWhenReady = process.env.ARBOL_BROWSER_SHOW_EMPTY_WHEN_READY === '1';
    delete process.env.ARBOL_BROWSER_SHOW_EMPTY_WHEN_READY;
    if (argv.length !== 6 || argv[0] !== layout.engine || process.execPath !== layout.engine ||
        argv[1] !== '--site-per-process' || argv[2] !== '--disable-features=MacAccessibilityTextOperation' ||
        argv[3] !== layout.hostEntry || argv[4] !== '--arbol-host-request' || !argv[5]?.startsWith('/')) throw unavailable('browser');
    const args = Object.freeze([argv[4], argv[5]] as const);
    const bootstrapURL = new URL('./bootstrap.js', import.meta.url).href;
    const bootstrap = await import(bootstrapURL) as typeof import('./bootstrap.js');
    // This finite read-only budget is not new engine admission: Native owns
    // the immutable original expiry and its expired/cancelled terminal branch.
    const native = await bootstrap.prepareNativeBoundary(bundle, localBudget, installedImagePath(layout), args[1]);
    capture = captureHostBuild(native.platform, selection, bundle, args[1]);
    const authoritiesURL = new URL('./authorities.js', import.meta.url).href;
    const authorities = await import(authoritiesURL) as typeof import('./authorities.js');
    const [request, host] = await Promise.all([
      consumeHostRequest(args, selection.build, buildRoot),
      authorities.verifyPackagedHost(selection, payload, localBudget, native.trust),
    ]);
    if (request.selection.build !== selection.build || request.selection.directory !== selection.directory ||
        request.selection.guard !== selection.guard) return terminateCapturedHostBuild(capture);
    const processURL = new URL('./process.js', import.meta.url).href;
    const attempts = await import(processURL) as typeof import('./process.js');
    const attempt = await attempts.withLaunchAttempt(request.profile, native.platform, localBudget, transaction => transaction.current);
    if (!attempt || attempt.request !== request.request || attempt.phase !== 'claimed' || attempt.stage !== 'untransferred')
      return terminateCapturedHostBuild(capture);
    // Sample caller clock first: translating native remaining admission can
    // shorten this original deadline, never extend it by the sampling gap.
    const sampled = performance.now(), nativeNow = native.platform.continuousTime();
    const deadline = Math.min(localBudget, sampled + attempt.expires - nativeNow); assertTime(deadline);
    if (layout.scope === 'installed')
      state.residence = await retainInstalledResidence(host.policy.stateRoot, native.platform, deadline);
    const exitURL = new URL('./exit.js', import.meta.url).href;
    const exits = await import(exitURL) as typeof import('./exit.js');
    const previous = exits.createProductionExitAuthority(native.platform, request.selection, host);
    owned = await prepareOwnedHost(app, request, host, native, previous, deadline, capture);
    if (!owned) return terminateCapturedHostBuild(capture);
    await state.residence?.publish(owned.instance);
    const effects: import('../native/fatal.js').FatalEffects = Object.freeze({
      closeAdmission() {
        state.closed = true;
        try { state.additional?.fence(); }
        finally { state.control?.ownership.control.closeAdmission(); state.transport?.closeAdmission(); }
      },
      invalidate() { state.control?.ownership.authority.closeAdmission(); },
      hidePages() { const window = state.shell?.host.window; if (window && !window.isDestroyed()) window.hide(); },
    });
    boundary = await owned.installNative(effects, deadline);
    if (app.isReady()) return owned.custody.terminate();
    const assertMenuInstalled = installApplicationMenu();
    noteHostStartup(owned.custody, 'engine-authority');
    const engine = authorities.createHostEngineAuthority(host, owned.custody, previous, deadline);
    const prepared = await prepareHost(app, owned, engine);
    prepared.custody.assertRetained(); assertTime(deadline);
    if (app.isReady() || state.closed) return prepared.custody.terminate();
    const installed = boundary;
    // Register, do not await. Electron can now finish this ESM evaluation and
    // reach readiness; the continuation owns all later errors and custody.
    void app.whenReady().then(async () => {
      try {
        assertTime(deadline); prepared.custody.assertRetained();
        if (!app.isReady() || state.closed) return prepared.custody.terminate();
        const icon = nativeImage.createFromPath(join(bundle, 'Contents/Resources/ArbolBrowser.png'));
        if (icon.isEmpty()) throw unavailable('browser');
        app.dock?.setIcon(icon);
        noteHostStartup(prepared.custody, 'host-session-bind-before');
        const sessions = await bindHostSessions(prepared, deadline);
        noteHostStartup(prepared.custody, 'host-session-bind-after');
        assertTime(deadline); prepared.custody.assertRetained();
        if (state.closed) return prepared.custody.terminate();
        await assembleAfterReady(prepared, sessions, installed, request, state, deadline, native.platform,
          assertMenuInstalled, showEmptyWhenReady, previous);
      } catch { state.closed = true; return installed.fatal.fail('native_boundary_unavailable'); }
    }, () => installed.fatal.fail('native_boundary_unavailable'));
  } catch (error) {
    state.closed = true;
    if (boundary) return boundary.fatal.fail('native_boundary_unavailable');
    if (owned) return owned.custody.terminate();
    if (capture) return terminateCapturedHostBuild(capture);
    // Pinned Electron's uncaught handler shows a GUI dialog and does not quit.
    // Only this unknown BEFORE-capture branch gets fixed process-local refusal.
    // It issues no clean/terminal witness, external signal or JS guard release.
    void error; app.exit(4);
  }
}
