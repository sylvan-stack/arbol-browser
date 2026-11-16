import { unavailable } from '../contracts/errors.js';
import type { CommandPorts } from './ports.js';

/** ABR-1 has no production native adapter, watchdog, qualified manifest or host.
 * There are intentionally no Electron imports or page/shell constructors here.
 * Later startup must replace this refusal with qualified preflight before any
 * view can be created; a JavaScript shield or support.node is never readiness. */
export async function preflightPageAdmission(): Promise<never> {
  throw unavailable('browser');
}

export const foundationPorts: CommandPorts = Object.freeze({
  process: Object.freeze({
    open: async () => preflightPageAdmission(),
    close: async () => { throw unavailable('browser'); },
    mcp: async () => { throw unavailable('browser'); },
  }),
  profiles: Object.freeze({
    list: async () => { throw unavailable('profile'); },
    create: async () => { throw unavailable('profile'); },
    remove: async () => { throw unavailable('profile'); },
  }),
});

// Explicit production primitives only. Ordinary entry above still refuses pages.
import type { CandidateTrust } from '../native/manifest.js';
import type { HeldLock, PlatformPort } from './platform.js';
import type { NativeWatchdog } from '../native/watchdog.js';
export interface NativeBoundaryPreparation {
  readonly trust: CandidateTrust;
  readonly platform: PlatformPort;
  arm(owner: HeldLock, build: HeldLock): Promise<NativeWatchdog>;
}
interface NativeServices {
  readonly manifest: typeof import('../native/manifest.js');
  readonly platform: typeof import('./platform.js');
  readonly watchdog: typeof import('../native/watchdog.js');
}
const preparations = new WeakSet<object>();
const preparationServices = new WeakMap<NativeBoundaryPreparation, NativeServices>();
const handovers = new WeakMap<NativeWatchdog, { prepared: NativeBoundaryPreparation; owner: HeldLock; build: HeldLock }>();
let boundaryAttempted = false;
/** Initial independent publisher verification precedes process-addon loading.
 * ABR-29 must await preparation, then acquire real owner/Build handles using
 * this exact platform instance. Both bundled host and physical bootstrap resolve
 * to the same physical lib/native and lib/runtime graph; no second cache/brand. */
export async function prepareNativeBoundary(bundle: string): Promise<NativeBoundaryPreparation> {
  if (boundaryAttempted || process.type !== 'browser') throw unavailable('browser');
  boundaryAttempted = true;
  const manifestUrl = new URL('../native/manifest.js', import.meta.url).href;
  const manifest = await import(manifestUrl) as typeof import('../native/manifest.js');
  const trust = manifest.verifyNativeCandidate(bundle);
  const platformUrl = new URL('../runtime/platform.js', import.meta.url).href;
  const platformModule = await import(platformUrl) as typeof import('./platform.js');
  manifest.assertCandidateTrust(trust);
  const platform = platformModule.loadPlatform();
  const watchdogUrl = new URL('../native/watchdog.js', import.meta.url).href;
  const watchdogModule = await import(watchdogUrl) as typeof import('../native/watchdog.js');
  const services: NativeServices = Object.freeze({ manifest, platform: platformModule, watchdog: watchdogModule });
  let armAttempted = false;
  const prepared: NativeBoundaryPreparation = Object.freeze({ trust, platform,
    async arm(owner: HeldLock, build: HeldLock): Promise<NativeWatchdog> {
      if (armAttempted) throw unavailable('browser'); armAttempted = true;
      services.manifest.assertCandidateTrust(trust);
      const custody = platform.prepareWatchdogCustody(owner, build, trust.bundle, trust.snapshotDigest);
      const watchdog = await services.watchdog.startNativeWatchdog(trust, custody);
      handovers.set(watchdog, { prepared, owner, build }); return watchdog;
    } });
  preparationServices.set(prepared, services); preparations.add(prepared); return prepared;
}
export function assertNativeBoundaryPreparation(value: NativeBoundaryPreparation): void {
  if (!preparations.has(value)) throw unavailable('browser');
}

import type { ProfileFatal, FatalEffects } from '../native/fatal.js';
import type { NativeCompatibility } from '../native/preflight.js';
import type { Binding, BindingKey } from '../native/api.js';
import type { View, WebContentsView } from 'electron';
import type { HostPreparation } from './host-entry.js';
import type { HostNativeLifetime } from './lifecycle.js';
import type { BuildSelection } from './selection.js';
import { lstat, realpath } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
export interface NativeFailureBoundary {
  readonly native: NativeCompatibility;
  readonly fatal: ProfileFatal;
  readonly watchdog: NativeWatchdog;
  readonly pageAdmission: false;
  retire(key: BindingKey, parent: View, view: WebContentsView): Promise<Binding>;
}
const installedBoundaries = new WeakSet<object>();
export function assertNativeFailureBoundary(value: NativeFailureBoundary): void {
  if (!installedBoundaries.has(value)) throw unavailable('browser');
  value.fatal.assertHealthy(); value.native.assertIntegrity();
}
/** The same concrete armed child covers feature setup and the one addon install.
 * Variable module URLs keep Electron-only imports out of the Node CLI bundle. */
export async function installNativeBoundary(prepared: NativeBoundaryPreparation, watchdog: NativeWatchdog,
  effects: FatalEffects): Promise<NativeFailureBoundary> {
  assertNativeBoundaryPreparation(prepared);
  const services = preparationServices.get(prepared);
  if (!services) throw unavailable('browser');
  services.watchdog.assertNativeWatchdog(watchdog);
  let fatal: ProfileFatal | undefined;
  try {
    assertNativeBoundaryPreparation(prepared);
    if (handovers.get(watchdog)?.prepared !== prepared) return watchdog.terminate();
    watchdog.assertArmed(prepared.trust);
    const fatalUrl = new URL('../native/fatal.js', import.meta.url).href;
    const fatalModule = await import(fatalUrl) as typeof import('../native/fatal.js');
    fatal = fatalModule.createProfileFatal(watchdog, effects);
    const featuresUrl = new URL('../native/features.js', import.meta.url).href;
    const features = await import(featuresUrl) as typeof import('../native/features.js');
    fatal.assertHealthy(); features.configureNativeFeatures();
    const preflightUrl = new URL('../native/preflight.js', import.meta.url).href;
    const preflight = await import(preflightUrl) as typeof import('../native/preflight.js');
    fatal.assertHealthy(); watchdog.assertArmed(prepared.trust);
    const retirementUrl = new URL('../native/retirement.js', import.meta.url).href;
    const retirement = await import(retirementUrl) as typeof import('../native/retirement.js');
    const guard = fatal;
    guard.assertHealthy(); watchdog.assertArmed(prepared.trust);
    const native = preflight.preflightNative(prepared.trust.bundle, reason => guard.fail(reason), watchdog);
    guard.attach(native);
    const boundary: NativeFailureBoundary = Object.freeze({ native, fatal: guard, watchdog, pageAdmission: false as const,
      retire: (key: BindingKey, parent: View, view: WebContentsView) => {
        guard.assertHealthy(); return retirement.retireNativeTarget(native, key, parent, view, reason => guard.fail(reason));
      } });
    installedBoundaries.add(boundary); return boundary;
  } catch { if (fatal) return fatal.fail('native_integrity_unavailable'); return watchdog.terminate(); }
}
async function assertHeldPath(path: string, held: HeldLock): Promise<void> {
  const expected = held.assertIdentity(), actual = await lstat(path, { bigint: true });
  if (await realpath(path) !== path || !actual.isFile() || actual.nlink !== 1n || (actual.mode & 0o7777n) !== 0o600n ||
      String(actual.dev) !== expected.device || String(actual.ino) !== expected.inode || actual.uid !== BigInt(expected.uid)) throw unavailable('browser');
  held.assertIdentity();
}
/** Native lifetime contribution, not EngineAuthority or complete host admission.
 * ABR-29 supplies its actual preparation/selection and real app-exit request. */
export function createNativeLifetime(boundary: NativeFailureBoundary, host: HostPreparation, selection: BuildSelection,
  requestApplicationExit: () => void): HostNativeLifetime {
  if (!installedBoundaries.has(boundary) || typeof requestApplicationExit !== 'function') throw unavailable('browser');
  const ownership = handovers.get(boundary.watchdog);
  if (!ownership) return boundary.fatal.fail('native_integrity_unavailable');
  let attached = false, exiting = false;
  const assertCustody = async () => {
    boundary.fatal.assertHealthy(); boundary.watchdog.assertArmed(boundary.native.trust);
    if (!selection.guard || host.instance.record.build !== selection.build) throw unavailable('browser');
    await host.instance.owner.assert(); await host.buildGuard.assert();
    await assertHeldPath(host.instance.owner.profile.paths.owner, ownership.owner);
    await assertHeldPath(selection.guard, ownership.build);
    boundary.fatal.assertHealthy(); boundary.watchdog.assertArmed(boundary.native.trust);
  };
  return Object.freeze({
    async armRetainedLifetime(current: HostPreparation): Promise<void> {
      try {
        if (attached || current !== host) return boundary.fatal.fail('native_integrity_unavailable');
        await assertCustody(); attached = true;
      } catch { return boundary.fatal.fail('native_integrity_unavailable'); }
    },
    async assertReady(): Promise<void> {
      try { if (!attached || exiting) return boundary.fatal.fail('native_integrity_unavailable'); await assertCustody(); boundary.native.assertIntegrity(); }
      catch { return boundary.fatal.fail('native_integrity_unavailable'); }
    },
    quarantine(): never { return boundary.fatal.fail('native_boundary_unavailable'); },
    async exit(deadline: number): Promise<never> {
      try {
        if (!attached || exiting || !Number.isFinite(deadline) || performance.now() >= deadline) return boundary.fatal.fail('native_boundary_unavailable');
        exiting = true; await assertCustody(); boundary.native.seal();
        // Healthy H/A continues through ordinary shutdown. The timer escalates
        // failure; no finally stops either monitor or releases original guards.
        const timer = setTimeout(() => boundary.fatal.fail('native_boundary_unavailable'), Math.max(1, deadline - performance.now()));
        timer.unref();
        const returned: unknown = requestApplicationExit();
        if (returned !== undefined) return boundary.fatal.fail('native_boundary_unavailable');
        return await new Promise<never>(() => {}); // only actual process exit ends this wait
      } catch { return boundary.fatal.fail('native_boundary_unavailable'); }
    },
  });
}

import type { ProfileSessions } from '../profiles/session.js';
import type { TabLifecycle, TabRegistry } from '../host/tabs.js';
import type { WindowHost } from '../host/windows.js';
import type { ShellAuthority, ShellRegistration } from '../host/shell-ipc.js';
import type { Contract } from '../contracts/generated.js';
/** Opaque trusted main-process contribution, explicitly not production page authority. */
export interface NativeShellPort { readonly pageAdmission: false }
interface ShellModules {
  windows: typeof import('../host/windows.js');
  tabs: typeof import('../host/tabs.js');
  ipc: typeof import('../host/shell-ipc.js');
  projections: typeof import('../host/projections.js');
}
const nativeShellPorts = new WeakMap<NativeShellPort, { boundary: NativeFailureBoundary; modules: ShellModules }>();
/** Canonical physical module URLs avoid duplicate native brands and bundled-entry asset paths. */
export async function prepareNativeShellPort(boundary: NativeFailureBoundary): Promise<NativeShellPort> {
  if (!installedBoundaries.has(boundary)) throw unavailable('browser');
  boundary.fatal.assertHealthy(); boundary.native.assertIntegrity();
  const windowsURL = new URL('../host/windows.js', import.meta.url).href;
  const tabsURL = new URL('../host/tabs.js', import.meta.url).href;
  const ipcURL = new URL('../host/shell-ipc.js', import.meta.url).href;
  const projectionsURL = new URL('../host/projections.js', import.meta.url).href;
  const windows = await import(windowsURL) as ShellModules['windows'];
  const tabs = await import(tabsURL) as ShellModules['tabs'];
  const ipc = await import(ipcURL) as ShellModules['ipc'];
  const projections = await import(projectionsURL) as ShellModules['projections'];
  boundary.fatal.assertHealthy(); boundary.native.assertIntegrity();
  const port: NativeShellPort = Object.freeze({ pageAdmission: false as const });
  nativeShellPorts.set(port, { boundary, modules: { windows, tabs, ipc, projections } }); return port;
}
export interface TrustedShellIntegration {
  readonly pageAdmission: false;
  readonly host: WindowHost;
  readonly tabs: TabRegistry;
  readonly registration: ShellRegistration;
  /** Invoke synchronously at ABR-10's actual authorized transport commit boundary. */
  agentTabs(recipient: string): Contract<'browser.TabsResult'>;
}
/** ABR-29 must supply its actual owned/prepared host and ABR-10/11 services.
 * No default services, EngineAuthority or readiness are invented here. The ordinary
 * entry above continues to refuse; this function is never invoked by this Beat. */
export async function integrateTrustedShell(port: NativeShellPort, prepared: HostPreparation,
  selection: BuildSelection, sessions: ProfileSessions, lifecycle: TabLifecycle, authority: ShellAuthority): Promise<TrustedShellIntegration> {
  const value = nativeShellPorts.get(port);
  if (!value) throw unavailable('browser');
  const { boundary, modules } = value;
  const ownership = handovers.get(boundary.watchdog);
  if (!ownership || !installedBoundaries.has(boundary)) throw unavailable('browser');
  await prepared.instance.owner.assert(); await prepared.buildGuard.assert(); await prepared.engine.assertReady();
  await assertHeldPath(prepared.instance.owner.profile.paths.owner, ownership.owner);
  if (!selection.guard || prepared.instance.record.build !== selection.build) throw unavailable('browser');
  await assertHeldPath(selection.guard, ownership.build);
  boundary.fatal.assertHealthy(); boundary.native.assertIntegrity(); authority.assertReady();
  const guardedLifecycle: TabLifecycle = {
    assertAdmission() { boundary.fatal.assertHealthy(); boundary.native.assertIntegrity(); authority.assertReady(); lifecycle.assertAdmission(); },
    connected: client => lifecycle.connected(client),
    register: (target, initial) => lifecycle.register(target, initial),
    state: target => modules.projections.projectShellTab(lifecycle.state(target), client => lifecycle.connected(client)),
    invalidate: target => lifecycle.invalidate(target), removed: target => lifecycle.removed(target),
    prepare: (target, url) => boundary.native.guard(() => lifecycle.prepare(target, url)),
    changed: () => lifecycle.changed(), exhausted: () => lifecycle.exhausted(),
  };
  const tabs = modules.tabs.createTabRegistry(guardedLifecycle);
  const guardedAuthority: ShellAuthority = {
    assertReady() { boundary.fatal.assertHealthy(); boundary.native.assertIntegrity(); authority.assertReady(); },
    assertOperational() { guardedLifecycle.assertAdmission(); authority.assertOperational(); },
    attachments: () => authority.attachments().map(client => ({ id: client.id, label: modules.projections.clientLabel(client.label) })),
    execute: (request, target) => boundary.native.guard(() => authority.execute(request, target)),
    subscribe: changed => authority.subscribe(changed), exhausted: () => authority.exhausted(),
  };
  let host: WindowHost;
  try {
    host = modules.windows.createWindowHost(sessions, boundary, () => {
      void tabs.closeWindow(host).catch(() => boundary.fatal.fail('native_retirement_unavailable'));
    });
    const registration = modules.ipc.registerShellIPC(host, tabs, guardedAuthority);
    // Return the actual registered hidden resources before any asynchronous
    // loading. Assembly must bind ownership/window closure first, then await
    // registration.load and genuine lifecycle.ready before showing the shell.
    return Object.freeze({ pageAdmission: false as const, host, tabs, registration,
      agentTabs: (recipient: string) => modules.projections.projectAgentTabs(tabs, recipient, client => lifecycle.connected(client)) });
  } catch { return boundary.fatal.fail('native_boundary_unavailable'); }
}
