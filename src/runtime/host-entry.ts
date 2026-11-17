import { app, session } from 'electron';
import { resolve, join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { preflightPageAdmission } from './bootstrap.js';
import { configureProfileSession, type SessionBinding, type ProfileSessions, type ProfileApp } from '../profiles/session.js';
import { prepareEngine, type EngineAuthority, type EngineTransaction } from '../profiles/compatibility.js';
import { acquireInstance, runtimeLocation, assertTime, type InstanceOwner, type PreviousExit, type RuntimeRecord } from './instance.js';
import { readJson, readProfile, type ProfileSnapshot } from '../profiles/records.js';
import { profilePaths } from '../profiles/paths.js';
import { consumeSelection, type BuildSelection } from './selection.js';
import { validator } from '../contracts/schema.js';
import { unavailable } from '../contracts/errors.js';
import { adoptHostBuildLease, type BuildLease } from './build-lease.js';
import { assertVerifiedHost, assertHostEngineAuthority, type VerifiedHost } from './authorities.js';
import { claimedHostAttempt } from './process.js';
import { prepareHostCustody, abortUnadmittedHost, type HostCustody } from './custody.js';
import type { NativeBoundaryPreparation } from './bootstrap.js';
import type { NativeWatchdog } from '../native/watchdog.js';
import type { OwnerLease } from '../profiles/locking.js';
import type { PriorMarkerExpectation } from './platform.js';

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
}
const ownedHosts = new WeakSet<object>();
export function assertOwnedHost(host: OwnedHost): void {
  if (!ownedHosts.has(host)) throw unavailable('browser'); host.custody.assertRetained();
}
/** Genuine pre-ready ownership only: no compatibility read, dirty marker,
 * setPath, Session or shell access precedes retained Native acknowledgement. */
export async function prepareOwnedHost(actualApp: ProfileApp, request: HostRequest, host: VerifiedHost,
  native: NativeBoundaryPreparation, previousExit: HostPreviousExit, deadline: number): Promise<OwnedHost | null> {
  if (process.type !== 'browser' || actualApp.isReady()) throw unavailable('browser');
  const bootstrapURL = new URL('./bootstrap.js', import.meta.url).href;
  const bootstrap = await import(bootstrapURL) as typeof import('./bootstrap.js');
  bootstrap.assertNativeBoundaryPreparation(native);
  const platform = native.platform;
  assertVerifiedHost(host, deadline); await host.assertTrusted(deadline);
  if (native.trust.bundle !== host.signed.bundle || native.trust.snapshotDigest !== host.signed.snapshotDigest ||
      request.selection.build !== host.identity.layout.build || request.selection.directory !== host.identity.layout.buildRoot)
    throw unavailable('browser');
  const location = await runtimeLocation(request.profile);
  if (!location) throw unavailable('browser');
  // This adopts, rather than releases/reopens, the original outer description.
  const buildGuard = await adoptHostBuildLease(host, platform, join(location.leaf, `launch-${request.request}.json`), deadline);
  const assertAdmission = async () => {
    assertTime(deadline); if (actualApp.isReady()) throw unavailable('browser');
    await claimedHostAttempt(request.profile, host, platform, request.request, deadline);
    await buildGuard.assert(); assertTime(deadline);
  };
  let instance: InstanceOwner | null = null, custody: HostCustody | undefined;
  try {
    await assertAdmission();
    instance = await acquireInstance(request.profile, platform, request.selection.build, previousExit, deadline,
      { assertAdmission, failed: owner => abortUnadmittedHost(owner, buildGuard, platform) });
    // The losing original still owns the genuine inherited Build, and must
    // publish terminal-only no-use before exact self exit. No invented Owner.
    if (!instance) return abortUnadmittedHost(undefined, buildGuard, platform);
    await assertAdmission(); await instance.owner.assert();
    const prior = await previousExit.priorExpectation(request.profile, instance.previous, instance.owner, buildGuard, deadline);
    await assertAdmission();
    custody = await prepareHostCustody(host, instance, buildGuard, platform, request.request, prior, deadline);
    const watchdog = await custody.arm(native, deadline);
    custody.assertRetained(); assertTime(deadline);
    if (actualApp.isReady()) return custody.terminate();
    const owned: OwnedHost = Object.freeze({ instance, buildGuard, custody, watchdog });
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
    await instance.owner.assert(); await buildGuard.assert(); custody.assertRetained();
    if (authority.build !== instance.record.build) return custody.terminate();
    const engine = await prepareEngine(instance.owner, authority);
    custody.assertRetained(); custody.assertMarker();
    const binding = await configureProfileSession(actualApp, engine);
    if (actualApp.isReady()) return custody.terminate();
    const prepared: HostPreparation = Object.freeze({ ...owned, engine, binding });
    ownedHosts.add(prepared); return prepared;
  } catch { return custody.terminate(); }
}
export async function bindHostSessions(prepared: HostPreparation): Promise<ProfileSessions> {
  assertOwnedHost(prepared);
  await prepared.instance.owner.assert(); await prepared.buildGuard.assert();
  return prepared.binding.bind(session);
}
/** The sealed native/control stages must call prepareHost with their verified
 * authority before ready, then bindHostSessions after ready. There is no
 * permissive candidate trust provider and no engine/page constructor here. */
async function candidateEntry(): Promise<void> {
  try {
    // Top-level await is retained in the packaged ESM entry. This blocks ready
    // until all required pre-ready preparation settles (Electron ESM contract).
    await preflightPageAdmission();
  } catch { app.exit(4); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await candidateEntry();
