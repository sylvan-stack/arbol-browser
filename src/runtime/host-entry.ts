import { app, session } from 'electron';
import { resolve, join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { preflightPageAdmission } from './bootstrap.js';
import { configureProfileSession, type SessionBinding, type ProfileSessions, type ProfileApp } from '../profiles/session.js';
import { prepareEngine, type EngineAuthority, type EngineTransaction } from '../profiles/compatibility.js';
import { acquireInstance, runtimeLocation, startupDeadline, type InstanceOwner, type PreviousExit } from './instance.js';
import type { PlatformPort } from './platform.js';
import { readJson, readProfile, type ProfileSnapshot } from '../profiles/records.js';
import { profilePaths, ownerUid } from '../profiles/paths.js';
import { consumeSelection, type BuildSelection } from './selection.js';
import { validator } from '../contracts/schema.js';
import type { BuildGuard } from './start.js';
import { unavailable } from '../contracts/errors.js';

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
/** Host independently acquires its Build guard and owner.lock. This is invoked
 * from an awaited ESM entry, before ready or any session/data construction. */
export async function prepareOwnedHost(actualApp: ProfileApp, request: HostRequest, platform: PlatformPort,
  authority: EngineAuthority & PreviousExit, acquireBuild: () => Promise<BuildGuard>): Promise<HostPreparation | null> {
  if (actualApp.isReady()) throw unavailable('browser');
  await authority.assertTrusted();
  const group = platform.groupCensus(process.pid);
  if (!group.some(member => member.pid === process.pid && member.uid === ownerUid() && member.group === process.pid))
    throw unavailable('browser');
  const buildGuard = await acquireBuild();
  let instance: InstanceOwner | null;
  try { instance = await acquireInstance(request.profile, platform, request.selection.build, authority, startupDeadline()); }
  catch (error) { buildGuard.release(); throw error; }
  if (!instance) { buildGuard.release(); return null; } // Losing host never opens data.
  // Ownership remains retained on every failed preparation. Native fatal/exit
  // machinery must establish helper exit before releasing it or terminating.
  hostGuards.add({ instance, buildGuard });
  return prepareHost(actualApp, instance, authority, buildGuard);
}
const hostGuards = new Set<{ instance: InstanceOwner; buildGuard: BuildGuard }>();

export interface HostPreparation {
  readonly instance: InstanceOwner; readonly engine: EngineTransaction; readonly binding: SessionBinding;
  readonly buildGuard: BuildGuard;
}
/** Called with the real app in the entry's awaited pre-ready phase. Ownership
 * and Build guards already belong to this host. No page authority is created. */
export async function prepareHost(actualApp: ProfileApp, instance: InstanceOwner, authority: EngineAuthority,
  buildGuard: BuildGuard): Promise<HostPreparation> {
  if (actualApp.isReady()) throw unavailable('browser');
  await instance.owner.assert(); await buildGuard.assert();
  if (authority.build !== instance.record.build) throw unavailable('browser');
  const engine = await prepareEngine(instance.owner, authority);
  const binding = await configureProfileSession(actualApp, engine);
  if (actualApp.isReady()) throw unavailable('browser');
  return Object.freeze({ instance, engine, binding, buildGuard });
}
export async function bindHostSessions(prepared: HostPreparation): Promise<ProfileSessions> {
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
