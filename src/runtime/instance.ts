import { createHash, randomBytes } from 'node:crypto';
import { lstatSync, realpathSync } from 'node:fs';
import { lstat, mkdir, realpath, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout } from 'node:timers/promises';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { unavailable } from '../contracts/errors.js';
import { ownerUid, privateFile, identity, sameIdentity, statOrAbsent, profileUnavailable, type Identity } from '../profiles/paths.js';
import { assertProfile, assertProfileSync, readJson, writeNewFile, type ProfileSnapshot } from '../profiles/records.js';
import { ownerLock, type OwnerLease } from '../profiles/locking.js';
import type { HeldLock, PlatformPort, ProcessIdentity } from './platform.js';

export type RuntimeRecord = Readonly<Contract<'wire.RuntimeRecord'>>;
export const now = (): number => performance.now();
export const token = (prefix: string): string => `${prefix}_${randomBytes(16).toString('base64url')}`;
export const startupDeadline = (): number => now() + 60000;
export function assertTime(deadline: number): void { if (now() >= deadline) throw unavailable('browser'); }
export function sameProcess(a: ProcessIdentity, b: ProcessIdentity): boolean {
  return a.pid === b.pid && a.uid === b.uid && a.startId === b.startId;
}
export function recordProcess(record: RuntimeRecord): ProcessIdentity {
  return { pid: record.pid, uid: ownerUid(), startId: record.processStartId };
}
export function originalAlive(record: RuntimeRecord, platform: PlatformPort): boolean {
  const observed = platform.processIdentity(record.pid);
  return observed !== null && sameProcess(observed, recordProcess(record));
}
export interface RuntimeLocation {
  readonly profile: ProfileSnapshot; readonly parent: string; readonly leaf: string; readonly hash: string;
  readonly agent: string; readonly management: string; readonly record: string;
  assert(): Promise<void>;
  assertSync(): void;
}
async function privateDirectory(path: string): Promise<Identity> {
  const st = await lstat(path);
  if (!st.isDirectory() || st.uid !== ownerUid() || (st.mode & 0o7777) !== 0o700) throw profileUnavailable();
  return identity(st);
}
function privateDirectorySync(path: string): Identity {
  const st = lstatSync(path);
  if (!st.isDirectory() || st.uid !== ownerUid() || (st.mode & 0o7777) !== 0o700) throw profileUnavailable();
  return identity(st);
}
/** /tmp is Darwin's specified system alias, not an arbitrary accepted symlink.
 * All browser-owned descendants are checked with lstat and retained identities. */
export async function runtimeLocation(profile: ProfileSnapshot, create = false): Promise<RuntimeLocation | undefined> {
  await assertProfile(profile);
  const tmp = await realpath('/tmp'), tmpStat = await lstat(tmp);
  if (tmp !== '/private/tmp' || !tmpStat.isDirectory() || tmpStat.uid !== 0 || (tmpStat.mode & 0o1777) !== 0o1777)
    throw profileUnavailable();
  const hash = createHash('sha256').update(profile.paths.root, 'utf8').digest('hex');
  const parent = `/tmp/ab-${ownerUid()}`, leaf = join(parent, hash.slice(0, 32));
  for (const path of [parent, leaf]) {
    if (!await statOrAbsent(path)) {
      if (!create) return undefined;
      try { await mkdir(path, { mode: 0o700 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    }
    await privateDirectory(path);
  }
  const parentIdentity = await privateDirectory(parent), leafIdentity = await privateDirectory(leaf);
  const agent = join(leaf, 'agent.sock'), management = join(leaf, 'manage.sock');
  if ([agent, management].some(path => Buffer.byteLength(path, 'utf8') + 1 > 104)) throw profileUnavailable();
  const location: RuntimeLocation = Object.freeze({ profile, parent, leaf, hash, agent, management,
    record: join(leaf, 'runtime.json'), async assert() {
      if (!sameIdentity(parentIdentity, await privateDirectory(parent)) ||
          !sameIdentity(leafIdentity, await privateDirectory(leaf)) || await realpath('/tmp') !== tmp)
        throw profileUnavailable();
      await assertProfile(profile);
    },
    assertSync() {
      if (!sameIdentity(parentIdentity, privateDirectorySync(parent)) ||
          !sameIdentity(leafIdentity, privateDirectorySync(leaf)) || realpathSync('/tmp') !== tmp)
        throw profileUnavailable();
      assertProfileSync(profile);
    },
  });
  await location.assert(); return location;
}
export async function readRuntime(location: RuntimeLocation): Promise<RuntimeRecord | undefined> {
  await location.assert();
  if (!await statOrAbsent(location.record)) return undefined;
  const { value } = await readJson(location.record, 16384);
  if (!validator('wire.RuntimeRecord')(value) || value.profile !== location.profile.record.id ||
      value.profileInstance !== location.profile.record.instance || value.profilePathHash !== location.hash ||
      value.agentSocket !== location.agent || value.managementSocket !== location.management) throw profileUnavailable();
  await location.assert(); return Object.freeze({ ...value });
}
export async function assertSocket(location: RuntimeLocation, path: string): Promise<void> {
  await location.assert();
  if (path !== location.agent && path !== location.management) throw profileUnavailable();
  const st = await lstat(path);
  if (!st.isSocket() || st.uid !== ownerUid() || (st.mode & 0o7777) !== 0o600 || st.nlink !== 1) throw profileUnavailable();
  await location.assert();
}
async function unchanged(location: RuntimeLocation, previous: RuntimeRecord | undefined): Promise<void> {
  if (JSON.stringify(await readRuntime(location)) !== JSON.stringify(previous)) throw profileUnavailable();
}
export interface PreviousExit {
  /** Must account for original main AND all helpers (including after main death).
   * Group emptiness alone is insufficient without trusted containment evidence. */
  assertExited(profile: ProfileSnapshot, previous: RuntimeRecord | undefined, owner?: OwnerLease): Promise<void>;
}
export interface InstanceAcquisition {
  /** Production uses the actual native short claim transaction. No engine or
   * marker access is permitted by this callback or by acquisition itself. */
  assertAdmission(): Promise<void>;
  /** Once production ownership is acquired, failed preparation retains the
   * actual guard and enters native unwind instead of the Foundation release. */
  failed(owner: OwnerLease): Promise<never>;
}
/** Only the host takes exclusive data ownership. A starter never retains this
 * lock while waiting for a LaunchServices host to acquire it. */
export async function acquireInstance(profile: ProfileSnapshot, platform: PlatformPort, build: string,
  previousExit: PreviousExit, deadline: number, acquisition?: InstanceAcquisition): Promise<InstanceOwner | null> {
  assertTime(deadline);
  if (!validator('browser.Build')(build)) throw profileUnavailable();
  await acquisition?.assertAdmission(); assertTime(deadline);
  const owner = await ownerLock(profile, platform, false, Math.min(deadline, now() + 10000));
  if (!owner) return null;
  try {
    await acquisition?.assertAdmission(); await owner.assert();
    const location = await runtimeLocation(profile, true);
    if (!location) throw profileUnavailable();
    const previous = await readRuntime(location);
    if (previous && originalAlive(previous, platform)) throw profileUnavailable();
    await previousExit.assertExited(profile, previous, owner);
    await owner.assert(); await unchanged(location, previous); assertTime(deadline);
    // Unknown/stale socket identity never licenses removal while its owner lives.
    for (const path of [location.agent, location.management]) {
      if (await statOrAbsent(path)) {
        if (!previous) throw profileUnavailable();
        await assertSocket(location, path); await owner.assert();
        if (originalAlive(previous, platform)) throw profileUnavailable();
        await acquisition?.assertAdmission(); await unlink(path);
      }
    }
    const own = platform.processIdentity(process.pid);
    if (!own || own.uid !== ownerUid()) throw profileUnavailable();
    const record: RuntimeRecord = Object.freeze({ wire: 1, profile: profile.record.id,
      profileInstance: profile.record.instance, profilePathHash: location.hash, instance: token('ins'),
      nonce: randomBytes(32).toString('base64url'), pid: own.pid, processStartId: own.startId,
      build, contract: 1, phase: 'starting', agentSocket: location.agent, managementSocket: location.management });
    let current = previous;
    const publish = async (next: RuntimeRecord) => {
      await owner.assert(); await unchanged(location, current);
      if (!validator('wire.RuntimeRecord')(next)) throw profileUnavailable();
      const temporary = join(location.leaf, `.runtime-${randomBytes(16).toString('hex')}`);
      await writeNewFile(temporary, JSON.stringify(next) + '\n');
      await owner.assert(); await unchanged(location, current);
      await rename(temporary, location.record);
      current = next; await location.assert();
    };
    await acquisition?.assertAdmission(); await publish(record);
    let phase: RuntimeRecord['phase'] = 'starting';
    return Object.freeze({ owner, location, previous, get record() { return current!; },
      async phase(next: 'ready' | 'closing') {
        if (phase === 'closing' || (next === 'ready' && phase !== 'starting')) throw profileUnavailable();
        if (next === 'ready') {
          await assertSocket(location, location.agent); await assertSocket(location, location.management);
        }
        phase = next; await publish(Object.freeze({ ...current!, phase: next }));
      },
    });
  } catch (error) { if (acquisition) return acquisition.failed(owner); owner.release(); throw error; }
}
export interface InstanceOwner {
  readonly owner: OwnerLease; readonly location: RuntimeLocation; readonly record: RuntimeRecord;
  readonly previous?: RuntimeRecord | undefined;
  phase(next: 'ready' | 'closing'): Promise<void>;
}
/** Separate stable startup inode serializes launch requests only; host never
 * waits for it. Bounded to 10 seconds, inside the original 60-second startup budget. */
export async function startupArbitration(location: RuntimeLocation, platform: PlatformPort,
  deadline: number): Promise<HeldLock> {
  const limit = Math.min(deadline, now() + 10000);
  do {
    await location.assert(); assertTime(limit);
    const held = platform.tryLock(join(location.leaf, 'startup.lock'));
    if (held) {
      try { held.assertIdentity(); await location.assert(); return held; }
      catch (error) { held.release(); throw error; }
    }
    await setTimeout(Math.min(25, Math.max(1, limit - now())));
  } while (now() < limit);
  throw profileUnavailable();
}
/** Never infer previous engine closure from an available owner flock. */
export const neverOpenedExit: PreviousExit = Object.freeze({ async assertExited(profile: ProfileSnapshot, previous: RuntimeRecord | undefined) {
  if (previous || await statOrAbsent(profile.paths.engine)) throw profileUnavailable();
} });
