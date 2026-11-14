import { performance } from 'node:perf_hooks';
import { setTimeout } from 'node:timers/promises';
import type { HeldLock, PlatformPort } from '../runtime/platform.js';
import { directory, assertDirectory, ensureRegistry, privateFile, statOrAbsent, identity, sameIdentity,
  profileUnavailable, type Identity } from './paths.js';
import { assertProfile, readProfile, type ProfileSnapshot } from './records.js';

export const lockDeadline = (): number => performance.now() + 10000;
export interface RegistryLease {
  readonly state: string; readonly platform: PlatformPort;
  assert(): Promise<void>; release(): void;
}
export interface OwnerLease {
  readonly profile: ProfileSnapshot;
  assert(): Promise<void>; release(): void;
}
async function acquire(platform: PlatformPort, path: string, deadline: number, wait: boolean): Promise<HeldLock | null> {
  do {
    if (performance.now() >= deadline) throw profileUnavailable();
    const held = platform.tryLock(path);
    if (held) { held.assertIdentity(); return held; }
    if (!wait) return null;
    await setTimeout(Math.min(25, Math.max(1, deadline - performance.now())));
  } while (performance.now() < deadline);
  throw profileUnavailable();
}
export async function registryLock(state: string, platform: PlatformPort, create = false,
  deadline = lockDeadline()): Promise<RegistryLease> {
  if (create) await ensureRegistry(state);
  const root = await directory(state), profiles = await directory(`${state}/profiles`);
  // Registry is the only stable lock that may be created outside staged publication.
  const held = await acquire(platform, `${state}/registry.lock`, deadline, true);
  if (!held) throw profileUnavailable();
  let released = false;
  const lease: RegistryLease = Object.freeze({ state, platform,
    async assert() {
      if (released) throw profileUnavailable();
      held.assertIdentity(); await assertDirectory(state, root); await assertDirectory(`${state}/profiles`, profiles);
    },
    release() { if (!released) { released = true; held.release(); } },
  });
  try { await lease.assert(); return lease; } catch (error) { lease.release(); throw error; }
}
/** Existing profile only; never creates/replaces owner.lock on an incomplete destination. */
export async function ownerLock(profile: ProfileSnapshot, platform: PlatformPort, wait = true,
  deadline = lockDeadline()): Promise<OwnerLease | null> {
  await assertProfile(profile);
  const stat = await statOrAbsent(profile.paths.owner);
  if (!stat) throw profileUnavailable();
  privateFile(stat);
  const held = await acquire(platform, profile.paths.owner, deadline, wait);
  if (!held) return null;
  let released = false;
  const expected: Identity = identity(stat);
  const lease: OwnerLease = Object.freeze({ profile,
    async assert() {
      if (released) throw profileUnavailable();
      const current = held.assertIdentity();
      if (current.device !== String(expected.device) || current.inode !== String(expected.inode)) throw profileUnavailable();
      await assertProfile(profile);
      const now = await statOrAbsent(profile.paths.owner);
      if (!now) throw profileUnavailable();
      privateFile(now);
      if (!sameIdentity(identity(now), expected)) throw profileUnavailable();
    },
    release() { if (!released) { released = true; held.release(); } },
  });
  try { await lease.assert(); return lease; } catch (error) { lease.release(); throw error; }
}
/** Startup uses the published lock only; callers retain it through all helper exit/flush. */
export async function lockExisting(profile: ProfileSnapshot, platform: PlatformPort,
  deadline = lockDeadline()): Promise<OwnerLease> {
  const held = await ownerLock(profile, platform, true, deadline);
  if (!held) throw profileUnavailable();
  return held;
}
export async function revalidateSelected(lease: OwnerLease): Promise<ProfileSnapshot> {
  await lease.assert(); return readProfile(lease.profile.paths);
}
