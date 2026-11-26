import { lstat, opendir, rm } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { BrowserFailure } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import type { ProfilePort } from '../runtime/ports.js';
import { loadPlatform, type PlatformPort } from '../runtime/platform.js';
import { originalAlive, readRuntime, runtimeLocation } from '../runtime/instance.js';
import { createProfile, managedProfiles } from './create.js';
import { registryLock, ownerLock, lockDeadline, type OwnerLease, type RegistryLease } from './locking.js';
import { readProfile, assertProfile, readJson, type ProfileSnapshot } from './records.js';
import { profilePaths, profileId, profileUnavailable, stateDirectory, registryExists, statOrAbsent,
  privateFile, ownerUid, assertDirectory, sameIdentity, identity, syncDirectory } from './paths.js';

/** ABR-3 supplies verified runtime/peer/process-tree inspection. A boolean from a
 * runtime record alone is not evidence. running must revalidate after awaits. */
export interface ProfileRuntimePort {
  running(profile: ProfileSnapshot, ownerAvailable: boolean, owner?: OwnerLease, registry?: RegistryLease): Promise<boolean>;
  /** Caller retains owner + registry; confirm all previous owned helpers are gone. */
  assertClosed(profile: ProfileSnapshot, owner?: OwnerLease, registry?: RegistryLease, purpose?: 'remove'): Promise<void>;
  /** Production coordinates exact runtime archive and the actual profile detach
   * under the same genuine Claim/Owner/Registry. Uncertainty retains guards. */
  detach?(profile: ProfileSnapshot, owner: OwnerLease, registry: RegistryLease, retired: string): Promise<'detached' | 'uncertain'>;
}
/** Read-only presentation state. Startup and retirement still need their own
 * proof and must never treat this observation as evidence of a safe exit. */
export async function hasRetainedProfileLock(profile: ProfileSnapshot, platform: PlatformPort): Promise<boolean> {
  const owner = await ownerLock(profile, platform, false);
  if (owner) {
    owner.release();
    return false;
  }
  const location = await runtimeLocation(profile);
  const record = location && await readRuntime(location);
  return Boolean(record && !originalAlive(record, platform));
}
async function noRuntimeFootprint(profile: ProfileSnapshot): Promise<void> {
  // Listing does not read engine.json, cookies, storage or page content.
  if (await statOrAbsent(profile.paths.engine)) throw profileUnavailable();
  const parent = `/tmp/ab-${ownerUid()}`;
  const hash = createHash('sha256').update(profile.paths.root, 'utf8').digest('hex');
  const parentStat = await statOrAbsent(parent);
  if (parentStat) {
    if (!parentStat.isDirectory() || parentStat.uid !== ownerUid() || (parentStat.mode & 0o7777) !== 0o700)
      throw profileUnavailable();
    // Any existing runtime leaf needs ABR-3's complete verified process authority.
    if (await statOrAbsent(join(parent, hash.slice(0, 32)))) throw profileUnavailable();
    if (!sameIdentity(identity(await lstat(parent)), identity(parentStat))) throw profileUnavailable();
  }
}
/** The foundation candidate has no host. Only provably never-opened profiles can
 * be reported closed without the later runtime verifier. Never guess on contention. */
const unopenedRuntime: ProfileRuntimePort = Object.freeze({
  async running(profile: ProfileSnapshot, ownerAvailable: boolean) {
    if (!ownerAvailable) throw profileUnavailable();
    await noRuntimeFootprint(profile); return false;
  },
  assertClosed: noRuntimeFootprint,
});
async function validateRemovalMarker(profile: ProfileSnapshot): Promise<void> {
  if (!await statOrAbsent(profile.paths.engine)) return;
  const read = await readJson(profile.paths.engine);
  if (!validator('profile2.EngineMarker')(read.value) || read.value.profileInstance !== profile.record.instance)
    throw profileUnavailable();
}
async function existingRegistry(state: string, platform: PlatformPort, deadline: number) {
  const stat = await statOrAbsent(join(state, 'registry.lock'));
  if (!stat) throw profileUnavailable();
  privateFile(stat);
  return registryLock(state, platform, false, deadline);
}
async function selectedRecords(registry: RegistryLease, id: string | undefined): Promise<readonly ProfileSnapshot[]> {
  if (id === undefined) return managedProfiles(registry);
  const paths = profilePaths(id, registry.state);
  await registry.assert();
  const records = await statOrAbsent(paths.root) ? [await readProfile(paths)] : [];
  await registry.assert();
  return records;
}
const retainedRemovals = new Set<{ owner: OwnerLease; registry: RegistryLease }>();
export function createProfileService(options: {
  state?: string; platform?: () => PlatformPort; runtime?: ProfileRuntimePort;
} = {}): ProfilePort {
  const state = options.state ?? stateDirectory();
  const platform = options.platform ?? loadPlatform, runtime = options.runtime ?? unopenedRuntime;
  const protect = async <T>(operation: () => Promise<T>): Promise<T> => {
    try { return await operation(); } catch (error) {
      if (error instanceof BrowserFailure) throw error;
      throw profileUnavailable();
    }
  };
  return Object.freeze({
    create: (id: string, request?: string) => protect(() => createProfile(id, request, platform(), state)),
    list: (id?: string) => protect(async () => {
      if (!await registryExists(state)) return { profiles: [] };
      const os = platform(), registry = await existingRegistry(state, os, lockDeadline());
      try {
        const records = await selectedRecords(registry, id), profiles = [];
        for (const profile of records) {
          const owner = await ownerLock(profile, os, false);
          try {
            let running: boolean;
            try {
              running = await runtime.running(profile, owner !== null, owner ?? undefined, registry);
            } catch (error) {
              if (owner || !(error instanceof BrowserFailure) || error.detail.code !== 'profile_unavailable' ||
                  !await hasRetainedProfileLock(profile, os)) throw error;
              await registry.assert(); await assertProfile(profile);
              // Retained custody still blocks admission. This row only reports that
              // the recorded Browser host is absent.
              profiles.push({ ...profile.record, running: false });
              continue;
            }
            // A verified running host cannot coexist with our exclusive owner lock.
            if (owner && running) throw profileUnavailable();
            if (!owner && !running) throw profileUnavailable();
            await registry.assert(); await assertProfile(profile);
            if (owner) await owner.assert();
            profiles.push({ ...profile.record, running });
          } finally { owner?.release(); }
        }
        await registry.assert();
        return { profiles };
      } finally { registry.release(); }
    }),
    remove: (id: string) => protect(async () => {
      profileId(id, true);
      const selected = await readProfile(profilePaths(id, state));
      await validateRemovalMarker(selected);
      const os = platform(), registry = await existingRegistry(state, os, lockDeadline());
      let uncertain = false;
      try {
        await assertProfile(selected);
        const owner = await ownerLock(selected, os, false);
        if (!owner) throw profileUnavailable();
        try {
          await validateRemovalMarker(selected);
          await runtime.assertClosed(selected, owner, registry, 'remove');
          await registry.assert(); await owner.assert();
          const lockStat = await lstat(selected.paths.owner); privateFile(lockStat);
          const retired = join(selected.paths.profiles, `.deleting-${randomBytes(16).toString('hex')}`);
          // Detach the published name first. Waiting starters must revalidate the
          // original pathname/instance and refuse; no removed profile is reopened.
          if (runtime.detach) {
            const result = await runtime.detach(selected, owner, registry, retired);
            if (result !== 'detached') {
              uncertain = true; retainedRemovals.add({ owner, registry }); throw profileUnavailable();
            }
          } else os.publishDirectory(selected.paths.root, retired);
          await syncDirectory(selected.paths.profiles);
          await assertDirectory(retired, selected.rootIdentity);
          const retiredLock = await lstat(join(retired, 'owner.lock')); privateFile(retiredLock);
          if (!sameIdentity(identity(lockStat), identity(retiredLock))) throw profileUnavailable();
          const entries = await opendir(retired);
          for await (const entry of entries) {
            if (entry.name === 'owner.lock') continue;
            await registry.assert(); await assertDirectory(retired, selected.rootIdentity);
            await rm(join(retired, entry.name), { recursive: true });
          }
          // Keep the empty owner-lock inode in a private tombstone: an opener may
          // still retain it. Never unlink/recreate a shared arbitration inode.
          await syncDirectory(retired); await syncDirectory(selected.paths.profiles);
          await registry.assert(); await assertDirectory(retired, selected.rootIdentity);
          return { profile: id, dataRemoved: true as const };
        } finally { if (!uncertain) owner.release(); }
      } finally { if (!uncertain) registry.release(); }
    }),
  });
}
