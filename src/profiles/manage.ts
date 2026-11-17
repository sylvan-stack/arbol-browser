import { constants } from 'node:fs';
import { lstat, open, opendir, rm } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { isatty } from 'node:tty';
import { BrowserFailure } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import type { ProfilePort, Stdio } from '../runtime/ports.js';
import { loadPlatform, type PlatformPort } from '../runtime/platform.js';
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
function confirmationRefused(): BrowserFailure {
  return new BrowserFailure({ code: 'control_refused', message: 'Profile removal requires typed terminal confirmation.',
    retryable: false, remedy: 'Use profiles remove with --delete-data in an interactive terminal.' }, 5);
}
async function confirmRemoval(id: string, _io: Stdio): Promise<void> {
  // /dev/tty requires a controlling terminal. A pipe, injected stdin or MCP body
  // cannot supply this confirmation. Nothing is ever written to JSON stdout.
  let tty;
  try { tty = await open('/dev/tty', constants.O_RDWR | constants.O_NOCTTY); }
  catch { throw confirmationRefused(); }
  try {
    if (!isatty(tty.fd)) throw confirmationRefused();
    await tty.writeFile(`Permanently delete profile ${id} and all its browser data. Type ${id} to confirm: `);
    const bytes = Buffer.alloc(67);
    let length = 0;
    while (length < bytes.length) {
      const read = await tty.read(bytes, length, bytes.length - length, null);
      if (!read.bytesRead) throw confirmationRefused();
      length += read.bytesRead;
      if (bytes.subarray(0, length).includes(10)) break;
    }
    const value = bytes.subarray(0, length).toString('utf8');
    if (value !== `${id}\n` && value !== `${id}\r\n`) throw confirmationRefused();
  } catch { throw confirmationRefused(); }
  finally { await tty.close(); }
}
async function validateRemovalMarker(profile: ProfileSnapshot): Promise<void> {
  if (!await statOrAbsent(profile.paths.engine)) return;
  const read = await readJson(profile.paths.engine);
  if (!validator('profile.EngineMarker')(read.value) || read.value.profileInstance !== profile.record.instance)
    throw profileUnavailable();
}
async function existingRegistry(state: string, platform: PlatformPort, deadline: number) {
  const stat = await statOrAbsent(join(state, 'registry.lock'));
  if (!stat) throw profileUnavailable();
  privateFile(stat);
  return registryLock(state, platform, false, deadline);
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
    list: () => protect(async () => {
      if (!await registryExists(state)) return { profiles: [] };
      const os = platform(), registry = await existingRegistry(state, os, lockDeadline());
      try {
        const records = await managedProfiles(registry), profiles = [];
        for (const profile of records) {
          const owner = await ownerLock(profile, os, false);
          try {
            const running = await runtime.running(profile, owner !== null, owner ?? undefined, registry);
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
    remove: (id: string, io: Stdio) => protect(async () => {
      profileId(id, true);
      const selected = await readProfile(profilePaths(id, state));
      await validateRemovalMarker(selected);
      await confirmRemoval(id, io);
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
