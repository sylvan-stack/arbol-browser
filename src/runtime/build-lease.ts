import { basename, dirname, join, resolve } from 'node:path';
import { lstat } from 'node:fs/promises';
import { directory, assertDirectory, privateFile, sameIdentity, identity, profileUnavailable } from '../profiles/paths.js';
import type { PlatformPort } from './platform.js';
import type { BuildSelection } from './selection.js';
import type { BuildGuard } from './start.js';

export interface BuildLease extends BuildGuard {
  readonly selection: BuildSelection;
}
/** Reacquire the launcher's exact stable .uses/<hex> shared kernel flock.
 * This is Build-use protection, never publisher/native/engine compatibility
 * authority. Direct incomplete candidates have no production guard and refuse.
 * No inherited FD (through LaunchServices, shell or Electron) is assumed.
 * Browser-specific prune/install policy is still ABR-24's integration work. */
export async function acquireBuildLease(input: BuildSelection, platform: PlatformPort): Promise<BuildLease> {
  const selection = Object.freeze({ ...input });
  if (!selection.guard || basename(selection.directory) !== selection.build ||
      basename(dirname(selection.directory)) !== 'arbol-browser' ||
      resolve(selection.directory) !== selection.directory ||
      selection.guard !== join(dirname(selection.directory), '.uses', selection.build)) throw profileUnavailable();
  const component = dirname(selection.directory), uses = dirname(selection.guard);
  const componentIdentity = await directory(component, false);
  const buildIdentity = await directory(selection.directory, false), usesIdentity = await directory(uses);
  const before = await lstat(selection.guard); privateFile(before);
  const expected = identity(before);
  const held = platform.trySharedLock(selection.guard);
  if (!held) throw profileUnavailable(); // pruning has an exclusive guard
  let released = false;
  const lease: BuildLease = Object.freeze({ selection,
    async assert() {
      if (released) throw profileUnavailable();
      const native = held.assertIdentity();
      if (native.device !== String(expected.device) || native.inode !== String(expected.inode)) throw profileUnavailable();
      await assertDirectory(uses, usesIdentity);
      // Build/component payload directories need not be private, but every
      // ancestor must be canonical, owner/root-owned and non-writable by others.
      if (!sameIdentity(await directory(component, false), componentIdentity) ||
          !sameIdentity(await directory(selection.directory, false), buildIdentity)) throw profileUnavailable();
      const current = await lstat(selection.guard); privateFile(current);
      if (!sameIdentity(identity(current), expected)) throw profileUnavailable();
      held.assertIdentity();
    },
    /** Only before engine use, after verified host-ready (starter), or after
     * complete original-main/helper exit and flush. No timeout/finally release. */
    release() { if (!released) { held.assertIdentity(); released = true; held.release(); } },
  });
  try { await lease.assert(); return lease; } catch (error) { lease.release(); throw error; }
}
