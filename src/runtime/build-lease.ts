import { basename, dirname, join, resolve } from 'node:path';
import { lstat } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { directory, assertDirectory, privateFile, sameIdentity, identity, profileUnavailable } from '../profiles/paths.js';
import type { PlatformPort, HeldLock } from './platform.js';
import type { BuildSelection } from './selection.js';
import type { BuildGuard } from './start.js';
import { assertVerifiedHost, type VerifiedHost } from './authorities.js';
import { assertPlatform } from './platform.js';

export interface BuildLease extends BuildGuard {
  readonly selection: BuildSelection;
}
const buildDescriptions = new WeakMap<BuildLease, { platform: PlatformPort; held: HeldLock }>();
/** Only the original real description behind this module's lease is handed to
 * the exact native platform. There is no descriptor export by guard pathname.
 * Native custody, not the JS reference or callback, retains it through exit. */
export async function withBuildLockForCustody<T>(lease: BuildLease, platform: PlatformPort,
  handover: (held: HeldLock) => T): Promise<T> {
  const source = buildDescriptions.get(lease);
  if (!source || source.platform !== platform || typeof handover !== 'function') throw profileUnavailable();
  await lease.assert();
  if (buildDescriptions.get(lease) !== source) throw profileUnavailable();
  source.held.assertIdentity(); return handover(source.held);
}
/** Host-only continuous outer description. This is deliberately separate from
 * the Node starter's ordinary independently acquired shared guard below. The
 * native original cannot be released in a running main or by GC; the OS closes
 * it at actual process death, and armed custody owns its duplicated copies. */
export async function adoptHostBuildLease(host: VerifiedHost, platform: PlatformPort,
  requestPath: string, deadline: number): Promise<BuildLease> {
  assertPlatform(platform); assertVerifiedHost(host, deadline); await host.assertTrusted(deadline);
  const layout = host.identity.layout;
  const selection: BuildSelection = Object.freeze({ build: layout.build, directory: layout.buildRoot,
    guard: join(dirname(layout.buildRoot), '.uses', layout.build), explicit: true });
  const held = platform.adoptHostBuild(requestPath, selection.guard, layout.bundle);
  const lease: BuildLease = Object.freeze({ selection,
    async assert() {
      const current = held.assertIdentity(), expected = host.guardIdentity;
      if (current.device !== expected.device || current.inode !== expected.inode || current.uid !== expected.uid) throw profileUnavailable();
      // A later identity check gets an operation budget; it does not renew the
      // independently fixed launch-attempt admission expiry.
      await host.assertTrusted(performance.now() + 5000); held.assertIdentity();
    },
    release(): never { throw profileUnavailable(); },
  });
  buildDescriptions.set(lease, { platform, held }); await lease.assert(); return lease;
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
    release() { if (!released) { held.assertIdentity(); released = true; buildDescriptions.delete(lease); held.release(); } },
  });
  buildDescriptions.set(lease, { platform, held });
  try { await lease.assert(); return lease; } catch (error) { lease.release(); throw error; }
}
