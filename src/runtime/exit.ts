import { fileURLToPath } from 'node:url';
/** Independent production closure. No Electron import, JS clean writer, PID
 * signal, lock-as-exit shortcut or receipt-only force provider lives here. */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { join, basename, dirname, resolve } from 'node:path';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';
import { promisify } from 'node:util';
import { unavailable } from '../contracts/errors.js';
import { assertProfile, readJson, type ProfileSnapshot } from '../profiles/records.js';
import { directory, identity, privateFile, sameIdentity, statOrAbsent } from '../profiles/paths.js';
import { ownerLock, withOwnerLockForCustody, type OwnerLease } from '../profiles/locking.js';
import { acquireBuildLease, withBuildLockForCustody, type BuildLease } from './build-lease.js';
import { assertHostCloseContinuity, assertHostStartupContinuity, assertTrustedHost, assertVerifiedHostMetadata, verifyPackagedHost, type VerifiedHost } from './authorities.js';
import { assertPlatform, assertExitInspectionReceipt, type PlatformPort, type ExitInspectionReceipt, type PriorMarkerExpectation } from './platform.js';
import { withLaunchAttempt, type LaunchAttempt } from './process.js';
import { now, assertTime, runtimeLocation, type RuntimeRecord } from './instance.js';
import { buildLocation, claimedLayout, selectedLayout, type BuildSelection, type PackagedLayout } from './selection.js';
import type { HostPreviousExit } from './host-entry.js';
import type { ExitAuthority } from './lifecycle.js';
import type { EngineExitEvidence } from '../profiles/compatibility.js';

export interface ProductionExitAuthority extends ExitAuthority, HostPreviousExit, EngineExitEvidence {
  /** Only this poll treats protection contention/in-flight closure as pending.
   * It never certifies closure or invokes an external signal on uncertainty. */
  assertClosedUnderOwner(profile: ProfileSnapshot, original: RuntimeRecord | undefined, owner: OwnerLease, deadline: number): Promise<void>;
  tryClosed(profile: ProfileSnapshot, original: RuntimeRecord, deadline: number, closeHost?: VerifiedHost): Promise<boolean>;
  /** Retires only the independently verified exact closed reservation, retaining
   * its native closed-claim history outside profile and transient socket roots. */
  retire(profile: ProfileSnapshot, owner: OwnerLease, deadline: number): Promise<void>;
  /** Private native admission under the actual temporary Owner and selected
   * Build. The caller releases temporary Owner before LaunchServices. */
  reserve(profile: ProfileSnapshot, owner: OwnerLease, host: VerifiedHost, build: BuildLease,
    pending: LaunchAttempt, deadline: number): Promise<void>;
  /** Cancellation is not an exit receipt. A possible claimed original still
   * needs independent native terminal evidence and later original absence. */
  withdraw(profile: ProfileSnapshot, owner: OwnerLease, deadline: number): Promise<void>;
}
const authorities = new WeakSet<object>();
const stableCloseRuntimeFields = ['wire', 'profile', 'profileInstance', 'profilePathHash', 'instance', 'nonce', 'pid',
  'processStartId', 'build', 'contract', 'agentSocket', 'managementSocket'] as const satisfies readonly (keyof RuntimeRecord)[];
export function isProductionExitAuthority(value: unknown): value is ProductionExitAuthority {
  return typeof value === 'object' && value !== null && authorities.has(value);
}
export function assertProductionExitAuthority(value: ProductionExitAuthority): void {
  if (!authorities.has(value)) throw unavailable('profile');
}
export function closedCandidate(value: unknown, profile: {
  readonly paths: Readonly<{ root: string; state: string }>; readonly record: Readonly<{ instance: string }>;
}, hash: string): LaunchAttempt {
  const attempt = value as LaunchAttempt;
  // These checks authorize only selecting an old immutable signed package and
  // guard. The native reader still validates the COMPLETE shared record grammar
  // and exact actual current/head snapshot before trusting any exit evidence.
  if (!attempt || typeof attempt !== 'object' || attempt.format !== 1 || attempt.phase !== 'closed' ||
      attempt.profile !== profile.paths.root || attempt.profileInstance !== profile.record.instance || attempt.profilePathHash !== hash ||
      typeof attempt.buildRoot !== 'string' || typeof attempt.buildGuard !== 'string' ||
      attempt.buildGuard !== buildLocation(attempt.build, attempt.buildRoot)?.guard ||
      !/^req_[A-Za-z0-9_-]{22}$/.test(attempt.request) || !attempt.terminal ||
      ![attempt.sourceDigest, attempt.productDigest, attempt.candidateDigest, attempt.terminal.digest].every(value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)))
    throw unavailable('profile');
  const prefix = join(profile.paths.state, 'exit-evidence', hash, attempt.request);
  if (![join(prefix, 'activation.json'), join(prefix, 'terminal.json'), join(prefix, 'unused.json')].includes(attempt.terminal.path)) throw unavailable('profile');
  claimedLayout(attempt); return attempt;
}

const diskImage = promisify(execFile);

/** Re-establish the previous immutable bundle at the path named by its real Claim.
 * The caller still proves the original native snapshot and policies before trusting it. */
export async function mountRetainedImage(layout: PackagedLayout, build: Pick<BuildLease, 'assert'>, platform: PlatformPort, deadline: number): Promise<void> {
  if (layout.scope !== 'installed' || await statOrAbsent(layout.bundle)) return;
  const guard = `${layout.guard}.mount`;
  privateFile(await lstat(guard));
  let mountGuard: ReturnType<PlatformPort['tryLock']>;
  do {
    assertTime(deadline);
    mountGuard = platform.tryLock(guard);
    if (!mountGuard) await setTimeout(Math.min(10, Math.max(1, deadline - now())));
  } while (!mountGuard);
  try {
    await build.assert(); mountGuard.assertIdentity();
    if (await statOrAbsent(layout.bundle)) return;
    const mount = dirname(layout.bundle), support = dirname(dirname(layout.guard));
    const point = await directory(mount);
    await directory(join(support, 'images'));
    await directory(join(support, 'releases'));
    const receipt = (await readJson(join(support, 'releases', `${layout.build}.json`), 4096)).value as Record<string, unknown>;
    if (receipt.format !== 1 || receipt.build !== layout.build || typeof receipt.imageSha256 !== 'string' ||
        !/^[0-9a-f]{64}$/.test(receipt.imageSha256)) throw unavailable('profile');
    const image = join(support, 'images', `${layout.build}.dmg`);
    const fd = await open(image, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const before = await fd.stat(); privateFile(before);
      if (before.size < 1 || before.size > 1073741824) throw unavailable('profile');
      const hash = createHash('sha256');
      for await (const bytes of fd.createReadStream({ autoClose: false })) { assertTime(deadline); hash.update(bytes); }
      const matches = async () => {
        const held = await fd.stat(), named = await lstat(image); privateFile(held); privateFile(named);
        return [held, named].every(stat => sameIdentity(identity(stat), identity(before)) && stat.size === before.size &&
          stat.mtimeMs === before.mtimeMs && stat.ctimeMs === before.ctimeMs);
      };
      if (hash.digest('hex') !== receipt.imageSha256 || !await matches() || (await readdir(mount)).length ||
          !sameIdentity(await directory(mount), point)) throw unavailable('profile');
      await build.assert(); mountGuard.assertIdentity(); assertTime(deadline);
      await diskImage('/usr/bin/hdiutil', ['attach', image, '-readonly', '-nokernel', '-mountpoint', mount,
        '-noautoopen', '-nobrowse', '-plist'], { timeout: Math.max(1, Math.floor(deadline - now())), maxBuffer: 1048576,
        env: { PATH: '/usr/bin:/bin' } });
      if (!await matches() || await realpath(layout.bundle) !== layout.bundle) throw unavailable('profile');
      await build.assert(); mountGuard.assertIdentity(); assertTime(deadline);
    } finally { await fd.close(); }
  } catch { throw unavailable('profile'); }
  finally { mountGuard.release(); }
}

/** Build selection is the current CLI location only. A previous instance's
 * signed package and original stable Build guard are always proved separately. */
export function createProductionExitAuthority(platform: PlatformPort, selection: BuildSelection, startingHost?: VerifiedHost): ProductionExitAuthority {
  assertPlatform(platform);
  type OldProof = { host: VerifiedHost; build: BuildLease };
  const priorProofs = new WeakMap<OwnerLease, Map<string, OldProof>>();
  const inspect = async (profile: ProfileSnapshot, previous: RuntimeRecord | undefined, owner: OwnerLease,
    mode: 'prior' | 'host' | 'full' | 'retire' | 'reserve' | 'withdraw', deadline: number, currentBuild?: BuildLease,
    pending?: LaunchAttempt, closeHost?: VerifiedHost): Promise<ExitInspectionReceipt> => {
    assertTime(deadline); await owner.assert(); await assertProfile(profile);
    if (owner.profile !== profile) throw unavailable('profile');
    const location = await runtimeLocation(profile, true); if (!location) throw unavailable('profile');
    const current = await withLaunchAttempt(profile, platform, deadline, transaction => transaction.current);
    // Pre-arm reads outside-profile proof only; marker inspection is explicitly
    // behind the actual native enrolled host capability in the separate mode.
    const actualMode = mode === 'prior' && current?.stage === 'retained' ? 'host' : mode;
    let candidate: LaunchAttempt | undefined, dataAttempt: LaunchAttempt | undefined;
    if (mode === 'withdraw') candidate = current;
    else if (current?.phase === 'closed') candidate = closedCandidate(current, profile, location.hash);
    else {
      const path = join(profile.paths.state, 'exit-evidence', location.hash, 'previous-claim.json');
      if (await statOrAbsent(path)) candidate = closedCandidate((await readJson(path, 16384)).value, profile, location.hash);
    }
    if (candidate?.terminal && basename(candidate.terminal.path) === 'unused.json') {
      // Selecting the old data Build is not accepting a certificate. Native
      // rereads the exact witness/digest and validates its direct binding and
      // full data-writer proof, actual marker and genuine independent guard.
      const receipt = (await readJson(candidate.terminal.path, 262144)).value as { priorDataClaim?: unknown };
      if (receipt.priorDataClaim !== null) dataAttempt = closedCandidate(receipt.priorDataClaim, profile, location.hash);
      if (dataAttempt && basename(dataAttempt.terminal!.path) === 'unused.json') throw unavailable('profile');
    }
    const release: BuildLease[] = [];
    const oldProof = async (attempt: LaunchAttempt): Promise<OldProof> => {
      const key = JSON.stringify(attempt), retained = priorProofs.get(owner)?.get(key);
      if (retained) {
        await retained.build.assert(); assertTime(deadline); return retained;
      }
      if (actualMode === 'host') throw unavailable('profile');
      const oldSelection: BuildSelection = Object.freeze({ build: attempt.build, directory: attempt.buildRoot,
        guard: attempt.buildGuard, explicit: true });
      const build = await acquireBuildLease(oldSelection, platform); release.push(build);
      const layout = claimedLayout(attempt), closing = attempt.runtime;
      if (closeHost && actualMode === 'full' && attempt === current && attempt === candidate &&
          attempt.stage === 'admitted' && previous?.phase === 'ready' && closing?.phase === 'closing' &&
          basename(attempt.terminal?.path ?? '') === 'activation.json' &&
          stableCloseRuntimeFields.every(key => closing[key] === previous[key]) &&
          closeHost.identity.layout.build === oldSelection.build && closeHost.identity.layout.buildRoot === oldSelection.directory &&
          closeHost.identity.layout.bundle === layout.bundle && closeHost.identity.layout.payload === layout.payload &&
          oldSelection.guard === closeHost.identity.layout.guard &&
          closeHost.policy.stateRoot === profile.paths.state && closeHost.signed.snapshotDigest === attempt.candidateDigest &&
          closeHost.identity.sourceDigest === attempt.sourceDigest && closeHost.identity.productDigest === attempt.productDigest) {
        const sameGuard = await withBuildLockForCustody(build, platform, held => {
          const actual = held.assertIdentity(), expected = closeHost.guardIdentity;
          return actual.device === expected.device && actual.inode === expected.inode && actual.uid === expected.uid;
        });
        const manifestURL = new URL('../native/manifest.js', import.meta.url).href;
        const manifest = await import(manifestURL) as typeof import('../native/manifest.js');
        if (sameGuard && manifest.assertRetainedReadOnlyStorage(closeHost.signed, deadline)) {
          await assertHostCloseContinuity(closeHost, deadline); await build.assert();
          return { host: closeHost, build };
        }
      }
      const matchesAttempt = (host: VerifiedHost) => host.policy.stateRoot === profile.paths.state &&
        host.signed.snapshotDigest === attempt.candidateDigest && host.identity.sourceDigest === attempt.sourceDigest &&
        host.identity.productDigest === attempt.productDigest;
      let host: VerifiedHost | undefined;
      if (startingHost && process.type === 'browser' && actualMode === 'prior') {
        assertVerifiedHostMetadata(startingHost, deadline);
        const currentLayout = startingHost.identity.layout;
        if (currentLayout.build === oldSelection.build && currentLayout.buildRoot === oldSelection.directory &&
            currentLayout.bundle === layout.bundle && currentLayout.payload === layout.payload &&
            oldSelection.guard === currentLayout.guard && matchesAttempt(startingHost)) {
          const sameGuard = await withBuildLockForCustody(build, platform, held => {
            const actual = held.assertIdentity(), expected = startingHost.guardIdentity;
            return actual.device === expected.device && actual.inode === expected.inode && actual.uid === expected.uid;
          });
          if (!sameGuard) throw unavailable('profile');
          const manifest = await import(new URL('../native/manifest.js', import.meta.url).href) as typeof import('../native/manifest.js');
          if (manifest.assertRetainedReadOnlyStorage(startingHost.signed, deadline)) {
            await assertHostStartupContinuity(startingHost, deadline, deadline);
            host = startingHost;
          }
        }
      }
      if (!host) {
        if (attempt.phase === 'closed') await mountRetainedImage(layout, build, platform, deadline);
        host = await verifyPackagedHost(oldSelection, layout.payload, deadline);
        if (!matchesAttempt(host)) throw unavailable('profile');
        await host.assertTrusted(deadline);
      }
      await build.assert();
      if (actualMode === 'prior') {
        const proofs = priorProofs.get(owner) ?? new Map<string, OldProof>(); proofs.set(key, { host, build }); priorProofs.set(owner, proofs);
        release.splice(release.indexOf(build), 1);
      }
      return { host, build };
    };
    try {
      const build = candidate ? (await oldProof(candidate)).build : currentBuild ?? await acquireBuildLease(selection, platform);
      if (!candidate && !currentBuild) release.push(build);
      const dataBuild = dataAttempt ? (await oldProof(dataAttempt)).build : undefined;
      const physicalLeaf = await realpath(location.leaf);
      const result = await withOwnerLockForCustody(owner, platform, heldOwner =>
        withBuildLockForCustody(build, platform, async heldBuild => {
          const invoke = (data?: import('./platform.js').HeldLock, next?: import('./platform.js').HeldLock) => platform.inspectExit(heldOwner, heldBuild, {
            format: 1, mode: actualMode, profile: profile.paths.root, profileInstance: profile.record.instance,
            profilePathHash: location.hash, runtimeLeaf: physicalLeaf, bundle: candidate ? claimedLayout(candidate).bundle :
              pending ? claimedLayout(pending).bundle : selectedLayout(build.selection, resolve(fileURLToPath(new URL('../../', import.meta.url)))).bundle,
            attempt: candidate ?? null, previous: previous ?? null, dataAttempt: dataAttempt ?? null, pending: pending ?? null,
          }, deadline, { ...(data ? { data } : {}), ...(next ? { next } : {}) });
          const withNext = (data?: import('./platform.js').HeldLock) => actualMode === 'reserve' && currentBuild ?
            withBuildLockForCustody(currentBuild, platform, next => invoke(data, next)) : invoke(data);
          return dataBuild ? withBuildLockForCustody(dataBuild, platform, data => withNext(data)) : withNext();
        }));
      assertExitInspectionReceipt(result); await owner.assert();
      for (const original of new Set([build, dataBuild, currentBuild])) if (original) await original.assert();
      await location.assert(); assertTime(deadline);
      if (actualMode === 'host') {
        const proofs = priorProofs.get(owner); priorProofs.delete(owner);
        for (const proof of proofs?.values() ?? []) release.push(proof.build);
      }
      return result;
    } finally { for (const build of new Set(release)) build.release(); }
  };
  const withOwner = async <T>(profile: ProfileSnapshot, supplied: OwnerLease | undefined, deadline: number,
    operation: (owner: OwnerLease) => Promise<T>): Promise<T> => {
    const owner = supplied ?? await ownerLock(profile, platform, false, deadline);
    if (!owner) throw unavailable('profile');
    try { await owner.assert(); return await operation(owner); }
    finally { if (!supplied) owner.release(); }
  };
  const authority: ProductionExitAuthority = Object.freeze({
    async assertExited(profile: ProfileSnapshot, previous: RuntimeRecord | undefined, owner?: OwnerLease) {
      const deadline = now() + 10000;
      // Host prior verification reads only independent outside-profile evidence;
      // actual marker comparison remains behind genuine Native enrollment.
      const mode = process.type === 'browser' ? 'prior' : 'full';
      await withOwner(profile, owner, deadline, held => inspect(profile, previous, held, mode, deadline));
    },
    async priorExpectation(profile: ProfileSnapshot, previous: RuntimeRecord | undefined,
      owner: OwnerLease, build: BuildLease, deadline: number): Promise<PriorMarkerExpectation> {
      const result = await inspect(profile, previous, owner, 'prior', deadline, build);
      return result.prior;
    },
    async assertCompleteExitAndFlush(profile: ProfileSnapshot) {
      const deadline = now() + 10000;
      await withOwner(profile, undefined, deadline, async held => {
        const result = await inspect(profile, undefined, held, 'full', deadline);
        if (!result.clean) throw unavailable('profile');
      });
    },
    async assertCensus(profile: ProfileSnapshot, original: RuntimeRecord, _group: readonly import('./platform.js').GroupProcess[]) {
      const deadline = now() + 10000;
      await withOwner(profile, undefined, deadline, held => inspect(profile, original, held, 'full', deadline));
    },
    async assertClosedUnderOwner(profile: ProfileSnapshot, original: RuntimeRecord | undefined, owner: OwnerLease, deadline: number) {
      await inspect(profile, original, owner, 'full', deadline);
    },
    async tryClosed(profile: ProfileSnapshot, original: RuntimeRecord, deadline: number, closeHost?: VerifiedHost) {
      assertTime(deadline);
      if (closeHost) assertVerifiedHostMetadata(closeHost, deadline);
      const owner = await ownerLock(profile, platform, false, deadline); if (!owner) return false;
      try { await inspect(profile, original, owner, 'full', deadline, undefined, undefined, closeHost); return true; }
      catch { assertTime(deadline); return false; }
      finally { owner.release(); }
    },
    async force(profile: ProfileSnapshot, original: RuntimeRecord, deadline: number) {
      // The actual native Close consumer, never this CLI, owns the already
      // armed +5/+8 enforcement. Join that exact outcome without an external
      // signal, synthetic monitor consent or a renewed grace period.
      while (now() < deadline) {
        if (await authority.tryClosed(profile, original, deadline)) return;
        await setTimeout(Math.min(10, Math.max(1, deadline - now())));
      }
      throw unavailable('profile');
    },
    async reserve(profile: ProfileSnapshot, owner: OwnerLease, host: VerifiedHost, build: BuildLease,
      pending: LaunchAttempt, deadline: number) {
      await assertTrustedHost(host, deadline); await build.assert();
      if (build.selection.directory !== host.identity.layout.buildRoot || pending.buildRoot !== build.selection.directory ||
          pending.candidateDigest !== host.signed.snapshotDigest || pending.sourceDigest !== host.identity.sourceDigest ||
          pending.productDigest !== host.identity.productDigest) throw unavailable('profile');
      await inspect(profile, undefined, owner, 'reserve', deadline, build, pending);
    },
    async withdraw(profile: ProfileSnapshot, owner: OwnerLease, deadline: number) {
      const current = await withLaunchAttempt(profile, platform, deadline, transaction => transaction.current);
      if (!current || current.phase === 'closed') return;
      if (current.stage !== 'untransferred' || !['pending', 'claimed', 'cancelled'].includes(current.phase)) throw unavailable('profile');
      await inspect(profile, undefined, owner, 'withdraw', deadline);
    },
    async retire(profile: ProfileSnapshot, owner: OwnerLease, deadline: number) {
      await inspect(profile, undefined, owner, 'retire', deadline);
    },
  });
  authorities.add(authority); return authority;
}
