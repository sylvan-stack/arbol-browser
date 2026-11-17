/** Independent production closure. No Electron import, JS clean writer, PID
 * signal, lock-as-exit shortcut or receipt-only force provider lives here. */
import { join, dirname, basename, resolve } from 'node:path';
import { realpath } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';
import { unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { assertProfile, readJson, type ProfileSnapshot } from '../profiles/records.js';
import { statOrAbsent } from '../profiles/paths.js';
import { ownerLock, withOwnerLockForCustody, type OwnerLease } from '../profiles/locking.js';
import { acquireBuildLease, withBuildLockForCustody, type BuildLease } from './build-lease.js';
import { verifyPackagedHost, type VerifiedHost } from './authorities.js';
import { assertPlatform, assertExitInspectionReceipt, type PlatformPort, type ExitInspectionReceipt, type PriorMarkerExpectation } from './platform.js';
import { withLaunchAttempt, type LaunchAttempt } from './process.js';
import { now, assertTime, runtimeLocation, type RuntimeRecord } from './instance.js';
import type { BuildSelection } from './selection.js';
import type { HostPreviousExit } from './host-entry.js';
import type { ExitAuthority } from './lifecycle.js';
import type { EngineExitEvidence } from '../profiles/compatibility.js';

export interface ProductionExitAuthority extends ExitAuthority, HostPreviousExit, EngineExitEvidence {
  /** Only this poll treats protection contention/in-flight closure as pending.
   * It never certifies closure or invokes an external signal on uncertainty. */
  tryClosed(profile: ProfileSnapshot, original: RuntimeRecord, deadline: number): Promise<boolean>;
  /** Retires only the independently verified exact closed reservation, retaining
   * its native closed-claim history outside profile and transient socket roots. */
  retire(profile: ProfileSnapshot, owner: OwnerLease, deadline: number): Promise<void>;
}
const authorities = new WeakSet<object>();
export function assertProductionExitAuthority(value: ProductionExitAuthority): void {
  if (!authorities.has(value)) throw unavailable('profile');
}
function closedCandidate(value: unknown, profile: ProfileSnapshot, hash: string): LaunchAttempt {
  const attempt = value as LaunchAttempt;
  // These checks authorize only selecting an old immutable signed package and
  // guard. The native reader still validates the COMPLETE shared record grammar
  // and exact actual current/head snapshot before trusting any exit evidence.
  if (!attempt || typeof attempt !== 'object' || attempt.format !== 1 || attempt.phase !== 'closed' ||
      attempt.profile !== profile.paths.root || attempt.profileInstance !== profile.record.instance || attempt.profilePathHash !== hash ||
      !validator('browser.Build')(attempt.build) || typeof attempt.buildRoot !== 'string' || resolve(attempt.buildRoot) !== attempt.buildRoot ||
      basename(attempt.buildRoot) !== attempt.build || basename(dirname(attempt.buildRoot)) !== 'arbol-browser' ||
      attempt.buildGuard !== join(dirname(attempt.buildRoot), '.uses', attempt.build) ||
      !/^req_[A-Za-z0-9_-]{22}$/.test(attempt.request) || !attempt.terminal ||
      ![attempt.sourceDigest, attempt.productDigest, attempt.candidateDigest, attempt.terminal.digest].every(value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)))
    throw unavailable('profile');
  const prefix = join(profile.paths.state, 'exit-evidence', hash, attempt.request);
  if (![join(prefix, 'activation.json'), join(prefix, 'terminal.json')].includes(attempt.terminal.path)) throw unavailable('profile');
  return attempt;
}
/** Build selection is the current CLI location only. A previous instance's
 * signed package and original stable Build guard are always proved separately. */
export function createProductionExitAuthority(platform: PlatformPort, selection: BuildSelection): ProductionExitAuthority {
  assertPlatform(platform);
  const priorProofs = new WeakMap<OwnerLease, { candidate: string; host: VerifiedHost; build: BuildLease }>();
  const inspect = async (profile: ProfileSnapshot, previous: RuntimeRecord | undefined, owner: OwnerLease,
    mode: 'prior' | 'full' | 'retire', deadline: number, currentBuild?: BuildLease): Promise<ExitInspectionReceipt> => {
    assertTime(deadline); await owner.assert(); await assertProfile(profile);
    if (owner.profile !== profile) throw unavailable('profile');
    const location = await runtimeLocation(profile, true); if (!location) throw unavailable('profile');
    const current = await withLaunchAttempt(profile, platform, deadline, transaction => transaction.current);
    let candidate: LaunchAttempt | undefined;
    if (current?.phase === 'closed') candidate = closedCandidate(current, profile, location.hash);
    else {
      const path = join(profile.paths.state, 'exit-evidence', location.hash, 'previous-claim.json');
      if (await statOrAbsent(path)) candidate = closedCandidate((await readJson(path, 16384)).value, profile, location.hash);
    }
    let build: BuildLease | undefined, release = false;
    try {
      if (candidate) {
        const oldSelection: BuildSelection = Object.freeze({ build: candidate.build, directory: candidate.buildRoot,
          guard: candidate.buildGuard, explicit: true });
        const retained = mode === 'prior' ? priorProofs.get(owner) : undefined;
        if (retained) {
          if (retained.candidate !== JSON.stringify(candidate)) throw unavailable('profile');
          if (retained.host.signed.snapshotDigest !== candidate.candidateDigest ||
              retained.host.identity.sourceDigest !== candidate.sourceDigest || retained.host.identity.productDigest !== candidate.productDigest ||
              retained.host.policy.stateRoot !== profile.paths.state) throw unavailable('profile');
          assertTime(deadline); build = retained.build;
          // Its exact old guard has remained held since genuine pre-arm trust.
          // Native rechecks signature/claim/receipt/current bytes off-thread;
          // no post-arm codesign child or synchronous whole-payload hash.
          await build.assert();
        } else {
          if (mode === 'prior' && current && current.stage !== 'untransferred') throw unavailable('profile');
          build = await acquireBuildLease(oldSelection, platform); release = true;
          const payload = join(candidate.buildRoot, 'ArbolBrowser.app/Contents/Resources/browser');
          const oldHost = await verifyPackagedHost(oldSelection, payload, deadline);
          if (oldHost.policy.stateRoot !== profile.paths.state || oldHost.signed.snapshotDigest !== candidate.candidateDigest ||
              oldHost.identity.sourceDigest !== candidate.sourceDigest || oldHost.identity.productDigest !== candidate.productDigest)
            throw unavailable('profile');
          await oldHost.assertTrusted(deadline); await build.assert();
          if (mode === 'prior') {
            priorProofs.set(owner, { candidate: JSON.stringify(candidate), host: oldHost, build }); release = false;
          }
        }
      } else {
        if (previous || mode === 'retire') throw unavailable('profile');
        build = currentBuild ?? await acquireBuildLease(selection, platform); release = !currentBuild;
      }
      const actualBuild = build, physicalLeaf = await realpath(location.leaf);
      const result = await withOwnerLockForCustody(owner, platform, heldOwner =>
        withBuildLockForCustody(actualBuild, platform, heldBuild => platform.inspectExit(heldOwner, heldBuild, {
          format: 1, mode, profile: profile.paths.root, profileInstance: profile.record.instance,
          profilePathHash: location.hash, runtimeLeaf: physicalLeaf, bundle: join(actualBuild.selection.directory, 'ArbolBrowser.app'),
          attempt: candidate ?? null, previous: previous ?? null,
        }, deadline)));
      assertExitInspectionReceipt(result); await owner.assert(); await actualBuild.assert(); await location.assert(); assertTime(deadline);
      if (mode === 'prior' && current?.stage === 'retained' && priorProofs.get(owner)?.build === actualBuild) {
        priorProofs.delete(owner); release = true;
      }
      return result;
    } finally { if (release) build?.release(); }
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
    async tryClosed(profile: ProfileSnapshot, original: RuntimeRecord, deadline: number) {
      assertTime(deadline);
      const owner = await ownerLock(profile, platform, false, deadline); if (!owner) return false;
      try { await inspect(profile, original, owner, 'full', deadline); return true; }
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
    async retire(profile: ProfileSnapshot, owner: OwnerLease, deadline: number) {
      await inspect(profile, undefined, owner, 'retire', deadline);
    },
  });
  authorities.add(authority); return authority;
}
