/** Private native-backed launch transactions. Nothing in this file supplies a
 * simulated host, watchdog, engine-exit certificate or successful tool effect. */
import { randomBytes } from 'node:crypto';
import { constants, openSync, closeSync, fstatSync, lstatSync, readSync, realpathSync, mkdirSync, renameSync, fsyncSync, rmdirSync, type BigIntStats } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout } from 'node:timers/promises';
import { unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { assertProfile, type ProfileSnapshot } from '../profiles/records.js';
import { assertPlatform, type HeldLock, type PlatformPort, type ProcessProvenance } from './platform.js';
import { noteOpenCommand, type OpenCommandObservation, assertHostCloseContinuity, assertHostStartupContinuity,
  assertHostStartupSnapshot, assertVerifiedHostMetadata, type VerifiedHost } from './authorities.js';
import { assertTime, now, runtimeLocation, type RuntimeLocation, type RuntimeRecord } from './instance.js';
import { createStarter, type LaunchAttemptPort, type LaunchWithdrawal } from './start.js';
import type { ProcessIntegration } from './lifecycle.js';
import { claimedLayout, selectedLayout, type BuildSelection } from './selection.js';
import { ownerLock, withOwnerLockForCustody, type OwnerLease, type RegistryLease } from '../profiles/locking.js';
import { acquireBuildLease, withBuildLockForCustody, type BuildLease } from './build-lease.js';
import { createProductionExitAuthority, assertProductionExitAuthority, type ProductionExitAuthority } from './exit.js';

export interface LaunchAttempt {
  readonly format: 1; readonly request: string; readonly nonce: string;
  readonly profile: string; readonly profileInstance: string; readonly profilePathHash: string;
  readonly build: string; readonly buildRoot: string; readonly buildGuard: string;
  readonly sourceDigest: string; readonly productDigest: string; readonly candidateDigest: string;
  readonly expires: number; readonly starter: ProcessProvenance;
  readonly phase: 'pending' | 'claimed' | 'ready' | 'closing' | 'cancelled' | 'closed';
  readonly stage: 'untransferred' | 'transferring' | 'retained' | 'mutation-started' | 'marker-bound' | 'admitted';
  readonly bootstrap: ProcessProvenance | null; readonly engine: ProcessProvenance | null;
  readonly runtime: RuntimeRecord | null;
  readonly terminal: Readonly<{ path: string; digest: string }> | null;
}
export interface AttemptTransaction {
  /** A record for an old profile instance may be read for genuine retirement
   * verification. It never grants adoption or permission to remove anything. */
  readonly current: LaunchAttempt | undefined;
  replace(next: LaunchAttempt): void;
}
function frozen<T>(value: T): T {
  if (value && typeof value === 'object') { for (const item of Object.values(value)) frozen(item); Object.freeze(value); }
  return value;
}
function parseAttempt(raw: string, location: RuntimeLocation): LaunchAttempt {
  const value = JSON.parse(raw) as LaunchAttempt;
  // Native has already checked the complete shared grammar, numeric domains,
  // self-consistent path hash and process fields. Bind its result to this exact
  // actual managed profile location before exposing even a read-only snapshot.
  if (!value || value.format !== 1 || value.profile !== location.profile.paths.root || value.profilePathHash !== location.hash)
    throw unavailable('profile');
  claimedLayout(value); return frozen(value);
}
// Only archiveRemovedRuntime can mint this private post-detach disposition.
// It cannot be requested through a transaction callback or a structural flag.
const detachResults = new WeakMap<object, 'detached' | 'uncertain'>();
function detachResult(kind: 'detached' | 'uncertain'): object {
  const value = Object.freeze({}); detachResults.set(value, kind); return value;
}
/** Separate short claim.lock, never the startup arbitration retained by a
 * starter. No owner/Build protection is acquired or released in this helper.
 * Every capability closes before yielding back to its caller. Async callbacks
 * are refused and their later continuations cannot mutate the transaction. */
export async function withLaunchAttempt<T>(profile: ProfileSnapshot, platform: PlatformPort, deadline: number,
  operation: (transaction: AttemptTransaction) => T): Promise<T> {
  assertPlatform(platform); assertTime(deadline); await assertProfile(profile);
  const location = await runtimeLocation(profile, true); if (!location) throw unavailable('profile');
  let held: HeldLock | undefined, active = false;
  try {
    const contention = Math.min(deadline, now() + 10000);
    while (!held) {
      assertTime(contention); await location.assert();
      held = platform.tryLock(join(location.leaf, 'claim.lock')) ?? undefined;
      if (!held) await setTimeout(Math.min(25, Math.max(1, contention - now())));
    }
    assertTime(deadline); location.assertSync(); held.assertIdentity();
    let raw = platform.readLaunchAttempt(held);
    let current = raw === null ? undefined : parseAttempt(raw, location);
    active = true;
    const assertCurrent = () => { if (!active) throw unavailable('profile'); assertTime(deadline); held!.assertIdentity(); };
    const transaction: AttemptTransaction = Object.freeze({
      get current() { assertCurrent(); return current; },
      replace(next: LaunchAttempt) {
        assertCurrent();
        if (next.profile !== profile.paths.root || next.profileInstance !== profile.record.instance || next.profilePathHash !== location.hash)
          throw unavailable('profile');
        const encoded = JSON.stringify(next) + '\n';
        platform.writeLaunchAttempt(held!, raw, encoded);
        raw = encoded; current = parseAttempt(encoded, location); assertCurrent();
      },
    });
    const result = operation(transaction); active = false;
    if (result && typeof (result as { then?: unknown }).then === 'function') throw unavailable('profile');
    if (result && typeof result === 'object' && detachResults.has(result)) {
      // The actual profile name is now intentionally detached. Rechecking it
      // as a live profile would turn a known commit into a fictitious failure.
      try { held.assertIdentity(); assertTime(deadline); }
      catch { detachResults.set(result, 'uncertain'); }
      return result;
    }
    location.assertSync(); held.assertIdentity(); assertTime(deadline); return result;
  } finally { active = false; held?.release(); }
}

/** Construct only a pending intent. The caller must reserve it under the short
 * native transaction and independently verify any previous claimed/closed family;
 * phase labels and an available lock supply no PreviousExit authority. */
export async function pendingLaunchAttempt(profile: ProfileSnapshot, host: VerifiedHost, platform: PlatformPort,
  request: string, deadline: number): Promise<LaunchAttempt> {
  assertPlatform(platform); assertVerifiedHostMetadata(host, deadline); await assertProfile(profile);
  if (!/^req_[A-Za-z0-9_-]{22}$/.test(request) ||
      profile.paths.root !== join(host.policy.stateRoot, 'profiles', profile.record.id)) throw unavailable('profile');
  const location = await runtimeLocation(profile, true); if (!location) throw unavailable('profile');
  const starter = platform.processProvenance(process.pid);
  if (!starter || starter.executable !== host.identity.layout.engine) throw unavailable('browser');
  // Sampling native first and the caller clock second is conservative. Sleep
  // can shorten native continuous-time admission, never extend the caller bound.
  const nativeNow = platform.continuousTime(), sampled = now(); assertTime(deadline);
  const expires = nativeNow + Math.min(60000, deadline - sampled);
  return frozen({ format: 1, request, nonce: randomBytes(32).toString('base64url'),
    profile: profile.paths.root, profileInstance: profile.record.instance, profilePathHash: location.hash,
    build: host.identity.layout.build, buildRoot: host.identity.layout.buildRoot,
    buildGuard: host.identity.layout.guard,
    sourceDigest: host.identity.sourceDigest, productDigest: host.identity.productDigest,
    candidateDigest: host.signed.snapshotDigest, expires, starter, phase: 'pending', stage: 'untransferred',
    bootstrap: null, engine: null, runtime: null, terminal: null });
}
/** Cancellation records permanent loss of this one attempt only. It neither
 * withdraws a submitted NSWorkspace notification nor claims custody/exit. */
export async function cancelLaunchAttempt(profile: ProfileSnapshot, platform: PlatformPort,
  request: string, nonce: string, deadline: number): Promise<LaunchWithdrawal> {
  return withLaunchAttempt(profile, platform, deadline, transaction => {
    const current = transaction.current;
    if (!current || current.request !== request) return 'absent';
    if (current.nonce !== nonce || current.profileInstance !== profile.record.instance)
      throw unavailable('profile');
    if (current.phase === 'ready' || current.phase === 'closing' || current.stage === 'admitted') return 'committed';
    if (current.phase === 'pending' || current.phase === 'claimed') {
      transaction.replace(frozen({ ...current, phase: 'cancelled' }));
    }
    return 'withdrawn';
  });
}

/** Independent post-exec binding, after native one-use Build adoption. The
 * returned snapshot grants no data/session access; custody and the serialized
 * mutation boundary must still be established by the pre-ready assembly. */
export async function claimedHostAttempt(profile: ProfileSnapshot, host: VerifiedHost, platform: PlatformPort,
  request: string, deadline: number): Promise<LaunchAttempt> {
  assertPlatform(platform); assertVerifiedHostMetadata(host, deadline); await assertProfile(profile);
  return withLaunchAttempt(profile, platform, deadline, transaction => {
    const current = transaction.current, self = platform.processProvenance(process.pid), layout = host.identity.layout;
    if (!current || current.request !== request || current.profileInstance !== profile.record.instance ||
        current.phase !== 'claimed' || current.stage !== 'untransferred' || current.expires <= platform.continuousTime() ||
        current.build !== layout.build || current.buildRoot !== layout.buildRoot ||
        current.buildGuard !== layout.guard ||
        current.sourceDigest !== host.identity.sourceDigest || current.productDigest !== host.identity.productDigest ||
        current.candidateDigest !== host.signed.snapshotDigest ||
        current.profile !== join(host.policy.stateRoot, 'profiles', profile.record.id) ||
        !self || !current.engine || (['pid', 'uid', 'startId', 'pidVersion', 'group', 'session',
          'parentStartId', 'parentPidVersion', 'executable'] as const).some(key => self[key] !== current.engine![key]) ||
        current.engine.executable !== layout.engine || current.starter.executable !== layout.engine ||
        current.bootstrap?.executable !== layout.bootstrap ||
        current.bootstrap.pid !== self.pid || current.bootstrap.startId !== self.startId ||
        current.bootstrap.pidVersion === self.pidVersion) throw unavailable('browser');
    if (claimedLayout(current).bundle !== layout.bundle) throw unavailable('browser');
    return current;
  });
}

/** Real packaged starter transactions. Process-local state merely remembers this
 * caller's nonce; durable native claim/cancel and the retained native originals
 * provide protection when the CLI or NSWorkspace reply disappears. */
export function createLaunchTransactions(host: VerifiedHost, platform: PlatformPort,
  exits: ProductionExitAuthority = createProductionExitAuthority(platform, {
    build: host.identity.layout.build, directory: host.identity.layout.buildRoot,
    guard: host.identity.layout.guard, explicit: true,
  }), closeVerification = false, reuseOpenSnapshot = false): LaunchAttemptPort {
  assertPlatform(platform); assertProductionExitAuthority(exits);
  const pending = new Map<string, LaunchAttempt>();
  return Object.freeze({
    async reserve(profile: ProfileSnapshot, request: string, deadline: number,
      heldBuild?: import('./start.js').BuildGuard, signal?: AbortSignal) {
      if (signal?.aborted) throw unavailable('browser');
      // The native reservation below still requires a complete current proof.
      await assertHostStartupContinuity(host, deadline, deadline);
      if (signal?.aborted) throw unavailable('browser');
      const next = await pendingLaunchAttempt(profile, host, platform, request, deadline);
      if (pending.has(request)) throw unavailable('browser'); pending.set(request, next);
      // Every production reservation, including the first and an expired
      // affirmatively unclaimed retry, reaches the native bound transition.
      // Temporary Owner is released BEFORE any LaunchServices submission.
      const owner = await ownerLock(profile, platform, false, deadline);
      if (!owner) throw unavailable('profile');
      let build: BuildLease | undefined;
      try {
        build = heldBuild as BuildLease | undefined;
        if (!build) build = await acquireBuildLease({ build: host.identity.layout.build, directory: host.identity.layout.buildRoot,
          guard: host.identity.layout.guard, explicit: true }, platform);
        // The genuine private Build handover, rather than this structural cast,
        // authorizes native admission. A fake or unrelated guard is rejected.
        if (signal?.aborted) throw unavailable('browser');
        await exits.reserve(profile, owner, host, build, next, deadline);
        await owner.assert(); await build.assert(); assertTime(deadline);
      } finally { owner.release(); if (!heldBuild) build?.release(); }
    },
    async launched(profile: ProfileSnapshot, request: string, pid: number, deadline: number, signal?: AbortSignal) {
      const expected = pending.get(request);
      if (!expected || !Number.isSafeInteger(pid) || pid <= 1) throw unavailable('browser');
      for (;;) {
        if (signal?.aborted) throw unavailable('browser');
        assertTime(deadline);
        const accepted = await withLaunchAttempt(profile, platform, deadline, transaction => {
          const current = transaction.current;
          if (!current || current.request !== request || current.nonce !== expected.nonce ||
              current.profileInstance !== profile.record.instance || current.expires <= platform.continuousTime() ||
              current.phase === 'cancelled' || current.phase === 'closed' || current.phase === 'closing') throw unavailable('browser');
          if (current.phase === 'pending') return false;
          const original = current.bootstrap, live = platform.processProvenance(pid);
          if (!original || original.pid !== pid || !live || original.startId !== live.startId || original.uid !== live.uid ||
              original.group !== live.group || original.session !== live.session ||
              original.executable !== join(host.identity.layout.bundle, 'Contents/MacOS/arbol-browser-native')) throw unavailable('browser');
          // NSWorkspace may reply on either side of the fixed exec. Its PID is
          // not proof by itself; require the matching durable original claim
          // and either that exact still-live outer or its actual adopted engine.
          if (live.pidVersion === original.pidVersion && live.executable === original.executable) return true;
          if (!current.engine) return false;
          if ((['pid', 'uid', 'startId', 'pidVersion', 'group', 'session', 'parentStartId', 'parentPidVersion', 'executable'] as const)
            .some(key => current.engine![key] !== live[key]) || live.executable !== host.identity.layout.engine) throw unavailable('browser');
          return true;
        });
        if (accepted) return assertHostStartupContinuity(host, deadline, deadline);
        await setTimeout(Math.min(10, Math.max(1, deadline - now())), undefined, signal ? { signal } : undefined);
      }
    },
    async publishedReady(profile: ProfileSnapshot, request: string, pid: number, deadline: number) {
      const expected = pending.get(request);
      if (!expected) throw unavailable('browser');
      return withLaunchAttempt(profile, platform, deadline, ({ current }) => {
        if (!current || current.request !== request || current.nonce !== expected.nonce ||
            current.profileInstance !== expected.profileInstance || current.profilePathHash !== expected.profilePathHash ||
            current.build !== expected.build || current.buildRoot !== expected.buildRoot || current.buildGuard !== expected.buildGuard ||
            current.sourceDigest !== expected.sourceDigest || current.productDigest !== expected.productDigest ||
            current.candidateDigest !== expected.candidateDigest || current.bootstrap?.pid !== pid) throw unavailable('browser');
        if (current.phase === 'claimed' && current.expires > platform.continuousTime()) return undefined;
        if (current.phase !== 'ready' || current.stage !== 'admitted' || current.engine?.pid !== pid ||
            !current.runtime || current.runtime.pid !== pid || current.runtime.phase !== 'ready') throw unavailable('browser');
        return current.runtime;
      });
    },
    async admitted(profile: ProfileSnapshot, record: RuntimeRecord, deadline: number, request?: string, joiningStartup = false) {
      const own = request ? pending.get(request) : undefined;
      if (request && !own) throw unavailable('browser');
      for (;;) {
        assertTime(deadline);
        const admitted = await withLaunchAttempt(profile, platform, deadline, transaction => {
          const current = transaction.current;
          if (!current || current.profileInstance !== profile.record.instance || current.profile !== profile.paths.root ||
              current.profilePathHash !== record.profilePathHash || (own &&
                (current.request !== own.request || current.nonce !== own.nonce || current.buildRoot !== own.buildRoot ||
                 current.sourceDigest !== own.sourceDigest || current.productDigest !== own.productDigest ||
                 current.candidateDigest !== own.candidateDigest))) throw unavailable('browser');
          if (current.phase === 'cancelled' || current.phase === 'closing' || current.phase === 'closed') throw unavailable('browser');
          if (current.phase !== 'ready') {
            if (current.expires <= platform.continuousTime()) throw unavailable('browser');
            return undefined;
          }
          if (current.stage !== 'admitted' || !current.runtime || current.runtime.phase !== 'ready' ||
              !current.engine || !current.bootstrap ||
              current.runtime.instance !== record.instance || current.runtime.nonce !== record.nonce || current.runtime.build !== record.build ||
              current.runtime.pid !== record.pid || current.runtime.processStartId !== record.processStartId ||
              current.runtime.agentSocket !== record.agentSocket || current.runtime.managementSocket !== record.managementSocket ||
              current.build !== record.build) throw unavailable('browser');
          const layout = claimedLayout(current);
          const live = platform.processProvenance(record.pid);
          if (!live || (['pid', 'uid', 'startId', 'pidVersion', 'group', 'session', 'parentStartId', 'parentPidVersion', 'executable'] as const)
              .some(key => live[key] !== current.engine![key]) || current.engine.pid !== current.bootstrap.pid ||
              current.engine.startId !== current.bootstrap.startId || current.engine.pidVersion === current.bootstrap.pidVersion ||
              current.engine.executable !== layout.engine ||
              current.bootstrap.executable !== layout.bootstrap) throw unavailable('browser');
          return current;
        });
        if (admitted) {
          const layout = claimedLayout(admitted);
          const selected = Object.freeze({ build: admitted.build, directory: admitted.buildRoot, guard: admitted.buildGuard, explicit: true });
          const lease = await acquireBuildLease(selected, platform);
          try {
            const authorityURL = new URL('./authorities.js', import.meta.url).href;
            const authorities = await import(authorityURL) as typeof import('./authorities.js');
            const sameHost = host.identity.layout.bundle === layout.bundle && host.identity.layout.build === admitted.build && host.identity.layout.buildRoot === admitted.buildRoot &&
              host.identity.layout.guard === admitted.buildGuard &&
              host.signed.snapshotDigest === admitted.candidateDigest && host.identity.sourceDigest === admitted.sourceDigest &&
              host.identity.productDigest === admitted.productDigest;
            // Signature-tool processes are outside the guarded engine family.
            // Only the standalone CLI may verify another Build this way.
            if (!sameHost && process.type === 'browser') throw unavailable('browser');
            const originalHost = sameHost ? host : await authorities.verifyPackagedHost(selected,
              layout.payload, deadline);
            if (originalHost.signed.snapshotDigest !== admitted.candidateDigest || originalHost.identity.sourceDigest !== admitted.sourceDigest ||
                originalHost.identity.productDigest !== admitted.productDigest || originalHost.policy.stateRoot !== profile.paths.state)
              throw unavailable('browser');
            if (sameHost && closeVerification) await assertHostCloseContinuity(originalHost, deadline);
            else if (sameHost && (own || joiningStartup || reuseOpenSnapshot)) {
              // The host completed its independent full snapshot before the
              // exact Claim could reach ready. Retain the CLI's verified
              // package for this startup and its exact Build lock.
              await withBuildLockForCustody(lease, platform, held => {
                const actual = held.assertIdentity(), expected = originalHost.guardIdentity;
                if (actual.device !== expected.device || actual.inode !== expected.inode || actual.uid !== expected.uid)
                  throw unavailable('browser');
              });
              if (own || joiningStartup) await assertHostStartupContinuity(originalHost, deadline, deadline);
              else await assertHostStartupSnapshot(originalHost, deadline);
            }
            else await originalHost.assertTrusted(deadline);
            await lease.assert(); assertTime(deadline);
            await withLaunchAttempt(profile, platform, deadline, transaction => {
              if (!transaction.current || JSON.stringify(transaction.current) !== JSON.stringify(admitted)) throw unavailable('browser');
              const actual = platform.processProvenance(record.pid);
              if (!actual || (['pid', 'uid', 'startId', 'pidVersion', 'group', 'session', 'parentStartId', 'parentPidVersion', 'executable'] as const)
                  .some(key => actual[key] !== admitted.engine![key])) throw unavailable('browser');
            });
            return;
          } finally { lease.release(); }
        }
        await setTimeout(Math.min(5, Math.max(1, deadline - now())));
      }
    },
    async cancel(profile: ProfileSnapshot, request: string, deadline: number) {
      const expected = pending.get(request);
      if (!expected) return 'absent'; // reservation failed before any native write/submission
      return cancelLaunchAttempt(profile, platform, request, expected.nonce, deadline);
    },
  });
}

/** Close joins an existing exact admitted host only; never reserves or starts. */
export async function assertProductionCloseReady(profile: ProfileSnapshot, record: RuntimeRecord,
  selection: import('./selection.js').BuildSelection, platform: PlatformPort,
  exits: ProductionExitAuthority, deadline: number, verifiedHost?: VerifiedHost): Promise<void> {
  const lease = await acquireBuildLease(selection, platform);
  try {
    const address = new URL('./authorities.js', import.meta.url).href;
    const authority = await import(address) as typeof import('./authorities.js');
    const layout = selectedLayout(selection, resolve(fileURLToPath(new URL('../../', import.meta.url))));
    let retained: VerifiedHost | undefined;
    if (verifiedHost) {
      assertVerifiedHostMetadata(verifiedHost, deadline);
      if (verifiedHost.identity.layout.build !== layout.build || verifiedHost.identity.layout.buildRoot !== layout.buildRoot ||
          verifiedHost.identity.layout.bundle !== layout.bundle || verifiedHost.identity.layout.payload !== layout.payload ||
          selection.guard !== layout.guard) throw unavailable('browser');
      const manifestURL = new URL('../native/manifest.js', import.meta.url).href;
      const manifest = await import(manifestURL) as typeof import('../native/manifest.js');
      if (manifest.assertRetainedReadOnlyStorage(verifiedHost.signed, deadline)) retained = verifiedHost;
    }
    const host = retained ?? await authority.verifyPackagedHost(selection, layout.payload, deadline);
    await createLaunchTransactions(host, platform, exits, Boolean(retained)).admitted(profile, record, deadline);
    await lease.assert(); assertTime(deadline);
  } finally { lease.release(); }
}

/** Actual selected, signed package integration. No caller-supplied providers,
 * fake native effects or MCP dependency can open this production boundary. */
export function createProductionProcessIntegration(host: VerifiedHost, selection: BuildSelection,
  platform: PlatformPort, exits: ProductionExitAuthority, observation?: OpenCommandObservation, openCutoff?: number): ProcessIntegration {
  // CLI wiring follows full verification and native provider loading. Native
  // reservation and the host's final readiness proof remain independent.
  assertPlatform(platform); assertProductionExitAuthority(exits); assertVerifiedHostMetadata(host, now() + 5000);
  if (host.identity.layout.build !== selection.build || host.identity.layout.buildRoot !== selection.directory ||
      selection.guard !== host.identity.layout.guard) throw unavailable('browser');
  const assertAppAvailable = () => {
    if (host.identity.layout.scope === 'installed' && !platform.browserAppAvailable?.()) throw unavailable('browser');
  };
  return Object.freeze({
    async assertAdmissionAvailable(deadline = now() + 5000) {
      assertAppAvailable();
      if (openCutoff === undefined) return host.assertTrusted(deadline);
      const cutoff = Math.min(deadline, openCutoff);
      await assertHostStartupContinuity(host, cutoff, cutoff);
    },
    async start(profile: ProfileSnapshot, endpoint: import('./transport.js').Endpoint, deadline: number,
      contentionDeadline: number, label?: string, signal?: AbortSignal) {
      noteOpenCommand(observation, 'open-current-signed-start');
      if (signal?.aborted) throw unavailable('browser');
      assertTime(deadline);
      assertAppAvailable();
      await assertHostStartupContinuity(host, deadline, deadline);
      if (signal?.aborted) throw unavailable('browser');
      if (profile.paths.state !== host.policy.stateRoot) throw unavailable('profile');
      const attempts = createLaunchTransactions(host, platform, exits, false, openCutoff !== undefined);
      const starter = createStarter({ selection, platform, attempts, ...(observation ? { observation } : {}),
        acquireBuild: () => acquireBuildLease(selection, platform),
        authority: {
          async assertTrusted(actual) {
            if (actual !== selection) throw unavailable('browser');
            // The intent file is a hint. Native reservation below still verifies the complete package.
            await assertHostStartupContinuity(host, deadline, deadline);
          },
          async assertReady(actual, record, request, joiningStartup) {
            await attempts.admitted(actual, record, deadline, request, joiningStartup);
          },
          async assertFailed(actual, request, launchedPid, limit) {
            for (;;) {
              assertTime(limit);
              const current = await withLaunchAttempt(actual, platform, limit, tx => tx.current);
              if (!current || current.request !== request || current.profileInstance !== actual.record.instance ||
                  (launchedPid !== undefined && current.bootstrap && current.bootstrap.pid !== launchedPid)) throw unavailable('profile');
              const owner = await ownerLock(actual, platform, false, limit);
              if (owner) try {
                await exits.withdraw(actual, owner, limit);
                await exits.assertClosedUnderOwner(actual, current.runtime ?? undefined, owner, limit);
                await owner.assert(); assertTime(limit); return;
              } catch { assertTime(limit); }
              finally { owner.release(); }
              await setTimeout(Math.min(10, Math.max(1, limit - now())));
            }
          },
        },
      });
      return starter(profile, endpoint, deadline, contentionDeadline, label, signal);
    },
  });
}

/** Post-proof bookkeeping only. Never manufactures exit/flush evidence. Actual
 * Registry/Owner remain held through the caller's final profile detach. The
 * stable short Claim inode remains in place; per-request native evidence stays
 * outside the profile and is never consumed as a fresh instance's authority. */
export async function archiveRemovedRuntime(profile: ProfileSnapshot, owner: OwnerLease, registry: RegistryLease,
  platform: PlatformPort, exits: ProductionExitAuthority, deadline: number, retired: string): Promise<'detached' | 'uncertain'> {
  assertPlatform(platform); assertProductionExitAuthority(exits); assertTime(deadline);
  if (owner.profile !== profile || registry.platform !== platform || registry.state !== profile.paths.state) throw unavailable('profile');
  await registry.assert(); await owner.assert();
  await withOwnerLockForCustody(owner, platform, held => { held.assertIdentity(); });
  const location = await runtimeLocation(profile);
  if (!location) throw unavailable('profile'); // caller's Native full reader creates its stable Claim location
  const original = await withLaunchAttempt(profile, platform, deadline, tx => tx.current);
  await exits.assertClosedUnderOwner(profile, undefined, owner, deadline);
  await registry.assert(); await owner.assert();
  let outcome: object | undefined;
  const result = await withLaunchAttempt(profile, platform, deadline, tx => {
    const finish = (kind: 'detached' | 'uncertain') => outcome = detachResult(kind);
    const current = tx.current;
    if (JSON.stringify(current) !== JSON.stringify(original)) throw unavailable('profile');
    // The only nonterminal Claim allowed by Native full inspection is its
    // permanent cancelled no-spawn prefix. No attached actor/engine/runtime can
    // be archived through this branch; those require Native terminal retirement.
    if (current && current.phase !== 'closed' && (current.phase !== 'cancelled' || current.stage !== 'untransferred' ||
        current.bootstrap || current.engine || current.runtime || current.terminal)) throw unavailable('profile');
    const same = (a: BigIntStats, b: BigIntStats) => a.dev === b.dev && a.ino === b.ino && a.uid === b.uid && a.mode === b.mode && a.nlink === b.nlink;
    const sameDirectory = (a: BigIntStats, b: BigIntStats) => a.dev === b.dev && a.ino === b.ino && a.uid === b.uid && a.mode === b.mode;
    const uid = BigInt(process.geteuid!());
    const directory = (path: string) => {
      assertTime(deadline);
      if (realpathSync(path) !== path) throw unavailable('profile');
      const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const actual = fstatSync(descriptor, { bigint: true }), named = lstatSync(path, { bigint: true });
        if (!actual.isDirectory() || actual.uid !== uid || (actual.mode & 0o7777n) !== 0o700n || !same(actual, named)) throw unavailable('profile');
        return { path, descriptor, actual };
      } catch (error) { closeSync(descriptor); throw error; }
    };
    type Directory = ReturnType<typeof directory>;
    const checkDirectory = (value: Directory) => {
      assertTime(deadline);
      if (realpathSync(value.path) !== value.path || !sameDirectory(value.actual, fstatSync(value.descriptor, { bigint: true })) ||
          !sameDirectory(value.actual, lstatSync(value.path, { bigint: true }))) throw unavailable('profile');
    };
    const regular = (parent: Directory, name: string, maximum: number) => {
      checkDirectory(parent); const path = join(parent.path, name);
      const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const first = fstatSync(descriptor, { bigint: true }), named = lstatSync(path, { bigint: true });
        if (!first.isFile() || first.uid !== uid || first.nlink !== 1n || (first.mode & 0o7777n) !== 0o600n ||
            first.size < 1n || first.size > BigInt(maximum) || !same(first, named)) throw unavailable('profile');
        const bytes = Buffer.alloc(Number(first.size) + 1); let offset = 0;
        while (offset < bytes.length) { assertTime(deadline); const n = readSync(descriptor, bytes, offset, bytes.length - offset, null); if (!n) break; offset += n; }
        const last = fstatSync(descriptor, { bigint: true });
        if (offset !== Number(first.size) || !same(first, last) || first.size !== last.size || first.mtimeNs !== last.mtimeNs ||
            first.ctimeNs !== last.ctimeNs || !same(first, lstatSync(path, { bigint: true }))) throw unavailable('profile');
        return { path, stat: last, value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, offset))) as Record<string, unknown> };
      } finally { closeSync(descriptor); }
    };
    const parents: Directory[] = [];
    try {
      const runtime = directory(realpathSync(location.leaf)); parents.push(runtime);
      const historyPath = join(profile.paths.state, 'exit-evidence', location.hash);
      let history: Directory | undefined;
      try { history = directory(historyPath); parents.push(history); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      const moves: Array<{ parent: Directory; name: string; stat: BigIntStats }> = [];
      const requests = new Set<string>(); if (current) requests.add(current.request);
      if (history) for (const name of ['previous-claim.json', 'current-attempt.json']) {
        let entry: ReturnType<typeof regular>;
        try { entry = regular(history, name, 16384); }
        catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
        if (entry.value.profile !== profile.paths.root || entry.value.profileInstance !== profile.record.instance ||
            entry.value.profilePathHash !== location.hash) throw unavailable('profile');
        if (typeof entry.value.request !== 'string' || !/^req_[A-Za-z0-9_-]{22}$/.test(entry.value.request)) throw unavailable('profile');
        requests.add(entry.value.request); moves.push({ parent: history, name, stat: entry.stat });
      }
      // Only bounded current authoritative names. Historical authenticated
      // launch/Close files cannot be reused by another nonce/profile instance;
      // leave their bytes intact rather than imposing a cumulative visit limit.
      for (const name of ['claim.json', 'runtime.json', 'agent.sock', 'manage.sock',
          ...[...requests].map(request => `launch-${request}.json`)]) {
        let stat: BigIntStats;
        try { stat = lstatSync(join(runtime.path, name), { bigint: true }); }
        catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
        if (name === 'agent.sock' || name === 'manage.sock') {
          if (!stat.isSocket() || stat.uid !== uid || stat.nlink !== 1n || (stat.mode & 0o7777n) !== 0o600n) throw unavailable('profile');
          moves.push({ parent: runtime, name, stat }); continue;
        }
        const actual = regular(runtime, name, 16384);
        if (name === 'claim.json') {
          if (!current || JSON.stringify(actual.value) !== JSON.stringify(current)) throw unavailable('profile');
        } else if (actual.value.profileInstance !== profile.record.instance ||
            actual.value.profile !== (name === 'runtime.json' ? profile.record.id : profile.paths.root) ||
            (name === 'runtime.json' ? !validator('wire.RuntimeRecord')(actual.value) :
              name !== `launch-${actual.value.request}.json`)) throw unavailable('profile');
        moves.push({ parent: runtime, name, stat: actual.stat });
      }
      // Prevalidate every entry before any rename. Separate same-device archives
      // retain the exact bytes/inodes even when state and /tmp differ by device.
      const archives = new Map<Directory, Directory>(), moved: typeof moves = [];
      const root = directory(profile.paths.root); parents.push(root);
      if (join(profile.paths.profiles, retired.split('/').at(-1)!) !== retired ||
          !/^\.deleting-[0-9a-f]{32}$/.test(retired.split('/').at(-1)!)) throw unavailable('profile');
      const absent = (path: string) => { try { lstatSync(path); return false; } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; return true;
      } };
      if (!absent(retired)) throw unavailable('profile');
      let detached = false, uncertain = false, preparingArchive = false;
      try {
        for (const parent of new Set(moves.map(move => move.parent))) {
          checkDirectory(parent); const path = join(parent.path, `removed-${profile.record.instance}`);
          mkdirSync(path, { mode: 0o700 }); preparingArchive = true;
          const archive = directory(path); parents.push(archive); archives.set(parent, archive); preparingArchive = false;
        }
        for (const move of moves) {
          const archive = archives.get(move.parent)!; checkDirectory(move.parent); checkDirectory(archive);
          const from = join(move.parent.path, move.name), to = join(archive.path, move.name);
          if (!same(move.stat, lstatSync(from, { bigint: true })) || !absent(to)) throw unavailable('profile');
          renameSync(from, to); moved.push(move);
          if (!same(move.stat, lstatSync(to, { bigint: true }))) throw unavailable('profile');
        }
        for (const parent of parents) { checkDirectory(parent); fsyncSync(parent.descriptor); }
        // Actual Native no-replacement rename, still inside the genuine short
        // Claim. A throw alone does not decide whether detach committed.
        try { platform.publishDirectory(profile.paths.root, retired); } catch { /* classify the actual physical result below */ }
        let published = false;
        try {
          const rootAbsent = absent(profile.paths.root), targetAbsent = absent(retired);
          if (rootAbsent && !targetAbsent && sameDirectory(root.actual, lstatSync(retired, { bigint: true }))) detached = true;
          else if (!rootAbsent && targetAbsent && sameDirectory(root.actual, lstatSync(profile.paths.root, { bigint: true }))) published = true;
          else uncertain = true;
        } catch { uncertain = true; }
        if (published) throw unavailable('profile');
        return finish(detached ? 'detached' : 'uncertain');
      } catch (error) {
        if (detached || uncertain || preparingArchive) return finish('uncertain');
        // Reverse exact moves on known pre-detach failure. Never overwrite an
        // active name or erase old evidence. A rollback uncertainty retains the
        // caller's original guards and the moved artifacts for examination.
        try {
          if (absent(profile.paths.root) || !absent(retired) ||
              !sameDirectory(root.actual, lstatSync(profile.paths.root, { bigint: true }))) return finish('uncertain');
          for (const move of moved.reverse()) {
            const archive = archives.get(move.parent)!, from = join(archive.path, move.name), to = join(move.parent.path, move.name);
            checkDirectory(move.parent); checkDirectory(archive);
            if (!absent(to) || !same(move.stat, lstatSync(from, { bigint: true }))) return finish('uncertain');
            renameSync(from, to);
            if (!same(move.stat, lstatSync(to, { bigint: true }))) return finish('uncertain');
          }
          for (const [parent, archive] of archives) {
            checkDirectory(archive); rmdirSync(archive.path); fsyncSync(parent.descriptor);
          }
        } catch { return finish('uncertain'); }
        throw error;
      }
    } finally { for (const parent of parents.reverse()) closeSync(parent.descriptor); }
  }).catch(error => {
    if (outcome) { detachResults.set(outcome, 'uncertain'); return outcome; }
    throw error;
  });
  const disposition = detachResults.get(result); detachResults.delete(result);
  if (!disposition) throw unavailable('profile'); return disposition;
}
