/** Private native-backed launch transactions. Nothing in this file supplies a
 * simulated host, watchdog, engine-exit certificate or successful tool effect. */
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { unavailable } from '../contracts/errors.js';
import { assertProfile, type ProfileSnapshot } from '../profiles/records.js';
import { assertPlatform, type HeldLock, type PlatformPort, type ProcessProvenance } from './platform.js';
import { assertVerifiedHost, type VerifiedHost } from './authorities.js';
import { assertTime, now, runtimeLocation, type RuntimeLocation, type RuntimeRecord } from './instance.js';
import type { LaunchAttemptPort } from './start.js';
import { ownerLock } from '../profiles/locking.js';
import { acquireBuildLease, type BuildLease } from './build-lease.js';
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
  return frozen(value);
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
    assertTime(deadline); await location.assert(); held.assertIdentity();
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
    await location.assert(); held.assertIdentity(); assertTime(deadline); return result;
  } finally { active = false; held?.release(); }
}

/** Construct only a pending intent. The caller must reserve it under the short
 * native transaction and independently verify any previous claimed/closed family;
 * phase labels and an available lock supply no PreviousExit authority. */
export async function pendingLaunchAttempt(profile: ProfileSnapshot, host: VerifiedHost, platform: PlatformPort,
  request: string, deadline: number): Promise<LaunchAttempt> {
  assertPlatform(platform); assertVerifiedHost(host, deadline); await assertProfile(profile);
  if (!/^req_[A-Za-z0-9_-]{22}$/.test(request) ||
      profile.paths.root !== join(host.policy.stateRoot, 'profiles', profile.record.id)) throw unavailable('profile');
  const location = await runtimeLocation(profile, true); if (!location) throw unavailable('profile');
  const starter = platform.processProvenance(process.pid);
  if (!starter || starter.executable !== host.identity.layout.engine) throw unavailable('browser');
  // Sampling native first and the caller clock second is conservative. Sleep
  // can shorten native continuous-time admission, never extend the caller bound.
  const nativeNow = platform.continuousTime(), sampled = now(); assertTime(deadline);
  const expires = nativeNow + Math.min(30000, deadline - sampled);
  return frozen({ format: 1, request, nonce: randomBytes(32).toString('base64url'),
    profile: profile.paths.root, profileInstance: profile.record.instance, profilePathHash: location.hash,
    build: host.identity.layout.build, buildRoot: host.identity.layout.buildRoot,
    buildGuard: join(host.identity.layout.buildRoot, '../.uses', host.identity.layout.build),
    sourceDigest: host.identity.sourceDigest, productDigest: host.identity.productDigest,
    candidateDigest: host.signed.snapshotDigest, expires, starter, phase: 'pending', stage: 'untransferred',
    bootstrap: null, engine: null, runtime: null, terminal: null });
}
/** Cancellation records permanent loss of this one attempt only. It neither
 * withdraws a submitted NSWorkspace notification nor claims custody/exit. */
export async function cancelLaunchAttempt(profile: ProfileSnapshot, platform: PlatformPort,
  request: string, nonce: string, deadline: number): Promise<LaunchAttempt | undefined> {
  return withLaunchAttempt(profile, platform, deadline, transaction => {
    const current = transaction.current;
    if (!current) return undefined;
    if (current.request !== request || current.nonce !== nonce || current.profileInstance !== profile.record.instance)
      throw unavailable('profile');
    if (current.phase === 'closed' || current.phase === 'cancelled') return current;
    const next: LaunchAttempt = frozen({ ...current, phase: 'cancelled' }); transaction.replace(next); return next;
  });
}

/** Independent post-exec binding, after native one-use Build adoption. The
 * returned snapshot grants no data/session access; custody and the serialized
 * mutation boundary must still be established by the pre-ready assembly. */
export async function claimedHostAttempt(profile: ProfileSnapshot, host: VerifiedHost, platform: PlatformPort,
  request: string, deadline: number): Promise<LaunchAttempt> {
  assertPlatform(platform); assertVerifiedHost(host, deadline); await assertProfile(profile);
  return withLaunchAttempt(profile, platform, deadline, transaction => {
    const current = transaction.current, self = platform.processProvenance(process.pid), layout = host.identity.layout;
    if (!current || current.request !== request || current.profileInstance !== profile.record.instance ||
        current.phase !== 'claimed' || current.stage !== 'untransferred' || current.expires <= platform.continuousTime() ||
        current.build !== layout.build || current.buildRoot !== layout.buildRoot ||
        current.buildGuard !== join(layout.buildRoot, '../.uses', layout.build) ||
        current.sourceDigest !== host.identity.sourceDigest || current.productDigest !== host.identity.productDigest ||
        current.candidateDigest !== host.signed.snapshotDigest ||
        current.profile !== join(host.policy.stateRoot, 'profiles', profile.record.id) ||
        !self || !current.engine || (['pid', 'uid', 'startId', 'pidVersion', 'group', 'session',
          'parentStartId', 'parentPidVersion', 'executable'] as const).some(key => self[key] !== current.engine![key]) ||
        current.engine.executable !== layout.engine || current.starter.executable !== layout.engine ||
        current.bootstrap?.executable !== join(layout.bundle, 'Contents/MacOS/arbol-browser-native') ||
        current.bootstrap.pid !== self.pid || current.bootstrap.startId !== self.startId ||
        current.bootstrap.pidVersion === self.pidVersion) throw unavailable('browser');
    return current;
  });
}

/** Real packaged starter transactions. Process-local state merely remembers this
 * caller's nonce; durable native claim/cancel and the retained native originals
 * provide protection when the CLI or NSWorkspace reply disappears. */
export function createLaunchTransactions(host: VerifiedHost, platform: PlatformPort,
  exits: ProductionExitAuthority = createProductionExitAuthority(platform, {
    build: host.identity.layout.build, directory: host.identity.layout.buildRoot,
    guard: join(host.identity.layout.buildRoot, '../.uses', host.identity.layout.build), explicit: true,
  })): LaunchAttemptPort {
  assertPlatform(platform); assertProductionExitAuthority(exits);
  const pending = new Map<string, LaunchAttempt>();
  return Object.freeze({
    async reserve(profile: ProfileSnapshot, request: string, deadline: number, heldBuild?: import('./start.js').BuildGuard) {
      assertVerifiedHost(host, deadline); await host.assertTrusted(deadline);
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
          guard: join(host.identity.layout.buildRoot, '../.uses', host.identity.layout.build), explicit: true }, platform);
        // The genuine private Build handover, rather than this structural cast,
        // authorizes native admission. A fake or unrelated guard is rejected.
        await exits.reserve(profile, owner, host, build, next, deadline);
        await owner.assert(); await build.assert(); assertTime(deadline);
      } finally { owner.release(); if (!heldBuild) build?.release(); }
    },
    async launched(profile: ProfileSnapshot, request: string, pid: number, deadline: number) {
      const expected = pending.get(request);
      if (!expected || !Number.isSafeInteger(pid) || pid <= 1) throw unavailable('browser');
      for (;;) {
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
        if (accepted) { assertVerifiedHost(host, deadline); return; }
        await setTimeout(Math.min(10, Math.max(1, deadline - now())));
      }
    },
    async admitted(profile: ProfileSnapshot, record: RuntimeRecord, deadline: number, request?: string) {
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
          const live = platform.processProvenance(record.pid);
          if (!live || (['pid', 'uid', 'startId', 'pidVersion', 'group', 'session', 'parentStartId', 'parentPidVersion', 'executable'] as const)
              .some(key => live[key] !== current.engine![key]) || current.engine.pid !== current.bootstrap.pid ||
              current.engine.startId !== current.bootstrap.startId || current.engine.pidVersion === current.bootstrap.pidVersion ||
              current.engine.executable !== join(current.buildRoot, 'ArbolBrowser.app/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron') ||
              current.bootstrap.executable !== join(current.buildRoot, 'ArbolBrowser.app/Contents/MacOS/arbol-browser-native')) throw unavailable('browser');
          return current;
        });
        if (admitted) {
          const selected = Object.freeze({ build: admitted.build, directory: admitted.buildRoot, guard: admitted.buildGuard, explicit: true });
          const lease = await acquireBuildLease(selected, platform);
          try {
            const authorityURL = new URL('./authorities.js', import.meta.url).href;
            const authorities = await import(authorityURL) as typeof import('./authorities.js');
            const sameHost = host.identity.layout.build === admitted.build && host.identity.layout.buildRoot === admitted.buildRoot &&
              join(host.identity.layout.buildRoot, '../.uses', host.identity.layout.build) === admitted.buildGuard &&
              host.signed.snapshotDigest === admitted.candidateDigest && host.identity.sourceDigest === admitted.sourceDigest &&
              host.identity.productDigest === admitted.productDigest;
            const originalHost = sameHost ? host : await authorities.verifyPackagedHost(selected,
              join(admitted.buildRoot, 'ArbolBrowser.app/Contents/Resources/browser'), deadline);
            if (originalHost.signed.snapshotDigest !== admitted.candidateDigest || originalHost.identity.sourceDigest !== admitted.sourceDigest ||
                originalHost.identity.productDigest !== admitted.productDigest || originalHost.policy.stateRoot !== profile.paths.state)
              throw unavailable('browser');
            await originalHost.assertTrusted(deadline); await lease.assert(); assertTime(deadline);
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
      if (!expected) return; // reservation failed before any native write/submission
      const belongs = await withLaunchAttempt(profile, platform, deadline, tx => tx.current?.request === request);
      if (!belongs) return; // reservation refused an unrelated already-owned attempt
      await cancelLaunchAttempt(profile, platform, request, expected.nonce, deadline);
    },
  });
}

/** Close joins an existing exact admitted host only; never reserves or starts. */
export async function assertProductionCloseReady(profile: ProfileSnapshot, record: RuntimeRecord,
  selection: import('./selection.js').BuildSelection, platform: PlatformPort,
  exits: ProductionExitAuthority, deadline: number): Promise<void> {
  const lease = await acquireBuildLease(selection, platform);
  try {
    const address = new URL('./authorities.js', import.meta.url).href;
    const authority = await import(address) as typeof import('./authorities.js');
    const host = await authority.verifyPackagedHost(selection,
      join(selection.directory, 'ArbolBrowser.app/Contents/Resources/browser'), deadline);
    await createLaunchTransactions(host, platform, exits).admitted(profile, record, deadline);
    await lease.assert(); assertTime(deadline);
  } finally { lease.release(); }
}
