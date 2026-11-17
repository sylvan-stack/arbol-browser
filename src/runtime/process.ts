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
