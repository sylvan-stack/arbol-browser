/** Exact production custody preparation. This module never supplies a test
 * process, permissive engine authority, flush receipt or native input effect. */
import { join } from 'node:path';
import { unavailable } from '../contracts/errors.js';
import { assertProfile } from '../profiles/records.js';
import { withOwnerLockForCustody, type OwnerLease } from '../profiles/locking.js';
import { terminateAdoptedBuild, withBuildLockForCustody, type BuildLease } from './build-lease.js';
import { assertVerifiedHost, bindArmedHost, type VerifiedHost } from './authorities.js';
import { assertPlatform, assertWatchdogCustody, type PlatformPort, type WatchdogCustody, type PriorMarkerExpectation } from './platform.js';
import { assertTime, type InstanceOwner } from './instance.js';
import { claimedHostAttempt } from './process.js';
import type { NativeBoundaryPreparation } from './bootstrap.js';
import type { NativeWatchdog } from '../native/watchdog.js';
import { assertActualSessionFactory, type ActualSessionFactory, type ActualSessionSeal } from '../profiles/session.js';
import { consumeSignedSnapshot } from '../native/manifest.js';

export interface HostCustody {
  readonly host: VerifiedHost;
  readonly instance: InstanceOwner;
  readonly build: BuildLease;
  /** Reuse the accepted canonical Native arm/hand-over route with the exact
   * already-prepared native descriptions and one-use private capability. */
  arm(prepared: NativeBoundaryPreparation, deadline: number): Promise<NativeWatchdog>;
  assertRetained(): void;
  /** Only actual protected management dispatch supplies this socket/request;
   * the original native holder authenticates and consumes the private carrier. */
  consumeClose(requestId: string, socketFd: number): import('./platform.js').CloseAdmission;
  localClose(): import('./platform.js').CloseAdmission;
  beginSessionUse(factory: ActualSessionFactory): Readonly<{
    accept(seal: ActualSessionSeal): import('./platform.js').WebsiteSessionReceipt;
    abort(): never;
  }>;
  beginMarkerMutation(marker: Readonly<import('../profiles/compatibility.js').EngineMarker>): Promise<import('../profiles/compatibility.js').EngineMutation>;
  assertMarker(): void;
  terminate(): never;
}
const receipts = new WeakMap<HostCustody, { native: WatchdogCustody; watchdog?: NativeWatchdog }>();
const preparations = new WeakSet<InstanceOwner>();
export function assertHostCustody(value: HostCustody): void {
  const actual = receipts.get(value);
  if (!actual?.watchdog) throw unavailable('browser');
  actual.native.assert(); actual.native.assertHost();
}
/** A current host operation, not a transferable signed-package assertion. */
export interface ArmedHostSnapshot { readonly deadline: number }
type SnapshotPurpose = 'native-install' | 'ownership' | 'window';
const armedSnapshots = new WeakMap<ArmedHostSnapshot, {
  custody: HostCustody; trust: import('../native/manifest.js').CandidateTrust;
  purpose: SnapshotPurpose; operation: object; runtime: import('./instance.js').RuntimeRecord;
  proof: import('../native/manifest.js').SignedSnapshotComparison; used: boolean;
}>();
const preparingSnapshots = new WeakSet<HostCustody>();
export async function prepareArmedHostSnapshot(custody: HostCustody, trust: import('../native/manifest.js').CandidateTrust,
  purpose: SnapshotPurpose, operation: object, deadline: number): Promise<ArmedHostSnapshot> {
  assertHostCustody(custody); assertTime(deadline);
  if (preparingSnapshots.has(custody) || !operation || trust.bundle !== custody.host.signed.bundle ||
      trust.snapshotDigest !== custody.host.signed.snapshotDigest) return custody.terminate();
  preparingSnapshots.add(custody);
  try {
    const moduleURL = new URL('../native/manifest.js', import.meta.url).href;
    const manifest = await import(moduleURL) as typeof import('../native/manifest.js');
    assertHostCustody(custody); assertTime(deadline);
    const runtime = custody.instance.record;
    const proof = await manifest.compareSignedSnapshot(trust, deadline);
    // No further await after minting: the caller immediately enters its exact
    // synchronous constructor/preflight chain with this private receipt.
    assertHostCustody(custody); assertTime(deadline);
    if (custody.instance.record !== runtime) return custody.terminate();
    const receipt: ArmedHostSnapshot = Object.freeze({ deadline });
    armedSnapshots.set(receipt, { custody, trust, purpose, operation, runtime, proof, used: false }); return receipt;
  } catch { return custody.terminate(); }
  finally { preparingSnapshots.delete(custody); }
}
export function consumeArmedHostSnapshot(receipt: ArmedHostSnapshot, trust: import('../native/manifest.js').CandidateTrust,
  purpose: SnapshotPurpose, operation: object): void {
  const actual = armedSnapshots.get(receipt);
  if (!actual) throw unavailable('browser');
  try {
    if (actual.used || actual.trust !== trust || actual.purpose !== purpose || actual.operation !== operation ||
        actual.custody.instance.record !== actual.runtime) return actual.custody.terminate();
    actual.used = true; assertTime(receipt.deadline); assertHostCustody(actual.custody);
    consumeSignedSnapshot(actual.proof, trust, receipt.deadline);
    assertHostCustody(actual.custody); assertTime(receipt.deadline);
  } catch { return actual.custody.terminate(); }
}

/** Cancellation/refusal before resource permission uses the actual adopted
 * native original. It retains any genuine acquired Owner and either publishes
 * authentic no-use or joins already-started native custody cleanup. Unknown
 * transfer stays protected; JS labels never certify family exit or flush. */
export async function abortUnadmittedHost(ownerLease: OwnerLease | undefined, build: BuildLease,
  platform: PlatformPort): Promise<never> {
  assertPlatform(platform);
  // Absence of Owner is real for pre-acquisition failure/losing contention.
  // Never manufacture an owner or start a monitor just to obtain an exit path.
  return terminateAdoptedBuild(build, platform, ownerLease);
}
/** Called after actual owner acquisition/runtime publication and before every
 * engine-marker/session operation. Prior is only a bound expectation here; the
 * independent held-guard PreviousExit reader and compatibility transaction must
 * still validate the actual marker. No profile payload is read or changed. */
export async function prepareHostCustody(host: VerifiedHost, instance: InstanceOwner, build: BuildLease,
  platform: PlatformPort, request: string, prior: PriorMarkerExpectation, deadline: number): Promise<HostCustody> {
  if (process.type !== 'browser' || preparations.has(instance)) throw unavailable('browser');
  preparations.add(instance); assertPlatform(platform); assertVerifiedHost(host, deadline);
  await assertProfile(instance.owner.profile); await instance.owner.assert(); await build.assert(); assertTime(deadline);
  const attempt = await claimedHostAttempt(instance.owner.profile, host, platform, request, deadline);
  if (instance.record.pid !== process.pid || instance.record.processStartId !== attempt.engine?.startId ||
      instance.record.build !== host.identity.layout.build || instance.record.phase !== 'starting' ||
      instance.record.profileInstance !== instance.owner.profile.record.instance) throw unavailable('browser');
  const input = Object.freeze({ requestPath: join(instance.location.leaf, `launch-${request}.json`),
    runtime: instance.record, prior: Object.freeze({ ...prior }),
    signedPolicy: Object.freeze({ policyDigest: host.policyDigest, compatibilityDigest: host.policy.compatibilityDigest }) });
  const native = await withOwnerLockForCustody(instance.owner, platform, owner =>
    withBuildLockForCustody(build, platform, heldBuild => {
      assertTime(deadline);
      return platform.prepareHostCustody(owner, heldBuild, host.signed.bundle, host.signed.snapshotDigest, input);
    }));
  assertWatchdogCustody(native);
  let attempted = false;
  const receipt: HostCustody = Object.freeze({ host, instance, build,
    async arm(prepared: NativeBoundaryPreparation, limit: number): Promise<NativeWatchdog> {
      if (attempted) return native.terminate(); attempted = true;
      try {
        const bootstrapURL = new URL('./bootstrap.js', import.meta.url).href;
        const bootstrap = await import(bootstrapURL) as typeof import('./bootstrap.js');
        bootstrap.assertNativeBoundaryPreparation(prepared);
        if (prepared.platform !== platform || prepared.trust.bundle !== host.signed.bundle ||
            prepared.trust.snapshotDigest !== host.signed.snapshotDigest) return native.terminate();
        assertTime(limit); await instance.owner.assert(); await build.assert(); assertTime(limit);
        const watchdog = await withOwnerLockForCustody(instance.owner, platform, owner =>
          withBuildLockForCustody(build, platform, heldBuild => prepared.arm(owner, heldBuild)));
        if (watchdog.custody !== native) return native.terminate();
        native.assert(); native.assertHost(); watchdog.assertArmed(prepared.trust); assertTime(limit);
        receipts.get(receipt)!.watchdog = watchdog; bindArmedHost(host, receipt); return watchdog;
      } catch { return native.terminate(); }
    },
    assertRetained() { assertHostCustody(receipt); },
    consumeClose(requestId: string, socketFd: number) { assertHostCustody(receipt); return native.consumeClose(requestId, socketFd); },
    localClose() { assertHostCustody(receipt); return native.localClose(); },
    beginSessionUse(factory: ActualSessionFactory) {
      assertHostCustody(receipt); assertActualSessionFactory(factory);
      const permit = native.beginSessionUse(factory); let used = false;
      return Object.freeze({
        accept(seal: ActualSessionSeal) {
          if (used) return permit.abort(); used = true;
          // The same native short claim is still held. Do not call the generic
          // assertRetained/controls path and recursively acquire that claim.
          try { return permit.accept(seal); }
          catch { return permit.abort(); }
        },
        abort(): never { return permit.abort(); },
      });
    },
    assertMarker() { assertHostCustody(receipt); native.assertMarker(); },
    async beginMarkerMutation(marker: Readonly<import('../profiles/compatibility.js').EngineMarker>) {
      assertHostCustody(receipt); await instance.owner.assert(); await build.assert();
      assertHostCustody(receipt);
      try { return native.beginMarkerMutation(`${JSON.stringify(marker)}\n`); }
      catch { return native.terminate(); }
    },
    terminate(): never { return native.terminate(); },
  });
  receipts.set(receipt, { native }); return receipt;
}
