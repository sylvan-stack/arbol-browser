/** Exact production custody preparation. This module never supplies a test
 * process, permissive engine authority, flush receipt or native input effect. */
import { join } from 'node:path';
import { unavailable } from '../contracts/errors.js';
import { assertProfile } from '../profiles/records.js';
import { withOwnerLockForCustody, type OwnerLease } from '../profiles/locking.js';
import { withBuildLockForCustody, type BuildLease } from './build-lease.js';
import { assertVerifiedHost, type VerifiedHost } from './authorities.js';
import { assertPlatform, assertWatchdogCustody, type PlatformPort, type WatchdogCustody, type PriorMarkerExpectation } from './platform.js';
import { assertTime, type InstanceOwner } from './instance.js';
import { claimedHostAttempt } from './process.js';
import type { NativeBoundaryPreparation } from './bootstrap.js';
import type { NativeWatchdog } from '../native/watchdog.js';

export interface HostCustody {
  readonly host: VerifiedHost;
  readonly instance: InstanceOwner;
  readonly build: BuildLease;
  /** Reuse the accepted canonical Native arm/hand-over route with the exact
   * already-prepared native descriptions and one-use private capability. */
  arm(prepared: NativeBoundaryPreparation, deadline: number): Promise<NativeWatchdog>;
  assertRetained(): void;
  terminate(): never;
}
const receipts = new WeakMap<HostCustody, { native: WatchdogCustody; watchdog?: NativeWatchdog }>();
const preparations = new WeakSet<InstanceOwner>();
export function assertHostCustody(value: HostCustody): void {
  const actual = receipts.get(value);
  if (!actual?.watchdog) throw unavailable('browser');
  actual.native.assert(); actual.native.assertHost();
}
/** Cancellation/refusal before pre-spawn preparation has not transferred a
 * child or admitted data. First retain the actual originals natively, then use
 * the same independently guarded native family unwind. This is never a JS
 * finally/release path or an assertion that a durable claim armed a watchdog. */
export async function abortUnadmittedHost(host: VerifiedHost, ownerLease: OwnerLease, build: BuildLease,
  platform: PlatformPort): Promise<never> {
  assertPlatform(platform);
  const native = await withOwnerLockForCustody(ownerLease, platform, owner =>
    withBuildLockForCustody(build, platform, heldBuild =>
      platform.prepareWatchdogCustody(owner, heldBuild, host.signed.bundle, host.signed.snapshotDigest)));
  return native.terminate();
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
    runtime: instance.record, prior: Object.freeze({ ...prior }) });
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
        receipts.get(receipt)!.watchdog = watchdog; return watchdog;
      } catch { return native.terminate(); }
    },
    assertRetained() { assertHostCustody(receipt); },
    terminate(): never { return native.terminate(); },
  });
  receipts.set(receipt, { native }); return receipt;
}
