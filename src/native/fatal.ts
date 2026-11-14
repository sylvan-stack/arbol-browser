/** Profile-wide irreversible authority and guarded native failure path. */
import { unavailable } from '../contracts/errors.js';
import { assertNativeWatchdog, type NativeWatchdog } from './watchdog.js';
import type { NativeCompatibility } from './preflight.js';
export interface FatalEffects {
  closeAdmission(): void;
  invalidate(): void;
  hidePages(): void;
}
export interface ProfileFatal {
  readonly closed: boolean;
  readonly reason: string | undefined;
  attach(native: NativeCompatibility): void;
  assertHealthy(): void;
  guard<T>(operation: () => T | Promise<T>): Promise<T>;
  fail(reason: string): never;
}
const diagnostics = new Set(['native_integrity_unavailable', 'native_retirement_unavailable', 'native_watchdog_unavailable']);
const fatalInstances = new WeakSet<object>();
export function assertProfileFatal(value: ProfileFatal): void {
  if (!fatalInstances.has(value)) throw unavailable('browser');
}
export function createProfileFatal(watchdog: NativeWatchdog, effects: FatalEffects): ProfileFatal {
  assertNativeWatchdog(watchdog);
  if (!effects || ['closeAdmission', 'invalidate', 'hidePages'].some(name => typeof effects[name as keyof FatalEffects] !== 'function')) throw unavailable('browser');
  let latched = false, cause: string | undefined, native: NativeCompatibility | undefined;
  function closed() { return latched || watchdog.fatal; }
  function synchronous(operation: () => void) {
    const result: unknown = operation();
    if (result !== undefined) throw unavailable('browser');
  }
  function fail(reason: string): never {
    if (!latched) {
      // This bit governs admission/content guards before ANY callback/await.
      latched = true; cause = diagnostics.has(reason) ? reason : 'native_boundary_unavailable';
      watchdog.quarantine(); // stop H and request F before every risky operation
      try {
        synchronous(() => effects.closeAdmission());
        synchronous(() => effects.invalidate());
        if (native) native.seal();
        synchronous(() => effects.hidePages());
      } catch { return watchdog.terminate(); }
    }
    // No app.exit/quit callback may drop the main's custody before its native
    // proof. This actual provider retains/waits and cannot return to the app.
    return watchdog.terminate();
  }
  const api: ProfileFatal = Object.freeze({
    get closed() { return closed(); }, get reason() { return cause; }, fail,
    attach(value: NativeCompatibility): void {
      if (native || closed() || value.trust === undefined || value.pageAdmission !== false) fail('native_boundary_unavailable');
      native = value;
    },
    assertHealthy(): void {
      if (closed()) throw unavailable('browser');
    },
    async guard<T>(operation: () => T | Promise<T>): Promise<T> {
      api.assertHealthy();
      if (!native) return fail('native_integrity_unavailable');
      try { return await native.guard(operation); }
      finally { api.assertHealthy(); } // never publishes a settled old content reply after fatal
    },
  });
  fatalInstances.add(api); return api;
}
