/** Main-process only, single attempt native preflight. This is not page authority. */
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { isMainThread } from 'node:worker_threads';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertNativeFeatures } from './features.js';
import { createNativeOwnership, validateOwnershipAddon, type NativeOwnership } from './api.js';
import { nativeLimit, pinnedRuntime, stable, refuse, verifyNativeCandidate, type CandidateTrust } from './manifest.js';

export interface CompatibilityAddon {
  getABI(): string;
  install(expected: string): string;
  status(): string;
  checkIntegrity(): string;
  seal(): string;
}
export type NativeStatus = Contract<'native.Status'>;
let attempted = false;
export function nativeReply<K extends 'native.Inventory' | 'native.Status'>(kind: K, raw: unknown): Contract<K> {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > nativeLimit) return refuse();
  const value: unknown = JSON.parse(raw);
  if (!validator(kind)(value)) return refuse();
  return value;
}
export interface NativeCompatibility {
  readonly trust: CandidateTrust;
  readonly pageAdmission: false;
  readonly ownership: NativeOwnership;
  assertIntegrity(): NativeStatus;
  /** Applies integrity checks both before dispatch and after async settlement. */
  guard<T>(operation: () => T | Promise<T>): Promise<T>;
  seal(): NativeStatus;
}
/** Implemented by ABR-7's independently verified child, never by a default stub. */
export interface ArmedWatchdogPort { assertArmed(trust: CandidateTrust): void }
export function preflightNative(bundle: string, fatal: (reason: string) => void, watchdog: ArmedWatchdogPort): NativeCompatibility {
  if (attempted) return refuse();
  attempted = true;
  let failed = false;
  let cadence: ReturnType<typeof setInterval> | undefined;
  const fail = (): never => { const first = !failed; failed = true; if (cadence) clearInterval(cadence); if (first) fatal('native_integrity_unavailable'); return refuse(); };
  try {
    if (!isMainThread || process.type !== 'browser' || typeof fatal !== 'function') refuse();
    const actual = { electron: process.versions.electron, chromium: process.versions.chrome, node: process.versions.node,
      napi: process.versions.napi, modules: process.versions.modules, platform: process.platform, arch: process.arch,
      macOS: process.getSystemVersion?.() };
    if (stable(actual) !== stable(pinnedRuntime)) refuse();
    for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'ELECTRON_EXTRA_LAUNCH_ARGS', 'ELECTRON_OVERRIDE_DIST_PATH', 'ELECTRON_RUN_AS_NODE', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH'])
      if (process.env[key] !== undefined) refuse();
    assertNativeFeatures();
    const trust = verifyNativeCandidate(bundle);
    if (!watchdog || typeof watchdog.assertArmed !== 'function') refuse();
    watchdog.assertArmed(trust);
    const addon = validateOwnershipAddon(createRequire(import.meta.url)(join(trust.bundle, 'Contents/Resources/browser/native/ownership.node')));
    const inventory = nativeReply('native.Inventory', addon.getABI());
    if (stable(inventory) !== stable(trust.manifest.nativeABI)) refuse();
    watchdog.assertArmed(trust);
    const installed = nativeReply('native.Status', addon.install(JSON.stringify(trust.manifest.nativeABI)));
    if (installed.phase !== 'ready' || installed.hooks === 0 || installed.hooks !== installed.appliedHooks) refuse();
    const assertIntegrity = (): NativeStatus => {
      try {
        if (failed) return refuse();
        assertNativeFeatures();
        watchdog.assertArmed(trust);
        const value = nativeReply('native.Status', addon.checkIntegrity());
        if (value.phase !== 'ready' || value.hooks !== installed.hooks || value.appliedHooks !== installed.appliedHooks) refuse();
        return value;
      } catch { return fail(); }
    };
    cadence = setInterval(() => { try { assertIntegrity(); } catch { /* fatal port owns quarantine; never publish a reply */ } }, 250);
    cadence.unref();
    const ownership = createNativeOwnership(addon, assertIntegrity, fail);
    return Object.freeze({ trust, pageAdmission: false as const, ownership, assertIntegrity,
      async guard<T>(operation: () => T | Promise<T>): Promise<T> { assertIntegrity(); try { return await operation(); } finally { assertIntegrity(); } },
      seal(): NativeStatus {
        try { if (cadence) clearInterval(cadence); const value = nativeReply('native.Status', addon.seal()); if (value.phase !== 'closing' || value.liveBindings !== 0 || value.hooks !== installed.hooks || value.appliedHooks !== installed.appliedHooks) refuse(); failed = true; return value; }
        catch { return fail(); }
      } });
  } catch { return fail(); }
}
