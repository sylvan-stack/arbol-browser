/** Main-process only, single attempt native preflight. This is not page authority. */
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { release } from 'node:os';
import { isMainThread } from 'node:worker_threads';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
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
  assertIntegrity(): NativeStatus;
  /** Applies integrity checks both before dispatch and after async settlement. */
  guard<T>(operation: () => T | Promise<T>): Promise<T>;
  seal(): NativeStatus;
}
export function preflightNative(bundle: string, fatal: (reason: string) => void): NativeCompatibility {
  if (attempted) return refuse();
  attempted = true;
  let failed = false;
  const fail = (): never => { failed = true; fatal('native_integrity_unavailable'); return refuse(); };
  try {
    if (!isMainThread || process.type !== 'browser' || typeof fatal !== 'function') refuse();
    const actual = { electron: process.versions.electron, chromium: process.versions.chrome, node: process.versions.node,
      napi: process.versions.napi, modules: process.versions.modules, platform: process.platform, arch: process.arch,
      // Darwin 26 is macOS 27; exact product version is checked independently below.
      macOS: process.getSystemVersion?.() };
    if (!release() || stable(actual) !== stable(pinnedRuntime)) refuse();
    for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'ELECTRON_EXTRA_LAUNCH_ARGS', 'ELECTRON_OVERRIDE_DIST_PATH', 'ELECTRON_RUN_AS_NODE', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH'])
      if (process.env[key] !== undefined) refuse();
    const trust = verifyNativeCandidate(bundle);
    const addon: CompatibilityAddon = createRequire(import.meta.url)(join(trust.bundle, 'Contents/Resources/browser/native/ownership.node')) as CompatibilityAddon;
    const expected = ['getABI', 'install', 'status', 'checkIntegrity', 'seal'];
    if (Object.getOwnPropertyNames(addon).sort().join(',') !== expected.sort().join(',') || expected.some(key => typeof addon[key as keyof CompatibilityAddon] !== 'function')) refuse();
    const inventory = nativeReply('native.Inventory', addon.getABI());
    if (stable(inventory) !== stable(trust.manifest.nativeABI)) refuse();
    const installed = nativeReply('native.Status', addon.install(JSON.stringify(trust.manifest.nativeABI)));
    if (installed.phase !== 'ready' || installed.hooks === 0 || installed.hooks !== installed.appliedHooks) refuse();
    const assertIntegrity = (): NativeStatus => {
      try {
        if (failed) return refuse();
        const value = nativeReply('native.Status', addon.checkIntegrity());
        if (value.phase !== 'ready' || value.hooks !== installed.hooks || value.appliedHooks !== installed.appliedHooks) refuse();
        return value;
      } catch { return fail(); }
    };
    return Object.freeze({ trust, pageAdmission: false as const, assertIntegrity,
      async guard<T>(operation: () => T | Promise<T>): Promise<T> { assertIntegrity(); const result = await operation(); assertIntegrity(); return result; },
      seal(): NativeStatus {
        try { failed = true; const value = nativeReply('native.Status', addon.seal()); if (value.phase !== 'closing') refuse(); return value; }
        catch { return fail(); }
      } });
  } catch { return fail(); }
}
