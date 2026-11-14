import { unavailable } from '../contracts/errors.js';
import type { CommandPorts } from './ports.js';

/** ABR-1 has no production native adapter, watchdog, qualified manifest or host.
 * There are intentionally no Electron imports or page/shell constructors here.
 * Later startup must replace this refusal with qualified preflight before any
 * view can be created; a JavaScript shield or support.node is never readiness. */
export async function preflightPageAdmission(): Promise<never> {
  throw unavailable('browser');
}

export const foundationPorts: CommandPorts = Object.freeze({
  process: Object.freeze({
    open: async () => preflightPageAdmission(),
    close: async () => { throw unavailable('browser'); },
    mcp: async () => { throw unavailable('browser'); },
  }),
  profiles: Object.freeze({
    list: async () => { throw unavailable('profile'); },
    create: async () => { throw unavailable('profile'); },
    remove: async () => { throw unavailable('profile'); },
  }),
});

// Explicit production primitives only. Ordinary entry above still refuses pages.
import { verifyNativeCandidate, assertCandidateTrust, type CandidateTrust } from '../native/manifest.js';
import { loadPlatform, type HeldLock, type PlatformPort } from './platform.js';
import { startNativeWatchdog, type NativeWatchdog } from '../native/watchdog.js';
export interface NativeBoundaryPreparation {
  readonly trust: CandidateTrust;
  readonly platform: PlatformPort;
  arm(owner: HeldLock, build: HeldLock): Promise<NativeWatchdog>;
}
const preparations = new WeakSet<object>();
let boundaryAttempted = false;
/** Initial independent publisher verification precedes process-addon loading.
 * ABR-29 acquires real owner/Build handles using this exact platform instance. */
export function prepareNativeBoundary(bundle: string): NativeBoundaryPreparation {
  if (boundaryAttempted || process.type !== 'browser') throw unavailable('browser');
  boundaryAttempted = true;
  const trust = verifyNativeCandidate(bundle), platform = loadPlatform();
  let armAttempted = false;
  const prepared: NativeBoundaryPreparation = Object.freeze({ trust, platform,
    async arm(owner: HeldLock, build: HeldLock): Promise<NativeWatchdog> {
      if (armAttempted) throw unavailable('browser'); armAttempted = true;
      assertCandidateTrust(trust);
      const custody = platform.prepareWatchdogCustody(owner, build, trust.bundle, trust.snapshotDigest);
      return startNativeWatchdog(trust, custody);
    } });
  preparations.add(prepared); return prepared;
}
export function assertNativeBoundaryPreparation(value: NativeBoundaryPreparation): void {
  if (!preparations.has(value)) throw unavailable('browser');
}
