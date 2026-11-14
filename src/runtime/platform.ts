import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { isAbsolute } from 'node:path';
import { unavailable } from '../contracts/errors.js';

export interface FileIdentity { readonly device: string; readonly inode: string; readonly uid: number }
export interface ProcessIdentity { readonly pid: number; readonly uid: number; readonly startId: string }
export interface GroupProcess extends ProcessIdentity { readonly group: number; readonly parentStartId: string; readonly executable: string }
export interface HeldLock {
  /** Check the retained descriptor against the published pathname after waits/transactions. */
  assertIdentity(): FileIdentity;
  /** Caller retains this object through flush and complete helper shutdown. Never unlinks. */
  release(): void;
}
export interface WatchdogCustody {
  readonly descriptors: readonly [number, number];
  record(primaryPid: number): string;
  bind(): void;
  assert(): void;
}
const custodyReceipts = new WeakSet<object>();
export function assertWatchdogCustody(value: WatchdogCustody): void {
  if (!custodyReceipts.has(value)) throw unavailable('browser');
}
export interface PlatformPort {
  prepareWatchdogCustody(owner: HeldLock, build: HeldLock, bundle: string, snapshotDigest: string): WatchdogCustody;

  /** Same-parent atomic directory publication; refuses every existing destination. */
  publishDirectory(source: string, destination: string): void;
  /** Nonblocking: null means contention. The caller enforces its monotonic deadline. */
  tryLock(absolutePath: string): HeldLock | null;
  trySharedLock(absolutePath: string): HeldLock | null;
  /** Observation only: cannot prove flush, escaped-helper death or executable trust. */
  groupCensus(group: number): readonly GroupProcess[];
  /** null means kernel ESRCH only; denied/uncertain observation throws unavailability. */
  processIdentity(pid: number): ProcessIdentity | null;
  /** Connected AF_UNIX stream FD owned by the caller; verifies UID, PID and kernel PID version. */
  peerIdentity(socketFd: number): ProcessIdentity;
}
interface NativeSupport {
  prepareWatchdogCustody(owner: object, build: object, bundle: string, digest: string): object;
  custodyDescriptors(handle: object): [number, number];
  watchdogRecord(handle: object, pid: number): string;
  watchdogBind(handle: object): void;
  watchdogAssert(handle: object): void;

  publishDirectory(source: string, destination: string): void;
  tryLock(path: string): object | null;
  trySharedLock(path: string): object | null;
  groupCensus(group: number): GroupProcess[];
  assertLock(handle: object): FileIdentity;
  releaseLock(handle: object): void;
  processIdentity(pid: number): ProcessIdentity | null;
  peerIdentity(fd: number): ProcessIdentity;
}

/** Explicit lazy loading: CLI info and schema parsing never load this private module.
 * ABR-2 injects this port into its locking code. It is not the BRW-4 input adapter.
 * Callers first validate canonical/private ancestors and recheck profile instance.
 * No JavaScript lockfile or PID-only implementation is an allowed fallback. */
export function loadPlatform(): PlatformPort {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw unavailable('profile');
  let native: NativeSupport;
  try {
    native = createRequire(import.meta.url)(fileURLToPath(new URL('../../native/platform.node', import.meta.url)));
    for (const name of ['tryLock', 'assertLock', 'releaseLock', 'processIdentity', 'peerIdentity', 'publishDirectory', 'trySharedLock', 'groupCensus', 'prepareWatchdogCustody', 'custodyDescriptors', 'watchdogRecord', 'watchdogBind', 'watchdogAssert'] as const)
      if (typeof native[name] !== 'function') throw new Error('Missing process support');
  } catch { throw unavailable('profile'); }
  const call = <T>(operation: () => T): T => {
    try { return operation(); } catch { throw unavailable('profile'); }
  };
  const locks = new WeakMap<HeldLock, object>();
  return Object.freeze({
    prepareWatchdogCustody(owner: HeldLock, build: HeldLock, bundle: string, digest: string): WatchdogCustody {
      const a = locks.get(owner), b = locks.get(build);
      if (!a || !b || a === b || !isAbsolute(bundle) || !/^[0-9a-f]{64}$/.test(digest)) throw unavailable('browser');
      owner.assertIdentity(); build.assertIdentity();
      const handle = call(() => native.prepareWatchdogCustody(a, b, bundle, digest));
      const descriptors = call(() => native.custodyDescriptors(handle));
      if (descriptors.length !== 2 || descriptors.some(fd => !Number.isInteger(fd) || fd < 3) || descriptors[0] === descriptors[1]) throw unavailable('browser');
      const receipt: WatchdogCustody = Object.freeze({ descriptors: Object.freeze(descriptors),
        record: (pid: number) => call(() => native.watchdogRecord(handle, pid)),
        bind: () => call(() => native.watchdogBind(handle)), assert: () => call(() => native.watchdogAssert(handle)) });
      custodyReceipts.add(receipt); return receipt;
    },
    publishDirectory(source: string, destination: string): void {
      if (![source, destination].every(path => isAbsolute(path) && !path.includes('\0'))) throw unavailable('profile');
      call(() => native.publishDirectory(source, destination));
    },
    ...Object.fromEntries((['tryLock', 'trySharedLock'] as const).map(method => [method, (path: string): HeldLock | null => {
      if (!isAbsolute(path) || path.includes('\0')) throw unavailable('profile');
      const handle = call(() => native[method](path));
      if (handle === null) return null;
      let released = false;
      const lease: HeldLock = Object.freeze({
        assertIdentity: () => { if (released) throw unavailable('profile'); return call(() => native.assertLock(handle)); },
        release: () => { if (!released) { released = true; call(() => native.releaseLock(handle)); } },
      });
      locks.set(lease, handle); return lease;
    }])) as Pick<PlatformPort, 'tryLock' | 'trySharedLock'>,
    groupCensus: (group: number) => call(() => native.groupCensus(group)),
    processIdentity: (pid: number) => call(() => native.processIdentity(pid)),
    peerIdentity: (fd: number) => call(() => native.peerIdentity(fd)),
  });
}
