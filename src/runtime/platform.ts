import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { isAbsolute } from 'node:path';
import { unavailable } from '../contracts/errors.js';

export interface FileIdentity { readonly device: string; readonly inode: string; readonly uid: number }
export interface ProcessIdentity { readonly pid: number; readonly uid: number; readonly startId: string }
export interface GroupProcess extends ProcessIdentity { readonly group: number; readonly parentStartId: string; readonly executable: string }
export interface ProcessProvenance extends GroupProcess {
  readonly pidVersion: number; readonly session: number; readonly parentPidVersion: number;
}
export interface HeldLock {
  /** Check the retained descriptor against the published pathname after waits/transactions. */
  assertIdentity(): FileIdentity;
  /** Caller retains this object through flush and complete helper shutdown. Never unlinks. */
  release(): void;
}
export interface WatchdogCustody {
  readonly descriptors: readonly [number, number];
  readonly startupDescriptor: number;
  capture(primaryPid: number): void;
  bind(): void;
  assert(): void;
  terminate(): never;
}
const custodyReceipts = new WeakSet<object>();
export function assertWatchdogCustody(value: WatchdogCustody): void {
  if (!custodyReceipts.has(value)) throw unavailable('browser');
}
export interface PlatformPort {
  /** Kernel continuous time shared by native outer, host and both monitors. */
  continuousTime(): number;
  processProvenance(pid: number): ProcessProvenance | null;
  /** Private fixed claim.json transaction, only under the genuine claim.lock.
   * No caller-supplied destination or engine/profile payload read is exposed. */
  readLaunchAttempt(lock: HeldLock): string | null;
  writeLaunchAttempt(lock: HeldLock, expected: string | null, next: string): void;
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
  continuousTime(): number;
  processProvenance(pid: number): ProcessProvenance | null;
  readLaunchAttempt(handle: object): string | null;
  writeLaunchAttempt(handle: object, expected: string | null, next: string): void;
  prepareWatchdogCustody(owner: object, build: object, bundle: string, digest: string): object;
  custodyDescriptors(handle: object): [number, number, number];
  captureWatchdog(handle: object, pid: number): void;
  watchdogBind(handle: object): void;
  watchdogAssert(handle: object): void;
  terminateProfileNow(handle: object): never;

  publishDirectory(source: string, destination: string): void;
  tryLock(path: string): object | null;
  trySharedLock(path: string): object | null;
  groupCensus(group: number): GroupProcess[];
  assertLock(handle: object): FileIdentity;
  releaseLock(handle: object): void;
  processIdentity(pid: number): ProcessIdentity | null;
  peerIdentity(fd: number): ProcessIdentity;
}
const platforms = new WeakSet<object>();
export function assertPlatform(value: PlatformPort): void {
  if (!platforms.has(value)) throw unavailable('profile');
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
    for (const name of ['continuousTime', 'processProvenance', 'readLaunchAttempt', 'writeLaunchAttempt', 'tryLock', 'assertLock', 'releaseLock', 'processIdentity', 'peerIdentity', 'publishDirectory', 'trySharedLock', 'groupCensus', 'prepareWatchdogCustody', 'custodyDescriptors', 'captureWatchdog', 'watchdogBind', 'watchdogAssert', 'terminateProfileNow'] as const)
      if (typeof native[name] !== 'function') throw new Error('Missing process support');
  } catch { throw unavailable('profile'); }
  const call = <T>(operation: () => T): T => {
    try { return operation(); } catch { throw unavailable('profile'); }
  };
  const locks = new WeakMap<HeldLock, object>();
  const port: PlatformPort = Object.freeze({
    continuousTime(): number {
      const value = call(() => native.continuousTime());
      if (!Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) throw unavailable('profile');
      return value;
    },
    processProvenance(pid: number): ProcessProvenance | null {
      const value = call(() => native.processProvenance(pid));
      if (value === null) return null;
      if (!value || Object.keys(value).sort().join(',') !== 'executable,group,parentPidVersion,parentStartId,pid,pidVersion,session,startId,uid' ||
          value.pid !== pid || ![value.pid, value.pidVersion, value.group, value.session].every(n => Number.isSafeInteger(n) && n > 0) ||
          !Number.isSafeInteger(value.uid) || value.uid !== process.geteuid?.() ||
          !Number.isSafeInteger(value.parentPidVersion) || value.parentPidVersion < 0 ||
          !/^[1-9][0-9]{0,19}$/.test(value.startId) || !/^(0|[1-9][0-9]{0,19})$/.test(value.parentStartId) ||
          typeof value.executable !== 'string' || !isAbsolute(value.executable) || value.executable.includes('\0')) throw unavailable('profile');
      return Object.freeze({ ...value });
    },
    readLaunchAttempt(lock: HeldLock): string | null {
      const handle = locks.get(lock); if (!handle) throw unavailable('profile'); lock.assertIdentity();
      const value = call(() => native.readLaunchAttempt(handle));
      if (value !== null && (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > 16384)) throw unavailable('profile');
      lock.assertIdentity(); return value;
    },
    writeLaunchAttempt(lock: HeldLock, expected: string | null, next: string): void {
      const handle = locks.get(lock); if (!handle || typeof next !== 'string' || !next.length || Buffer.byteLength(next) > 16384 ||
          (expected !== null && (typeof expected !== 'string' || !expected.length || Buffer.byteLength(expected) > 16384))) throw unavailable('profile');
      lock.assertIdentity(); call(() => native.writeLaunchAttempt(handle, expected, next)); lock.assertIdentity();
    },
    prepareWatchdogCustody(owner: HeldLock, build: HeldLock, bundle: string, digest: string): WatchdogCustody {
      const a = locks.get(owner), b = locks.get(build);
      if (!a || !b || a === b || !isAbsolute(bundle) || !/^[0-9a-f]{64}$/.test(digest)) throw unavailable('browser');
      owner.assertIdentity(); build.assertIdentity();
      const handle = call(() => native.prepareWatchdogCustody(a, b, bundle, digest));
      const descriptors = call(() => native.custodyDescriptors(handle));
      if (descriptors.length !== 3 || descriptors.some(fd => !Number.isInteger(fd) || fd < 3) || new Set(descriptors).size !== 3) throw unavailable('browser');
      const receipt: WatchdogCustody = Object.freeze({ descriptors: Object.freeze([descriptors[0], descriptors[1]] as const), startupDescriptor: descriptors[2],
        capture: (pid: number) => call(() => native.captureWatchdog(handle, pid)),
        bind: () => call(() => native.watchdogBind(handle)), assert: () => call(() => native.watchdogAssert(handle)),
        terminate: (): never => { native.terminateProfileNow(handle); throw unavailable('browser'); } });
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
  platforms.add(port); return port;
}
