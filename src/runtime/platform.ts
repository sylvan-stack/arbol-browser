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
  /** Only actual native spawn transports the private finalization/state FDs.
   * These numbers are genuine pipe endpoints, never a shared-state writer. */
  spawn(): Readonly<{ pid: number; reader: number; writer: number }>;
  prepareHost(input: HostFinalizationInput): void;
  assertHost(): void;
  beginMarkerMutation(bytes: string): import('../profiles/compatibility.js').EngineMutation;
  assertMarker(): void;
  /** Native shared attribution precedes any JS/native cleanup; no raw flags. */
  latchFatal(): void;
  now(): number;
  capture(primaryPid: number): void;
  bind(): void;
  assert(): void;
  terminate(): never;
}
export type PriorMarkerExpectation = Readonly<{ kind: 'absent' } | { kind: 'activated' | 'terminal'; path: string; digest: string }>;
export interface HostFinalizationInput {
  readonly requestPath: string;
  readonly runtime: import('./instance.js').RuntimeRecord;
  /** Expectation only. Independent PreviousExit and actual post-enrollment
   * marker binding must still verify it before any engine/data admission. */
  readonly prior: PriorMarkerExpectation;
}
const custodyReceipts = new WeakSet<object>();
export function assertWatchdogCustody(value: WatchdogCustody): void {
  if (!custodyReceipts.has(value)) throw unavailable('browser');
}
export interface PlatformPort {
  /** One-use fixed-exec native adoption. No numeric FD or role is accepted. */
  adoptHostBuild(requestPath: string, guard: string, bundle: string): HeldLock;
  /** Kernel continuous time shared by native outer, host and both monitors. */
  continuousTime(): number;
  processProvenance(pid: number): ProcessProvenance | null;
  /** Private fixed claim.json transaction, only under the genuine claim.lock.
   * No caller-supplied destination or engine/profile payload read is exposed. */
  readLaunchAttempt(lock: HeldLock): string | null;
  writeLaunchAttempt(lock: HeldLock, expected: string | null, next: string): void;
  /** Prepare once from genuine original leases, then the existing canonical
   * bootstrap.arm consumes this exact custody/tuple; it never creates another.
   * Native retained descriptions, not this handover slot, protect the lifetime. */
  prepareHostCustody(owner: HeldLock, build: HeldLock, bundle: string, snapshotDigest: string, input: HostFinalizationInput): WatchdogCustody;
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
  beginHostMarkerMutation(handle: object, bytes: string): object;
  acceptHostMarkerMutation(handle: object): void;
  assertHostMarker(handle: object): void;
  abortHostMarkerMutation(handle: object): never;
  prepareHostFinalization(handle: object, input: string): void;
  spawnWatchdog(handle: object): { pid: number; reader: number; writer: number };
  assertHostFinalization(handle: object): void;
  latchWatchdogFatal(handle: object): void;
  adoptHostBuild(requestPath: string, guard: string, bundle: string): object;
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
    for (const name of ['beginHostMarkerMutation', 'acceptHostMarkerMutation', 'assertHostMarker', 'abortHostMarkerMutation', 'latchWatchdogFatal', 'prepareHostFinalization', 'spawnWatchdog', 'assertHostFinalization', 'adoptHostBuild', 'continuousTime', 'processProvenance', 'readLaunchAttempt', 'writeLaunchAttempt', 'tryLock', 'assertLock', 'releaseLock', 'processIdentity', 'peerIdentity', 'publishDirectory', 'trySharedLock', 'groupCensus', 'prepareWatchdogCustody', 'custodyDescriptors', 'captureWatchdog', 'watchdogBind', 'watchdogAssert', 'terminateProfileNow'] as const)
      if (typeof native[name] !== 'function') throw new Error('Missing process support');
  } catch { throw unavailable('profile'); }
  const call = <T>(operation: () => T): T => {
    try { return operation(); } catch { throw unavailable('profile'); }
  };
  const locks = new WeakMap<HeldLock, object>();
  const wrapLock = (handle: object, retained = false): HeldLock => {
    let released = false;
    const lease: HeldLock = Object.freeze({
      assertIdentity: () => { if (released) throw unavailable('profile'); return call(() => native.assertLock(handle)); },
      release: () => {
        if (retained) throw unavailable('profile');
        if (!released) { call(() => native.releaseLock(handle)); released = true; }
      },
    });
    locks.set(lease, handle); return lease;
  };
  let hostHandover: { owner: HeldLock; build: HeldLock; bundle: string; digest: string;
    custody: WatchdogCustody; consumed: boolean; prepared: boolean } | undefined;
  const makeCustody = (owner: HeldLock, build: HeldLock, bundle: string, digest: string): WatchdogCustody => {
      const a = locks.get(owner), b = locks.get(build);
      if (!a || !b || a === b || !isAbsolute(bundle) || !/^[0-9a-f]{64}$/.test(digest)) throw unavailable('browser');
      owner.assertIdentity(); build.assertIdentity();
      const handle = call(() => native.prepareWatchdogCustody(a, b, bundle, digest));
      const descriptors = call(() => native.custodyDescriptors(handle));
      if (descriptors.length !== 3 || descriptors.some(fd => !Number.isInteger(fd) || fd < 3) || new Set(descriptors).size !== 3) throw unavailable('browser');
      const receipt: WatchdogCustody = Object.freeze({ descriptors: Object.freeze([descriptors[0], descriptors[1]] as const), startupDescriptor: descriptors[2],
        spawn() {
          const value = call(() => native.spawnWatchdog(handle));
          if (!value || Object.keys(value).sort().join(',') !== 'pid,reader,writer' ||
              !Number.isSafeInteger(value.pid) || value.pid <= 1 ||
              ![value.reader, value.writer].every(fd => Number.isSafeInteger(fd) && fd >= 3) || value.reader === value.writer) throw unavailable('browser');
          return Object.freeze({ ...value });
        },
        prepareHost(input: HostFinalizationInput) {
          const encoded = JSON.stringify(input);
          if (!encoded || Buffer.byteLength(encoded) > 16384) throw unavailable('browser');
          call(() => native.prepareHostFinalization(handle, encoded));
        },
        assertHost: () => call(() => native.assertHostFinalization(handle)),
        assertMarker: () => call(() => native.assertHostMarker(handle)),
        beginMarkerMutation(bytes: string) {
          if (typeof bytes !== 'string' || Buffer.byteLength(bytes) > 16384) throw unavailable('browser');
          let accepted = false;
          const permit = call(() => native.beginHostMarkerMutation(handle, bytes));
          return Object.freeze({
            accept() {
              if (accepted) throw unavailable('browser');
              call(() => native.acceptHostMarkerMutation(permit)); accepted = true;
            },
            assertBound() { if (!accepted) throw unavailable('browser'); call(() => native.assertHostMarker(handle)); },
            abort(): never { native.abortHostMarkerMutation(permit); throw unavailable('browser'); },
          });
        },
        latchFatal: () => call(() => native.latchWatchdogFatal(handle)),
        now: () => call(() => native.continuousTime()),
        capture: (pid: number) => call(() => native.captureWatchdog(handle, pid)),
        bind: () => call(() => native.watchdogBind(handle)), assert: () => call(() => native.watchdogAssert(handle)),
        terminate: (): never => { native.terminateProfileNow(handle); throw unavailable('browser'); } });
      custodyReceipts.add(receipt); return receipt;
  };
  const port: PlatformPort = Object.freeze({
    adoptHostBuild(requestPath: string, guard: string, bundle: string): HeldLock {
      if (process.type !== 'browser' || ![requestPath, guard, bundle].every(path => isAbsolute(path) && !path.includes('\0')))
        throw unavailable('browser');
      const lease = wrapLock(call(() => native.adoptHostBuild(requestPath, guard, bundle)), true);
      lease.assertIdentity(); return lease;
    },
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
    prepareHostCustody(owner: HeldLock, build: HeldLock, bundle: string, digest: string, input: HostFinalizationInput): WatchdogCustody {
      if (hostHandover || process.type !== 'browser') throw unavailable('browser');
      const custody = makeCustody(owner, build, bundle, digest);
      hostHandover = { owner, build, bundle, digest, custody, consumed: false, prepared: false };
      try { custody.prepareHost(input); hostHandover.prepared = true; return custody; }
      catch { return custody.terminate(); }
    },
    prepareWatchdogCustody(owner: HeldLock, build: HeldLock, bundle: string, digest: string): WatchdogCustody {
      if (!hostHandover) return makeCustody(owner, build, bundle, digest);
      const actual = hostHandover;
      if (!actual.prepared || actual.consumed || actual.owner !== owner || actual.build !== build || actual.bundle !== bundle || actual.digest !== digest)
        throw unavailable('browser');
      owner.assertIdentity(); build.assertIdentity(); actual.consumed = true; return actual.custody;
    },
    publishDirectory(source: string, destination: string): void {
      if (![source, destination].every(path => isAbsolute(path) && !path.includes('\0'))) throw unavailable('profile');
      call(() => native.publishDirectory(source, destination));
    },
    ...Object.fromEntries((['tryLock', 'trySharedLock'] as const).map(method => [method, (path: string): HeldLock | null => {
      if (!isAbsolute(path) || path.includes('\0')) throw unavailable('profile');
      const handle = call(() => native[method](path));
      if (handle === null) return null;
      return wrapLock(handle);
    }])) as Pick<PlatformPort, 'tryLock' | 'trySharedLock'>,
    groupCensus: (group: number) => call(() => native.groupCensus(group)),
    processIdentity: (pid: number) => call(() => native.processIdentity(pid)),
    peerIdentity: (fd: number) => call(() => native.peerIdentity(fd)),
  });
  platforms.add(port); return port;
}
