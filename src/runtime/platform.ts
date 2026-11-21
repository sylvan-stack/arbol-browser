import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { isAbsolute } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { unavailable } from '../contracts/errors.js';
import { assertActualSessionFactory, consumeActualSessionSeal, type ActualSessionFactory, type ActualSessionSeal } from '../profiles/session.js';
import { assertHostCustody, type HostCustody } from './custody.js';

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
/** Genuine one-command native receipt; numeric fields are observations, never
 * transferable authority. The private native handle stays in this port. */
export interface CloseBudget { readonly received: number; readonly grace: number; readonly overall: number }
export interface CloseAdmission extends CloseBudget { readonly kind: 'management' | 'local-window' }
export interface WebsiteSessionReceipt {
  pagesRetired(): void;
  domRequested(): void;
  cookieAcknowledged(): void;
  quitIntended(): void;
}
export interface SessionUsePermit {
  accept(seal: ActualSessionSeal): WebsiteSessionReceipt;
  abort(): never;
}
export interface WatchdogCustody {
  readonly descriptors: readonly [number, number];
  readonly startupDescriptor: number;
  /** Only actual native spawn transports the private finalization/state FDs.
   * These numbers are genuine pipe endpoints, never a shared-state writer. */
  spawn(): Readonly<{ pid: number; reader: number; writer: number }>;
  prepareHost(input: HostFinalizationInput): void;
  ready(runtime: import('./instance.js').RuntimeRecord, agent: number, management: number): void;
  consumeClose(requestId: string, socketFd: number): CloseAdmission;
  localClose(): CloseAdmission;
  beginSessionUse(factory: ActualSessionFactory): SessionUsePermit;
  assertHost(): void;
  beginMarkerMutation(bytes: string): import('../profiles/compatibility.js').EngineMutation;
  assertMarker(): void;
  /** Native shared attribution precedes any JS/native cleanup; no raw flags. */
  latchFatal(): void;
  /** Optional warning only, on this genuine receipt and existing native handle. */
  noteLoss?(stage: HostLossStage): void;
  now(): number;
  capture(primaryPid: number): void;
  bind(): void;
  assert(): void;
  terminate(): never;
}
export type PriorMarkerExpectation = Readonly<{ kind: 'absent' } | { kind: 'activated' | 'terminal'; path: string; digest: string }>;
export interface NativeExitInput {
  readonly format: 1;
  readonly mode: 'prior' | 'host' | 'full' | 'retire' | 'reserve' | 'withdraw';
  readonly profile: string; readonly profileInstance: string; readonly profilePathHash: string;
  readonly runtimeLeaf: string; readonly bundle: string;
  readonly attempt: import('./process.js').LaunchAttempt | null;
  readonly previous: import('./instance.js').RuntimeRecord | null;
  readonly dataAttempt?: import('./process.js').LaunchAttempt | null;
  readonly pending?: import('./process.js').LaunchAttempt | null;
}
export interface ExitInspectionReceipt {
  readonly kind: 'never-opened' | 'activated' | 'terminal' | 'withdrawn'; readonly clean: boolean;
  readonly prior: PriorMarkerExpectation; readonly request: string | null;
}
const exitInspectionReceipts = new WeakSet<object>();
export function assertExitInspectionReceipt(value: ExitInspectionReceipt): void {
  if (!exitInspectionReceipts.has(value)) throw unavailable('profile');
}
export interface HostFinalizationInput {
  readonly requestPath: string;
  readonly signedPolicy: Readonly<{ policyDigest: string; compatibilityDigest: string }>;
  readonly runtime: import('./instance.js').RuntimeRecord;
  /** Expectation only. Independent PreviousExit and actual post-enrollment
   * marker binding must still verify it before any engine/data admission. */
  readonly prior: PriorMarkerExpectation;
}
const custodyReceipts = new WeakSet<object>();
export function assertWatchdogCustody(value: WatchdogCustody): void {
  if (!custodyReceipts.has(value)) throw unavailable('browser');
}
/** Native-verified process-lifetime protection, not a clipboard operation or
 * a caller-created readiness fact. The handle stays inside this provider. */
export interface SystemClipboardProtection { readonly scope: 'browser-general-pasteboard' }
const clipboardProtections = new WeakMap<SystemClipboardProtection, { custody: HostCustody; check: () => void }>();
export function assertSystemClipboardProtection(value: SystemClipboardProtection, custody: HostCustody): void {
  const actual = clipboardProtections.get(value);
  if (!actual || actual.custody !== custody) throw unavailable('browser');
  actual.check();
}
const hostLossStages = Object.freeze(['watchdog-spawn-loss', 'watchdog-readiness-loss', 'watchdog-pipe-error', 'watchdog-pipe-end', 'watchdog-ack-malformed', 'watchdog-ack-order', 'watchdog-ack-expiry', 'watchdog-custody-refusal', 'watchdog-termination', 'watchdog-transport-loss', 'native_integrity_unavailable', 'native_retirement_unavailable', 'native_watchdog_unavailable', 'native_boundary_unavailable'] as const);
export type HostLossStage = typeof hostLossStages[number];
const hostStartupStages = Object.freeze(['arm-readback', 'native-install-snapshot', 'native-feature-addon-preflight',
  'engine-authority', 'owned-lease-policy', 'engine-owner-policy', 'marker-read',
  'existing-marker-compatibility', 'fresh-marker-compatibility', 'verified-prior-exit', 'native-marker-permit', ...hostLossStages,
  'host-session-configure-before',
  'host-session-configure-after',
  'host-session-bind-before',
  'host-session-bind-after',
  'host-control-prepare-before',
  'host-control-prepare-after',
  'host-shell-port-before',
  'host-shell-port-after',
  'host-shell-integrate-before',
  'host-shell-integrate-after',
  'host-control-bind-before',
  'host-control-bind-after',
  'host-listeners-before',
  'host-listeners-after',
  'host-lifecycle-bind-before',
  'host-lifecycle-bind-after',
  'host-shell-load-before',
  'host-shell-load-after',
  'host-lifecycle-ready-before',
  'host-lifecycle-ready-after',
  'lifecycle-control-proof-before',
  'lifecycle-control-proof-after',
  'lifecycle-arm-before',
  'lifecycle-arm-after',
  'lifecycle-readiness-prepare-before',
  'lifecycle-readiness-prepare-after',
  'lifecycle-native-proof-before',
  'lifecycle-native-proof-after',
  'lifecycle-engine-proof-before',
  'lifecycle-engine-proof-after',
  'lifecycle-build-proof-before',
  'lifecycle-build-proof-after',
  'lifecycle-owner-proof-before',
  'lifecycle-owner-proof-after',
  'lifecycle-public-ready-before',
  'lifecycle-public-ready-after',
  'lifecycle-final-trust-before',
  'lifecycle-final-trust-after',
  'protected-ready-validate-before',
  'protected-ready-validate-after',
  'protected-claim-ready-before',
  'protected-claim-ready-after',
  'ready-trust-metadata-before',
  'ready-trust-metadata-after',
  'ready-trust-isolation-before',
  'ready-trust-isolation-after',
  'ready-trust-guard-before',
  'ready-trust-guard-after',
  'ready-trust-directories-before',
  'ready-trust-directories-after',
  'ready-trust-snapshot-before',
  'ready-trust-snapshot-after',
  'ready-trust-consume-before',
  'ready-trust-consume-after',
  'armed-trust-failure-bundle-selection',
  'armed-trust-failure-initial-snapshot',
  'armed-trust-failure-outer-signature-verification',
  'armed-trust-failure-outer-signature-details',
  'armed-trust-failure-outer-signature-entitlements',
  'armed-trust-failure-nested-signature-verification',
  'armed-trust-failure-nested-signature-details',
  'armed-trust-failure-nested-signature-entitlements',
  'armed-trust-failure-publisher',
  'armed-trust-failure-compatibility',
  'armed-trust-failure-inventory',
  'armed-trust-failure-final-snapshot',
  'armed-trust-failure-final-physical-comparison',
  'armed-trust-failure-repeated-snapshot',
  'armed-trust-failure-repeated-physical',
  'armed-trust-failure-repeated-manifest',
  'armed-trust-failure-repeated-cutoff',
  'armed-trust-failure-snapshot-receipt',
  'armed-trust-failure-verification-cutoff',
  'armed-trust-failure-snapshot-root-identity',
  'armed-trust-failure-snapshot-root-change-time',
  'armed-trust-failure-snapshot-entry-identity',
  'armed-trust-failure-snapshot-file-description',
  'armed-trust-failure-snapshot-file-read',
  'armed-trust-failure-storage-context',
  'armed-trust-failure-snapshot-symlink',
  'armed-trust-failure-snapshot-directory-membership',
  'armed-trust-failure-snapshot-encoded-mismatch',
  'armed-trust-failure-snapshot-filesystem'] as const);
export type HostStartupStage = typeof hostStartupStages[number];
export interface PlatformPort {
  /** Warning-only finite local milestone on the genuine original native handle. */
  noteHostStartup(custody: WatchdogCustody, stage: HostStartupStage): void;
  /** Before app readiness, actual Sessions and all chrome/website creation. */
  protectSystemClipboard(custody: HostCustody, deadline: number): Promise<SystemClipboardProtection>;
  /** Actual held owner and independently verified OLD Build; native claims,
   * complete receipts, physical metadata/marker/frontiers and full original
   * absence are verified off the caller event loop under the original bound. */
  inspectExit(owner: HeldLock, build: HeldLock, input: NativeExitInput, deadline: number, guards?: Readonly<{ data?: HeldLock; next?: HeldLock }>): Promise<ExitInspectionReceipt>;
  /** One-use fixed-exec native adoption. No numeric FD or role is accepted. */
  adoptHostBuild(requestPath: string, guard: string, bundle: string): HeldLock;
  adoptInstalledLaunch(bundle: string): { lock: HeldLock; deadline: number };
  /** Actual adopted original only: authentic no-use terminal or retained real
   * custody unwind, never normal adoption from cancellation or a public kill. */
  terminateAdoptedHost(build: HeldLock, owner?: HeldLock): never;
  /** Kernel continuous time shared by native outer, host and both monitors. */
  continuousTime(): number;
  captureCloseBudget(): CloseBudget;
  stampCloseRequest(budget: CloseBudget, runtimeLeaf: string, runtime: import('./instance.js').RuntimeRecord, requestId: string, socketFd: number): Promise<void>;
  retireCloseBudget(budget: CloseBudget): Promise<void>;
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
  noteHostStartup?(custody: object, stage: number): void;
  beginHostClipboard(custody: object): object;
  finishHostClipboard(custody: object, preparation: object): boolean;
  assertHostClipboard(custody: object, preparation: object): void;
  beginExitInspection(owner: object, build: object, input: string, nativeDeadline: number, data: object | null, next: object | null): object;
  pollExitInspection(handle: object): string | null;
  cancelExitInspection(handle: object): void;
  beginHostSessionUse(handle: object): object;
  acceptHostSessionUse(handle: object, facts: string): object;
  abortHostSessionUse(handle: object): never;
  recordPagesRetired(handle: object): void;
  recordDOMRequested(handle: object): void;
  recordCookieAcknowledged(handle: object): void;
  recordQuitIntended(handle: object): void;
  captureCloseBudget(): CloseBudget & { handle: object };
  beginCloseStamp(handle: object, runtimeLeaf: string, runtime: string, requestId: string, socketFd: number): void;
  pollCloseStamp(handle: object): number;
  cancelCloseStamp(handle: object): void;
  beginCloseRetirement(handle: object): void;
  pollCloseRetirement(handle: object): number;
  consumeCloseRequest(handle: object, requestId: string, socketFd: number): CloseAdmission;
  armLocalClose(handle: object): CloseAdmission;
  beginHostMarkerMutation(handle: object, bytes: string): object;
  acceptHostMarkerMutation(handle: object): void;
  assertHostMarker(handle: object): void;
  abortHostMarkerMutation(handle: object): never;
  prepareHostFinalization(handle: object, input: string, policyDigest: string, compatibilityDigest: string): void;
  publishHostReady(handle: object, runtime: string, agent: number, management: number): void;
  spawnWatchdog(handle: object): { pid: number; reader: number; writer: number };
  assertHostFinalization(handle: object): void;
  latchWatchdogFatal(handle: object): void;
  adoptHostBuild(requestPath: string, guard: string, bundle: string): object;
  adoptInstalledLaunch?(bundle: string): { lock: object; remaining: number };
  terminateAdoptedHost(build: object, owner: object | null): never;
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
    for (const name of ['publishHostReady', 'beginExitInspection', 'pollExitInspection', 'cancelExitInspection', 'beginHostSessionUse', 'acceptHostSessionUse', 'abortHostSessionUse', 'recordPagesRetired', 'recordDOMRequested', 'recordCookieAcknowledged', 'recordQuitIntended', 'captureCloseBudget', 'beginCloseStamp', 'pollCloseStamp', 'cancelCloseStamp', 'beginCloseRetirement', 'pollCloseRetirement', 'consumeCloseRequest', 'armLocalClose', 'beginHostMarkerMutation', 'acceptHostMarkerMutation', 'assertHostMarker', 'abortHostMarkerMutation', 'latchWatchdogFatal', 'prepareHostFinalization', 'spawnWatchdog', 'assertHostFinalization', 'adoptHostBuild', 'terminateAdoptedHost', 'continuousTime', 'processProvenance', 'readLaunchAttempt', 'writeLaunchAttempt', 'tryLock', 'assertLock', 'releaseLock', 'processIdentity', 'peerIdentity', 'publishDirectory', 'trySharedLock', 'groupCensus', 'prepareWatchdogCustody', 'custodyDescriptors', 'captureWatchdog', 'watchdogBind', 'watchdogAssert', 'terminateProfileNow'] as const)
      if (typeof native[name] !== 'function') throw new Error('Missing process support');
    for (const name of ['beginHostClipboard', 'finishHostClipboard', 'assertHostClipboard'] as const)
      if (typeof native[name] !== 'function') throw new Error('Missing clipboard protection');
  } catch { throw unavailable('profile'); }
  const call = <T>(operation: () => T): T => {
    try { return operation(); } catch { throw unavailable('profile'); }
  };
  const locks = new WeakMap<HeldLock, object>();
  const budgets = new WeakMap<CloseBudget, object>();
  const consumedBudgets = new WeakMap<CloseBudget, object>();
  const custodyHandles = new WeakMap<WatchdogCustody, object>();
  let clipboardAttempted = false;
  const clockBudget = (value: CloseBudget): CloseBudget => {
    if (!value || ![value.received, value.grace, value.overall].every(n => Number.isFinite(n) && n > 0) ||
        Math.abs(value.grace - value.received - 5000) > 0.001 || Math.abs(value.overall - value.received - 8000) > 0.001)
      throw unavailable('browser');
    return Object.freeze({ received: value.received, grace: value.grace, overall: value.overall });
  };
  const closeAdmission = (value: CloseAdmission): CloseAdmission => {
    const budget = clockBudget(value);
    if (value.kind !== 'management' && value.kind !== 'local-window') throw unavailable('browser');
    return Object.freeze({ ...budget, kind: value.kind });
  };
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
          const encoded = JSON.stringify({ requestPath: input.requestPath, runtime: input.runtime, prior: input.prior });
          if (!encoded || Buffer.byteLength(encoded) > 16384) throw unavailable('browser');
          call(() => native.prepareHostFinalization(handle, encoded, input.signedPolicy.policyDigest, input.signedPolicy.compatibilityDigest));
        },
        ready(runtime: import('./instance.js').RuntimeRecord, agent: number, management: number) {
          if (![agent, management].every(fd => Number.isSafeInteger(fd) && fd >= 3) || agent === management) throw unavailable('browser');
          call(() => native.publishHostReady(handle, JSON.stringify(runtime), agent, management));
        },
        consumeClose: (requestId: string, socketFd: number) => closeAdmission(call(() => native.consumeCloseRequest(handle, requestId, socketFd))),
        localClose: () => closeAdmission(call(() => native.armLocalClose(handle))),
        beginSessionUse(factory: ActualSessionFactory): SessionUsePermit {
          assertActualSessionFactory(factory);
          const permit = call(() => native.beginHostSessionUse(handle)); let used = false;
          return Object.freeze({
            accept(seal: ActualSessionSeal): WebsiteSessionReceipt {
              if (used) throw unavailable('browser'); used = true;
              const encoded = JSON.stringify(consumeActualSessionSeal(factory, seal));
              if (!encoded || Buffer.byteLength(encoded) > 16384) throw unavailable('browser');
              const sealed = call(() => native.acceptHostSessionUse(permit, encoded));
              return Object.freeze({
                pagesRetired: () => call(() => native.recordPagesRetired(sealed)),
                domRequested: () => call(() => native.recordDOMRequested(sealed)),
                cookieAcknowledged: () => call(() => native.recordCookieAcknowledged(sealed)),
                quitIntended: () => call(() => native.recordQuitIntended(sealed)),
              });
            },
            abort(): never { native.abortHostSessionUse(permit); throw unavailable('browser'); },
          });
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
        noteLoss(stage: HostLossStage): void {
          try {
            const index = hostStartupStages.indexOf(stage);
            if (hostLossStages.includes(stage) && index >= 0 && typeof native.noteHostStartup === 'function')
              native.noteHostStartup(handle, index);
          } catch { /* Warning only: retain the original fatal/termination path. */ }
        },
        now: () => call(() => native.continuousTime()),
        capture: (pid: number) => call(() => native.captureWatchdog(handle, pid)),
        bind: () => call(() => native.watchdogBind(handle)), assert: () => call(() => native.watchdogAssert(handle)),
        terminate: (): never => { native.terminateProfileNow(handle); throw unavailable('browser'); } });
      custodyReceipts.add(receipt); custodyHandles.set(receipt, handle); return receipt;
  };
  const port: PlatformPort = Object.freeze({
    noteHostStartup(custody: WatchdogCustody, stage: HostStartupStage): void {
      try {
        const handle = custodyHandles.get(custody), index = hostStartupStages.indexOf(stage);
        if (handle && index >= 0 && typeof native.noteHostStartup === 'function') native.noteHostStartup(handle, index);
      } catch { /* Warning-only: preserve the actual operation and its error. */ }
    },
    async protectSystemClipboard(custody: HostCustody, deadline: number): Promise<SystemClipboardProtection> {
      assertHostCustody(custody);
      const actual = hostHandover;
      if (clipboardAttempted || !actual?.prepared || !actual.consumed || process.type !== 'browser' ||
          custody.host.signed.bundle !== actual.bundle || custody.host.signed.snapshotDigest !== actual.digest ||
          !Number.isFinite(deadline) || performance.now() >= deadline) throw unavailable('browser');
      clipboardAttempted = true;
      const handle = custodyHandles.get(actual.custody); if (!handle) return custody.terminate();
      const current = () => {
        assertHostCustody(custody);
        if (hostHandover !== actual || !actual.prepared || !actual.consumed ||
            custody.host.signed.bundle !== actual.bundle || custody.host.signed.snapshotDigest !== actual.digest)
          throw unavailable('browser');
      };
      let actualApp: typeof import('electron').app | undefined;
      let isReady: (() => boolean) | undefined;
      const preparing = () => {
        current();
        if (performance.now() >= deadline || (actualApp && (actualApp.isReady !== isReady || isReady!.call(actualApp))))
          throw unavailable('browser');
      };
      try {
        preparing();
        const address = 'electron';
        const actual = await import(address) as typeof import('electron');
        actualApp = actual.app;
        if (!actualApp || typeof actualApp.isReady !== 'function') throw unavailable('browser');
        isReady = actualApp.isReady; preparing();
        preparing(); await custody.host.assertTrusted(deadline); preparing();
        // Source hashing/signature verification runs in the retained native
        // worker. The real host heartbeat continues through every await.
        const preparation = call(() => native.beginHostClipboard(handle)); preparing();
        for (;;) {
          preparing(); const ready = call(() => native.finishHostClipboard(handle, preparation)); preparing();
          if (ready === true) break;
          if (ready !== false) throw unavailable('browser');
          await setTimeout(Math.min(20, Math.max(1, deadline - performance.now()))); preparing();
        }
        const check = () => { current(); call(() => native.assertHostClipboard(handle, preparation)); current(); };
        check();
        const protection: SystemClipboardProtection = Object.freeze({ scope: 'browser-general-pasteboard' });
        clipboardProtections.set(protection, { custody, check }); return protection;
      } catch { return custody.terminate(); }
    },
    adoptHostBuild(requestPath: string, guard: string, bundle: string): HeldLock {
      if (process.type !== 'browser' || ![requestPath, guard, bundle].every(path => isAbsolute(path) && !path.includes('\0')))
        throw unavailable('browser');
      const lease = wrapLock(call(() => native.adoptHostBuild(requestPath, guard, bundle)), true);
      lease.assertIdentity(); return lease;
    },
    adoptInstalledLaunch(bundle: string): { lock: HeldLock; deadline: number } {
      if (process.type === 'browser' || typeof native.adoptInstalledLaunch !== 'function' ||
          !isAbsolute(bundle) || bundle.includes('\0')) throw unavailable('browser');
      const adopt = native.adoptInstalledLaunch;
      const began = performance.now();
      const { lock, remaining } = call(() => adopt(bundle));
      if (!lock || typeof lock !== 'object' || !Number.isFinite(remaining) || remaining <= 0 || remaining > 60000)
        throw unavailable('browser');
      const held = wrapLock(lock);
      held.assertIdentity();
      return { lock: held, deadline: began + remaining };
    },
    continuousTime(): number {
      const value = call(() => native.continuousTime());
      if (!Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) throw unavailable('profile');
      return value;
    },
    captureCloseBudget(): CloseBudget {
      const value = call(() => native.captureCloseBudget()), receipt = clockBudget(value);
      if (!value.handle || typeof value.handle !== 'object') throw unavailable('browser');
      budgets.set(receipt, value.handle); return receipt;
    },
    async stampCloseRequest(budget: CloseBudget, runtimeLeaf: string, runtime: import('./instance.js').RuntimeRecord, requestId: string, socketFd: number): Promise<void> {
      const handle = budgets.get(budget); if (!handle) throw unavailable('browser'); budgets.delete(budget); consumedBudgets.set(budget, handle);
      if (!isAbsolute(runtimeLeaf) || runtimeLeaf.includes('\0') || !/^req_[A-Za-z0-9_-]{22}$/.test(requestId) ||
          !Number.isInteger(socketFd) || socketFd < 0) throw unavailable('browser');
      const encoded = JSON.stringify(runtime);
      if (!encoded || Buffer.byteLength(encoded) > 16384) throw unavailable('browser');
      let complete = false;
      try {
        call(() => native.beginCloseStamp(handle, runtimeLeaf, encoded, requestId, socketFd));
        for (;;) {
          const current = call(() => native.continuousTime());
          if (current >= budget.grace) throw unavailable('browser');
          const state = call(() => native.pollCloseStamp(handle));
          if (state === 1) { complete = true; return; }
          if (state !== 0) throw unavailable('browser');
          await setTimeout(Math.min(10, Math.max(1, budget.grace - current)));
        }
      } finally { if (!complete) call(() => native.cancelCloseStamp(handle)); }
    },
    async retireCloseBudget(budget: CloseBudget): Promise<void> {
      const handle = consumedBudgets.get(budget) ?? budgets.get(budget);
      if (!handle) throw unavailable('browser');
      budgets.delete(budget); consumedBudgets.delete(budget);
      call(() => native.beginCloseRetirement(handle));
      for (;;) {
        const current = call(() => native.continuousTime()), state = call(() => native.pollCloseRetirement(handle));
        if (state === 1) return;
        if (state !== 0 || current >= budget.overall) throw unavailable('browser');
        await setTimeout(Math.min(10, Math.max(1, budget.overall - current)));
      }
    },
    terminateAdoptedHost(build: HeldLock, owner?: HeldLock): never {
      const actual = locks.get(build), actualOwner = owner ? locks.get(owner) : null;
      if (!actual || (owner && !actualOwner)) throw unavailable('browser');
      build.assertIdentity(); owner?.assertIdentity(); return call(() => native.terminateAdoptedHost(actual, actualOwner ?? null));
    },
    async inspectExit(owner: HeldLock, build: HeldLock, input: NativeExitInput, deadline: number, guards?: Readonly<{ data?: HeldLock; next?: HeldLock }>): Promise<ExitInspectionReceipt> {
      const actualOwner = locks.get(owner), actualBuild = locks.get(build);
      if (!actualOwner || !actualBuild || !Number.isFinite(deadline)) throw unavailable('profile');
      owner.assertIdentity(); build.assertIdentity();
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      const nativeDeadline = nativeNow + Math.min(10000, deadline - sampled);
      const actualData = guards?.data ? locks.get(guards.data) : null, actualNext = guards?.next ? locks.get(guards.next) : null;
      if ((guards?.data && !actualData) || (guards?.next && !actualNext)) throw unavailable('profile');
      guards?.data?.assertIdentity(); guards?.next?.assertIdentity();
      const handle = call(() => native.beginExitInspection(actualOwner, actualBuild,
        JSON.stringify({ ...input, dataAttempt: input.dataAttempt ?? null, pending: input.pending ?? null }), nativeDeadline,
        actualData ?? null, actualNext ?? null));
      try {
        while (performance.now() < deadline && call(() => native.continuousTime()) < nativeDeadline) {
          const raw = call(() => native.pollExitInspection(handle));
          if (raw !== null) {
            if (typeof raw !== 'string' || !raw.length || Buffer.byteLength(raw) > 16384) throw unavailable('profile');
            const value = JSON.parse(raw) as ExitInspectionReceipt & { format: number };
            if (!value || Object.keys(value).sort().join(',') !== 'clean,format,kind,prior,request' || value.format !== 1 ||
                !['never-opened', 'activated', 'terminal', 'withdrawn'].includes(value.kind) || typeof value.clean !== 'boolean' ||
                value.clean !== (value.kind === 'activated') || (value.kind === 'withdrawn') !== (input.mode === 'withdraw') || (value.request !== null && !/^req_[A-Za-z0-9_-]{22}$/.test(value.request)))
              throw unavailable('profile');
            const prior = value.prior;
            if (!prior || (prior.kind === 'absent' ? Object.keys(prior).join(',') !== 'kind' :
                !['activated', 'terminal'].includes(prior.kind) || Object.keys(prior).sort().join(',') !== 'digest,kind,path' ||
                !isAbsolute(prior.path) || !/^[0-9a-f]{64}$/.test(prior.digest))) throw unavailable('profile');
            owner.assertIdentity(); build.assertIdentity(); guards?.data?.assertIdentity(); guards?.next?.assertIdentity();
            if (performance.now() >= deadline || call(() => native.continuousTime()) >= nativeDeadline) throw unavailable('profile');
            const result: ExitInspectionReceipt = Object.freeze({ kind: value.kind, clean: value.clean,
              prior: Object.freeze({ ...prior }), request: value.request });
            exitInspectionReceipts.add(result); return result;
          }
          await setTimeout(Math.min(5, Math.max(1, deadline - performance.now())));
        }
        throw unavailable('profile');
      } finally { call(() => native.cancelExitInspection(handle)); }
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
      // Native retains the adopted Build/owner descriptions even when host
      // preparation never reached complete authenticated enrollment. It cannot
      // downgrade that failure to the legacy signal-only termination provider.
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
