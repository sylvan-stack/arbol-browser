import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { isAbsolute } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import type { Contract } from '../contracts/generated.js';
import { assertActualSessionFactory, consumeActualSessionSeal, type ActualSessionFactory, type ActualSessionSeal } from '../profiles/session.js';

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
export interface MaintenanceGuard {
  readonly path: string;
  /** Original exclusive description, retained until process exit. */
  assertIdentity(): FileIdentity;
}
export interface MaintenanceFileEvidence {
  readonly identity: FileIdentity & Readonly<{ mode: number }>;
  readonly sha256: string;
}
export interface MaintenanceFacts {
  readonly scope: 'isolated' | 'installed'; readonly epoch: string;
  readonly bundle: string; readonly runtime: string; readonly stateRoot: string; readonly registry: string;
  readonly runtimeIdentity: FileIdentity & Readonly<{ mode: number }>;
  readonly policySha256: string; readonly hostPolicySha256: string;
  readonly launcherSha256: string; readonly imageSha256: string;
  readonly journalPath: string; readonly journal: MaintenanceFileEvidence;
  readonly selection: MaintenanceFileEvidence | null;
  readonly oldBuildPath: string | null; readonly newBuildPath: string;
}
export interface IsolatedMaintenanceInput {
  readonly scope: 'isolated'; readonly bundle: string; readonly policy: string; readonly runtime: string;
}
export interface InstalledMaintenanceInput { readonly scope: 'installed'; readonly bundle: string }
export interface MaintenanceCustody {
  readonly facts: MaintenanceFacts;
  readonly oldBuild: MaintenanceGuard | null;
  readonly newBuild: MaintenanceGuard;
  /** Adoption budget only. It never releases the closed admission epoch. */
  readonly deadline: number;
  assert(): void;
}

export const maintenanceStagingPoints = ['empty-staging', 'partial-staging', 'staged-record', 'staged-marker',
  'staged-progress', 'marker-rename', 'marker-durable'] as const;
export type MaintenanceStagingPoint = typeof maintenanceStagingPoints[number];
export type MaintenanceScratchPoint = 'empty-staging' | 'partial-staging';
export type MaintenanceScratch = Readonly<{ name: string; identity: MaintenanceFileEvidence['identity'] }>;
export type MaintenanceInterruptionPoint =
  | 'before-transaction' | 'transaction-publication' | 'current-publication' | 'native-rename-excl'
  | MaintenanceStagingPoint | 'record-rename' | 'record-durable'
  | 'claim-retained' | 'capture-durable' | 'receipt-durable' | 'committed-progress' | 'completion';

export type MaintenanceTransactionPoint = 'before-transaction' | 'transaction-publication' | 'current-publication';
export type MaintenanceProgressPoint = 'committed-progress' | 'completion';
export type MaintenanceProgressWitness = Readonly<{
  attempt: string;
  profileSha256: string | null;
  file: MaintenanceFileEvidence;
}>;
export type MaintenanceTransactionWitness = Readonly<{
  attempt: string;
  transaction: MaintenanceFileEvidence;
  current: MaintenanceFileEvidence | null;
}>;
export interface MaintenanceStateRoot {
  readonly path: string; readonly initial: 'absent' | 'present';
  readonly identity: MaintenanceFileEvidence['identity'] | null;
  readonly parent: Readonly<{ path: string; identity: MaintenanceFileEvidence['identity'] }>;
  readonly policySha256: string; readonly epoch: string;
  assert(): void;
}
const maintenanceReceipts = new WeakSet<object>();
export function assertMaintenanceCustody(value: MaintenanceCustody): void {
  if (!maintenanceReceipts.has(value)) throw unavailable('browser');
  value.assert();
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
export type PriorMarkerExpectation = Readonly<{ kind: 'absent' } | {
  kind: 'activated' | 'terminal'; path: string; digest: string;
  migration?: Readonly<{ path: string; digest: string }>;
}>;
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
export interface MigrationSourceObservation {
  readonly bundle: MaintenanceFileEvidence['identity']; readonly bundleStamp: string;
  readonly policy: MaintenanceFileEvidence; readonly policyStamp: string;
}
export type NativeMigrationInput = Omit<NativeExitInput, 'mode' | 'pending'> & Readonly<{
  mode: 'migrate-verify'; sources: Readonly<{ closed: MigrationSourceObservation | null; data: MigrationSourceObservation | null }>;
}>;
export type NativeMigrationCommitInput = Omit<NativeMigrationInput, 'mode'> & Readonly<{
  mode: 'migrate-commit'; migration: Readonly<{ attempt: string; transactionSha256: string }>;
}>;
export type NativeMigrationProgressInput = Omit<NativeMigrationCommitInput, 'mode' | 'sources'> & Readonly<{ mode: 'migrate-receipt-progress' }>;
export type NativeMigrationCommittedInput = Omit<NativeMigrationProgressInput, 'mode'> & Readonly<{ mode: 'migrate-committed-check' }>;
export type NativeMigrationRecoveryInput = Omit<NativeMigrationCommitInput, 'mode'> & Readonly<{ mode: 'migrate-recover' }>;
export interface MigrationRecoveryReceipt {
  readonly epoch: string; readonly attempt: string; readonly profileInstance: string; readonly profilePathHash: string;
  readonly record: MaintenanceFileEvidence;
}
export interface MigrationRecoveryPermit extends MigrationRecoveryReceipt {
  commit(): Promise<MigrationRecoveryReceipt>;
  cancel(): void;
}
const migrationRecoveryReceipts = new WeakSet<object>();
export function assertMigrationRecoveryReceipt(value: MigrationRecoveryReceipt, custody: MaintenanceCustody): void {
  assertMaintenanceCustody(custody);
  if (!migrationRecoveryReceipts.has(value) || value.epoch !== custody.facts.epoch) throw unavailable('profile');
}
export interface MigrationCommitReceipt {
  readonly epoch: string; readonly attempt: string; readonly profileInstance: string; readonly profilePathHash: string;
  readonly receipt: MaintenanceFileEvidence;
}
const migrationCommitReceipts = new WeakSet<object>();
export function assertMigrationCommitReceipt(value: MigrationCommitReceipt, custody: MaintenanceCustody): void {
  assertMaintenanceCustody(custody);
  if (!migrationCommitReceipts.has(value) || value.epoch !== custody.facts.epoch) throw unavailable('profile');
}
export interface MigrationCommittedValidation extends MigrationCommitReceipt {
  readonly committed: MaintenanceFileEvidence;
  readonly completion: MaintenanceFileEvidence | null;
}
const migrationCommittedValidations = new WeakSet<object>();
export function assertMigrationCommittedValidation(value: MigrationCommittedValidation, custody: MaintenanceCustody): void {
  assertMaintenanceCustody(custody);
  if (!migrationCommittedValidations.has(value) || value.epoch !== custody.facts.epoch) throw unavailable('profile');
}
export type MigrationCompletionEvidence = MigrationCommitReceipt | MigrationCommittedValidation;
export function assertMigrationCompletionEvidence(value: MigrationCompletionEvidence, custody: MaintenanceCustody): void {
  assertMaintenanceCustody(custody);
  if ((!migrationCommitReceipts.has(value) && !migrationCommittedValidations.has(value)) || value.epoch !== custody.facts.epoch)
    throw unavailable('profile');
}
export interface MigrationInspectionReceipt {
  readonly epoch: string; readonly profileInstance: string; readonly profilePathHash: string;
  readonly evidence: Readonly<Contract<'migration.Evidence'>>;
  readonly profileDirectory: Readonly<Contract<'migration.Identity'>>;
  readonly record: MaintenanceFileEvidence; readonly marker: MaintenanceFileEvidence | null;
}
const migrationInspectionReceipts = new WeakSet<object>();
export function assertMigrationInspectionReceipt(value: MigrationInspectionReceipt, custody: MaintenanceCustody): void {
  assertMaintenanceCustody(custody);
  if (!migrationInspectionReceipts.has(value) || value.epoch !== custody.facts.epoch) throw unavailable('profile');
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
  /** Actual held owner and independently verified OLD Build; native claims,
   * complete receipts, physical metadata/marker/frontiers and full original
   * absence are verified off the caller event loop under the original bound. */
  inspectExit(owner: HeldLock, build: HeldLock, input: NativeExitInput, deadline: number, guards?: Readonly<{ data?: HeldLock; next?: HeldLock }>): Promise<ExitInspectionReceipt>;
  inspectMigration(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: HeldLock | MaintenanceGuard,
    input: NativeMigrationInput, deadline: number, data?: HeldLock | MaintenanceGuard): Promise<MigrationInspectionReceipt>;
  commitMigration(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: HeldLock | MaintenanceGuard,
    input: NativeMigrationCommitInput, deadline: number, data?: HeldLock | MaintenanceGuard): Promise<MigrationCommitReceipt>;
  validateMigrationProgress(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: MaintenanceGuard,
    input: NativeMigrationProgressInput, deadline: number): Promise<MigrationCommitReceipt>;
  validateMigrationCommitted(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: MaintenanceGuard,
    input: NativeMigrationCommittedInput, deadline: number): Promise<MigrationCommittedValidation>;
  prepareMigrationRecovery(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: HeldLock | MaintenanceGuard,
    input: NativeMigrationRecoveryInput, deadline: number, data?: HeldLock | MaintenanceGuard): Promise<MigrationRecoveryPermit>;
  /** One-use fixed-exec native adoption. No numeric FD or role is accepted. */
  adoptHostBuild(requestPath: string, guard: string, bundle: string): HeldLock;
  adoptInstalledLaunch(bundle: string): { lock: HeldLock; deadline: number };
  inspectInstalledMountTopology?(bundle: string, root: number): string;
  adoptMaintenanceCustody(input: IsolatedMaintenanceInput | InstalledMaintenanceInput): MaintenanceCustody;
  /** Read-only query on an adopted custody. Only the real writer can stop. */
  maintenanceInterruptionMatches?(custody: MaintenanceCustody, point: MaintenanceInterruptionPoint): boolean;
  bindMaintenanceTransaction?(custody: MaintenanceCustody, attempt: string, archive: MaintenanceFileEvidence,
    registry: HeldLock | null, owners: readonly HeldLock[], deadline: number): void;
  /** Native resolves the fixed transaction paths and checks the actual files. */
  parkMaintenanceTransaction?(custody: MaintenanceCustody, point: MaintenanceTransactionPoint,
    witness: MaintenanceTransactionWitness, deadline: number): never;
  parkMaintenanceStaging?(custody: MaintenanceCustody, point: MaintenanceStagingPoint, attempt: string,
    profileSha256: string, staging: MaintenanceFileEvidence['identity'], scratch: MaintenanceScratch | null, deadline: number): never;
  parkMaintenanceProgress?(custody: MaintenanceCustody, point: MaintenanceProgressPoint,
    witness: MaintenanceProgressWitness, deadline: number): never;
  observeMaintenanceStateRoot(custody: MaintenanceCustody): MaintenanceStateRoot;
  publishMaintenanceFile(custody: MaintenanceCustody, source: string, destination: string,
    parent: MaintenanceFileEvidence['identity'], file: MaintenanceFileEvidence, deadline: number): void;
  /** Actual adopted original only: authentic no-use terminal or retained real
   * custody unwind, never normal adoption from cancellation or a public kill. */
  terminateAdoptedHost(build: HeldLock, owner?: HeldLock): never;
  /** Kernel continuous time shared by native outer, host and both monitors. */
  continuousTime(): number;
  captureCloseBudget(): CloseBudget;
  stampCloseRequest(budget: CloseBudget, runtimeLeaf: string, runtime: import('./instance.js').RuntimeRecord, requestId: string, socketFd: number): Promise<void>;
  retireCloseBudget(budget: CloseBudget): Promise<void>;
  processProvenance(pid: number): ProcessProvenance | null;
  requestProfileOpen?(profile: string, instance: string): boolean;
  browserAppAvailable?(): boolean;
  activateProfileWindow?(peer: ProcessIdentity): boolean;
  seqoyaBackendArguments?(peer: ProcessIdentity, runtime: string, entry: string, lock: string): boolean;
  /** Private fixed claim.json transaction, only under the genuine claim.lock.
   * No caller-supplied destination or engine/profile payload read is exposed. */
  readLaunchAttempt(lock: HeldLock): string | null;
  /** Format-2 selection hint only; native inspection still validates proof. */
  canonicalMigrationClaimDigest(claim: import('./process.js').LaunchAttempt): string;
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
  beginExitInspection(owner: object, build: object, input: string, nativeDeadline: number, data: object | null, next: object | null,
    registry?: object, maintenance?: object): object;
  pollExitInspection(handle: object): string | null;
  pollMigrationRecovery(handle: object): string | null;
  consumeMigrationRecovery(handle: object): void;
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
  inspectInstalledMountTopology?(bundle: string, root: number): string;
  adoptMaintenanceCustody?(bundle: string, policy: string | null, runtime: string | null): {
    handle: object; oldBuild: object | null; newBuild: object; facts: string; remaining: number;
  };
  assertMaintenanceCustody?(handle: object): void;
  maintenanceInterruptionMatches?(handle: object, point: MaintenanceInterruptionPoint): boolean;
  bindMaintenanceTransaction?(handle: object, archive: string, registry: object | null, owners: readonly object[], deadline: number): void;
  parkMaintenanceTransaction?(handle: object, point: MaintenanceTransactionPoint, witness: string, deadline: number): never;
  parkMaintenanceStaging?(handle: object, point: MaintenanceStagingPoint, witness: string, deadline: number): never;
  parkMaintenanceProgress?(handle: object, point: MaintenanceProgressPoint, witness: string, deadline: number): never;
  publishMaintenanceFile?(handle: object, source: string, destination: string, expected: string, deadline: number): void;
  observeMaintenanceStateRoot?(handle: object): string;
  assertMaintenanceStateRoot?(handle: object): void;
  terminateAdoptedHost(build: object, owner: object | null): never;
  continuousTime(): number;
  processProvenance(pid: number): ProcessProvenance | null;
  requestProfileOpen?(profile: string, instance: string): boolean;
  browserAppAvailable?(): boolean;
  activateProfileWindow?(pid: number, startId: string): boolean;
  seqoyaBackendArguments?(pid: number, start: string, runtime: string, entry: string, lock: string): boolean;
  readLaunchAttempt(handle: object): string | null;
  canonicalMigrationClaimDigest?(claim: string): string;
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
  } catch { throw unavailable('profile'); }
  const call = <T>(operation: () => T): T => {
    try { return operation(); } catch { throw unavailable('profile'); }
  };
  const locks = new WeakMap<HeldLock, object>();
  const budgets = new WeakMap<CloseBudget, object>();
  const consumedBudgets = new WeakMap<CloseBudget, object>();
  const custodyHandles = new WeakMap<WatchdogCustody, object>();
  const maintenanceHandles = new WeakMap<MaintenanceCustody, object>();
  const maintenanceBuildHandles = new WeakMap<MaintenanceGuard, object>();
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
    adoptHostBuild(requestPath: string, guard: string, bundle: string): HeldLock {
      if (process.type !== 'browser' || ![requestPath, guard, bundle].every(path => isAbsolute(path) && !path.includes('\0')))
        throw unavailable('browser');
      const lease = wrapLock(call(() => native.adoptHostBuild(requestPath, guard, bundle)), true);
      lease.assertIdentity(); return lease;
    },
    inspectInstalledMountTopology(bundle: string, root: number): string {
      if (!native.inspectInstalledMountTopology || !isAbsolute(bundle) || !Number.isSafeInteger(root) ||
          root < 3 || root > 0x7fffffff) throw unavailable('browser');
      const stamp = call(() => native.inspectInstalledMountTopology!(bundle, root));
      if (typeof stamp !== 'string' || !/^-?\d{1,10}:-?\d{1,10}$/.test(stamp)) throw unavailable('browser');
      return stamp;
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
    adoptMaintenanceCustody(input: IsolatedMaintenanceInput | InstalledMaintenanceInput): MaintenanceCustody {
      if (!input || process.type === 'browser' || !['isolated', 'installed'].includes(input.scope) ||
          Object.keys(input).sort().join(',') !== (input.scope === 'installed' ? 'bundle,scope' : 'bundle,policy,runtime,scope') ||
          !(input.scope === 'installed' ? [input.bundle] : [input.bundle, input.policy, input.runtime])
            .every(path => typeof path === 'string' && isAbsolute(path) && !path.includes('\0')) ||
          typeof native.adoptMaintenanceCustody !== 'function' || typeof native.assertMaintenanceCustody !== 'function')
        throw unavailable('browser');
      const adopt = native.adoptMaintenanceCustody, check = native.assertMaintenanceCustody;
      const began = performance.now();
      const value = call(() => adopt(input.bundle, input.scope === 'isolated' ? input.policy : null,
        input.scope === 'isolated' ? input.runtime : null));
      if (!value || !value.handle || typeof value.handle !== 'object' || !value.newBuild || typeof value.newBuild !== 'object' ||
          (value.oldBuild !== null && typeof value.oldBuild !== 'object') ||
          !Number.isFinite(value.remaining) || value.remaining <= 0 || value.remaining > 60000 || typeof value.facts !== 'string')
        throw unavailable('browser');
      const facts = call(() => JSON.parse(value.facts)) as MaintenanceFacts;
      const digest = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
      const identity = (i: MaintenanceFileEvidence['identity']): boolean => !!i &&
        /^[0-9]+$/.test(i.device) && /^[0-9]+$/.test(i.inode) && Number.isSafeInteger(i.uid) && i.uid === process.getuid?.();
      const evidence = (e: MaintenanceFileEvidence): boolean => !!e && identity(e.identity) && e.identity.mode === 0o600 && digest(e.sha256);
      if (!facts || facts.scope !== input.scope || facts.bundle !== input.bundle ||
          (input.scope === 'isolated' && facts.runtime !== input.runtime) ||
          ![facts.epoch, facts.policySha256, facts.hostPolicySha256, facts.launcherSha256, facts.imageSha256].every(digest) ||
          ![facts.runtime, facts.stateRoot, facts.registry, facts.journalPath, facts.newBuildPath].every(p => typeof p === 'string' && isAbsolute(p) && !p.includes('\0')) ||
          !identity(facts.runtimeIdentity) || facts.runtimeIdentity.mode !== 0o700 || !evidence(facts.journal) ||
          (facts.selection !== null && !evidence(facts.selection)) ||
          (facts.oldBuildPath === null) !== (value.oldBuild === null) ||
          (facts.oldBuildPath !== null && (typeof facts.oldBuildPath !== 'string' || !isAbsolute(facts.oldBuildPath))))
        throw unavailable('browser');
      const assert = () => call(() => check(value.handle));
      const guard = (handle: object, path: string): MaintenanceGuard => {
        const value: MaintenanceGuard = Object.freeze({ path,
          assertIdentity: () => { assert(); return call(() => native.assertLock(handle)); },
        });
        maintenanceBuildHandles.set(value, handle); return value;
      };
      Object.freeze(facts.runtimeIdentity); Object.freeze(facts.journal.identity); Object.freeze(facts.journal);
      if (facts.selection) { Object.freeze(facts.selection.identity); Object.freeze(facts.selection); }
      const custody: MaintenanceCustody = Object.freeze({ facts: Object.freeze(facts),
        oldBuild: value.oldBuild === null ? null : guard(value.oldBuild, facts.oldBuildPath!),
        newBuild: guard(value.newBuild, facts.newBuildPath), deadline: began + value.remaining, assert });
      assert(); maintenanceReceipts.add(custody); maintenanceHandles.set(custody, value.handle); return custody;
    },
    maintenanceInterruptionMatches(custody: MaintenanceCustody, point: MaintenanceInterruptionPoint): boolean {
      assertMaintenanceCustody(custody);
      const handle = maintenanceHandles.get(custody), matches = native.maintenanceInterruptionMatches;
      if (!handle || typeof matches !== 'function') throw unavailable('profile');
      const value = call(() => matches(handle, point));
      if (typeof value !== 'boolean') throw unavailable('profile');
      assertMaintenanceCustody(custody);
      return value;
    },
    bindMaintenanceTransaction(custody: MaintenanceCustody, attempt: string, archive: MaintenanceFileEvidence,
      registry: HeldLock | null, owners: readonly HeldLock[], deadline: number): void {
      assertMaintenanceCustody(custody);
      const handle = maintenanceHandles.get(custody), bind = native.bindMaintenanceTransaction;
      const registryHandle = registry === null ? null : locks.get(registry);
      if (!handle || typeof bind !== 'function' || registryHandle === undefined || owners.length > 4096 ||
          !/^[0-9a-f]{32}$/.test(attempt) || !validator('migration.File')(archive) || !Number.isFinite(deadline))
        throw unavailable('profile');
      const ownerHandles = owners.map(owner => {
        const value = locks.get(owner);
        if (!value) throw unavailable('profile');
        return value;
      });
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      call(() => bind(handle, JSON.stringify({ attempt, archive }), registryHandle, ownerHandles,
        nativeNow + Math.min(10000, deadline - sampled)));
      assertMaintenanceCustody(custody);
    },
    parkMaintenanceTransaction(custody: MaintenanceCustody, point: MaintenanceTransactionPoint,
      witness: MaintenanceTransactionWitness, deadline: number): never {
      assertMaintenanceCustody(custody);
      const handle = maintenanceHandles.get(custody), park = native.parkMaintenanceTransaction;
      if (!handle || typeof park !== 'function' || !Number.isFinite(deadline) ||
          !/^[0-9a-f]{32}$/.test(witness.attempt) || !validator('migration.File')(witness.transaction) ||
          (point === 'current-publication' ? !validator('migration.File')(witness.current) : witness.current !== null))
        throw unavailable('profile');
      const encoded = JSON.stringify({ attempt: witness.attempt, transaction: witness.transaction, current: witness.current });
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      call(() => park(handle, point, encoded, nativeNow + Math.min(10000, deadline - sampled)));
      // A valid stop terminates the parked writer. A return is never progress.
      throw unavailable('profile');
    },
    parkMaintenanceStaging(custody: MaintenanceCustody, point: MaintenanceStagingPoint, attempt: string,
      profileSha256: string, staging: MaintenanceFileEvidence['identity'], scratch: MaintenanceScratch | null, deadline: number): never {
      assertMaintenanceCustody(custody);
      const handle = maintenanceHandles.get(custody), park = native.parkMaintenanceStaging;
      const scratchPoint = point === 'empty-staging' || point === 'partial-staging';
      if (!handle || typeof park !== 'function' || !Number.isFinite(deadline) || !maintenanceStagingPoints.includes(point) ||
          !/^[0-9a-f]{32}$/.test(attempt) || !/^[0-9a-f]{64}$/.test(profileSha256) ||
          !validator('migration.Identity')(staging) || staging.mode !== 0o700 ||
          (scratchPoint ? !scratch || !/^\.migration-[0-9a-f]{32}$/.test(scratch.name) ||
            !validator('migration.Identity')(scratch.identity) || scratch.identity.mode !== 0o600 : scratch !== null))
        throw unavailable('profile');
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      call(() => park(handle, point, JSON.stringify({ attempt, profileSha256, staging, scratch }),
        nativeNow + Math.min(10000, deadline - sampled)));
      throw unavailable('profile');
    },
    parkMaintenanceProgress(custody: MaintenanceCustody, point: MaintenanceProgressPoint,
      witness: MaintenanceProgressWitness, deadline: number): never {
      assertMaintenanceCustody(custody);
      const handle = maintenanceHandles.get(custody), park = native.parkMaintenanceProgress;
      if (!handle || typeof park !== 'function' || !Number.isFinite(deadline) ||
          !/^[0-9a-f]{32}$/.test(witness.attempt) || !validator('migration.File')(witness.file) ||
          (point === 'committed-progress' ? typeof witness.profileSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(witness.profileSha256) :
            point !== 'completion' || witness.profileSha256 !== null)) throw unavailable('profile');
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      call(() => park(handle, point, JSON.stringify(witness), nativeNow + Math.min(10000, deadline - sampled)));
      throw unavailable('profile');
    },
    publishMaintenanceFile(custody: MaintenanceCustody, source: string, destination: string,
      parent: MaintenanceFileEvidence['identity'], file: MaintenanceFileEvidence, deadline: number): void {
      assertMaintenanceCustody(custody);
      const handle = maintenanceHandles.get(custody), publish = native.publishMaintenanceFile;
      if (!handle || typeof publish !== 'function' || !validator('migration.Identity')(parent) || parent.mode !== 0o700 ||
          !validator('migration.File')(file) || file.identity.mode !== 0o600 ||
          !Number.isFinite(deadline) || ![source, destination].every(path => isAbsolute(path) && !path.includes('\0')))
        throw unavailable('profile');
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      call(() => publish(handle, source, destination, JSON.stringify({ parent, file }), nativeNow + Math.min(10000, deadline - sampled)));
      assertMaintenanceCustody(custody);
      if (performance.now() >= deadline) throw unavailable('profile');
    },
    observeMaintenanceStateRoot(custody: MaintenanceCustody): MaintenanceStateRoot {
      assertMaintenanceCustody(custody);
      const handle = maintenanceHandles.get(custody);
      if (!handle || typeof native.observeMaintenanceStateRoot !== 'function' || typeof native.assertMaintenanceStateRoot !== 'function')
        throw unavailable('browser');
      const observe = native.observeMaintenanceStateRoot, check = native.assertMaintenanceStateRoot;
      const value = call(() => JSON.parse(observe(handle))) as Omit<MaintenanceStateRoot, 'assert'>;
      const identity = (i: MaintenanceFileEvidence['identity']): boolean => !!i &&
        typeof i.device === 'string' && /^[0-9]+$/.test(i.device) && typeof i.inode === 'string' && /^[0-9]+$/.test(i.inode) &&
        i.uid === process.getuid?.() && i.mode === 0o700;
      if (!value || value.path !== custody.facts.stateRoot || value.epoch !== custody.facts.epoch ||
          value.policySha256 !== custody.facts.hostPolicySha256 || !['absent', 'present'].includes(value.initial) ||
          (value.initial === 'absent' ? value.identity !== null : !value.identity || !identity(value.identity)) ||
          !value.parent || value.parent.path !== value.path.slice(0, value.path.lastIndexOf('/')) || !identity(value.parent.identity))
        throw unavailable('browser');
      if (value.identity) Object.freeze(value.identity);
      Object.freeze(value.parent.identity); Object.freeze(value.parent);
      const assert = () => { assertMaintenanceCustody(custody); call(() => check(handle)); };
      const root: MaintenanceStateRoot = Object.freeze({ ...value, assert }); assert(); return root;
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
    async inspectMigration(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: HeldLock | MaintenanceGuard,
      input: NativeMigrationInput, deadline: number, data?: HeldLock | MaintenanceGuard): Promise<MigrationInspectionReceipt> {
      assertMaintenanceCustody(custody);
      const guardHandle = (value: HeldLock | MaintenanceGuard) => locks.get(value as HeldLock) ?? maintenanceBuildHandles.get(value as MaintenanceGuard);
      const actualCustody = maintenanceHandles.get(custody), actualRegistry = locks.get(registry), actualOwner = locks.get(owner);
      const actualBuild = guardHandle(build), actualData = data ? guardHandle(data) : null;
      if (!actualCustody || !actualRegistry || !actualOwner || !actualBuild || (data && !actualData) ||
          input.mode !== 'migrate-verify' || !Number.isFinite(deadline)) throw unavailable('profile');
      const assert = () => { assertMaintenanceCustody(custody); registry.assertIdentity(); owner.assertIdentity(); build.assertIdentity(); data?.assertIdentity(); };
      assert();
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      const nativeDeadline = nativeNow + Math.min(10000, deadline - sampled);
      const handle = call(() => native.beginExitInspection(actualOwner, actualBuild,
        JSON.stringify({ ...input, dataAttempt: input.dataAttempt ?? null, pending: null }), nativeDeadline,
        actualData ?? null, null, actualRegistry, actualCustody));
      try {
        while (performance.now() < deadline && call(() => native.continuousTime()) < nativeDeadline) {
          const raw = call(() => native.pollExitInspection(handle));
          if (raw !== null) {
            if (typeof raw !== 'string' || !raw.length || Buffer.byteLength(raw) > 16384) throw unavailable('profile');
            const value = JSON.parse(raw) as MigrationInspectionReceipt & { format: number; kind: string };
            if (!value || Object.keys(value).sort().join(',') !== 'epoch,evidence,format,kind,marker,profileDirectory,profileInstance,profilePathHash,record' ||
                value.format !== 1 || value.kind !== 'migration-verification' || value.epoch !== custody.facts.epoch ||
                value.profileInstance !== input.profileInstance || value.profilePathHash !== input.profilePathHash ||
                !validator('migration.Evidence')(value.evidence) || !validator('migration.Identity')(value.profileDirectory) ||
                !validator('migration.File')(value.record) || (value.marker !== null && !validator('migration.File')(value.marker)) ||
                value.evidence.clean !== (value.evidence.classification === 'clean')) throw unavailable('profile');
            assert(); if (performance.now() >= deadline || call(() => native.continuousTime()) >= nativeDeadline) throw unavailable('profile');
            Object.freeze(value.record.identity); Object.freeze(value.record);
            if (value.marker) { Object.freeze(value.marker.identity); Object.freeze(value.marker); }
            const receipt: MigrationInspectionReceipt = Object.freeze({ epoch: value.epoch, profileInstance: value.profileInstance,
              profilePathHash: value.profilePathHash, evidence: Object.freeze(value.evidence), profileDirectory: Object.freeze(value.profileDirectory),
              record: value.record, marker: value.marker });
            migrationInspectionReceipts.add(receipt); return receipt;
          }
          await setTimeout(Math.min(5, Math.max(1, deadline - performance.now())));
        }
        throw unavailable('profile');
      } finally { call(() => native.cancelExitInspection(handle)); }
    },
    async commitMigration(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: HeldLock | MaintenanceGuard,
      input: NativeMigrationCommitInput, deadline: number, data?: HeldLock | MaintenanceGuard): Promise<MigrationCommitReceipt> {
      assertMaintenanceCustody(custody);
      const guardHandle = (value: HeldLock | MaintenanceGuard) => locks.get(value as HeldLock) ?? maintenanceBuildHandles.get(value as MaintenanceGuard);
      const actualCustody = maintenanceHandles.get(custody), actualRegistry = locks.get(registry), actualOwner = locks.get(owner);
      const actualBuild = guardHandle(build), actualData = data ? guardHandle(data) : null;
      if (!actualCustody || !actualRegistry || !actualOwner || !actualBuild || (data && !actualData) ||
          input.mode !== 'migrate-commit' || !Number.isFinite(deadline) || !input.migration ||
          Object.keys(input.migration).sort().join(',') !== 'attempt,transactionSha256' ||
          !/^[0-9a-f]{32}$/.test(input.migration.attempt) || !/^[0-9a-f]{64}$/.test(input.migration.transactionSha256)) throw unavailable('profile');
      const assert = () => { assertMaintenanceCustody(custody); registry.assertIdentity(); owner.assertIdentity(); build.assertIdentity(); data?.assertIdentity(); };
      assert();
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      const nativeDeadline = nativeNow + Math.min(10000, deadline - sampled);
      const handle = call(() => native.beginExitInspection(actualOwner, actualBuild,
        JSON.stringify({ ...input, dataAttempt: input.dataAttempt ?? null, pending: null }), nativeDeadline,
        actualData ?? null, null, actualRegistry, actualCustody));
      try {
        while (performance.now() < deadline && call(() => native.continuousTime()) < nativeDeadline) {
          const raw = call(() => native.pollExitInspection(handle));
          if (raw !== null) {
            if (typeof raw !== 'string' || !raw.length || Buffer.byteLength(raw) > 16384) throw unavailable('profile');
            const value = JSON.parse(raw) as MigrationCommitReceipt & { format: number; kind: string };
            if (!value || Object.keys(value).sort().join(',') !== 'attempt,epoch,format,kind,profileInstance,profilePathHash,receipt' ||
                value.format !== 1 || value.kind !== 'migration-committed' || value.epoch !== custody.facts.epoch ||
                value.attempt !== input.migration.attempt || value.profileInstance !== input.profileInstance ||
                value.profilePathHash !== input.profilePathHash || !validator('migration.File')(value.receipt)) throw unavailable('profile');
            assert(); if (performance.now() >= deadline || call(() => native.continuousTime()) >= nativeDeadline) throw unavailable('profile');
            Object.freeze(value.receipt.identity); Object.freeze(value.receipt);
            const receipt: MigrationCommitReceipt = Object.freeze({ epoch: value.epoch, attempt: value.attempt,
              profileInstance: value.profileInstance, profilePathHash: value.profilePathHash, receipt: value.receipt });
            migrationCommitReceipts.add(receipt); return receipt;
          }
          await setTimeout(Math.min(5, Math.max(1, deadline - performance.now())));
        }
        throw unavailable('profile');
      } finally { call(() => native.cancelExitInspection(handle)); }
    },
    async validateMigrationProgress(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: MaintenanceGuard,
      input: NativeMigrationProgressInput, deadline: number): Promise<MigrationCommitReceipt> {
      assertMaintenanceCustody(custody);
      const guardHandle = (value: HeldLock | MaintenanceGuard) => locks.get(value as HeldLock) ?? maintenanceBuildHandles.get(value as MaintenanceGuard);
      const actualCustody = maintenanceHandles.get(custody), actualRegistry = locks.get(registry), actualOwner = locks.get(owner);
      const actualBuild = guardHandle(build), actualData = null;
      if (!actualCustody || !actualRegistry || !actualOwner || !actualBuild ||
          input.mode !== 'migrate-receipt-progress' || !Number.isFinite(deadline) || !input.migration ||
          Object.keys(input.migration).sort().join(',') !== 'attempt,transactionSha256' ||
          !/^[0-9a-f]{32}$/.test(input.migration.attempt) || !/^[0-9a-f]{64}$/.test(input.migration.transactionSha256)) throw unavailable('profile');
      const assert = () => { assertMaintenanceCustody(custody); registry.assertIdentity(); owner.assertIdentity(); build.assertIdentity(); };
      assert();
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      const nativeDeadline = nativeNow + Math.min(10000, deadline - sampled);
      const handle = call(() => native.beginExitInspection(actualOwner, actualBuild,
        JSON.stringify({ ...input, dataAttempt: input.dataAttempt ?? null, pending: null }), nativeDeadline,
        actualData ?? null, null, actualRegistry, actualCustody));
      try {
        while (performance.now() < deadline && call(() => native.continuousTime()) < nativeDeadline) {
          const raw = call(() => native.pollExitInspection(handle));
          if (raw !== null) {
            if (typeof raw !== 'string' || !raw.length || Buffer.byteLength(raw) > 16384) throw unavailable('profile');
            const value = JSON.parse(raw) as MigrationCommitReceipt & { format: number; kind: string };
            if (!value || Object.keys(value).sort().join(',') !== 'attempt,epoch,format,kind,profileInstance,profilePathHash,receipt' ||
                value.format !== 1 || value.kind !== 'migration-receipt-progress' || value.epoch !== custody.facts.epoch ||
                value.attempt !== input.migration.attempt || value.profileInstance !== input.profileInstance ||
                value.profilePathHash !== input.profilePathHash || !validator('migration.File')(value.receipt)) throw unavailable('profile');
            assert(); if (performance.now() >= deadline || call(() => native.continuousTime()) >= nativeDeadline) throw unavailable('profile');
            Object.freeze(value.receipt.identity); Object.freeze(value.receipt);
            const receipt: MigrationCommitReceipt = Object.freeze({ epoch: value.epoch, attempt: value.attempt,
              profileInstance: value.profileInstance, profilePathHash: value.profilePathHash, receipt: value.receipt });
            migrationCommitReceipts.add(receipt); return receipt;
          }
          await setTimeout(Math.min(5, Math.max(1, deadline - performance.now())));
        }
        throw unavailable('profile');
      } finally { call(() => native.cancelExitInspection(handle)); }
    },
    async validateMigrationCommitted(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: MaintenanceGuard,
      input: NativeMigrationCommittedInput, deadline: number): Promise<MigrationCommittedValidation> {
      assertMaintenanceCustody(custody);
      const guardHandle = (value: HeldLock | MaintenanceGuard) => locks.get(value as HeldLock) ?? maintenanceBuildHandles.get(value as MaintenanceGuard);
      const actualCustody = maintenanceHandles.get(custody), actualRegistry = locks.get(registry), actualOwner = locks.get(owner);
      const actualBuild = guardHandle(build), actualData = null;
      if (!actualCustody || !actualRegistry || !actualOwner || !actualBuild ||
          input.mode !== 'migrate-committed-check' || !Number.isFinite(deadline) || !input.migration ||
          Object.keys(input.migration).sort().join(',') !== 'attempt,transactionSha256' ||
          !/^[0-9a-f]{32}$/.test(input.migration.attempt) || !/^[0-9a-f]{64}$/.test(input.migration.transactionSha256)) throw unavailable('profile');
      const assert = () => { assertMaintenanceCustody(custody); registry.assertIdentity(); owner.assertIdentity(); build.assertIdentity(); };
      assert();
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      const nativeDeadline = nativeNow + Math.min(10000, deadline - sampled);
      const handle = call(() => native.beginExitInspection(actualOwner, actualBuild,
        JSON.stringify({ ...input, dataAttempt: input.dataAttempt ?? null, pending: null }), nativeDeadline,
        actualData ?? null, null, actualRegistry, actualCustody));
      try {
        while (performance.now() < deadline && call(() => native.continuousTime()) < nativeDeadline) {
          const raw = call(() => native.pollExitInspection(handle));
          if (raw !== null) {
            if (typeof raw !== 'string' || !raw.length || Buffer.byteLength(raw) > 16384) throw unavailable('profile');
            const value = JSON.parse(raw) as MigrationCommittedValidation & { format: number; kind: string };
            if (!value || Object.keys(value).sort().join(',') !== 'attempt,committed,completion,epoch,format,kind,profileInstance,profilePathHash,receipt' ||
                value.format !== 1 || value.kind !== 'migration-committed-validated' || value.epoch !== custody.facts.epoch ||
                value.attempt !== input.migration.attempt || value.profileInstance !== input.profileInstance ||
                value.profilePathHash !== input.profilePathHash || (!validator('migration.File')(value.receipt) || !validator('migration.File')(value.committed) ||
                  (value.completion !== null && !validator('migration.File')(value.completion)))) throw unavailable('profile');
            assert(); if (performance.now() >= deadline || call(() => native.continuousTime()) >= nativeDeadline) throw unavailable('profile');
            Object.freeze(value.receipt.identity); Object.freeze(value.receipt);
            Object.freeze(value.committed.identity); Object.freeze(value.committed);
            if (value.completion) { Object.freeze(value.completion.identity); Object.freeze(value.completion); }
            const receipt: MigrationCommittedValidation = Object.freeze({ epoch: value.epoch, attempt: value.attempt,
              profileInstance: value.profileInstance, profilePathHash: value.profilePathHash, receipt: value.receipt,
              committed: value.committed, completion: value.completion });
            migrationCommittedValidations.add(receipt); return receipt;
          }
          await setTimeout(Math.min(5, Math.max(1, deadline - performance.now())));
        }
        throw unavailable('profile');
      } finally { call(() => native.cancelExitInspection(handle)); }
    },
    async prepareMigrationRecovery(custody: MaintenanceCustody, registry: HeldLock, owner: HeldLock, build: HeldLock | MaintenanceGuard,
      input: NativeMigrationRecoveryInput, deadline: number, data?: HeldLock | MaintenanceGuard): Promise<MigrationRecoveryPermit> {
      assertMaintenanceCustody(custody);
      const guardHandle = (value: HeldLock | MaintenanceGuard) => locks.get(value as HeldLock) ?? maintenanceBuildHandles.get(value as MaintenanceGuard);
      const actualCustody = maintenanceHandles.get(custody), actualRegistry = locks.get(registry), actualOwner = locks.get(owner);
      const actualBuild = guardHandle(build), actualData = data ? guardHandle(data) : null;
      if (!actualCustody || !actualRegistry || !actualOwner || !actualBuild || (data && !actualData) ||
          typeof native.pollMigrationRecovery !== 'function' || typeof native.consumeMigrationRecovery !== 'function' ||
          input.mode !== 'migrate-recover' || !Number.isFinite(deadline) || !input.migration ||
          Object.keys(input.migration).sort().join(',') !== 'attempt,transactionSha256' ||
          !/^[0-9a-f]{32}$/.test(input.migration.attempt) || !/^[0-9a-f]{64}$/.test(input.migration.transactionSha256)) throw unavailable('profile');
      const assert = () => { assertMaintenanceCustody(custody); registry.assertIdentity(); owner.assertIdentity(); build.assertIdentity(); data?.assertIdentity(); };
      assert();
      const nativeNow = call(() => native.continuousTime()), sampled = performance.now();
      if (sampled >= deadline) throw unavailable('profile');
      const nativeDeadline = nativeNow + Math.min(10000, deadline - sampled);
      const handle = call(() => native.beginExitInspection(actualOwner, actualBuild,
        JSON.stringify({ ...input, dataAttempt: input.dataAttempt ?? null, pending: null }), nativeDeadline,
        actualData ?? null, null, actualRegistry, actualCustody));
      const read = (raw: string, kind: string): MigrationRecoveryReceipt => {
        if (!raw || Buffer.byteLength(raw) > 16384) throw unavailable('profile');
        const value = JSON.parse(raw) as MigrationRecoveryReceipt & { format: number; kind: string };
        if (!value || Object.keys(value).sort().join(',') !== 'attempt,epoch,format,kind,profileInstance,profilePathHash,record' ||
            value.format !== 1 || value.kind !== kind || value.epoch !== custody.facts.epoch || value.attempt !== input.migration.attempt ||
            value.profileInstance !== input.profileInstance || value.profilePathHash !== input.profilePathHash ||
            !validator('migration.File')(value.record)) throw unavailable('profile');
        assert();
        if (performance.now() >= deadline || call(() => native.continuousTime()) >= nativeDeadline) throw unavailable('profile');
        Object.freeze(value.record.identity); Object.freeze(value.record);
        return Object.freeze({ epoch: value.epoch, attempt: value.attempt, profileInstance: value.profileInstance,
          profilePathHash: value.profilePathHash, record: value.record });
      };
      let transferred = false;
      try {
        while (performance.now() < deadline && call(() => native.continuousTime()) < nativeDeadline) {
          const raw = call(() => native.pollMigrationRecovery(handle));
          if (raw !== null) {
            const ready = read(raw, 'migration-record-permit'); let used = false;
            const permit: MigrationRecoveryPermit = Object.freeze({ ...ready,
              cancel(): void { if (!used) { used = true; call(() => native.cancelExitInspection(handle)); } },
              async commit(): Promise<MigrationRecoveryReceipt> {
                if (used) throw unavailable('profile'); used = true;
                try {
                  assert(); call(() => native.consumeMigrationRecovery(handle));
                  while (performance.now() < deadline && call(() => native.continuousTime()) < nativeDeadline) {
                    const completed = call(() => native.pollExitInspection(handle));
                    if (completed !== null) {
                      const receipt = read(completed, 'migration-record-recovered');
                      if (JSON.stringify(receipt.record) !== JSON.stringify(ready.record)) throw unavailable('profile');
                      migrationRecoveryReceipts.add(receipt); return receipt;
                    }
                    await setTimeout(Math.min(5, Math.max(1, deadline - performance.now())));
                  }
                  throw unavailable('profile');
                } finally { call(() => native.cancelExitInspection(handle)); }
              }
            });
            transferred = true; return permit;
          }
          await setTimeout(Math.min(5, Math.max(1, deadline - performance.now())));
        }
        throw unavailable('profile');
      } finally { if (!transferred) call(() => native.cancelExitInspection(handle)); }
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
                !['activated', 'terminal'].includes(prior.kind) || Object.keys(prior).sort().join(',') !==
                  (prior.migration === undefined ? 'digest,kind,path' : 'digest,kind,migration,path') ||
                !isAbsolute(prior.path) || !/^[0-9a-f]{64}$/.test(prior.digest))) throw unavailable('profile');
            if (prior.kind !== 'absent' && prior.migration !== undefined &&
                (!prior.migration || Object.keys(prior.migration).sort().join(',') !== 'digest,path' ||
                  typeof prior.migration.path !== 'string' || !isAbsolute(prior.migration.path) ||
                  typeof prior.migration.digest !== 'string' || !/^[0-9a-f]{64}$/.test(prior.migration.digest))) throw unavailable('profile');
            owner.assertIdentity(); build.assertIdentity(); guards?.data?.assertIdentity(); guards?.next?.assertIdentity();
            if (performance.now() >= deadline || call(() => native.continuousTime()) >= nativeDeadline) throw unavailable('profile');
            const result: ExitInspectionReceipt = Object.freeze({ kind: value.kind, clean: value.clean,
              prior: Object.freeze({ ...prior, ...(prior.kind !== 'absent' && prior.migration ?
                { migration: Object.freeze({ ...prior.migration }) } : {}) }), request: value.request });
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
    browserAppAvailable(): boolean {
      return typeof native.browserAppAvailable === 'function' && call(() => native.browserAppAvailable!()) === true;
    },
    requestProfileOpen(profile: string, instance: string): boolean {
      return typeof native.requestProfileOpen === 'function' &&
        call(() => native.requestProfileOpen!(profile, instance)) === true;
    },
    activateProfileWindow(peer: ProcessIdentity): boolean {
      return peer.uid === process.geteuid?.() && typeof native.activateProfileWindow === 'function' &&
        call(() => native.activateProfileWindow!(peer.pid, peer.startId)) === true;
    },
    seqoyaBackendArguments(peer: ProcessIdentity, runtime: string, entry: string, lock: string): boolean {
      return typeof native.seqoyaBackendArguments === 'function' &&
        call(() => native.seqoyaBackendArguments!(peer.pid, peer.startId, runtime, entry, lock)) === true;
    },
    readLaunchAttempt(lock: HeldLock): string | null {
      const handle = locks.get(lock); if (!handle) throw unavailable('profile'); lock.assertIdentity();
      const value = call(() => native.readLaunchAttempt(handle));
      if (value !== null && (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > 16384)) throw unavailable('profile');
      lock.assertIdentity(); return value;
    },
    canonicalMigrationClaimDigest(claim: import('./process.js').LaunchAttempt): string {
      const raw = JSON.stringify(claim);
      if (!raw || Buffer.byteLength(raw) >= 16384 || typeof native.canonicalMigrationClaimDigest !== 'function') throw unavailable('profile');
      const value = call(() => native.canonicalMigrationClaimDigest!(raw));
      if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw unavailable('profile');
      return value;
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
