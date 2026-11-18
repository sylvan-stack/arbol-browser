/** Node-safe physical package identity. Cryptographic authority is established
 * separately; an editable metadata object or launcher environment is no trust. */
import { join, isAbsolute, resolve, dirname, basename } from 'node:path';
import { userInfo } from 'node:os';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { packagedLayout, selectedLayout, type BuildSelection, type PackagedLayout } from './selection.js';
import type { Contract } from '../contracts/generated.js';
import { directory, assertDirectory } from '../profiles/paths.js';
import { noteHostStartup, assertHostCustody } from './custody.js';
import type { SignedBundle, SignedVerificationPhase } from '../native/manifest.js';

const physicalFS = process.getBuiltinModule(typeof process.versions.electron === 'string' ? 'original-fs' : 'fs') as typeof import('node:fs') | undefined;
if (!physicalFS || !physicalFS.promises || typeof physicalFS.promises.open !== 'function') throw unavailable('browser');
const { constants, promises: { open, realpath, lstat } } = physicalFS;

export interface PackagedIdentity {
  readonly layout: PackagedLayout;
  readonly component: Readonly<Contract<'wire.ComponentInfo'>>;
  readonly sourceDigest: string;
  readonly compileDigest: string;
  readonly productDigest: string;
  readonly metadataDigest: string;
}
export interface PhysicalJson { readonly value: unknown; readonly digest: string }
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
/** Exact physical regular file; no Electron ASAR view or following a final link.
 * Signature/resource checks must additionally authenticate these bytes. */
export async function physicalJson(path: string, limit = 1048576, deadline = Infinity): Promise<PhysicalJson> {
  const check = () => { if (deadline !== Infinity) assertBudget(deadline); }; check();
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1048576 || await realpath(path) !== path) throw unavailable('browser');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    check();
    const before = await file.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o022n) !== 0n ||
        !named.isFile() || named.dev !== before.dev || named.ino !== before.ino || named.nlink !== before.nlink ||
        named.uid !== before.uid || named.mode !== before.mode ||
        before.size < 1n || before.size > BigInt(limit)) throw unavailable('browser');
    const buffer = Buffer.alloc(Number(before.size) + 1); let length = 0;
    while (length < buffer.length) {
      check();
      const read = await file.read(buffer, length, buffer.length - length, null);
      if (!read.bytesRead) break; length += read.bytesRead;
    }
    const raw = buffer.subarray(0, length), after = await file.stat({ bigint: true }), lastName = await lstat(path, { bigint: true });
    check();
    if (BigInt(raw.length) !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        !lastName.isFile() || lastName.dev !== after.dev || lastName.ino !== after.ino ||
        lastName.nlink !== 1n || lastName.mode !== before.mode || lastName.uid !== before.uid ||
        lastName.size !== after.size || lastName.mtimeNs !== after.mtimeNs || lastName.ctimeNs !== after.ctimeNs ||
        await realpath(path) !== path) throw unavailable('browser');
    return Object.freeze({ value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)),
      digest: createHash('sha256').update(raw).digest('hex') });
  } catch { throw unavailable('browser'); } finally { await file.close(); }
}
function decodePackagedIdentity(layout: PackagedLayout, metadata: PhysicalJson, stateDirectory: string): PackagedIdentity {
  const value = metadata.value as Record<string, unknown>;
  const host = value?.host as Record<string, unknown>;
  const component = { ...(value?.component as object), stateDirectory };
  if (!value || value.format !== 1 || !validator('wire.ComponentInfo')(component) ||
      component.build !== layout.build || !digest(value.sourceDigest) || !host ||
      Object.keys(host).sort().join(',') !== 'compileDigest,layout,productDigest' || host.layout !== 1 ||
      !digest(host.compileDigest) || !digest(host.productDigest)) throw unavailable('browser');
  return Object.freeze({ layout, component: Object.freeze(component), sourceDigest: value.sourceDigest,
    compileDigest: host.compileDigest, productDigest: host.productDigest, metadataDigest: metadata.digest });
}
export async function readPackagedIdentity(selection: BuildSelection, payload: string,
  stateDirectory: string, deadline = Infinity): Promise<PackagedIdentity> {
  const layout = selectedLayout(selection, payload);
  for (const path of [layout.buildRoot, layout.bundle, layout.payload]) {
    if (deadline !== Infinity) assertBudget(deadline);
    if (await realpath(path) !== path) throw unavailable('browser');
  }
  const metadata = await physicalJson(join(payload, 'metadata.json'), 1048576, deadline);
  return decodePackagedIdentity(layout, metadata, stateDirectory);
}

export interface HostPolicy {
  readonly format: 1; readonly purpose: 'blocked' | 'isolated-qualification' | 'production';
  readonly build: string; readonly buildRoot: string; readonly stateRoot: string;
  readonly sourceDigest: string; readonly productDigest: string; readonly metadataDigest: string;
  readonly compatibilityDigest: string; readonly reviewDigest: string; readonly qualificationDigest: string;
  readonly readerKey: string; readonly readableReaderKeys: readonly string[]; readonly readableDataEpochs: readonly number[];
}
export interface VerifiedHost {
  readonly identity: PackagedIdentity; readonly policy: Readonly<HostPolicy>;
  readonly signed: SignedBundle;
  readonly policyDigest: string;
  readonly guardIdentity: Readonly<{ device: string; inode: string; uid: number }>;
  assertTrusted(deadline: number, originalStartupCutoff?: number): Promise<void>;
}
const verifiedHosts = new WeakSet<object>();
const armedHosts = new WeakMap<VerifiedHost, import('./custody.js').HostCustody>();
const startupTrustChecks = new WeakMap<VerifiedHost, (deadline: number, originalStartupCutoff: number) => Promise<void>>();
const closeTrustChecks = new WeakMap<VerifiedHost, (deadline: number) => Promise<void>>();
export async function assertHostStartupContinuity(host: VerifiedHost, deadline: number, originalStartupCutoff: number): Promise<void> {
  const check = startupTrustChecks.get(host);
  if (!check) throw unavailable('browser');
  await check(deadline, originalStartupCutoff);
}
export async function assertHostCloseContinuity(host: VerifiedHost, deadline: number): Promise<void> {
  const check = closeTrustChecks.get(host);
  if (!check) throw unavailable('browser');
  await check(deadline);
}
export function bindArmedHost(host: VerifiedHost, custody: import('./custody.js').HostCustody): void {
  if (!verifiedHosts.has(host) || custody.host !== host || armedHosts.has(host)) throw unavailable('browser');
  assertHostCustody(custody); armedHosts.set(host, custody);
}
const armedTrustFailureStages = Object.freeze({
  'bundle-selection': 'armed-trust-failure-bundle-selection',
  'initial-snapshot': 'armed-trust-failure-initial-snapshot',
  'outer-signature-verification': 'armed-trust-failure-outer-signature-verification',
  'outer-signature-details': 'armed-trust-failure-outer-signature-details',
  'outer-signature-entitlements': 'armed-trust-failure-outer-signature-entitlements',
  'nested-signature-verification': 'armed-trust-failure-nested-signature-verification',
  'nested-signature-details': 'armed-trust-failure-nested-signature-details',
  'nested-signature-entitlements': 'armed-trust-failure-nested-signature-entitlements',
  'publisher': 'armed-trust-failure-publisher',
  'compatibility': 'armed-trust-failure-compatibility',
  'inventory': 'armed-trust-failure-inventory',
  'final-snapshot': 'armed-trust-failure-final-snapshot',
  'final-physical-comparison': 'armed-trust-failure-final-physical-comparison',
  'repeated-snapshot': 'armed-trust-failure-repeated-snapshot',
  'repeated-physical': 'armed-trust-failure-repeated-physical',
  'repeated-manifest': 'armed-trust-failure-repeated-manifest',
  'repeated-cutoff': 'armed-trust-failure-repeated-cutoff',
  'snapshot-receipt': 'armed-trust-failure-snapshot-receipt',
  'verification-cutoff': 'armed-trust-failure-verification-cutoff',
  'snapshot-root-identity': 'armed-trust-failure-snapshot-root-identity',
  'snapshot-root-change-time': 'armed-trust-failure-snapshot-root-change-time',
  'snapshot-entry-identity': 'armed-trust-failure-snapshot-entry-identity',
  'snapshot-file-description': 'armed-trust-failure-snapshot-file-description',
  'snapshot-file-read': 'armed-trust-failure-snapshot-file-read',
  'storage-context': 'armed-trust-failure-storage-context',
  'snapshot-symlink': 'armed-trust-failure-snapshot-symlink',
  'snapshot-directory-membership': 'armed-trust-failure-snapshot-directory-membership',
  'snapshot-encoded-mismatch': 'armed-trust-failure-snapshot-encoded-mismatch',
  'snapshot-filesystem': 'armed-trust-failure-snapshot-filesystem'
} as const satisfies Record<SignedVerificationPhase, import('./platform.js').HostStartupStage>);
const hostPolicyKeys = ['format', 'purpose', 'build', 'buildRoot', 'stateRoot', 'sourceDigest', 'productDigest',
  'metadataDigest', 'compatibilityDigest', 'reviewDigest', 'qualificationDigest', 'readerKey',
  'readableReaderKeys', 'readableDataEpochs'].sort().join(',');
function canonicalPath(value: unknown): value is string {
  return typeof value === 'string' && isAbsolute(value) && resolve(value) === value && !value.includes('\0');
}
function below(path: string, parent: string): boolean { return path === parent || path.startsWith(parent + '/'); }
/** Resolve even a not-yet-created protected location through its real nearest
 * ancestor. An existing installation alias must not hide its physical target. */
async function protectedLocation(path: string, deadline: number): Promise<string> {
  const tail: string[] = []; let current = path;
  for (;;) {
    assertBudget(deadline);
    try { await lstat(current); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT' || current === dirname(current)) throw unavailable('browser');
      tail.unshift(basename(current)); current = dirname(current); continue;
    }
    // A dangling existing alias is uncertainty, not an absent normal install.
    const physical = await realpath(current); assertBudget(deadline); return join(physical, ...tail);
  }
}
async function assertIsolation(layout: PackagedLayout, state: string, deadline: number): Promise<void> {
  const account = userInfo();
  if (!process.geteuid || account.uid !== process.geteuid() || !canonicalPath(account.homedir)) throw unavailable('browser');
  assertBudget(deadline);
  const accountHome = await realpath(account.homedir);
  for (const protectedPath of [join(accountHome, 'Library/Application Support/Arbol/builds'),
    join(accountHome, 'Library/Application Support/Arbol/browser')]) {
    const physical = await protectedLocation(protectedPath, deadline);
    for (const actual of [layout.buildRoot, state])
      if (below(actual, physical) || below(physical, actual)) throw unavailable('browser');
  }
  for (const path of [dirname(layout.buildRoot), layout.buildRoot, state]) { assertBudget(deadline); await directory(path); }
}
function readPolicy(input: unknown): Readonly<HostPolicy> {
  const value = input as HostPolicy;
  if (!value || Object.keys(value).sort().join(',') !== hostPolicyKeys || value.format !== 1 ||
      !['blocked', 'isolated-qualification', 'production'].includes(value.purpose) ||
      !validator('browser.Build')(value.build) || !canonicalPath(value.buildRoot) || !canonicalPath(value.stateRoot) ||
      ![value.sourceDigest, value.productDigest, value.metadataDigest, value.compatibilityDigest,
        value.reviewDigest, value.qualificationDigest].every(digest) ||
      typeof value.readerKey !== 'string' || !value.readerKey || value.readerKey.length > 256 ||
      !Array.isArray(value.readableReaderKeys) || !Array.isArray(value.readableDataEpochs) ||
      !value.readableReaderKeys.length || !value.readableDataEpochs.length ||
      value.readableReaderKeys.some(key => typeof key !== 'string' || !key || key.length > 256) ||
      value.readableDataEpochs.some(epoch => !Number.isSafeInteger(epoch) || epoch < 1) ||
      new Set(value.readableReaderKeys).size !== value.readableReaderKeys.length ||
      new Set(value.readableDataEpochs).size !== value.readableDataEpochs.length ||
      !value.readableReaderKeys.includes(value.readerKey)) throw unavailable('browser');
  return Object.freeze({ ...value, readableReaderKeys: Object.freeze([...value.readableReaderKeys]),
    readableDataEpochs: Object.freeze([...value.readableDataEpochs]) });
}
/** Source-owned metadata only. Callers retain independent full signed proof
 * at their existing resource boundary; this grants no Owner or ready authority. */
export function assertVerifiedHostMetadata(value: VerifiedHost, deadline: number): void {
  if (!verifiedHosts.has(value)) throw unavailable('browser');
  assertBudget(deadline);
}
export function assertVerifiedHost(value: VerifiedHost, deadline: number): void {
  assertVerifiedHostMetadata(value, deadline); value.signed.assertIdentity(deadline); assertVerifiedHostMetadata(value, deadline);
}
/** One current complete verification at a boundary that otherwise repeated the
 * same snapshot scan immediately before assertTrusted. Brand and cutoff are
 * checked here; assertTrusted retains the independent full physical proof. */
export async function assertTrustedHost(value: VerifiedHost, deadline: number): Promise<void> {
  if (!verifiedHosts.has(value)) throw unavailable('browser');
  assertBudget(deadline); await value.assertTrusted(deadline); assertBudget(deadline);
}
function assertBudget(deadline: number): void {
  if (!Number.isFinite(deadline) || performance.now() >= deadline) throw unavailable('browser');
}
const openCommandStageNames = Object.freeze(['open-dispatch-admission-trust', 'open-profile-selection',
  'open-current-signed-start', 'open-starter-profile-recheck', 'open-runtime-location',
  'open-initial-build-lease', 'open-startup-arbitration', 'open-reservation',
  'open-launch', 'open-native-ready-attachment', 'open-reply', 'open-reply-validation'] as const);
export type OpenCommandStage = typeof openCommandStageNames[number];
export interface OpenCommandObservation { readonly stage: OpenCommandStage | undefined }
const openCommandStages = new WeakMap<OpenCommandObservation, OpenCommandStage | undefined>();
/** This private command-local token observes fixed milestones only. It carries
 * no authority, callbacks, raw values, deadline or failure replacement. */
export function createOpenCommandObservation(): OpenCommandObservation {
  const observation: OpenCommandObservation = Object.freeze({ get stage() { return openCommandStages.get(observation); } });
  openCommandStages.set(observation, undefined); return observation;
}
export function noteOpenCommand(observation: OpenCommandObservation | undefined, stage: OpenCommandStage): void {
  try { if (observation && openCommandStages.has(observation) && openCommandStageNames.includes(stage))
    openCommandStages.set(observation, stage); }
  catch { /* Observation cannot change an original result or failure. */ }
}
export type HostVerificationStage = 'signed-bundle' | 'signed-policy-metadata-compatibility' |
  'isolated-roots' | 'build-guard' | 'initial-verified-host';
export type HostVerificationObservation = Readonly<object>;
const verificationStages = new WeakMap<HostVerificationObservation, HostVerificationStage>();
const verificationFailurePhases = new WeakMap<HostVerificationObservation, SignedVerificationPhase>();
/** A command-local observation only. It is never a VerifiedHost or callback,
 * and no supplied object can change the verifier's authority or failure. */
export function createHostVerificationObservation(): HostVerificationObservation {
  const observation = Object.freeze({});
  verificationStages.set(observation, 'signed-bundle');
  return observation;
}
export function readHostVerificationStage(observation: HostVerificationObservation): HostVerificationStage | undefined {
  return verificationStages.get(observation);
}
export function readHostVerificationFailurePhase(observation: HostVerificationObservation): SignedVerificationPhase | undefined {
  try { return verificationFailurePhases.get(observation); }
  catch { return undefined; }
}
function noteHostVerification(observation: HostVerificationObservation | undefined, stage: HostVerificationStage): void {
  if (observation && verificationStages.has(observation)) verificationStages.set(observation, stage);
}
/** The trusted signing recipe issues a purpose-bound policy. Qualification uses
 * the real product providers on one isolated registered Build and private state;
 * it changes no Native check and cannot open the owner's production profiles.
 * The full source digest includes later testing-only source; productDigest pins
 * the separately reviewed actual product/compiler/sign inputs, never Git HEAD. */
export async function verifyPackagedHost(selection: BuildSelection, payload: string, deadline: number,
  bootstrapSigned?: SignedBundle, observation?: HostVerificationObservation): Promise<VerifiedHost> {
  noteHostVerification(observation, 'signed-bundle');
  assertBudget(deadline);
  const layout = selectedLayout(selection, payload);
  const manifestURL = new URL('../native/manifest.js', import.meta.url).href;
  const manifests = await import(manifestURL) as typeof import('../native/manifest.js');
  let signed: SignedBundle;
  try {
    if (bootstrapSigned) {
      // The canonical bootstrap alone owns this Native candidate brand. Reuse
      // that exact original frozen object, with no second signer or snapshot.
      signed = manifests.reuseNativeCandidateForHost(layout.bundle, bootstrapSigned, deadline);
    } else signed = manifests.verifySignedBundle(layout.bundle, deadline);
  } catch (error) {
    try {
      const phase = manifests.readSignedVerificationPhase(error);
      if (observation && verificationStages.has(observation) && phase && !verificationFailurePhases.has(observation))
        verificationFailurePhases.set(observation, phase);
    } catch { /* Preserve the original public redaction and failure. */ }
    throw unavailable('browser');
  }
  assertBudget(deadline);
  noteHostVerification(observation, 'signed-policy-metadata-compatibility');
  const policyFile = join(layout.bundle, 'Contents/Resources/host-policy.json');
  const rawPolicy = await physicalJson(policyFile, 1048576, deadline), policy = readPolicy(rawPolicy.value);
  const identity = await readPackagedIdentity(selection, payload, policy.stateRoot, deadline);
  const compatibility = await physicalJson(join(layout.bundle, 'Contents/Resources/native-compatibility.json'), 1048576, deadline);
  const manifest = signed.manifest;
  // ABR-29 supplies no independent production release authority. A candidate's
  // own signed qualification strings cannot authorize the owner's data.
  if (policy.purpose !== 'isolated-qualification' || policy.build !== selection.build || policy.buildRoot !== layout.buildRoot ||
      policy.sourceDigest !== identity.sourceDigest || policy.productDigest !== identity.productDigest ||
      policy.metadataDigest !== identity.metadataDigest || policy.compatibilityDigest !== compatibility.digest ||
      manifest.writerKey !== policy.readerKey ||
      manifests.stable(manifest.compatibleReaderKeys) !== manifests.stable(policy.readableReaderKeys) ||
      manifests.stable(manifest.readableDataEpochs) !== manifests.stable(policy.readableDataEpochs)) throw unavailable('browser');
  if (below(policy.stateRoot, layout.buildRoot) || below(layout.buildRoot, policy.stateRoot)) throw unavailable('browser');
  if (manifest.qualification !== `host-isolated:1:${policy.productDigest}` ||
        policy.readerKey !== `host-isolated:1:${policy.productDigest}`) throw unavailable('browser');
    // Explicit disposable roots are prepared by the separately authorized
    // qualifier; no environment or request may relocate them or create a bypass.
  noteHostVerification(observation, 'isolated-roots');
  await assertIsolation(layout, policy.stateRoot, deadline);
  noteHostVerification(observation, 'build-guard');
  const usesIdentity = await directory(dirname(selection.guard)); assertBudget(deadline);
  const guard = await lstat(selection.guard, { bigint: true });
  const guardIdentity = Object.freeze({ device: String(guard.dev), inode: String(guard.ino), uid: Number(guard.uid) });
  const assertGuard = async (limit: number) => {
    assertBudget(limit);
    await assertDirectory(dirname(selection.guard), usesIdentity);
    const current = await lstat(selection.guard, { bigint: true });
    if (!current.isFile() || current.nlink !== 1n || (current.mode & 0o7777n) !== 0o600n ||
        current.uid !== BigInt(userInfo().uid) || current.dev !== guard.dev || current.ino !== guard.ino ||
        await realpath(selection.guard) !== selection.guard) throw unavailable('browser');
    assertBudget(limit);
  };
  // Observation only: earlier armed scans cannot consume final ready labels.
  let readyTrustObserved = false;
  const result: VerifiedHost = Object.freeze({ identity, policy, signed, policyDigest: rawPolicy.digest, guardIdentity,
    assertTrusted: (limit: number, originalStartupCutoff?: number) => verifyTrusted(limit, originalStartupCutoff),
  });
  async function verifyTrusted(limit: number, originalStartupCutoff?: number, retainedFor?: 'startup' | 'close'): Promise<void> {
    if (!verifiedHosts.has(result)) throw unavailable('browser');
    const custody = armedHosts.get(result);
    let observeReady = false;
    try {
      // The original registry binds this frozen host to its actual custody
      // and instance. Only startup uses the already captured Claim cutoff.
      if (originalStartupCutoff !== undefined) {
        if (custody && custody.host !== result) throw unavailable('browser');
        if (!custody || custody.instance.record.phase === 'starting') limit = originalStartupCutoff;
      }
      assertBudget(limit); if (custody) assertHostCustody(custody);
      try {
        if (custody && custody.host === result && custody.instance.record.phase === 'ready' && !readyTrustObserved) {
          readyTrustObserved = true; observeReady = true;
        }
      } catch { /* Observation never replaces verification or its failure. */ }
      if (observeReady) noteHostStartup(custody, 'ready-trust-metadata-before');
      if ((await physicalJson(policyFile, 1048576, limit)).digest !== rawPolicy.digest ||
          (await physicalJson(join(payload, 'metadata.json'), 1048576, limit)).digest !== identity.metadataDigest ||
          (await physicalJson(join(layout.bundle, 'Contents/Resources/native-compatibility.json'), 1048576, limit)).digest !== compatibility.digest)
        throw unavailable('browser');
      if (observeReady) noteHostStartup(custody, 'ready-trust-metadata-after');
      assertBudget(limit);
      if (observeReady) noteHostStartup(custody, 'ready-trust-isolation-before');
      await assertIsolation(layout, policy.stateRoot, limit);
      if (observeReady) noteHostStartup(custody, 'ready-trust-isolation-after');
      if (observeReady) noteHostStartup(custody, 'ready-trust-guard-before');
      await assertGuard(limit);
      if (observeReady) noteHostStartup(custody, 'ready-trust-guard-after');
      if (observeReady) noteHostStartup(custody, 'ready-trust-directories-before');
      for (const path of [layout.buildRoot, layout.bundle, layout.payload]) { assertBudget(limit); await directory(path, false); }
      if (observeReady) noteHostStartup(custody, 'ready-trust-directories-after');
      const retainedPhase = retainedFor === 'close' ? 'closing' : 'starting';
      if (retainedFor && (!custody || custody.instance.record.phase === retainedPhase) &&
          manifests.assertRetainedReadOnlyStorage(signed, limit)) {
        if (custody) assertHostCustody(custody);
      } else if (custody) {
        assertHostCustody(custody);
        if (observeReady) noteHostStartup(custody, 'ready-trust-snapshot-before');
        const proof = await manifests.compareSignedSnapshot(signed, limit);
        if (observeReady) noteHostStartup(custody, 'ready-trust-snapshot-after');
        assertHostCustody(custody);
        if (observeReady) noteHostStartup(custody, 'ready-trust-consume-before');
        manifests.consumeSignedSnapshot(proof, signed, limit);
        if (observeReady) noteHostStartup(custody, 'ready-trust-consume-after');
        assertHostCustody(custody);
      } else signed.assertIdentity(limit);
      assertBudget(limit);
    } catch (error) {
      try {
        const phase = manifests.readSignedVerificationPhase(error);
        if (observation && verificationStages.has(observation) && phase && !verificationFailurePhases.has(observation))
          verificationFailurePhases.set(observation, phase);
        if (custody && phase) noteHostStartup(custody, armedTrustFailureStages[phase]);
      } catch { /* Observation cannot alter custody or the original failure. */ }
      // Detected armed package drift closes the real original even if an
      // upstream caller would otherwise redact or swallow an exception.
      if (custody) return custody.terminate();
      throw error;
    }
  }
  startupTrustChecks.set(result, (limit, cutoff) => verifyTrusted(limit, cutoff, 'startup'));
  closeTrustChecks.set(result, limit => verifyTrusted(limit, undefined, 'close'));
  noteHostVerification(observation, 'initial-verified-host');
  assertBudget(deadline); verifiedHosts.add(result); await result.assertTrusted(deadline); return result;
}

/** Metadata-only host-layout correlation. It reads only fixed neighboring
 * package files, never state/profile, a native addon, a socket or a subprocess.
 * No VerifiedHost/admission capability is minted from this information. */
export async function readPackagedComponentInfo(payload: string, deadline = performance.now() + 5000): Promise<Contract<'wire.ComponentInfo'>> {
  assertBudget(deadline);
  const metadata = await physicalJson(join(payload, 'metadata.json'), 1048576, deadline);
  const value = metadata.value as Record<string, unknown>;
  const component = value?.component as Record<string, unknown> | undefined;
  if (!component || typeof component.build !== 'string') throw unavailable('browser');
  const layout = packagedLayout(component.build, payload);
  for (const path of [layout.buildRoot, layout.bundle, layout.payload]) {
    assertBudget(deadline); if (await realpath(path) !== path) throw unavailable('browser');
  }
  const policyFile = join(layout.bundle, 'Contents/Resources/host-policy.json');
  const rawPolicy = await physicalJson(policyFile, 16383, deadline), policy = readPolicy(rawPolicy.value);
  const identity = decodePackagedIdentity(layout, metadata, policy.stateRoot);
  if (policy.build !== layout.build || policy.buildRoot !== layout.buildRoot || policy.metadataDigest !== metadata.digest ||
      policy.sourceDigest !== identity.sourceDigest || policy.productDigest !== identity.productDigest) throw unavailable('browser');
  // Correlate final fixed package bytes. Canonical stateRoot is reported as
  // declared by policy without opening/creating that directory or consuming a
  // launcher hint. Runtime/compatibility/signature admission remains separate.
  if ((await physicalJson(policyFile, 16383, deadline)).digest !== rawPolicy.digest ||
      (await physicalJson(join(payload, 'metadata.json'), 1048576, deadline)).digest !== metadata.digest) throw unavailable('browser');
  assertBudget(deadline); return identity.component;
}
/** Canonical actual signed host engine authority. No version inference, selected
 * Foundation metadata or user/environment compatibility input is accepted. */
const engineAuthorities = new WeakSet<object>();
export function assertHostEngineAuthority(value: import('../profiles/compatibility.js').EngineAuthority): void {
  if (!engineAuthorities.has(value)) throw unavailable('browser');
}
export function createHostEngineAuthority(host: VerifiedHost, custody: import('./custody.js').HostCustody,
  previousExit: import('./host-entry.js').HostPreviousExit, originalStartupCutoff: number): import('../profiles/compatibility.js').EngineAuthority {
  if (!verifiedHosts.has(host) || custody.host !== host) throw unavailable('browser');
  custody.assertRetained();
  const authority: import('../profiles/compatibility.js').EngineAuthority = Object.freeze({
    build: host.identity.layout.build, manifest: host.signed.manifest,
    async assertTrusted() {
      custody.assertRetained(); await host.assertTrusted(performance.now() + 5000, originalStartupCutoff); custody.assertRetained();
    },
    async assertPreviousEngineExited(profile: import('../profiles/records.js').ProfileSnapshot) {
      if (profile !== custody.instance.owner.profile) return custody.terminate();
      await previousExit.assertExited(profile, custody.instance.previous, custody.instance.owner);
      custody.assertRetained();
    },
    async beginMutation(owner: import('../profiles/locking.js').OwnerLease,
      marker: Readonly<import('../profiles/compatibility.js').EngineMarker>) {
      if (owner !== custody.instance.owner) return custody.terminate();
      return custody.beginMarkerMutation(marker);
    },
  });
  engineAuthorities.add(authority); return authority;
}
