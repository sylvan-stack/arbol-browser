/** Node-safe physical package identity. Cryptographic authority is established
 * separately; an editable metadata object or launcher environment is no trust. */
import { createRequire } from 'node:module';
import { join, isAbsolute, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { selectedLayout, type BuildSelection, type PackagedLayout } from './selection.js';
import type { Contract } from '../contracts/generated.js';
import { stateDirectory as ownerStateDirectory, directory } from '../profiles/paths.js';
import type { SignedBundle } from '../native/manifest.js';

const { constants, promises: { open, realpath, lstat } } = createRequire(import.meta.url)(
  process.type === 'browser' ? 'original-fs' : 'node:fs') as typeof import('node:fs');

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
export async function readPackagedIdentity(selection: BuildSelection, payload: string,
  stateDirectory: string, deadline = Infinity): Promise<PackagedIdentity> {
  const layout = selectedLayout(selection, payload);
  for (const path of [layout.buildRoot, layout.bundle, layout.payload]) {
    if (deadline !== Infinity) assertBudget(deadline);
    if (await realpath(path) !== path) throw unavailable('browser');
  }
  const metadata = await physicalJson(join(payload, 'metadata.json'), 1048576, deadline);
  const value = metadata.value as Record<string, unknown>;
  const host = value?.host as Record<string, unknown>;
  const component = { ...(value?.component as object), stateDirectory };
  if (!value || value.format !== 1 || !validator('wire.ComponentInfo')(component) ||
      component.build !== selection.build || !digest(value.sourceDigest) || !host ||
      Object.keys(host).sort().join(',') !== 'compileDigest,layout,productDigest' || host.layout !== 1 ||
      !digest(host.compileDigest) || !digest(host.productDigest)) throw unavailable('browser');
  return Object.freeze({ layout, component: Object.freeze(component), sourceDigest: value.sourceDigest,
    compileDigest: host.compileDigest, productDigest: host.productDigest, metadataDigest: metadata.digest });
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
  assertTrusted(deadline: number): Promise<void>;
}
const verifiedHosts = new WeakSet<object>();
const hostPolicyKeys = ['format', 'purpose', 'build', 'buildRoot', 'stateRoot', 'sourceDigest', 'productDigest',
  'metadataDigest', 'compatibilityDigest', 'reviewDigest', 'qualificationDigest', 'readerKey',
  'readableReaderKeys', 'readableDataEpochs'].sort().join(',');
function canonicalPath(value: unknown): value is string {
  return typeof value === 'string' && isAbsolute(value) && resolve(value) === value && !value.includes('\0');
}
function below(path: string, parent: string): boolean { return path === parent || path.startsWith(parent + '/'); }
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
export function assertVerifiedHost(value: VerifiedHost, deadline: number): void {
  if (!verifiedHosts.has(value)) throw unavailable('browser');
  assertBudget(deadline); value.signed.assertIdentity(deadline); assertBudget(deadline);
}
function assertBudget(deadline: number): void {
  if (!Number.isFinite(deadline) || performance.now() >= deadline) throw unavailable('browser');
}
/** The trusted signing recipe issues a purpose-bound policy. Qualification uses
 * the real product providers on one isolated registered Build and private state;
 * it changes no Native check and cannot open the owner's production profiles.
 * The full source digest includes later testing-only source; productDigest pins
 * the separately reviewed actual product/compiler/sign inputs, never Git HEAD. */
export async function verifyPackagedHost(selection: BuildSelection, payload: string, deadline: number): Promise<VerifiedHost> {
  assertBudget(deadline);
  const layout = selectedLayout(selection, payload);
  const manifestURL = new URL('../native/manifest.js', import.meta.url).href;
  const manifests = await import(manifestURL) as typeof import('../native/manifest.js');
  let signed: SignedBundle;
  try { signed = manifests.verifySignedBundle(layout.bundle, deadline); } catch { throw unavailable('browser'); }
  assertBudget(deadline);
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
  const ownerState = ownerStateDirectory();
  if (below(policy.stateRoot, layout.buildRoot)) throw unavailable('browser');
  if (below(policy.stateRoot, ownerState) || below(ownerState, policy.stateRoot) ||
        manifest.qualification !== `host-isolated:1:${policy.productDigest}` ||
        policy.readerKey !== `host-isolated:1:${policy.productDigest}`) throw unavailable('browser');
    // Explicit disposable roots are prepared by the separately authorized
    // qualifier; no environment or request may relocate them or create a bypass.
  assertBudget(deadline); await directory(policy.stateRoot); assertBudget(deadline);
  const result: VerifiedHost = Object.freeze({ identity, policy, signed,
    async assertTrusted(limit: number) {
      if (!verifiedHosts.has(result)) throw unavailable('browser');
      assertBudget(limit); signed.assertIdentity(limit);
      if ((await physicalJson(policyFile, 1048576, limit)).digest !== rawPolicy.digest ||
          (await physicalJson(join(payload, 'metadata.json'), 1048576, limit)).digest !== identity.metadataDigest ||
          (await physicalJson(join(layout.bundle, 'Contents/Resources/native-compatibility.json'), 1048576, limit)).digest !== compatibility.digest)
        throw unavailable('browser');
      assertBudget(limit);
      for (const path of [layout.buildRoot, layout.bundle, layout.payload]) { assertBudget(limit); await directory(path, false); }
      signed.assertIdentity(limit); assertBudget(limit);
    } });
  assertBudget(deadline); verifiedHosts.add(result); await result.assertTrusted(deadline); return result;
}
