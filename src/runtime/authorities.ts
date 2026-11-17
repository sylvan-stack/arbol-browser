/** Node-safe physical package identity. Cryptographic authority is established
 * separately; an editable metadata object or launcher environment is no trust. */
import { createRequire } from 'node:module';
import { join, isAbsolute, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { selectedLayout, type BuildSelection, type PackagedLayout } from './selection.js';
import type { Contract } from '../contracts/generated.js';
import { stateDirectory as ownerStateDirectory, directory } from '../profiles/paths.js';
import type { SignedBundle } from '../native/manifest.js';

const { constants, promises: { open, realpath } } = createRequire(import.meta.url)(
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
export async function physicalJson(path: string, limit = 1048576): Promise<PhysicalJson> {
  if (await realpath(path) !== path) throw unavailable('browser');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o022n) !== 0n ||
        before.size < 1n || before.size > BigInt(limit)) throw unavailable('browser');
    const raw = await file.readFile(), after = await file.stat({ bigint: true });
    if (BigInt(raw.length) !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        await realpath(path) !== path) throw unavailable('browser');
    return Object.freeze({ value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)),
      digest: createHash('sha256').update(raw).digest('hex') });
  } catch { throw unavailable('browser'); } finally { await file.close(); }
}
export async function readPackagedIdentity(selection: BuildSelection, payload: string,
  stateDirectory: string): Promise<PackagedIdentity> {
  const layout = selectedLayout(selection, payload);
  for (const path of [layout.buildRoot, layout.bundle, layout.payload])
    if (await realpath(path) !== path) throw unavailable('browser');
  const metadata = await physicalJson(join(payload, 'metadata.json'));
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
  assertTrusted(): Promise<void>;
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
export function assertVerifiedHost(value: VerifiedHost): void {
  if (!verifiedHosts.has(value)) throw unavailable('browser');
  value.signed.assertIdentity();
}
/** The trusted signing recipe issues a purpose-bound policy. Qualification uses
 * the real product providers on one isolated registered Build and private state;
 * it changes no Native check and cannot open the owner's production profiles.
 * The full source digest includes later testing-only source; productDigest pins
 * the separately reviewed actual product/compiler/sign inputs, never Git HEAD. */
export async function verifyPackagedHost(selection: BuildSelection, payload: string): Promise<VerifiedHost> {
  const layout = selectedLayout(selection, payload);
  const manifestURL = new URL('../native/manifest.js', import.meta.url).href;
  const manifests = await import(manifestURL) as typeof import('../native/manifest.js');
  let signed: SignedBundle;
  try { signed = manifests.verifySignedBundle(layout.bundle); } catch { throw unavailable('browser'); }
  const policyFile = join(layout.bundle, 'Contents/Resources/host-policy.json');
  const rawPolicy = await physicalJson(policyFile), policy = readPolicy(rawPolicy.value);
  const identity = await readPackagedIdentity(selection, payload, policy.stateRoot);
  const compatibility = await physicalJson(join(layout.bundle, 'Contents/Resources/native-compatibility.json'));
  const manifest = signed.manifest;
  if (policy.purpose === 'blocked' || policy.build !== selection.build || policy.buildRoot !== layout.buildRoot ||
      policy.sourceDigest !== identity.sourceDigest || policy.productDigest !== identity.productDigest ||
      policy.metadataDigest !== identity.metadataDigest || policy.compatibilityDigest !== compatibility.digest ||
      manifest.writerKey !== policy.readerKey ||
      manifests.stable(manifest.compatibleReaderKeys) !== manifests.stable(policy.readableReaderKeys) ||
      manifests.stable(manifest.readableDataEpochs) !== manifests.stable(policy.readableDataEpochs)) throw unavailable('browser');
  const ownerState = ownerStateDirectory();
  if (below(policy.stateRoot, layout.buildRoot)) throw unavailable('browser');
  if (policy.purpose === 'isolated-qualification') {
    if (below(policy.stateRoot, ownerState) || below(ownerState, policy.stateRoot) ||
        manifest.qualification !== `host-isolated:1:${policy.productDigest}` ||
        policy.readerKey !== `host-isolated:1:${policy.productDigest}`) throw unavailable('browser');
    // Explicit disposable roots are prepared by the separately authorized
    // qualifier; no environment or request may relocate them or create a bypass.
    await directory(policy.stateRoot);
  } else if (policy.stateRoot !== ownerState ||
      manifest.qualification !== `host-production:1:${policy.productDigest}:${policy.qualificationDigest}` ||
      policy.readableReaderKeys.some(key => key.includes('unqualified') || key.startsWith('host-isolated:')))
    throw unavailable('browser');
  const result: VerifiedHost = Object.freeze({ identity, policy, signed,
    async assertTrusted() {
      if (!verifiedHosts.has(result)) throw unavailable('browser');
      signed.assertIdentity();
      if ((await physicalJson(policyFile)).digest !== rawPolicy.digest ||
          (await physicalJson(join(payload, 'metadata.json'))).digest !== identity.metadataDigest ||
          (await physicalJson(join(layout.bundle, 'Contents/Resources/native-compatibility.json'))).digest !== compatibility.digest)
        throw unavailable('browser');
      for (const path of [layout.buildRoot, layout.bundle, layout.payload]) await directory(path, false);
      signed.assertIdentity();
    } });
  verifiedHosts.add(result); await result.assertTrusted(); return result;
}
