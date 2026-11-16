/** Node-safe physical package identity. Cryptographic authority is established
 * separately; an editable metadata object or launcher environment is no trust. */
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { selectedLayout, type BuildSelection, type PackagedLayout } from './selection.js';
import type { Contract } from '../contracts/generated.js';

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
