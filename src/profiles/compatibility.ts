import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, opendir, rename } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { BrowserFailure } from '../contracts/errors.js';
import { profileUnavailable, statOrAbsent, sameIdentity, syncDirectory, ownerUid, type Identity } from './paths.js';
import { readJson, writeNewFile, type ProfileSnapshot } from './records.js';
import type { OwnerLease } from './locking.js';

export type EngineMarker = Contract<'profile2.EngineMarker'>;
// Opaque artifacts Electron places beside the explicit website data directory.
const nonEngineRootNames = new Set(['profile.json', 'engine.json', 'owner.lock', 'logs', 'data', 'userData']);
const knownEngineRootTypes = new Map([['Local State', 'file'], ['GraphiteDawnCache', 'directory'], ['GPUPersistentCache', 'directory']]);
const storageNodeLimit = 131072;

async function storageNames(path: string): Promise<string[]> {
  const stream = await opendir(path);
  const names = new Set<string>();
  try {
    for (let entry = await stream.read(); entry; entry = await stream.read()) {
      const name = entry.name;
      if (!name || name === '.' || name === '..' || name.includes('/') || name.includes('\uFFFD') ||
          names.has(name) || names.size >= storageNodeLimit) throw profileUnavailable();
      names.add(name);
    }
  } finally { await stream.close(); }
  return [...names];
}

function sameStorageNode(a: BigIntStats, b: BigIntStats): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.uid === b.uid && a.gid === b.gid &&
    a.nlink === b.nlink && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

/** Validate opaque profile-root storage while the actual Engine Owner is held.
 * Never adopt a symlink or a file that can be written through another name. */
export async function assertEngineRootStorage(owner: OwnerLease, root: Identity): Promise<void> {
  await owner.assert();
  const uid = BigInt(ownerUid()), device = BigInt(root.device);
  const path = owner.profile.paths.root;
  let visited = 0;
  const check = async (parent: string, name: string, depth: number): Promise<void> => {
    if (depth > 128 || ++visited > storageNodeLimit) throw profileUnavailable();
    const child = join(parent, name);
    const first = await lstat(child, { bigint: true });
    const folder = first.isDirectory(), type = depth === 0 ? knownEngineRootTypes.get(name) : undefined;
    if (first.dev !== device || first.uid !== uid || (first.mode & 0o022n) !== 0n ||
        (!folder && (!first.isFile() || first.nlink !== 1n)) ||
        (type && folder !== (type === 'directory'))) throw profileUnavailable();
    const handle = await open(child, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK |
      (folder ? constants.O_DIRECTORY : 0));
    try {
      if (!sameStorageNode(first, await handle.stat({ bigint: true })) ||
          !sameStorageNode(first, await lstat(child, { bigint: true }))) throw profileUnavailable();
      if (folder) for (const entry of await storageNames(child)) await check(child, entry, depth + 1);
      if (!sameStorageNode(first, await handle.stat({ bigint: true })) ||
          !sameStorageNode(first, await lstat(child, { bigint: true }))) throw profileUnavailable();
    } finally { await handle.close(); }
  };
  const held = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try {
    const first = await held.stat({ bigint: true });
    if (first.dev !== device || first.ino !== BigInt(root.inode) || first.uid !== uid || (first.mode & 0o7777n) !== 0o700n ||
        !sameStorageNode(first, await lstat(path, { bigint: true }))) throw profileUnavailable();
    for (const name of await storageNames(path)) if (!nonEngineRootNames.has(name)) await check(path, name, 0);
    if (!sameStorageNode(first, await held.stat({ bigint: true })) ||
        !sameStorageNode(first, await lstat(path, { bigint: true }))) throw profileUnavailable();
  } finally { await held.close(); }
  await owner.assert();
}
/** Supplied by signed package preflight, never by CLI input or PackageMetadata.
 * assertTrusted must verify the exact immutable Build/runtime/manifest payload.
 * ABR-2 provides no permissive production implementation of this authority. */
export interface EngineAuthority {
  readonly build: string;
  readonly manifest: Readonly<Contract<'native.BuildCompatibility'>>;
  assertTrusted(): Promise<void>;
  /** Includes original main process AND owned helpers, not just flock/PID death. */
  assertPreviousEngineExited(profile: ProfileSnapshot): Promise<void>;
  /** Production-only native claim permit. Its original short lock spans the
   * real atomic marker transaction; acceptance captures the resulting inode. */
  beginMutation?(owner: OwnerLease, marker: Readonly<EngineMarker>): Promise<EngineMutation>;
}
export interface EngineMutation {
  accept(): void;
  assertBound(): void;
  abort(): never;
}
export interface EngineExitEvidence {
  /** Called after Chromium session/storage flush and complete main/helper exit.
   * An adapter disconnect, closed window or bare app quit event is insufficient. */
  assertCompleteExitAndFlush(profile: ProfileSnapshot): Promise<void>;
}
export interface EngineTransaction {
  readonly owner: OwnerLease;
  readonly marker: Readonly<EngineMarker>;
  assertReady(): Promise<void>;
  /** Does not release ownership; keep owner/build protection until this settles. */
  completeExit(evidence: EngineExitEvidence): Promise<void>;
}
export interface EngineInspection {
  /** A single continuation bound to the inspected Owner and prior marker. */
  prepare(): Promise<EngineTransaction>;
}
const inspectedOwners = new WeakSet<OwnerLease>();
interface StoredMarker { readonly marker: Readonly<EngineMarker>; readonly identity: Identity }
async function storedMarker(profile: ProfileSnapshot): Promise<StoredMarker | undefined> {
  if (!await statOrAbsent(profile.paths.engine)) return undefined;
  const read = await readJson(profile.paths.engine);
  if (!validator('profile2.EngineMarker')(read.value) || read.value.profileInstance !== profile.record.instance)
    throw profileUnavailable();
  return { marker: Object.freeze({ ...read.value }), identity: read.identity };
}
async function emptyDirectory(path: string): Promise<boolean> {
  const entries = await opendir(path);
  try { return await entries.read() === null; } finally { await entries.close(); }
}
async function assertFreshStorage(profile: ProfileSnapshot): Promise<void> {
  // A missing marker never adopts existing native storage, even after a crash.
  if (!await emptyDirectory(profile.paths.data) || !await emptyDirectory(profile.paths.userData) ||
      (await storageNames(profile.paths.root)).some(name => !nonEngineRootNames.has(name))) throw profileUnavailable();
}
async function assertMarker(profile: ProfileSnapshot, expected: StoredMarker | undefined): Promise<void> {
  const current = await storedMarker(profile);
  if (Boolean(current) !== Boolean(expected) || (current && expected &&
      (!sameIdentity(current.identity, expected.identity) || JSON.stringify(current.marker) !== JSON.stringify(expected.marker))))
    throw profileUnavailable();
}
async function replaceMarker(owner: OwnerLease, expected: StoredMarker | undefined,
  marker: EngineMarker): Promise<StoredMarker> {
  const profile = owner.profile;
  await owner.assert(); await assertMarker(profile, expected);
  // No temporary metadata is written until all format/compatibility checks pass.
  const temporary = join(profile.paths.root, `.engine-${randomBytes(16).toString('hex')}.tmp`);
  await writeNewFile(temporary, `${JSON.stringify(marker)}\n`);
  await owner.assert(); await assertMarker(profile, expected);
  await rename(temporary, profile.paths.engine);
  await syncDirectory(profile.paths.root);
  await owner.assert();
  const result = await storedMarker(profile);
  if (!result || JSON.stringify(result.marker) !== JSON.stringify(marker)) throw profileUnavailable();
  return result;
}
/** Dirty markers are readable only by an explicitly allowed reader/epoch.
 * No major-version, management-format or lexical-version inference is used. */
export type EnginePreparationStage = 'engine-owner-policy' | 'marker-read' | 'existing-marker-compatibility' |
  'fresh-marker-compatibility' | 'verified-prior-exit' | 'native-marker-permit';
export async function inspectEngine(owner: OwnerLease, authority: EngineAuthority,
  observation?: (stage: EnginePreparationStage) => void): Promise<EngineInspection> {
  // The production caller closes over its original custody only. Foundation
  // supplies nothing; this helper never participates in a check or failure.
  const note = (stage: EnginePreparationStage) => { try { observation?.(stage); } catch { /* warning only */ } };
  try {
    // Consume before the first await. Failed preparation also requires a fresh
    // ownership transaction; no same-lease retry may race a prior continuation.
    if (inspectedOwners.has(owner)) throw profileUnavailable();
    inspectedOwners.add(owner);
    note('engine-owner-policy');
    await owner.assert();
    const profile = owner.profile;
    await authority.assertTrusted();
    note('marker-read');
    const previous = await storedMarker(profile);
    // Snapshot verified inputs: later caller mutation must not change the transaction.
    const manifest: Contract<'native.BuildCompatibility'> = structuredClone(authority.manifest);
    const build = authority.build;
    if (!validator('native.BuildCompatibility')(manifest) || !validator('browser.Build')(build) ||
        !manifest.compatibleReaderKeys.includes(manifest.writerKey) || !manifest.readableDataEpochs.includes(manifest.dataEpoch))
      throw profileUnavailable();
    if (previous) {
      note('existing-marker-compatibility');
      if (!manifest.readableDataEpochs.includes(previous.marker.dataEpoch) ||
          !manifest.compatibleReaderKeys.includes(previous.marker.requiredReader)) throw profileUnavailable();
    } else {
      note('fresh-marker-compatibility');
      if (manifest.dataEpoch !== 1) throw profileUnavailable();
      await assertFreshStorage(profile);
    }
    note('verified-prior-exit');
    await authority.assertPreviousEngineExited(profile);
    await owner.assert(); await assertMarker(profile, previous);
    const dirty: EngineMarker = { format: 2, profileInstance: profile.record.instance, engine: 'chromium',
      dataEpoch: manifest.dataEpoch, lastWriterBuild: build, lastWriterChromium: manifest.runtime.chromium,
      lastWriterElectron: manifest.runtime.electron, requiredReader: manifest.writerKey, cleanExit: false };
    if (!validator('profile2.EngineMarker')(dirty)) throw profileUnavailable();
    const beginMutation = authority.beginMutation?.bind(authority);
    let consumed = false;
    return Object.freeze({ async prepare(): Promise<EngineTransaction> {
      if (consumed) throw profileUnavailable();
      consumed = true;
      try {
        await owner.assert();
        if (!previous) await assertFreshStorage(profile);
        await assertMarker(profile, previous);
        note('native-marker-permit');
        const mutation = await beginMutation?.(owner, Object.freeze(dirty));
        return await bindEngineMarker(owner, previous, dirty, mutation);
      } catch (error) { if (error instanceof BrowserFailure) throw error; throw profileUnavailable(); }
    } });
  } catch (error) { if (error instanceof BrowserFailure) throw error; throw profileUnavailable(); }
}

async function bindEngineMarker(owner: OwnerLease, previous: StoredMarker | undefined, dirty: EngineMarker,
  mutation: EngineMutation | undefined): Promise<EngineTransaction> {
  const profile = owner.profile;
  let current: StoredMarker;
  try { current = await replaceMarker(owner, previous, dirty); mutation?.accept(); }
  catch (error) { if (mutation) return mutation.abort(); throw error; }
  let phase: 'prepared' | 'closing' | 'clean' | 'failed' = 'prepared';
  return Object.freeze({ owner, marker: current.marker,
    async assertReady() {
      if (phase !== 'prepared') throw profileUnavailable();
      await owner.assert(); await assertMarker(profile, current);
      mutation?.assertBound();
    },
    async completeExit(evidence: EngineExitEvidence) {
      // A real host cannot certify its own future process death or publish
      // clean while disappearing. Its retained native finalizer does that.
      if (mutation || phase !== 'prepared') throw profileUnavailable();
      phase = 'closing';
      try {
        await owner.assert(); await assertMarker(profile, current);
        await evidence.assertCompleteExitAndFlush(profile);
        await owner.assert(); await assertMarker(profile, current);
        current = await replaceMarker(owner, current, { ...dirty, cleanExit: true });
        phase = 'clean';
      } catch { phase = 'failed'; throw profileUnavailable(); }
    },
  });
}

export async function prepareEngine(owner: OwnerLease, authority: EngineAuthority,
  observation?: (stage: EnginePreparationStage) => void): Promise<EngineTransaction> {
  return (await inspectEngine(owner, authority, observation)).prepare();
}
