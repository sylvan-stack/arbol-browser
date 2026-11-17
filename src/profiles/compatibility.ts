import { opendir, rename } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { BrowserFailure } from '../contracts/errors.js';
import { profileUnavailable, statOrAbsent, sameIdentity, syncDirectory, type Identity } from './paths.js';
import { readJson, writeNewFile, type ProfileSnapshot } from './records.js';
import type { OwnerLease } from './locking.js';

export type EngineMarker = Contract<'profile.EngineMarker'>;
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
const preparedOwners = new WeakSet<OwnerLease>();
interface StoredMarker { readonly marker: Readonly<EngineMarker>; readonly identity: Identity }
async function storedMarker(profile: ProfileSnapshot): Promise<StoredMarker | undefined> {
  if (!await statOrAbsent(profile.paths.engine)) return undefined;
  const read = await readJson(profile.paths.engine);
  if (!validator('profile.EngineMarker')(read.value) || read.value.profileInstance !== profile.record.instance)
    throw profileUnavailable();
  return { marker: Object.freeze({ ...read.value }), identity: read.identity };
}
async function emptyDirectory(path: string): Promise<boolean> {
  const entries = await opendir(path);
  try { return await entries.read() === null; } finally { await entries.close(); }
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
export async function prepareEngine(owner: OwnerLease, authority: EngineAuthority): Promise<EngineTransaction> {
  try {
    // Consume before the first await. Failed preparation also requires a fresh
    // ownership transaction; no same-lease retry may race a prior continuation.
    if (preparedOwners.has(owner)) throw profileUnavailable();
    preparedOwners.add(owner);
    await owner.assert();
    const profile = owner.profile;
    await authority.assertTrusted();
    const previous = await storedMarker(profile);
    // Snapshot verified inputs: later caller mutation must not change the transaction.
    const manifest: Contract<'native.BuildCompatibility'> = structuredClone(authority.manifest);
    const build = authority.build;
    if (!validator('native.BuildCompatibility')(manifest) || !validator('browser.Build')(build) ||
        !manifest.compatibleReaderKeys.includes(manifest.writerKey) || !manifest.readableDataEpochs.includes(manifest.dataEpoch))
      throw profileUnavailable();
    if (previous) {
      if (!manifest.readableDataEpochs.includes(previous.marker.dataEpoch) ||
          !manifest.compatibleReaderKeys.includes(previous.marker.requiredReader)) throw profileUnavailable();
    } else {
      // Missing marker never adopts existing native storage, even after a crash.
      if (manifest.dataEpoch !== 1 || !await emptyDirectory(profile.paths.data) ||
          !await emptyDirectory(profile.paths.userData)) throw profileUnavailable();
    }
    await authority.assertPreviousEngineExited(profile);
    await owner.assert(); await assertMarker(profile, previous);
    const dirty: EngineMarker = { format: 1, profileInstance: profile.record.instance, engine: 'chromium',
      dataEpoch: manifest.dataEpoch, lastWriterBuild: build, lastWriterChromium: manifest.runtime.chromium,
      lastWriterElectron: manifest.runtime.electron, requiredReader: manifest.writerKey, cleanExit: false };
    if (!validator('profile.EngineMarker')(dirty)) throw profileUnavailable();
    const mutation = await authority.beginMutation?.(owner, Object.freeze({ ...dirty }));
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
        // clean while disappearing. Its original retained native finalizer is
        // the only production clean writer. Foundation's explicit port remains.
        if (mutation) throw profileUnavailable();
        if (phase !== 'prepared') throw profileUnavailable();
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
  } catch (error) { if (error instanceof BrowserFailure) throw error; throw profileUnavailable(); }
}
