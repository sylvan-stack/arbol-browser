import { performance } from 'node:perf_hooks';
import { mkdir, opendir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import type { PlatformPort } from '../runtime/platform.js';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, invalidInput, unavailable } from '../contracts/errors.js';
import { profilePaths, directory, assertDirectory, statOrAbsent, syncDirectory, profileUnavailable, profileId, privateFile, stateDirectory, profileMissing } from './paths.js';
import { writeNewFile, readProfile, newRecord, type ProfileRecord, type ProfileSnapshot } from './records.js';
import { lockExisting, registryLock, lockDeadline, type RegistryLease } from './locking.js';

function requireActiveSelection(signal?: AbortSignal): void {
  if (signal?.aborted) throw unavailable('browser');
}

/** Internal transaction. No cleanup of uncertain staging directories and no adoption.
 * A failure after rename may have committed creation; only the exact receipt may retry. */
export async function publishProfile(registry: RegistryLease, record: Readonly<ProfileRecord>,
  deadline: number, signal?: AbortSignal): Promise<ProfileSnapshot> {
  requireActiveSelection(signal);
  if (performance.now() >= deadline) throw profileUnavailable();
  await registry.assert();
  const paths = profilePaths(record.id, registry.state);
  if (await statOrAbsent(paths.root)) throw profileUnavailable();
  requireActiveSelection(signal);
  const staged = join(paths.profiles, `.creating-${randomBytes(16).toString('hex')}`);
  await mkdir(staged, { mode: 0o700 });
  const stagedIdentity = await directory(staged);
  for (const name of ['data', 'logs', 'userData']) await mkdir(join(staged, name), { mode: 0o700 });
  await writeNewFile(join(staged, 'profile.json'), `${JSON.stringify(record)}\n`);
  await writeNewFile(join(staged, 'owner.lock'), '');
  for (const name of ['data', 'logs', 'userData']) await syncDirectory(join(staged, name));
  await syncDirectory(staged);
  await registry.assert(); await assertDirectory(staged, stagedIdentity);
  if (performance.now() >= deadline) throw profileUnavailable();
  requireActiveSelection(signal);
  registry.platform.publishDirectory(staged, paths.root);
  // Continue to verify the committed profile even if the caller now leaves.
  await syncDirectory(paths.profiles);
  await registry.assert(); await assertDirectory(paths.root, stagedIdentity);
  const published = await readProfile(paths);
  const owner = await lockExisting(published, registry.platform, deadline);
  try { await registry.assert(); await owner.assert(); return published; }
  finally { owner.release(); }
}

export const MAX_PROFILES = 4096;
/** Bounded metadata scan, including incomplete destinations as refusals rather than
 * partial success. Private transaction remnants are preserved and never adopted. */
export async function managedProfiles(registry: RegistryLease): Promise<ProfileSnapshot[]> {
  await registry.assert();
  const records: ProfileSnapshot[] = [];
  const entries = await opendir(join(registry.state, 'profiles'));
  let count = 0;
  for await (const entry of entries) {
    if (++count > MAX_PROFILES * 2) throw profileUnavailable();
    if (/^\.(creating|deleting)-[0-9a-f]{32}$/.test(entry.name)) {
      await directory(join(registry.state, 'profiles', entry.name));
      continue;
    }
    // An unknown entry is uncertain registry state, not a name to omit.
    try { profileId(entry.name); } catch { throw profileUnavailable(); }
    const snapshot = await readProfile(profilePaths(entry.name, registry.state));
    const lock = await statOrAbsent(snapshot.paths.owner);
    if (!lock) throw profileUnavailable();
    privateFile(lock);
    records.push(snapshot);
    if (records.length > MAX_PROFILES) throw profileUnavailable();
  }
  await registry.assert();
  return records.sort((a, b) => a.record.id.localeCompare(b.record.id, 'en'));
}
function requestToken(request: string | undefined): void {
  if (request !== undefined && !/^create_[A-Za-z0-9_-]{22}$/.test(request)) throw invalidInput();
}
async function createManaged(id: string, request: string | undefined, platform: PlatformPort,
  state: string, allowDefault: boolean, deadline = lockDeadline(), signal?: AbortSignal): Promise<Contract<'profile.ProfileCreated'>> {
  profileId(id, !allowDefault); requestToken(request);
  const paths = profilePaths(id, state);
  try {
    requireActiveSelection(signal);
    // Unsupported existing metadata is read/refused before even registry creation.
    if (await statOrAbsent(paths.root)) await readProfile(paths);
    requireActiveSelection(signal);
    const registry = await registryLock(state, platform, true, deadline);
    try {
      requireActiveSelection(signal);
      const records = await managedProfiles(registry);
      requireActiveSelection(signal);
      const existing = records.find(item => item.record.id === id);
      if (existing) {
        // Internal default first use may converge, ordinary explicit creation may not.
        if ((allowDefault && id === 'default') || (request !== undefined && existing.record.creationRequest === request))
          return { profile: { ...existing.record }, created: false };
        throw profileUnavailable();
      }
      if (records.length >= MAX_PROFILES) throw new BrowserFailure({ code: 'control_refused',
        message: 'The profile registry is at capacity.', retryable: false,
        remedy: 'Remove an unused profile explicitly before creating another.' });
      const created = await publishProfile(registry, newRecord(id, request), deadline, signal);
      return { profile: { ...created.record }, created: true };
    } finally { registry.release(); }
  } catch (error) { if (error instanceof BrowserFailure) throw error; throw profileUnavailable(); }
}
export function createProfile(id: string, request: string | undefined, platform: PlatformPort,
  state = stateDirectory()): Promise<Contract<'profile.ProfileCreated'>> {
  return createManaged(id, request, platform, state, false);
}
/** The process service calls this before owner arbitration. Only startup may
 * create the default profile; existing and named selections are read-only. */
export async function selectProfile(id: string, platform: PlatformPort,
  options: { state?: string; createDefault?: boolean; deadline?: number; signal?: AbortSignal } = {}): Promise<ProfileSnapshot> {
  profileId(id);
  const state = options.state ?? stateDirectory(), paths = profilePaths(id, state);
  try {
    requireActiveSelection(options.signal);
    if (!await statOrAbsent(paths.root)) {
      requireActiveSelection(options.signal);
      if (id !== 'default' || !options.createDefault) throw profileMissing();
      await createManaged(id, undefined, platform, state, true, options.deadline, options.signal);
    }
    requireActiveSelection(options.signal);
    const selected = await readProfile(paths);
    requireActiveSelection(options.signal);
    return selected;
  } catch (error) { if (error instanceof BrowserFailure) throw error; throw profileUnavailable(); }
}
