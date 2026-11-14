import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { validator } from '../contracts/schema.js';
import type { Contract } from '../contracts/generated.js';
import { directory, identity, sameIdentity, privateFile, profileId, profileMissing, profileUnavailable,
  missing, type Identity, type ProfilePaths, assertDirectory } from './paths.js';

export type ProfileRecord = Contract<'profile.ProfileRecord'>;
export interface ProfileSnapshot {
  readonly paths: ProfilePaths; readonly record: Readonly<ProfileRecord>;
  readonly rootIdentity: Identity; readonly recordIdentity: Identity; readonly dataIdentity: Identity;
}
/** No-follow, bounded management JSON only. Never reads any Chromium content. */
export async function readJson(path: string, maxBytes = 65536): Promise<{ value: unknown; identity: Identity }> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat(); privateFile(before);
    if (before.size > maxBytes) throw profileUnavailable();
    const bytes = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const after = await handle.stat(); privateFile(after);
    const published = await lstat(path); privateFile(published);
    if (!sameIdentity(identity(published), identity(before))) throw profileUnavailable();
    if (bytesRead !== before.size || bytesRead > maxBytes || after.size !== before.size ||
        after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw profileUnavailable();
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, bytesRead)));
    return { value, identity: identity(before) };
  } finally { await handle.close(); }
}
export function validatedRecord(value: unknown, id: string): Readonly<ProfileRecord> {
  if (!validator('profile.ProfileRecord')(value) || value.id !== id || !value.createdAt.endsWith('Z')) throw profileUnavailable();
  return Object.freeze({ ...value });
}
export function newRecord(id: string, creationRequest = `create_${randomBytes(16).toString('base64url')}`): Readonly<ProfileRecord> {
  profileId(id);
  return validatedRecord({ format: 1, id, instance: `prf_${randomBytes(16).toString('base64url')}`,
    creationRequest, createdAt: new Date().toISOString() }, id);
}
export async function readProfile(paths: ProfilePaths): Promise<ProfileSnapshot> {
  try {
    await directory(paths.state); await directory(paths.profiles);
    const rootIdentity = await directory(paths.root);
    const raw = await readJson(paths.record);
    // Refuse an unsupported management format before opening a lock or changing a file.
    const record = validatedRecord(raw.value, paths.id);
    const dataIdentity = await directory(paths.data);
    await directory(paths.logs);
    await assertDirectory(paths.root, rootIdentity);
    return Object.freeze({ paths, record, rootIdentity, recordIdentity: raw.identity, dataIdentity });
  } catch (error) {
    if (missing(error)) {
      // A missing whole profile is distinct from an incomplete destination.
      const { statOrAbsent } = await import('./paths.js');
      if (!await statOrAbsent(paths.root)) throw profileMissing();
    }
    throw profileUnavailable();
  }
}
export async function assertProfile(snapshot: ProfileSnapshot): Promise<void> {
  const current = await readProfile(snapshot.paths);
  if (!sameIdentity(current.rootIdentity, snapshot.rootIdentity) ||
      !sameIdentity(current.dataIdentity, snapshot.dataIdentity) ||
      !sameIdentity(current.recordIdentity, snapshot.recordIdentity) ||
      JSON.stringify(current.record) !== JSON.stringify(snapshot.record)) throw profileUnavailable();
}
/** New files only, synchronized before they can be published. */
export async function writeNewFile(path: string, content: string): Promise<void> {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { privateFile(await handle.stat()); await handle.writeFile(content, 'utf8'); await handle.sync(); }
  finally { await handle.close(); }
}
