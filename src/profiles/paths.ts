import { constants, lstatSync, realpathSync, type Stats } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { BrowserFailure, invalidInput } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import installation from '../runtime/installation-paths.json' with { type: 'json' };

export function profileUnavailable(): BrowserFailure {
  return new BrowserFailure({ code: 'profile_unavailable', message: 'Profile state or ownership cannot be verified.',
    retryable: false, remedy: 'Preserve the data and use a compatible qualified browser Build.' });
}
export function profileMissing(): BrowserFailure {
  return new BrowserFailure({ code: 'profile_not_found', message: 'The selected profile does not exist.', retryable: false }, 3);
}
export function profileId(id: unknown, additional = false): string {
  if (!validator('browser.ProfileId')(id) || (additional && id === 'default')) throw invalidInput();
  return id;
}
export function missing(error: unknown): boolean { return (error as NodeJS.ErrnoException)?.code === 'ENOENT'; }
export const ownerUid = (): number => {
  if (!process.geteuid) throw profileUnavailable();
  return process.geteuid();
};
export interface Identity { readonly device: number; readonly inode: number }
export function identity(stat: Stats): Identity { return Object.freeze({ device: stat.dev, inode: stat.ino }); }
export function sameIdentity(a: Identity, b: Identity): boolean { return a.device === b.device && a.inode === b.inode; }
export function privateFile(stat: Stats): void {
  if (!stat.isFile() || stat.uid !== ownerUid() || (stat.mode & 0o7777) !== 0o600 || stat.nlink !== 1) throw profileUnavailable();
}
export async function statOrAbsent(path: string): Promise<Stats | undefined> {
  try { return await lstat(path); } catch (error) { if (missing(error)) return undefined; throw profileUnavailable(); }
}
/** Inspect each lexical ancestor, rejecting symlinks and writable foreign paths.
 * Shared system/home ancestors may be readable; browser-owned directories are 0700. */
export async function directory(path: string, privateMode = true): Promise<Identity> {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes('\0')) throw profileUnavailable();
  const root = parse(path).root;
  let cursor = root;
  const uid = ownerUid();
  for (const part of path.slice(root.length).split('/').filter(Boolean)) {
    cursor = join(cursor, part);
    const st = await lstat(cursor);
    if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o022) !== 0 ||
        (st.uid !== uid && st.uid !== 0)) throw profileUnavailable();
  }
  const stat = await lstat(path);
  if (privateMode && (stat.uid !== uid || (stat.mode & 0o7777) !== 0o700)) throw profileUnavailable();
  if (await realpath(path) !== path) throw profileUnavailable();
  return identity(stat);
}
/** Same checks without yielding while a genuine short Claim is held. */
export function directorySync(path: string, privateMode = true): Identity {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes('\0')) throw profileUnavailable();
  const root = parse(path).root;
  let cursor = root;
  const uid = ownerUid();
  for (const part of path.slice(root.length).split('/').filter(Boolean)) {
    cursor = join(cursor, part);
    const st = lstatSync(cursor);
    if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o022) !== 0 ||
        (st.uid !== uid && st.uid !== 0)) throw profileUnavailable();
  }
  const stat = lstatSync(path);
  if (privateMode && (stat.uid !== uid || (stat.mode & 0o7777) !== 0o700)) throw profileUnavailable();
  if (realpathSync(path) !== path) throw profileUnavailable();
  return identity(stat);
}
export async function assertDirectory(path: string, expected: Identity): Promise<void> {
  if (!sameIdentity(await directory(path), expected)) throw profileUnavailable();
}
/** Never chmod/adopt an existing destination. Each created directory is separately checked. */
export async function ensureDirectory(path: string, privateMode = true): Promise<Identity> {
  const before = await statOrAbsent(path);
  let created = false;
  if (!before) {
    await directory(dirname(path), false);
    try { await mkdir(path, { mode: 0o700 }); created = true; } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
  }
  const result = await directory(path, privateMode);
  if (created) {
    await syncDirectory(path, privateMode);
    await syncDirectory(dirname(path), false);
  }
  return result;
}
export async function syncDirectory(path: string, privateMode = true): Promise<void> {
  const expected = await directory(path, privateMode);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try {
    if (!sameIdentity(identity(await handle.stat()), expected)) throw profileUnavailable();
    await handle.sync();
    if (!sameIdentity(await directory(path, privateMode), expected)) throw profileUnavailable();
  } finally { await handle.close(); }
}
export interface ProfilePaths {
  readonly state: string; readonly profiles: string; readonly registry: string;
  readonly id: string; readonly root: string; readonly record: string; readonly owner: string;
  readonly data: string; readonly logs: string; readonly userData: string; readonly engine: string;
}
export const stateDirectory = (): string => join(homedir(), installation.root, installation.browser);
export function profilePaths(id: string, state = stateDirectory()): ProfilePaths {
  profileId(id);
  if (!isAbsolute(state) || state !== resolve(state) || state.includes('\0')) throw profileUnavailable();
  const root = join(state, 'profiles', id);
  return Object.freeze({ state, profiles: join(state, 'profiles'), registry: join(state, 'registry.lock'), id, root,
    record: join(root, 'profile.json'), owner: join(root, 'owner.lock'), data: join(root, 'data'),
    logs: join(root, 'logs'), userData: join(root, 'userData'), engine: join(root, 'engine.json') });
}
/** Creation alone may establish browser/profiles. Missing selection never calls this. */
export async function ensureRegistry(state: string): Promise<void> {
  await ensureDirectory(dirname(state), state === stateDirectory());
  await ensureDirectory(state);
  await ensureDirectory(join(state, 'profiles'));
  await syncDirectory(state);
}
export async function registryExists(state: string): Promise<boolean> {
  if (!await statOrAbsent(state)) return false;
  await directory(state);
  if (!await statOrAbsent(join(state, 'profiles'))) throw profileUnavailable();
  await directory(join(state, 'profiles'));
  return true;
}
