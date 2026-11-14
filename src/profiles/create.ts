import { mkdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { profilePaths, directory, assertDirectory, statOrAbsent, syncDirectory, profileUnavailable } from './paths.js';
import { writeNewFile, readProfile, type ProfileRecord, type ProfileSnapshot } from './records.js';
import { lockExisting, type RegistryLease } from './locking.js';

/** Internal transaction. No cleanup of uncertain staging directories and no adoption.
 * A failure after rename may have committed creation; only the exact receipt may retry. */
export async function publishProfile(registry: RegistryLease, record: Readonly<ProfileRecord>,
  deadline: number): Promise<ProfileSnapshot> {
  await registry.assert();
  const paths = profilePaths(record.id, registry.state);
  if (await statOrAbsent(paths.root)) throw profileUnavailable();
  const staged = join(paths.profiles, `.creating-${randomBytes(16).toString('hex')}`);
  await mkdir(staged, { mode: 0o700 });
  const stagedIdentity = await directory(staged);
  for (const name of ['data', 'logs', 'userData']) await mkdir(join(staged, name), { mode: 0o700 });
  await writeNewFile(join(staged, 'profile.json'), `${JSON.stringify(record)}\n`);
  await writeNewFile(join(staged, 'owner.lock'), '');
  for (const name of ['data', 'logs', 'userData']) await syncDirectory(join(staged, name));
  await syncDirectory(staged);
  await registry.assert(); await assertDirectory(staged, stagedIdentity);
  registry.platform.publishDirectory(staged, paths.root);
  await syncDirectory(paths.profiles);
  await registry.assert(); await assertDirectory(paths.root, stagedIdentity);
  const published = await readProfile(paths);
  const owner = await lockExisting(published, registry.platform, deadline);
  try { await registry.assert(); await owner.assert(); return published; }
  finally { owner.release(); }
}
