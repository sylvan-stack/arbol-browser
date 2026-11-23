import { constants, type BigIntStats } from 'node:fs';
import { lstat, mkdir, open, realpath, link, unlink } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { dirname, join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertMigrationAdmission, type MigrationAdmission } from './migration-admission.js';
import { assertMigrationPreflight, type MigrationPreflight } from './migration-preflight.js';
import { migrationDirectory, migrationIdentity, migrationDigest, migrationValue, readMigrationFile, sameMigrationFile,
  sameMigrationIdentity, type MigrationContent, type MigrationIdentity } from './migration-owner.js';
import { missing, ownerUid, profileUnavailable, syncDirectory } from './paths.js';

const mercury = '/Volumes/Mercury', archiveRoot = `${mercury}/Arbol`;
// ARC-5's real archive identity, shared with Arbol database/archive_volume.py.
const mercuryUUID = 'AE1E97B8-CE93-4019-B6DC-21482165C3F2';
const transactionLimit = 4096 * (4 * 87384 + 8192) + 65536;
export class MigrationArchiveUnavailable extends Error {
  readonly code = 'archive_unavailable';
  constructor() { super('The verified Mercury archive is unavailable.'); }
}
export function migrationTime(deadline: number): void {
  if (!Number.isFinite(deadline) || performance.now() >= deadline) throw profileUnavailable();
}
export async function migrationAbsent(path: string): Promise<void> {
  try { await lstat(path); } catch (error) { if (missing(error)) return; throw error; }
  throw profileUnavailable();
}
export async function ensureMigrationDirectory(path: string, assert: () => Promise<void>): Promise<MigrationIdentity> {
  await assert(); const parent = await migrationDirectory(dirname(path));
  try { await lstat(path); }
  catch (error) {
    if (!missing(error)) throw error;
    await mkdir(path, { mode: 0o700 }); await syncDirectory(dirname(path));
  }
  const result = await migrationDirectory(path);
  if (result.device !== parent.device || !sameMigrationIdentity(parent, await migrationDirectory(dirname(path)))) throw profileUnavailable();
  await assert(); return result;
}
/** Atomic no-replace publication. A same-directory private temporary file is
 * fsynced before linking the final name, then unlinked and the directory synced.
 * Crash-between-link-and-unlink remains a closed, unprovable two-link file;
 * it is never accepted as a management record or silently overwritten. */
export async function publishMigrationFile(path: string, bytes: Uint8Array, deadline: number,
  assert: () => Promise<void>): Promise<MigrationContent> {
  migrationTime(deadline); await assert();
  const parent = await migrationDirectory(dirname(path)); await migrationAbsent(path);
  const temporary = join(dirname(path), `.migration-${randomBytes(16).toString('hex')}`);
  const fd = await open(temporary, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const original = await fd.stat({ bigint: true });
    if (!original.isFile() || original.nlink !== 1n || original.uid !== BigInt(ownerUid()) || (original.mode & 0o7777n) !== 0o600n ||
        String(original.dev) !== parent.device) throw profileUnavailable();
    await fd.writeFile(bytes); await fd.sync();
    const staged = await readMigrationFile(temporary, Math.max(65536, bytes.byteLength));
    if (staged.sha256 !== migrationDigest(bytes) || !sameMigrationIdentity(staged.identity, migrationIdentity(original))) throw profileUnavailable();
    await assert(); migrationTime(deadline);
    if (!sameMigrationIdentity(parent, await migrationDirectory(dirname(path)))) throw profileUnavailable();
    await link(temporary, path);
    const published = await lstat(path, { bigint: true }), held = await fd.stat({ bigint: true });
    if (!published.isFile() || published.dev !== original.dev || published.ino !== original.ino || published.nlink !== 2n ||
        held.dev !== original.dev || held.ino !== original.ino || held.nlink !== 2n) throw profileUnavailable();
    await unlink(temporary); await fd.sync(); await syncDirectory(dirname(path));
    const result = await readMigrationFile(path, Math.max(65536, bytes.byteLength));
    if (!sameMigrationFile(result, staged) || !sameMigrationIdentity(parent, await migrationDirectory(dirname(path)))) throw profileUnavailable();
    await assert(); migrationTime(deadline); return result;
  } finally { await fd.close(); }
}
interface Archive {
  assert(): Promise<void>;
  ensure(path: string): Promise<void>;
  write(path: string, bytes: Uint8Array): Promise<void>;
  read(path: string, limit: number): Promise<Buffer>;
  close(): Promise<void>;
}
/** No path override and no internal-disk fallback, including isolated runs. */
async function requireMercury(deadline: number): Promise<Archive> {
  const refuse = (): never => { throw new MigrationArchiveUnavailable(); };
  const command = (program: string, args: string[], input?: Buffer): Buffer => {
    migrationTime(deadline);
    const result = spawnSync(program, args, { ...(input ? { input } : {}), env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
      timeout: Math.max(1, Math.min(10000, Math.floor(deadline - performance.now()))), maxBuffer: 1048576 });
    if (result.error || result.status !== 0 || !result.stdout.length) return refuse();
    return result.stdout;
  };
  let mount;
  try {
    const raw = command('/usr/sbin/diskutil', ['info', '-plist', mercury]);
    const info = JSON.parse(command('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], raw).toString('utf8'));
    if (!info || info.MountPoint !== mercury || info.VolumeUUID !== mercuryUUID) return refuse();
    const original = await lstat(mercury, { bigint: true }), volumes = await lstat('/Volumes', { bigint: true });
    if (!original.isDirectory() || original.dev === volumes.dev || await realpath(mercury) !== mercury) return refuse();
    mount = await open(mercury, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const retained = mount;
    const assert = async (): Promise<void> => {
      migrationTime(deadline);
      const held = await retained.stat({ bigint: true }), named = await lstat(mercury, { bigint: true });
      if (![held, named].every(st => st.isDirectory() && st.dev === original.dev && st.ino === original.ino) ||
          await realpath(mercury) !== mercury) refuse();
    };
    const path = async (target: string, absent = false): Promise<BigIntStats | undefined> => {
      await assert();
      if (resolve(target) !== target || (target !== archiveRoot && !target.startsWith(`${archiveRoot}/`))) return refuse();
      const parts = relative(mercury, target).split('/'); let current = mercury, last: BigIntStats | undefined;
      for (let index = 0; index < parts.length; index++) {
        current = join(current, parts[index]!);
        try { last = await lstat(current, { bigint: true }); }
        catch (error) { if (absent && missing(error) && index === parts.length - 1) return undefined; throw error; }
        if (last.dev !== original.dev || (!last.isDirectory() && !(index === parts.length - 1 && last.isFile() && last.nlink === 1n))) return refuse();
      }
      await assert(); return last;
    };
    if (!(await path(archiveRoot))?.isDirectory()) return refuse();
    return {
      assert,
      async ensure(target) {
        if (!await path(target, true)) { await mkdir(target, { mode: 0o700 }); }
        if (!(await path(target))?.isDirectory()) refuse();
        const fd = await open(dirname(target), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        try { await fd.sync(); } finally { await fd.close(); }
        await assert();
      },
      async write(target, bytes) {
        if (await path(target, true)) refuse();
        const fd = await open(target, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try {
          await fd.writeFile(bytes); await fd.sync();
          const held = await fd.stat({ bigint: true }), named = await path(target);
          if (!held.isFile() || held.nlink !== 1n || held.dev !== original.dev || !named || held.ino !== named.ino || held.size !== BigInt(bytes.byteLength)) refuse();
          const read = Buffer.alloc(bytes.byteLength); let at = 0;
          while (at < read.length) { const part = await fd.read(read, at, read.length - at, at); if (!part.bytesRead) refuse(); at += part.bytesRead; }
          if (migrationDigest(read) !== migrationDigest(bytes)) refuse();
          const parent = await open(dirname(target), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
          try { await parent.sync(); } finally { await parent.close(); }
          await assert();
        } finally { await fd.close(); }
      },
      async read(target, limit) {
        const named = await path(target);
        if (!named?.isFile() || named.size < 1n || named.size > BigInt(limit)) return refuse();
        const fd = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        try {
          const same = (value: BigIntStats) => value.isFile() && value.dev === named.dev && value.ino === named.ino &&
            value.nlink === 1n && value.size === named.size && value.mtimeNs === named.mtimeNs && value.ctimeNs === named.ctimeNs;
          if (!same(await fd.stat({ bigint: true }))) return refuse();
          const bytes = Buffer.alloc(Number(named.size) + 1); let count = 0;
          while (count < bytes.length) { const part = await fd.read(bytes, count, bytes.length - count, count); if (!part.bytesRead) break; count += part.bytesRead; }
          const after = await path(target);
          if (count !== Number(named.size) || !after || !same(after) || !same(await fd.stat({ bigint: true }))) return refuse();
          return bytes.subarray(0, count);
        } finally { await fd.close(); }
      },
      close: () => retained.close(),
    };
  } catch { if (mount) await mount.close(); return refuse(); }
}
export interface MigrationTransaction {
  readonly admission: MigrationAdmission;
  readonly value: Readonly<Contract<'migration.Transaction'>>;
  readonly file: MigrationContent; readonly current: MigrationContent;
  readonly root: string; readonly attempt: string;
  assert(deadline: number): Promise<void>;
}
const transactions = new WeakSet<object>();
export function assertMigrationTransaction(value: MigrationTransaction): void {
  if (!transactions.has(value)) throw profileUnavailable(); assertMigrationAdmission(value.admission);
}
export async function verifyMigrationArchive(transaction: MigrationTransaction, deadline: number): Promise<void> {
  assertMigrationTransaction(transaction); await transaction.assert(deadline);
  const archive = await requireMercury(deadline);
  try {
    const backup = join(archiveRoot, 'backups', 'browser-profile-format-2', transaction.value.attempt);
    if (migrationDigest(await archive.read(join(backup, 'transaction.json'), transactionLimit)) !== transaction.file.sha256)
      throw new MigrationArchiveUnavailable();
    for (const entry of transaction.value.profiles) {
      if (migrationDigest(await archive.read(join(backup, entry.pathSha256, 'profile.json'), 65536)) !== entry.originalRecord.sha256 ||
          (entry.originalMarker && migrationDigest(await archive.read(join(backup, entry.pathSha256, 'engine.json'), 65536)) !== entry.originalMarker.sha256))
        throw new MigrationArchiveUnavailable();
    }
    await archive.assert(); await transaction.assert(deadline);
  } catch { throw new MigrationArchiveUnavailable(); }
  finally { await archive.close(); }
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value;
}
/** Reopen only exact native-bound admission; caller separately reacquires the
 * original registry/owner custody and classifies physical files for recovery. */
export async function readMigrationTransaction(admission: MigrationAdmission, deadline: number): Promise<MigrationTransaction | null> {
  await admission.assert(deadline);
  const facts = admission.custody.facts, root = join(facts.runtime, 'browser-profile-migration'), path = join(root, 'current');
  try { await lstat(path); } catch (error) { if (missing(error)) return null; throw error; }
  const rootIdentity = await migrationDirectory(root), current = await readMigrationFile(path, 16384);
  const pointer = migrationValue(current, 16384) as { format?: unknown; attempt?: unknown; transactionSha256?: unknown };
  if (!pointer || Object.keys(pointer).sort().join(',') !== 'attempt,format,transactionSha256' || pointer.format !== 1 ||
      typeof pointer.attempt !== 'string' || !/^[0-9a-f]{32}$/.test(pointer.attempt) ||
      typeof pointer.transactionSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(pointer.transactionSha256)) throw profileUnavailable();
  const attempt = join(root, pointer.attempt), attemptIdentity = await migrationDirectory(attempt);
  const file = await readMigrationFile(join(attempt, 'transaction.json'), transactionLimit), value = migrationValue(file, transactionLimit);
  if (file.sha256 !== pointer.transactionSha256 || !validator('migration.Transaction')(value) || value.attempt !== pointer.attempt ||
      value.epoch !== facts.epoch || value.root.path !== facts.stateRoot || value.root.initial !== admission.host.root.initial ||
      !isDeepStrictEqual(value.root.identity, admission.host.root.identity) || !sameMigrationIdentity(value.runtime, facts.runtimeIdentity) ||
      !sameMigrationFile(value.journal, facts.journal) || !isDeepStrictEqual(value.selection, admission.selection) ||
      !isDeepStrictEqual(value.selectionFile, facts.selection) || !isDeepStrictEqual(value.oldBuild, admission.journal.before) ||
      !isDeepStrictEqual(value.newBuild, admission.journal.after) || value.sourceSha256 !== admission.host.identity.sourceDigest ||
      value.productSha256 !== admission.host.identity.productDigest || value.candidateSha256 !== admission.host.signed.snapshotDigest) throw profileUnavailable();
  const transaction: MigrationTransaction = Object.freeze({ admission, value: freeze(value), file, current, root, attempt,
    async assert(cutoff: number) {
      await admission.assert(cutoff);
      if (!sameMigrationIdentity(rootIdentity, await migrationDirectory(root)) || !sameMigrationIdentity(attemptIdentity, await migrationDirectory(attempt)) ||
          !sameMigrationFile(file, await readMigrationFile(join(attempt, 'transaction.json'), transactionLimit)) ||
          !sameMigrationFile(current, await readMigrationFile(path, 16384))) throw profileUnavailable();
      await admission.assert(cutoff);
    },
  });
  transactions.add(transaction); await transaction.assert(deadline); return transaction;
}
export async function createMigrationTransaction(preflight: MigrationPreflight, deadline: number): Promise<MigrationTransaction> {
  assertMigrationPreflight(preflight); await preflight.assertOriginals(deadline);
  const admission = preflight.admission, facts = admission.custody.facts;
  const root = join(facts.runtime, 'browser-profile-migration'); await migrationAbsent(join(root, 'current'));
  const id = randomBytes(16).toString('hex'), attempt = join(root, id);
  const value: Contract<'migration.Transaction'> = { format: 1, kind: 'browser-profile-migration', attempt: id,
    root: preflight.root, runtime: facts.runtimeIdentity, selection: admission.selection, selectionFile: facts.selection,
    journal: facts.journal, epoch: facts.epoch, oldBuild: admission.journal.before, newBuild: admission.journal.after,
    sourceSha256: admission.host.identity.sourceDigest, productSha256: admission.host.identity.productDigest,
    candidateSha256: admission.host.signed.snapshotDigest, profiles: preflight.profiles.map(profile => profile.entry) };
  if (!validator('migration.Transaction')(value)) throw profileUnavailable();
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  const archive = await requireMercury(deadline);
  try {
    const backups = join(archiveRoot, 'backups'), base = join(backups, 'browser-profile-format-2'), backup = join(base, id);
    await archive.ensure(backups); await archive.ensure(base); await archive.ensure(backup);
    for (const { owner, entry } of preflight.profiles) {
      await admission.assert(deadline); await owner.assert(); await archive.assert();
      const folder = join(backup, entry.pathSha256); await archive.ensure(folder);
      await archive.write(join(folder, 'profile.json'), Buffer.from(entry.originalRecord.base64, 'base64'));
      if (entry.originalMarker) await archive.write(join(folder, 'engine.json'), Buffer.from(entry.originalMarker.base64, 'base64'));
    }
    await archive.write(join(backup, 'transaction.json'), bytes);
    await preflight.assertOriginals(deadline); await archive.assert();
    const assert = async () => { await preflight.assertOriginals(deadline); await archive.assert(); await migrationAbsent(join(root, 'current')); };
    await ensureMigrationDirectory(root, assert); await migrationAbsent(attempt);
    await ensureMigrationDirectory(attempt, assert); await ensureMigrationDirectory(join(attempt, 'progress'), assert);
    const file = await publishMigrationFile(join(attempt, 'transaction.json'), bytes, deadline, assert);
    await archive.assert(); await preflight.assertOriginals(deadline);
    // After the pointer is visible it cannot be required absent by the final
    // assertion. Exact transaction/admission and native custody remain held.
    await publishMigrationFile(join(root, 'current'), Buffer.from(`${JSON.stringify({ format: 1, attempt: id, transactionSha256: file.sha256 })}\n`),
      deadline, async () => { await preflight.assertOriginals(deadline); await archive.assert(); });
    const transaction = await readMigrationTransaction(admission, deadline); if (!transaction) throw profileUnavailable();
    return transaction;
  } finally { await archive.close(); }
}
