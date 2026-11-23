import { constants, type BigIntStats } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertMaintenanceCustody, assertPlatform, type HeldLock, type MaintenanceCustody, type PlatformPort } from '../runtime/platform.js';
import { directory, ownerUid, profileId, profileUnavailable } from './paths.js';
import { parseStrictJson } from './strict-json.js';
import { convertProfileRecord } from './format2.js';

export type MigrationIdentity = Readonly<Contract<'migration.Identity'>>;
export type MigrationFile = Readonly<Contract<'migration.File'>>;
export type MigrationContent = Readonly<Contract<'migration.Content'>>;
export const migrationDigest = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
export function migrationIdentity(stat: BigIntStats): MigrationIdentity {
  return Object.freeze({ device: String(stat.dev), inode: String(stat.ino), uid: Number(stat.uid), mode: Number(stat.mode & 0o7777n) });
}
export function sameMigrationIdentity(a: MigrationIdentity, b: MigrationIdentity): boolean {
  return a.device === b.device && a.inode === b.inode && a.uid === b.uid && a.mode === b.mode;
}
export function sameMigrationFile(a: MigrationFile, b: MigrationFile): boolean {
  return sameMigrationIdentity(a.identity, b.identity) && a.sha256 === b.sha256;
}
function privateManagementFile(stat: BigIntStats): void {
  if (!stat.isFile() || stat.uid !== BigInt(ownerUid()) || (stat.mode & 0o7777n) !== 0o600n || stat.nlink !== 1n)
    throw profileUnavailable();
}
function samePhysicalFile(a: BigIntStats, b: BigIntStats): boolean {
  return ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs', 'birthtimeNs']
    .every(key => a[key as keyof BigIntStats] === b[key as keyof BigIntStats]);
}
export async function migrationDirectory(path: string): Promise<MigrationIdentity> {
  await directory(path);
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.uid !== BigInt(ownerUid()) || (stat.mode & 0o7777n) !== 0o700n) throw profileUnavailable();
  return migrationIdentity(stat);
}
/** Bounded management bytes only. The immutable base64 is the observed bytes;
 * callers cannot mutate an aliased Buffer or make a parsed object authoritative. */
export async function readMigrationFile(path: string, limit = 65536): Promise<MigrationContent> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1500000000) throw profileUnavailable();
  const parent = await migrationDirectory(dirname(path));
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat({ bigint: true }); privateManagementFile(before);
    if (before.size < 1n || before.size > BigInt(limit)) throw profileUnavailable();
    const bytes = Buffer.alloc(Number(before.size) + 1); let count = 0;
    while (count < bytes.length) {
      const read = await fd.read(bytes, count, bytes.length - count, count);
      if (!read.bytesRead) break;
      count += read.bytesRead;
    }
    const after = await fd.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    privateManagementFile(after); privateManagementFile(named);
    if (count !== Number(before.size) || !samePhysicalFile(before, after) || !samePhysicalFile(after, named) ||
        !sameMigrationIdentity(parent, await migrationDirectory(dirname(path)))) throw profileUnavailable();
    const raw = bytes.subarray(0, count);
    parseStrictJson(raw, limit);
    return Object.freeze({ identity: migrationIdentity(before), sha256: migrationDigest(raw), base64: raw.toString('base64') });
  } finally { await fd.close(); }
}
export function migrationValue(content: MigrationContent, limit = 65536): unknown {
  const bytes = Buffer.from(content.base64, 'base64');
  if (bytes.toString('base64') !== content.base64 || migrationDigest(bytes) !== content.sha256) throw profileUnavailable();
  return parseStrictJson(bytes, limit);
}
export interface MigrationOwner {
  readonly path: string; readonly state: string; readonly id: string; readonly instance: string;
  readonly directory: MigrationIdentity; readonly lock: MigrationIdentity; readonly original: MigrationContent;
  assert(): Promise<void>;
  /** Only the exact format-only target can join the accepted original inode. */
  admitStaged(staged: MigrationFile): Promise<void>;
  release(): void;
}
const descriptions = new WeakMap<MigrationOwner, { platform: PlatformPort; held: HeldLock; custody: MaintenanceCustody }>();
/** Existing owner.lock only, no wait and no creating or adopting an absent file. */
export async function acquireMigrationOwner(custody: MaintenanceCustody, platform: PlatformPort, id: string,
  original: MigrationContent, expectedDirectory: MigrationIdentity, expectedLock: MigrationIdentity,
  deadline: number, staged?: MigrationFile): Promise<MigrationOwner | null> {
  assertMaintenanceCustody(custody); assertPlatform(platform); profileId(id);
  if (performance.now() >= deadline || !validator('migration.Content')(original)) throw profileUnavailable();
  const value = migrationValue(original);
  if (!validator('profile.ProfileRecord')(value) || value.id !== id || !value.createdAt.endsWith('Z')) throw profileUnavailable();
  // Copy all caller records before any await. No mutable caller object becomes
  // an authority for a replacement inode later in the transaction.
  const source: MigrationContent = Object.freeze({ ...original, identity: Object.freeze({ ...original.identity }) });
  const root = Object.freeze({ ...expectedDirectory }), lock = Object.freeze({ ...expectedLock });
  const path = join(custody.facts.stateRoot, 'profiles', id), lockPath = join(path, 'owner.lock');
  const targetSha256 = migrationDigest(convertProfileRecord(Buffer.from(source.base64, 'base64'), id));
  let target: MigrationFile | undefined;
  const accept = (candidate: MigrationFile): MigrationFile => {
    if (!validator('migration.File')(candidate) || candidate.sha256 !== targetSha256 || candidate.identity.mode !== 0o600 ||
        candidate.identity.uid !== ownerUid() || candidate.identity.device !== root.device ||
        sameMigrationIdentity(candidate.identity, source.identity)) throw profileUnavailable();
    return Object.freeze({ identity: Object.freeze({ ...candidate.identity }), sha256: candidate.sha256 });
  };
  if (staged) target = accept(staged);
  const physical = async (): Promise<void> => {
    assertMaintenanceCustody(custody);
    if (!sameMigrationIdentity(root, await migrationDirectory(path))) throw profileUnavailable();
    const actual = await lstat(lockPath, { bigint: true }); privateManagementFile(actual);
    if (!sameMigrationIdentity(lock, migrationIdentity(actual)) || lock.device !== root.device) throw profileUnavailable();
    const record = await readMigrationFile(join(path, 'profile.json'));
    if (!sameMigrationFile(record, source) && (!target || !sameMigrationFile(record, target))) throw profileUnavailable();
    if (!sameMigrationIdentity(root, await migrationDirectory(path))) throw profileUnavailable();
    assertMaintenanceCustody(custody);
  };
  await physical(); if (performance.now() >= deadline) throw profileUnavailable();
  const held = platform.tryLock(lockPath); if (!held) return null;
  let released = false;
  const lease: MigrationOwner = Object.freeze({ path, state: custody.facts.stateRoot, id, instance: value.instance,
    directory: root, lock, original: source,
    async assert() {
      if (released) throw profileUnavailable();
      const actual = held.assertIdentity();
      if (actual.device !== lock.device || actual.inode !== lock.inode || actual.uid !== lock.uid) throw profileUnavailable();
      await physical(); held.assertIdentity();
      if (released) throw profileUnavailable();
    },
    async admitStaged(candidate: MigrationFile) {
      const next = accept(candidate); await lease.assert();
      if (target && !sameMigrationFile(target, next)) throw profileUnavailable();
      target = next; await lease.assert();
    },
    release() { if (!released) { released = true; descriptions.delete(lease); held.release(); } },
  });
  descriptions.set(lease, { platform, held, custody });
  try { await lease.assert(); return lease; } catch (error) { lease.release(); throw error; }
}
/** Private genuine-description handover; never expose a numeric FD. */
export async function withMigrationOwner<T>(owner: MigrationOwner, platform: PlatformPort, custody: MaintenanceCustody,
  operation: (held: HeldLock) => T): Promise<T> {
  const original = descriptions.get(owner);
  if (!original || original.platform !== platform || original.custody !== custody) throw profileUnavailable();
  await owner.assert();
  if (descriptions.get(owner) !== original) throw profileUnavailable();
  original.held.assertIdentity(); return operation(original.held);
}
