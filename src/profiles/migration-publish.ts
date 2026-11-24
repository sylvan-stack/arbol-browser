import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, opendir, rename, rmdir, unlink, type FileHandle } from 'node:fs/promises';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertMigrationCommitReceipt, assertMigrationCompletionEvidence, assertMigrationInspectionReceipt, assertMigrationRecoveryReceipt,
  type HeldLock, type MaintenanceScratch, type MaintenanceStagingPoint, type MigrationCommitReceipt,
  type MigrationCompletionEvidence, type MigrationInspectionReceipt } from '../runtime/platform.js';
import { withMigrationInspection } from '../runtime/migration-exit.js';
import { migrationDirectory, migrationIdentity, migrationValue, readMigrationFile, sameMigrationFile, sameMigrationIdentity,
  withMigrationOwner, type MigrationOwner, type MigrationContent, type MigrationIdentity } from './migration-owner.js';
import { assertMigrationTransaction, ensureMigrationDirectory, migrationAbsent, migrationTime,
  publishMigrationFile, type MigrationTransaction } from './migration-transaction.js';
import { missing, ownerUid, profileUnavailable, syncDirectory } from './paths.js';

type Entry = Readonly<Contract<'migration.ProfileEntry'>>;
type Staged = Readonly<Contract<'migration.Staged'>>;
type StagingInterruption = Readonly<{ point: MaintenanceStagingPoint;
  park(staging: MigrationIdentity, scratch?: MaintenanceScratch): never }>;
export const migrationStagePath = (transaction: MigrationTransaction, hash: string): string =>
  join(transaction.value.root.path, 'migration-staged', transaction.value.attempt, hash);
export async function assertMigrationProfile(transaction: MigrationTransaction, registry: HeldLock, owner: MigrationOwner,
  entry: Entry, deadline: number): Promise<void> {
  assertMigrationTransaction(transaction); await transaction.assert(deadline);
  const { root } = transaction.value, actual = registry.assertIdentity();
  if (root.initial !== 'present' || !root.registry || !root.profiles || owner.state !== root.path || owner.id !== entry.id ||
      owner.instance !== entry.instance || !sameMigrationIdentity(owner.directory, entry.directory) ||
      !sameMigrationIdentity(owner.lock, entry.ownerLock) || !sameMigrationFile(owner.original, entry.originalRecord) ||
      actual.device !== root.registry.device || actual.inode !== root.registry.inode || actual.uid !== root.registry.uid ||
      !sameMigrationIdentity(await migrationDirectory(join(root.path, 'profiles')), root.profiles) ||
      !transaction.value.profiles.some(value => isDeepStrictEqual(value, entry))) throw profileUnavailable();
  await withMigrationOwner(owner, transaction.admission.platform, transaction.admission.custody, held => held.assertIdentity());
  for (const [name, identity] of [['data', entry.dataDirectory], ['userData', entry.userDataDirectory]] as const)
    if (!sameMigrationIdentity(await migrationDirectory(join(owner.path, name)), identity)) throw profileUnavailable();
  registry.assertIdentity(); migrationTime(deadline);
}
export async function readMigrationStage(transaction: MigrationTransaction, entry: Entry, deadline: number): Promise<Staged | null> {
  await transaction.assert(deadline);
  const path = join(transaction.attempt, 'progress', `${entry.pathSha256}.staged.json`);
  try { await lstat(path); } catch (error) { if (missing(error)) return null; throw error; }
  const value = migrationValue(await readMigrationFile(path, 16384), 16384);
  if (!validator('migration.Staged')(value) || value.attempt !== transaction.value.attempt || value.profileSha256 !== entry.pathSha256 ||
      value.record.sha256 !== entry.targetRecord.sha256 || value.record.identity.device !== entry.directory.device ||
      value.record.identity.mode !== 0o600 || sameMigrationIdentity(value.record.identity, entry.originalRecord.identity) ||
      (entry.targetMarker ? !value.marker || value.marker.sha256 !== entry.targetMarker.sha256 ||
        value.marker.identity.device !== entry.directory.device || value.marker.identity.mode !== 0o600 ||
        sameMigrationIdentity(value.marker.identity, entry.originalMarker!.identity) : value.marker !== null)) throw profileUnavailable();
  Object.freeze(value.record.identity); Object.freeze(value.record);
  if (value.marker) { Object.freeze(value.marker.identity); Object.freeze(value.marker); }
  return Object.freeze(value);
}
function originalVerification(transaction: MigrationTransaction, entry: Entry, proof: MigrationInspectionReceipt): void {
  assertMigrationInspectionReceipt(proof, transaction.admission.custody);
  if (proof.profileInstance !== entry.instance || proof.profilePathHash !== entry.pathSha256 ||
      !sameMigrationIdentity(proof.profileDirectory, entry.directory) || !sameMigrationFile(proof.record, entry.originalRecord) ||
      !isDeepStrictEqual(proof.evidence, entry.evidence) ||
      (entry.originalMarker ? !proof.marker || !sameMigrationFile(proof.marker, entry.originalMarker) : proof.marker !== null)) throw profileUnavailable();
}
/** Raw scratch inspection is deliberately separate from the strict management
 * reader: a killed writer can leave zero bytes or an incomplete JSON prefix.
 * Such bytes grant only disposal of this unpublished temporary, never proof. */
async function reconcileStaging(transaction: MigrationTransaction, owner: MigrationOwner, entry: Entry, staging: string,
  assert: () => Promise<void>): Promise<void> {
  const expected = new Map<string, Buffer>([['profile.json', Buffer.from(entry.targetRecord.base64, 'base64')]]);
  if (entry.targetMarker) expected.set('engine.json', Buffer.from(entry.targetMarker.base64, 'base64'));
  const maximum = Math.max(...[...expected.values()].map(bytes => bytes.length));
  const parent = await open(staging, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const temporaries: { path: string; fd: FileHandle; stat: BigIntStats; bytes: Buffer }[] = [];
  const same = (a: BigIntStats, b: BigIntStats) => ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs', 'birthtimeNs']
    .every(key => a[key as keyof BigIntStats] === b[key as keyof BigIntStats]);
  try {
    const original = migrationIdentity(await parent.stat({ bigint: true }));
    const originalPair = async () => {
      await assert();
      if (!sameMigrationIdentity(original, migrationIdentity(await parent.stat({ bigint: true }))) ||
          !sameMigrationIdentity(original, await migrationDirectory(staging)) || original.device !== entry.directory.device ||
          !sameMigrationFile(await readMigrationFile(join(owner.path, 'profile.json')), entry.originalRecord)) throw profileUnavailable();
      if (entry.originalMarker) {
        if (!sameMigrationFile(await readMigrationFile(join(owner.path, 'engine.json')), entry.originalMarker)) throw profileUnavailable();
      } else await migrationAbsent(join(owner.path, 'engine.json'));
      await migrationAbsent(join(transaction.attempt, 'progress', `${entry.pathSha256}.staged.json`));
    };
    await originalPair();
    const read = async (fd: FileHandle, path: string): Promise<{ stat: BigIntStats; bytes: Buffer }> => {
      const stat = await fd.stat({ bigint: true });
      if (!stat.isFile() || stat.uid !== BigInt(ownerUid()) || (stat.mode & 0o7777n) !== 0o600n || stat.nlink !== 1n ||
          String(stat.dev) !== original.device || stat.size < 0n || stat.size > BigInt(maximum)) throw profileUnavailable();
      const bytes = Buffer.alloc(Number(stat.size) + 1); let count = 0;
      while (count < bytes.length) {
        const value = await fd.read(bytes, count, bytes.length - count, count);
        if (!value.bytesRead) break; count += value.bytesRead;
      }
      if (count !== Number(stat.size) || !same(stat, await fd.stat({ bigint: true })) ||
          !same(stat, await lstat(path, { bigint: true }))) throw profileUnavailable();
      const raw = bytes.subarray(0, count);
      if (![...expected.values()].some(target => raw.length <= target.length && raw.equals(target.subarray(0, raw.length))))
        throw profileUnavailable();
      return { stat, bytes: raw };
    };
    const directory = await opendir(staging); let count = 0;
    try {
      for (;;) {
        const item = await directory.read(); if (!item) break;
        if (++count > 4096) throw profileUnavailable();
        const path = join(staging, item.name), target = expected.get(item.name);
        if (target) {
          const file = await readMigrationFile(path);
          if (file.base64 !== target.toString('base64') || file.identity.device !== original.device) throw profileUnavailable();
        } else {
          if (!/^\.migration-[0-9a-f]{32}$/.test(item.name)) throw profileUnavailable();
          const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
          try { temporaries.push({ path, fd, ...await read(fd, path) }); }
          catch (error) { await fd.close(); throw error; }
        }
      }
    } finally { await directory.close(); }
    // Validate the complete bounded inventory before removing any scratch.
    for (const temporary of temporaries) {
      await originalPair(); const current = await read(temporary.fd, temporary.path);
      if (!same(current.stat, temporary.stat) || !current.bytes.equals(temporary.bytes)) throw profileUnavailable();
      await unlink(temporary.path);
      const removed = await temporary.fd.stat({ bigint: true });
      if (removed.nlink !== 0n || removed.dev !== temporary.stat.dev || removed.ino !== temporary.stat.ino) throw profileUnavailable();
      await syncDirectory(staging); await originalPair();
    }
    await originalPair();
  } finally {
    const closed = await Promise.allSettled(temporaries.map(temporary => temporary.fd.close()));
    await parent.close();
    const failed = closed.find(value => value.status === 'rejected');
    if (failed?.status === 'rejected') throw failed.reason;
  }
}
async function stageProfile(transaction: MigrationTransaction, registry: HeldLock, owner: MigrationOwner, entry: Entry,
  verify: () => Promise<MigrationInspectionReceipt>, deadline: number, interruption?: StagingInterruption):
  Promise<{ staged: Staged; directory: MigrationIdentity }> {
  originalVerification(transaction, entry, await verify());
  const profileAssert = () => assertMigrationProfile(transaction, registry, owner, entry, deadline);
  const base = join(owner.state, 'migration-staged'), attempt = join(base, transaction.value.attempt), staging = join(attempt, entry.pathSha256);
  const baseIdentity = await ensureMigrationDirectory(base, profileAssert), attemptIdentity = await ensureMigrationDirectory(attempt, profileAssert);
  const stagingIdentity = await ensureMigrationDirectory(staging, profileAssert);
  const assert = async () => {
    await profileAssert();
    for (const [path, identity] of [[base, baseIdentity], [attempt, attemptIdentity], [staging, stagingIdentity]] as const)
      if (!sameMigrationIdentity(identity, await migrationDirectory(path))) throw profileUnavailable();
  };
  // A crash may leave a fully fsynced target before the staged entry. Only
  // exact predetermined target bytes on private single-link files may be
  // recorded now, after fresh native ORIGINAL proof; unknown remnants refuse.
  await reconcileStaging(transaction, owner, entry, staging, assert);
  originalVerification(transaction, entry, await verify());
  const target = async (name: 'profile.json' | 'engine.json', expected: Contract<'migration.Target'>): Promise<MigrationContent> => {
    const path = join(staging, name); let exists = true;
    try { await lstat(path); } catch (error) { if (!missing(error)) throw error; exists = false; }
    const point = interruption?.point;
    const scratch = name === 'profile.json' && interruption && (point === 'empty-staging' || point === 'partial-staging') ?
      { point, park: (file: MaintenanceScratch) => interruption.park(stagingIdentity, file) } : undefined;
    const durablePoint = name === 'profile.json' ? 'staged-record' : 'staged-marker';
    if (exists && interruption) throw profileUnavailable();
    const actual = exists ? await readMigrationFile(path) :
      await publishMigrationFile(transaction.admission, path, Buffer.from(expected.base64, 'base64'), deadline, assert, scratch);
    if (actual.sha256 !== expected.sha256 || actual.base64 !== expected.base64 || actual.identity.device !== entry.directory.device)
      throw profileUnavailable();
    if (interruption?.point === durablePoint) interruption.park(stagingIdentity);
    await assert(); return actual;
  };
  const record = await target('profile.json', entry.targetRecord);
  const marker = entry.targetMarker ? await target('engine.json', entry.targetMarker) : null;
  if (record.sha256 !== entry.targetRecord.sha256 || record.identity.device !== entry.directory.device ||
      (marker && (marker.sha256 !== entry.targetMarker?.sha256 || marker.identity.device !== entry.directory.device))) throw profileUnavailable();
  const file = (value: MigrationContent) => Object.freeze({ identity: value.identity, sha256: value.sha256 });
  const staged: Staged = Object.freeze({ format: 1, attempt: transaction.value.attempt, profileSha256: entry.pathSha256,
    record: file(record), marker: marker ? file(marker) : null });
  if (!validator('migration.Staged')(staged)) throw profileUnavailable();
  await publishMigrationFile(transaction.admission, join(transaction.attempt, 'progress', `${entry.pathSha256}.staged.json`),
    Buffer.from(`${JSON.stringify(staged)}\n`), deadline, assert);
  if (interruption?.point === 'staged-progress') interruption.park(stagingIdentity);
  const actual = await readMigrationStage(transaction, entry, deadline);
  if (!actual || !isDeepStrictEqual(actual, staged)) throw profileUnavailable();
  return { staged: actual, directory: stagingIdentity };
}
async function renameMigrationMarker(owner: MigrationOwner, staging: string, interruption?: StagingInterruption,
  stagingIdentity?: MigrationIdentity): Promise<void> {
  const source = join(staging, 'engine.json'), destination = join(owner.path, 'engine.json');
  if (!interruption) {
    await rename(source, destination);
    await syncDirectory(owner.path); await syncDirectory(staging);
    return;
  }
  if (!stagingIdentity || (interruption.point !== 'marker-rename' && interruption.point !== 'marker-durable'))
    throw profileUnavailable();
  const flags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
  const profile = await open(owner.path, flags);
  try {
    const directory = await open(staging, flags);
    try {
      const assertDirectories = async () => {
        if (!sameMigrationIdentity(owner.directory, migrationIdentity(await profile.stat({ bigint: true }))) ||
            !sameMigrationIdentity(owner.directory, await migrationDirectory(owner.path)) ||
            !sameMigrationIdentity(stagingIdentity, migrationIdentity(await directory.stat({ bigint: true }))) ||
            !sameMigrationIdentity(stagingIdentity, await migrationDirectory(staging))) throw profileUnavailable();
      };
      await assertDirectories();
      await rename(source, destination);
      if (interruption.point === 'marker-rename') interruption.park(stagingIdentity);
      await profile.sync(); await directory.sync();
      await assertDirectories();
      interruption.park(stagingIdentity);
    } finally { await directory.close(); }
  } finally { await profile.close(); }
}
export async function assertConvertedMigrationProfile(transaction: MigrationTransaction, owner: MigrationOwner,
  entry: Entry, staged: Staged, deadline: number): Promise<void> {
  await transaction.assert(deadline); await owner.assert();
  if (!sameMigrationFile(await readMigrationFile(join(owner.path, 'profile.json')), staged.record)) throw profileUnavailable();
  if (staged.marker) {
    if (!sameMigrationFile(await readMigrationFile(join(owner.path, 'engine.json')), staged.marker)) throw profileUnavailable();
  } else await migrationAbsent(join(owner.path, 'engine.json'));
  if (!sameMigrationIdentity(await migrationDirectory(owner.path), entry.directory)) throw profileUnavailable();
}
export async function publishMigrationCommitted(transaction: MigrationTransaction, registry: HeldLock, owner: MigrationOwner,
  entry: Entry, receipt: MigrationCommitReceipt, deadline: number): Promise<void> {
  assertMigrationCommitReceipt(receipt, transaction.admission.custody);
  if (receipt.attempt !== transaction.value.attempt || receipt.profileInstance !== entry.instance || receipt.profilePathHash !== entry.pathSha256)
    throw profileUnavailable();
  const staged = await readMigrationStage(transaction, entry, deadline); if (!staged) throw profileUnavailable();
  const assert = async () => {
    await assertMigrationProfile(transaction, registry, owner, entry, deadline);
    await assertConvertedMigrationProfile(transaction, owner, entry, staged, deadline);
    const actual = await readMigrationFile(join(transaction.root, 'receipts', `${entry.pathSha256}.json`), 262144);
    const value = migrationValue(actual, 262144);
    if (!sameMigrationFile(actual, receipt.receipt) || !validator('migration.Receipt')(value) ||
        value.attempt !== transaction.value.attempt || value.transactionSha256 !== transaction.file.sha256 ||
        value.profileSha256 !== entry.pathSha256 || value.instance !== entry.instance || !isDeepStrictEqual(value.evidence, entry.evidence) ||
        !sameMigrationFile(value.convertedRecord, staged.record) ||
        (staged.marker ? !value.convertedMarker || !sameMigrationFile(value.convertedMarker, staged.marker) : value.convertedMarker !== null)) throw profileUnavailable();
  };
  const committed: Contract<'migration.Committed'> = { format: 1, attempt: transaction.value.attempt,
    profileSha256: entry.pathSha256, receipt: receipt.receipt };
  if (!validator('migration.Committed')(committed)) throw profileUnavailable();
  await publishMigrationFile(transaction.admission, join(transaction.attempt, 'progress', `${entry.pathSha256}.committed.json`),
    Buffer.from(`${JSON.stringify(committed)}\n`), deadline, assert);
}
/** Continuation is only a routing hint. Native independently proves original,
 * mid-pair or converted metadata before the corresponding action. */
export async function publishMigrationProfile(transaction: MigrationTransaction, registry: HeldLock, owner: MigrationOwner,
  entry: Entry, deadline: number, continuation: 'original' | 'marker' | 'converted' = 'original'): Promise<MigrationCommitReceipt> {
  await assertMigrationProfile(transaction, registry, owner, entry, deadline);
  await migrationAbsent(join(transaction.root, 'receipts', `${entry.pathSha256}.json`));
  await migrationAbsent(join(transaction.attempt, 'progress', `${entry.pathSha256}.committed.json`));
  const selected = transaction.stagingInterruption;
  const interruption: StagingInterruption | undefined = selected?.profileSha256 === entry.pathSha256 ? {
    point: selected.point,
    park(staging, scratch) {
      const { platform, custody } = transaction.admission, park = platform.parkMaintenanceStaging;
      if (!park) throw profileUnavailable();
      return park.call(platform, custody, selected.point, transaction.value.attempt, entry.pathSha256, staging, scratch ?? null, deadline);
    },
  } : undefined;
  return withMigrationInspection(transaction.admission.host, transaction.admission.platform, registry, owner, deadline, async inspection => {
    let staged = await readMigrationStage(transaction, entry, deadline), stagingIdentity: MigrationIdentity | undefined;
    if (interruption && (staged || continuation !== 'original')) throw profileUnavailable();
    if (!staged) {
      if (continuation !== 'original') throw profileUnavailable();
      const written = await stageProfile(transaction, registry, owner, entry, () => inspection.verify(), deadline, interruption);
      staged = written.staged; stagingIdentity = written.directory;
    }
    await owner.admitStaged(staged.record);
    const staging = migrationStagePath(transaction, entry.pathSha256);
    if (continuation === 'original') {
      // The durable staged entry precedes every replacement. Compare exact
      // source and target bytes/inodes; native repeats all original proof last.
      if (!sameMigrationFile(await readMigrationFile(join(staging, 'profile.json')), staged.record)) throw profileUnavailable();
      if (entry.originalMarker) {
        if (!staged.marker || !sameMigrationFile(await readMigrationFile(join(staging, 'engine.json')), staged.marker) ||
            !sameMigrationFile(await readMigrationFile(join(owner.path, 'engine.json')), entry.originalMarker)) throw profileUnavailable();
      }
      originalVerification(transaction, entry, await inspection.verify());
      if (entry.originalMarker) await renameMigrationMarker(owner, staging, interruption, stagingIdentity);
    }
    if (continuation !== 'converted') {
      // The native mid-pair verifier is also the normal marker-to-record
      // bridge. Its worker retains Claim and all original sources while the
      // one-use permit rechecks, renames, syncs and verifies the exact record.
      const permit = await inspection.recover(transaction.value.attempt, transaction.file.sha256);
      const recovered = await permit.commit(); assertMigrationRecoveryReceipt(recovered, transaction.admission.custody);
      if (!sameMigrationFile(recovered.record, staged.record)) throw profileUnavailable();
    }
    await assertConvertedMigrationProfile(transaction, owner, entry, staged, deadline);
    const receipt = await inspection.commit(transaction.value.attempt, transaction.file.sha256);
    await publishMigrationCommitted(transaction, registry, owner, entry, receipt, deadline); return receipt;
  });
}
export async function publishMigrationCompletion(transaction: MigrationTransaction,
  receipts: ReadonlyMap<string, MigrationCompletionEvidence>, deadline: number, assertCustody: () => Promise<void>): Promise<MigrationContent> {
  assertMigrationTransaction(transaction);
  if (receipts.size !== transaction.value.profiles.length) throw profileUnavailable();
  const items: Contract<'migration.CompletionItem'>[] = [];
  for (const entry of transaction.value.profiles) {
    const proof = receipts.get(entry.pathSha256); if (!proof) throw profileUnavailable();
    assertMigrationCompletionEvidence(proof, transaction.admission.custody);
    if (proof.attempt !== transaction.value.attempt || proof.profilePathHash !== entry.pathSha256 || proof.profileInstance !== entry.instance)
      throw profileUnavailable();
    items.push({ profileSha256: entry.pathSha256, receiptSha256: proof.receipt.sha256 });
  }
  const assert = async () => {
    await transaction.assert(deadline); await assertCustody();
    for (const entry of transaction.value.profiles) {
      const expected = receipts.get(entry.pathSha256)!;
      const receipt = await readMigrationFile(join(transaction.root, 'receipts', `${entry.pathSha256}.json`), 262144);
      const value = migrationValue(await readMigrationFile(join(transaction.attempt, 'progress', `${entry.pathSha256}.committed.json`), 16384), 16384);
      if (!sameMigrationFile(receipt, expected.receipt) || !validator('migration.Committed')(value) ||
          value.attempt !== transaction.value.attempt || value.profileSha256 !== entry.pathSha256 || !sameMigrationFile(value.receipt, expected.receipt))
        throw profileUnavailable();
    }
    await assertCustody(); await transaction.assert(deadline);
  };
  const completion: Contract<'migration.Completion'> = { format: 1, attempt: transaction.value.attempt,
    transactionSha256: transaction.file.sha256, profiles: items };
  if (!validator('migration.Completion')(completion)) throw profileUnavailable();
  return publishMigrationFile(transaction.admission, join(transaction.attempt, 'completed.json'), Buffer.from(`${JSON.stringify(completion)}\n`), deadline, assert);
}
export async function cleanMigrationStaging(transaction: MigrationTransaction, deadline: number,
  assertCustody: () => Promise<void>): Promise<void> {
  await transaction.assert(deadline); await assertCustody();
  for (const entry of transaction.value.profiles) {
    const path = migrationStagePath(transaction, entry.pathSha256);
    try { await lstat(path); } catch (error) { if (missing(error)) continue; throw error; }
    const identity = await migrationDirectory(path);
    if (identity.device !== entry.directory.device) throw profileUnavailable();
    await rmdir(path); await syncDirectory(join(transaction.value.root.path, 'migration-staged', transaction.value.attempt));
  }
  if (transaction.value.profiles.length) {
    const path = join(transaction.value.root.path, 'migration-staged', transaction.value.attempt);
    try { await lstat(path); } catch (error) { if (missing(error)) return; throw error; }
    await migrationDirectory(path); await rmdir(path); await syncDirectory(join(transaction.value.root.path, 'migration-staged'));
  }
  await assertCustody(); await transaction.assert(deadline);
}
