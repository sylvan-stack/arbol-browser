import { lstat, rename, rmdir } from 'node:fs/promises';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertMigrationCommitReceipt, assertMigrationInspectionReceipt, assertMigrationRecoveryReceipt,
  type HeldLock, type MigrationCommitReceipt, type MigrationInspectionReceipt } from '../runtime/platform.js';
import { withMigrationInspection } from '../runtime/migration-exit.js';
import { migrationDirectory, migrationValue, readMigrationFile, sameMigrationFile, sameMigrationIdentity,
  withMigrationOwner, type MigrationOwner, type MigrationContent } from './migration-owner.js';
import { assertMigrationTransaction, ensureMigrationDirectory, migrationAbsent, migrationTime,
  publishMigrationFile, type MigrationTransaction } from './migration-transaction.js';
import { missing, profileUnavailable, syncDirectory } from './paths.js';

type Entry = Readonly<Contract<'migration.ProfileEntry'>>;
type Staged = Readonly<Contract<'migration.Staged'>>;
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
async function stageProfile(transaction: MigrationTransaction, registry: HeldLock, owner: MigrationOwner, entry: Entry,
  proof: MigrationInspectionReceipt, deadline: number): Promise<Staged> {
  originalVerification(transaction, entry, proof);
  const assert = () => assertMigrationProfile(transaction, registry, owner, entry, deadline);
  const base = join(owner.state, 'migration-staged'), attempt = join(base, transaction.value.attempt), staging = join(attempt, entry.pathSha256);
  await ensureMigrationDirectory(base, assert); await ensureMigrationDirectory(attempt, assert);
  await migrationAbsent(staging); await ensureMigrationDirectory(staging, assert);
  const record = await publishMigrationFile(join(staging, 'profile.json'), Buffer.from(entry.targetRecord.base64, 'base64'), deadline, assert);
  const marker = entry.targetMarker ? await publishMigrationFile(join(staging, 'engine.json'), Buffer.from(entry.targetMarker.base64, 'base64'), deadline, assert) : null;
  if (record.sha256 !== entry.targetRecord.sha256 || record.identity.device !== entry.directory.device ||
      (marker && (marker.sha256 !== entry.targetMarker?.sha256 || marker.identity.device !== entry.directory.device))) throw profileUnavailable();
  const file = (value: MigrationContent) => Object.freeze({ identity: value.identity, sha256: value.sha256 });
  const staged: Staged = Object.freeze({ format: 1, attempt: transaction.value.attempt, profileSha256: entry.pathSha256,
    record: file(record), marker: marker ? file(marker) : null });
  if (!validator('migration.Staged')(staged)) throw profileUnavailable();
  await publishMigrationFile(join(transaction.attempt, 'progress', `${entry.pathSha256}.staged.json`),
    Buffer.from(`${JSON.stringify(staged)}\n`), deadline, assert);
  const actual = await readMigrationStage(transaction, entry, deadline);
  if (!actual || !isDeepStrictEqual(actual, staged)) throw profileUnavailable();
  return actual;
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
  await publishMigrationFile(join(transaction.attempt, 'progress', `${entry.pathSha256}.committed.json`),
    Buffer.from(`${JSON.stringify(committed)}\n`), deadline, assert);
}
/** Continuation is only a routing hint. Native independently proves original,
 * mid-pair or converted metadata before the corresponding action. */
export async function publishMigrationProfile(transaction: MigrationTransaction, registry: HeldLock, owner: MigrationOwner,
  entry: Entry, deadline: number, continuation: 'original' | 'marker' | 'converted' = 'original'): Promise<MigrationCommitReceipt> {
  await assertMigrationProfile(transaction, registry, owner, entry, deadline);
  await migrationAbsent(join(transaction.root, 'receipts', `${entry.pathSha256}.json`));
  await migrationAbsent(join(transaction.attempt, 'progress', `${entry.pathSha256}.committed.json`));
  return withMigrationInspection(transaction.admission.host, transaction.admission.platform, registry, owner, deadline, async inspection => {
    let staged = await readMigrationStage(transaction, entry, deadline);
    if (!staged) {
      if (continuation !== 'original') throw profileUnavailable();
      staged = await stageProfile(transaction, registry, owner, entry, await inspection.verify(), deadline);
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
      if (entry.originalMarker) {
        await rename(join(staging, 'engine.json'), join(owner.path, 'engine.json'));
        await syncDirectory(owner.path); await syncDirectory(staging);
      }
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
  receipts: ReadonlyMap<string, MigrationCommitReceipt>, deadline: number, assertCustody: () => Promise<void>): Promise<MigrationContent> {
  assertMigrationTransaction(transaction);
  if (receipts.size !== transaction.value.profiles.length) throw profileUnavailable();
  const items: Contract<'migration.CompletionItem'>[] = [];
  for (const entry of transaction.value.profiles) {
    const proof = receipts.get(entry.pathSha256); if (!proof) throw profileUnavailable();
    assertMigrationCommitReceipt(proof, transaction.admission.custody);
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
  return publishMigrationFile(join(transaction.attempt, 'completed.json'), Buffer.from(`${JSON.stringify(completion)}\n`), deadline, assert);
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
