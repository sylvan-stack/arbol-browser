import { lstat, opendir } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertMigrationCommittedValidation, type HeldLock, type MigrationCompletionEvidence, type NativeMigrationProgressInput } from '../runtime/platform.js';
import { closedCandidate } from '../runtime/exit.js';
import { acquireMigrationOwner, migrationDirectory, migrationIdentity, migrationValue, readMigrationFile, sameMigrationFile,
  sameMigrationIdentity, withMigrationOwner, type MigrationOwner, type MigrationContent, type MigrationFile } from './migration-owner.js';
import { assertMigrationTransaction, migrationAbsent, migrationTime, verifyMigrationArchive, type MigrationTransaction } from './migration-transaction.js';
import { assertMigrationProfile, assertConvertedMigrationProfile, cleanMigrationStaging, publishMigrationCommitted,
  publishMigrationCompletion, publishMigrationProfile, readMigrationStage } from './migration-publish.js';
import { missing, ownerUid, profileId, profileUnavailable } from './paths.js';

type Entry = Readonly<Contract<'migration.ProfileEntry'>>;
type Staged = Readonly<Contract<'migration.Staged'>>;
export interface MigrationRecoveryResult { readonly completion: MigrationContent | null; readonly busy: readonly string[] }
async function optionalFile(path: string, limit = 65536): Promise<MigrationContent | null> {
  try { await lstat(path); } catch (error) { if (missing(error)) return null; throw error; }
  // Once a name was observed, its disappearance is uncertainty, not absence.
  return readMigrationFile(path, limit);
}
function classification(actual: MigrationContent | null, original: MigrationFile | null,
  staged: MigrationFile | null): 'original' | 'converted' | 'absent' {
  if (!original) { if (actual || staged) throw profileUnavailable(); return 'absent'; }
  if (!actual) throw profileUnavailable();
  // Identity first; identical bytes on an unrecorded inode never qualify.
  if (sameMigrationIdentity(actual.identity, original.identity)) {
    if (!sameMigrationFile(actual, original)) throw profileUnavailable(); return 'original';
  }
  if (staged && sameMigrationIdentity(actual.identity, staged.identity)) {
    if (!sameMigrationFile(actual, staged)) throw profileUnavailable(); return 'converted';
  }
  throw profileUnavailable();
}
interface RecoveryProfile {
  readonly entry: Entry; readonly owner: MigrationOwner; readonly staged: Staged | null;
  readonly state: 'original' | 'marker' | 'converted' | 'receipt' | 'committed';
  readonly receipt: MigrationContent | null; readonly committed: MigrationContent | null;
}
async function classify(transaction: MigrationTransaction, owner: MigrationOwner, entry: Entry, staged: Staged | null,
  completed: boolean, deadline: number): Promise<RecoveryProfile> {
  await owner.assert(); await transaction.assert(deadline);
  const record = classification(await optionalFile(join(owner.path, 'profile.json')), entry.originalRecord, staged?.record ?? null);
  const marker = classification(await optionalFile(join(owner.path, 'engine.json')), entry.originalMarker, staged?.marker ?? null);
  const receipt = await optionalFile(join(transaction.root, 'receipts', `${entry.pathSha256}.json`), 262144);
  const committed = await optionalFile(join(transaction.attempt, 'progress', `${entry.pathSha256}.committed.json`), 16384);
  if ((record === 'converted' && marker === 'original') || (committed && !receipt) || (completed && !committed)) throw profileUnavailable();
  let state: RecoveryProfile['state'];
  if (receipt) {
    if (!staged || record !== 'converted' || marker === 'original') throw profileUnavailable();
    const value = migrationValue(receipt, 262144);
    if (!validator('migration.Receipt')(value) || value.attempt !== transaction.value.attempt || value.transactionSha256 !== transaction.file.sha256 ||
        value.profileSha256 !== entry.pathSha256 || value.instance !== entry.instance || value.profilePath !== owner.path ||
        !sameMigrationFile(value.convertedRecord, staged.record) ||
        (staged.marker ? !value.convertedMarker || !sameMigrationFile(value.convertedMarker, staged.marker) : value.convertedMarker !== null)) throw profileUnavailable();
    if (committed) {
      const progress = migrationValue(committed, 16384);
      if (!validator('migration.Committed')(progress) || progress.attempt !== transaction.value.attempt ||
          progress.profileSha256 !== entry.pathSha256 || !sameMigrationFile(progress.receipt, receipt)) throw profileUnavailable();
    }
    state = committed ? 'committed' : 'receipt';
  } else if (record === 'converted') state = 'converted';
  else if (record === 'original' && staged && (marker === 'converted' || marker === 'absent')) state = 'marker';
  else if (record === 'original' && (marker === 'original' || marker === 'absent')) state = 'original';
  else throw profileUnavailable();
  await owner.assert(); return Object.freeze({ entry, owner, staged, state, receipt, committed });
}
/** Claims retained by native receipt publication are selection hints only.
 * Native rereads the ACTUAL closed Claim and independently rederives the whole
 * retained proof; this route never obtains a retired Build lease or payload. */
async function receiptInput(transaction: MigrationTransaction, item: RecoveryProfile): Promise<NativeMigrationProgressInput> {
  if (!item.receipt) throw profileUnavailable();
  const receipt = migrationValue(item.receipt, 262144);
  if (!validator('migration.Receipt')(receipt)) throw profileUnavailable();
  const { owner, entry } = item, platform = transaction.admission.platform;
  const profile = { paths: { root: owner.path, state: owner.state }, record: { instance: owner.instance } };
  const claim = async (digest: string | null) => {
    if (!digest) return null;
    const file = await readMigrationFile(join(owner.state, 'exit-evidence', entry.pathSha256, 'claims', `${digest}.json`), 16384);
    const value = closedCandidate(migrationValue(file, 16384), profile, entry.pathSha256);
    if (file.sha256 !== digest || platform.canonicalMigrationClaimDigest(value) !== digest) throw profileUnavailable();
    return value;
  };
  const closed = await claim(receipt.evidence.closedClaimSha256), data = await claim(receipt.evidence.dataClaimSha256);
  const unused = closed && basename(closed.terminal!.path) === 'unused.json';
  if (data && basename(data.terminal!.path) === 'unused.json') throw profileUnavailable();
  return Object.freeze({ format: 1, mode: 'migrate-receipt-progress', profile: owner.path, profileInstance: owner.instance,
    profilePathHash: entry.pathSha256, runtimeLeaf: `/private/tmp/ab-${ownerUid()}/${entry.pathSha256.slice(0, 32)}`,
    bundle: transaction.admission.custody.facts.bundle, attempt: closed, dataAttempt: unused ? data : null, previous: null,
    migration: Object.freeze({ attempt: transaction.value.attempt, transactionSha256: transaction.file.sha256 }) });
}
export async function recoverMigration(transaction: MigrationTransaction, deadline: number): Promise<MigrationRecoveryResult> {
  assertMigrationTransaction(transaction); await transaction.assert(deadline);
  // Restart also requires the real archive and exact original backups before
  // any continuation. It cannot replace a missing backup with current bytes.
  await verifyMigrationArchive(transaction, deadline);
  const { admission, value } = transaction, { custody, platform } = admission;
  const owners: MigrationOwner[] = [], items: RecoveryProfile[] = [], busy: string[] = [];
  let registry: HeldLock | null = null;
  const completedPath = join(transaction.attempt, 'completed.json');
  const completed = await optionalFile(completedPath, 1048576);
  const receipts = new Map<string, MigrationCompletionEvidence>();
  let names: string[] = [];
  const inventory = async (): Promise<string[]> => {
    const result: string[] = [], stream = await opendir(join(value.root.path, 'profiles'));
    try {
      for (;;) {
        const entry = await stream.read(); if (!entry) break;
        if (result.length >= 4096) throw profileUnavailable(); profileId(entry.name); result.push(entry.name);
      }
    } finally { await stream.close(); }
    return result.sort();
  };
  const assert = async () => {
    migrationTime(deadline); await transaction.assert(deadline);
    if (value.root.initial === 'absent') {
      if (registry || value.profiles.length || value.root.profiles !== null || value.root.registry !== null) throw profileUnavailable();
    } else {
      if (!registry || !value.root.identity || !value.root.profiles || !value.root.registry) throw profileUnavailable();
      const actual = registry.assertIdentity(), named = await lstat(join(value.root.path, 'registry.lock'), { bigint: true });
      if (!named.isFile() || named.nlink !== 1n || !sameMigrationIdentity(migrationIdentity(named), value.root.registry) ||
          actual.device !== value.root.registry.device || actual.inode !== value.root.registry.inode || actual.uid !== value.root.registry.uid ||
          !sameMigrationIdentity(await migrationDirectory(value.root.path), value.root.identity) ||
          !sameMigrationIdentity(await migrationDirectory(join(value.root.path, 'profiles')), value.root.profiles) ||
          JSON.stringify(await inventory()) !== JSON.stringify(names)) throw profileUnavailable();
    }
    for (const owner of owners) await owner.assert();
    migrationTime(deadline);
  };
  try {
    if (value.root.initial === 'present') {
      if (!value.root.registry || !value.root.profiles || !value.root.identity) throw profileUnavailable();
      const lock = await lstat(join(value.root.path, 'registry.lock'), { bigint: true });
      if (!lock.isFile() || lock.nlink !== 1n || !sameMigrationIdentity(migrationIdentity(lock), value.root.registry)) throw profileUnavailable();
      registry = platform.tryLock(join(value.root.path, 'registry.lock')); if (!registry) throw profileUnavailable();
      names = value.profiles.map(entry => entry.id).sort();
      if (new Set(names).size !== names.length || new Set(value.profiles.map(entry => entry.pathSha256)).size !== value.profiles.length)
        throw profileUnavailable();
    }
    await assert();
    for (const entry of value.profiles) {
      profileId(entry.id);
      const path = join(value.root.path, 'profiles', entry.id);
      if (entry.pathSha256 !== createHash('sha256').update(path, 'utf8').digest('hex')) throw profileUnavailable();
      const staged = await readMigrationStage(transaction, entry, deadline);
      const owner = await acquireMigrationOwner(custody, platform, entry.id, entry.originalRecord, entry.directory,
        entry.ownerLock, deadline, staged?.record);
      if (!owner) { busy.push(entry.id); continue; }
      owners.push(owner);
      items.push(await classify(transaction, owner, entry, staged, completed !== null, deadline));
    }
    await assert();
    if (busy.length) return Object.freeze({ completion: null, busy: Object.freeze(busy) });
    // Classify the ENTIRE transaction before the first metadata change. Native
    // still validates each corresponding action; these states grant no proof.
    for (const item of items) {
      if (!registry) throw profileUnavailable();
      await assertMigrationProfile(transaction, registry, item.owner, item.entry, deadline);
      const now = await classify(transaction, item.owner, item.entry, item.staged, completed !== null, deadline);
      if (now.state !== item.state || !isDeepStrictEqual(now.receipt, item.receipt) || !isDeepStrictEqual(now.committed, item.committed)) throw profileUnavailable();
      let receipt: MigrationCompletionEvidence;
      if (item.state === 'receipt' || item.state === 'committed') {
        if (!item.staged) throw profileUnavailable();
        await assertConvertedMigrationProfile(transaction, item.owner, item.entry, item.staged, deadline);
        const input = await receiptInput(transaction, item);
        if (item.state === 'receipt') {
          const committed = await withMigrationOwner(item.owner, platform, custody, held =>
            platform.validateMigrationProgress(custody, registry!, held, custody.newBuild, input, deadline));
          await publishMigrationCommitted(transaction, registry, item.owner, item.entry, committed, deadline); receipt = committed;
        } else {
          const checked = await withMigrationOwner(item.owner, platform, custody, held => platform.validateMigrationCommitted(custody, registry!,
            held, custody.newBuild, { ...input, mode: 'migrate-committed-check' }, deadline));
          assertMigrationCommittedValidation(checked, custody);
          if (!item.committed || !item.receipt || !sameMigrationFile(checked.committed, item.committed) ||
              !sameMigrationFile(checked.receipt, item.receipt) ||
              (completed ? !checked.completion || !sameMigrationFile(checked.completion, completed) : checked.completion !== null)) throw profileUnavailable();
          receipt = checked;
        }
      } else receipt = await publishMigrationProfile(transaction, registry, item.owner, item.entry, deadline, item.state);
      receipts.set(item.entry.pathSha256, receipt); await assert();
    }
    let completion: MigrationContent;
    if (completed) {
      const record = migrationValue(completed, 1048576);
      const expected: Contract<'migration.Completion'> = { format: 1, attempt: value.attempt, transactionSha256: transaction.file.sha256,
        profiles: value.profiles.map(entry => ({ profileSha256: entry.pathSha256, receiptSha256: receipts.get(entry.pathSha256)!.receipt.sha256 })) };
      if (!validator('migration.Completion')(record) || !isDeepStrictEqual(record, expected) ||
          !sameMigrationFile(completed, await readMigrationFile(completedPath, 1048576))) throw profileUnavailable();
      completion = completed;
    } else completion = await publishMigrationCompletion(transaction, receipts, deadline, assert);
    await cleanMigrationStaging(transaction, deadline, assert);
    await assert();
    if (!sameMigrationFile(completion, await readMigrationFile(completedPath, 1048576))) throw profileUnavailable();
    return Object.freeze({ completion, busy: Object.freeze([]) });
  } finally {
    for (const owner of owners.reverse()) owner.release(); registry?.release();
  }
}
