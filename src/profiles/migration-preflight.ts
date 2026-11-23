import { lstat, opendir } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertMigrationInspectionReceipt, type HeldLock, type MigrationInspectionReceipt } from '../runtime/platform.js';
import { withMigrationInspection } from '../runtime/migration-exit.js';
import { assertMigrationAdmission, type MigrationAdmission } from './migration-admission.js';
import { acquireMigrationOwner, migrationDirectory, migrationIdentity, migrationValue, migrationDigest, readMigrationFile,
  sameMigrationFile, sameMigrationIdentity, type MigrationOwner, type MigrationContent, type MigrationIdentity } from './migration-owner.js';
import { convertEngineMarker, convertProfileRecord } from './format2.js';
import { missing, ownerUid, profileId, profileUnavailable } from './paths.js';

export interface MigrationProfile {
  readonly owner: MigrationOwner;
  readonly entry: Readonly<Contract<'migration.ProfileEntry'>>;
  readonly verification: MigrationInspectionReceipt;
}
export interface MigrationPreflight {
  readonly admission: MigrationAdmission;
  readonly root: Readonly<Contract<'migration.Root'>>;
  readonly profiles: readonly MigrationProfile[];
  readonly busy: readonly string[];
  assert(deadline: number): Promise<void>;
  assertOriginals(deadline: number): Promise<void>;
  release(): void;
}
const registryDescriptions = new WeakMap<MigrationPreflight, HeldLock | null>();
export function assertMigrationPreflight(value: MigrationPreflight): void {
  if (!registryDescriptions.has(value)) throw profileUnavailable();
  assertMigrationAdmission(value.admission);
}
export async function withMigrationRegistry<T>(preflight: MigrationPreflight, deadline: number,
  operation: (held: HeldLock) => T): Promise<T> {
  assertMigrationPreflight(preflight); await preflight.assert(deadline);
  const held = registryDescriptions.get(preflight); if (!held) throw profileUnavailable();
  held.assertIdentity(); return operation(held);
}
/** Bounded name-only inventory; no unknown/remnant tree is silently omitted. */
async function names(path: string, maximum: number): Promise<string[]> {
  const stream = await opendir(path), values = new Set<string>();
  try {
    for (;;) {
      const entry = await stream.read(); if (!entry) break;
      const name = entry.name;
      if (!name || name === '.' || name === '..' || name.includes('/') || name.includes('\uFFFD') || values.has(name) || values.size >= maximum)
        throw profileUnavailable();
      values.add(name);
    }
  } finally { await stream.close(); }
  return [...values].sort((a, b) => a.localeCompare(b, 'en'));
}
async function lockIdentity(path: string): Promise<MigrationIdentity> {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isFile() || stat.uid !== BigInt(ownerUid()) || stat.nlink !== 1n || (stat.mode & 0o7777n) !== 0o600n)
    throw profileUnavailable();
  return migrationIdentity(stat);
}
const management = new Set(['profile.json', 'engine.json', 'owner.lock', 'logs', 'data', 'userData']);
const storage = new Map([['Local State', 'file'], ['GraphiteDawnCache', 'directory'], ['GPUPersistentCache', 'directory']]);
async function profileNames(owner: MigrationOwner): Promise<void> {
  for (const name of await names(owner.path, 32)) {
    if (management.has(name)) continue;
    const kind = storage.get(name); if (!kind) throw profileUnavailable();
    const stat = await lstat(join(owner.path, name), { bigint: true });
    if (String(stat.dev) !== owner.directory.device || stat.uid !== BigInt(ownerUid()) || (stat.mode & 0o022n) !== 0n ||
        (kind === 'directory' ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1n)) throw profileUnavailable();
  }
}
export async function preflightMigration(admission: MigrationAdmission, deadline: number): Promise<MigrationPreflight> {
  assertMigrationAdmission(admission); await admission.assert(deadline);
  const { custody, platform, host } = admission, state = custody.facts.stateRoot;
  const heldOwners: MigrationOwner[] = [], profiles: MigrationProfile[] = [], busy: string[] = [];
  let registry: HeldLock | null = null, released = false;
  let originalNames: string[] = [], root: Readonly<Contract<'migration.Root'>>;
  const assertRegistry = async (cutoff: number): Promise<void> => {
    if (released) throw profileUnavailable();
    await admission.assert(cutoff);
    if (root.initial === 'absent') { if (registry) throw profileUnavailable(); return; }
    if (!registry || !root.identity || !root.profiles || !root.registry) throw profileUnavailable();
    const actual = registry.assertIdentity();
    if (actual.device !== root.registry.device || actual.inode !== root.registry.inode || actual.uid !== root.registry.uid ||
        !sameMigrationIdentity(root.identity, await migrationDirectory(state)) ||
        !sameMigrationIdentity(root.profiles, await migrationDirectory(join(state, 'profiles'))) ||
        !sameMigrationIdentity(root.registry, await lockIdentity(join(state, 'registry.lock'))) ||
        JSON.stringify(await names(join(state, 'profiles'), 8192)) !== JSON.stringify(originalNames)) throw profileUnavailable();
    registry.assertIdentity();
  };
  const release = (): void => {
    if (released) return; released = true;
    for (const owner of heldOwners.reverse()) owner.release(); registry?.release();
  };
  try {
    if (host.root.initial === 'absent') root = Object.freeze({ path: state, initial: 'absent', identity: null, profiles: null, registry: null });
    else {
      const identity = await migrationDirectory(state), profileRoot = await migrationDirectory(join(state, 'profiles'));
      const lock = await lockIdentity(join(state, 'registry.lock'));
      if (!host.root.identity || !sameMigrationIdentity(identity, host.root.identity) || identity.device !== profileRoot.device || lock.device !== identity.device)
        throw profileUnavailable();
      registry = platform.tryLock(join(state, 'registry.lock')); if (!registry) throw profileUnavailable();
      root = Object.freeze({ path: state, initial: 'present', identity, profiles: profileRoot, registry: lock });
      originalNames = await names(join(state, 'profiles'), 8192);
      if (originalNames.length > 4096 || (admission.journal.before === null && originalNames.length)) throw profileUnavailable();
      for (const name of originalNames) { try { profileId(name); } catch { throw profileUnavailable(); } }
      await assertRegistry(deadline);
      for (const id of originalNames) {
        await assertRegistry(deadline);
        const path = join(state, 'profiles', id), directory = await migrationDirectory(path);
        const record = await readMigrationFile(join(path, 'profile.json')), value = migrationValue(record);
        if (!validator('profile.ProfileRecord')(value) || value.id !== id || !value.createdAt.endsWith('Z') ||
            directory.device !== identity.device || record.identity.device !== identity.device) throw profileUnavailable();
        const owner = await acquireMigrationOwner(custody, platform, id, record, directory, await lockIdentity(join(path, 'owner.lock')), deadline);
        if (!owner) { busy.push(id); continue; }
        heldOwners.push(owner); await profileNames(owner);
        const dataDirectory = await migrationDirectory(join(path, 'data')), userDataDirectory = await migrationDirectory(join(path, 'userData'));
        const logs = await migrationDirectory(join(path, 'logs'));
        if ([dataDirectory, userDataDirectory, logs].some(value => value.device !== directory.device)) throw profileUnavailable();
        let marker: MigrationContent | null = null;
        try { await lstat(join(path, 'engine.json')); marker = await readMigrationFile(join(path, 'engine.json')); }
        catch (error) { if (!missing(error)) throw error; }
        if (marker) {
          const value = migrationValue(marker);
          if (!validator('profile.EngineMarker')(value) || value.profileInstance !== owner.instance || marker.identity.device !== directory.device ||
              !host.policy.readableReaderKeys.includes(value.requiredReader) || !host.policy.readableDataEpochs.includes(value.dataEpoch)) throw profileUnavailable();
        }
        const verification = await withMigrationInspection(host, platform, registry, owner, deadline, value => value.verify());
        assertMigrationInspectionReceipt(verification, custody);
        if (!sameMigrationIdentity(verification.profileDirectory, directory) || !sameMigrationFile(verification.record, record) ||
            (marker ? !verification.marker || !sameMigrationFile(verification.marker, marker) : verification.marker !== null)) throw profileUnavailable();
        const hash = createHash('sha256').update(path, 'utf8').digest('hex');
        if (verification.profilePathHash !== hash || verification.profileInstance !== owner.instance) throw profileUnavailable();
        const target = (bytes: Buffer) => Object.freeze({ sha256: migrationDigest(bytes), base64: bytes.toString('base64') });
        const entry: Readonly<Contract<'migration.ProfileEntry'>> = Object.freeze({ id, instance: owner.instance, pathSha256: hash,
          directory, dataDirectory, userDataDirectory, ownerLock: owner.lock, originalRecord: record, originalMarker: marker,
          targetRecord: target(convertProfileRecord(Buffer.from(record.base64, 'base64'), id)),
          targetMarker: marker ? target(convertEngineMarker(Buffer.from(marker.base64, 'base64'), owner.instance)) : null,
          evidence: verification.evidence });
        if (!validator('migration.ProfileEntry')(entry)) throw profileUnavailable();
        profiles.push(Object.freeze({ owner, entry, verification }));
      }
    }
    const preflight: MigrationPreflight = Object.freeze({ admission, root, profiles: Object.freeze(profiles), busy: Object.freeze(busy),
      async assert(cutoff: number) {
        await assertRegistry(cutoff);
        for (const { owner, entry } of profiles) {
          await owner.assert();
          if (!sameMigrationIdentity(entry.dataDirectory, await migrationDirectory(join(owner.path, 'data'))) ||
              !sameMigrationIdentity(entry.userDataDirectory, await migrationDirectory(join(owner.path, 'userData')))) throw profileUnavailable();
        }
        await assertRegistry(cutoff);
      },
      async assertOriginals(cutoff: number) {
        await preflight.assert(cutoff);
        if (busy.length) throw profileUnavailable();
        for (const { owner, entry } of profiles) {
          if (!sameMigrationFile(await readMigrationFile(join(owner.path, 'profile.json')), entry.originalRecord)) throw profileUnavailable();
          if (entry.originalMarker) {
            if (!sameMigrationFile(await readMigrationFile(join(owner.path, 'engine.json')), entry.originalMarker)) throw profileUnavailable();
          } else {
            try { await lstat(join(owner.path, 'engine.json')); } catch (error) { if (missing(error)) continue; throw error; }
            throw profileUnavailable();
          }
        }
        await preflight.assert(cutoff);
      },
      release() { registryDescriptions.delete(preflight); release(); },
    });
    registryDescriptions.set(preflight, registry); await preflight.assert(deadline); return preflight;
  } catch (error) { release(); throw error; }
}
