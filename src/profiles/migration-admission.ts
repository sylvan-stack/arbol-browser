import { lstat, readdir, realpath } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { userInfo } from 'node:os';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertMaintenanceCustody, assertPlatform, type InstalledMaintenanceInput, type IsolatedMaintenanceInput,
  type MaintenanceCustody, type PlatformPort } from '../runtime/platform.js';
import { physicalJson, verifyMaintenancePackagedHost, assertVerifiedMaintenanceHost, type VerifiedMaintenanceHost } from '../runtime/authorities.js';
import { packagedLayout, type BuildSelection } from '../runtime/selection.js';
import installation from '../runtime/installation-paths.json' with { type: 'json' };
import { missing, profileUnavailable } from './paths.js';
import { migrationDirectory, migrationValue, readMigrationFile, sameMigrationFile, sameMigrationIdentity, type MigrationContent } from './migration-owner.js';

export interface MigrationAdmission {
  readonly custody: MaintenanceCustody; readonly host: VerifiedMaintenanceHost; readonly platform: PlatformPort;
  readonly journal: Readonly<Contract<'migration.Journal'>>;
  readonly journalFile: MigrationContent;
  readonly selection: Readonly<Contract<'migration.Selection'>> | null;
  assert(deadline: number): Promise<void>;
}
const admitted = new WeakSet<object>();
export function assertMigrationAdmission(value: MigrationAdmission): void {
  if (!admitted.has(value)) throw profileUnavailable();
  assertMaintenanceCustody(value.custody); assertVerifiedMaintenanceHost(value.host);
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
/** Adoption occurs before reading a profile. Input names only the fixed
 * current image and, for isolation, its explicit sealed fixture authority. */
export async function admitMigration(platform: PlatformPort, input: InstalledMaintenanceInput | IsolatedMaintenanceInput,
  deadline: number): Promise<MigrationAdmission> {
  assertPlatform(platform);
  if (!Number.isFinite(deadline) || performance.now() >= deadline) throw profileUnavailable();
  const payload = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const build = basename(dirname(dirname(input.bundle))), layout = packagedLayout(build, payload);
  if (layout.bundle !== input.bundle || process.execPath !== layout.engine ||
      (layout.scope === 'installed') !== (input.scope === 'installed')) throw profileUnavailable();
  const custody = platform.adoptMaintenanceCustody(input), facts = custody.facts;
  assertMaintenanceCustody(custody);
  const selection: BuildSelection = Object.freeze({ build, directory: layout.buildRoot, guard: layout.guard, explicit: true });
  if (facts.bundle !== layout.bundle || facts.scope !== input.scope || facts.newBuildPath !== layout.guard ||
      custody.newBuild.path !== layout.guard) throw profileUnavailable();
  const journalFile = await readMigrationFile(facts.journalPath, 16384), decoded = migrationValue(journalFile, 16384);
  if (!sameMigrationFile(journalFile, facts.journal) || !validator('migration.Journal')(decoded)) throw profileUnavailable();
  const journal = freeze(decoded), support = dirname(facts.journalPath);
  if (basename(facts.journalPath) !== 'install-transaction.json' || journal.after.selection.build !== build ||
      journal.after.selection.imageSha256 !== facts.imageSha256 || journal.after.launcherSha256 !== facts.launcherSha256 ||
      (journal.before === null) !== (custody.oldBuild === null) ||
      (journal.before && (journal.before.selection.build === build ||
        facts.oldBuildPath !== join(dirname(layout.guard), journal.before.selection.build) || custody.oldBuild?.path !== facts.oldBuildPath))) throw profileUnavailable();
  let release: MigrationContent | undefined;
  if (input.scope === 'installed') {
    const account = userInfo(), home = await realpath(account.homedir);
    if (!process.geteuid || process.geteuid() !== account.uid ||
        support !== dirname(join(home, ...installation.stableUses)) || facts.runtime !== join(home, installation.root, 'runtime')) throw profileUnavailable();
    release = await readMigrationFile(join(support, 'releases', `${build}.json`), 16384);
    const value = migrationValue(release, 16384) as Record<string, unknown>;
    if (!value || Object.keys(value).sort().join(',') !== 'build,format,imageSha256,launcherSha256,payloadDigest,source' ||
        value.format !== 1 || value.build !== build || value.imageSha256 !== facts.imageSha256 ||
        value.launcherSha256 !== facts.launcherSha256) throw profileUnavailable();
  } else {
    if (input.runtime !== facts.runtime || input.policy !== join(layout.bundle, 'Contents/Resources/maintenance-fixture.json')) throw profileUnavailable();
    const sealed = await physicalJson(input.policy, 16384, deadline), fixture = sealed.value as Record<string, unknown>;
    if (sealed.digest !== facts.policySha256 || !fixture || fixture.runtime !== facts.runtime || fixture.stateRoot !== facts.stateRoot ||
        fixture.bundle !== layout.bundle || fixture.build !== build || fixture.hostPolicySha256 !== facts.hostPolicySha256 ||
        fixture.launcherSha256 !== facts.launcherSha256 || typeof fixture.fixture !== 'string' || support !== join(fixture.fixture, 'support')) throw profileUnavailable();
  }
  const host = await verifyMaintenancePackagedHost(selection, payload, deadline, custody, platform);
  if (host.policy.stateRoot !== facts.stateRoot || host.policyDigest !== facts.hostPolicySha256 ||
      host.root.policySha256 !== facts.hostPolicySha256 || facts.registry !== join(facts.stateRoot, 'profiles') ||
      !sameMigrationIdentity(await migrationDirectory(facts.runtime), facts.runtimeIdentity)) throw profileUnavailable();
  const selectedPath = join(support, 'selected.json');
  let selected: Readonly<Contract<'migration.Selection'>> | null = null;
  const assertSelection = async (): Promise<void> => {
    if (journal.before === null) {
      if (facts.selection !== null) throw profileUnavailable();
      try { await lstat(selectedPath); } catch (error) { if (missing(error)) return; throw error; }
      throw profileUnavailable();
    }
    if (!facts.selection) throw profileUnavailable();
    const file = await readMigrationFile(selectedPath, 16384), value = migrationValue(file, 16384);
    if (!sameMigrationFile(file, facts.selection) || !validator('migration.Selection')(value) ||
        !isDeepStrictEqual(value, journal.before.selection)) throw profileUnavailable();
    selected = freeze(value);
  };
  await assertSelection();
  // List names only, before any record/marker read. A null previous selection
  // never authorizes adoption of pre-existing profiles on first installation.
  if (journal.before === null && host.root.initial === 'present') {
    await migrationDirectory(facts.registry);
    if ((await readdir(facts.registry)).length) throw profileUnavailable();
    host.root.assert();
  }
  const admission: MigrationAdmission = Object.freeze({ custody, host, platform, journal, journalFile, selection: selected,
    async assert(cutoff: number) {
      if (!Number.isFinite(cutoff) || performance.now() >= cutoff) throw profileUnavailable();
      assertMaintenanceCustody(custody); assertVerifiedMaintenanceHost(host); host.root.assert();
      if (!sameMigrationFile(await readMigrationFile(facts.journalPath, 16384), journalFile) ||
          !sameMigrationIdentity(await migrationDirectory(facts.runtime), facts.runtimeIdentity)) throw profileUnavailable();
      await assertSelection();
      if (release && !sameMigrationFile(await readMigrationFile(join(support, 'releases', `${build}.json`), 16384), release)) throw profileUnavailable();
      assertMaintenanceCustody(custody); host.root.assert();
      if (performance.now() >= cutoff) throw profileUnavailable();
    },
  });
  admitted.add(admission); await admission.assert(deadline); return admission;
}
