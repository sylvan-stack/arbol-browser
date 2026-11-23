import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { missing, ownerUid, profileUnavailable } from '../profiles/paths.js';
import { parseStrictJson } from '../profiles/strict-json.js';
import { readMigrationFile, migrationIdentity, migrationValue, withMigrationOwner, type MigrationOwner } from '../profiles/migration-owner.js';
import { assertMaintenanceCustody, assertPlatform, type HeldLock, type MaintenanceGuard, type NativeMigrationInput,
  type MigrationInspectionReceipt, type MigrationCommitReceipt, type MigrationRecoveryPermit, type MigrationSourceObservation, type PlatformPort } from './platform.js';
import { assertVerifiedMaintenanceHost, verifyPackagedHost, type VerifiedHost, type VerifiedMaintenanceHost } from './authorities.js';
import { acquireBuildLease, maintenanceBuildLease, withBuildLockForCustody, withMaintenanceBuildLock,
  type BuildLease, type MaintenanceBuildLease } from './build-lease.js';
import { claimedLayout, type BuildSelection } from './selection.js';
import { closedCandidate, mountRetainedImage } from './exit.js';
import type { LaunchAttempt } from './process.js';

const stamp = (value: BigIntStats): string => [value.dev, value.ino, value.mode, value.uid, value.gid,
  value.nlink, value.size, value.mtimeNs, value.ctimeNs, value.birthtimeNs].join(':');
const nodeIdentity = (value: BigIntStats): string => [value.dev, value.ino, value.uid, value.mode].join(':');
/** Exact system temporary namespace. Observe absence without creating either
 * private parent or leaf; no ordinary runtime/profile reader is called. */
async function migrationRuntime(path: string): Promise<{ hash: string; leaf: string; exists: boolean; assert(): Promise<void> }> {
  const hash = createHash('sha256').update(path, 'utf8').digest('hex');
  const parent = `/private/tmp/ab-${ownerUid()}`, leaf = join(parent, hash.slice(0, 32));
  const observe = async (): Promise<string[]> => {
    const system = await lstat('/private/tmp', { bigint: true });
    if (await realpath('/tmp') !== '/private/tmp' || !system.isDirectory() || system.uid !== 0n ||
        (system.mode & 0o7777n) !== 0o1777n) throw profileUnavailable();
    const result = [nodeIdentity(system)];
    for (const name of [parent, leaf]) {
      let stat: BigIntStats;
      try { stat = await lstat(name, { bigint: true }); }
      catch (error) { if (!missing(error)) throw profileUnavailable(); result.push('absent'); continue; }
      if (!stat.isDirectory() || stat.uid !== BigInt(ownerUid()) || (stat.mode & 0o7777n) !== 0o700n ||
          await realpath(name) !== name || result.includes('absent')) throw profileUnavailable();
      result.push(nodeIdentity(stat));
    }
    return result;
  };
  const original = await observe();
  return Object.freeze({ hash, leaf, exists: original[2] !== 'absent', async assert() {
    if ((await observe()).join('|') !== original.join('|')) throw profileUnavailable();
  } });
}
/** The runtime's ancestry is checked by migrationRuntime, including the one
 * specified sticky system directory. Read only the management Claim, no lock
 * creation. Native inspection later acquires and rechecks the genuine Claim. */
async function runtimeClaim(leaf: string): Promise<unknown | null> {
  const path = join(leaf, 'claim.json');
  let fd;
  try { fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { if (missing(error)) return null; throw profileUnavailable(); }
  try {
    const before = await fd.stat({ bigint: true });
    if (!before.isFile() || before.uid !== BigInt(ownerUid()) || before.nlink !== 1n ||
        (before.mode & 0o7777n) !== 0o600n || before.size < 1n || before.size > 16384n) throw profileUnavailable();
    const bytes = Buffer.alloc(Number(before.size) + 1); let count = 0;
    while (count < bytes.length) { const part = await fd.read(bytes, count, bytes.length - count, count); if (!part.bytesRead) break; count += part.bytesRead; }
    if (count !== Number(before.size) || stamp(await fd.stat({ bigint: true })) !== stamp(before) ||
        stamp(await lstat(path, { bigint: true })) !== stamp(before)) throw profileUnavailable();
    return parseStrictJson(bytes.subarray(0, count), 16384);
  } finally { await fd.close(); }
}
export interface MigrationInspection {
  readonly input: NativeMigrationInput;
  verify(): Promise<MigrationInspectionReceipt>;
  commit(attempt: string, transactionSha256: string): Promise<MigrationCommitReceipt>;
  recover(attempt: string, transactionSha256: string): Promise<MigrationRecoveryPermit>;
}
/** Read hints choose leases only. Every operation invokes native Claim and
 * predecessor proof rederivation; no parsed JS certificate supplies a verdict. */
export async function withMigrationInspection<T>(host: VerifiedMaintenanceHost, platform: PlatformPort, registry: HeldLock,
  owner: MigrationOwner, deadline: number, operation: (inspection: MigrationInspection) => Promise<T>): Promise<T> {
  assertPlatform(platform); assertVerifiedMaintenanceHost(host);
  const custody = host.custody;
  const check = async (): Promise<void> => {
    if (!Number.isFinite(deadline) || performance.now() >= deadline || owner.state !== custody.facts.stateRoot) throw profileUnavailable();
    assertMaintenanceCustody(custody); host.root.assert(); registry.assertIdentity(); await owner.assert();
  };
  await check();
  const location = await migrationRuntime(owner.path);
  const current = location.exists ? await runtimeClaim(location.leaf) : null;
  const profile = { paths: { root: owner.path, state: owner.state }, record: { instance: owner.instance } };
  let candidate: LaunchAttempt | undefined, data: LaunchAttempt | undefined;
  if (current && typeof current === 'object' && 'phase' in current && current.phase === 'closed') candidate = closedCandidate(current, profile, location.hash);
  else {
    const path = join(owner.state, 'exit-evidence', location.hash, 'previous-claim.json');
    try { await lstat(path); candidate = closedCandidate(migrationValue(await readMigrationFile(path, 16384), 16384), profile, location.hash); }
    catch (error) { if (!missing(error)) throw error; }
  }
  if (candidate?.terminal && basename(candidate.terminal.path) === 'unused.json') {
    const value = migrationValue(await readMigrationFile(candidate.terminal.path, 262144), 262144);
    if (!value || typeof value !== 'object' || !('priorDataClaim' in value)) throw profileUnavailable();
    if (value.priorDataClaim !== null) data = closedCandidate(value.priorDataClaim, profile, location.hash);
    if (data && basename(data.terminal!.path) === 'unused.json') throw profileUnavailable();
  }
  const releasable: BuildLease[] = [];
  type Proof = { lease: BuildLease | MaintenanceBuildLease; maintenance: boolean; bundle: string;
    host: VerifiedHost; source: MigrationSourceObservation; assert(): Promise<void> };
  const proof = async (attempt?: LaunchAttempt): Promise<Proof> => {
    const layout = attempt ? claimedLayout(attempt) : host.identity.layout;
    const selection: BuildSelection = Object.freeze({ build: layout.build, directory: layout.buildRoot, guard: layout.guard, explicit: true });
    const maintenance = layout.guard === custody.newBuild.path || layout.guard === custody.oldBuild?.path;
    const lease = maintenance ? maintenanceBuildLease(custody, platform, selection) : await acquireBuildLease(selection, platform);
    if (!maintenance) releasable.push(lease as BuildLease);
    await lease.assert(); await check();
    let verified: VerifiedHost;
    if (layout.bundle === custody.facts.bundle) {
      verified = host;
      assertVerifiedMaintenanceHost(host); await host.assertTrusted(deadline);
      if (attempt && (host.signed.snapshotDigest !== attempt.candidateDigest || host.identity.sourceDigest !== attempt.sourceDigest ||
          host.identity.productDigest !== attempt.productDigest)) throw profileUnavailable();
    } else {
      if (!attempt) throw profileUnavailable();
      await mountRetainedImage(layout, lease, platform, deadline);
      const previous = await verifyPackagedHost(selection, layout.payload, deadline); verified = previous;
      if (previous.policy.stateRoot !== owner.state || previous.signed.snapshotDigest !== attempt.candidateDigest ||
          previous.identity.sourceDigest !== attempt.sourceDigest || previous.identity.productDigest !== attempt.productDigest) throw profileUnavailable();
      await previous.assertTrusted(deadline);
    }
    const observe = async (): Promise<MigrationSourceObservation> => {
      const bundle = await lstat(layout.bundle, { bigint: true });
      const policy = await lstat(join(layout.bundle, 'Contents/Resources/host-policy.json'), { bigint: true });
      return Object.freeze({ bundle: migrationIdentity(bundle), bundleStamp: stamp(bundle),
        policy: Object.freeze({ identity: migrationIdentity(policy), sha256: verified.policyDigest }), policyStamp: stamp(policy) });
    };
    const source = await observe();
    const assert = async (): Promise<void> => {
      await lease.assert(); await check();
      if (JSON.stringify(await observe()) !== JSON.stringify(source)) throw profileUnavailable();
      // Retain and check the ORIGINAL signed snapshot and storage descriptors,
      // never a fresh host whose observations could adopt a replacement tree.
      await verified.assertTrusted(deadline);
      if (JSON.stringify(await observe()) !== JSON.stringify(source)) throw profileUnavailable();
      await lease.assert(); await check();
    };
    await assert(); return { lease, maintenance, bundle: layout.bundle, host: verified, source, assert };
  };
  try {
    const closed = await proof(candidate), writer = data ? await proof(data) : undefined;
    await location.assert(); await check();
    const input: NativeMigrationInput = Object.freeze({ format: 1, mode: 'migrate-verify', profile: owner.path,
      profileInstance: owner.instance, profilePathHash: location.hash, runtimeLeaf: location.leaf, bundle: closed.bundle,
      attempt: candidate ?? null, dataAttempt: data ?? null, previous: null,
      sources: Object.freeze({ closed: candidate ? closed.source : null, data: data ? writer!.source : null }) });
    let active = true;
    const permits = new Set<MigrationRecoveryPermit>();
    const withProof = <R>(selected: Proof, callback: (lock: HeldLock | MaintenanceGuard) => R): Promise<R> => selected.maintenance ?
      withMaintenanceBuildLock(selected.lease, platform, custody, callback) : withBuildLockForCustody(selected.lease as BuildLease, platform, callback);
    const invoke = async <R>(native: (held: HeldLock, build: HeldLock | MaintenanceGuard, data?: HeldLock | MaintenanceGuard) => Promise<R>): Promise<R> => {
      if (!active) throw profileUnavailable();
      await check(); await location.assert(); await closed.assert(); await writer?.assert();
      const result = await withMigrationOwner(owner, platform, custody, held => withProof(closed, build =>
        writer ? withProof(writer, data => native(held, build, data)) : native(held, build)));
      await closed.assert(); await writer?.assert(); await check(); await location.assert(); if (!active) throw profileUnavailable(); return result;
    };
    const inspection: MigrationInspection = Object.freeze({ input,
      verify: () => invoke((held, build, data) => platform.inspectMigration(custody, registry, held, build, input, deadline, data)),
      commit: (attempt: string, transactionSha256: string) => invoke((held, build, data) => platform.commitMigration(custody, registry,
        held, build, { ...input, mode: 'migrate-commit', migration: { attempt, transactionSha256 } }, deadline, data)),
      async recover(attempt: string, transactionSha256: string) {
        const permit = await invoke((held, build, data) => platform.prepareMigrationRecovery(custody, registry,
          held, build, { ...input, mode: 'migrate-recover', migration: { attempt, transactionSha256 } }, deadline, data));
        permits.add(permit);
        return Object.freeze({ ...permit,
          cancel() { permits.delete(permit); permit.cancel(); },
          async commit() {
            if (!active || !permits.delete(permit)) throw profileUnavailable();
            try {
              await closed.assert(); await writer?.assert(); await check(); await location.assert();
              const result = await permit.commit();
              await closed.assert(); await writer?.assert(); await check(); await location.assert(); return result;
            } finally { permit.cancel(); }
          },
        });
      },
    });
    try { return await operation(inspection); } finally { active = false; for (const permit of permits) permit.cancel(); }
  } finally { for (const lease of releasable.reverse()) lease.release(); }
}
