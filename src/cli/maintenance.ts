#!/usr/bin/env node
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { pinnedRuntime } from '../native/manifest.js';
import { packagedLayout } from '../runtime/selection.js';
import { loadPlatform, type InstalledMaintenanceInput, type IsolatedMaintenanceInput,
  type MigrationCompletionEvidence } from '../runtime/platform.js';
import { admitMigration } from '../profiles/migration-admission.js';
import { preflightMigration, withMigrationRegistry } from '../profiles/migration-preflight.js';
import { createMigrationTransaction, readMigrationTransaction, MigrationArchiveUnavailable,
  type MigrationTransaction } from '../profiles/migration-transaction.js';
import { cleanMigrationStaging, publishMigrationCompletion, publishMigrationProfile } from '../profiles/migration-publish.js';
import { recoverMigration } from '../profiles/migration-recovery.js';
import { profileUnavailable } from '../profiles/paths.js';

type Result = Contract<'migration.Result'>;
function result(completionSha256: string | null = null, converted = 0, neverOpened = 0,
  busy: readonly string[] = [], diagnostic: string | null = null): Result {
  const value = { format: 1 as const, converted, neverOpened, busy: [...busy], completionSha256, diagnostic };
  if (!validator('migration.Result')(value)) throw profileUnavailable();
  return value;
}
/** No caller-supplied Build, state root, journal, guard or production runtime.
 * These paths select a route only; native adoption supplies all authority. */
function invocation(args: readonly string[]): InstalledMaintenanceInput | IsolatedMaintenanceInput {
  const payload = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const bundle = dirname(dirname(dirname(payload)));
  if (basename(dirname(bundle)) !== 'app') throw profileUnavailable();
  const layout = packagedLayout(basename(dirname(dirname(bundle))), payload);
  if (process.type === 'browser' || process.execPath !== layout.engine ||
      process.versions.electron !== pinnedRuntime.electron || process.versions.node !== pinnedRuntime.node ||
      process.versions.modules !== pinnedRuntime.modules || process.versions.napi !== pinnedRuntime.napi ||
      process.platform !== pinnedRuntime.platform || process.arch !== pinnedRuntime.arch) throw profileUnavailable();
  if (args.length === 0 && layout.scope === 'installed') return { scope: 'installed', bundle };
  if (layout.scope !== 'isolated' || args.length !== 4 || args[0] !== '--isolated-policy' || args[2] !== '--runtime')
    throw profileUnavailable();
  const policy = args[1]!, runtime = args[3]!;
  if (![policy, runtime].every(path => isAbsolute(path) && resolve(path) === path && !path.includes('\0'))) throw profileUnavailable();
  return { scope: 'isolated', bundle, policy, runtime };
}
function completed(transaction: MigrationTransaction, digest: string): Result {
  const entries = transaction.value.profiles;
  // converted counts every converted management record; neverOpened is the
  // verified subset whose native data has never been opened.
  return result(digest, entries.length, entries.filter(entry => entry.evidence.classification === 'never-opened').length);
}
async function migrate(args: readonly string[]): Promise<Result> {
  const input = invocation(args);
  const admission = await admitMigration(loadPlatform(), input, performance.now() + 60000);
  // The capsule deadline limits adoption. Original exclusive descriptions and
  // parent/source continuity remain mandatory throughout the operation. A
  // bounded invocation can resume forward from durable progress on timeout;
  // native operations retain their separate, shorter time limits.
  const deadline = performance.now() + 30 * 60 * 1000;
  const existing = await readMigrationTransaction(admission, deadline);
  if (existing) {
    const resumed = await recoverMigration(existing, deadline);
    if (resumed.busy.length) return result(null, 0, 0, resumed.busy, 'busy');
    if (!resumed.completion) throw profileUnavailable();
    return completed(existing, resumed.completion.sha256);
  }
  const preflight = await preflightMigration(admission, deadline);
  try {
    if (preflight.busy.length) return result(null, 0, 0, preflight.busy, 'busy');
    // This includes the unconditional real Mercury check for zero profiles.
    const transaction = await createMigrationTransaction(preflight, deadline);
    const receipts = new Map<string, MigrationCompletionEvidence>();
    for (const { owner, entry } of preflight.profiles) {
      const receipt = await withMigrationRegistry(preflight, deadline, registry =>
        publishMigrationProfile(transaction, registry, owner, entry, deadline));
      receipts.set(entry.pathSha256, receipt);
    }
    const assert = () => preflight.assert(deadline);
    const completion = await publishMigrationCompletion(transaction, receipts, deadline, assert);
    await cleanMigrationStaging(transaction, deadline, assert);
    await transaction.assert(deadline); await assert();
    return completed(transaction, completion.sha256);
  } finally { preflight.release(); }
}

// This is a separate executable module. The ordinary CLI never imports it.
// Never serialize an exception: paths, provider/site text and native details
// cannot enter the management result. No guard release or selection change is
// exposed here; originals remain with the signed parent until this child exits.
let output: Result;
try { output = await migrate(process.argv.slice(2)); }
catch (error) { output = result(null, 0, 0, [], error instanceof MigrationArchiveUnavailable ? 'archive_unavailable' : 'migration_unavailable'); }
process.exitCode = output.completionSha256 === null ? 4 : 0;
await new Promise<void>((resolveOutput, rejectOutput) => {
  process.stdout.write(`${JSON.stringify(output)}\n`, error => error ? rejectOutput(error) : resolveOutput());
});
