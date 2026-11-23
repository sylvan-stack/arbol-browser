/** AFM-9 external durable-state observations. No fabricated crash state,
 * native proof, signal-by-PID guessing, or claim that polling proves fsync. */
import assert from 'node:assert/strict';
import { lstat, open, readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonical, exactFile, hash, privateDirectory } from '../../scripts/package-host.mjs';
import { assertFixture, evidence } from './migration-fixture.mjs';

export const interruptionBoundaries = Object.freeze([
  'before-transaction', 'transaction-publication', 'current-publication', 'native-rename-excl',
  'empty-staging', 'partial-staging', 'staged-progress', 'marker-rename', 'record-rename',
  'capture-receipt', 'committed-progress', 'completion', 'final-verification', 'reopening',
  'selection', 'journal-removal', 'compatible-pre-journal-backup',
].map(boundary => Object.freeze({ boundary, status: 'unqualified',
  dependency: 'Reviewed isolated-only coordination at the actual signed durable operation with original process/custody binding',
  pollingEstablishesBoundary: false })));

/** Snapshot only fixed fixture management namespaces, never website storage.
 * Races are errors; a series of snapshots is not an atomic custody proof. */
export async function observeDurableState(record, build) {
  const layout = await assertFixture(record, build), files = {}, directories = {};
  let count = 0, bytes = 0;
  const budget = { files: 131072, directories: 65536, bytes: 268435456 };
  async function visit(relative, recursive) {
    const path = join(layout.fixture, relative);
    let st;
    try { st = await lstat(path, { bigint: true }); }
    catch (error) { if (error.code === 'ENOENT') { files[relative] = null; return; } throw error; }
    assert.equal(st.uid, BigInt(process.getuid())); assert.equal(st.isSymbolicLink(), false);
    if (st.isDirectory()) {
      assert.ok(Object.keys(directories).length < budget.directories);
      directories[relative] = await privateDirectory(path, true);
      if (recursive) for (const entry of (await readdir(path)).sort()) await visit(relative + '/' + entry, true);
      assert.deepEqual(await privateDirectory(path, true), directories[relative]);
      return;
    }
    assert.ok(st.isFile() && st.nlink === 1n && !(st.mode & 0o022n));
    assert.ok(++count <= budget.files); bytes += Number(st.size); assert.ok(bytes <= budget.bytes);
    if (st.size) {
      const file = await exactFile(path, budget.bytes);
      const after = await lstat(path, { bigint: true });
      for (const key of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']) assert.equal(after[key], st[key]);
      assert.equal(file.bytes.length, Number(st.size));
      assert.deepEqual(file.identity, { device: String(st.dev), inode: String(st.ino), uid: Number(st.uid), mode: Number(st.mode & 0o7777n) });
      files[relative] = { identity: file.identity, size: String(file.bytes.length), sha256: file.sha256 };
    } else {
      const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const held = await fd.stat({ bigint: true }), named = await lstat(path, { bigint: true });
        for (const key of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']) {
          assert.equal(held[key], st[key]); assert.equal(named[key], held[key]);
        }
        files[relative] = { identity: { device: String(held.dev), inode: String(held.ino), uid: Number(held.uid),
          mode: Number(held.mode & 0o7777n) }, size: '0', sha256: hash('') };
      } finally { await fd.close(); }
    }
  }
  for (const name of ['support/selection.lock', 'support/selected.json', 'support/install-transaction.json',
    'support/install-previous-launcher', 'bin/arbol-browser']) await visit(name, false);
  for (const name of ['arbol-browser/.uses', 'support/releases', 'support/rollback-launchers',
    'support/pre-format-2-rollback-launchers', 'runtime/browser-profile-migration']) await visit(name, true);
  await assertFixture(record, build);
  return { format: 1, files, directories, digest: hash(canonical({ files, directories })),
    observationBudget: budget, atomic: false, nativeAdmission: false, establishesInterruptionBoundary: false };
}

/** Observe a real operation without controlling its result or its processes.
 * Any observation error or exhausted ceiling remains explicit. The operation
 * must itself be bounded by the actual recorded child runner. */
export async function observeOperation(record, build, directory, operation, timeout = 32 * 60 * 1000) {
  await privateDirectory(directory, true); await assertFixture(record, build);
  const started = performance.now(), events = []; let finished = false, operationResult, operationError, rejected = false;
  const running = Promise.resolve().then(operation).then(value => { operationResult = value; }, error => { rejected = true; operationError = error; })
    .finally(() => { finished = true; });
  let previous = null, samples = 0, complete = true;
  while (!finished) {
    if (performance.now() - started > timeout || samples >= 4096) { complete = false; break; }
    try {
      const snapshot = await observeDurableState(record, build);
      if (snapshot.digest !== previous) {
        events.push(await evidence(directory, 'observation-' + (++samples), snapshot)); previous = snapshot.digest;
      }
    } catch (error) {
      complete = false; events.push(await evidence(directory, 'observation-' + (++samples), { status: 'unavailable', error: String(error) }));
    }
    await delay(100);
  }
  // Do not abandon or kill the operation when an observer budget is reached.
  // The real operation's own deadline remains responsible for its termination.
  await running;
  await evidence(directory, 'observation-summary', { events, complete, elapsedMs: performance.now() - started,
    operationFailed: rejected, exactInterruptionQualified: false, boundaries: interruptionBoundaries });
  if (rejected) throw operationError;
  return { operationResult, complete, exactInterruptionQualified: false };
}
