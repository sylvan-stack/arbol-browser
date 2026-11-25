/** AFM-9 signed interruption wire and independent durable-state observations. */
import assert from 'node:assert/strict';
import { lstat, open, readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonical, exactFile, hash, privateDirectory } from '../../scripts/package-host.mjs';
import { qualificationDirectory, qualificationFixture, qualificationJson, qualificationKeys, qualificationRoles,
  qualificationSha } from '../../scripts/qualification-authority.mjs';
import { assertFixture, evidence } from './migration-fixture.mjs';

const points = [
  // Point, writer, per-profile frame, required artifact kinds in wire order.
  ['before-transaction', 'engine', false, ['mercury-transaction']],
  ['transaction-publication', 'engine', false, ['transaction']],
  ['current-publication', 'engine', false, ['transaction', 'current']],
  ['native-rename-excl', 'engine', false, ['transaction', 'current']],
  ['empty-staging', 'engine', true, ['scratch']],
  ['partial-staging', 'engine', true, ['scratch']],
  ['staged-record', 'engine', true, ['staged-record']],
  ['staged-marker', 'engine', true, ['staged-marker']],
  ['staged-progress', 'engine', true, ['staged-progress']],
  ['marker-rename', 'engine', true, ['staged-progress', 'marker']],
  ['marker-durable', 'engine', true, ['staged-progress', 'marker']],
  ['record-rename', 'engine', true, ['staged-progress', 'record']],
  ['record-durable', 'engine', true, ['staged-progress', 'record']],
  ['claim-retained', 'engine', true, ['retained-claim']],
  ['capture-durable', 'engine', true, ['capture']],
  ['receipt-durable', 'engine', true, ['receipt']],
  ['committed-progress', 'engine', true, ['receipt', 'committed']],
  ['completion', 'engine', false, ['completion']],
  ['final-verification', 'installer', false, ['completion']],
  ['reopening-proof', 'installer', false, ['completion', 'proof']],
  ['archive-retired', 'installer', false, ['proof', 'retired-directory']],
  ['selection', 'installer', false, ['proof', 'selection']],
  ['journal-unlinked', 'installer', false, ['proof', 'selection']],
  ['journal-removal', 'installer', false, ['proof', 'selection']],
  ['compatible-pre-journal-backup', 'installer', false, ['selection', 'compatible-backup']],
];
export const interruptionBoundaries = Object.freeze(points.map(([boundary, writer, perProfile, artifacts]) => Object.freeze({
  boundary, writer, role: boundary === 'compatible-pre-journal-backup' ? 'B' : 'A', perProfile,
  artifacts: Object.freeze(artifacts), status: 'unqualified', pollingEstablishesBoundary: false,
})));

const hex32 = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
const decimal = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value);
const positiveInteger = value => Number.isSafeInteger(value) && value > 0;
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const refusalLine = Buffer.from('Fixed qualification operation refused; preserve its original evidence.\n');
const qualificationImages = qualificationRoles.map(role => join(qualificationDirectory, 'qualification/artifacts', role, 'ArbolBrowser.dmg'));

function frame(bytes, limit) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length > 1 && bytes.indexOf(0x0a) === bytes.length - 1, 'Expected one EOF-framed line');
  return qualificationJson(bytes, limit);
}

function linesOf(bytes, maximum) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length <= maximum);
  const lines = [];
  for (let start = 0; start < bytes.length;) {
    const end = bytes.indexOf(0x0a, start);
    assert.ok(end >= start, 'Expected complete diagnostic or event lines');
    lines.push(bytes.subarray(start, end + 1));
    start = end + 1;
  }
  return lines;
}

function interruptionDiagnostics(bytes, { refusal = false, launcher = null, reauthenticated = false } = {}) {
  const lines = linesOf(bytes, 4096);
  if (refusal) assert.ok(lines.pop()?.equals(refusalLine), 'Expected fixed qualification refusal diagnostic');
  if (launcher) assert.deepEqual(frame(lines.pop(), 4096), launcher);
  let pending = null;
  const diagnostics = [], attachments = [];
  for (const line of lines) {
    const event = frame(line, 4096);
    qualificationKeys(event, ['phase', 'image', 'mount']);
    const { phase, image, mount } = event;
    assert.ok(typeof image === 'string' && (qualificationImages.includes(image) ||
      (dirname(image) === join(qualificationFixture, 'support/images') && /^[1-9a-f][0-9a-f]{0,15}\.dmg$/.test(basename(image)))));
    assert.ok(typeof mount === 'string' && mount.startsWith('/') && resolve(mount) === mount &&
      /^arbol-browser-isolated-release-[A-Za-z0-9]{6}$/.test(basename(mount)));
    if (phase === 'owned-image-attach') {
      assert.equal(pending, null, 'An additional attachment preceded the original cleanup');
      pending = { image, mount };
      attachments.push(image);
    } else {
      assert.equal(phase, 'owned-image-cleaned', 'An unaccounted image mapping leaves this fixture unavailable');
      assert.deepEqual(pending, { image, mount }, 'Owned cleanup differs from its original attach');
      pending = null;
    }
    diagnostics.push(event);
  }
  assert.equal(pending, null, 'An original image attachment has no cleanup observation');
  const count = qualificationImages.length;
  assert.deepEqual(attachments.slice(0, count), qualificationImages);
  if (reauthenticated) assert.deepEqual(attachments.slice(-count), qualificationImages);
  assert.ok(attachments.length >= count * (reauthenticated ? 2 : 1));
  const intermediate = reauthenticated ? attachments.slice(count, -count) : attachments.slice(count);
  assert.ok(intermediate.every(image => !qualificationImages.includes(image)));
  if (refusal && !launcher) assert.deepEqual(intermediate, []);
  return diagnostics;
}

function validateActor(actor) {
  qualificationKeys(actor, ['pid', 'startId', 'pidVersion']);
  assert.ok(positiveInteger(actor.pid) && decimal(actor.startId) && positiveInteger(actor.pidVersion));
}

function validateArtifact(value, kind, empty = false) {
  qualificationKeys(value, ['kind', 'identity', 'size', 'sha256']);
  const { identity, size, sha256 } = value;
  qualificationKeys(identity, ['device', 'inode', 'uid', 'mode']);
  const mode = kind === 'retired-directory' ? 0o700 : kind === 'compatible-backup' ? 0o755 : 0o600;
  assert.equal(value.kind, kind);
  assert.ok(decimal(identity.device) && decimal(identity.inode) && identity.inode !== '0');
  assert.equal(identity.uid, process.getuid());
  assert.equal(identity.mode, mode);
  assert.ok(decimal(size) && qualificationSha(sha256));
  assert.equal(size === '0', empty || kind === 'retired-directory');
  if (empty) assert.equal(sha256, hash(''));
}

function interruptRequest(bytes) {
  const value = frame(bytes, 16384);
  qualificationKeys(value, ['schema', 'action', 'role', 'authoritySha256', 'point']);
  const boundary = interruptionBoundaries.find(row => row.boundary === value.point);
  assert.ok(value.schema === 1 && value.action === 'interrupt' && boundary?.role === value.role && qualificationSha(value.authoritySha256));
  return { value, boundary };
}

/** Validate the first real writer frame before replying on its original stop pipe. */
export function interruptionStop(requestBytes, parkedBytes, installerPid) {
  const { value, boundary } = interruptRequest(requestBytes);
  const parked = frame(parkedBytes, 4096);
  qualificationKeys(parked, ['schema', 'event', 'requestSha256', 'nonce', 'point', 'actor', 'journal',
    'attempt', 'transactionSha256', 'profileSha256', 'artifacts']);
  const requestSha256 = hash(requestBytes);
  assert.ok(parked.schema === 1 && parked.event === 'parked' && parked.point === value.point &&
    parked.requestSha256 === requestSha256 && hex32(parked.nonce) && positiveInteger(installerPid));
  validateActor(parked.actor);
  assert.equal(parked.actor.pid === installerPid, boundary.writer === 'installer');
  if (boundary.role === 'A') {
    validateArtifact(parked.journal, 'journal');
    assert.ok(hex32(parked.attempt) && qualificationSha(parked.transactionSha256));
  } else {
    assert.equal(parked.journal, null);
    assert.equal(parked.attempt, null);
    assert.equal(parked.transactionSha256, null);
  }
  assert.ok(boundary.perProfile ? qualificationSha(parked.profileSha256) : parked.profileSha256 === null);
  assert.ok(Array.isArray(parked.artifacts) && parked.artifacts.length === boundary.artifacts.length);
  for (const [index, kind] of boundary.artifacts.entries()) {
    const artifact = parked.artifacts[index];
    validateArtifact(artifact, kind, value.point === 'empty-staging');
    if (kind === 'transaction' || kind === 'mercury-transaction') assert.equal(artifact.sha256, parked.transactionSha256);
  }
  return { parked, stopBytes: encode({ schema: 1, action: 'interrupt', requestSha256, nonce: parked.nonce, point: value.point }) };
}

/** Inspect bytes and wait status captured by the direct spawning controller.
 * The returned transcript still requires the independent restart oracles. */
export function verifyInterruptionTranscript(requestBytes, eventBytes, writtenStop, installer) {
  const { boundary } = interruptRequest(requestBytes);
  const engine = boundary.writer === 'engine';
  const lines = linesOf(eventBytes, (engine ? 3 : 2) * 4096);
  assert.equal(lines.length, engine ? 3 : 2);
  const [notice, acknowledgement, reap] = lines;
  const { parked, stopBytes } = interruptionStop(requestBytes, notice, installer.pid);
  assert.ok(installer.complete === true && installer.supervisorSignal === false && Buffer.isBuffer(installer.stdout) && !installer.stdout.length);
  assert.ok(Buffer.isBuffer(writtenStop) && writtenStop.equals(stopBytes));
  const { requestSha256, nonce, actor, point } = parked;
  const accepted = frame(acknowledgement, 4096);
  assert.deepEqual(accepted, { schema: 1, event: 'stop-accepted', requestSha256, nonce, point, actor, stopSha256: hash(writtenStop) });
  if (!engine) {
    assert.equal(installer.signal, 'SIGKILL');
    assert.equal(installer.code, null);
    const diagnostics = interruptionDiagnostics(installer.stderr);
    return { parked, accepted, reaped: null, launcher: null, diagnostics };
  }
  const reaped = frame(reap, 4096);
  assert.deepEqual(reaped, { schema: 1, event: 'worker-reaped', requestSha256, nonce, actor,
    disposition: 'signaled', status: 9, supervisor: 'wait-only' });
  assert.equal(installer.code, 5);
  assert.equal(installer.signal, null);
  const launcher = { schema: 1, event: 'launcher-exit', requestSha256, nonce, code: 137, signal: null, complete: true };
  const diagnostics = interruptionDiagnostics(installer.stderr, { refusal: true, launcher });
  return { parked, accepted, reaped, launcher, diagnostics };
}

/** Require the actual retry result or the precise request-bound mismatch.
 * Callers compare protected before/after observations independently. */
export function verifyInterruptionRetry(requestBytes, installer, expectedBuild) {
  const request = frame(requestBytes, 16384);
  qualificationKeys(request, ['schema', 'action', 'role', 'authoritySha256']);
  assert.ok(request.schema === 1 && request.action === 'retry' && ['A', 'B'].includes(request.role) && qualificationSha(request.authoritySha256));
  assert.ok(positiveInteger(installer.pid) && installer.complete === true && installer.supervisorSignal === false && installer.signal === null);
  const result = frame(installer.stdout, 65536);
  if (expectedBuild === null) {
    assert.equal(request.role, 'B');
    assert.equal(installer.code, 3);
    assert.deepEqual(result, { schema: 1, requestSha256: hash(requestBytes), refusal: 'pending-journal-candidate-mismatch' });
  } else {
    assert.match(expectedBuild, /^[1-9a-f][0-9a-f]{0,15}$/);
    assert.equal(installer.code, 0);
    assert.deepEqual(result, { schema: 1, authoritySha256: request.authoritySha256, selected: expectedBuild });
  }
  const diagnostics = interruptionDiagnostics(installer.stderr, { refusal: expectedBuild === null, reauthenticated: expectedBuild !== null });
  return { result, diagnostics };
}

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
