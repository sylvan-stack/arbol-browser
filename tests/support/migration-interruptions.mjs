/** AFM-9 signed interruption wire and independent durable-state observations. */
import assert from 'node:assert/strict';
import { lstat, mkdtemp, open, readdir, readlink } from 'node:fs/promises';
import { closeSync, constants, fstatSync } from 'node:fs';
import { execFileSync, spawn } from 'node:child_process';
import { Socket } from 'node:net';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { canonical, command, exactFile, hash, maintenanceFixtureLayout, privateDirectory } from '../../scripts/package-host.mjs';
import { qualificationDirectory, qualificationFile, qualificationFixture, qualificationJson, qualificationKeys, qualificationRoles,
  qualificationSha } from '../../scripts/qualification-authority.mjs';
import { assertFixture, evidence, harnessIdentity, historicalInputs, metadataSnapshot } from './migration-fixture.mjs';

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

const controller = fileURLToPath(import.meta.url);
const producer = join(qualificationDirectory, 'delivery/browser-producer');
const node = '/Users/msix/.nvm/versions/node/v24.22.1/bin/node';
const python = '/Users/msix/.local/share/uv/python/cpython-3.14.8-macos-aarch64-none/bin/python3.14';
const environment = { PATH: '/usr/bin:/bin', HOME: '/Users/msix', LANG: 'C.UTF-8', GIT_OPTIONAL_LOCKS: '0' };
const firstFd = 100, endFd = 136;
const bridge = `import os, sys
os.closerange(${firstFd}, ${endFd})
os.execv(sys.argv[1], sys.argv[1:])`;
const bootstrap = `import os, sys
for target in range(${firstFd}, ${endFd}, 2):
    read, write = os.pipe()
    os.dup2(read, target, inheritable=True)
    os.dup2(write, target + 1, inheritable=True)
    os.close(read)
    os.close(write)
os.execv(sys.argv[1], sys.argv[1:])`;
const guardReader = `import fcntl, json, os, stat, sys
os.closerange(${firstFd}, ${endFd})
held = []
def identity(info):
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
    return {'device': str(info.st_dev), 'inode': str(info.st_ino), 'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}
for path in sys.argv[1:]:
    assert os.path.realpath(path) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    original = identity(os.fstat(fd))
    assert original == identity(os.lstat(path))
    held.append((path, fd, original))
print(json.dumps({path: value for path, _, value in held}), flush=True)
assert sys.stdin.buffer.read() == b'done\\n'
for path, fd, original in held:
    assert original == identity(os.fstat(fd)) == identity(os.lstat(path))
`;

function reader(stream, limit) {
  const iterator = stream[Symbol.asyncIterator](), parts = [];
  let pending = Buffer.alloc(0), bytes = 0, ended = false;
  async function more() {
    const { value, done } = await iterator.next();
    if (done) { ended = true; return; }
    bytes += value.length;
    assert.ok(bytes <= limit, 'Fixed child output exceeded its bound');
    parts.push(value);
    pending = Buffer.concat([pending, value]);
  }
  return {
    async line() {
      for (;;) {
        const end = pending.indexOf(10);
        if (end >= 0) { const line = pending.subarray(0, end + 1); pending = pending.subarray(end + 1); return line; }
        assert.ok(!ended, 'Fixed child closed before its required frame');
        await more();
      }
    },
    async finish() { while (!ended) await more(); return Buffer.concat(parts); },
  };
}

function waitChild(child) {
  return new Promise(resolve => {
    child.once('error', error => resolve({ code: null, signal: null, error: String(error) }));
    child.once('exit', (code, signal) => resolve({ code, signal, error: null }));
  });
}

function send(stream, bytes, eof = false) {
  return new Promise((resolve, reject) => {
    const done = error => { stream.off('error', done); if (error) reject(error); else resolve(); };
    stream.once('error', done);
    if (eof) stream.end(bytes, done);
    else stream.write(bytes, done);
  });
}

/** The bridge execs in place, so Node waits for the actual producer PID. */
function fixedProcess(entry, extra, nextPipe, timeout) {
  const channels = [['input', true, 0], ['output', false, 1], ...extra];
  const stdio = ['ignore', 'ignore', 'pipe'], inherited = [], descriptors = {};
  for (const [name, writable, index] of channels) {
    const [read, write] = nextPipe();
    for (const fd of [read, write]) {
      const st = fstatSync(fd, { bigint: true });
      assert.ok(st.isFIFO() && st.dev === 0n && st.nlink === 0n && st.uid === BigInt(process.getuid()));
    }
    const childEnd = writable ? read : write, parentEnd = writable ? write : read;
    inherited.push(childEnd);
    stdio[index] = childEnd;
    descriptors[name] = { parentEnd, writable };
  }
  const script = entry === 'qualification-verify-v1' ? 'isolated-release.mjs' : 'install-release.mjs';
  let child;
  try { child = spawn(python, ['-c', bridge, node, join(producer, 'scripts', script), entry], { cwd: producer, env: environment, stdio }); }
  finally { for (const fd of inherited) closeSync(fd); }
  const wait = waitChild(child), pipes = {};
  for (const [name, { parentEnd, writable }] of Object.entries(descriptors)) {
    pipes[name] = new Socket({ fd: parentEnd, readable: !writable, writable });
    pipes[name].on('error', () => {});
  }
  const output = reader(pipes.output, entry === 'qualification-observe-v1' ? 8 * 65536 : 65536);
  const diagnostics = reader(child.stderr, entry === 'qualification-observe-v1' ? 8 * 4096 : 4096);
  const events = pipes.events && reader(pipes.events, 3 * 4096);
  const preparation = pipes.preparation && reader(pipes.preparation, 4096);
  // Drain diagnostics concurrently so their byte cap applies during execution.
  const errors = diagnostics.finish().then(bytes => ({ bytes }), error => ({ error }));
  let supervisorSignal = false, exited = false;
  void wait.then(() => { exited = true; });
  const timer = setTimeout(() => {
    if (!exited) { supervisorSignal = true; child.kill('SIGKILL'); }
    for (const socket of Object.values(pipes)) socket.destroy(new Error('Fixed child deadline expired'));
    child.stderr.destroy(new Error('Fixed child deadline expired'));
  }, timeout);
  return { pid: child.pid, pipes, output, events, preparation, async finish() {
    for (const [name, { writable }] of Object.entries(descriptors)) if (writable && !pipes[name].writableEnded) pipes[name].end();
    const settled = await Promise.allSettled([wait, output.finish(), errors, events?.finish(), preparation?.finish()]);
    clearTimeout(timer);
    const [status, stdout, stderr, eventBytes, notice] = settled.map(row => row.status === 'fulfilled' ? row.value : { error: String(row.reason) });
    return { ...status, pid: child.pid, supervisorSignal, stdout, stderr: stderr.bytes ?? stderr,
      eventBytes, notice, complete: !status.error && !supervisorSignal && settled.every(row => row.status === 'fulfilled') && !stderr.error };
  } };
}

const waits = { read: 10 * 60_000, install: 52 * 60_000, observer: 120 * 60_000 };
const bytesEvidence = value => Buffer.isBuffer(value) ? { base64: value.toString('base64'), sha256: hash(value) } : value;

async function recordChild(directory, label, child, request, exchange = {}) {
  const result = await child.finish();
  const { stdout, stderr, eventBytes, notice, ...status } = result;
  await evidence(directory, label, { ...status, stdout: bytesEvidence(stdout), stderr: bytesEvidence(stderr),
    events: bytesEvidence(eventBytes), notice: bytesEvidence(notice), request: bytesEvidence(request),
    ...Object.fromEntries(Object.entries(exchange).map(([key, value]) => [key, bytesEvidence(value)])) });
  return result;
}

async function ordinaryRequest(directory, label, entry, request, nextPipe) {
  const child = fixedProcess(entry, [], nextPipe, entry === 'qualification-verify-v1' ? waits.read : waits.install);
  const bytes = encode(request);
  try { await send(child.pipes.input, bytes, true); }
  catch (error) { await recordChild(directory, label, child, bytes); throw error; }
  return { bytes, result: await recordChild(directory, label, child, bytes) };
}

async function protectedState(record, build, builds, extra) {
  const root = join(qualificationFixture, 'state/browser'), profiles = join(root, 'profiles');
  const present = await lstat(root).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
  const names = present ? (await readdir(profiles)).sort() : [];
  assert.ok(names.every(name => /^[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(name)));
  const paths = [join(qualificationFixture, 'support/selection.lock'),
    ...[...new Set(builds)].sort().map(value => join(qualificationFixture, 'arbol-browser/.uses', value)),
    ...(present ? [join(root, 'registry.lock'), ...names.map(name => join(profiles, name, 'owner.lock'))] : [])];
  const child = spawn(python, ['-c', guardReader, ...paths], { cwd: producer, env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  const wait = waitChild(child), stdout = reader(child.stdout, 1024 * 1024);
  const diagnostics = reader(child.stderr, 4096).finish().catch(error => Buffer.from(String(error)));
  let result, failed;
  const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
  child.stdin.on('error', () => {});
  try {
    const line = await stdout.line();
    const guards = qualificationJson(line, 1024 * 1024);
    assert.deepEqual(Object.keys(guards), paths);
    const metadata = await metadataSnapshot(record, build);
    assert.deepEqual(metadata.profiles.map(profile => profile.id), names);
    const durable = await observeDurableState(record, build);
    const images = {}, imageDirectory = join(qualificationFixture, 'support/images');
    await privateDirectory(imageDirectory, true);
    for (const name of (await readdir(imageDirectory)).sort()) {
      assert.match(name, /^[1-9a-f][0-9a-f]{0,15}\.dmg$/);
      images[name] = await qualificationFile(join(imageDirectory, name), 1024 ** 3, 0o600, false, performance.now() + 60_000);
    }
    const alias = join(qualificationFixture, 'aliases/arbol-browser');
    const link = await lstat(alias, { bigint: true });
    assert.ok(link.isSymbolicLink() && link.uid === BigInt(process.getuid()));
    const target = await readlink(alias);
    assert.equal(target, join(qualificationFixture, 'bin/arbol-browser'));
    result = { guards, metadata, durable, images, alias: { target, device: String(link.dev), inode: String(link.ino) },
      effect: extra ? await extra(durable) : null };
  } catch (error) { failed = error; }
  finally { child.stdin.end('done\n'); }
  const status = await wait;
  clearTimeout(timer);
  const stderr = await diagnostics;
  if (failed) throw failed;
  assert.deepEqual(status, { code: 0, signal: null, error: null }, `Original read guards changed ${stderr.toString()}`);
  return result;
}

const earlyPoints = ['before-transaction', 'transaction-publication', 'current-publication', 'native-rename-excl'];
const buildId = /^[1-9a-f][0-9a-f]{0,15}$/;
const migrationPath = 'runtime/browser-profile-migration';
const initialJournal = 'support/install-transaction.json';

function artifactReference({ identity, size, sha256 }) { return { identity, size, sha256 }; }

async function earlyState(point, parked, durable) {
  const file = (relative, reference) => assert.deepEqual(durable.files[relative], artifactReference(reference), relative);
  file(initialJournal, parked.journal);
  const current = `${migrationPath}/current`, transaction = `${migrationPath}/${parked.attempt}/transaction.json`;
  const backup = join('/Volumes/Mercury/Arbol/backups/browser-profile-format-2', parked.attempt, 'transaction.json');
  const xml = command('/usr/sbin/diskutil', ['info', '-plist', '/Volumes/Mercury']);
  const volume = JSON.parse(execFileSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], { input: xml, timeout: 10000, env: environment }));
  assert.equal(volume.VolumeUUID, historicalInputs.volumeUUID);
  const mercury = await qualificationFile(backup, 8 * 1024 * 1024, 0o600, false, performance.now() + 60_000);
  assert.equal(mercury.identity.device, String((await lstat('/Volumes/Mercury', { bigint: true })).dev));
  assert.equal(mercury.sha256, parked.transactionSha256);
  if (point === 'before-transaction') {
    assert.deepEqual(artifactReference(mercury), artifactReference(parked.artifacts[0]));
    assert.equal(durable.files[transaction] ?? null, null);
  } else {
    file(transaction, parked.artifacts[0]);
    assert.equal(durable.files[transaction].sha256, mercury.sha256);
  }
  if (parked.artifacts.length === 2) {
    file(current, parked.artifacts[1]);
    const pointer = await exactFile(join(qualificationFixture, current), 16384);
    assert.deepEqual(qualificationJson(pointer.bytes), { format: 1, attempt: parked.attempt, transactionSha256: parked.transactionSha256 });
  } else assert.equal(durable.files[current] ?? null, null);
  assert.deepEqual(Object.keys(durable.files).filter(path => path.startsWith(migrationPath + '/') &&
    durable.files[path] !== null).sort(), (point === 'before-transaction' ? [] : parked.artifacts.length === 2 ? [current, transaction] : [transaction]).sort());
  return { mercury, journal: durable.files[initialJournal], pointer: durable.files[current] ?? null };
}

async function fixedEarlyRecovery(point) {
  assert.ok(earlyPoints.includes(point));
  assert.equal(process.execPath, node);
  const authorityPath = join(qualificationDirectory, 'qualification/authority.json');
  const authority = await qualificationFile(authorityPath, 16384, 0o600, false);
  const manifestPath = join(qualificationDirectory, 'delivery/producer-manifest.json');
  const manifest = await qualificationFile(manifestPath, 16 * 1024 * 1024, 0o600, true);
  const pins = qualificationJson(manifest.bytes, 16 * 1024 * 1024);
  assert.equal(pins.executables.node.sha256, '6f32069480ec14d52b6d7b1f3c7124cfbbc46203abf5ddf5c65b127435f3f329');
  const published = execFileSync('/usr/bin/git', ['--no-replace-objects', '-C', '/Users/msix/Artifacts/forester', 'show',
    'refs/remotes/origin/main:sagas/sylvan-stack/arbol-format-2-migration/browser-profile-migration/AFM-9.md'],
  { encoding: 'utf8', env: environment, timeout: 10000 });
  for (const marker of ['SOURCE', 'RUNTIME']) {
    const [, payload] = published.split(`<!-- AFM-9-QUALIFICATION-${marker}-DELIVERY:BEGIN -->`);
    assert.ok(payload);
    const [block] = payload.split(`<!-- AFM-9-QUALIFICATION-${marker}-DELIVERY:END -->`);
    const declaration = qualificationJson(Buffer.from(block.trim()), 65536);
    assert.equal(declaration.status, 'accepted');
    assert.equal(declaration.producerManifestSha256, manifest.reference.sha256);
  }
  assert.deepEqual(await qualificationFile(node, 256 * 1024 * 1024), pins.executables.node);
  for (const name of ['scripts/isolated-release.mjs', 'scripts/install-release.mjs']) {
    const script = await qualificationFile(join(producer, name), 1024 * 1024);
    assert.equal(script.sha256, pins.files[name].sha256);
    assert.equal(script.identity.mode, pins.files[name].mode);
  }
  const directory = await mkdtemp(join(qualificationDirectory, 'qualification/recovery-'));
  const authoritySha256 = authority.sha256;
  const children = [], observerRequests = [], observerResponses = [];
  let cursor = firstFd, stopChild, observer;
  function nextPipe() { const read = cursor; cursor += 2; assert.ok(cursor <= endFd); return [read, read + 1]; }
  const request = (label, entry, value) => ordinaryRequest(directory, label, entry, { schema: 1, authoritySha256, ...value }, nextPipe);
  await evidence(directory, 'identity', { point, authority, producerManifest: manifest.reference, harness: await harnessIdentity() });
  try {
    const verified = await request('verify', 'qualification-verify-v1', { action: 'verify' });
    assert.equal(verified.result.code, 0); assert.equal(verified.result.complete, true);
    interruptionDiagnostics(verified.result.stderr);
    const view = frame(verified.result.stdout, 65536);
    assert.ok(view.schema === 1 && view.authoritySha256 === authoritySha256 && view.producerManifestSha256 === manifest.reference.sha256);
    assert.equal(view.fixture.root, qualificationFixture);
    const historical = view.releases.historical.build, build = view.releases.A.build, alternative = view.releases.B.build;
    assert.equal(historical, '1'); assert.ok(buildId.test(build) && buildId.test(alternative) && build !== alternative);
    const record = { fixture: qualificationFixture, layouts: {} };
    for (const value of [historical, build]) {
      const layout = await maintenanceFixtureLayout(join(qualificationFixture, 'arbol-browser', value), join(qualificationFixture, 'state/browser'));
      const { bin, ...originals } = view.fixture.directories;
      assert.deepEqual(layout.directories, originals);
      record.layouts[value] = layout;
    }
    const baseline = await protectedState(record, historical, [historical]);
    assert.equal(baseline.durable.files[initialJournal], null);
    assert.equal(baseline.durable.files[`${migrationPath}/current`] ?? null, null);
    await evidence(directory, 'original-state', baseline);
    observer = fixedProcess('qualification-observe-v1', [], nextPipe, waits.observer);
    async function observe(action, phase) {
      const sequence = observerRequests.length;
      const outgoing = encode({ schema: 1, sequence, action, ...(phase && { phase }) });
      observerRequests.push(outgoing);
      await send(observer.pipes.input, outgoing);
      const incoming = await observer.output.line();
      observerResponses.push(incoming);
      const value = frame(incoming, 65536);
      assert.ok(value.schema === 1 && value.sequence === sequence && value.authoritySha256 === authoritySha256 &&
        value.producerManifestSha256 === manifest.reference.sha256);
      return value;
    }
    const original = await observe('open-original');
    assert.equal(original.kind, 'observed-original'); assert.ok(qualificationSha(original.originalObservationSha256));
    stopChild = fixedProcess('qualification-interrupt-v1', [
      ['stop', true, 3], ['events', false, 4], ['ack', true, 5], ['preparation', false, 6],
    ], nextPipe, waits.install);
    const input = encode({ schema: 1, action: 'interrupt', role: 'A', authoritySha256, point });
    const requestSha256 = hash(input);
    let stop, ack, prepared;
    try {
      await send(stopChild.pipes.input, input, true);
      const notice = frame(await stopChild.preparation.line(), 4096);
      assert.deepEqual(notice, { schema: 1, phase: 'prepared-journal', requestSha256 });
      prepared = await observe('bind-prepared-journal');
      assert.equal(prepared.kind, 'observed-prepared-journal'); assert.ok(qualificationSha(prepared.preparedObservationSha256));
      ack = encode({ schema: 1, phase: 'continue', requestSha256 });
      await send(stopChild.pipes.ack, ack, true);
      const live = interruptionStop(input, await stopChild.events.line(), stopChild.pid);
      stop = live.stopBytes;
      await send(stopChild.pipes.stop, stop, true);
    } finally { children.push(await recordChild(directory, 'interruption', stopChild, input, { ack, stop })); }
    const stopped = children[0];
    const interrupted = verifyInterruptionTranscript(input, stopped.eventBytes, stop, stopped);
    assert.deepEqual(frame(stopped.notice, 4096), { schema: 1, phase: 'prepared-journal', requestSha256 });
    const snapshot = () => protectedState(record, build, [historical, build], durable => earlyState(point, interrupted.parked, durable));
    const parked = await snapshot();
    assert.deepEqual(parked.metadata, baseline.metadata);
    for (const [path, identity] of Object.entries(baseline.guards)) assert.deepEqual(parked.guards[path], identity);
    await evidence(directory, 'interrupted-state', parked);
    for (const number of [1, 2]) {
      const attempt = await request(`mismatch-${number}`, 'qualification-interrupt-v1', { action: 'retry', role: 'B' });
      verifyInterruptionRetry(attempt.bytes, attempt.result, null);
      assert.deepEqual(await snapshot(), parked, 'A different candidate changed closed state');
    }
    const first = await request('exact-retry-1', 'qualification-interrupt-v1', { action: 'retry', role: 'A' });
    verifyInterruptionRetry(first.bytes, first.result, build);
    const terminal = await observe('terminal', 'A');
    assert.ok(terminal.kind === 'observed-terminal-retirement' && terminal.phase === 'A' && terminal.selected === build &&
      terminal.journalDisposition === 'absent' && terminal.nativeAdmission === false);
    assert.equal(terminal.originalObservationSha256, original.originalObservationSha256);
    assert.equal(terminal.preparedObservationSha256, prepared.preparedObservationSha256);
    assert.deepEqual(terminal.originalDirectory, terminal.retiredDirectory);
    assert.equal(terminal.originalInventorySha256, terminal.retiredInventorySha256);
    if (point === 'current-publication' || point === 'native-rename-excl') assert.equal(terminal.transaction.sha256, interrupted.parked.transactionSha256);
    const after = await protectedState(record, build, [historical, build]);
    assert.equal(after.durable.files[initialJournal], null);
    for (const [path, identity] of Object.entries(parked.guards)) assert.deepEqual(after.guards[path], identity);
    const second = await request('exact-retry-2', 'qualification-interrupt-v1', { action: 'retry', role: 'A' });
    verifyInterruptionRetry(second.bytes, second.result, build);
    assert.deepEqual(await protectedState(record, build, [historical, build]), after, 'Completed exact retry changed protected state');
    await evidence(directory, 'recovered-state', { point, terminal, after, scope: 'A interruption and recovery; B, rollback-A and C not observed' });
  } catch (error) {
    await evidence(directory, 'failure', { point, error: String(error.stack ?? error) });
    throw error;
  } finally {
    if (observer) await recordChild(directory, 'observer', observer, Buffer.concat(observerRequests), { responses: Buffer.concat(observerResponses) });
    for (; cursor < endFd; cursor++) closeSync(cursor);
  }
  return { directory, point, recoveredA: true };
}

if (process.argv[1] && resolve(process.argv[1]) === controller) {
  const [action, point, ...extra] = process.argv.slice(2);
  assert.ok(extra.length === 0 && earlyPoints.includes(point));
  if (action === '--run-fixed-point') {
    const executable = await qualificationFile(python, 256 * 1024 * 1024);
    assert.equal(executable.sha256, '3104082b75b7a6dc6ae6db236fe64e850ca909139e84d1cd9f699bd6fa5132ff');
    const child = spawn(python, ['-c', bootstrap, node, controller, '--inherited-fixed-point', point], { env: environment, stdio: 'inherit' });
    const status = await waitChild(child);
    assert.equal(status.error, null);
    process.exitCode = status.code ?? 1;
  } else {
    assert.equal(action, '--inherited-fixed-point');
    console.log(JSON.stringify(await fixedEarlyRecovery(point)));
  }
}
