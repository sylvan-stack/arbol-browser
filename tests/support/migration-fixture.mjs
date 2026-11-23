/** AFM-9 disposable preparation. No import-time work, invented Build records,
 * native custody, profile bytes, or qualification verdicts. */
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, chmod, lstat, readdir, realpath, open } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { inventoryDigest, root } from '../../scripts/package-base.mjs';
import { canonical, command, exactFile, hash, json, privateDirectory, maintenanceFixtureLayout,
  currentHostCompilation, acceptedHostProduct, acceptedReleaseProduct, prepareUnsignedHost,
  stockElectronArchive, writeExclusive } from '../../scripts/package-host.mjs';
import { signHost } from '../../scripts/sign-host.mjs';
import { signMigrationPredecessor } from '../../scripts/sign-migration-predecessor.mjs';
import { sealIsolatedRelease, verifyIsolatedRelease } from '../../scripts/isolated-release.mjs';

export const historicalInputs = Object.freeze({
  directory: '/Volumes/Mercury/Arbol/backups/browser-format-2-historical-inputs-9bbfd76',
  capture: '40f67aa3e8b963aa349adb0e7e6468837b2117a9f4b3fe7ddd78cf590d947b94',
  imageDirectory: '/Volumes/Mercury/Arbol/backups/browser-signed-predecessor-1-fe91ff2db13a5d23',
  imageCapture: 'cd03660b64d0a6b0573976c3e49228a5de7156288c8edd4f7f7347e257cce000',
  volumeUUID: 'AE1E97B8-CE93-4019-B6DC-21482165C3F2',
});
const names = /^[a-z0-9][a-z0-9-]{0,95}$/;
export async function evidence(directory, name, value) {
  assert.match(name, names); await privateDirectory(directory, true);
  const path = join(directory, name + '.json');
  await writeExclusive(path, JSON.stringify(value, null, 2) + '\n');
  const fd = await open(path, 'r'); try { await fd.sync(); } finally { await fd.close(); }
  const parent = await open(directory, 'r'); try { await parent.sync(); } finally { await parent.close(); }
  return { path, sha256: (await exactFile(path, 8388608)).sha256 };
}
export async function authenticateInputs(review) {
  const compiled = await currentHostCompilation();
  const production = await acceptedReleaseProduct(review, compiled), isolated = await acceptedHostProduct(review, compiled);
  return { review, source: compiled.sourceIdentity, productDigest: compiled.record.productDigest,
    compileDigest: compiled.digest, productSources: compiled.productSources,
    productOutputs: compiled.productOutputs, compilerInputs: compiled.record.compilerInputs,
    productionDigest: production.digest, isolatedDigest: isolated.digest };
}
export async function authenticateHistoricalInputs() {
  const xml = command('/usr/sbin/diskutil', ['info', '-plist', '/Volumes/Mercury']);
  const conversion = spawnSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'],
    { input: xml, encoding: 'utf8', timeout: 10000, maxBuffer: 1048576 });
  assert.equal(conversion.status, 0); const volume = JSON.parse(conversion.stdout);
  assert.equal(volume.VolumeUUID, historicalInputs.volumeUUID);
  const observed = {};
  for (const [directory, expected] of [[historicalInputs.directory, historicalInputs.capture],
    [historicalInputs.imageDirectory, historicalInputs.imageCapture]]) {
    const capture = await json(join(directory, 'capture.json')); assert.equal(capture.sha256, expected);
    observed[directory] = { capture: capture.sha256, files: {} };
    for (const [name, entry] of Object.entries(capture.value.files)) {
      assert.ok(name !== '.' && name !== '..' && !name.includes('/'));
      const file = await exactFile(join(directory, name), 1073741824);
      assert.equal(file.sha256, typeof entry === 'string' ? entry : entry.sha256);
      observed[directory].files[name] = file.sha256;
    }
  }
  const revision = 'ff358ed1173486c2ef6b5757824b91e24b898285';
  const forester = '/Users/msix/Artifacts/forester';
  command('/usr/bin/git', ['-C', forester, 'merge-base', '--is-ancestor', revision, 'refs/remotes/origin/main']);
  for (const [role, beat, marker] of [['production', 'ABR-24', 'ABR-24-RELEASE-SOURCE-ADMISSION'],
    ['isolated', 'ABR-29', 'ABR-29-HOST-SOURCE-ADMISSION']]) {
    const admission = (await json(join(historicalInputs.directory, role + '-admission.json'))).value;
    assert.equal(admission.sourceGit, '9bbfd76d4926309d151897a28396af4e2e1fe0d7');
    // Published path is retained by Git itself, not inferred from a fixture.
    const paths = command('/usr/bin/git', ['-C', forester, 'ls-tree', '-r', '--name-only', revision])
      .trim().split('\n').filter(path => path.endsWith('/' + beat + '.md'));
    assert.equal(paths.length, 1);
    const text = command('/usr/bin/git', ['-C', forester, 'show', `${revision}:${paths[0]}`]);
    const blocks = [...text.matchAll(/<!-- ([A-Z0-9-]+SOURCE-ADMISSION):BEGIN -->\s*([\s\S]*?)\s*<!-- \1:END -->/g)];
    assert.equal(blocks.length, 1); assert.equal(blocks[0][1], marker);
    assert.equal(canonical(JSON.parse(blocks[0][2])), canonical(admission));
  }
  return { volumeUUID: volume.VolumeUUID, observed, historicalAdmission: revision,
    image: join(historicalInputs.imageDirectory, 'ArbolBrowser.dmg'),
    signedReceiptPath: join(historicalInputs.directory, 'signed-release.json') };
}

/** Allocate once at the final sealed path; never move or reuse another run. */
export async function allocateFixture(parent, label, builds = ['1', '2', '3']) {
  assert.match(label, names); await privateDirectory(parent, true);
  assert.ok(builds.length > 0 && new Set(builds).size === builds.length);
  for (const build of builds) assert.match(build, /^[1-9a-f][0-9a-f]{0,15}$/);
  const fixture = await mkdtemp(join(parent, label + '-')); await chmod(fixture, 0o700);
  for (const name of ['support', 'arbol-browser', 'arbol-browser/.uses', 'runtime', 'state', 'bin', 'evidence', 'staging'])
    await mkdir(join(fixture, name), { mode: 0o700 });
  const layouts = {};
  for (const build of builds) {
    const buildRoot = join(fixture, 'arbol-browser', build);
    await mkdir(buildRoot, { mode: 0o700 }); await mkdir(join(buildRoot, 'app'), { mode: 0o700 });
    layouts[build] = await maintenanceFixtureLayout(buildRoot, join(fixture, 'state/browser'));
    assert.ok(layouts[build]);
  }
  const record = { format: 1, kind: 'physical-disposable-fixture', fixture, layouts,
    createdAt: new Date().toISOString(), qualification: 'unexecuted' };
  await evidence(join(fixture, 'evidence'), 'allocation', record); return record;
}

export async function assertFixture(record, build) {
  assert.equal(await realpath(record.fixture), record.fixture);
  const layout = await maintenanceFixtureLayout(join(record.fixture, 'arbol-browser', build), join(record.fixture, 'state/browser'));
  assert.equal(canonical(layout), canonical(record.layouts[build]), 'Original physical fixture changed');
  return layout;
}

/** Calls only the already reviewed normal signing recipes. The returned audit
 * is packaging evidence, never an admission to a runtime case. */
export async function signFixtureRelease(record, build, { review, runtimeArchive, historical }) {
  const layout = await assertFixture(record, build), inputs = await authenticateInputs(review);
  const attempt = await mkdtemp(join(record.fixture, 'staging', `build-${build}-`)); await chmod(attempt, 0o700);
  const out = join(attempt, 'ArbolBrowser.app');
  await evidence(attempt, 'inputs', { inputs, layout, historical: Boolean(historical), qualification: 'unexecuted' });
  try {
    if (historical) {
      assert.equal(build, '1');
      const original = await authenticateHistoricalInputs();
      assert.equal(historical.image, original.image); assert.equal(historical.signedReceiptPath, original.signedReceiptPath);
      await evidence(attempt, 'historical-inputs', original);
      await signMigrationPredecessor({ out, buildRoot: dirname(dirname(layout.bundle)), stateRoot: layout.stateRoot,
        image: historical.image, signedReceiptPath: historical.signedReceiptPath, review });
    } else {
      assert.notEqual(build, '1');
      assert.equal((await exactFile(runtimeArchive, 536870912)).sha256, stockElectronArchive.sha256);
      await prepareUnsignedHost({ out, buildRoot: dirname(dirname(layout.bundle)), stateRoot: layout.stateRoot,
        runtimeArchive, review, purpose: 'isolated-qualification' });
      await signHost({ bundle: out, runtimeArchive, review });
    }
    const sealed = await sealIsolatedRelease({ bundle: out, out: join(attempt, 'image'), review });
    const options = { image: sealed.image, signedReceiptPath: sealed.signedReceiptPath, review };
    const release = await verifyIsolatedRelease(options);
    await assertFixture(record, build);
    assert.equal(canonical(await authenticateInputs(review)), canonical(inputs));
    const result = { options, build, source: release.source, productDigest: release.productDigest,
      profileFormat: release.profileFormat, imageSha256: release.imageSha256, receiptSha256: release.receiptSha256,
      payloadDigest: release.payloadDigest, launcherSha256: release.launcher.sha256, fixture: layout,
      auditSha256: (await exactFile(out + '.signature-audit.json', 8388608)).sha256, qualification: 'unexecuted' };
    await evidence(attempt, 'signed-artifact', result); return result;
  } catch (error) {
    await evidence(attempt, 'failure', { observedAt: new Date().toISOString(), error: String(error.stack ?? error), qualification: 'failed-preparation' });
    throw error;
  }
}

/** Read only management metadata and physical data-directory identity; never
 * inspect Chromium storage. Absence is observed without creating the root. */
export async function metadataSnapshot(record, build) {
  const layout = await assertFixture(record, build), state = layout.stateRoot;
  const identity = st => ({ device: String(st.dev), inode: String(st.ino), uid: st.uid, mode: st.mode & 0o7777 });
  const directory = async path => { await privateDirectory(path, true); return identity(await lstat(path)); };
  try { await lstat(state); } catch (error) { if (error.code === 'ENOENT') return { root: null, profiles: [] }; throw error; }
  const rootIdentity = await directory(state), profiles = join(state, 'profiles');
  try { await lstat(profiles); } catch (error) { if (error.code === 'ENOENT') return { root: rootIdentity, profiles: [] }; throw error; }
  const registry = await directory(profiles), rows = [];
  for (const id of (await readdir(profiles)).sort()) {
    assert.match(id, /^(?:default|[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?)$/);
    const path = join(profiles, id), row = { id, directory: await directory(path), data: await directory(join(path, 'data')) };
    for (const name of ['profile.json', 'engine.json']) {
      try {
        const file = await exactFile(join(path, name), 65536);
        let value = null, malformed = false;
        try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(file.bytes)); } catch { malformed = true; }
        row[name] = { sha256: file.sha256, identity: file.identity, value, malformed };
      }
      catch (error) { if (name !== 'engine.json' || error.code !== 'ENOENT') throw error; row[name] = null; }
    }
    rows.push(row);
  }
  assert.deepEqual(await directory(state), rootIdentity); assert.deepEqual(await directory(profiles), registry);
  return { root: rootIdentity, registry, profiles: rows };
}

/** Execute a bounded child and preserve every result. Only caller-owned
 * disposable commands may be supplied; this is not a shell interface. */
export async function recordedChild(directory, name, program, args, { env = { PATH: '/usr/bin:/bin' }, timeout = 120000 } = {}) {
  assert.match(name, names); await privateDirectory(directory, true);
  await evidence(directory, name + '-start', { program, args, startedAt: new Date().toISOString() });
  const result = await new Promise(resolve => {
    const child = spawn(program, args, { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', error = null, exceeded = false, settled = false, drain;
    const finish = (status, signal, complete) => {
      if (settled) return; settled = true; clearTimeout(timer); clearTimeout(drain);
      child.stdout.destroy(); child.stderr.destroy(); child.unref();
      resolve({ pid: child.pid ?? null, status, signal, stdout, stderr, error, exceeded, complete });
    };
    const expire = () => {
      if (exceeded) return; exceeded = true; child.kill('SIGKILL');
      // Never kill a browser family to manufacture closure. A descendant that
      // retains pipes is unresolved evidence, not an indefinitely pending run.
      drain = setTimeout(() => finish(null, null, false), 2000);
    };
    const timer = setTimeout(expire, timeout);
    const collect = stream => bytes => {
      if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) + bytes.length > 8388608) { expire(); return; }
      if (stream === 'stdout') stdout += bytes; else stderr += bytes;
    };
    child.stdout.on('data', collect('stdout')); child.stderr.on('data', collect('stderr'));
    child.once('error', e => { error = String(e); });
    child.once('close', (status, signal) => finish(status, signal, true));
  });
  await evidence(directory, name + '-result', { ...result, finishedAt: new Date().toISOString() }); return result;
}

export async function harnessIdentity() {
  const files = {};
  for (const name of ['tests/support/migration-fixture.mjs', 'tests/support/migration-interruptions.mjs',
    'tests/qualification/verify_migration.mjs', 'tests/support/control.mjs']) files[name] = (await exactFile(join(root, name), 8388608)).sha256;
  return { files, digest: inventoryDigest(files) };
}
