// Testing-only fixture orchestration; no active inventoried cases or readiness provider.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, lstatSync } from 'node:fs';
import { mkdir, readFile, writeFile, realpath, readdir, readlink, lstat } from 'node:fs/promises';
import { join, resolve, sep, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
export const nativeConsumer = Object.freeze({
  manifest: '/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-42-20261115/consumer-manifest.json',
  digest: 'cb041c3918bba14ccd5ea299cbd0b6c4159e3d97b169138c96ed70397f57601f',
});
const hash = value => createHash('sha256').update(value).digest('hex');
const run = (file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 30000,
  env: { PATH: '/usr/bin:/bin', HOME: process.env.HOME }, maxBuffer: 1024 * 1024 });
export async function verifiedConsumer() {
  const bytes = await readFile(nativeConsumer.manifest);
  assert.equal(hash(bytes), nativeConsumer.digest, 'Immutable consumer manifest drift');
  const value = JSON.parse(bytes);
  assert.equal(await realpath(value.candidate), value.candidate);
  assert.equal(value.pageAdmission, false);
  assert.equal(hash(await readFile(value.manifest.path)), value.manifest.sha256);
  const sourceReview = JSON.parse(await readFile(value.sourceReviewManifest.path));
  assert.equal(hash(await readFile(value.sourceReviewManifest.path)), value.sourceReviewManifest.sha256);
  const sourceRecord = JSON.parse(await readFile(join(sourceReview.frozenSource, '../source-before.json')));
  assert.equal(hash(await readFile(join(sourceReview.frozenSource, '../source-before.json'))), sourceReview.records['source-checkpoint-35c9560/source-before.json']);
  for (const [file, digest] of Object.entries(sourceRecord.sources))
    assert.equal(hash(await readFile(join(sourceReview.frozenSource, file))), digest, 'Frozen accepted source drift');
  for (const [file, digest] of Object.entries(sourceReview.compiledInventory))
    assert.equal(hash(await readFile(join(sourceReview.frozenDist, file))), digest, 'Frozen compiled source drift');
  const inventoryBytes = await readFile(value.bundle.inventory.path);
  assert.equal(hash(inventoryBytes), value.bundle.inventory.sha256);
  const expected = JSON.parse(inventoryBytes).files, actual = {};
  async function physical(path) {
    for (const name of (await readdir(path)).sort()) {
      const child = join(path, name), st = await lstat(child), key = relative(value.candidate, child);
      if (st.isSymbolicLink()) actual[key] = hash(`symlink\0${await readlink(child)}`);
      else if (st.isDirectory()) await physical(child);
      else {
        assert.ok(st.isFile());
        const digest = createHash('sha256'); for await (const bytes of createReadStream(child)) digest.update(bytes);
        actual[key] = digest.digest('hex');
      }
    }
  }
  await physical(value.candidate); assert.deepEqual(actual, expected, 'Complete physical native consumer drift');
  return Object.freeze(value);
}
export async function prepareNativeFixtures(output) {
  const destination = resolve(output);
  assert.ok(!destination.startsWith(root + sep) && !destination.startsWith('/Users/msix/Artifacts/'));
  const consumer = await verifiedConsumer();
  assert.ok(!destination.startsWith(consumer.candidate + sep));
  await mkdir(destination, { mode: 0o700 }); // refuse reuse
  assert.equal(await realpath(destination), destination);
  const compiler = run('/usr/bin/xcrun', ['--find', 'clang++']).trim();
  const sdk = run('/usr/bin/xcrun', ['--show-sdk-path']).trim();
  const sources = ['native-launch.mm', 'native-observer.mm', 'native-entry.mjs', 'native.mjs'];
  const inputs = {};
  for (const file of sources) inputs[file] = hash(await readFile(join(root, 'tests/support', file)));
  for (const file of ['native-launch', 'native-observer']) run(compiler, ['-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
    '-fobjc-arc', '-arch', 'arm64', '-isysroot', sdk, '-mmacosx-version-min=27.0', join(root, 'tests/support', file + '.mm'),
    '-framework', 'Foundation', '-o', join(destination, file)]);
  const record = { format: 1, consumerManifest: nativeConsumer, candidate: consumer.candidate, sourceInputs: inputs,
    compiler, compilerVersion: run(compiler, ['--version']), sdk,
    binaries: Object.fromEntries(await Promise.all(['native-launch', 'native-observer'].map(async file => [file, hash(await readFile(join(destination, file)))]))),
    sourceCommit: run('/usr/bin/git', ['-C', root, 'rev-parse', 'HEAD']).trim(), qualification: 'fixtures-only; no native gate or production readiness claim' };
  await writeFile(join(destination, 'fixture-manifest.json'), JSON.stringify(record, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return Object.freeze({ directory: destination, consumer, record });
}
export function observeNative(fixtures, kind, value) {
  assert.ok(['process', 'group', 'contend'].includes(kind));
  return JSON.parse(run(join(fixtures.directory, 'native-observer'), [kind, String(value)]));
}
export async function launchNativeFixture(fixtures, { mode = 'boundary', callback = undefined, output }) {
  assert.ok(['boundary', 'callbacks'].includes(mode)); assert.ok(mode !== 'callbacks' || callback);
  const consumer = await verifiedConsumer(); assert.equal(consumer.candidate, fixtures.consumer.candidate);
  const directory = resolve(output); assert.ok(directory.startsWith(fixtures.directory + sep));
  for (const [file, expected] of Object.entries(fixtures.record.sourceInputs))
    assert.equal(hash(await readFile(join(root, 'tests/support', file))), expected, 'Prepared fixture source drift');
  await mkdir(directory, { mode: 0o700 });
  const home = join(directory, 'home'); await mkdir(home, { mode: 0o700 });
  for (const name of ['app-data', 'session-data']) await mkdir(join(home, name), { mode: 0o700 });
  const config = { format: 1, mode, bundle: fixtures.consumer.candidate, output: directory, home,
    owner: join(directory, 'owner.lock'), build: join(directory, 'build.lock'), callback };
  const request = join(directory, 'request.json');
  await writeFile(request, JSON.stringify(config) + '\n', { mode: 0o600, flag: 'wx' });
  const entry = await realpath(join(root, 'tests/support/native-entry.mjs'));
  const child = spawn(join(fixtures.directory, 'native-launch'), [config.bundle, entry, home, request], {
    env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'], cwd: directory, detached: false,
  });
  let stdout = '', stderr = '', timedOut = false;
  const observations = [], tracked = new Map();
  child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
  const started = performance.now();
  function sample() {
    try {
      const identity = observeNative(fixtures, 'process', child.pid), group = observeNative(fixtures, 'group', child.pid);
      for (const member of group.members) if (member.status === 'alive') {
        const key = `${member.pid}:${member.startId}:${member.pidVersion}`;
        if (!tracked.has(key)) tracked.set(key, member);
        // Custody remains in the original group; its actual parent identifies
        // the outside primary without trusting a fixture-supplied ready receipt.
        if (member.executable === join(config.bundle, 'Contents/Resources/browser/native/watchdog')) {
          const parent = observeNative(fixtures, 'process', member.parent);
          if (parent.status === 'alive' && parent.executable === member.executable && parent.startId === member.parentStartId)
            if (!tracked.has(`${parent.pid}:${parent.startId}:${parent.pidVersion}`))
              tracked.set(`${parent.pid}:${parent.startId}:${parent.pidVersion}`, parent);
        }
      }
      const current = [...tracked.values()].map(original => ({ original, current: observeNative(fixtures, 'process', original.pid) }));
      const locks = {};
      for (const name of ['owner', 'build']) try { if (lstatSync(config[name]).isFile()) locks[name] = observeNative(fixtures, 'contend', config[name]); } catch { /* absence grants no custody evidence */ }
      const value = { elapsedMs: performance.now() - started, identity, group, current, locks }; observations.push(value); return value;
    } catch (error) { const value = { elapsedMs: performance.now() - started, unavailable: String(error) }; observations.push(value); return value; }
  }
  const timer = setInterval(sample, 100);
  // Timeout teardown is explicitly not production enforcement evidence.
  const deadline = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 90000);
  const outcome = await new Promise((accept, reject) => { child.once('error', reject); child.once('exit', (code, signal) => accept({ code, signal })); })
    .finally(() => { clearInterval(timer); clearTimeout(deadline); });
  const exitObserved = performance.now();
  let final = sample();
  while (performance.now() - exitObserved < 10000 && (!final.current || final.current.some(({ original, current }) =>
    current.status === 'uncertain' || (current.status === 'alive' && current.startId === original.startId)))) {
    await new Promise(accept => setTimeout(accept, 100)); final = sample();
  }
  const record = { format: 1, mode, candidate: config.bundle, consumerManifest: nativeConsumer, pid: child.pid,
    elapsedMs: performance.now() - started, ...outcome, timedOut, stdout, stderr, observations,
    qualification: 'fixture feasibility only; no complete gate/native qualification result' };
  await writeFile(join(directory, 'launch-result.json'), JSON.stringify(record, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return record;
}
