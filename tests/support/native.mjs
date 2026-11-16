// Testing-only fixture orchestration; no active inventoried cases or readiness provider.
import assert from 'node:assert/strict';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, constants } from 'node:fs';
import { mkdir, readFile, writeFile, realpath, readdir, readlink, lstat, cp, appendFile, link, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve, sep, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
export const nativeConsumer = Object.freeze({
  manifest: '/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-46-20261116-6df9y348/consumer-manifest.json',
  digest: '25fe40877f7c3415bc5c5cce034320440bdfbb287170e30c9cb319728ca9490e',
});
const hash = value => createHash('sha256').update(value).digest('hex');
const run = (file, args, timeout = 30000) => execFileSync(file, args, { encoding: 'utf8', timeout,
  env: { PATH: '/usr/bin:/bin', HOME: process.env.HOME }, maxBuffer: 1024 * 1024 });
async function physicalInventory(directory) {
  const actual = {};
  async function walk(path) {
    for (const name of (await readdir(path)).sort()) {
      const child = join(path, name), st = await lstat(child), key = relative(directory, child);
      if (st.isSymbolicLink()) actual[key] = hash(`symlink\0${await readlink(child)}`);
      else if (st.isDirectory()) await walk(child);
      else {
        assert.ok(st.isFile());
        const digest = createHash('sha256'); for await (const bytes of createReadStream(child)) digest.update(bytes);
        actual[key] = digest.digest('hex');
      }
    }
  }
  await walk(directory); return actual;
}
const trustVariants = new WeakSet(); // Fixture provenance only; never a product capability.
const trustResource = 'Contents/Resources/browser/metadata.json';
export const trustProviderMethod = 'NSWindow#makeFirstResponder:';
const publisherResource = 'Contents/Resources/publisher-requirement.json';
export const publisherRequirement = '=anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists';
const compatibilityResource = 'Contents/Resources/native-compatibility.json';
export async function prepareNativeTrustVariant(fixtures, destination, { kind = 'sealed-resource' } = {}) {
  assert.ok(['sealed-resource', 'wrong-publisher', 'frozen-trust', 'provider-mismatch'].includes(kind));
  const consumer = await verifiedConsumer(), candidate = resolve(destination);
  assert.ok(candidate.startsWith(fixtures.directory + sep) && candidate.endsWith('.app'));
  const baseBytes = await readFile(consumer.bundle.inventory.path);
  assert.equal(hash(baseBytes), consumer.bundle.inventory.sha256);
  const original = JSON.parse(baseBytes).files;
  await cp(consumer.candidate, candidate, { recursive: true, dereference: false, verbatimSymlinks: true,
    force: false, errorOnExist: true, mode: constants.COPYFILE_FICLONE });
  assert.deepEqual(await physicalInventory(candidate), original, 'Trust copy does not match immutable baseline');
  run('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R', '=anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists', candidate]);
  let providerChange;
  if (kind === 'sealed-resource') await appendFile(join(candidate, publisherResource), '\n');
  if (kind === 'wrong-publisher') run('/usr/bin/codesign', ['--force', '--sign', '-',
    '--preserve-metadata=identifier,entitlements,flags,runtime', candidate]);
  if (kind === 'provider-mismatch') {
    const path = join(candidate, compatibilityResource);
    const compatibility = JSON.parse(await readFile(path, 'utf8'));
    const method = compatibility.nativeABI.methods[trustProviderMethod];
    assert.equal(method.provider, 'AppKit');
    providerChange = { method: trustProviderMethod, before: method.provider, after: 'Electron Framework' };
    method.provider = providerChange.after;
    await writeFile(path, JSON.stringify(compatibility, null, 2) + '\n');
    // Re-sign only the disposable outer bundle; the executing Electron,
    // ownership addon and all packaged resources beneath browser stay frozen.
    run('/usr/bin/codesign', ['--force', '--sign', 'F1B6782A3BACC18E73FE08CA424C0A81450A982C',
      '--preserve-metadata=identifier,entitlements,flags,runtime', '--timestamp', candidate]);
    run('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R',
      '=anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists', candidate]);
  }
  const files = await physicalInventory(candidate);
  const differences = [...new Set([...Object.keys(original), ...Object.keys(files)])].filter(key => original[key] !== files[key]);
  if (kind === 'provider-mismatch' || kind === 'wrong-publisher') {
    const outerSignatureFiles = ['Contents/MacOS/arbol-browser-native', 'Contents/_CodeSignature/CodeResources'];
    const permitted = kind === 'provider-mismatch' ? [...outerSignatureFiles, compatibilityResource] : outerSignatureFiles;
    assert.ok(differences.includes(kind === 'provider-mismatch' ? compatibilityResource : outerSignatureFiles[0]));
    assert.ok(differences.every(path => permitted.includes(path)));
  } else assert.deepEqual(differences, kind === 'frozen-trust' ? [] : [publisherResource]);
  if (kind === 'sealed-resource') assert.deepEqual(JSON.parse(await readFile(join(candidate, publisherResource))),
    JSON.parse(await readFile(join(consumer.candidate, publisherResource))));
  const record = { format: 1, scope: 'disposable trust variant', kind,
    candidate, baseCandidate: consumer.candidate, baseConsumerManifest: nativeConsumer,
    changedResource: kind === 'sealed-resource' ? { path: publisherResource, before: original[publisherResource], after: files[publisherResource] } : null,
    providerChange, differences, files, preCorruptionSignatureVerified: true };
  const path = candidate + '.variant.json', bytes = JSON.stringify(record, null, 2) + '\n';
  await writeFile(path, bytes, { mode: 0o600, flag: 'wx' });
  const variant = Object.freeze({ ...record, manifest: { path, sha256: hash(bytes) } });
  trustVariants.add(variant); return variant;
}
export async function verifiedConsumer() {
  const bytes = await readFile(nativeConsumer.manifest);
  assert.equal(hash(bytes), nativeConsumer.digest, 'Immutable consumer manifest drift');
  const value = JSON.parse(bytes);
  assert.equal(await realpath(value.candidate), value.candidate);
  assert.equal(value.pageAdmission, false);
  assert.equal(hash(await readFile(value.manifest.path)), value.manifest.sha256);
  const sourceReview = JSON.parse(await readFile(value.sourceReviewManifest.path));
  assert.equal(hash(await readFile(value.sourceReviewManifest.path)), value.sourceReviewManifest.sha256);
  const sourceBytes = await readFile(sourceReview.sourceRecord.path);
  assert.equal(hash(sourceBytes), sourceReview.sourceRecord.sha256);
  assert.deepEqual(sourceReview.sourceRecord, value.sourceRecord);
  const sourceRecord = JSON.parse(sourceBytes);
  for (const [file, digest] of Object.entries(sourceRecord.sources))
    assert.equal(hash(await readFile(join(sourceReview.frozenSource, file))), digest, 'Frozen accepted source drift');
  for (const [file, digest] of Object.entries(sourceReview.compiledInventory))
    assert.equal(hash(await readFile(join(sourceReview.frozenDist, file))), digest, 'Frozen compiled source drift');
  const inventoryBytes = await readFile(value.bundle.inventory.path);
  assert.equal(hash(inventoryBytes), value.bundle.inventory.sha256);
  assert.deepEqual(await physicalInventory(value.candidate), JSON.parse(inventoryBytes).files, 'Complete physical native consumer drift');
  return Object.freeze(value);
}
export async function createNativeOutput(output) {
  assert.ok(isAbsolute(output) && resolve(output) === output);
  assert.ok(![root, '/Users/msix/Artifacts', dirname(nativeConsumer.manifest)].some(path => output === path || output.startsWith(path + sep)));
  const parent = dirname(output), stat = await lstat(parent);
  assert.equal(await realpath(parent), parent);
  assert.ok(stat.isDirectory() && stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o700,
    'Native evidence requires a private output parent');
  await mkdir(output, { mode: 0o700 });
  return output;
}
export const censusScenarios = Object.freeze(['absent', 'outside-reuse', 'live-original', 'unresolved',
  'same-start-uid', 'same-start-version', 'inside-reuse', 'never-verified', 'final-original-live']);
export async function runCensusWitness(output, { predecessor = false } = {}) {
  await createNativeOutput(output);
  const consumer = await verifiedConsumer();
  const review = JSON.parse(await readFile(consumer.sourceReviewManifest.path));
  const sourceRecord = JSON.parse(await readFile(review.sourceRecord.path));
  const effectiveHeader = join(review.frozenSource, 'watchdog/boundary.hpp');
  assert.equal(hash(await readFile(effectiveHeader)), sourceRecord.sources['watchdog/boundary.hpp']);
  const driver = join(root, 'tests/support/native-census.mm');
  let header = effectiveHeader;
  if (predecessor) {
    header = join(output, 'predecessor-boundary.hpp');
    await writeFile(header, execFileSync('/usr/bin/git', ['-C', root, 'show', consumer.parent + ':watchdog/boundary.hpp']), { mode: 0o600, flag: 'wx' });
  }
  const compiler = run('/usr/bin/xcrun', ['--find', 'clang++']).trim();
  const sdk = run('/usr/bin/xcrun', ['--show-sdk-path']).trim();
  const binary = join(output, 'native-census');
  const arguments_ = ['-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-fobjc-arc', '-arch', 'arm64',
    '-isysroot', sdk, '-mmacosx-version-min=27.0', `-DARBOL_CENSUS_HEADER="${header}"`, driver,
    '-framework', 'Foundation', '-framework', 'Security', '-o', binary];
  const inputs = { driver: { path: driver, sha256: hash(await readFile(driver)) },
    header: { path: header, sha256: hash(await readFile(header)) },
    acceptedHeader: { path: effectiveHeader, sha256: sourceRecord.sources['watchdog/boundary.hpp'] } };
  const record = { consumerManifest: nativeConsumer, sourceReview: consumer.sourceReviewManifest, sourceRecord: review.sourceRecord,
    sourceCommit: consumer.commit, predecessorCommit: predecessor ? consumer.parent : null, inputs,
    compiler, compilerVersion: run(compiler, ['--version']), arguments: arguments_, sdk, scenarios: [], passed: false };
  try {
    run(compiler, arguments_);
    record.binary = { path: binary, sha256: hash(await readFile(binary)) };
    for (const scenario of predecessor ? ['absent'] : censusScenarios) {
      const row = JSON.parse(run(binary, [consumer.candidate, scenario]));
      record.scenarios.push(row);
      assert.equal(row.admitted, true);
      assert.equal(row.helperVerified, scenario !== 'never-verified');
      assert.equal(row.accepted, !predecessor && ['absent', 'outside-reuse'].includes(scenario), scenario);
      assert.ok(row.targets.every(target => target.pid !== row.originalHelper.pid), 'No exited or replacement helper may be a signal target');
      assert.equal(row.seen.some(item => JSON.stringify(item) === JSON.stringify(row.originalHelper)), scenario !== 'never-verified');
      if (!predecessor && ['absent', 'outside-reuse', 'final-original-live'].includes(scenario))
        assert.ok(row.faultObservations.filter(item => item.call === 'pidinfo' && item.pid === row.originalHelper.pid).length >= 3,
          'The original must reach final reconciliation');
    }
    for (const value of [inputs.driver, inputs.header]) assert.equal(hash(await readFile(value.path)), value.sha256);
    record.passed = true;
  } catch (error) { record.error = String(error.stack ?? error); throw error; }
  finally { await writeFile(join(output, 'census-record.json'), JSON.stringify(record, null, 2) + '\n', { mode: 0o600, flag: 'wx' }); }
  return record;
}
export async function prepareNativeFixtures(output, { callbacks = false } = {}) {
  const destination = resolve(output);
  assert.ok(!destination.startsWith(root + sep) && !destination.startsWith('/Users/msix/Artifacts/'));
  const consumer = await verifiedConsumer();
  assert.ok(!destination.startsWith(consumer.candidate + sep));
  await createNativeOutput(destination);
  const compiler = run('/usr/bin/xcrun', ['--find', 'clang++']).trim();
  const sdk = run('/usr/bin/xcrun', ['--show-sdk-path']).trim();
  const sources = ['native-launch.mm', 'native-observer.mm', 'native-entry.mjs', 'native.mjs'];
  if (callbacks) sources.push('native-callbacks.mm');
  const inputs = {};
  for (const file of sources) inputs[file] = hash(await readFile(join(root, 'tests/support', file)));
  for (const file of ['native-launch', 'native-observer']) run(compiler, ['-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
    '-fobjc-arc', '-arch', 'arm64', '-isysroot', sdk, '-mmacosx-version-min=27.0', join(root, 'tests/support', file + '.mm'),
    '-framework', 'Foundation', '-o', join(destination, file)]);
  let callback;
  if (callbacks) {
    const headers = '/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-46-20261116-6df9y348/headers/node_headers/include/node';
    const { nativeCompilerPolicy } = await import('../../scripts/compile-native.mjs');
    for (const [file, digest] of Object.entries(nativeCompilerPolicy.headerHashes))
      assert.equal(hash(await readFile(join(headers, file))), digest, 'Pinned callback header drift');
    const path = join(destination, 'native-callbacks.node');
    const arguments_ = ['-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-fobjc-arc', '-fblocks', '-fvisibility=hidden',
      '-DNAPI_VERSION=8', '-arch', 'arm64', '-isysroot', sdk, '-mmacosx-version-min=27.0', '-bundle', '-undefined', 'dynamic_lookup',
      '-I', headers, join(root, 'tests/support/native-callbacks.mm'), '-framework', 'Cocoa', '-o', path];
    run(compiler, arguments_); const unsignedDigest = hash(await readFile(path));
    run('/usr/bin/codesign', ['--force', '--sign', 'F1B6782A3BACC18E73FE08CA424C0A81450A982C', '--options', 'runtime', '--timestamp', path]);
    run('/usr/bin/codesign', ['--verify', '--strict', '-R', '=anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists', path]);
    const details = spawnSync('/usr/bin/codesign', ['-dvvv', path], { encoding: 'utf8', timeout: 30000 });
    const entitlements = spawnSync('/usr/bin/codesign', ['-d', '--entitlements', ':-', path], { encoding: 'utf8', timeout: 30000 });
    assert.equal(details.status, 0); assert.ok(details.stderr.includes('TeamIdentifier=7V372XL59S') && details.stderr.includes('runtime)') && details.stderr.includes('Timestamp='));
    assert.equal(entitlements.status, 0); assert.ok(!/com\.apple\.security\./.test(entitlements.stdout + entitlements.stderr));
    callback = { path, unsignedDigest, signedDigest: hash(await readFile(path)), compilerArguments: arguments_, headers, headerHashes: nativeCompilerPolicy.headerHashes, details: details.stderr, entitlements: entitlements.stdout + entitlements.stderr,
      policySources: Object.fromEntries(await Promise.all(['scripts/compile-native.mjs', 'scripts/package-base.mjs'].map(async file => [file, hash(await readFile(join(root, file)))]))) };
  }
  for (const [file, digest] of Object.entries(inputs)) assert.equal(hash(await readFile(join(root, 'tests/support', file))), digest, 'Fixture source drift during compilation');
  if (callback) for (const [file, digest] of Object.entries(callback.headerHashes)) assert.equal(hash(await readFile(join(callback.headers, file))), digest, 'Callback header drift during compilation');
  const record = { format: 1, consumerManifest: nativeConsumer, candidate: consumer.candidate, sourceInputs: inputs,
    compiler, compilerVersion: run(compiler, ['--version']), sdk, callback,
    binaries: Object.fromEntries(await Promise.all(['native-launch', 'native-observer'].map(async file => [file, hash(await readFile(join(destination, file)))]))),
    harnessRuntime: { node: process.versions.node, arch: process.arch, platform: process.platform },
    sourceCommit: run('/usr/bin/git', ['-C', root, 'rev-parse', 'HEAD']).trim(), scope: 'private native qualification fixtures' };
  await writeFile(join(destination, 'fixture-manifest.json'), JSON.stringify(record, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return Object.freeze({ directory: destination, consumer, record });
}
export function observeNative(fixtures, kind, value, timeout) {
  assert.ok(['process', 'group', 'contend', 'custody', 'startup-slots'].includes(kind));
  return JSON.parse(run(join(fixtures.directory, 'native-observer'), [kind, String(value)], timeout));
}
async function publishReadyMarker(path) {
  const pending = path + '.pending';
  await writeFile(pending, 'ready\n', { mode: 0o600, flag: 'wx' });
  try {
    await link(pending, path); // Publish complete bytes without replacing an existing marker.
  } finally {
    await unlink(pending);
  }
}

async function observeFrozenTrust(variant, output, onStage) {
  const resourcePath = join(variant.candidate, trustResource);
  const original = await readFile(resourcePath);
  assert.equal(hash(original), variant.files[trustResource]);
  await onStage('frozen-trust-ready');
  await appendFile(resourcePath, '\n');
  const altered = hash(await readFile(resourcePath));
  assert.notEqual(altered, hash(original));
  await publishReadyMarker(join(output, 'drift-ready'));
  await onStage('frozen-trust-drift-refused');
  await writeFile(resourcePath, original);
  assert.deepEqual(await physicalInventory(variant.candidate), variant.files);
  await publishReadyMarker(join(output, 'restore-ready'));
  await onStage('frozen-trust-restored-refused');
  return { before: hash(original), altered, restored: hash(await readFile(resourcePath)) };
}
const installPoisonScenarios = new Set(['pre-commit-poison', 'rollback-confirmed', 'rollback-unconfirmed']);
export const bindingScenarios = Object.freeze(['stale-nonce', 'stale-contents', 'stale-revision', 'detached-view',
  'ambiguous-creation', 'reentrant-creation', 'retired-replacement']);
export const retirementScenarios = Object.freeze(['success', 'detach-throws', 'destroy-missing', 'native-detach-blocked']);
export const startupScenarios = Object.freeze(['startup-descriptors', 'bootstrap-identity-refused', 'late-readiness',
  'primary-producer-lost', 'custody-producer-lost', 'custody-withholds-c', 'custody-withholds-g', 'primary-withholds-j']);
export const failureScenarios = Object.freeze(['heartbeat-silence', 'ack-silence', 'eof', 'malformed', 'out-of-order',
  'integrity-refused', 'cleanup-blocked', 'exit-blocked', 'fatal-shortening']);
export const monitorScenarios = Object.freeze(['primary-lost', 'primary-hung', 'primary-timeout', 'custody-lost', 'custody-hung', 'both-lost', 'custody-consent']);

async function observeStartupBirths(fixtures, directory, pid, mode, waitForStage) {
  const published = await waitForStage('locks');
  await waitForStage('startup-observer-waiting');
  const main = observeNative(fixtures, 'process', pid);
  assert.equal(main.executable, join(fixtures.consumer.candidate, 'Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron'));
  const helper = join(fixtures.consumer.candidate, 'Contents/Resources/browser/native/watchdog');
  const locks = { owner: { path: join(directory, 'owner.lock'), ...published.owner }, build: { path: join(directory, 'build.lock'), ...published.build } };
  const verb = mode === 'bootstrap-identity-refused' ? 'startup-refusal' : 'startup-births';
  return observeWithMarker(fixtures, directory, verb, { main, helper, mode, locks }, 'startup-observer-ready');
}

async function observeFailureCustody(fixtures, directory, pid, waitForStage, monitorScenario) {
  const published = await waitForStage('locks');
  const ready = await waitForStage(monitorScenario ? 'monitor-observer-waiting' : 'failure-observer-waiting');
  const browser = join(fixtures.consumer.candidate, 'Contents/Resources/browser');
  const engine = join(browser, 'runtime/Electron.app/Contents');
  const helper = join(browser, 'native/watchdog');
  const family = observeNative(fixtures, 'group', pid).members.filter(member => member.status === 'alive');
  const main = family.find(member => member.pid === pid);
  const anchor = family.find(member => member.executable === helper && member.parent !== pid);
  assert.equal(main?.executable, join(engine, 'MacOS/Electron'));
  assert.ok(anchor, 'No actual custody process in the original group');
  const primary = observeNative(fixtures, 'process', anchor.parent);
  assert.equal(primary.executable, helper);
  assert.equal(primary.group, primary.pid);
  assert.equal(primary.originalParentVersion, main.pidVersion);
  assert.equal(anchor.originalParentVersion, primary.pidVersion);
  const engineHelpers = ['', ' (Renderer)', ' (GPU)', ' (Plugin)'].map(suffix =>
    join(engine, `Frameworks/Electron Helper${suffix}.app/Contents/MacOS/Electron Helper${suffix}`));
  for (const member of family) assert.ok(member === main || member === anchor || (
    engineHelpers.includes(member.executable) && member.originalParentVersion === main.pidVersion),
  `Unclassified process ${member.pid} in the original group`);
  assert.ok(family.some(member => member.pid === ready.renderer && member.executable === engineHelpers[1]), 'No actual fixture renderer');
  const locks = { owner: { path: join(directory, 'owner.lock'), ...published.owner }, build: { path: join(directory, 'build.lock'), ...published.build } };
  const request = { format: 1, group: pid, anchor, processes: [...family, primary], locks };
  if (!monitorScenario) return observeWithMarker(fixtures, directory, 'failure-custody', request, 'failure-observer-ready');
  return observeWithSentinel(fixtures, directory, request, monitorScenario);
}

async function observeSupportedHelperExit(fixtures, directory, pid, waitForStage) {
  const record = { scope: 'independent kernel process and original lock observations', samples: [], passed: false };
  try {
    const published = await waitForStage('locks');
    const ready = await waitForStage('helper-exit-observer-waiting');
    const family = observeNative(fixtures, 'group', pid).members;
    const helper = join(fixtures.consumer.candidate, 'Contents/Resources/browser/native/watchdog');
    const anchor = family.find(member => member.status === 'alive' && member.executable === helper && member.parent !== pid);
    assert.ok(anchor);
    const primary = observeNative(fixtures, 'process', anchor.parent);
    const main = family.find(member => member.pid === pid), renderer = family.find(member => member.pid === ready.renderer);
    assert.equal(primary.executable, helper); assert.equal(primary.group, primary.pid);
    assert.equal(renderer?.executable, join(fixtures.consumer.candidate,
      'Contents/Resources/browser/runtime/Electron.app/Contents/Frameworks/Electron Helper (Renderer).app/Contents/MacOS/Electron Helper (Renderer)'));
    record.originals = { main, primary, custody: anchor, renderer };
    const locks = { owner: { path: join(directory, 'owner.lock'), ...published.owner }, build: { path: join(directory, 'build.lock'), ...published.build } };
    const request = { format: 1, group: pid, anchor, processes: [main, primary, anchor, renderer], locks };
    const sample = () => observeNative(fixtures, 'custody', JSON.stringify(request));
    record.baseline = sample();
    await publishReadyMarker(join(directory, 'helper-exit-observer-ready'));
    record.requested = await waitForStage('helper-exit-requested');
    const deadline = performance.now() + 10000;
    for (;;) {
      const current = observeNative(fixtures, 'process', renderer.pid);
      record.samples.push({ at: performance.now(), renderer: current });
      if (current.status === 'gone') break;
      assert.ok(performance.now() < deadline, 'Original renderer did not disappear after supported close');
      await new Promise(accept => setTimeout(accept, 50));
    }
    record.afterExit = sample();
    await publishReadyMarker(join(directory, 'helper-exit-observed'));
    record.live = await waitForStage('helper-exit-live');
    // Keep the signed census and protocol active beyond another full watchdog interval.
    await new Promise(accept => setTimeout(accept, 2300));
    record.continued = sample();
    record.protocol = (await readFile(join(directory, 'failure.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
    record.passed = true;
  } catch (error) { record.error = String(error.stack ?? error); }
  finally {
    await writeFile(join(directory, 'helper-exit-observation.json'), JSON.stringify(record, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    await publishReadyMarker(join(directory, 'helper-exit-release'));
  }
  return record;
}

async function observeWithSentinel(fixtures, directory, custody, mode) {
  const profile = join(directory, 'sentinel');
  await mkdir(profile, { mode: 0o700 });
  const child = spawn(join(fixtures.directory, 'native-observer'), ['sentinel', profile], {
    detached: true, stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin' },
  });
  let inputError;
  child.stdin.on('error', error => { inputError = String(error); });
  const done = new Promise(accept => { child.once('close', (code, signal) => accept({ code, signal })); });
  const sample = () => ({ process: observeNative(fixtures, 'process', child.pid),
    locks: Object.fromEntries(['owner', 'build'].map(name => [name, observeNative(fixtures, 'contend', join(profile, `${name}.lock`))])) });
  let result;
  try {
    await new Promise((accept, reject) => {
      child.once('error', reject);
      child.once('close', () => reject(new Error('The sentinel exited before readiness')));
      let ready = '';
      child.stdout.on('data', bytes => { ready += bytes; if (ready === 'ready\n') accept(); });
    });
    const before = sample();
    assert.equal(before.process.group, child.pid);
    assert.notEqual(before.process.group, custody.group);
    assert.ok(Object.values(before.locks).every(lock => !lock.acquired));
    const request = { custody, mode, sentinel: before.process, trigger: join(directory, 'monitor-trigger') };
    result = await observeWithMarker(fixtures, directory, 'monitor-loss', request, 'monitor-observer-ready');
    result.sentinel = { before, after: sample() };
  } finally {
    child.stdin.end();
    const exit = await done;
    if (result?.sentinel) result.sentinel.exit = { ...exit, inputError };
  }
  return result;
}

async function observeWithMarker(fixtures, directory, command, request, markerName) {
  const observer = spawn(join(fixtures.directory, 'native-observer'), [command, JSON.stringify(request)],
    { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin' } });
  let out = '', err = '', marker;
  observer.stdout.on('data', chunk => {
    out += chunk;
    if (!marker && out.startsWith('{"stage":"watch-ready"}\n')) {
      marker = publishReadyMarker(join(directory, markerName));
      void marker.catch(() => {});
    }
  });
  observer.stderr.on('data', chunk => { err += chunk; });
  const code = await new Promise((accept, reject) => {
    observer.once('error', reject);
    observer.once('close', accept);
  });
  await marker;
  assert.equal(code, 0, err);
  const lines = out.trim().split('\n');
  assert.ok(lines.length === 2 || lines.length === 1, 'The external observer did not finish its bracketed read');
  const result = JSON.parse(lines.at(-1));
  if (lines.length === 1) assert.ok(result.unavailable);
  return result;
}

export async function launchNativeFixture(fixtures, {
  mode = 'boundary', callback = fixtures.record.callback?.path, output, variant, poisonScenario, bindingScenario, retirementScenario, startupScenario, failureScenario, monitorScenario,
}) {
  const callbackModes = ['callbacks', 'resolver-control', 'install-poison', 'binding-lifetime', 'cached-routes', 'concurrent-responder', 'retirement', 'startup-custody', 'failure-custody', 'monitor-loss', 'helper-exit', 'custom-ax'];
  assert.ok(['boundary', 'frozen-trust', 'frozen-trust-restored', 'provider-mismatch', ...callbackModes].includes(mode));
  assert.ok(callback || !callbackModes.includes(mode));
  assert.equal(mode === 'install-poison', installPoisonScenarios.has(poisonScenario));
  assert.equal(mode === 'binding-lifetime', bindingScenarios.includes(bindingScenario));
  assert.equal(mode === 'retirement', retirementScenarios.includes(retirementScenario));
  assert.equal(mode === 'startup-custody', startupScenarios.includes(startupScenario));
  assert.equal(mode === 'failure-custody', failureScenarios.includes(failureScenario));
  assert.equal(mode === 'monitor-loss', monitorScenarios.includes(monitorScenario));
  assert.equal(['frozen-trust', 'frozen-trust-restored'].includes(mode), variant?.kind === 'frozen-trust');
  assert.equal(mode === 'provider-mismatch', variant?.kind === 'provider-mismatch');
  const consumer = await verifiedConsumer(); assert.equal(consumer.candidate, fixtures.consumer.candidate);
  for (const [file, digest] of Object.entries(fixtures.record.binaries))
    assert.equal(hash(await readFile(join(fixtures.directory, file))), digest, 'Prepared observer/launcher binary drift');
  if (variant) {
    assert.ok(trustVariants.has(variant), 'Unprepared fixture variant');
    assert.equal(variant.baseCandidate, consumer.candidate);
    assert.equal(hash(await readFile(variant.manifest.path)), variant.manifest.sha256);
    assert.equal(await realpath(variant.candidate), variant.candidate);
    assert.deepEqual(await physicalInventory(variant.candidate), variant.files, 'Declared disposable variant drift');
  }
  const directory = resolve(output); assert.ok(directory.startsWith(fixtures.directory + sep));
  for (const [file, expected] of Object.entries(fixtures.record.sourceInputs))
    assert.equal(hash(await readFile(join(root, 'tests/support', file))), expected, 'Prepared fixture source drift');
  await mkdir(directory, { mode: 0o700 });
  const home = join(directory, 'home'); await mkdir(home, { mode: 0o700 });
  for (const name of ['app-data', 'session-data']) await mkdir(join(home, name), { mode: 0o700 });
  if (callback) { assert.equal(callback, fixtures.record.callback?.path); assert.equal(hash(await readFile(callback)), fixtures.record.callback.signedDigest); }
  const config = { format: 1, mode, bundle: variant?.candidate ?? fixtures.consumer.candidate, output: directory, home, trustProbe: Boolean(variant),
    providerMethod: variant?.providerChange?.method, poisonScenario, bindingScenario, retirementScenario, startupScenario, failureScenario, monitorScenario,
    owner: join(directory, 'owner.lock'), build: join(directory, 'build.lock'), callback };
  const request = join(directory, 'request.json');
  await writeFile(request, JSON.stringify(config) + '\n', { mode: 0o600, flag: 'wx' });
  const entry = await realpath(join(root, 'tests/support/native-entry.mjs'));
  const child = spawn(join(fixtures.directory, 'native-launch'), [config.bundle, entry, home, request], {
    env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'], cwd: directory, detached: false,
  });
  let stdout = '', stderr = '', timedOut = false;
  const observations = [], tracked = new Map();
  const startupSlots = [];
  child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
  const started = performance.now();
  function sample(stopAt = Infinity) {
    const inspect = (kind, value) => {
      const milliseconds = Math.floor(stopAt - performance.now());
      assert.ok(milliseconds > 0, 'Terminal kernel observation deadline reached');
      return observeNative(fixtures, kind, value, Math.min(milliseconds, 30000));
    };
    try {
      const identity = inspect('process', child.pid), group = inspect('group', child.pid);
      for (const member of group.members) if (member.status === 'alive') {
        const key = `${member.pid}:${member.startId}:${member.pidVersion}`;
        if (!tracked.has(key)) tracked.set(key, member);
        // Custody remains in the original group; its actual parent identifies
        // the outside primary without trusting a fixture-supplied ready receipt.
        if (member.parent > 1 && member.executable === join(config.bundle, 'Contents/Resources/browser/native/watchdog')) {
          const parent = inspect('process', member.parent);
          if (parent.status === 'alive' && parent.executable === member.executable && parent.startId === member.parentStartId)
            if (!tracked.has(`${parent.pid}:${parent.startId}:${parent.pidVersion}`))
              tracked.set(`${parent.pid}:${parent.startId}:${parent.pidVersion}`, parent);
        }
      }
      let current, locks = {}, ordered;
      const published = stdout.split('\n').flatMap(line => { try { const value = JSON.parse(line); return value.stage === 'locks' ? [value] : []; } catch { return []; } }).at(-1);
      const originals = [...tracked.values()].filter(value => value.executable.startsWith(config.bundle + sep));
      if (startupScenario === 'startup-descriptors' && startupSlots.length === 0 && stdout.includes('"stage":"startup-descriptors"')) {
        const monitors = originals.filter(value => value.executable === join(config.bundle, 'Contents/Resources/browser/native/watchdog'));
        const anchor = monitors.find(value => value.group === child.pid && value.parent !== child.pid);
        const primary = monitors.find(value => value.pid === anchor?.parent && value.startId === anchor.parentStartId);
        if (anchor && primary) startupSlots.push(...[primary, anchor].map(expected => ({ expected, ...inspect('startup-slots', expected.pid) })));
      }
      if (published && originals.length) {
        const anchor = originals.find(value => value.executable === join(config.bundle, 'Contents/Resources/browser/native/watchdog') && value.group === child.pid && value.parent !== child.pid) ?? null;
        ordered = inspect('custody', JSON.stringify({ format: 1, group: child.pid, anchor, processes: originals,
          locks: { owner: { path: config.owner, ...published.owner }, build: { path: config.build, ...published.build } } }));
      }
      if (ordered?.order) {
        current = ordered.order.find(point => point.stage === 'before-close')?.processes ?? [];
        locks = ordered.locks ?? {};
      } else {
        current = originals.map(original => ({ original, current: inspect('process', original.pid) }));
      }
      // The combined observer supplies post-reads/locks; do not add sequential
      // process/contender subprocesses that obscure ordering and burden startup.
      assert.ok(performance.now() <= stopAt, 'Terminal sample completed after the deadline');
      const value = { elapsedMs: performance.now() - started, identity, group, current, locks, ordered }; observations.push(value); return value;
    } catch (error) { const value = { elapsedMs: performance.now() - started, unavailable: String(error) }; observations.push(value); return value; }
  }
  const timer = setInterval(sample, 100);
  async function waitForStage(stage) {
    const deadline = performance.now() + 15000;
    const marker = `"stage":"${stage}"`;
    for (;;) {
      const line = stdout.split('\n').slice(0, -1).find(line => line.startsWith('{' + marker));
      if (line) return JSON.parse(line);
      assert.ok(child.exitCode === null && child.signalCode === null && performance.now() < deadline, `Missing fixture observation ${stage}`);
      await new Promise(accept => setTimeout(accept, 25));
    }
  }
  const trustProbe = mode === 'frozen-trust' ? observeFrozenTrust(variant, directory, waitForStage)
    .catch(error => ({ unavailable: String(error.message ?? error) })) : undefined;
  const watchBirths = mode === 'startup-custody' && startupScenario !== 'late-readiness';
  const startupBirths = watchBirths ? observeStartupBirths(fixtures, directory, child.pid, startupScenario, waitForStage)
    .catch(error => ({ unavailable: String(error.message ?? error) })) : undefined;
  const failureCustody = ['failure-custody', 'monitor-loss'].includes(mode) ? observeFailureCustody(fixtures, directory, child.pid, waitForStage, monitorScenario)
    .catch(error => ({ unavailable: String(error.message ?? error) })) : undefined;
  const helperExit = mode === 'helper-exit' ? observeSupportedHelperExit(fixtures, directory, child.pid, waitForStage) : undefined;
  // Timeout teardown is explicitly not production enforcement evidence.
  const deadline = setTimeout(() => {
    timedOut = true;
    child.kill('SIGKILL');
    child.stdout.destroy();
    child.stderr.destroy();
  }, 90000);
  const outcome = await new Promise((accept, reject) => { child.once('error', reject); child.once('close', (code, signal) => accept({ code, signal })); })
    .finally(() => { clearInterval(timer); clearTimeout(deadline); });
  const exitObserved = performance.now();
  const births = await startupBirths;
  for (const identity of Object.values(births?.first ?? {})) {
    const key = `${identity.pid}:${identity.startId}:${identity.pidVersion}`;
    if (!tracked.has(key)) tracked.set(key, identity);
  }
  const locksPublished = stdout.split('\n').some(line => line.startsWith('{"stage":"locks",'));
  const awaitingRetirement = sample => !sample.current || sample.current.some(({ original, current }) =>
    current.status === 'uncertain' || (current.status === 'alive' && current.startId === original.startId));
  const awaitingLockRelease = sample => locksPublished && (sample.ordered?.unavailable ||
    !['owner', 'build'].every(name => sample.ordered?.locks?.[name]?.acquired === true));
  const terminalDeadline = exitObserved + 10000;
  let final = sample(terminalDeadline);
  while (performance.now() < terminalDeadline && (awaitingRetirement(final) || awaitingLockRelease(final))) {
    await new Promise(accept => setTimeout(accept, 100));
    if (performance.now() >= terminalDeadline) break;
    final = sample(terminalDeadline);
  }
  const record = { format: 1, mode, candidate: config.bundle, consumerManifest: nativeConsumer, derivation: variant ?? null,
    consumerRole: variant ? 'immutable baseline only; executing copy is explicitly derived' : 'exact executing consumer', pid: child.pid,
    elapsedMs: performance.now() - started, ...outcome, timedOut, stdout, stderr, observations,
    frozenTrust: await trustProbe, startupSlots: mode === 'startup-custody' ? startupSlots : undefined, startupBirths: births,
    failureCustody: await failureCustody, helperExit: await helperExit,
    scope: 'one private fixture launch' };
  await writeFile(join(directory, 'launch-result.json'), JSON.stringify(record, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return record;
}

export function requireNativeLaunch(launch, events, { armed = false } = {}) {
  const launcher = events.find(event => event.stage === 'launcher');
  const executable = join(launch.candidate, 'Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron');
  const fields = ['pid', 'startId', 'group', 'session', 'uid'];
  const witnessed = identity => identity?.status === 'alive' && identity.executed === true && identity.executable === executable &&
    fields.every(field => launcher?.[field] === identity[field]);
  if (!launch.observations.some(sample => witnessed(sample.identity))) throw Object.assign(
    new Error('Independent observer missed the post-exec Electron identity'), { code: 'fixture_observation_unavailable' });
  if (armed) {
    if (!launch.observations.some(({ ordered }) => ordered && !ordered.unavailable && ['owner', 'build'].every(name =>
      ordered.locks[name]?.acquired === false && ['before', 'after'].every(stage =>
        ordered.order.find(point => point.stage === stage + '-' + name)?.processes.some(row =>
          row.identityMatches && witnessed(row.current)))))) throw Object.assign(
      new Error('Independent observer missed live main holding both original locks'), { code: 'fixture_observation_unavailable' });
  }
}

export function assertOriginalsGoneOnAcquisition(launch, captured) {
  const final = launch.observations.at(-1).ordered;
  assert.ok(final && !final.unavailable, 'No ordered final exact-inode observations');
  const originals = captured ?? final.expected.processes;
  for (const name of ['owner', 'build']) {
    assert.equal(final.locks[name].acquired, true);
    for (const phase of ['before', 'after']) {
      const rows = final.order.find(row => row.stage === phase + '-' + name).processes;
      for (const original of originals) {
        const match = rows.find(row => ['pid', 'startId', 'pidVersion', 'uid', 'session', 'executable']
          .every(key => row.original[key] === original[key]));
        assert.ok(match, 'Final sample omitted original ' + original.pid);
        assert.equal(match.current.status, 'gone');
      }
    }
  }
}

export async function requirePreTrialExit(launch, events, reportPath) {
  requireNativeLaunch(launch, events, { armed: true });
  const persisted = JSON.parse(await readFile(join(dirname(reportPath), 'entry-events.json'), 'utf8'));
  assert.deepEqual(persisted, events.filter(event => event.stage !== 'launcher'));
  assert.equal(persisted.at(-1).stage, 'installed');
  assert.equal(persisted.at(-1).status.phase, 'ready');
  assert.equal(launch.stderr, '');
  await assert.rejects(lstat(reportPath), { code: 'ENOENT' }, 'An existing case record precludes retry');
  for (const { ordered } of launch.observations) {
    for (const name of ['owner', 'build']) {
      if (ordered?.locks?.[name]?.acquired !== true) continue;
      const before = ordered.order.find(point => point.stage === 'before-' + name).processes;
      const after = ordered.order.find(point => point.stage === 'after-' + name).processes;
      assert.ok(!before.some(row => row.identityMatches && after.some(other => other.identityMatches &&
        other.original.pid === row.original.pid && other.original.startId === row.original.startId)),
      'A captured original survived acquisition of the ' + name + ' lock');
    }
  }
  assertOriginalsGoneOnAcquisition(launch);
}
