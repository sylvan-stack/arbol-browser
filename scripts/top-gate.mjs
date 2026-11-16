// Complete explicit top-tier selection. No discovery, filters or native/page stand-ins.
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, readdir, readlink, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { inventoryDigest, sourceInventory } from './package-base.mjs';
import { nativeConsumer, verifiedConsumer } from '../tests/support/native.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const foundationSelection = [
  ['receiptRace', 'tests/top/test_foundation_boundary.mjs'],
  ['ownershipBoundary', 'tests/top/test_foundation_concurrency.mjs'],
  ['preservationBoundary', 'tests/top/test_foundation_recovery.mjs'],
  ['transportBoundary', 'tests/top/test_foundation_recovery.mjs'],
  ['closeAcquisitionBoundary', 'tests/top/test_foundation_concurrency.mjs'],
  ['startupAcquisitionBoundary', 'tests/top/test_foundation_concurrency.mjs'],
];
const selection = [
  ['nativeTrustBoundary', 'boundary', ['exact-consumer-control', 'sealed-resource-copy-refusal', 'wrong-publisher-copy-refusal',
    'frozen-trust-after-restored-copy', 'fresh-restored-control', 'provider-mismatch-refusal']],
  ['nativeInstallPoison', 'boundary', ['resolver-control', 'pre-commit-poison', 'rollback-confirmed', 'rollback-unconfirmed']],
  ['nativeBindingLifetime', 'concurrency', ['stale-nonce', 'stale-contents', 'stale-revision', 'detached-view',
    'ambiguous-creation', 'reentrant-creation', 'retired-replacement']],
  ['nativeCachedRouteBoundary', 'concurrency', ['matched-focus-and-renderer-swap']],
  ['nativeConcurrentResponder', 'concurrency', ['native-responder-and-trusted-input']],
  ['nativeRetirementBoundary', 'recovery', ['success', 'detach-throws', 'destroy-missing', 'native-detach-blocked']],
  ['nativeStartupCustodyBoundary', 'recovery', ['startup-descriptors', 'bootstrap-identity-refused', 'late-readiness',
    'primary-producer-lost', 'custody-producer-lost', 'custody-withholds-c', 'custody-withholds-g', 'primary-withholds-j']],
  ['nativeFailureCustodyBoundary', 'recovery', ['heartbeat-silence', 'ack-silence', 'eof', 'malformed', 'out-of-order',
    'integrity-refused', 'cleanup-blocked', 'exit-blocked', 'fatal-shortening']],
  ['nativeMonitorLossBoundary', 'recovery', ['primary-lost', 'primary-hung', 'custody-lost', 'custody-hung', 'both-lost', 'custody-consent']],
].map(([id, group, scenarios]) => [id, 'tests/top/test_native_' + group + '.mjs', scenarios]);
const allCases = [...foundationSelection, ...selection];
const foundationSupport = ['tests/support/foundation.mjs', 'tests/support/foundation-deadlines.mjs', 'tests/support/foundation-startup-deadlines.mjs'];
const nativeSupport = ['tests/support/native.mjs', 'tests/support/native-entry.mjs', 'tests/support/native-callbacks.mm',
  'tests/support/native-observer.mm', 'tests/support/native-launch.mm', 'scripts/compile-native.mjs', 'scripts/package-base.mjs'];
const boundFiles = ['test-tiers.json', 'scripts/top-gate.mjs', 'arbol-build.json'];
const sourceFiles = (cases, support) => [...new Set([...boundFiles, ...support, ...cases.map(([, file]) => file)])].sort();
const snapshot = (files) => Promise.all(files.map(async file => [file, hash(await readFile(join(repository, file)))])).then(Object.fromEntries);
const readJson = async path => JSON.parse(await readFile(path, 'utf8'));

async function readSelection() {
  const inventory = await readJson(join(repository, 'test-tiers.json'));
  assert.deepEqual(inventory.cases.map(item => [item.id, item.file, ...(item.scenarios ? [item.scenarios] : [])]), allCases);
  assert.ok(inventory.cases.every(item => item.tier === 'top' && item.status === 'retained'));
  return inventory;
}
async function verifyExports(cases) {
  const modules = new Map();
  for (const file of new Set(cases.map(([, file]) => file))) {
    const test = await import(pathToFileURL(join(repository, file)));
    assert.deepEqual(Object.keys(test).sort(), cases.filter(([, path]) => path === file).map(([id]) => id).sort(),
      'Missing/commented case or unselected exported case');
    modules.set(file, test);
  }
  return modules;
}

const args = process.argv.slice(2), embedded = args.at(-1) === '--embedded';
if (embedded) args.pop();
assert.ok(args.length === 4 || (!embedded && args.length === 6),
  'Usage: top-gate.mjs --candidate <package> --out <new-private-output> [--native-consumer <pinned-manifest>]');
assert.equal(args[0], '--candidate'); assert.equal(args[2], '--out');
assert.ok(args[1] && args[3] && isAbsolute(args[1]) && isAbsolute(args[3]));
if (args.length === 6) {
  assert.equal(args[4], '--native-consumer');
  assert.equal(args[5], nativeConsumer.manifest, 'Only the pinned ABR-46 manifest can qualify this gate');
}
const candidate = await realpath(args[1]), output = resolve(args[3]);
const protectedRoots = [resolve(repository), candidate, dirname(nativeConsumer.manifest), '/Users/msix/Artifacts'];
assert.ok(!protectedRoots.some(path => output === path || output.startsWith(path + sep)),
  'Qualification evidence must be outside the checkout, candidate and artifact trees');
if (!embedded) {
  assert.equal(await realpath(dirname(output)), dirname(output), 'Qualification output must have a canonical parent');
  await mkdir(output, { mode: 0o700 }); // refuse reuse of prior evidence
  const file = join(output, 'result.json');
  const gate = { format: 2, candidate, output, selection: allCases.map(([id]) => id), cases: [], startedAt: new Date().toISOString(), passed: false };
  const save = () => writeFile(file, JSON.stringify(gate, null, 2) + '\n', { mode: 0o600 });
  try {
    const inventory = await readSelection();
    gate.unavailableOutsideSelection = inventory.unavailable;
    const sources = sourceFiles(allCases, [...foundationSupport, ...nativeSupport]);
    gate.harness = await snapshot(sources);
    gate.harnessCommit = execFileSync('/usr/bin/git', ['-C', repository, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const nativeModules = await verifyExports(selection);
    const native = await verifiedConsumer();
    gate.nativeConsumer = { pin: nativeConsumer, candidate: native.candidate, codeCommit: native.commit,
      sourceDigest: native.sourceDigest, bundle: native.bundle, manifest: native.manifest, sourceReviewManifest: native.sourceReviewManifest };
    const { nativeConsumer: admitted } = inventory;
    assert.deepEqual(admitted, { manifest: nativeConsumer.manifest, digest: nativeConsumer.digest,
      codeCommit: native.commit, sourceDigest: native.sourceDigest, compatibilityDigest: native.manifest.sha256 });
    const foundationSource = inventoryDigest(await sourceInventory());
    const foundationOutput = join(output, 'foundation'), home = join(foundationOutput, 'runtime-home');
    await mkdir(foundationOutput, { mode: 0o700 });
    await mkdir(home, { mode: 0o700 });
    await save();
    const result = spawnSync(join(candidate, 'runtime/Electron.app/Contents/MacOS/Electron'),
      [fileURLToPath(import.meta.url), '--candidate', candidate, '--out', foundationOutput, '--embedded'], {
        cwd: repository, env: { HOME: home, PATH: '/usr/bin:/bin', ELECTRON_RUN_AS_NODE: '1', LANG: 'en_US.UTF-8' },
        stdio: 'inherit', timeout: 90000,
      });
    if (result.error) throw result.error;
    const foundation = await readJson(join(foundationOutput, 'result.json'));
    assert.equal(foundation.candidate, candidate);
    assert.equal(foundation.sourceDigest, foundationSource, 'Foundation package is not built from the current source');
    assert.deepEqual(foundation.selection, foundationSelection.map(([id]) => id));
    assert.deepEqual(foundation.harness, Object.fromEntries(sourceFiles(foundationSelection, foundationSupport).map(path =>
      [path, gate.harness[path]])));
    gate.foundation = { record: join(foundationOutput, 'result.json'), sourceDigest: foundation.sourceDigest,
      metadataDigest: foundation.metadataDigest, payloadDigest: foundation.payloadDigest, runtime: foundation.runtime, passed: foundation.passed };
    gate.cases.push(...foundation.cases);
    assert.equal(result.signal, null);
    assert.equal(foundation.passed, result.status === 0);
    await save();
    for (const [id, body, expected] of selection) {
      const began = performance.now(), destination = join(output, id);
      const row = { id, status: 'failed', scenarios: [] };
      gate.cases.push(row);
      try {
        let failure;
        try { await nativeModules.get(body)[id]({ output: destination }); }
        catch (error) { failure = error; }
        row.record = join(destination, 'case-result.json');
        const report = await readJson(row.record).catch(error => {
          if (error.code !== 'ENOENT') throw error;
          return null;
        });
        if (report) {
          assert.equal(report.case, id);
          assert.equal(report.sourceBodyDigest, gate.harness[body]);
          assert.deepEqual(report.nativeConsumer, nativeConsumer);
        }
        const raw = report?.scenarios ?? (report?.record && report?.launch
          ? [{ id: expected[0], status: report.status, record: report.record, launch: report.launch }] : []);
        const actual = raw.map(scenario => [scenario.id ?? scenario.scenario, scenario]);
        row.scenarios = expected.map(scenario => {
          const entry = actual.find(([name]) => name === scenario)?.[1];
          return { ...entry, id: scenario, status: entry?.status === 'incomplete' ? 'unavailable' : (entry?.status ?? 'unavailable') };
        });
        if (failure) throw failure;
        assert.equal(report?.status, 'passed');
        assert.deepEqual(actual.map(([name]) => name), expected, 'Required native scenario selection drift');
        assert.ok(row.scenarios.every(item => item.status === 'passed'), 'Required native oracle unavailable or failed');
        const fixture = await readJson(join(destination, 'fixtures/fixture-manifest.json'));
        row.fixtureManifest = join(destination, 'fixtures/fixture-manifest.json');
        row.fixtureManifestDigest = hash(await readFile(row.fixtureManifest));
        assert.equal(fixture.candidate, native.candidate);
        assert.equal(fixture.sourceCommit, gate.harnessCommit);
        assert.deepEqual(fixture.consumerManifest, nativeConsumer);
        assert.deepEqual(Object.keys(fixture.sourceInputs).sort(), ['native-entry.mjs', 'native-launch.mm', 'native-observer.mm', 'native.mjs',
          ...(id === 'nativeTrustBoundary' ? [] : ['native-callbacks.mm'])].sort());
        for (const [path, digest] of Object.entries(fixture.sourceInputs))
          assert.equal(digest, gate.harness['tests/support/' + path]);
        if (id !== 'nativeTrustBoundary') {
          for (const path of ['scripts/compile-native.mjs', 'scripts/package-base.mjs'])
            assert.equal(fixture.callback.policySources[path], gate.harness[path]);
          assert.equal(hash(await readFile(fixture.callback.path)), fixture.callback.signedDigest);
        }
        for (const name of ['native-launch', 'native-observer'])
          assert.equal(hash(await readFile(join(destination, 'fixtures', name))), fixture.binaries[name]);
        row.status = 'passed';
        console.log('PASS ' + id);
      } catch (error) {
        row.error = String(error.stack ?? error);
        row.scenarios = expected.map(scenario =>
          row.scenarios.find(item => item.id === scenario) ?? { id: scenario, status: 'unavailable' });
        console.error('FAIL ' + id + ': ' + error.message);
      }
      row.elapsedMs = performance.now() - began;
      await save();
    }
    assert.deepEqual(await snapshot(sources), gate.harness, 'Qualification harness changed during the gate');
    assert.equal(inventoryDigest(await sourceInventory()), foundationSource, 'Foundation source changed during the gate');
    assert.deepEqual(gate.cases.map(item => item.id), gate.selection);
    gate.passed = foundation.passed && gate.cases.every(item => item.status === 'passed');
  } catch (error) {
    gate.gateError = String(error.stack ?? error);
    console.error('GATE FAILED: ' + error.message);
  }
  gate.nativeScenarios = gate.cases.flatMap(item => item.scenarios ?? []).reduce((counts, item) => {
    counts[item.status] = (counts[item.status] ?? 0) + 1;
    return counts;
  }, {});
  gate.finishedAt = new Date().toISOString();
  await save();
  process.exitCode = gate.passed ? 0 : 1;
} else {
  try {
  // Electron's ASAR filesystem view must not replace physical archive bytes in
  // the package inventory. The embedded runtime exposes this documented flag.
  process.noAsar = true;
  const inventory = await readSelection();
  const metadataBytes = await readFile(join(candidate, 'metadata.json'));
  const metadata = JSON.parse(metadataBytes), payload = {};
  async function walk(path) {
    const st = await lstat(path), name = relative(candidate, path);
    if (st.isSymbolicLink()) {
      const link = await readlink(path);
      assert.ok(resolve(dirname(path), link).startsWith(candidate + sep), 'Escaping package link');
      payload[name] = hash(`symlink\0${link}`);
    } else if (st.isDirectory()) {
      for (const item of (await readdir(path)).sort()) await walk(join(path, item));
    } else {
      assert.ok(st.isFile());
      const h = createHash('sha256'); for await (const bytes of createReadStream(path)) h.update(bytes);
      payload[name] = h.digest('hex');
    }
  }
  for (const name of ['bin', 'lib', 'native', 'runtime', 'node_modules', 'package.json'].sort()) await walk(join(candidate, name));
  const mismatches = [...new Set([...Object.keys(payload), ...Object.keys(metadata.files)])]
    .filter(name => payload[name] !== metadata.files[name]);
  assert.equal(mismatches.length, 0, `Physical package differs at ${mismatches.slice(0, 8).join(', ')}`);
  const actualRuntime = { electron: process.versions.electron, chromium: process.versions.chrome,
    node: process.versions.node, napi: process.versions.napi, modules: process.versions.modules,
    platform: process.platform, arch: process.arch,
    macOS: execFileSync('/usr/bin/sw_vers', ['-productVersion'], { encoding: 'utf8' }).trim() };
  assert.deepEqual(actualRuntime, metadata.runtime, 'Declared runtime is not the executing runtime');
  const files = sourceFiles(foundationSelection, foundationSupport);
  const harness = await snapshot(files);
  const result = { format: 1, candidate, output, build: metadata.component.build,
    startedAt: new Date().toISOString(), sourceDigest: metadata.sourceDigest,
    metadataDigest: hash(metadataBytes), payloadDigest: hash(JSON.stringify(payload)), payloadEntries: Object.keys(payload).length,
    harness, runtime: actualRuntime, selection: foundationSelection.map(([id]) => id), cases: [],
    unavailable: inventory.unavailable, qualification: 'foundation-top-tier-only; production admission remains blocked' };
  const modules = await verifyExports(foundationSelection);
  for (const [id, file] of foundationSelection) {
    const began = performance.now();
    try {
      const evidence = await modules.get(file)[id]({ candidate, output });
      result.cases.push({ id, status: 'passed', elapsedMs: performance.now() - began, evidence });
      console.log(`PASS ${id}`);
    } catch (error) {
      result.cases.push({ id, status: 'failed', elapsedMs: performance.now() - began, error: String(error.stack ?? error) });
      console.error(`FAIL ${id}: ${error.stack ?? error}`);
    }
    await writeFile(join(output, 'result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  }
  for (const [file, expected] of Object.entries(harness)) assert.equal(hash(await readFile(join(repository, file))), expected);
  result.finishedAt = new Date().toISOString();
  result.passed = result.cases.length === foundationSelection.length && result.cases.every(item => item.status === 'passed');
  await writeFile(join(output, 'result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  process.exitCode = result.passed ? 0 : 1;
  } catch (error) {
    let partial = { format: 1, candidate, output, selection: foundationSelection.map(([id]) => id), cases: [] };
    try { partial = JSON.parse(await readFile(join(output, 'result.json'), 'utf8')); } catch { /* preflight selected no cases */ }
    await writeFile(join(output, 'result.json'), JSON.stringify({ ...partial, passed: false,
      gateError: String(error.stack ?? error), finishedAt: new Date().toISOString() }, null, 2) + '\n', { mode: 0o600 });
    console.error(`GATE FAILED: ${error.message}`); process.exitCode = 1;
  }
}
