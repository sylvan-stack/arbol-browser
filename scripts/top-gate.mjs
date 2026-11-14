// Complete explicit top-tier selection. No discovery, filters or native/page stand-ins.
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, readdir, readlink, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const selected = [
  ['receiptRace', 'tests/top/test_foundation_boundary.mjs'],
  ['ownershipBoundary', 'tests/top/test_foundation_concurrency.mjs'],
  ['preservationBoundary', 'tests/top/test_foundation_recovery.mjs'],
  ['transportBoundary', 'tests/top/test_foundation_recovery.mjs'],
  ['closeAcquisitionBoundary', 'tests/top/test_foundation_concurrency.mjs'],
  ['startupAcquisitionBoundary', 'tests/top/test_foundation_concurrency.mjs'],
];
const args = process.argv.slice(2), embedded = args.at(-1) === '--embedded';
if (embedded) args.pop();
assert.equal(args.length, 4, 'Usage: top-gate.mjs --candidate <package> --out <new-private-output>');
assert.equal(args[0], '--candidate'); assert.equal(args[2], '--out');
assert.ok(args[1] && args[3] && isAbsolute(args[1]) && isAbsolute(args[3]));
const candidate = await realpath(args[1]), output = resolve(args[3]);
assert.ok(!output.startsWith(repository) && output !== candidate && !output.startsWith(candidate + sep));
if (!embedded) {
  await mkdir(output, { mode: 0o700 }); // refuse reuse of prior evidence
  const home = join(output, 'runtime-home'); await mkdir(home, { mode: 0o700 });
  const result = spawnSync(join(candidate, 'runtime/Electron.app/Contents/MacOS/Electron'),
    [fileURLToPath(import.meta.url), ...args, '--embedded'], {
      cwd: repository, env: { HOME: home, PATH: '/usr/bin:/bin', ELECTRON_RUN_AS_NODE: '1', LANG: 'en_US.UTF-8' },
      stdio: 'inherit', timeout: 90000,
    });
  if (result.error) console.error(result.error.message);
  process.exitCode = result.status === 0 ? 0 : 1;
} else {
  try {
  // Electron's ASAR filesystem view must not replace physical archive bytes in
  // the package inventory. The embedded runtime exposes this documented flag.
  process.noAsar = true;
  const inventory = JSON.parse(await readFile(join(repository, 'test-tiers.json'), 'utf8'));
  assert.deepEqual(inventory.cases.map(item => [item.id, item.file]), selected);
  assert.ok(inventory.cases.every(item => item.tier === 'top' && item.status === 'retained'));
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
  const sourceFiles = [...new Set(['test-tiers.json', 'scripts/top-gate.mjs', 'tests/support/foundation.mjs', 'tests/support/foundation-deadlines.mjs', 'tests/support/foundation-startup-deadlines.mjs', ...selected.map(([, file]) => file)])].sort();
  const harness = Object.fromEntries(await Promise.all(sourceFiles.map(async file => [file, hash(await readFile(join(repository, file)))])));
  const result = { format: 1, candidate, output, build: metadata.component.build,
    startedAt: new Date().toISOString(), sourceDigest: metadata.sourceDigest,
    metadataDigest: hash(metadataBytes), payloadDigest: hash(JSON.stringify(payload)), payloadEntries: Object.keys(payload).length,
    harness, runtime: actualRuntime, selection: selected.map(([id]) => id), cases: [],
    unavailable: inventory.unavailable, qualification: 'foundation-top-tier-only; production admission remains blocked' };
  for (const file of [...new Set(selected.map(([, file]) => file))]) {
    const module = await import(pathToFileURL(join(repository, file)));
    assert.deepEqual(Object.keys(module).sort(), selected.filter(([, path]) => path === file).map(([id]) => id).sort(),
      'Missing/commented case or unselected exported case');
  }
  for (const [id, file] of selected) {
    const began = performance.now();
    try {
      const module = await import(pathToFileURL(join(repository, file)));
      const evidence = await module[id]({ candidate, output });
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
  result.passed = result.cases.length === selected.length && result.cases.every(item => item.status === 'passed');
  await writeFile(join(output, 'result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  process.exitCode = result.passed ? 0 : 1;
  } catch (error) {
    let partial = { format: 1, candidate, output, selection: selected.map(([id]) => id), cases: [] };
    try { partial = JSON.parse(await readFile(join(output, 'result.json'), 'utf8')); } catch { /* preflight selected no cases */ }
    await writeFile(join(output, 'result.json'), JSON.stringify({ ...partial, passed: false,
      gateError: String(error.stack ?? error), finishedAt: new Date().toISOString() }, null, 2) + '\n', { mode: 0o600 });
    console.error(`GATE FAILED: ${error.message}`); process.exitCode = 1;
  }
}
