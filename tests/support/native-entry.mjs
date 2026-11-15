// External trusted qualification entry; never packaged as the production host.
import { app } from 'electron';
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { readFile, writeFile, realpath, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const events = [];
let config, boundary, prepared, watchdog;
async function event(stage, values = {}) {
  const value = { stage, elapsedMs: performance.now(), ...values }; events.push(value);
  process.stdout.write(JSON.stringify(value) + '\n');
  if (config) await writeFile(join(config.output, 'entry-events.json'), JSON.stringify(events, null, 2) + '\n', { mode: 0o600 });
}
try {
  const path = process.env.ARBOL_BROWSER_QUALIFICATION_REQUEST;
  assert.ok(path && await realpath(path) === path);
  const stat = await lstat(path);
  assert.ok(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o600 && stat.nlink === 1 && stat.size <= 16384);
  config = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(config.format, 1); assert.ok(['boundary', 'callbacks'].includes(config.mode));
  assert.equal(await realpath(config.home), config.home); assert.equal(process.env.HOME, config.home);
  app.setPath('userData', join(config.home, 'app-data')); app.setPath('sessionData', join(config.home, 'session-data'));
  await event('entry', { pid: process.pid, appReady: app.isReady(), argv: process.argv, runtime: process.versions });
  const originalFS = createRequire(import.meta.url)('original-fs');
  const standardFS = createRequire(import.meta.url)('node:fs');
  const archive = join(config.bundle, 'Contents/Resources/browser/runtime/Electron.app/Contents/Resources/default_app.asar');
  const witness = {};
  for (const [name, fs] of [['standard', standardFS], ['physical', originalFS]]) {
    try { const stat = fs.lstatSync(archive); witness[name] = { file: stat.isFile(), directory: stat.isDirectory(), digest: createRequire(import.meta.url)('node:crypto').createHash('sha256').update(fs.readFileSync(archive)).digest('hex') }; }
    catch (error) { witness[name] = { error: String(error) }; }
  }
  await event('archive-witness', { noAsar: process.noAsar ?? false, witness });
  const bootstrapURL = pathToFileURL(join(config.bundle, 'Contents/Resources/browser/lib/runtime/bootstrap.js')).href;
  const bootstrap = await import(bootstrapURL);
  prepared = await bootstrap.prepareNativeBoundary(config.bundle);
  bootstrap.assertNativeBoundaryPreparation(prepared);
  let counterfeitRefused = false;
  try { bootstrap.assertNativeBoundaryPreparation({ ...prepared }); } catch { counterfeitRefused = true; }
  assert.ok(counterfeitRefused);
  await event('prepared', { snapshotDigest: prepared.trust.snapshotDigest, counterfeitRefused, appReady: app.isReady() });
  const owner = prepared.platform.tryLock(config.owner), build = prepared.platform.trySharedLock(config.build); assert.ok(owner && build);
  globalThis.qualificationOriginalLocks = { owner, build }; // strong originals, never finally-release
  await event('locks', { owner: owner.assertIdentity(), build: build.assertIdentity() });
  watchdog = await prepared.arm(owner, build); watchdog.assertArmed(prepared.trust);
  await event('armed', { descriptors: watchdog.custody.descriptors, startupDescriptor: watchdog.custody.startupDescriptor, appReady: app.isReady() });
  boundary = await bootstrap.installNativeBoundary(prepared, watchdog, {
    closeAdmission() { events.push({ stage: 'admission-closed' }); },
    invalidate() { events.push({ stage: 'authority-invalidated' }); },
    hidePages() { events.push({ stage: 'pages-hidden' }); },
  });
  assert.equal(boundary.pageAdmission, false);
  await event('installed', { status: boundary.native.assertIntegrity(), appReady: app.isReady() });
  if (config.mode === 'callbacks') throw new Error('callback_fixture_not_prepared'); // later booked leaf
  await new Promise(accept => setTimeout(accept, 350)); // external kernel/lock observation interval
  boundary.native.seal(); await event('sealed'); app.exit(0);
} catch (error) {
  await event('unavailable', { error: String(error.stack ?? error) });
  if (watchdog) watchdog.terminate(); // real native retained-custody loss path
  app.exit(70);
}
