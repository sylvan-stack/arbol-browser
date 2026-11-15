// External trusted qualification entry; never packaged as the production host.
import { app, BaseWindow, WebContentsView, webContents } from 'electron';
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { readFile, writeFile, realpath, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const events = [];
let config, boundary, prepared, watchdog, bootstrap, preparationBefore;
async function event(stage, values = {}) {
  const value = { stage, elapsedMs: performance.now(), ...values }; events.push(value);
  process.stdout.write(JSON.stringify(value) + '\n');
  if (config) await writeFile(join(config.output, 'entry-events.json'), JSON.stringify(events, null, 2) + '\n', { mode: 0o600 });
}
function admissionObservation() {
  const report = process.report.getReport();
  assert.ok(Array.isArray(report.sharedObjects) && report.sharedObjects.every(path => typeof path === 'string'));
  return { nativeImages: report.sharedObjects.filter(path => /\/(?:platform|ownership)\.node$/.test(path)),
    windows: BaseWindow.getAllWindows().map(value => value.id), webContents: webContents.getAllWebContents().map(value => value.id), appReady: app.isReady() };
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
  bootstrap = await import(bootstrapURL);
  preparationBefore = admissionObservation();
  await event('preparation-observation', { before: preparationBefore });
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
    closeAdmission() { void event('admission-closed'); },
    invalidate() { void event('authority-invalidated'); },
    hidePages() { void event('pages-hidden'); },
  });
  assert.equal(boundary.pageAdmission, false);
  await event('installed', { status: boundary.native.assertIntegrity(), admission: admissionObservation(), appReady: app.isReady() });
  if (config.mode === 'callbacks') {
    assert.ok(config.callback && await realpath(config.callback) === config.callback);
    const bridge = createRequire(import.meta.url)(config.callback);
    assert.deepEqual(Object.getOwnPropertyNames(bridge).sort(), ['block', 'capture', 'descriptor', 'invoke', 'releaseClients', 'state']);
    await event('callback-loaded', { path: config.callback,
      capsule: JSON.parse(bridge.descriptor(watchdog.custody.startupDescriptor)),
      owner: JSON.parse(bridge.descriptor(watchdog.custody.descriptors[0])),
      build: JSON.parse(bridge.descriptor(watchdog.custody.descriptors[1])) });
    // Resolve this entry before ready; callback setup then uses the real app event.
    app.whenReady().then(async () => {
      void event('callback-ready');
      app.setAccessibilitySupportEnabled(true);
      void event('callback-accessibility-enabled');
      let window = new BaseWindow({ width: 640, height: 360, show: false });
      void event('callback-window-created');
      let view = new WebContentsView({ webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false } });
      void event('callback-view-created');
      const key = value => ({ id: value.id, nonce: value.nonce, webContentsId: value.webContentsId, revision: value.revision });
      let binding = boundary.native.ownership.bind(window.getNativeWindowHandle(), view.webContents.id, () => window.contentView.addChildView(view));
      void event('callback-bound', { binding });
      view.setBounds({ x: 0, y: 0, width: 640, height: 360 });
      binding = boundary.native.ownership.mark(key(binding), false);
      void event('callback-user-enabled', { binding });
      const html = '<!doctype html><button id="button" aria-label="Native fixture button" onclick="this.textContent=Number(this.textContent)+1">0</button><input id="field" aria-label="Native fixture field" value="abc"><script>globalThis.events=[];field.addEventListener("input",e=>events.push({type:e.type,trusted:e.isTrusted}));button.addEventListener("click",e=>events.push({type:e.type,trusted:e.isTrusted}));field.focus();</script>';
      await view.webContents.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
      window.showInactive(); view.webContents.focus();
      await new Promise(accept => setTimeout(accept, 350));
      const cached = JSON.parse(bridge.capture(window.getNativeWindowHandle()));
      await event('callback-view', { binding, cached, state: JSON.parse(bridge.state(cached.token)), appReady: app.isReady() });
      const focus = JSON.parse(bridge.invoke(cached.token, 'focus'));
      await event('callback-focus-observation', { focus, state: JSON.parse(bridge.state(cached.token)) });
      const before = await view.webContents.executeJavaScript('({text:field.value,events:[...events]})');
      const invocation = JSON.parse(bridge.invoke(cached.token, 'text'));
      await new Promise(accept => setTimeout(accept, 150));
      const after = await view.webContents.executeJavaScript('({text:field.value,events:[...events]})');
      await event('callback-positive-observation', { before, invocation, after, state: JSON.parse(bridge.state(cached.token)) });
      const pressBefore = await view.webContents.executeJavaScript('({button:button.textContent,events:[...events]})');
      const press = JSON.parse(bridge.invoke(cached.token, 'press'));
      await new Promise(accept => setTimeout(accept, 150));
      const pressAfter = await view.webContents.executeJavaScript('({button:button.textContent,events:[...events]})');
      await event('callback-ax-positive-observation', { before: pressBefore, invocation: press, after: pressAfter });
      const resigned = JSON.parse(bridge.invoke(cached.token, 'resignFocus'));
      await event('callback-focus-released', { resigned, state: JSON.parse(bridge.state(cached.token)) });
      if (!resigned.returned) throw new Error('fixture_native_focus_release_unavailable');
      let originalContents = view.webContents;
      const retired = await boundary.retire(key(binding), window.contentView, view);
      await event('callback-retired-observation', { retired, destroyed: originalContents.isDestroyed(), state: JSON.parse(bridge.state(cached.token)) });
      view = null; originalContents = null;
      await new Promise(accept => setTimeout(accept, 100));
      await event('callback-js-references-released', { state: JSON.parse(bridge.state(cached.token)) });
      const released = JSON.parse(bridge.releaseClients(cached.token));
      await event('callback-ax-clients-released', { released, state: JSON.parse(bridge.state(cached.token)) });
      const weakDeadline = performance.now() + 2000;
      do {
        await new Promise(accept => setTimeout(accept, 250));
        const state = JSON.parse(bridge.state(cached.token));
        await event('callback-weak-observation', { state });
        if (!state.weakRootAlive && !state.weakWidgetAlive) break;
      } while (performance.now() < weakDeadline);
      await event('callback-window-close-requested');
      window.close(); window = null;
      await event('callback-window-closed');
      boundary.native.seal(); await event('sealed'); app.exit(0);
    }).catch(async error => {
      await event('callback-unavailable', { error: String(error.stack ?? error) });
      watchdog.terminate();
    });
  } else {
  await new Promise(accept => setTimeout(accept, 350)); // external kernel/lock observation interval
  boundary.native.seal(); await event('sealed'); app.exit(0);
  }
 } catch (error) {
  if (!prepared && config) {
    const locks = {};
    for (const name of ['owner', 'build']) {
      try { const stat = await lstat(config[name]); locks[name] = { exists: true, device: String(stat.dev), inode: String(stat.ino) }; }
      catch (failure) { locks[name] = failure.code === 'ENOENT' ? { exists: false } : { unavailable: String(failure) }; }
    }
    let retry;
    if (config.trustProbe && bootstrap) {
      try { await bootstrap.prepareNativeBoundary(config.bundle); retry = { refused: false }; }
      catch (failure) { retry = { refused: true, error: String(failure) }; }
    }
    let after; try { after = admissionObservation(); } catch (failure) { after = { unavailable: String(failure) }; }
    await event('trust-refusal-observation', { before: preparationBefore, after, locks, retry });
  }
  await event('unavailable' , { error: String(error.stack ?? error) });
  if (watchdog) watchdog.terminate(); // real native retained-custody loss path
  app.exit(70);
}
