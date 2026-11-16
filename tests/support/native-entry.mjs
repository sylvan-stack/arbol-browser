// External trusted qualification entry; never packaged as the production host.
import { app, BaseWindow, WebContentsView, webContents } from 'electron';
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { readFile, writeFile, realpath, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const events = [];
let config, boundary, prepared, watchdog, bootstrap, preparationBefore;
const resolverMode = 'resolver-control';
const poisonMode = 'install-poison';
let eventWrite = Promise.resolve();
async function event(stage, values = {}) {
  const value = { stage, elapsedMs: performance.now(), ...values }; events.push(value);
  process.stdout.write(JSON.stringify(value) + '\n');
  if (config) {
    const path = join(config.output, 'entry-events.json');
    const snapshot = JSON.stringify(events, null, 2) + '\n';
    eventWrite = eventWrite.then(() => writeFile(path, snapshot, { mode: 0o600 }));
    await eventWrite;
  }
}
function admissionObservation() {
  const report = process.report.getReport();
  assert.ok(Array.isArray(report.sharedObjects) && report.sharedObjects.every(path => typeof path === 'string'));
  return { nativeImages: report.sharedObjects.filter(path => /\/(?:platform|ownership)\.node$/.test(path)),
    windows: BaseWindow.getAllWindows().map(value => value.id), webContents: webContents.getAllWebContents().map(value => value.id), appReady: app.isReady() };
}
async function waitForFixtureMarker(name) {
  const deadline = performance.now() + 15000;
  for (;;) {
    try { assert.equal(await readFile(join(config.output, name), 'utf8'), 'ready\n'); return; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    assert.ok(performance.now() < deadline, 'External fixture marker did not arrive');
    await new Promise(accept => setTimeout(accept, 25));
  }
}
function observeCall(call) {
  try { return { returned: call() }; }
  catch (error) { return { error: String(error.message ?? error) }; }
}
async function observeInstallPoison(bootstrapURL) {
  const features = await import(new URL('../native/features.js', bootstrapURL));
  features.configureNativeFeatures();
  features.assertNativeFeatures();
  watchdog.assertArmed(prepared.trust);
  assert.ok(config.callback && await realpath(config.callback) === config.callback);
  const require = createRequire(import.meta.url);
  const addonPath = join(config.bundle, 'Contents/Resources/browser/native/ownership.node');
  const addon = require(addonPath), bridge = require(config.callback);
  const expected = JSON.parse(addon.getABI());
  assert.deepEqual(expected, prepared.trust.manifest.nativeABI);
  const keys = Object.keys(expected.methods), audit = () => JSON.parse(bridge.auditMethods(keys));
  assert.equal(JSON.parse(addon.status()).phase, 'new');
  const originals = audit();
  const preCommit = config.poisonScenario === 'pre-commit-poison';
  const argument = preCommit ? { ...expected, abi: expected.abi + 1 } : expected;
  let install, status, returnedMethods, journal, poisonArmed;
  if (!preCommit) assert.equal(JSON.parse(bridge.startResolverControl(addonPath)).active, true);
  try {
    if (!preCommit) {
      assert.equal(JSON.parse(bridge.armInstallPoison(config.poisonScenario)).armed, true);
      poisonArmed = true;
    }
    install = observeCall(() => addon.install(JSON.stringify(argument)));
    status = JSON.parse(addon.status());
    returnedMethods = audit();
  } finally {
    if (!preCommit) {
      bridge.stopResolverControl();
      if (poisonArmed) journal = JSON.parse(bridge.finishInstallPoison());
    }
  }
  const methods = audit();
  const retry = observeCall(() => addon.install(JSON.stringify(expected)));
  const result = { scenario: config.poisonScenario, install, status, originals, returnedMethods, methods, journal,
    retry, retryStatus: JSON.parse(addon.status()), retryMethods: audit(), admission: admissionObservation() };
  writeFileSync(join(config.output, 'install-poison.json'), JSON.stringify(result) + '\n', { mode: 0o600, flag: 'wx' });
  watchdog.terminate();
}
try {
  const path = process.env.ARBOL_BROWSER_QUALIFICATION_REQUEST;
  assert.ok(path && await realpath(path) === path);
  const stat = await lstat(path);
  assert.ok(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o600 && stat.nlink === 1 && stat.size <= 16384);
  config = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(config.format, 1); assert.ok(['boundary', 'callbacks', 'frozen-trust', 'provider-mismatch', resolverMode, poisonMode].includes(config.mode));
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
  const otherBootstrap = await import(bootstrapURL + '?qualification-instance');
  assert.notEqual(otherBootstrap, bootstrap);
  assert.throws(() => otherBootstrap.assertNativeBoundaryPreparation(prepared));
  await assert.rejects(() => bootstrap.prepareNativeBoundary(config.bundle));
  bootstrap.assertNativeBoundaryPreparation(prepared);
  await event('prepared', { snapshotDigest: prepared.trust.snapshotDigest, counterfeitRefused,
    crossModuleRefused: true, repeatPreparationRefused: true, appReady: app.isReady() });

  if (config.mode === 'frozen-trust') {
    const manifestModule = await import(new URL('../native/manifest.js', bootstrapURL));
    manifestModule.assertCandidateTrust(prepared.trust);
    assert.ok(Object.isFrozen(prepared.trust.manifest) && Object.isFrozen(prepared.trust.manifest.files));
    await event('frozen-trust-ready', { admission: admissionObservation() });
    await waitForFixtureMarker('drift-ready');
    assert.throws(() => manifestModule.assertCandidateTrust(prepared.trust), /native_candidate_unavailable/);
    await event('frozen-trust-drift-refused', { admission: admissionObservation() });
    await waitForFixtureMarker('restore-ready');
    assert.throws(() => manifestModule.assertCandidateTrust(prepared.trust), /native_candidate_unavailable/);
    assert.throws(() => manifestModule.verifyNativeCandidate(config.bundle), /native_candidate_unavailable/);
    await event('frozen-trust-restored-refused', { admission: admissionObservation() });
    app.exit(0);
    await new Promise(() => {});
  }

  const owner = prepared.platform.tryLock(config.owner), build = prepared.platform.trySharedLock(config.build); assert.ok(owner && build);
  globalThis.qualificationOriginalLocks = { owner, build }; // strong originals, never finally-release
  await event('locks', { owner: owner.assertIdentity(), build: build.assertIdentity() });
  watchdog = await prepared.arm(owner, build); watchdog.assertArmed(prepared.trust);
  await event('armed', { descriptors: watchdog.custody.descriptors, startupDescriptor: watchdog.custody.startupDescriptor, appReady: app.isReady() });
  if (config.mode === poisonMode) await observeInstallPoison(bootstrapURL);
  let resolver;
  if (config.mode === resolverMode) {
    assert.ok(config.callback && await realpath(config.callback) === config.callback);
    const require = createRequire(import.meta.url);
    const addonPath = join(config.bundle, 'Contents/Resources/browser/native/ownership.node');
    const addon = require(addonPath), bridge = require(config.callback);
    const inventory = JSON.parse(addon.getABI());
    assert.deepEqual(inventory, prepared.trust.manifest.nativeABI);
    const keys = Object.keys(inventory.methods);
    const dispatch = JSON.parse(bridge.resolverDispatch());
    const originals = JSON.parse(bridge.auditMethods(keys));
    for (const [key, expected] of Object.entries(inventory.methods)) {
      const entry = originals[key];
      if (expected === '<absent>') assert.equal(entry, expected);
      else {
        assert.equal(entry.encoding, expected.encoding);
        assert.equal(entry.image.split('/').at(-1), expected.provider);
      }
    }
    await event('resolver-dispatch', { dispatch, admission: admissionObservation() });
    resolver = { addonPath, addon, bridge, inventory, keys, originals };
  }
  const effects = {
    closeAdmission() {
      if (config.mode === 'provider-mismatch') {
        const addonPath = join(config.bundle, 'Contents/Resources/browser/native/ownership.node');
        const admission = admissionObservation();
        assert.ok(admission.nativeImages.includes(addonPath), 'Preflight did not reach the actual ownership addon');
        const addon = createRequire(import.meta.url)(addonPath);
        const actual = JSON.parse(addon.getABI()).methods[config.providerMethod];
        const expected = prepared.trust.manifest.nativeABI.methods[config.providerMethod];
        const observation = { admission, actual, expected, status: JSON.parse(addon.status()) };
        writeFileSync(join(config.output, 'provider-refusal.json'), JSON.stringify(observation) + '\n',
          { mode: 0o600, flag: 'wx' });
      }
      void event('admission-closed');
    },
    invalidate() { void event('authority-invalidated'); },
    hidePages() { void event('pages-hidden'); },
  };
  if (resolver) {
    const { addonPath, addon, bridge, inventory, keys, originals } = resolver;
    let control, afterGetABI, afterInstall;
    try {
      assert.equal(JSON.parse(bridge.startResolverControl(addonPath)).active, true);
      control = true;
      assert.deepEqual(JSON.parse(addon.getABI()), inventory);
      assert.deepEqual(JSON.parse(bridge.auditMethods(keys)), originals);
      afterGetABI = JSON.parse(bridge.resolverControlObservation());
      assert.ok(afterGetABI.appKit > 0 && afterGetABI.electron > 0, 'No matching synchronous provider callback');
      boundary = await bootstrap.installNativeBoundary(prepared, watchdog, effects);
    } finally {
      if (control) afterInstall = JSON.parse(bridge.stopResolverControl());
    }
    assert.ok(afterInstall.appKit > afterGetABI.appKit && afterInstall.electron > afterGetABI.electron);
    const installed = JSON.parse(bridge.auditMethods(keys));
    for (const [key, original] of Object.entries(originals)) {
      if (original === '<absent>') assert.equal(installed[key], original);
      else {
        assert.equal(installed[key].encoding, original.encoding);
        assert.equal(installed[key].image, addonPath);
        assert.notEqual(installed[key].implementation, original.implementation);
      }
    }
    await event('resolver-control', { afterGetABI, afterInstall, originals, installed });
  } else boundary = await bootstrap.installNativeBoundary(prepared, watchdog, effects);
  assert.equal(boundary.pageAdmission, false);
  await event('installed', { status: boundary.native.assertIntegrity(), admission: admissionObservation(), appReady: app.isReady() });
  if (config.mode === 'callbacks') {
    assert.ok(config.callback && await realpath(config.callback) === config.callback);
    const bridge = createRequire(import.meta.url)(config.callback);
    assert.deepEqual(Object.getOwnPropertyNames(bridge).sort(), ['armInstallPoison', 'auditMethods', 'block', 'capture', 'descriptor', 'finishInstallPoison', 'invoke',
      'releaseClients', 'resolverControlObservation', 'resolverDispatch', 'startResolverControl', 'state', 'stopResolverControl']);
    await event('callback-loaded', { path: config.callback,
      capsule: JSON.parse(bridge.descriptor(watchdog.custody.startupDescriptor)),
      owner: JSON.parse(bridge.descriptor(watchdog.custody.descriptors[0])),
      build: JSON.parse(bridge.descriptor(watchdog.custody.descriptors[1])) });
    // This fixture owns the exit request after observing retirement. Keep the
    // usual last-window notification, but do not let it race the final record.
    let allWindowsClosed = 0;
    app.on('window-all-closed', () => { allWindowsClosed++; });
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
      const html = `<!doctype html>
        <button id="button" aria-label="Native fixture button" onclick="this.textContent=Number(this.textContent)+1">0</button>
        <input id="field" aria-label="Native fixture field" value="abc">
        <script>
          globalThis.events = [];
          for (const type of ['input', 'compositionstart', 'compositionupdate', 'compositionend']) {
            field.addEventListener(type, event => events.push({
              type: event.type, trusted: event.isTrusted, data: event.data, inputType: event.inputType,
            }));
          }
          button.addEventListener('click', event => events.push({ type: event.type, trusted: event.isTrusted }));
          field.focus();
        </script>`;
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

      const fieldState = () => view.webContents.executeJavaScript(
        '({text:field.value, selection:[field.selectionStart,field.selectionEnd], events:[...events]})');
      for (const routes of [['selectAll'], ['delete'], ['directDelete'], ['mark', 'unmark']]) {
        await view.webContents.executeJavaScript("field.value='edit'; field.focus(); field.setSelectionRange(4,4); events.length=0");
        for (const route of routes) {
          const before = await fieldState();
          let invocation;
          try { invocation = JSON.parse(bridge.invoke(cached.token, route)); }
          catch (error) { invocation = { route, unavailable: String(error.message ?? error) }; }
          await new Promise(accept => setTimeout(accept, 150));
          await event('callback-edit-observation', { route, before, invocation, after: await fieldState() });
        }
      }
      // A short normal callback verifies synchronous execution without
      // exceeding the watchdog heartbeat deadline or injecting a fault.
      const began = performance.now();
      const returned = JSON.parse(bridge.block(40));
      const elapsedMs = performance.now() - began;
      watchdog.assertArmed(prepared.trust);
      assert.equal(returned.returnedAfterMs, 40);
      assert.ok(elapsedMs >= 40);
      await event('callback-bounded-main-thread-observation', { returned, observedMs: elapsedMs });
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
      await event('callback-window-closed', { allWindowsClosed, remainingWindows: BaseWindow.getAllWindows().length });
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
