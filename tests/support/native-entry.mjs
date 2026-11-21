// External trusted qualification entry; never packaged as the production host.
import { app, BaseWindow, WebContentsView, webContents } from 'electron';
import { ChildProcess } from 'node:child_process';
import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { appendFileSync, closeSync, openSync, writeFileSync } from 'node:fs';
import { readFile, writeFile, realpath, lstat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const events = [];
let config, boundary, prepared, watchdog, bootstrap, preparationBefore;
const resolverMode = 'resolver-control';
const poisonMode = 'install-poison';
const bindingMode = 'binding-lifetime';
const cachedRoutesMode = 'cached-routes';
const concurrentResponderMode = 'concurrent-responder';
const retirementMode = 'retirement';
const startupCustodyMode = 'startup-custody';
const failureCustodyMode = 'failure-custody';
const monitorCustodyMode = 'monitor-loss';
const helperExitMode = 'helper-exit';
const customAXMode = 'custom-ax';
const viewOptions = { webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false } };
const bindingKey = ({ id, nonce, webContentsId, revision }) => ({ id, nonce, webContentsId, revision });
let eventWrite = Promise.resolve();
let retirementEffect;
let failureEffect, failureProtocol;
let cachedRouteObservation;
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

function armWithWatchdogWitness(owner, build) {
  const helper = join(config.bundle, 'Contents/Resources/browser/native/watchdog');
  const spawn = ChildProcess.prototype.spawn;
  const delayed = config.startupScenario === 'late-readiness';
  const path = join(config.output, 'readiness.jsonl');
  const waitCell = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
  let witnessed = false;
  const record = (stage, values) => appendFileSync(path, JSON.stringify({ stage, ...values }) + '\n', { mode: 0o600 });
  ChildProcess.prototype.spawn = function observeSpawn(options) {
    if (options.file !== helper) return spawn.call(this, options);
    assert.equal(witnessed, false);
    assert.deepEqual(options.args, [helper, '--watchdog']);
    assert.equal(options.detached, false);
    const spawnStarted = performance.now();
    const result = spawn.call(this, options);
    const spawnReturned = performance.now();
    assert.ok(this.pid > 1 && this.stdout);
    witnessed = true;
    if ([failureCustodyMode, monitorCustodyMode, helperExitMode].includes(config.mode)) {
      captureFailureStreams(this);
      return result;
    }
    const primary = this.pid;
    record('spawn', { primary, executable: helper, spawnStarted, spawnReturned, delayed });
    // The real client installs its data listener after spawn returns. Observe
    // the actual first chunk before that listener runs, preserving its bytes.
    this.stdout.prependOnceListener('data', chunk => {
      const received = performance.now();
      assert.ok(Buffer.isBuffer(chunk));
      assert.equal(chunk.toString('ascii'), `R 1 ${process.pid}\n`);
      record('received', { primary, received, frame: chunk.toString('ascii') });
      if (delayed) {
        // The packaged startup clock was started before spawn. Waiting past
        // this upper bound makes delivery late even if the timer cannot run.
        const releaseAt = spawnReturned + 1050;
        while (performance.now() < releaseAt) Atomics.wait(waitCell, 0, 0, releaseAt - performance.now());
      }
      record('deliver', { primary, delivered: performance.now(), admission: admissionObservation() });
    });
    return result;
  };
  try {
    const ready = prepared.arm(owner, build);
    assert.ok(witnessed, 'Canonical arm did not spawn the signed watchdog synchronously');
    return ready;
  } finally { ChildProcess.prototype.spawn = spawn; }
}

function captureFailureStreams(child) {
  const bridge = createRequire(import.meta.url)(config.callback);
  const path = join(config.output, 'failure.jsonl');
  const clock = () => JSON.parse(bridge.monotonicNanos()).nanos;
  const log = (stage, values = {}) => appendFileSync(path, JSON.stringify({ stage, nanos: clock(), ...values }) + '\n', { mode: 0o600 });
  const protocol = { child, log, ack: null, write: null, withhold: false, freezeWrites: false, afterFatalAck: null };
  failureProtocol = protocol;
  log('spawn', { primary: child.pid });
  const write = child.stdin.write.bind(child.stdin);
  child.stdin.write = (chunk, ...options) => {
    const frame = chunk.toString();
    if (protocol.freezeWrites) {
      assert.match(frame, /^[HF] [1-9][0-9]*\n$/);
      log('withheld-host-frame', { frame });
      return true;
    }
    protocol.write = frame;
    log('host-frame', { frame });
    return write(chunk, ...options);
  };
  const emit = child.stdout.emit.bind(child.stdout);
  let buffer = '';
  child.stdout.emit = (name, chunk, ...args) => {
    if (name === 'data') {
      buffer += chunk.toString('ascii');
      assert.ok(buffer.length <= 4096);
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        const frame = line + '\n';
        log(protocol.withhold ? 'withheld-frame' : 'primary-frame', { frame });
        if (/^A [1-9][0-9]*\n$/.test(frame)) protocol.ack = frame;
        if (protocol.afterFatalAck?.frame === frame) protocol.afterFatalAck.run();
      }
      if (protocol.withhold) return true;
    }
    return emit(name, chunk, ...args);
  };
}

async function observeHelperExit() {
  const window = new BaseWindow({ width: 320, height: 200, show: false });
  const view = new WebContentsView(viewOptions), contents = view.webContents;
  const ownership = boundary.native.ownership;
  const binding = ownership.bind(window.getNativeWindowHandle(), contents.id, () => window.contentView.addChildView(view));
  await loadFixturePage(view, 'Supported helper exit');
  const renderer = contents.mainFrame.osProcessId;
  await event('helper-exit-observer-waiting', { renderer, binding });
  await waitForFixtureMarker('helper-exit-observer-ready');
  const retired = ownership.retire(bindingKey(binding));
  window.contentView.removeChildView(view);
  const destroyed = new Promise(accept => contents.once('destroyed', accept));
  contents.close({ waitForBeforeUnload: false });
  await destroyed;
  await event('helper-exit-requested', { renderer, retired, destroyed: contents.isDestroyed(), mechanism: 'WebContents.close without beforeunload' });
  await waitForFixtureMarker('helper-exit-observed');
  const previous = failureProtocol.ack;
  await waitForObservation(() => failureProtocol.ack, value => value && value !== previous, 'No continued real heartbeat acknowledgement after independent exit observation');
  watchdog.assertArmed(prepared.trust);
  await event('helper-exit-live', { acknowledgement: failureProtocol.ack, status: boundary.native.assertIntegrity() });
  await waitForFixtureMarker('helper-exit-release');
  watchdog.terminate();
}

async function observeFailure(bridge, addon) {
  const monitor = config.mode === monitorCustodyMode;
  const scenario = monitor ? config.monitorScenario : config.failureScenario;
  const protocol = failureProtocol;
  const { child, log } = protocol;
  const window = new BaseWindow({ width: 320, height: 200, show: false });
  const view = new WebContentsView(viewOptions), contents = view.webContents;
  const binding = boundary.native.ownership.bind(window.getNativeWindowHandle(), contents.id, () => { window.contentView.addChildView(view); });
  view.setBounds({ x: 0, y: 0, width: 320, height: 200 });
  await loadFixturePage(view, 'Failure custody');
  if (scenario === 'integrity-refused' || scenario === 'cleanup-blocked') window.showInactive();
  const renderer = contents.mainFrame.osProcessId;
  assert.ok(renderer > 1);
  let admission = true, authority = contents.id;
  const durationMs = 6500;
  const block = place => {
    log('native-block-enter', { place, durationMs });
    bridge.block(durationMs);
    log('native-block-return', { place });
    watchdog.terminate();
  };
  failureEffect = name => {
    if (name === 'admission-closed') admission = false;
    if (name === 'authority-invalidated') authority = null;
    if (name === 'pages-hidden') window.hide();
    log(name, { admission, authority, closed: boundary.fatal.closed, reason: boundary.fatal.reason, fatal: watchdog.fatal,
      native: JSON.parse(addon.status()), visible: window.isVisible() });
    if (name === 'pages-hidden' && scenario === 'cleanup-blocked') block('cleanup');
  };
  await event(monitor ? 'monitor-observer-waiting' : 'failure-observer-waiting', { scenario, renderer, binding });
  await waitForFixtureMarker(monitor ? 'monitor-observer-ready' : 'failure-observer-ready');
  const previousAck = protocol.ack;
  await waitForObservation(() => protocol.ack, ack => ack && ack !== previousAck, 'No fresh signed watchdog acknowledgement');
  watchdog.assertArmed(prepared.trust);
  if (monitor) {
    if (scenario !== 'both-lost') {
      await waitForObservation(() => protocol.ack, ack => ack && protocol.write === ack.replace(/^A /, 'H '),
        'The last real host write had no matching acknowledgement');
      assert.equal(protocol.write, protocol.ack.replace(/^A /, 'H '));
      protocol.freezeWrites = true;
    }
    log('monitor-armed', { scenario, renderer, acknowledgement: protocol.ack, lastWrite: protocol.write,
      writesFenced: protocol.freezeWrites, native: JSON.parse(addon.status()) });
    await writeFile(join(config.output, 'monitor-trigger'), 'ready\n', { mode: 0o600, flag: 'wx' });
    return;
  }
  log('fault', { scenario, renderer, acknowledgement: protocol.ack, native: JSON.parse(addon.status()), visible: window.isVisible() });
  if (scenario === 'heartbeat-silence') block('running-main');
  else if (scenario === 'ack-silence') protocol.withhold = true;
  else if (scenario === 'eof') child.stdin.end(() => {
    log('stdin-ended');
    block('after-stdin-eof');
  });
  else if (scenario === 'malformed' || scenario === 'out-of-order') {
    const frame = scenario === 'malformed' ? 'H ?\n' : protocol.ack.replace(/^A /, 'H ');
    child.stdin.write(frame, 'ascii', error => {
      assert.ifError(error);
      log('fault-write', { frame });
      block('after-fault-write');
    });
  } else if (scenario === 'integrity-refused') {
    app.commandLine.appendSwitch('site-per-process', 'fixture-invalid');
    log('integrity-check', { value: app.commandLine.getSwitchValue('site-per-process') });
    boundary.native.assertIntegrity();
    log('integrity-return');
  } else if (scenario === 'cleanup-blocked') {
    boundary.fatal.fail('native_retirement_unavailable');
  } else if (scenario === 'exit-blocked') {
    app.once('before-quit', () => block('before-quit'));
    app.once('will-quit', () => log('will-quit'));
    log('exit-request', { sealed: boundary.native.seal() });
    app.quit();
    log('exit-return');
  } else {
    assert.equal(scenario, 'fatal-shortening');
    watchdog.quarantine();
    assert.match(protocol.write, /^F [1-9][0-9]*\n$/);
    const sequence = BigInt(protocol.write.slice(2)) + 1n;
    protocol.afterFatalAck = { frame: `A ${sequence}\n`, run: () => block('after-post-fatal-heartbeat') };
    child.stdin.write(`H ${sequence}\n`, 'ascii');
  }
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
async function waitForObservation(read, matches, message, timeoutMs = 2500) {
  const deadline = performance.now() + timeoutMs;
  for (;;) {
    const observed = await read();
    if (matches(observed)) return observed;
    assert.ok(performance.now() < deadline, message);
    await new Promise(accept => setTimeout(accept, 50));
  }
}
function requireFixtureFocus(window) {
  assert.ok(window.isFocused(), 'The selected Browser test window lost keyboard focus');
}
async function selectFixtureWindow(window, contents) {
  if (!window.isVisible()) {
    const label = [config.mode, config.bindingScenario ?? config.retirementScenario].filter(Boolean).join(' / ');
    window.setTitle(`Arbol Browser test · Click title bar · ${label}`);
    window.showInactive();
    await event('manual-focus-required', { label });
    await waitForObservation(() => window.isFocused(), Boolean,
      'Select the Browser test window by clicking its title bar', 20000);
    window.setTitle(`Arbol Browser test · ${label}`);
    await event('manual-focus-selected', { label });
  }
  // Select the local responder only after the operator made this window key.
  requireFixtureFocus(window);
  contents.focus();
}
async function loadFixturePage(view, label) {
  const html = `<!doctype html><button id="button" aria-label="${label}">0</button>
    <input id="field" aria-label="Native fixture field" value="abc">
    <script>
      globalThis.clicks = [];
      button.addEventListener('click', event => {
        button.textContent = Number(button.textContent) + 1;
        clicks.push(event.isTrusted);
      });
      field.focus();
    </script>`;
  await view.webContents.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
}
async function observeBindingLifetime(bridge, addon) {
  app.setAccessibilitySupportEnabled(true);
  app.on('window-all-closed', () => {});
  const window = new BaseWindow({ width: 640, height: 360, show: false });
  const handle = window.getNativeWindowHandle();
  const native = boundary.native.ownership;
  const roots = () => JSON.parse(bridge.windowPages(handle));
  const status = () => JSON.parse(addon.status());
  const rawInfo = key => addon.bindingInfo(JSON.stringify(key));
  const attach = view => window.contentView.addChildView(view);
  const bind = view => native.bind(handle, view.webContents.id, () => attach(view));
  const bounds = view => view.setBounds({ x: 0, y: 0, width: 640, height: 360 });
  const state = token => JSON.parse(bridge.state(token));
  const press = token => {
    requireFixtureFocus(window);
    return JSON.parse(bridge.invoke(token, 'press'));
  };
  const readPage = view => view.webContents.executeJavaScript('({count:Number(button.textContent),clicks:[...clicks]})');
  const captureClient = async (stage, contents) => {
    let client;
    try {
      await new Promise(accept => setTimeout(accept, 350));
      return await waitForObservation(() => {
        try { client = JSON.parse(bridge.capture(handle)); } catch (error) {
          if (error.message !== 'fixture_requires_one_actual_widget') throw error;
          return undefined;
        }
        if (!client.button) bridge.releaseClients(client.token);
        return client;
      }, value => value?.button, `Cached accessibility client unavailable for ${stage}`);
    } catch (error) {
      await event('binding-ax-unavailable', { stageName: stage, client, state: client && state(client.token), roots: roots(),
        enabled: app.isAccessibilitySupportEnabled(), focused: contents.isFocused(), bounds: window.getBounds(), status: status() });
      throw error;
    }
  };
  const scenario = config.bindingScenario;
  const before = status();
  await event('binding-started', { scenario });
  let observation;
  let view = new WebContentsView(viewOptions);
  if (scenario === 'ambiguous-creation' || scenario === 'reentrant-creation') {
    const extra = new WebContentsView(viewOptions);
    const empty = roots();
    assert.equal(addon.beginBinding(handle, view.webContents.id), undefined);
    attach(view);
    if (scenario === 'ambiguous-creation') attach(extra);
    const attached = roots(), during = status();
    const refusal = observeCall(() => scenario === 'ambiguous-creation'
      ? addon.finishBinding() : addon.beginBinding(handle, extra.webContents.id));
    observation = { empty, attached, during, refusal, contents: [view.webContents.id, extra.webContents.id],
      retry: observeCall(() => addon.finishBinding()) };
  } else {
    const created = bind(view);
    const initial = JSON.parse(rawInfo(bindingKey(created)));
    const attached = roots();
    if (scenario === 'retired-replacement') {
      bounds(view);
      const user = native.mark(bindingKey(created), false);
      const restored = native.restore(bindingKey(user));
      await loadFixturePage(view, 'Original fixture button');
      await selectFixtureWindow(window, view.webContents);
      await event('binding-original-loaded', { created });
      const oldClient = await captureClient('original', view.webContents);
      const oldPress = press(oldClient.token);
      const oldEffect = await waitForObservation(() => readPage(view), value => value.count === 1, 'Original native click did not arrive');
      await event('binding-original-clicked', { oldClient, oldPress, oldEffect });
      requireFixtureFocus(window);
      const resigned = JSON.parse(bridge.invoke(oldClient.token, 'resignFocus'));
      assert.equal(resigned.returned, true);
      const blocked = native.mark(bindingKey(restored), true);
      const restoreBlocked = native.restore(bindingKey(blocked));
      const blockedPress = press(oldClient.token);
      const blockedEffect = await readPage(view);
      const retired = native.retire(bindingKey(restoreBlocked));
      const retiredState = state(oldClient.token);
      const retiredPress = press(oldClient.token);
      const retiredEffect = await readPage(view);
      await event('binding-tombstoned', { retired, retiredState, retiredPress, retiredEffect });
      const newView = new WebContentsView(viewOptions);
      window.contentView.removeChildView(view);
      const detached = roots();
      let contents = view.webContents;
      let destroyEvent = false;
      contents.once('destroyed', () => { destroyEvent = true; });
      contents.close({ waitForBeforeUnload: false });
      await waitForObservation(() => destroyEvent && contents.isDestroyed(), Boolean, 'Original WebContents did not destroy');
      view = null; contents = null;
      const gone = await waitForObservation(() => state(oldClient.token), value => !value.weakRootAlive && !value.weakWidgetAlive,
        'Original native weak references did not clear');
      await event('binding-original-destroyed', { destroyEvent, detached, gone });
      const replacement = bind(newView);
      const replacementBlocked = JSON.parse(rawInfo(bindingKey(replacement)));
      bounds(newView);
      const replacementUser = native.mark(bindingKey(replacement), false);
      await loadFixturePage(newView, 'Replacement fixture button');
      await selectFixtureWindow(window, newView.webContents);
      await event('binding-replacement-loaded', { replacement });
      const newClient = await captureClient('replacement', newView.webContents);
      const newRoots = roots(), newBefore = await readPage(newView);
      const oldStateAfterReplacement = state(oldClient.token), newState = state(newClient.token);
      const stalePress = press(oldClient.token);
      const afterStalePress = await readPage(newView);
      const newPress = press(newClient.token);
      const newEffect = await waitForObservation(() => readPage(newView), value => value.count > 0, 'Replacement native click did not arrive');
      const readyAfterClicks = boundary.native.assertIntegrity();
      const refusal = observeCall(() => rawInfo(bindingKey(retired)));
      observation = { created, initial, attached, user, restored, oldClient, oldPress, oldEffect, resigned, blocked, restoreBlocked,
        blockedPress, blockedEffect, retired, retiredState, retiredPress, retiredEffect, detached, destroyEvent, gone,
        replacement, replacementBlocked, replacementUser, newClient, newRoots, oldStateAfterReplacement, newState, newBefore, stalePress, afterStalePress,
        newPress, newEffect, readyAfterClicks, refusal };
    } else {
      const marked = native.mark(bindingKey(created), false);
      const correct = bindingKey(marked), stale = { ...correct };
      const live = JSON.parse(rawInfo(correct));
      let other, detached;
      if (scenario === 'stale-nonce') stale.nonce = randomUUID();
      if (scenario === 'stale-contents') {
        const extra = new WebContentsView(viewOptions);
        other = bind(extra);
        stale.webContentsId = other.webContentsId;
      }
      if (scenario === 'stale-revision') stale.revision = created.revision;
      if (scenario === 'detached-view') {
        window.contentView.removeChildView(view);
        detached = { roots: roots(), contentsAlive: !view.webContents.isDestroyed() };
      }
      const refusal = observeCall(() => rawInfo(stale));
      observation = { created, initial, live, marked, attached, correct, stale, other, detached, refusal,
        retry: observeCall(() => rawInfo(correct)) };
    }
  }
  writeFileSync(join(config.output, 'binding-lifetime.json'), JSON.stringify({ scenario, before, after: status(), ...observation }) + '\n',
    { mode: 0o600, flag: 'wx' });
  watchdog.terminate();
}
async function observeCachedRoutes(bridge) {
  const observation = cachedRouteObservation = {
    milestone: 'window-creation', unexpectedInput: [], unexpectedInputCount: 0,
    capture: { original: { polls: 0, widgetUnavailable: 0, incompletePair: 0 },
      replacement: { polls: 0, widgetUnavailable: 0, incompletePair: 0 } },
  };
  app.setAccessibilitySupportEnabled(true);
  const window = new BaseWindow({ title: 'Arbol Browser native test', width: 640, height: 360, show: false });
  const handle = window.getNativeWindowHandle();
  const view = new WebContentsView(viewOptions), contents = view.webContents;
  contents.on('before-input-event', (_event, input) => {
    ++observation.unexpectedInputCount;
    if (observation.unexpectedInput.length < 4) {
      const type = ['keyDown', 'keyUp', 'rawKeyDown', 'char'].includes(input.type) ? input.type : 'other';
      observation.unexpectedInput.push({ type, repeat: input.isAutoRepeat === true, milestone: observation.milestone });
    }
  });
  const ownership = boundary.native.ownership;
  const created = ownership.bind(handle, contents.id, () => window.contentView.addChildView(view));
  view.setBounds({ x: 0, y: 0, width: 640, height: 360 });
  const initialUser = ownership.mark(bindingKey(created), false);
  const html = `<!doctype html><button id="button" aria-label="Route fixture button">0</button>
    <input id="field" aria-label="Route fixture field" value="edit">
    <script>
      globalThis.records = [];
      for (const type of ['input', 'compositionstart', 'compositionupdate', 'compositionend']) {
        field.addEventListener(type, event => records.push({ type: event.type, trusted: event.isTrusted,
          data: event.data ?? null, inputType: event.inputType ?? null }));
      }
      button.addEventListener('click', event => {
        button.textContent = Number(button.textContent) + 1;
        records.push({ type: 'click', trusted: event.isTrusted });
      });
      field.focus();
    </script>`;
  const server = createServer((request, response) => {
    if (request.url !== '/page') { response.writeHead(404).end(); return; }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(html);
  });
  await new Promise((accept, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', accept);
  });
  const port = server.address().port;
  const frame = () => {
    const { url, osProcessId, processId, routingId, frameTreeNodeId } = contents.mainFrame;
    return { url, osProcessId, processId, routingId, frameTreeNodeId };
  };
  const capture = which => {
    observation.milestone = `capture-${which}`;
    const samples = observation.capture[which];
    return waitForObservation(() => {
      ++samples.polls;
      let client;
      try { client = JSON.parse(bridge.capture(handle)); } catch (error) {
        if (error.message !== 'fixture_requires_one_actual_widget') throw error;
        ++samples.widgetUnavailable;
        return undefined;
      }
      if (!client.button || !client.field) {
        ++samples.incompletePair;
        bridge.releaseClients(client.token);
      }
      return client;
    }, value => value?.button && value?.field, 'Real cached accessibility controls unavailable');
  };
  const invoke = (token, route) => {
    requireFixtureFocus(window);
    return observeCall(() => JSON.parse(bridge.invoke(token, route)));
  };
  const state = () => {
    assert.equal(observation.unexpectedInputCount, 0, 'An unrelated keyboard event reached the disposable fixture');
    return contents.executeJavaScript(
      '({button:Number(button.textContent),text:field.value,selection:[field.selectionStart,field.selectionEnd],events:[...records]})');
  };
  const reset = () => contents.executeJavaScript("button.textContent='0';field.value='edit';field.focus();field.setSelectionRange(4,4);records.length=0");
  const settle = () => new Promise(accept => setTimeout(accept, 180));
  const matrix = async (phase, token, sequences) => {
    observation.milestone = `matrix-${phase}`;
    const routes = [];
    for (const sequence of sequences) {
      await reset();
      for (const route of sequence) {
        const before = await state(), responder = JSON.parse(bridge.state(token));
        const dispatched = invoke(token, route);
        await settle();
        routes.push({ route, before, responder, dispatched, after: await state() });
      }
    }
    await event('cached-route-matrix', { phase, routes, observation: structuredClone(observation) });
    return routes;
  };
  observation.milestone = 'initial-page-load';
  await contents.loadURL(`http://127.0.0.1:${port}/page`);
  observation.milestone = 'initial-focus';
  await selectFixtureWindow(window, contents);
  await settle();
  const original = await capture('original');
  const originalState = JSON.parse(bridge.state(original.token));
  const originalFrame = frame();
  const focus = invoke(original.token, 'focus');
  const axRoutes = [['press'], ['axValue']];
  const allRoutes = [...axRoutes, ['text'], ['delete'], ['directDelete'], ['selectAll'], ['mark', 'unmark']];
  const user = await matrix('user', original.token, allRoutes);
  observation.milestone = 'press-contexts';
  await reset();
  const beforeContexts = await state();
  requireFixtureFocus(window);
  const contexts = ['unknown', 'off-main', 'reentrant'].map(context => JSON.parse(bridge.invokePressContext(original.token, context)));
  await settle();
  const afterContexts = await state();
  const blockedBinding = ownership.mark(bindingKey(initialUser), true);
  const blocked = await matrix('agent', original.token, [...allRoutes.slice(0, -1), ['mark']]);
  const restored = ownership.restore(bindingKey(blockedBinding));
  const resumedBinding = ownership.mark(bindingKey(restored), false);
  const resumed = await matrix('resumed-user', original.token, allRoutes);

  observation.milestone = 'composition';
  await reset();
  const prime = invoke(original.token, 'mark');
  await settle();
  const composition = async binding => ({ dom: await state(), native: ownership.interactionState(bindingKey(binding)),
    responder: JSON.parse(bridge.state(original.token)) });
  const primed = await composition(resumedBinding);
  const compositionBlocked = ownership.mark(bindingKey(resumedBinding), true);
  const beforeUnmark = await composition(compositionBlocked);
  const deniedUnmark = invoke(original.token, 'unmark');
  await settle();
  const afterUnmark = await composition(compositionBlocked);
  const compositionUser = ownership.mark(bindingKey(compositionBlocked), false);
  const allowedUnmark = invoke(original.token, 'unmark');
  await settle();
  const cleared = await composition(compositionUser);
  const liveUnmark = { prime, primed, beforeUnmark, deniedUnmark, afterUnmark, allowedUnmark, cleared };
  const resigned = invoke(original.token, 'resignFocus');
  const navigationBlocked = ownership.mark(bindingKey(compositionUser), true);
  observation.milestone = 'replacement-navigation';
  await event('cached-route-navigating', { originalFrame, navigationBlocked, observation: structuredClone(observation) });
  await contents.loadURL(`http://localhost:${port}/page`);
  const replacementFrame = frame();
  observation.replacementFrame = { osProcessId: replacementFrame.osProcessId, processId: replacementFrame.processId,
    routingId: replacementFrame.routingId, frameTreeNodeId: replacementFrame.frameTreeNodeId };
  const replacement = await capture('replacement');
  const replacementBlocked = ownership.bindingInfo(bindingKey(navigationBlocked));
  const oldStateAfterNavigation = JSON.parse(bridge.state(original.token));
  const replacementState = JSON.parse(bridge.state(replacement.token));
  const afterNavigation = await matrix('agent-after-frame-swap', replacement.token, axRoutes);
  const replacementUser = ownership.mark(bindingKey(replacementBlocked), false);
  const replacementPositive = await matrix('user-after-frame-swap', replacement.token, axRoutes);
  await new Promise((accept, reject) => server.close(error => error ? reject(error) : accept()));
  const report = { created, initialUser, original, originalFrame, originalState, focus, user, contexts, beforeContexts, afterContexts, resigned,
    blockedBinding, blocked, restored, resumedBinding, resumed, liveUnmark, compositionBlocked, compositionUser, navigationBlocked, replacementFrame, replacement,
    replacementBlocked, oldStateAfterNavigation, replacementState, afterNavigation, replacementUser, replacementPositive,
    status: boundary.native.assertIntegrity() };
  writeFileSync(join(config.output, 'cached-routes.json'), JSON.stringify(report) + '\n', { mode: 0o600, flag: 'wx' });
  watchdog.terminate();
}
async function observeCustomAX(bridge) {
  app.setAccessibilitySupportEnabled(true);
  const window = new BaseWindow({ width: 640, height: 360, show: false });
  const ownership = boundary.native.ownership, handle = window.getNativeWindowHandle();
  const html = `<!doctype html><div role="tablist"><div role="tab" tabindex="0" aria-label="Custom action tab" aria-actions="counter">Tab</div></div>
    <button id="counter">Counter action</button><input aria-label="Custom fixture field">
    <script>globalThis.clicks=[];counter.addEventListener('click',e=>clicks.push({trusted:e.isTrusted,target:e.target.id}));</script>`;
  const attach = async () => {
    const view = new WebContentsView(viewOptions), contents = view.webContents;
    const binding = ownership.bind(handle, contents.id, () => window.contentView.addChildView(view));
    view.setBounds({ x: 0, y: 0, width: 640, height: 360 });
    const user = ownership.mark(bindingKey(binding), false);
    await contents.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
    await selectFixtureWindow(window, contents);
    const client = await waitForObservation(() => {
      const value = JSON.parse(bridge.capture(handle));
      if (!value.cachedHandler) bridge.releaseClients(value.token);
      return value;
    }, value => value.cachedHandler, 'No positive target-specific aria-actions handler');
    return { view, contents, binding, user, client };
  };
  const sample = async (page, phase) => {
    await page.contents.executeJavaScript('clicks.length=0');
    const state = () => page.contents.executeJavaScript('({clicks:[...clicks],tabAttached:document.querySelector("[role=tab]").isConnected})');
    const before = await state(), nativeBefore = JSON.parse(bridge.state(page.client.token));
    requireFixtureFocus(window);
    const dispatched = JSON.parse(bridge.invoke(page.client.token, 'custom'));
    await new Promise(accept => setTimeout(accept, 180));
    return { phase, token: page.client.token, origin: page.client.actionOriginIdentity, before, nativeBefore, dispatched,
      after: await state(), nativeAfter: JSON.parse(bridge.state(page.client.token)) };
  };
  const original = await attach();
  const allowed = await sample(original, 'allowed');
  const blockedBinding = ownership.mark(bindingKey(original.user), true);
  const blocked = await sample(original, 'blocked');
  const resumedBinding = ownership.mark(bindingKey(blockedBinding), false);
  const resumed = await sample(original, 'resumed');
  const retiredBinding = ownership.retire(bindingKey(resumedBinding));
  // Deliberately leave the exact originating AX tab and native page attached.
  // This exercises the tombstone with a live weak-reference target.
  const retired = await sample(original, 'retired-attached');
  window.contentView.removeChildView(original.view);
  original.contents.close({ waitForBeforeUnload: false });
  await waitForObservation(() => original.contents.isDestroyed(), Boolean, 'Original custom AX page did not close');
  const fresh = await attach(), freshAllowed = await sample(fresh, 'fresh-allowed');
  const report = { html, original: original.client, blockedBinding, resumedBinding, retiredBinding,
    allowed, blocked, resumed, retired, fresh: fresh.client, freshBinding: fresh.user, freshAllowed,
    inventory: prepared.trust.manifest.nativeABI,
    installedRoutes: JSON.parse(bridge.auditMethods(Object.keys(prepared.trust.manifest.nativeABI.methods))),
    features: { disabled: app.commandLine.getSwitchValue('disable-features'), sitePerProcess: app.commandLine.hasSwitch('site-per-process') },
    status: boundary.native.assertIntegrity() };
  writeFileSync(join(config.output, 'custom-ax.json'), JSON.stringify(report) + '\n', { mode: 0o600, flag: 'wx' });
  await event('custom-ax-complete');watchdog.terminate();
}
async function observeConcurrentResponder(bridge) {
  app.setAccessibilitySupportEnabled(true);
  const window = new BaseWindow({ width: 720, height: 340, show: false });
  const handle = window.getNativeWindowHandle();
  const { ownership } = boundary.native;
  const pages = () => JSON.parse(bridge.windowPages(handle));
  const html = `<!doctype html><meta charset="utf-8"><title>Arbol fixture shell</title>
    <style>body{margin:0}input,button,#pointer,#drop{position:absolute;left:8px}
      input{top:10px;width:136px}button{top:49px}#pointer{top:90px;width:125px;height:50px;background:#ddd}
      #drop{top:160px;width:125px;height:50px;background:#eee}</style>
    <input id="field" aria-label="Fixture text"><button id="button" aria-label="Fixture activation">0</button>
    <div id="pointer">Pointer target</div><div id="drop">Drop target</div>
    <script>
      globalThis.records = [];
      globalThis.held = null;
      const record = e => records.push({type:e.type, trusted:e.isTrusted, key:e.key, data:e.data,
        pointerId:e.pointerId, buttons:e.buttons});
      for (const name of ['keydown','keyup','input','compositionstart','compositionupdate','compositionend'])
        field.addEventListener(name, record);
      for (const name of ['pointerdown','pointerup','gotpointercapture','lostpointercapture'])
        pointer.addEventListener(name, record);
      pointer.addEventListener('pointerdown', e => { held=e.pointerId; pointer.setPointerCapture(e.pointerId); });
      for (const name of ['dragenter','dragover','dragleave','drop']) drop.addEventListener(name, e => {
        record(e); e.preventDefault();
      });
      button.addEventListener('click', e => { button.textContent=Number(button.textContent)+1; record(e); });
    </script>`;
  // All four pages deliberately have the same URL, title, and native classes.
  const url = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
  async function page(kind, index) {
    const previous = pages();
    const view = new WebContentsView(viewOptions), contents = view.webContents;
    const attach = () => { window.contentView.addChildView(view); };
    const created = kind === 'unknown' ? (attach(), null) : ownership.bind(handle, contents.id, attach);
    const binding = created && kind !== 'agent' ? ownership.mark(bindingKey(created), false) : created;
    const roots = pages().filter(root => !previous.includes(root));
    assert.equal(roots.length, 1);
    view.setBounds({ x: index * 175, y: 0, width: 175, height: 300 });
    await contents.loadURL(url);
    return { kind, contents, webContentsId: contents.id, created, binding, root: roots[0], title: contents.getTitle(), sameURL: contents.getURL() === url };
  }
  const agent = await page('agent', 0), shell = await page('shell', 1), user = await page('user', 2);
  const unknown = await page('unknown', 3);
  const targets = { agent, shell, user, unknown };
  await selectFixtureWindow(window, user.contents);
  await event('concurrent-window-shown', { pages: pages(), windows: BaseWindow.getAllWindows().length });
  for (const target of Object.values(targets)) {
    target.client = await waitForObservation(() => {
      try {
        const client = JSON.parse(bridge.captureRoot(handle, target.root));
        if (target.kind === 'unknown' || (client.button && client.field)) return client;
        bridge.releaseClients(client.token);
      } catch (error) {
        if (error.message !== 'fixture_requires_one_actual_widget') throw error;
      }
      return undefined;
    }, Boolean, `Native accessibility clients unavailable for ${target.kind}`);
  }
  const read = target => target.contents.executeJavaScript(`({ text:field.value, button:Number(button.textContent),
    focused:document.activeElement===field, capture:held!==null&&pointer.hasPointerCapture(held), records:[...records] })`);
  const native = target => JSON.parse(bridge.state(target.client.token));
  const invoke = (target, route) => {
    requireFixtureFocus(window);
    return JSON.parse(bridge.invoke(target.client.token, route));
  };
  const input = action => {
    requireFixtureFocus(window);
    return JSON.parse(bridge.windowInput(user.client.token, action));
  };
  const focusField = target => target.contents.executeJavaScript('field.focus()');
  const focus = invoke(user, 'focus');
  await focusField(user);
  const before = await read(user);
  const nativeBefore = native(user);
  const firstKey = input('b');
  const typedBefore = await waitForObservation(() => read(user), value => value.text === 'b', 'AppKit key did not reach selected page');
  const debugger_ = agent.contents.debugger;
  debugger_.attach('1.3');
  const trace = [];
  const cdp = async (method, params) => {
    trace.push({ point: 'request', method, at: performance.now(), user: native(user), agent: native(agent) });
    const reply = await debugger_.sendCommand(method, params);
    trace.push({ point: 'reply', method, at: performance.now(), user: native(user), agent: native(agent) });
    return reply;
  };
  let keyDuring, agentAfter, userAfter;
  try {
    const mouse = { x: 36, y: 22, button: 'left', clickCount: 1 };
    await cdp('Input.dispatchMouseEvent', { ...mouse, type: 'mousePressed', buttons: 1 });
    await cdp('Input.dispatchMouseEvent', { ...mouse, type: 'mouseReleased', buttons: 0 });
    const pending = cdp('Input.insertText', { text: 'agent' });
    keyDuring = input('z');
    trace.push({ point: 'appkit-key', at: performance.now(), user: native(user), agent: native(agent), key: keyDuring });
    await pending;
    [agentAfter, userAfter] = await Promise.all([
      waitForObservation(() => read(agent), value => value.text === 'agent', 'Background CDP did not reach agent page'),
      waitForObservation(() => read(user), value => value.text === 'bz', 'AppKit key did not reach user page during CDP'),
    ]);
  } finally { debugger_.detach(); }
  await event('concurrent-input-observed', { focus, nativeBefore, before, firstKey, typedBefore, trace, agentAfter, userAfter });
  const ax = {};
  for (const target of [shell, user, agent, unknown]) {
    const before = await read(target);
    const press = target === unknown ? observeCall(() => invoke(target, 'press')) : invoke(target, 'press');
    const after = target === shell || target === user
      ? await waitForObservation(() => read(target), value => value.button === before.button + 1, `Native AX press had no effect for ${target.kind}`)
      : await read(target);
    ax[target.kind] = { before, press, after };
  }
  requireFixtureFocus(window);
  await waitForObservation(() => native(user), state => state.windowKey, 'Disposable window did not regain key status');
  const refocus = invoke(user, 'focus');
  await focusField(user);
  const agentFocus = invoke(agent, 'focus');
  const userAfterAgent = native(user), agentAfterFocus = native(agent);
  const unknownFocus = invoke(unknown, 'focus');
  const userAfterUnknown = native(user), unknownAfter = native(unknown);
  await event('concurrent-ax-observed', { ax, refocus, agentFocus, userAfterAgent, agentAfterFocus, unknownFocus, userAfterUnknown, unknownAfter });

  const interaction = () => ({ native: ownership.interactionState(bindingKey(user.binding)),
    binding: ownership.bindingInfo(bindingKey(user.binding)) });
  const sample = async () => ({ ...interaction(), page: await read(user) });
  const idle = await sample();
  const down = input('down');
  await event('concurrent-pointer-down', { idle, down, after: await sample() });
  const held = await waitForObservation(sample, value => value.page.capture, 'Native pointer did not capture in the renderer');
  const heldAgain = await sample();
  const up = input('up');
  const released = await waitForObservation(sample, value => !value.page.capture &&
    value.page.records.some(event => event.type === 'lostpointercapture'), 'Native pointer capture did not release');
  await event('concurrent-pointer-observed', { idle, down, held, heldAgain, up, released });

  requireFixtureFocus(window);
  await waitForObservation(() => native(user), state => state.windowKey, 'Disposable window lost key status before composition');
  invoke(user, 'focus');
  await focusField(user);
  const mark = invoke(user, 'mark');
  const marked = await waitForObservation(sample, value => value.page.records.some(event => event.type === 'compositionupdate'),
    'Native marked composition did not reach the renderer');
  const markedAgain = await sample();
  const unmark = invoke(user, 'unmark');
  const unmarked = await waitForObservation(sample, value => value.page.records.some(event => event.type === 'compositionend'),
    'Native composition did not end');
  await event('concurrent-marked-observed', { mark, marked, markedAgain, unmark, unmarked });

  const destinationInput = action => JSON.parse(bridge.destinationInput(user.client.token, action));
  const enter = destinationInput('enter');
  let drag, dragAgain, exit;
  try {
    drag = await waitForObservation(sample, value => value.page.records.some(event => event.type === 'dragenter'),
      'Native destination callback did not reach the renderer');
    dragAgain = await sample();
  } finally { exit = destinationInput('exit'); }
  const exited = await waitForObservation(sample, value => value.page.records.some(event => event.type === 'dragleave'),
    'Native destination exit did not reach the renderer');
  await event('concurrent-drag-observed', { enter, drag, dragAgain, exit, exited });

  const report = {
    targets: Object.fromEntries(Object.entries(targets).map(([name, { contents, ...target }]) => [name, {
      ...target, native: native(target), finalBinding: target.binding && ownership.bindingInfo(bindingKey(target.binding)),
    }])),
    focus, nativeBefore, before, firstKey, typedBefore, trace, agentAfter, userAfter, ax, refocus, agentFocus, userAfterAgent, agentAfterFocus, unknownFocus, userAfterUnknown, unknownAfter,
    pointer: { idle, down, held, heldAgain, up, released }, composition: { mark, marked, markedAgain, unmark, unmarked },
    destination: { enter, drag, dragAgain, exit, exited },
    status: boundary.native.assertIntegrity(),
  };
  writeFileSync(join(config.output, 'concurrent-responder.json'), JSON.stringify(report) + '\n', { mode: 0o600, flag: 'wx' });
  watchdog.terminate();
}

async function observeRetirement(bridge, addon) {
  const scenario = config.retirementScenario;
  assert.ok(['success', 'detach-throws', 'destroy-missing', 'native-detach-blocked'].includes(scenario));
  await event('retirement-ready', { scenario });
  app.setAccessibilitySupportEnabled(true);
  const window = new BaseWindow({ width: 420, height: 260, show: false });
  const view = new WebContentsView(viewOptions), contents = view.webContents;
  const parent = window.contentView, handle = window.getNativeWindowHandle(), { ownership } = boundary.native;
  const created = ownership.bind(handle, contents.id, () => { parent.addChildView(view); });
  const user = ownership.mark(bindingKey(created), false);
  view.setBounds({ x: 0, y: 0, width: 420, height: 260 });
  await loadFixturePage(view, 'Retirement fixture activation');
  await selectFixtureWindow(window, contents);
  const client = await waitForObservation(() => {
    try {
      const candidate = JSON.parse(bridge.capture(handle));
      if (candidate.button) return candidate;
      bridge.releaseClients(candidate.token);
    } catch (error) {
      if (error.message !== 'fixture_requires_one_actual_widget') throw error;
    }
    return undefined;
  }, Boolean, 'No cached native AX client in retirement fixture');
  const press = () => JSON.parse(bridge.invoke(client.token, 'press'));
  const state = () => JSON.parse(bridge.state(client.token));
  const button = () => contents.executeJavaScript('({button:Number(button.textContent), clicks:[...clicks]})');
  const baseline = await button();
  requireFixtureFocus(window);
  const positive = press();
  const activated = await waitForObservation(button, value => value.button === baseline.button + 1, 'Native retirement positive click unavailable');
  requireFixtureFocus(window);
  await waitForObservation(state, value => value.windowKey, 'Retirement window lost key status');
  requireFixtureFocus(window);
  const resigned = JSON.parse(bridge.invoke(client.token, 'resignFocus'));
  const realRemove = parent.removeChildView.bind(parent), realClose = contents.close.bind(contents);
  let destroyed = 0, admission = true, fixtureAuthority = contents.id;
  const snapshot = () => ({ attached: parent.children.includes(view), roots: JSON.parse(bridge.windowPages(handle)),
    destroyed, isDestroyed: contents.isDestroyed(), native: JSON.parse(addon.status()), state: state(), visible: window.isVisible() });
  const journal = join(config.output, 'retirement.jsonl');
  const log = (stage, fields = {}) => appendFileSync(journal,
    JSON.stringify({ stage, scenario, at: performance.now(), ...fields }) + '\n', { mode: 0o600 });
  contents.on('destroyed', () => { destroyed++; log('destroyed', { isDestroyed: contents.isDestroyed() }); });
  log('positive', { webContentsId: contents.id, client, created, user, baseline, positive, activated, resigned, snapshot: snapshot() });
  retirementEffect = name => {
    if (name === 'admission-closed') admission = false;
    if (name === 'authority-invalidated') fixtureAuthority = null;
    if (name === 'pages-hidden') window.hide();
    log(name, { admission, fixtureAuthority, closed: boundary.fatal.closed, reason: boundary.fatal.reason,
      watchdogFatal: watchdog.fatal, snapshot: snapshot(), press: press() });
  };
  parent.removeChildView = target => {
    assert.equal(target, view);
    log('before-remove', { snapshot: snapshot(), press: press() });
    if (scenario === 'detach-throws') throw new Error('fixture_detach_refused');
    if (scenario === 'native-detach-blocked') {
      watchdog.assertArmed(prepared.trust);
      log('native-block-enter', { durationMs: 5000 });
      const fd = openSync(journal, 'a');
      try { log('native-block-return', { returned: JSON.parse(bridge.blockDetach(fd)) }); }
      finally { closeSync(fd); }
    }
    realRemove(target);
    log('after-remove', { snapshot: snapshot(), press: press() });
  };
  contents.close = options => {
    log('close-called', { options, snapshot: snapshot() });
    if (scenario === 'destroy-missing') return;
    realClose(options);
  };
  const retired = await boundary.retire(bindingKey(user), parent, view);
  log('returned', { retired, snapshot: snapshot(), press: press() });
  watchdog.terminate();
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
  app.setActivationPolicy('accessory');
  const path = process.env.ARBOL_BROWSER_QUALIFICATION_REQUEST;
  assert.ok(path && await realpath(path) === path);
  const stat = await lstat(path);
  assert.ok(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o600 && stat.nlink === 1 && stat.size <= 16384);
  config = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(config.manualFocusApproved, true, 'Native fixture request lacks per-run approval');
  assert.equal(config.format, 1); assert.ok(['boundary', 'callbacks', 'frozen-trust', 'frozen-trust-restored', 'provider-mismatch', resolverMode, poisonMode, bindingMode,
    cachedRoutesMode, concurrentResponderMode, retirementMode, startupCustodyMode, failureCustodyMode, monitorCustodyMode, helperExitMode, customAXMode].includes(config.mode));
  const startupScenarios = ['startup-descriptors', 'bootstrap-identity-refused', 'late-readiness',
    'primary-producer-lost', 'custody-producer-lost', 'custody-withholds-c', 'custody-withholds-g', 'primary-withholds-j'];
  assert.equal(config.mode === startupCustodyMode, startupScenarios.includes(config.startupScenario));
  const failureScenarios = ['heartbeat-silence', 'ack-silence', 'eof', 'malformed', 'out-of-order',
    'integrity-refused', 'cleanup-blocked', 'exit-blocked', 'fatal-shortening'];
  assert.equal(config.mode === failureCustodyMode, failureScenarios.includes(config.failureScenario));
  const monitorScenarios = ['primary-lost', 'primary-hung', 'primary-timeout', 'custody-lost', 'custody-hung', 'both-lost', 'custody-consent'];
  assert.equal(config.mode === monitorCustodyMode, monitorScenarios.includes(config.monitorScenario));
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

  if (['frozen-trust', 'frozen-trust-restored'].includes(config.mode)) {
    const manifestModule = await import(new URL('../native/manifest.js', bootstrapURL));
    manifestModule.assertCandidateTrust(prepared.trust);
    assert.ok(Object.isFrozen(prepared.trust.manifest) && Object.isFrozen(prepared.trust.manifest.files));
    if (config.mode === 'frozen-trust-restored') {
      await event('fresh-restored-control', { admission: admissionObservation() });
      app.exit(0);
      await new Promise(() => {});
    }
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
  if (config.startupScenario === 'bootstrap-identity-refused') {
    await event('startup-observer-waiting');
    await waitForFixtureMarker('startup-observer-ready');
    const original = process.env.ARBOL_BROWSER_BOOTSTRAP;
    const [version, pid, start, group, session, uid] = original.split(':');
    assert.equal(pid, String(process.pid));
    const changed = [version, pid, String(BigInt(start) + 1n), group, session, uid].join(':');
    process.env.ARBOL_BROWSER_BOOTSTRAP = changed;
    try { await assert.rejects(prepared.arm(owner, build)); }
    finally { process.env.ARBOL_BROWSER_BOOTSTRAP = original; }
    await assert.rejects(prepared.arm(owner, build)); // A real retry with the correct launch value also refuses.
    await event('startup-identity-refused', { original, changed, retryRefused: true, admission: admissionObservation(),
      owner: owner.assertIdentity(), build: build.assertIdentity() });
    await new Promise(accept => setTimeout(accept, 350));
    app.exit(0);
    await new Promise(() => {});
  }
  if (config.mode === startupCustodyMode && config.startupScenario !== 'late-readiness') {
    await event('startup-observer-waiting');
    await waitForFixtureMarker('startup-observer-ready');
  }
  const observesProtocol = [failureCustodyMode, monitorCustodyMode, helperExitMode].includes(config.mode);
  if (observesProtocol) assert.ok(config.callback && await realpath(config.callback) === config.callback);
  watchdog = await (observesProtocol || config.mode === startupCustodyMode ? armWithWatchdogWitness(owner, build) : prepared.arm(owner, build));
  watchdog.assertArmed(prepared.trust);
  await event('armed', { descriptors: watchdog.custody.descriptors, startupDescriptor: watchdog.custody.startupDescriptor, appReady: app.isReady() });
  if (config.startupScenario === 'startup-descriptors') {
    assert.ok(config.callback && await realpath(config.callback) === config.callback);
    const bridge = createRequire(import.meta.url)(config.callback);
    const descriptor = fd => JSON.parse(bridge.descriptor(fd));
    await event('startup-descriptors', { capsule: descriptor(watchdog.custody.startupDescriptor),
      owner: descriptor(watchdog.custody.descriptors[0]), build: descriptor(watchdog.custody.descriptors[1]), admission: admissionObservation() });
    await new Promise(accept => setTimeout(accept, 350));
  }
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
      retirementEffect?.('admission-closed');
      failureEffect?.('admission-closed');
      void event('admission-closed');
    },
    invalidate() { retirementEffect?.('authority-invalidated'); failureEffect?.('authority-invalidated'); void event('authority-invalidated'); },
    hidePages() { retirementEffect?.('pages-hidden'); failureEffect?.('pages-hidden'); void event('pages-hidden'); },
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
    await event('resolver-control', { afterGetABI, afterInstall, originals, installed, resolverAfter: JSON.parse(bridge.resolverDispatch()) });
  } else boundary = await bootstrap.installNativeBoundary(prepared, watchdog, effects);
  assert.equal(boundary.pageAdmission, false);
  await event('installed', { status: boundary.native.assertIntegrity(), admission: admissionObservation(), appReady: app.isReady() });
  if ([bindingMode, cachedRoutesMode, concurrentResponderMode, retirementMode, failureCustodyMode, monitorCustodyMode, helperExitMode, customAXMode].includes(config.mode)) {
    assert.ok(config.callback && await realpath(config.callback) === config.callback);
    const require = createRequire(import.meta.url);
    const bridge = require(config.callback);
    const loadAddon = () => require(join(config.bundle, 'Contents/Resources/browser/native/ownership.node'));
    const run = {
      [bindingMode]: () => observeBindingLifetime(bridge, loadAddon()),
      [cachedRoutesMode]: () => observeCachedRoutes(bridge),
      [concurrentResponderMode]: () => observeConcurrentResponder(bridge),
      [retirementMode]: () => observeRetirement(bridge, loadAddon()),
      [failureCustodyMode]: () => observeFailure(bridge, loadAddon()),
      [monitorCustodyMode]: () => observeFailure(bridge, loadAddon()),
      [helperExitMode]: () => observeHelperExit(),
      [customAXMode]: () => observeCustomAX(bridge),
    }[config.mode];
    // Electron's entry must resolve before its application-ready event.
    app.whenReady().then(run).catch(async error => {
      const stage = { [bindingMode]: 'binding-unavailable', [cachedRoutesMode]: 'cached-route-unavailable',
        [concurrentResponderMode]: 'concurrent-responder-unavailable', [retirementMode]: 'retirement-unavailable',
        [failureCustodyMode]: 'failure-custody-unavailable', [monitorCustodyMode]: 'monitor-loss-unavailable', [helperExitMode]: 'helper-exit-unavailable', [customAXMode]: 'custom-ax-unavailable' }[config.mode];
      await event(stage, { error: String(error.stack ?? error),
        ...(stage === 'cached-route-unavailable' && cachedRouteObservation ? { observation: structuredClone(cachedRouteObservation) } : {}) });
      watchdog.terminate();
    });
  } else if (config.mode === 'callbacks') {
    assert.ok(config.callback && await realpath(config.callback) === config.callback);
    const bridge = createRequire(import.meta.url)(config.callback);
    assert.deepEqual(Object.getOwnPropertyNames(bridge).sort(), ['armInstallPoison', 'auditMethods', 'block', 'capture', 'captureRoot', 'descriptor', 'destinationInput', 'finishInstallPoison', 'invoke', 'invokePressContext',
      'monotonicNanos', 'releaseClients', 'resolverControlObservation', 'resolverDispatch', 'startResolverControl', 'state', 'stopResolverControl', 'windowInput', 'windowPages']);
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
      let view = new WebContentsView(viewOptions);
      void event('callback-view-created');
      const key = bindingKey;
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
      await selectFixtureWindow(window, view.webContents);
      await new Promise(accept => setTimeout(accept, 350));
      const cached = JSON.parse(bridge.capture(window.getNativeWindowHandle()));
      await event('callback-view', { binding, cached, state: JSON.parse(bridge.state(cached.token)), appReady: app.isReady() });
      requireFixtureFocus(window);
      const focus = JSON.parse(bridge.invoke(cached.token, 'focus'));
      await event('callback-focus-observation', { focus, state: JSON.parse(bridge.state(cached.token)) });
      const before = await view.webContents.executeJavaScript('({text:field.value,events:[...events]})');
      requireFixtureFocus(window);
      const invocation = JSON.parse(bridge.invoke(cached.token, 'text'));
      await new Promise(accept => setTimeout(accept, 150));
      const after = await view.webContents.executeJavaScript('({text:field.value,events:[...events]})');
      await event('callback-positive-observation', { before, invocation, after, state: JSON.parse(bridge.state(cached.token)) });
      const pressBefore = await view.webContents.executeJavaScript('({button:button.textContent,events:[...events]})');
      requireFixtureFocus(window);
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
          requireFixtureFocus(window);
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
      requireFixtureFocus(window);
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
