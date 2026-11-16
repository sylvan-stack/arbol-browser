// Scoped native qualification of the pinned signed consumer.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createNativeOutput, bindingScenarios, launchNativeFixture, nativeConsumer, prepareNativeFixtures, requireNativeLaunch, requirePreTrialExit } from '../support/native.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const refusal = { error: 'native_binding_failed' };

function assertCreated(value, actual) {
  assert.deepEqual(actual, value);
  assert.ok(Number.isInteger(value.id) && value.id >= 0);
  assert.ok(Number.isInteger(value.webContentsId) && value.webContentsId > 0);
  assert.match(value.nonce, /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/);
  assert.equal(value.revision, 0);
  assert.equal(value.blocked, true);
  assert.equal(value.retired, false);
}

function assertRetiredReplacement(report) {
  const { created, user, restored, blocked, restoreBlocked, retired, replacement, replacementBlocked, replacementUser,
    oldClient, newClient, oldPress, oldEffect, blockedPress, blockedEffect, retiredPress, retiredEffect, retiredState,
    detached, destroyEvent, gone, newRoots, oldStateAfterReplacement, newState, newBefore, stalePress, afterStalePress,
    newPress, newEffect, readyAfterClicks } = report;
  assert.deepEqual(report.attached, [oldClient.root]);
  assert.deepEqual(user, { ...created, revision: 1, blocked: false });
  assert.deepEqual(restored, user);
  assert.deepEqual(blocked, { ...user, revision: 2, blocked: true });
  assert.deepEqual(restoreBlocked, blocked);
  assert.deepEqual(retired, { ...blocked, revision: 3, retired: true });
  assert.equal(oldPress.returned, true);
  assert.deepEqual(oldEffect, { count: 1, clicks: [true] });
  assert.equal(blockedPress.returned, false);
  assert.deepEqual(blockedEffect, oldEffect);
  assert.equal(retiredPress.returned, false);
  assert.deepEqual(retiredEffect, oldEffect);
  assert.equal(retiredState.attached, true);
  assert.equal(retiredState.cachedButton, true);
  assert.deepEqual(detached, []);
  assert.equal(destroyEvent, true);
  assert.equal(gone.cachedButton, true);
  assert.equal(gone.weakRootAlive, false);
  assert.equal(gone.weakWidgetAlive, false);
  assertCreated(replacement, replacementBlocked);
  for (const name of ['id', 'nonce', 'webContentsId']) assert.notEqual(replacement[name], created[name]);
  // A new object can reuse a freed address. Observe both weak identities
  // after replacement while retaining both accessibility clients.
  assert.equal(oldStateAfterReplacement.weakRootAlive, false);
  assert.equal(oldStateAfterReplacement.weakWidgetAlive, false);
  assert.equal(oldStateAfterReplacement.cachedButton, true);
  assert.equal(newState.weakRootAlive, true);
  assert.equal(newState.weakWidgetAlive, true);
  assert.equal(newState.attached, true);
  assert.notEqual(oldClient.buttonIdentity, newClient.buttonIdentity);
  assert.deepEqual(newRoots, [newClient.root]);
  assert.deepEqual(replacementUser, { ...replacement, revision: 1, blocked: false });
  assert.equal(stalePress.returned, false);
  assert.deepEqual(newBefore, { count: 0, clicks: [] });
  assert.deepEqual(afterStalePress, newBefore);
  assert.equal(newPress.returned, true);
  assert.deepEqual(newEffect, { count: 1, clicks: [true] });
  assert.equal(readyAfterClicks.phase, 'ready');
  assert.equal(readyAfterClicks.liveBindings, 1);
  assert.equal(readyAfterClicks.policyObjects, 2);
}

function assertBindingScenario(id, report) {
  assert.equal(report.scenario, id);
  assert.equal(report.before.phase, 'ready');
  assert.equal(report.before.liveBindings, 0);
  assert.deepEqual(report.refusal, refusal);
  assert.equal(report.after.phase, 'poisoned');
  assert.equal(report.after.reason, 'native_binding_failed');
  assert.equal(report.after.liveBindings, 0);
  if (id === 'ambiguous-creation' || id === 'reentrant-creation') {
    assert.deepEqual(report.empty, []);
    assert.equal(report.attached.length, id === 'ambiguous-creation' ? 2 : 1);
    assert.equal(new Set(report.attached).size, report.attached.length);
    assert.notEqual(...report.contents);
    assert.equal(report.during.phase, 'ready');
    assert.equal(report.during.policyObjects, 0);
    assert.equal(report.after.policyObjects, 0);
    assert.deepEqual(report.retry, refusal);
    return;
  }
  assertCreated(report.created, report.initial);
  assert.equal(report.attached.length, 1);
  if (id === 'retired-replacement') {
    assertRetiredReplacement(report);
    return;
  }
  assert.deepEqual(report.marked, { ...report.created, revision: 1, blocked: false });
  assert.deepEqual(report.live, report.marked);
  assert.deepEqual(report.retry, refusal);
  const fields = Object.keys(report.correct).filter(key => report.correct[key] !== report.stale[key]);
  if (id === 'detached-view') {
    assert.deepEqual(fields, []);
    assert.deepEqual(report.detached, { roots: [], contentsAlive: true });
  } else {
    const expected = { 'stale-nonce': 'nonce', 'stale-contents': 'webContentsId', 'stale-revision': 'revision' }[id];
    assert.deepEqual(fields, [expected]);
    if (id === 'stale-contents') assert.equal(report.stale.webContentsId, report.other.webContentsId);
    if (id === 'stale-revision') assert.equal(report.stale.revision, report.created.revision);
  }
}

export async function nativeBindingLifetime({ output }) {
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
  const result = { format: 1, case: 'nativeBindingLifetime', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    scope: 'pinned-consumer native observations', scenarios: [],
    unavailable: ['binding identifier/revision/lifetime exhaustion has no bounded trigger on the signed ABI'] };
  const errors = [];
  for (const id of bindingScenarios) {
    const output = join(fixtures.directory, id);
    const observation = { id, status: 'unavailable', launch: join(output, 'launch-result.json'), record: join(output, 'binding-lifetime.json') };
    result.scenarios.push(observation);
    try {
      const launch = await launchNativeFixture(fixtures, { mode: 'binding-lifetime', bindingScenario: id, output });
      assert.equal(launch.timedOut, false);
      assert.equal(launch.candidate, fixtures.consumer.candidate);
      const events = launch.stdout.trim().split('\n').map(line => JSON.parse(line));
      assert.ok(events.some(event => event.stage === 'armed'));
      assert.ok(events.some(event => event.stage === 'installed' && event.status.phase === 'ready'));
      assert.equal(launch.signal, 'SIGKILL');
      const unavailable = events.find(event => event.stage === 'binding-unavailable');
      assert.equal(unavailable, undefined, unavailable?.error);
      assertBindingScenario(id, JSON.parse(await readFile(observation.record, 'utf8')));
      observation.status = 'passed';
    } catch (error) {
      observation.error = String(error.stack ?? error);
      errors.push(error);
    }
  }
  assert.equal(digest(await readFile(bodyPath)), sourceBodyDigest);
  if (!errors.length) result.status = 'passed';
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (errors.length) throw new AggregateError(errors, 'Incomplete native binding lifetime');
  return result;
}

const cachedRoutes = Object.freeze({
  press: 'BrowserAccessibilityCocoa#accessibilityPerformPress',
  axValue: 'BrowserAccessibilityCocoa#setAccessibilityValue:',
  text: 'RenderWidgetHostViewCocoa#insertText:replacementRange:',
  delete: 'RenderWidgetHostViewCocoa#doCommandBySelector:',
  directDelete: 'RenderWidgetHostViewCocoa#deleteBackward:',
  selectAll: 'RenderWidgetHostViewCocoa#selectAll:',
  mark: 'RenderWidgetHostViewCocoa#setMarkedText:selectedRange:replacementRange:',
  unmark: 'RenderWidgetHostViewCocoa#unmarkText',
});

function assertRouteMatrix(matrix, blocked, routes = Object.keys(cachedRoutes)) {
  assert.deepEqual(matrix.map(({ route }) => route), routes);
  for (const { route, before, dispatched, after } of matrix) {
    assert.deepEqual(dispatched, { returned: { route, returned: route !== 'press' || !blocked } });
    if (route !== 'unmark') assert.deepEqual(before, { button: 0, text: 'edit', selection: [4, 4], events: [] });
    if (blocked) {
      assert.deepEqual(after, before);
      continue;
    }
    switch (route) {
      case 'press':
        assert.deepEqual(after, { ...before, button: 1, events: [{ type: 'click', trusted: true }] });
        break;
      case 'axValue':
        assert.equal(after.text, 'AX fixture edit');
        assert.ok(after.events.some(event => event.type === 'input' && event.trusted));
        break;
      case 'text':
        assert.equal(after.text, 'editN');
        assert.ok(after.events.some(event => event.inputType === 'insertText' && event.trusted && event.data === 'N'));
        break;
      case 'delete':
      case 'directDelete':
        assert.equal(after.text, 'edi');
        assert.ok(after.events.some(event => event.inputType === 'deleteContentBackward' && event.trusted));
        break;
      case 'selectAll':
        assert.deepEqual(after, { ...before, selection: [0, 4] });
        break;
      case 'mark':
        assert.equal(after.text, 'editM');
        for (const type of ['compositionstart', 'compositionupdate', 'input']) {
          assert.ok(after.events.some(event => event.type === type && event.trusted));
        }
        break;
      case 'unmark':
        assert.equal(after.text, 'editM');
        assert.ok(!before.events.some(event => event.type === 'compositionend'));
        assert.ok(after.events.some(event => event.type === 'compositionend' && event.data === 'M'));
        break;
    }
  }
}

export async function nativeCachedRouteBoundary({ output }) {
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeCachedRouteBoundary', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    scope: 'pinned-consumer native observations', representatives: cachedRoutes,
    complementaryRoutes: {
      'cached custom action handler': 'no positive handler exposed by the controlled renderer',
      'AX action forwarding, attribute value, focus and selected text/range': 'separate from cached press and setAccessibilityValue:',
      'insertText: forwarding, undo/redo/paste and paste-and-match-style': 'separate from the direct insertion and command representatives',
      'generated editing selectors': 'deleteBackward: and selectAll: only, other selectors require their own evidence',
      'finishComposingText, multilingual IME, dictation and writing/text services': 'separate from the observed mark/unmark callbacks',
      'text marker range setter': 'expected absent under the pinned MacAccessibilityTextOperation feature configuration',
    } };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    const output = join(fixtures.directory, 'routes');
    result.launch = join(output, 'launch-result.json');
    result.record = join(output, 'cached-routes.json');
    const launch = await launchNativeFixture(fixtures, { mode: 'cached-routes', output });
    assert.equal(launch.timedOut, false);
    assert.equal(launch.signal, 'SIGKILL');
    assert.equal(launch.candidate, fixtures.consumer.candidate);
    const events = launch.stdout.trim().split('\n').map(line => JSON.parse(line));
    assert.ok(events.some(event => event.stage === 'armed'));
    assert.ok(events.some(event => event.stage === 'installed' && event.status.phase === 'ready'));
    const unavailable = events.find(event => event.stage === 'cached-route-unavailable');
    assert.equal(unavailable, undefined, unavailable?.error);
    const report = JSON.parse(await readFile(result.record, 'utf8'));
    assert.equal(report.originalState.windowKey, true);
    assert.equal(report.focus.returned?.returned, true);
    assert.equal(report.resigned.returned?.returned, true);
    for (const phase of ['user', 'resumed']) assertRouteMatrix(report[phase], false);
    assertRouteMatrix(report.blocked, true, Object.keys(cachedRoutes).slice(0, -1));
    for (const phase of ['user', 'blocked', 'resumed']) {
      for (const { route, responder } of report[phase]) {
        if (route !== 'press' && route !== 'axValue') {
          assert.equal(responder.windowKey, true);
          assert.equal(responder.firstResponder, true, phase + ' ' + route);
        }
      }
    }
    assertRouteMatrix(report.afterNavigation, true, ['press', 'axValue']);
    assertRouteMatrix(report.replacementPositive, false, ['press', 'axValue']);
    for (const [index, { responder }] of report.afterNavigation.entries()) {
      assert.equal(responder.firstResponder, report.replacementPositive[index].responder.firstResponder);
      assert.equal(responder.windowKey, report.replacementPositive[index].responder.windowKey);
    }
    const { prime, primed, beforeUnmark, deniedUnmark, afterUnmark, allowedUnmark, cleared } = report.liveUnmark;
    assert.deepEqual(prime, { returned: { route: 'mark', returned: true } });
    for (const sample of [primed, beforeUnmark, afterUnmark, cleared]) {
      assert.equal(sample.responder.firstResponder, true);
      assert.equal(sample.responder.windowKey, true);
    }
    for (const sample of [primed, beforeUnmark, afterUnmark]) assert.equal(sample.native.marked, true);
    assert.equal(primed.dom.text, 'editM');
    assert.ok(primed.dom.events.some(event => event.type === 'compositionstart' && event.trusted));
    assert.ok(!primed.dom.events.some(event => event.type === 'compositionend'));
    assert.deepEqual(beforeUnmark.dom, primed.dom);
    assert.deepEqual(deniedUnmark, { returned: { route: 'unmark', returned: true } });
    assert.deepEqual(afterUnmark.dom, beforeUnmark.dom);
    assert.deepEqual(allowedUnmark, deniedUnmark);
    assert.equal(cleared.native.marked, false);
    assert.ok(cleared.dom.events.some(event => event.type === 'compositionend' && event.data === 'M'));
    assert.deepEqual(report.beforeContexts, report.afterContexts);
    assert.deepEqual(report.contexts.map(context => context.context), ['unknown', 'off-main', 'reentrant']);
    const image = join(fixtures.consumer.candidate, 'Contents/Resources/browser/native/ownership.node');
    for (const context of report.contexts) { assert.equal(context.image, image); assert.equal(context.returned, false); }
    assert.equal(report.contexts[1].mainThread, false);
    assert.equal(report.contexts[1].threw, false);
    assert.equal(report.contexts[2].nestedCalls, 1);
    assert.equal(report.contexts[2].nestedResult, false);
    assert.deepEqual(report.custom, { error: 'fixture_missing_handler' });
    assert.equal(report.originalFrame.frameTreeNodeId, report.replacementFrame.frameTreeNodeId);
    assert.ok(report.originalFrame.osProcessId > 0 && report.replacementFrame.osProcessId > 0);
    assert.notEqual(report.originalFrame.osProcessId, report.replacementFrame.osProcessId);
    assert.notEqual(report.originalFrame.processId, report.replacementFrame.processId);
    assert.equal(report.original.root, report.replacement.root);
    assert.equal(report.oldStateAfterNavigation.cachedButton, true);
    assert.equal(report.oldStateAfterNavigation.weakRootAlive, true);
    assert.equal(report.oldStateAfterNavigation.weakWidgetAlive, false);
    assert.equal(report.replacementState.weakWidgetAlive, true);
    assert.equal(report.replacementState.attached, true);
    assert.deepEqual(report.blockedBinding, { ...report.initialUser, revision: 2, blocked: true });
    assert.deepEqual(report.restored, report.blockedBinding);
    assert.deepEqual(report.resumedBinding, { ...report.blockedBinding, revision: 3, blocked: false });
    assert.deepEqual(report.compositionBlocked, { ...report.resumedBinding, revision: 4, blocked: true });
    assert.deepEqual(report.compositionUser, { ...report.compositionBlocked, revision: 5, blocked: false });
    assert.deepEqual(report.navigationBlocked, { ...report.compositionUser, revision: 6, blocked: true });
    assert.deepEqual(report.replacementBlocked, report.navigationBlocked);
    assert.deepEqual(report.replacementUser, { ...report.replacementBlocked, revision: 7, blocked: false });
    assert.equal(report.status.phase, 'ready');
    assert.equal(report.status.liveBindings, 1);
    result.status = 'passed';
  } catch (error) { failure = error; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), sourceBodyDigest);
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}

function assertConcurrentResponder(report) {
  const { agent, user, shell, unknown } = report.targets;
  assert.equal(new Set([agent, user, shell, unknown].map(target => target.root)).size, 4);
  assert.equal(new Set([agent, user, shell, unknown].map(target => target.webContentsId)).size, 4);
  for (const target of [agent, user, shell, unknown]) {
    assert.equal(target.sameURL, true);
    assert.equal(target.title, shell.title);
    assert.equal(target.root, target.client.root);
    assert.equal(target.native.attached, true);
    assert.equal(target.native.rootHidden, false);
  }
  for (const target of [agent, user, shell]) {
    assertCreated(target.created, { ...target.created, webContentsId: target.webContentsId });
    assert.deepEqual(target.binding, target === agent ? target.created : { ...target.created, revision: 1, blocked: false });
    assert.deepEqual(target.finalBinding, target.binding);
  }
  assert.equal(new Set([agent, user, shell].map(target => target.created.id)).size, 3);
  assert.equal(unknown.created, null);
  assert.equal(unknown.finalBinding, null);
  assert.equal(report.status.phase, 'ready');
  assert.equal(report.status.liveBindings, 3);
  assert.equal(report.focus.returned, true);
  assert.equal(report.before.text, '');
  assert.equal(report.before.focused, true);
  assert.equal(report.nativeBefore.firstResponder, true);
  assert.equal(report.firstKey.firstResponderBefore, true);
  assert.equal(report.firstKey.firstResponderAfter, true);
  assert.equal(report.typedBefore.text, 'b');
  assert.deepEqual(report.trace.map(({ point, method }) => [point, method ?? null]), [
    ['request', 'Input.dispatchMouseEvent'], ['reply', 'Input.dispatchMouseEvent'],
    ['request', 'Input.dispatchMouseEvent'], ['reply', 'Input.dispatchMouseEvent'],
    ['request', 'Input.insertText'], ['appkit-key', null], ['reply', 'Input.insertText'],
  ]);
  for (const point of report.trace) {
    assert.equal(point.user.windowKey, true);
    assert.equal(point.user.firstResponder, true);
    assert.equal(point.agent.firstResponder, false);
  }
  const during = report.trace[5];
  assert.ok(report.trace[4].at < during.at && during.at < report.trace[6].at);
  assert.equal(during.key.firstResponderBefore, true);
  assert.equal(during.key.firstResponderAfter, true);
  assert.equal(report.agentAfter.text, 'agent');
  assert.equal(report.agentAfter.focused, true);
  assert.deepEqual(report.agentAfter.records.map(({ type, trusted, data }) => [type, trusted, data]), [['input', true, 'agent']]);
  assert.equal(report.userAfter.text, 'bz');
  assert.equal(report.userAfter.focused, true);
  assert.deepEqual(report.userAfter.records.filter(event => event.type === 'keydown').map(({ key, trusted }) => [key, trusted]),
    [['b', true], ['z', true]]);
  assert.deepEqual(report.userAfter.records.filter(event => event.type === 'input').map(({ data, trusted }) => [data, trusted]),
    [['b', true], ['z', true]]);
  for (const name of ['shell', 'user']) {
    const { before, press, after } = report.ax[name];
    assert.equal(press.returned, true);
    assert.equal(after.button, before.button + 1);
    assert.deepEqual(after.records.slice(before.records.length).map(({ type, trusted }) => [type, trusted]), [['click', true]]);
  }
  assert.equal(report.ax.agent.press.returned, false);
  assert.deepEqual(report.ax.agent.after, report.ax.agent.before);
  assert.equal(unknown.client.axNodes, 1); // Native widget only, with no exposed AX children.
  assert.equal(unknown.client.button, false);
  assert.equal(unknown.client.field, false);
  assert.deepEqual(report.ax.unknown.press, { error: 'fixture_missing_button' });
  assert.deepEqual(report.ax.unknown.after, report.ax.unknown.before);
  assert.equal(report.refocus.returned, true);
  assert.equal(report.agentFocus.returned, false);
  assert.equal(report.userAfterAgent.firstResponder, true);
  assert.equal(report.agentAfterFocus.firstResponder, false);
  assert.equal(report.unknownFocus.returned, false);
  assert.equal(report.userAfterUnknown.windowKey, true);
  assert.equal(report.userAfterUnknown.firstResponder, true);
  assert.equal(report.unknownAfter.firstResponder, false);
  const { idle, held, heldAgain, released } = report.pointer;
  const { marked, markedAgain, unmarked } = report.composition;
  const { drag, dragAgain, exited } = report.destination;
  for (const point of [idle, held, heldAgain, released, marked, markedAgain, unmarked, drag, dragAgain, exited])
    assert.deepEqual(point.binding, user.binding);
  for (const point of [held, heldAgain]) {
    assert.equal(point.native.busy, true);
    assert.equal(point.native.buttons, 1);
    assert.equal(point.native.pressedButtons, 1);
    assert.equal(point.page.capture, true);
  }
  for (const point of [idle, released, unmarked, exited]) {
    assert.equal(point.native.busy, false);
    assert.equal(point.native.buttons, 0);
    assert.equal(point.page.capture, false);
  }
  for (const type of ['pointerdown', 'pointerup', 'gotpointercapture', 'lostpointercapture'])
    assert.ok(released.page.records.some(event => event.type === type && event.trusted === true), `Missing trusted ${type}`);
  for (const point of [marked, markedAgain]) {
    assert.equal(point.native.busy, true);
    assert.equal(point.native.marked, true);
    assert.ok(point.page.records.some(event => event.type === 'compositionupdate' && event.trusted === true && event.data === 'M'));
  }
  assert.equal(unmarked.native.marked, false);
  assert.ok(unmarked.page.records.some(event => event.type === 'compositionend'));
  for (const point of [drag, dragAgain]) {
    assert.equal(point.native.busy, true);
    assert.equal(point.native.htmlTarget, true);
    assert.equal(point.native.htmlSource, false);
    assert.ok(point.page.records.some(event => event.type === 'dragenter' && event.trusted === true));
  }
  assert.equal(exited.native.htmlTarget, false);
  assert.equal(exited.native.drops, unmarked.native.drops);
  assert.ok(exited.page.records.some(event => event.type === 'dragleave' && event.trusted === true));
  assert.ok(!exited.page.records.some(event => event.type === 'drop'));
}

export async function nativeConcurrentResponder({ output }) {
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeConcurrentResponder', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    scope: 'pinned-consumer native observations', scenarios: [],
    limits: ['Window-local AppKit events exercise the native dispatcher without physical input.',
      'Interaction state is a snapshot. Controller and generation changes, Take/Return and operation settlement are outside this case.',
      'The destination callback uses fictional NSDraggingInfo and a unique pasteboard. Physical OS source drag and trackpad momentum are unobserved.'] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    const scenario = { id: 'native-responder-and-trusted-input', status: 'unavailable', attempts: [] };
    result.scenarios.push(scenario);
    let lastError;
    for (let number = 1; number <= 3; number++) {
      const output = join(fixtures.directory, number === 1 ? 'responders' : 'responders-' + number);
      const attempt = { number, status: 'failed', launch: join(output, 'launch-result.json'), record: join(output, 'concurrent-responder.json') };
      scenario.attempts.push(attempt);
      try {
        const launch = await launchNativeFixture(fixtures, { mode: 'concurrent-responder', output });
        const events = launch.stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
        const unavailable = events.find(event => ['unavailable', 'concurrent-responder-unavailable'].includes(event.stage));
        assert.equal(unavailable, undefined, unavailable?.error);
        assert.equal(launch.timedOut, false);
        assert.equal(launch.signal, 'SIGKILL');
        assert.equal(launch.candidate, fixtures.consumer.candidate);
        assert.ok(events.some(event => event.stage === 'armed'));
        assert.ok(events.some(event => event.stage === 'installed' && event.status.phase === 'ready'));
        requireNativeLaunch(launch, events);
        if (!events.some(event => event.stage === 'concurrent-window-shown')) {
          await requirePreTrialExit(launch, events, attempt.record);
          attempt.status = 'unavailable';
          throw new Error('The signed process exited before the concurrent responder trial');
        }
        assertConcurrentResponder(JSON.parse(await readFile(attempt.record, 'utf8')));
        attempt.status = 'passed';
      } catch (error) {
        lastError = error;
        attempt.error = String(error.stack ?? error);
      }
      scenario.status = attempt.status;
      if (scenario.status !== 'unavailable') break;
    }
    if (scenario.status !== 'passed') throw lastError;
    result.status = 'passed';
  } catch (error) { failure = error; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), sourceBodyDigest);
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}
