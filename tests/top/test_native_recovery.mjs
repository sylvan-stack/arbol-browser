// Native qualification bodies remain standalone until independent admission.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchNativeFixture, nativeConsumer, prepareNativeFixtures, retirementScenarios } from '../support/native.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const jsonLines = text => text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
const fatalStages = ['admission-closed', 'authority-invalidated', 'pages-hidden'];

function assertRetirement(scenario, records) {
  assert.ok(records.every(record => record.scenario === scenario));
  const stages = ['positive', 'before-remove'];
  if (scenario === 'success') stages.push('after-remove', 'close-called', 'destroyed', 'returned');
  if (scenario === 'detach-throws') stages.push(...fatalStages);
  if (scenario === 'destroy-missing') stages.push('after-remove', 'close-called', ...fatalStages);
  if (scenario === 'native-detach-blocked') stages.push('native-block-enter');
  assert.deepEqual(records.map(record => record.stage), stages);
  const rows = Object.fromEntries(records.map(record => [record.stage, record]));
  const positive = rows.positive;
  assert.equal(positive.created.webContentsId, positive.webContentsId);
  assert.equal(positive.created.revision, 0);
  assert.equal(positive.created.blocked, true);
  assert.equal(positive.created.retired, false);
  assert.deepEqual(positive.user, { ...positive.created, revision: 1, blocked: false });
  assert.equal(positive.positive.returned, true);
  assert.deepEqual(positive.baseline, { button: 0, clicks: [] });
  assert.deepEqual(positive.activated, { button: 1, clicks: [true] });
  assert.equal(positive.resigned.returned, true);
  assert.equal(positive.snapshot.native.liveBindings, 1);
  for (const name of ['positive', 'before-remove']) {
    const { snapshot } = rows[name];
    assert.equal(snapshot.native.phase, 'ready');
    assert.equal(snapshot.attached, true);
    assert.deepEqual(snapshot.roots, [positive.client.root]);
    assert.equal(snapshot.state.attached, true);
    assert.equal(snapshot.state.weakRootAlive, true);
    assert.equal(snapshot.state.cachedButton, true);
    assert.equal(snapshot.isDestroyed, false);
  }
  // At the real detach call, the original view is still attached but the
  // process has no live bindings and the positively used cached client denies.
  const before = rows['before-remove'];
  assert.equal(before.snapshot.native.liveBindings, 0);
  assert.equal(before.snapshot.native.policyObjects, positive.snapshot.native.policyObjects);
  assert.equal(before.press.returned, false);
  for (const name of ['after-remove', 'close-called', 'returned']) {
    if (!rows[name]) continue;
    const { snapshot } = rows[name];
    assert.equal(snapshot.attached, false);
    assert.deepEqual(snapshot.roots, []);
    assert.equal(snapshot.state.attached, false);
    assert.equal(snapshot.state.cachedButton, true);
  }
  if (rows['close-called']) {
    assert.deepEqual(rows['close-called'].options, { waitForBeforeUnload: false });
    assert.equal(rows['close-called'].snapshot.isDestroyed, false);
  }
  if (scenario === 'success') {
    assert.deepEqual(rows.returned.retired, { ...positive.user, revision: 3, blocked: true, retired: true });
    assert.equal(rows.returned.snapshot.destroyed, 1);
    assert.equal(rows.returned.snapshot.isDestroyed, true);
    assert.equal(rows.returned.press.returned, false);
  }
  if (rows['after-remove']) assert.equal(rows['after-remove'].press.returned, false);
  if (rows['native-block-enter']) assert.equal(rows['native-block-enter'].durationMs, 5000);
  if (rows['admission-closed']) {
    const attached = scenario === 'detach-throws';
    for (const stage of fatalStages) {
      const row = rows[stage];
      assert.equal(row.admission, false);
      assert.equal(row.closed, true);
      assert.equal(row.watchdogFatal, true);
      assert.equal(row.reason, 'native_retirement_unavailable');
      assert.equal(row.snapshot.native.liveBindings, 0);
      assert.equal(row.snapshot.attached, attached);
      assert.equal(row.snapshot.isDestroyed, false);
      assert.equal(row.snapshot.destroyed, 0);
      assert.equal(row.snapshot.state.cachedButton, true);
      assert.equal(row.press.returned, false);
    }
    assert.equal(rows['admission-closed'].fixtureAuthority, positive.webContentsId);
    assert.equal(rows['authority-invalidated'].fixtureAuthority, null);
    assert.equal(rows['pages-hidden'].fixtureAuthority, null);
    assert.equal(rows['admission-closed'].snapshot.native.phase, 'ready');
    assert.equal(rows['pages-hidden'].snapshot.native.phase, 'closing');
    assert.equal(rows['pages-hidden'].snapshot.visible, false);
  }
}

export async function nativeRetirementBoundary({ output }) {
  const destination = resolve(output);
  assert.ok(destination.startsWith('/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-8-20261115/'));
  await mkdir(destination, { mode: 0o700 });
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeRetirementBoundary', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    gateAdmission: 'pending independent actual-body review', scenarios: [],
    limits: ['The test intercepts detach and close on disposable Electron objects.',
      'Native blocking acts inside the fixture detach call. The observed signal and process identities do not identify its issuer or certify complete helper custody.',
      'Full host lifecycle transitions are downstream.'] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    for (const scenario of retirementScenarios) {
      const output = join(fixtures.directory, scenario);
      const entry = { scenario, status: 'incomplete', launch: join(output, 'launch-result.json'), record: join(output, 'retirement.jsonl') };
      result.scenarios.push(entry);
      try {
        const launch = await launchNativeFixture(fixtures, { mode: 'retirement', output, retirementScenario: scenario });
        const events = jsonLines(launch.stdout);
        const unavailable = events.find(event => ['unavailable', 'retirement-unavailable'].includes(event.stage));
        assert.equal(unavailable, undefined, unavailable?.error);
        assert.equal(launch.timedOut, false);
        assert.equal(launch.signal, 'SIGKILL');
        assert.equal(launch.candidate, fixtures.consumer.candidate);
        assert.ok(events.some(event => event.stage === 'armed'));
        assert.ok(events.some(event => event.stage === 'installed' && event.status.phase === 'ready'));
        assert.ok(events.some(event => event.stage === 'retirement-ready' && event.scenario === scenario),
          `The ${scenario} process ended before the retirement readiness observation`);
        const final = launch.observations.at(-1);
        const original = final.current?.find(row => row.original.pid === launch.pid);
        assert.equal(original?.original.executable, join(launch.candidate, 'Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron'));
        assert.equal(original.current.status, 'gone');
        assertRetirement(scenario, jsonLines(await readFile(entry.record, 'utf8')));
        entry.status = 'passed';
      } catch (error) { failure ??= error; entry.error = String(error.stack ?? error); }
    }
    if (!failure) result.status = 'passed';
  } catch (error) { failure = error; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), sourceBodyDigest);
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}
