// Native qualification bodies remain standalone until independent admission.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchNativeFixture, nativeConsumer, prepareNativeFixtures, retirementScenarios, startupScenarios } from '../support/native.mjs';

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

function assertStartupDescriptors(launch, events) {
  const started = events.find(event => event.stage === 'startup-descriptors');
  assert.ok(started, 'The signed process did not publish its real startup descriptors');
  assert.ok(events.some(event => event.stage === 'installed' && event.status.phase === 'ready'));
  assert.ok(events.some(event => event.stage === 'sealed'));
  const original = events.find(event => event.stage === 'launcher');
  const { capsule, owner, build, admission } = started;
  const armed = events.find(event => event.stage === 'armed');
  assert.deepEqual(armed.descriptors, [owner.fd, build.fd]);
  assert.equal(armed.startupDescriptor, capsule.fd);
  assert.deepEqual(admission.windows, []);
  assert.deepEqual(admission.webContents, []);
  assert.ok(!admission.nativeImages.some(path => path.endsWith('/ownership.node')));
  assert.equal(capsule.links, 0);
  assert.equal(capsule.mode, 0o600);
  assert.equal(capsule.accessMode, 0);
  assert.ok(capsule.size > 0 && capsule.size <= 16384);
  const value = capsule.capsule;
  assert.equal(value.format, 2);
  assert.equal(value.mode, 'primary');
  assert.equal(value.producerRole, 'main');
  assert.equal(value.bundle, launch.candidate);
  assert.equal(value.candidateSnapshotDigest, events.find(event => event.stage === 'prepared').snapshotDigest);
  const executing = launch.observations.map(sample => sample.identity).find(identity => identity?.pid === original.pid &&
    identity.executable === join(launch.candidate, 'Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron'));
  assert.ok(executing, 'The observer did not identify the post-exec Electron process');
  for (const field of ['pid', 'startId', 'uid', 'group', 'session']) assert.equal(executing[field], original[field]);
  // exec can change pidVersion. The capsule must name the executing image.
  const main = Object.fromEntries(['pid', 'startId', 'pidVersion', 'uid', 'group', 'session'].map(field => [field, executing[field]]));
  assert.deepEqual(value.main, main);
  const { session, ...producer } = main;
  assert.deepEqual(value.producer, producer);
  assert.equal(capsule.uid, main.uid);
  assert.notDeepEqual([owner.device, owner.inode], [build.device, build.inode]);
  assert.equal(value.locks.owner.heldMode, 2); // Darwin LOCK_EX
  assert.equal(value.locks.build.heldMode, 1); // Darwin LOCK_SH
  const locks = events.find(event => event.stage === 'locks');
  for (const [name, descriptor] of [['owner', owner], ['build', build]]) {
    for (const field of ['device', 'inode', 'uid', 'mode']) {
      assert.equal(descriptor[field], value.locks[name][field]);
    }
    for (const field of ['device', 'inode', 'uid']) assert.equal(descriptor[field], locks[name][field]);
    assert.equal(descriptor.mode, 0o600);
    assert.equal(descriptor.links, 1);
  }
  assert.equal(launch.startupSlots.length, 2, 'The external observer missed the two running monitors');
  const [primary, custody] = launch.startupSlots;
  assert.equal(primary.before.group, primary.before.pid);
  assert.equal(primary.before.parent, main.pid);
  assert.equal(primary.before.originalParentVersion, main.pidVersion);
  assert.equal(custody.before.group, main.group);
  assert.equal(custody.before.parent, primary.before.pid);
  assert.equal(custody.before.originalParentVersion, primary.before.pidVersion);
  for (const monitor of [primary, custody]) {
    assert.equal(monitor.identityMatches, true);
    assert.equal(monitor.before.session, session);
    assert.equal(monitor.before.group, monitor.after.group);
    for (const key of ['pid', 'startId', 'pidVersion', 'uid', 'executable']) assert.equal(monitor.before[key], monitor.expected[key]);
    assert.deepEqual(monitor.slots.map(slot => slot.fd), [3, 4, 5]);
    for (const [index, original] of [owner, build].entries()) {
      const slot = monitor.slots[index];
      assert.equal(slot.regular, true);
      for (const key of ['device', 'inode', 'uid', 'mode', 'links']) assert.equal(slot[key], original[key]);
    }
    // The real helpers close the input capsule while reading it at startup.
    // The raw slot-5 result remains in the observer record.
  }
  assert.ok(launch.observations.some(sample => sample.locks.owner?.acquired === false && sample.locks.build?.acquired === false &&
    sample.current.some(row => row.identityMatches && row.original.pid === custody.before.pid)));
  const births = launch.startupBirths;
  assert.ok(births.capsules, births.unavailable);
  for (const [role, running] of [['primary', primary], ['custody', custody]]) {
    const born = births.capsules[role]?.observation;
    assert.ok(born, `The observer missed the live startup capsule of ${role}`);
    for (const point of [born.before, born.after]) {
      for (const field of ['pid', 'startId', 'pidVersion', 'uid', 'executable']) assert.equal(point[field], running.before[field]);
      assert.equal(point.group, main.group);
    }
    const [ownerSlot, buildSlot, capsuleSlot] = born.slots;
    assert.deepEqual([ownerSlot.inode, buildSlot.inode], [owner.inode, build.inode]);
    assert.equal(capsuleSlot.fd, 5);
    assert.equal(capsuleSlot.flags & 3, 1); // Darwin f_flag: FREAD, without FWRITE.
    assert.equal(capsuleSlot.mode, 0o600);
    assert.equal(capsuleSlot.links, 0);
    assert.equal(capsuleSlot.uid, main.uid);
    assert.equal(capsuleSlot.regular, true);
    assert.ok(capsuleSlot.bytes > 0 && capsuleSlot.bytes <= 16384);
  }
  const originalCapsule = births.capsules.primary.observation.slots[2];
  assert.equal(originalCapsule.device, capsule.device);
  assert.equal(originalCapsule.inode, capsule.inode);
  assert.equal(originalCapsule.bytes, capsule.size);
  const custodyCapsule = births.capsules.custody.observation.slots[2];
  assert.notDeepEqual([custodyCapsule.device, custodyCapsule.inode], [originalCapsule.device, originalCapsule.inode]);
  assert.ok(BigInt(births.capsules.primary.observedAtNanos) < BigInt(births.capsules.custody.observedAtNanos));
  const overlap = births.capsules.custody.primaryOverlap;
  assert.equal(overlap.length, 2);
  for (const point of overlap) {
    assert.equal(point.status, 'alive');
    assert.equal(point.group, main.group);
    for (const key of ['pid', 'startId', 'pidVersion', 'uid', 'executable']) assert.equal(point[key], primary.before[key]);
  }
  const mainOverlap = births.capsules.custody.mainOverlap;
  assert.equal(mainOverlap.length, 2);
  for (const point of mainOverlap) {
    assert.equal(point.status, 'alive');
    assert.equal(point.stopped, true);
    for (const key of Object.keys(main)) assert.equal(point[key], main[key]);
  }
  assert.ok(BigInt(births.capsules.primary.mainHeldAtNanos) < BigInt(births.capsules.custody.observedAtNanos));
}

function assertStartupIdentityRefusal(launch, events) {
  assert.equal(launch.code, 0);
  assert.equal(launch.signal, null);
  const actual = events.find(event => event.stage === 'launcher');
  const refusal = events.find(event => event.stage === 'startup-identity-refused');
  assert.ok(refusal);
  assert.equal(refusal.original, ['1', actual.pid, actual.startId, actual.group, actual.session, actual.uid].join(':'));
  assert.equal(refusal.changed, ['1', actual.pid, String(BigInt(actual.startId) + 1n), actual.group, actual.session, actual.uid].join(':'));
  assert.equal(refusal.retryRefused, true);
  assert.deepEqual(refusal.admission.windows, []);
  assert.deepEqual(refusal.admission.webContents, []);
  assert.ok(!refusal.admission.nativeImages.some(path => path.endsWith('/ownership.node')));
  assert.ok(!events.some(event => event.stage === 'armed' || event.stage === 'installed'));
  assert.ok(launch.observations.some(sample => sample.locks.owner?.acquired === false && sample.locks.build?.acquired === false));
  assert.ok(!launch.observations.some(sample => sample.current?.some(row => row.original.executable.endsWith('/native/watchdog'))));
}

function assertReadinessDelivery(launch, events, records, delayed) {
  assert.deepEqual(records.map(record => record.stage), ['spawn', 'received', 'deliver']);
  const [spawn, received, delivery] = records;
  assert.equal(spawn.delayed, delayed);
  assert.equal(spawn.executable, join(launch.candidate, 'Contents/Resources/browser/native/watchdog'));
  assert.equal(received.frame, `R 1 ${launch.pid}\n`);
  assert.equal(spawn.primary, received.primary);
  assert.equal(spawn.primary, delivery.primary);
  assert.ok(spawn.spawnStarted <= spawn.spawnReturned && spawn.spawnReturned <= received.received && received.received <= delivery.delivered);
  assert.deepEqual(delivery.admission.windows, []);
  assert.deepEqual(delivery.admission.webContents, []);
  assert.ok(!delivery.admission.nativeImages.some(path => path.endsWith('/ownership.node')));
  if (!delayed) {
    assert.ok(events.find(event => event.stage === 'armed').elapsedMs >= delivery.delivered);
    assert.equal(launch.startupSlots[0].before.pid, spawn.primary);
    return;
  }
  assert.ok(received.received - spawn.spawnStarted < 1000, 'The fixture did not observe R before applying its delay');
  assert.ok(delivery.delivered - spawn.spawnReturned >= 1050, 'R was not delayed beyond the startup deadline');
  assert.equal(launch.signal, 'SIGKILL');
  assert.ok(!events.some(event => event.stage === 'armed' || event.stage === 'installed'));
  const primary = launch.observations.flatMap(sample => sample.current ?? []).find(row =>
    row.identityMatches && row.original.pid === spawn.primary && row.original.executable === spawn.executable);
  assert.ok(primary, 'No external kernel observation of the actual primary');
  const final = launch.observations.at(-1);
  assert.equal(final.current.find(row => row.original.pid === launch.pid).current.status, 'gone');
  assert.equal(final.current.find(row => row.original.pid === spawn.primary).current.status, 'gone');
}

function assertStartupBirthFault(launch, events, scenario) {
  const births = launch.startupBirths;
  const fault = births?.fault;
  assert.ok(fault, births?.unavailable ?? 'The observer missed the requested startup phase');
  assert.equal(fault.unavailable, undefined, fault.unavailable);
  const { observed, sample, producer, targetAfter, queued } = fault;
  const target = observed.before;
  const transfer = scenario === 'custody-withholds-g' || scenario === 'primary-withholds-j';
  const withholds = transfer || scenario === 'custody-withholds-c';
  const targetGroup = scenario === 'primary-withholds-j' ? target.pid : launch.pid;
  assert.equal(observed.identityMatches, true);
  assert.equal(target.stopped, true);
  assert.equal(observed.after.stopped, true);
  assert.equal(target.group, targetGroup);
  if (transfer) {
    const g = scenario === 'custody-withholds-g';
    for (const queues of [fault.beforeStop, queued]) {
      assert.equal(queues.primary.group, births.first.primary.pid);
      assert.equal(queues.anchorBefore.group, launch.pid);
      assert.equal(queues.anchorAfter.group, launch.pid);
      assert.deepEqual([queues.forwardBytes, queues.reverseBytes], g ? [4, 0] : [0, 4]);
    }
    assert.equal(target.pid, g ? queued.anchorAfter.pid : queued.primary.pid);
    assert.equal((g ? queued.anchorAfter : queued.primary).stopped, true);
  } else {
    assert.equal(observed.slots[2].fd, 5);
    assert.equal(observed.slots[2].links, 0);
    assert.equal(observed.slots[2].flags & 3, 1);
    assert.equal(fault.primaryBefore.group, launch.pid);
    assert.equal(producer.pid, scenario === 'primary-producer-lost' ? launch.pid : births.first.primary.pid);
  }
  assert.ok(sample.order, sample.unavailable);
  for (const lock of ['owner', 'build']) {
    assert.equal(sample.locks[lock].acquired, false);
    for (const stage of [`before-${lock}`, `after-${lock}`]) {
      const rows = sample.order.find(point => point.stage === stage).processes;
      const row = rows.find(row => row.original.pid === target.pid);
      assert.equal(row.identityMatches, true);
      assert.equal(row.current.stopped, true);
      assert.equal(row.current.group, targetGroup);
      if (!withholds) assert.equal(rows.find(row => row.original.pid === producer.pid).current.status, 'gone');
    }
  }
  if (withholds) {
    assert.equal(targetAfter.status, 'gone', 'The fixture reached the resume limit with the stopped process still alive');
    assert.ok(BigInt(fault.finishedAtNanos) - BigInt(fault.triggeredAtNanos) >= 600000000n, 'The stopped process disappeared before the startup deadline');
  }
  assert.equal(launch.signal, 'SIGKILL');
  assert.ok(!events.some(event => event.stage === 'armed' || event.stage === 'installed'));
  const final = launch.observations.at(-1);
  for (const pid of [launch.pid, ...Object.values(births.first).map(identity => identity.pid)])
    assert.equal(final.current.find(row => row.original.pid === pid).current.status, 'gone');
  assert.equal(final.locks.owner.acquired, true);
  assert.equal(final.locks.build.acquired, true);
}

export async function nativeStartupCustodyBoundary({ output }) {
  const destination = resolve(output);
  assert.ok(destination.startsWith('/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-8-20261115/'));
  await mkdir(destination, { mode: 0o700 });
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeStartupCustodyBoundary', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    gateAdmission: 'pending independent actual-body review', scenarios: [],
    limits: ['The original main is held in its process group across the measured startup handoff until custody is observed.',
      'Private transfer phases are inferred from the exact signed startup sequence and the observed pipe queue lengths.',
      'The fixture records identified originals and lock contention. Its census is sampled.'] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    for (const scenario of startupScenarios) {
      const output = join(fixtures.directory, scenario);
      const entry = { scenario, status: 'incomplete', launch: join(output, 'launch-result.json') };
      result.scenarios.push(entry);
      try {
        const launch = await launchNativeFixture(fixtures, { mode: 'startup-custody', output, startupScenario: scenario });
        const events = jsonLines(launch.stdout);
        const unavailable = events.find(event => event.stage === 'unavailable');
        assert.equal(unavailable, undefined, unavailable?.error);
        assert.equal(launch.timedOut, false);
        assert.equal(launch.candidate, fixtures.consumer.candidate);
        if (scenario === 'bootstrap-identity-refused') assertStartupIdentityRefusal(launch, events);
        else if (scenario === 'startup-descriptors' || scenario === 'late-readiness') {
          if (scenario === 'startup-descriptors') assertStartupDescriptors(launch, events);
          entry.readiness = join(output, 'readiness.jsonl');
          assertReadinessDelivery(launch, events, jsonLines(await readFile(entry.readiness, 'utf8')), scenario === 'late-readiness');
        } else {
          assertStartupBirthFault(launch, events, scenario);
          if (scenario === 'custody-withholds-g' || scenario === 'primary-withholds-j') {
            const trace = jsonLines(await readFile(join(output, 'readiness.jsonl'), 'utf8'));
            assert.deepEqual(trace.map(record => record.stage), ['spawn']);
            assert.equal(trace[0].primary, launch.startupBirths.first.primary.pid);
          }
        }
        entry.status = 'observed';
      } catch (error) { failure ??= error; entry.error = String(error.stack ?? error); }
    }
    if (!failure) result.status = 'passed';
  } catch (error) { failure = error; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), sourceBodyDigest);
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}
