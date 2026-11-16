// Scoped native qualification of the pinned signed consumer.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertOriginalsGoneOnAcquisition, createNativeOutput, runCensusWitness, failureScenarios, launchNativeFixture, monitorScenarios, nativeConsumer, prepareNativeFixtures, requireNativeLaunch, requirePreTrialExit, retirementScenarios, startupScenarios } from '../support/native.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const jsonLines = text => text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
const fatalStages = ['admission-closed', 'authority-invalidated', 'pages-hidden'];

function assertRetirement(scenario, records) {
  assert.ok(records.every(record => record.scenario === scenario || record.stage === 'native-detach-in-call'));
  const stages = ['positive', 'before-remove'];
  if (scenario === 'success') stages.push('after-remove', 'close-called', 'destroyed', 'returned');
  if (scenario === 'detach-throws') stages.push(...fatalStages);
  if (scenario === 'destroy-missing') stages.push('after-remove', 'close-called', ...fatalStages);
  if (scenario === 'native-detach-blocked') stages.push('native-block-enter', 'native-detach-in-call');
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
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeRetirementBoundary', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    scope: 'pinned-consumer native observations', scenarios: [],
    limits: ['The test intercepts detach and close on disposable Electron objects.',
      'Native blocking acts inside the fixture detach call. The observed signal and process identities do not identify its issuer or certify complete helper custody.',
      'Full host lifecycle transitions are downstream.',
      'At most three fresh attempts can recover an independently witnessed exit before retirement readiness or journal activity.'] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    for (const scenario of retirementScenarios) {
      const entry = { scenario, status: 'unavailable', attempts: [] };
      result.scenarios.push(entry);
      let lastError;
      for (let number = 1; number <= 3; number++) {
        const output = join(fixtures.directory, number === 1 ? scenario : scenario + '-' + number);
        const attempt = { number, status: 'failed', launch: join(output, 'launch-result.json'), record: join(output, 'retirement.jsonl') };
        entry.attempts.push(attempt);
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
          const final = launch.observations.at(-1);
          const original = final.current?.find(row => row.original.pid === launch.pid);
          assert.equal(original?.original.executable, join(launch.candidate, 'Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron'));
          assert.equal(original.current.status, 'gone');
          requireNativeLaunch(launch, events);
          const ready = events.find(event => event.stage === 'retirement-ready');
          if (!ready) {
            await requirePreTrialExit(launch, events, attempt.record);
            attempt.status = 'unavailable';
            throw new Error(`The ${scenario} process ended before retirement readiness or journal activity`);
          }
          assert.equal(ready.scenario, scenario);
          const records = jsonLines(await readFile(attempt.record, 'utf8'));
          assertRetirement(scenario, records);
          if (scenario === 'native-detach-blocked') {
            const marker = records.find(record => record.stage === 'native-detach-in-call');
            assert.equal(marker.pid, launch.pid);
            const during = launch.observations.find(({ ordered }) => ordered && !ordered.unavailable &&
              ['owner', 'build'].every(name => !ordered.locks[name].acquired && ['before', 'after'].every(phase => {
                const point = ordered.order.find(row => row.stage === phase + '-' + name);
                return BigInt(point.nanos) > BigInt(marker.nanos) &&
                  point.processes.some(row => row.original.pid === marker.pid && row.identityMatches);
              })));
            assert.ok(during, 'Both locks must contend while the original main is in the native detach block');
            assert.ok(BigInt(final.ordered.order.find(row => row.stage === 'before-close').nanos) > BigInt(marker.nanos));
            assertOriginalsGoneOnAcquisition(launch, final.ordered.expected.processes);
          }
          attempt.status = 'passed';
        } catch (error) {
          lastError = error;
          attempt.error = String(error.stack ?? error);
        }
        entry.status = attempt.status;
        if (entry.status !== 'unavailable') break;
      }
      if (entry.status !== 'passed') failure ??= lastError;
    }
    if (!failure) result.status = 'passed';
  } catch (error) { failure = error; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), sourceBodyDigest);
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}

function assertStartupDescriptors(launch, events) {
  assert.equal(launch.code, 0);
  assert.equal(launch.signal, null);
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
  const witness = launch.startupBirths;
  assert.equal(witness?.forkFence, true, witness?.unavailable);
  assert.equal(witness.main.pid, launch.pid);
  assert.equal(witness.main.startId, actual.startId);
  assert.deepEqual(witness.after, { pid: launch.pid, status: 'gone' });
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
  const starting = launch.observations.find(({ ordered }) => ordered && !ordered.unavailable &&
    ['owner', 'build'].every(name => !ordered.locks[name].acquired &&
      ['before', 'after'].every(phase => {
        const rows = ordered.order.find(row => row.stage === phase + '-' + name).processes;
        const main = rows.find(row => row.identityMatches && row.current.pid === launch.pid)?.current;
        const primary = rows.find(row => row.identityMatches && row.current.pid === spawn.primary)?.current;
        const custody = rows.find(row => row.identityMatches && row.current.parent === primary?.pid)?.current;
        return main?.executed && primary?.executable === spawn.executable && custody?.executable === spawn.executable &&
          primary.parent === main.pid && primary.parentStartId === main.startId && primary.originalParentVersion === main.pidVersion &&
          custody.parentStartId === primary.startId && custody.originalParentVersion === primary.pidVersion &&
          primary.group === primary.pid && custody.group === main.group && primary.session === main.session && custody.session === main.session;
      })));
  assert.ok(starting, 'The observer missed both exact startup monitors while both locks contended');
  assertOriginalsGoneOnAcquisition(launch, starting.ordered.expected.processes);
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
  assertOriginalsGoneOnAcquisition(launch, [births.main, ...Object.values(births.first)]);
}

export async function nativeStartupCustodyBoundary({ output }) {
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeStartupCustodyBoundary', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    scope: 'pinned-consumer native observations', scenarios: [],
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

function assertFailureCustody(launch, fault, { requireFinalHolderSample = true } = {}) {
  const trace = launch.failureCustody;
  assert.equal(trace?.failure, undefined, trace?.failure);
  for (const sample of [...(trace?.observations ?? []), trace?.last, trace?.terminal].filter(Boolean)) {
    for (const name of ['owner', 'build']) {
      if (!sample.locks?.[name]?.acquired) continue;
      const pre = sample.order.find(row => row.stage === 'before-' + name).processes;
      const post = sample.order.find(row => row.stage === 'after-' + name).processes;
      assert.ok(!pre.some(row => row.identityMatches && post.some(after => after.identityMatches &&
        after.original.pid === row.original.pid)), 'Original survived a successful acquisition of ' + name);
    }
  }
  requireMonitorWitness(trace?.capturedOriginalsRetired, trace?.unavailable ?? 'No independent captured-originals trace');
  assert.deepEqual(trace.unexpected, [], 'A process joined the original group after the initial census');
  const identity = trace.observations[0].expected.processes;
  assert.deepEqual(trace.forkFence.watched, identity);
  assert.ok(BigInt(trace.forkFence.armedAtNanos) < BigInt(fault.nanos));
  assert.ok(BigInt(trace.forkFence.verifiedThroughNanos) >= BigInt(trace.terminal.heldThroughNanos));
  const monitors = identity.filter(member => member.executable.endsWith('/native/watchdog'));
  const main = identity.find(member => member.pid === launch.pid);
  const engines = identity.filter(member => member !== main && !monitors.includes(member));
  assert.ok(main);
  assert.equal(monitors.length, 2);
  assert.ok(engines.some(member => member.pid === fault.renderer));
  const rows = (sample, stage) => sample.order.find(item => item.stage === stage).processes;
  const gone = (rows, target) => rows.some(row => row.original.pid === target.pid && row.current.status === 'gone');
  let teardownBeforeFinalHolder = false;
  let mainGone;
  for (const sample of trace.observations) {
    const finalRows = rows(sample, 'before-close');
    if (!mainGone && gone(finalRows, main)) mainGone = BigInt(sample.order.find(item => item.stage === 'before-close').nanos);
    const bracketed = ['owner', 'build'].flatMap(lock => {
      const before = rows(sample, `before-${lock}`), after = rows(sample, `after-${lock}`);
      const shared = before.filter(row => row.identityMatches && after.some(other => other.identityMatches && other.original.pid === row.original.pid));
      if (shared.length) assert.equal(sample.locks[lock].acquired, false, `Original surviving across ${lock} acquisition`);
      return [before, after].map(rows => ({
        acquired: sample.locks[lock].acquired,
        same: rows.filter(row => row.identityMatches),
        gone: rows.filter(row => row.current.status === 'gone'),
      }));
    });
    const sole = bracketed[0].same[0]?.original;
    const census = sample.order.find(row => row.stage === 'census')?.census;
    if (census && !census.unavailable && sole && [main, ...monitors].some(member => member.pid === sole.pid) &&
        bracketed.every(bracket => !bracket.acquired && bracket.same.length === 1 &&
          bracket.same[0].original.pid === sole.pid && bracket.gone.length === identity.length - 1)) {
      teardownBeforeFinalHolder = true;
    }
  }
  if (requireFinalHolderSample && !teardownBeforeFinalHolder) throw Object.assign(
    new Error('Observer missed the final surviving holder after engine and peer disappearance'), { code: 'fixture_observation_unavailable' });
  const final = trace.terminal;
  assert.deepEqual(final.order.find(row => row.stage === 'census').census.members, []);
  for (const name of ['owner', 'build']) {
    assert.equal(final.locks[name].acquired, true);
    for (const phase of ['before', 'after']) {
      const observed = rows(final, phase + '-' + name);
      assert.equal(observed.length, identity.length);
      assert.ok(observed.every(row => row.current.status === 'gone'));
    }
  }
  assert.ok(mainGone);
  return mainGone;
}

function assertFailureScenario(launch, records, scenario) {
  const index = records.findIndex(record => record.stage === 'fault');
  assert.ok(index > 0, 'The signed process did not reach the requested fault');
  const before = records.slice(0, index), fault = records[index], after = records.slice(index + 1);
  const at = (stage) => after.find(record => record.stage === stage);
  const output = before.find(record => record.stage === 'primary-frame' && record.frame === `R 1 ${launch.pid}\n`);
  assert.ok(output);
  assert.equal(fault.scenario, scenario);
  assert.equal(fault.native.phase, 'ready');
  assert.equal(fault.native.liveBindings, 1);
  assert.ok(before.some(record => record.stage === 'primary-frame' && record.frame === fault.acknowledgement));
  assert.ok(before.some(record => record.stage === 'host-frame' && record.frame === fault.acknowledgement.replace(/^A /, 'H ')));
  assert.ok(!['native-block-return', 'integrity-return', 'will-quit', 'exit-return'].some(stage => at(stage)));
  const mainGone = assertFailureCustody(launch, fault);
  const elapsedMs = record => Number(mainGone - BigInt(record.nanos)) / 1e6;
  if (scenario === 'heartbeat-silence') {
    assert.equal(at('native-block-enter')?.place, 'running-main');
    assert.ok(!at('host-frame'));
    assert.ok(elapsedMs(fault) >= 1700 && elapsedMs(fault) < 5000);
  } else if (scenario === 'ack-silence') {
    assert.ok(after.some(record => record.stage === 'withheld-frame' && /^A [1-9]/.test(record.frame)));
    assert.ok(after.some(record => record.stage === 'host-frame' && /^H [1-9]/.test(record.frame)));
  } else if (scenario === 'eof') {
    assert.ok(at('stdin-ended'), 'The actual primary input did not finish closing');
    assert.equal(at('native-block-enter')?.place, 'after-stdin-eof');
    assert.ok(!at('host-frame'));
    assert.ok(elapsedMs(fault) >= 0 && elapsedMs(fault) < 600);
  } else if (scenario === 'malformed' || scenario === 'out-of-order') {
    const expected = scenario === 'malformed' ? 'H ?\n' : fault.acknowledgement.replace(/^A /, 'H ');
    assert.equal(at('fault-write')?.frame, expected);
    assert.equal(at('native-block-enter')?.place, 'after-fault-write');
    assert.ok(elapsedMs(fault) >= 0 && elapsedMs(fault) < 600);
  } else if (scenario === 'cleanup-blocked' || scenario === 'integrity-refused') {
    assert.equal(fault.visible, true);
    assert.deepEqual(after.filter(record => fatalStages.includes(record.stage)).map(record => record.stage), fatalStages);
    assert.ok(after.some(record => record.stage === 'host-frame' && /^F [1-9]/.test(record.frame)));
    for (const stage of fatalStages) {
      const value = at(stage);
      assert.equal(value.admission, false);
      assert.equal(value.closed, true);
      assert.equal(value.fatal, true);
      assert.equal(value.reason, scenario === 'cleanup-blocked' ? 'native_retirement_unavailable' : 'native_integrity_unavailable');
    }
    assert.equal(at('authority-invalidated').authority, null);
    assert.equal(at('pages-hidden').native.phase, 'closing');
    assert.equal(at('pages-hidden').native.liveBindings, 0);
    assert.equal(at('pages-hidden').visible, false);
    if (scenario === 'cleanup-blocked') assert.equal(at('native-block-enter')?.place, 'cleanup');
    else assert.equal(at('integrity-check')?.value, 'fixture-invalid');
  } else if (scenario === 'exit-blocked') {
    assert.equal(at('exit-request')?.sealed.phase, 'closing');
    assert.equal(at('native-block-enter')?.place, 'before-quit');
  } else {
    assert.equal(scenario, 'fatal-shortening');
    const frames = after.filter(record => record.stage === 'host-frame');
    assert.equal(frames.length, 2);
    const [fatal, heartbeat] = frames;
    assert.match(fatal.frame, /^F [1-9][0-9]*\n$/);
    assert.equal(heartbeat.frame, `H ${BigInt(fatal.frame.slice(2)) + 1n}\n`);
    for (const frame of frames) assert.ok(after.some(record => record.stage === 'primary-frame' && record.frame === frame.frame.replace(/^[FH] /, 'A ')));
    assert.equal(at('native-block-enter')?.place, 'after-post-fatal-heartbeat');
    assert.ok(elapsedMs(fatal) >= 650 && elapsedMs(fatal) < 1700);
  }
}

export async function nativeFailureCustodyBoundary({ output }) {
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeFailureCustodyBoundary', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    scope: 'pinned-consumer native observations', scenarios: [],
    limits: ['Identified originals are fork/exec-fenced from their verified pre-fault baseline. Earlier group membership is sampled.',
      'The blocked exit uses the real Electron quit request after packaged native seal in the fixture.',
      'Up to three fresh attempts can recover a pre-fault observation miss or a typed missing witness. A witnessed failure ends the scenario.'] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    for (const scenario of failureScenarios) {
      const entry = { scenario, status: 'unavailable', attempts: [] };
      result.scenarios.push(entry);
      let lastError;
      for (let number = 1; number <= 3; number++) {
        const output = join(fixtures.directory, number === 1 ? scenario : scenario + '-' + number);
        const attempt = { number, status: 'failed', launch: join(output, 'launch-result.json'), record: join(output, 'failure.jsonl') };
        entry.attempts.push(attempt);
        try {
          const launch = await launchNativeFixture(fixtures, { mode: 'failure-custody', output, failureScenario: scenario });
          const events = jsonLines(launch.stdout);
          const unavailable = events.find(event => ['unavailable', 'failure-custody-unavailable'].includes(event.stage));
          assert.equal(unavailable, undefined, unavailable?.error);
          assert.equal(launch.timedOut, false);
          assert.equal(launch.candidate, fixtures.consumer.candidate);
          assert.ok(events.some(event => event.stage === 'armed'));
          assert.ok(events.some(event => event.stage === 'installed' && event.status.phase === 'ready'));
          assert.equal(launch.signal, 'SIGKILL');
          const records = jsonLines(await readFile(attempt.record, 'utf8'));
          requireMonitorWitness(records.some(record => record.stage === 'fault'), 'SIGKILL after installation, before the requested fault');
          assertFailureScenario(launch, records, scenario);
          attempt.status = 'passed';
        } catch (error) {
          if (error.code === 'fixture_observation_unavailable') attempt.status = 'unavailable';
          lastError = error;
          attempt.error = String(error.stack ?? error);
        }
        entry.status = attempt.status;
        if (entry.status !== 'unavailable') break;
      }
      if (entry.status !== 'passed') failure ??= lastError;
    }
    if (!failure) result.status = 'passed';
  } catch (error) { failure = error; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), sourceBodyDigest);
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}

function requireMonitorWitness(value, message) {
  if (!value) throw Object.assign(new Error(message), { code: 'fixture_observation_unavailable' });
  return value;
}

function assertMonitorFault(launch, records, scenario) {
  const armed = requireMonitorWitness(records.find(record => record.stage === 'monitor-armed'), 'The main process exited before the monitor fault');
  const ready = records.find(record => record.stage === 'primary-frame' && record.frame === `R 1 ${launch.pid}\n`);
  assert.ok(ready);
  assert.equal(armed.scenario, scenario);
  assert.equal(armed.native.phase, 'ready');
  assert.equal(armed.native.liveBindings, 1);
  assert.ok(records.some(record => record.stage === 'primary-frame' && record.frame === armed.acknowledgement));
  assert.ok(records.some(record => record.stage === 'host-frame' && record.frame === armed.acknowledgement.replace(/^A /, 'H ')));
  assertFailureCustody(launch, armed, { requireFinalHolderSample: false });
  const trace = launch.failureCustody;
  const fault = trace.monitor;
  requireMonitorWitness(fault?.triggeredAtNanos, 'The external observer did not trigger the requested monitor fault');
  assert.ok(BigInt(fault.triggeredAtNanos) > BigInt(armed.nanos));
  const original = trace.observations[0].expected;
  const main = original.processes.find(member => member.pid === launch.pid);
  const custody = original.anchor;
  const primary = original.processes.find(member => member.pid === custody.parent);
  const survivor = scenario.startsWith('primary-') ? custody : primary;
  const target = survivor === primary ? custody : primary;
  const compare = (actual, expected) => {
    assert.equal(actual.status, 'alive');
    for (const key of ['pid', 'startId', 'pidVersion', 'group', 'uid', 'executable', 'session']) assert.equal(actual[key], expected[key]);
  };
  compare(fault.responsiveMain, main);
  assert.equal(fault.responsiveMain.stopped, false);
  const both = scenario === 'both-lost';
  assert.equal(armed.writesFenced, !both);
  if (!both) {
    assert.equal(armed.lastWrite, armed.acknowledgement.replace(/^A /, 'H '));
    assert.ok(!records.some(record => record.stage === 'host-frame' && BigInt(record.nanos) > BigInt(armed.nanos)));
  }
  if (both) {
    assert.equal(fault.stoppedMain, undefined);
    assert.deepEqual(fault.lossSignals.map(signal => signal.original), [custody, primary]);
  } else {
    compare(fault.stoppedMain, main);
    assert.equal(fault.stoppedMain.stopped, true);
    assert.ok(!records.some(record => record.stage === 'host-frame' && BigInt(record.nanos) > BigInt(fault.triggeredAtNanos)));
  }
  const rows = (sample, stage) => sample.order.find(row => row.stage === stage).processes;
  const processRow = (sample, stage, expected) => rows(sample, stage).find(row => row.original.pid === expected.pid);
  const validCensus = sample => Boolean(sample.order.find(row => row.stage === 'census')?.census?.members);
  const heldAfterPeerLoss = expect => trace.observations.some(sample => validCensus(sample) &&
    ['owner', 'build'].every(lock => !sample.locks[lock].acquired && [`before-${lock}`, `after-${lock}`].every(stage => expect(sample, stage))));
  if (both) {
    requireMonitorWitness(heldAfterPeerLoss((sample, stage) => [custody, primary].every(monitor => processRow(sample, stage, monitor).current.status === 'gone') &&
      processRow(sample, stage, main).identityMatches && !processRow(sample, stage, main).current.stopped),
    'Observer missed the responsive main holding both locks after both monitors disappeared');
  } else if (scenario.endsWith('-lost')) {
    assert.deepEqual(fault.lossSignals.map(signal => signal.original), [target]);
    requireMonitorWitness(heldAfterPeerLoss((sample, stage) => processRow(sample, stage, target).current.status === 'gone' &&
      processRow(sample, stage, survivor).identityMatches && !processRow(sample, stage, survivor).current.stopped),
    'Observer missed the executing monitor after the signalled peer disappeared');
  } else {
    compare(fault.stoppedMonitor, target);
    assert.equal(fault.stoppedMonitor.stopped, true);
    assert.equal(fault.lossSignals, undefined);
    assert.deepEqual([fault.emptyQueues.forwardBytes, fault.emptyQueues.reverseBytes], [0, 0]);
    const targetExit = fault.exitNotes?.find(note => note.pid === target.pid);
    const offer = requireMonitorWitness(fault.retirementOffer,
      `Observer missed the real post-quiescence retirement frame (target exit signal ${targetExit?.signal ?? 'unobserved'})`);
    const pending = target === primary ? [0, 4] : [4, 0];
    assert.deepEqual([offer.queues.forwardBytes, offer.queues.reverseBytes], pending);
    requireMonitorWitness(validCensus(offer.sample), 'Retirement-offer census unavailable');
    for (const lock of ['owner', 'build']) {
      assert.equal(offer.sample.locks[lock].acquired, false);
      for (const stage of [`before-${lock}`, `after-${lock}`]) {
        const stopped = processRow(offer.sample, stage, target);
        const running = processRow(offer.sample, stage, survivor);
        requireMonitorWitness(stopped.identityMatches && stopped.current.stopped && running.identityMatches && !running.current.stopped,
          `Observer missed contention on ${lock} with the stopped peer and surviving monitor`);
        requireMonitorWitness(rows(offer.sample, stage).filter(row => ![primary.pid, custody.pid].includes(row.original.pid))
          .every(row => row.current.status === 'gone'), `Observer missed engine exit before contention on ${lock}`);
      }
    }
    const stop = target === primary ? offer.queues.primary : offer.queues.anchorAfter;
    assert.equal(stop.stopped, true);
    if (scenario === 'primary-timeout') {
      const keeper = requireMonitorWitness(fault.keeper, 'No independent primary group keeper');
      assert.equal(keeper.descriptorBytes, 0); assert.equal(keeper.descriptorErrno, 0); assert.equal(keeper.readyPipeClosed, true);
      assert.equal(keeper.child.group, primary.group); assert.equal(keeper.child.parent, keeper.parent.pid);
      assert.equal(keeper.child.session, primary.session); assert.equal(keeper.parent.session, primary.session);
      assert.notEqual(keeper.parent.group, primary.group);
      compare(fault.keeperBeforeCleanup, keeper.child);
      compare(fault.observerBeforeCleanup, keeper.parent);
      assert.ok(BigInt(fault.emptyQueuesAtNanos) < BigInt(offer.nanos));
      const empty = requireMonitorWitness(fault.lastQuiescentEmpty, 'No empty queue bracket after original main and engine disappeared');
      assert.deepEqual([empty.queues.forwardBytes, empty.queues.reverseBytes], [0, 0]);
      assert.ok(BigInt(fault.emptyQueuesAtNanos) < BigInt(empty.nanos) && BigInt(empty.nanos) < BigInt(offer.nanos));
      for (const name of ['owner', 'build']) for (const stage of ['before-' + name, 'after-' + name]) {
        assert.equal(empty.sample.locks[name].acquired, false);
        assert.ok(rows(empty.sample, stage).filter(row => ![primary.pid, custody.pid].includes(row.original.pid))
          .every(row => row.current.status === 'gone'));
      }
      const near = requireMonitorWitness(fault.nearTimeout, 'No still-live stopped primary near the one-second deadline');
      const elapsed = Number(BigInt(near.nanos) - BigInt(offer.nanos)) / 1e6;
      assert.ok(elapsed >= 900 && elapsed < 1000, `Near-timeout observation at ${elapsed} ms`);
      assert.deepEqual([near.queues.forwardBytes, near.queues.reverseBytes], [0, 4], 'Current P remains unanswered; no T');
      compare(near.queues.primary, primary); assert.equal(near.queues.primary.stopped, true);
      compare(near.queues.anchorAfter, custody); assert.equal(near.queues.anchorAfter.stopped, false);
      compare(near.keeper, keeper.child);
      for (const name of ['owner', 'build']) {
        assert.equal(near.sample.locks[name].acquired, false);
        for (const stage of ['before-' + name, 'after-' + name]) {
          const row = processRow(near.sample, stage, primary);
          assert.equal(row.identityMatches, true); assert.equal(row.current.stopped, true);
        }
      }
      const exited = requireMonitorWitness(fault.exitNotes?.find(note => note.pid === primary.pid), 'No independent primary exit status');
      assert.equal(exited.signal, 9, 'Natural SIGHUP is not timeout retirement');
      const retirementMs = Number(BigInt(exited.observedAtNanos) - BigInt(offer.nanos)) / 1e6;
      assert.ok(retirementMs >= 990 && retirementMs < 1500, `Primary retirement at ${retirementMs} ms`);
      assert.ok(BigInt(exited.observedAtNanos) < BigInt(fault.keeperCleanupAtNanos));
      requireMonitorWitness(heldAfterPeerLoss((sample, stage) => processRow(sample, stage, primary).current.status === 'gone' &&
        processRow(sample, stage, custody).identityMatches), 'No original custody holding both locks after exact primary disappearance');
      assert.equal(fault.keeperCleanup.signal, 9);
    }
    if (scenario === 'custody-consent') {
      const consent = requireMonitorWitness(fault.retirementConsent, 'Observer missed the real reverse queue after custody consumed the retirement request');
      assert.ok(BigInt(offer.nanos) < BigInt(fault.resumedForConsent) && BigInt(fault.resumedForConsent) < BigInt(consent.nanos));
      assert.deepEqual([consent.queues.forwardBytes, consent.queues.reverseBytes], [0, 4]);
      compare(consent.queues.anchorAfter, custody);
      assert.equal(consent.queues.anchorAfter.stopped, false);
      requireMonitorWitness(validCensus(consent.sample), 'Retirement-consent census unavailable');
      assert.ok(!consent.sample.locks.owner.acquired && !consent.sample.locks.build.acquired);
      const custodyExit = requireMonitorWitness(fault.exitNotes?.find(note => note.pid === custody.pid), 'No custody exit status');
      const primaryExit = requireMonitorWitness(fault.exitNotes?.find(note => note.pid === primary.pid), 'No primary exit status');
      assert.equal(custodyExit.code, 0);
      assert.equal(primaryExit.code, 0);
      requireMonitorWitness(heldAfterPeerLoss((sample, stage) => processRow(sample, stage, custody).current.status === 'gone' &&
        processRow(sample, stage, primary).identityMatches), 'No live primary holding both locks after successful custody exit');
    }
  }
  const sentinel = trace.sentinel;
  compare(sentinel.after.process, sentinel.before.process);
  compare(fault.sentinelAfter, sentinel.before.process);
  for (const name of ['owner', 'build']) {
    assert.equal(sentinel.before.locks[name].acquired, false);
    assert.deepEqual(sentinel.after.locks[name], sentinel.before.locks[name]);
    assert.notDeepEqual([sentinel.before.locks[name].device, sentinel.before.locks[name].inode],
      [original.locks[name].device, original.locks[name].inode]);
  }
  assert.ok(original.processes.every(member => member.group !== sentinel.before.process.group));
  assert.equal(sentinel.exit.code, 0);
  assert.equal(sentinel.exit.signal, null);
  assert.equal(sentinel.exit.inputError, undefined);
}

export async function nativeMonitorLossBoundary({ output }) {
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), sourceBodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeMonitorLossBoundary', status: 'incomplete', sourceBodyDigest, nativeConsumer,
    scope: 'pinned-consumer native observations', scenarios: [],
    limits: ['The observer fenced fork and exec of the identified originals from the verified pre-fault baseline through final acquisition.',
      'Retirement frames are inferred from queue lengths and the exact signed monitor source.',
      'An unavailable observation can use up to three fresh launches. Observed failures end the scenario.'],
    unsupported: ['Loss of both independent monitors while the main cannot execute.'] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    for (const scenario of monitorScenarios) {
      const entry = { scenario, status: 'unavailable', attempts: [] };
      result.scenarios.push(entry);
      let lastError;
      for (let number = 1; number <= 3; number++) {
        const output = join(fixtures.directory, number === 1 ? scenario : `${scenario}-${number}`);
        const attempt = { number, status: 'failed', launch: join(output, 'launch-result.json'), record: join(output, 'failure.jsonl') };
        entry.attempts.push(attempt);
        try {
          const launch = await launchNativeFixture(fixtures, { mode: 'monitor-loss', output, monitorScenario: scenario });
          const events = jsonLines(launch.stdout);
          const unavailable = events.find(event => ['unavailable', 'monitor-loss-unavailable'].includes(event.stage));
          assert.equal(unavailable, undefined, unavailable?.error);
          assert.equal(launch.timedOut, false);
          assert.equal(launch.candidate, fixtures.consumer.candidate);
          assert.ok(events.some(event => event.stage === 'armed'));
          assert.ok(events.some(event => event.stage === 'installed' && event.status.phase === 'ready'));
          assert.equal(launch.signal, 'SIGKILL');
          assertMonitorFault(launch, jsonLines(await readFile(attempt.record, 'utf8')), scenario);
          attempt.status = 'passed';
        } catch (error) {
          if (error.code === 'fixture_observation_unavailable') attempt.status = 'unavailable';
          lastError = error;
          attempt.error = String(error.stack ?? error);
        }
        entry.status = attempt.status;
        if (attempt.status !== 'unavailable') break;
      }
      if (entry.status !== 'passed') failure ??= lastError;
    }
    if (!failure) result.status = 'passed';
  } catch (error) { failure = error; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), sourceBodyDigest);
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}

// Prospective ABR-47 case; admission and ordinary gate wiring follow body review.
export async function nativeHelperExitBoundary({ output }) {
  const destination = await createNativeOutput(output);
  const sourceBodyDigest = digest(await readFile(fileURLToPath(import.meta.url)));
  const result = { format: 1, case: 'nativeHelperExitBoundary', status: 'incomplete', sourceBodyDigest, nativeConsumer, scenarios: [] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    const census = await runCensusWitness(join(fixtures.directory, 'census'));
    result.scenarios.push({ id: 'kernel-helper-exit-controls', status: 'passed', record: join(fixtures.directory, 'census/census-record.json'),
      inputs: census.inputs, binary: census.binary });
    const runtime = join(fixtures.directory, 'supported-exit');
    const launch = await launchNativeFixture(fixtures, { mode: 'helper-exit', output: runtime });
    result.scenarios.push({ id: 'signed-supported-helper-exit', status: 'failed', record: join(runtime, 'helper-exit-observation.json'),
      launch: join(runtime, 'launch-result.json') });
    assert.equal(launch.timedOut, false);
    const witness = launch.helperExit;
    assert.equal(witness.passed, true, witness.error);
    assert.equal(witness.requested.destroyed, true);
    assert.equal(witness.requested.mechanism, 'WebContents.close without beforeunload');
    assert.equal(witness.samples.at(-1).renderer.status, 'gone');
    for (const [name, snapshot] of Object.entries({ baseline: witness.baseline, afterExit: witness.afterExit, continued: witness.continued })) {
      assert.equal(snapshot.unavailable, undefined);
      for (const lock of ['owner', 'build']) {
        assert.equal(snapshot.locks[lock].acquired, false);
        for (const stage of ['before-' + lock, 'after-' + lock]) {
          const rows = snapshot.order.find(row => row.stage === stage).processes;
          for (const row of rows) {
            if (row.original.pid === witness.originals.renderer.pid && name !== 'baseline') assert.equal(row.current.status, 'gone');
            else { assert.equal(row.identityMatches, true); assert.equal(row.current.stopped, false); }
          }
        }
      }
    }
    assert.match(witness.live.acknowledgement, /^A [1-9][0-9]*\n$/);
    const liveSequence = BigInt(witness.live.acknowledgement.slice(2));
    const acks = witness.protocol.filter(row => row.stage === 'primary-frame' && /^A /.test(row.frame));
    assert.ok(acks.some(row => BigInt(row.frame.slice(2)) > liveSequence), 'A later signed acknowledgement must follow the independently witnessed disappearance');
    for (const ack of acks) assert.ok(witness.protocol.some(row => row.stage === 'host-frame' && row.frame === ack.frame.replace(/^A /, 'H ')));
    result.scenarios.at(-1).status = 'passed';
    result.status = 'passed';
  } catch (error) { failure = error; result.error = String(error.stack ?? error); }
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}
