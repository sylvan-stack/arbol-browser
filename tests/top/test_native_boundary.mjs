// Scoped native qualification of the pinned signed consumer.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createNativeOutput, nativeConsumer, publisherRequirement, requireNativeLaunch, prepareNativeFixtures, prepareNativeTrustVariant, launchNativeFixture } from '../support/native.mjs';
const digest = value => createHash('sha256').update(value).digest('hex');
const stages = record => record.stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
export async function nativeTrustBoundary({ output }) {
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), bodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeTrustBoundary', status: 'incomplete', sourceBodyDigest: bodyDigest,
    nativeConsumer, scenarios: [], scope: 'pinned-consumer native observations',
    unavailable: [] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'));
    const positive = await launchNativeFixture(fixtures, { output: join(fixtures.directory, 'positive') });
    const events = stages(positive), installed = events.find(value => value.stage === 'installed');
    requireNativeLaunch(positive, events, { armed: true });
    assert.equal(positive.timedOut, false); assert.equal(positive.code, 0);
    assert.ok(events.some(value => value.stage === 'prepared' && value.counterfeitRefused === true
      && value.crossModuleRefused === true && value.repeatPreparationRefused === true));
    assert.ok(events.some(value => value.stage === 'armed'));
    assert.equal(installed?.status.phase, 'ready'); assert.ok(installed.status.hooks > 0);
    assert.equal(installed.status.hooks, installed.status.appliedHooks);
    assert.deepEqual(installed.admission.windows, []); assert.deepEqual(installed.admission.webContents, []);
    assert.deepEqual([...installed.admission.nativeImages].sort(), ['ownership.node', 'platform.node'].map(name =>
      join(fixtures.consumer.candidate, 'Contents/Resources/browser/native', name)).sort());
    result.scenarios.push({ id: 'exact-consumer-control', status: 'passed', record: join(fixtures.directory, 'positive/launch-result.json'),
      candidate: positive.candidate, consumerRole: positive.consumerRole, installed });
    for (const kind of ['sealed-resource', 'wrong-publisher']) {
      const variant = await prepareNativeTrustVariant(fixtures, join(fixtures.directory, kind + '-copy.app'), { kind });
      const signature = requirement => {
        const verification = spawnSync('/usr/bin/codesign', ['--verify', '--strict', '--deep',
          ...(requirement ? ['-R', requirement] : []), variant.candidate],
        { encoding: 'utf8', timeout: 30000, env: { PATH: '/usr/bin:/bin' } });
        assert.equal(verification.error, undefined);
        assert.equal(verification.signal, null);
        assert.ok(Number.isInteger(verification.status));
        return { status: verification.status, stderr: verification.stderr };
      };
      const structure = signature(), publisher = signature(publisherRequirement);
      if (kind === 'wrong-publisher') {
        assert.equal(structure.status, 0);
        assert.notEqual(publisher.status, 0);
        assert.match(publisher.stderr, /requirement/i);
      } else {
        assert.notEqual(structure.status, 0);
        assert.match(structure.stderr, /sealed resource/i);
      }
      const output = join(fixtures.directory, kind + '-refusal');
      const negative = await launchNativeFixture(fixtures, { output, variant });
      const refused = stages(negative), observation = refused.find(value => value.stage === 'trust-refusal-observation');
      requireNativeLaunch(negative, refused);
      assert.equal(negative.timedOut, false); assert.equal(negative.code, 70);
      assert.ok(refused.some(value => value.stage === 'unavailable' && value.error.includes('native_candidate_unavailable')));
      assert.ok(!refused.some(value => ['prepared', 'locks', 'armed', 'installed'].includes(value.stage)));
      assert.deepEqual(observation?.before.nativeImages, []); assert.deepEqual(observation.after.nativeImages, []);
      assert.deepEqual(observation.after.windows, []); assert.deepEqual(observation.after.webContents, []);
      assert.equal(observation.locks.owner.exists, false); assert.equal(observation.locks.build.exists, false);
      assert.equal(observation.retry.refused, true);
      assert.equal(negative.consumerRole, 'immutable baseline only; executing copy is explicitly derived');
      result.scenarios.push({ id: kind + '-copy-refusal', status: 'passed', record: join(output, 'launch-result.json'),
        derivation: variant.manifest, structure, publisher, observation });
    }
    const frozen = await prepareNativeTrustVariant(fixtures, join(fixtures.directory, 'frozen-trust-copy.app'), { kind: 'frozen-trust' });
    const frozenOutput = join(fixtures.directory, 'frozen-trust-refusal');
    const drift = await launchNativeFixture(fixtures, { mode: 'frozen-trust', output: frozenOutput, variant: frozen });
    const driftEvents = stages(drift);
    requireNativeLaunch(drift, driftEvents);
    assert.equal(drift.timedOut, false); assert.equal(drift.code, 0);
    assert.ok(drift.frozenTrust && !drift.frozenTrust.unavailable);
    assert.notEqual(drift.frozenTrust.before, drift.frozenTrust.altered);
    assert.equal(drift.frozenTrust.before, drift.frozenTrust.restored);
    const probeStages = driftEvents.filter(event => event.stage.startsWith('frozen-trust-'));
    assert.deepEqual(probeStages.map(event => event.stage), [
      'frozen-trust-ready', 'frozen-trust-drift-refused', 'frozen-trust-restored-refused',
    ]);
    for (const { admission } of probeStages) {
      assert.deepEqual(admission.windows, []);
      assert.deepEqual(admission.webContents, []);
      assert.deepEqual(admission.nativeImages, [join(frozen.candidate, 'Contents/Resources/browser/native/platform.node')]);
    }
    assert.ok(!driftEvents.some(event => ['locks', 'armed', 'installed'].includes(event.stage)));
    for (const name of ['owner.lock', 'build.lock'])
      await assert.rejects(lstat(join(frozenOutput, name)), { code: 'ENOENT' });
    result.scenarios.push({ id: 'frozen-trust-after-restored-copy', status: 'passed',
      record: join(frozenOutput, 'launch-result.json'), probeStages, observedResource: drift.frozenTrust });
    const restoredOutput = join(fixtures.directory, 'fresh-restored-control');
    const restored = await launchNativeFixture(fixtures, { mode: 'frozen-trust-restored', output: restoredOutput, variant: frozen });
    const restoredEvents = stages(restored);
    requireNativeLaunch(restored, restoredEvents);
    assert.equal(restored.code, 0);
    assert.equal(restored.timedOut, false);
    const restoredPreparation = restoredEvents.find(event => event.stage === 'prepared');
    assert.ok(restoredPreparation?.snapshotDigest);
    assert.equal(restoredPreparation.snapshotDigest, driftEvents.find(event => event.stage === 'prepared').snapshotDigest);
    assert.ok(!restoredEvents.some(event => ['locks', 'armed', 'installed'].includes(event.stage)));
    result.scenarios.push({ id: 'fresh-restored-control', status: 'passed', record: join(restoredOutput, 'launch-result.json') });
    const mismatch = await prepareNativeTrustVariant(fixtures, join(fixtures.directory, 'provider-mismatch-copy.app'),
      { kind: 'provider-mismatch' });
    const mismatchOutput = join(fixtures.directory, 'provider-mismatch-refusal');
    const refusedProvider = await launchNativeFixture(fixtures, { mode: 'provider-mismatch', output: mismatchOutput, variant: mismatch });
    const providerEvents = stages(refusedProvider);
    requireNativeLaunch(refusedProvider, providerEvents, { armed: true });
    const providerReport = join(mismatchOutput, 'provider-refusal.json');
    const providerObservation = JSON.parse(await readFile(providerReport, 'utf8'));
    assert.equal(refusedProvider.timedOut, false);
    assert.equal(refusedProvider.signal, 'SIGKILL');
    assert.ok(providerEvents.some(event => event.stage === 'prepared'));
    assert.ok(providerEvents.some(event => event.stage === 'armed'));
    assert.ok(!providerEvents.some(event => event.stage === 'installed'));
    assert.deepEqual(providerObservation.admission.windows, []);
    assert.deepEqual(providerObservation.admission.webContents, []);
    assert.deepEqual(providerObservation.expected, { ...providerObservation.actual, provider: mismatch.providerChange.after });
    assert.equal(providerObservation.actual.provider, mismatch.providerChange.before);
    assert.equal(providerObservation.status.phase, 'new');
    assert.equal(providerObservation.status.hooks, 0);
    assert.equal(providerObservation.status.appliedHooks, 0);
    assert.equal(providerObservation.status.liveBindings, 0);
    result.scenarios.push({ id: 'provider-mismatch-refusal', status: 'passed',
      record: join(mismatchOutput, 'launch-result.json'), providerReport, providerObservation });
    result.status = 'passed';
  } catch (error) { failure = error; result.status = 'failed'; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), bodyDigest, 'Case source changed during observation');
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}

export async function nativeInstallPoison({ output }) {
  const destination = await createNativeOutput(output);
  const bodyPath = fileURLToPath(import.meta.url), bodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeInstallPoison', status: 'incomplete', sourceBodyDigest: bodyDigest,
    nativeConsumer, scenarios: [], scope: 'pinned-consumer native observations' };
  const decrement = 'BrowserAccessibilityCocoa#accessibilityPerformDecrement';
  const press = 'BrowserAccessibilityCocoa#accessibilityPerformPress';
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'), { callbacks: true });
    const addonPath = join(fixtures.consumer.candidate, 'Contents/Resources/browser/native/ownership.node');
    const controlOutput = join(fixtures.directory, 'resolver-control');
    const control = await launchNativeFixture(fixtures, { mode: 'resolver-control', output: controlOutput });
    const controlEvents = stages(control);
    requireNativeLaunch(control, controlEvents, { armed: true });
    assert.equal(control.timedOut, false);
    assert.equal(control.code, 0);
    assert.ok(controlEvents.some(event => event.stage === 'sealed'));
    const installed = controlEvents.find(event => event.stage === 'installed');
    assert.equal(installed?.status.phase, 'ready');
    assert.equal(installed.status.hooks, installed.status.appliedHooks);
    assert.deepEqual(installed.admission.windows, []);
    assert.deepEqual(installed.admission.webContents, []);
    const audit = controlEvents.find(event => event.stage === 'resolver-control');
    const dispatch = controlEvents.find(event => event.stage === 'resolver-dispatch').dispatch;
    assert.equal(audit.resolverAfter.declaredEncoding, dispatch.declaredEncoding);
    assert.equal(audit.resolverAfter.declaredImage, dispatch.declaredImage);
    for (const receiver of Object.values(audit.resolverAfter.receivers)) {
      assert.equal(receiver.sameMethod, true);
      assert.equal(receiver.sameImplementation, true);
      assert.equal(receiver.providerPath, addonPath);
    }
    assert.ok(audit.afterGetABI.appKit > 0 && audit.afterGetABI.electron > 0);
    assert.ok(audit.afterInstall.appKit > audit.afterGetABI.appKit && audit.afterInstall.electron > audit.afterGetABI.electron);
    assert.ok(Object.values(audit.installed).some(value => value.image === addonPath));
    result.scenarios.push({ id: 'resolver-control', status: 'passed', record: join(controlOutput, 'launch-result.json') });
    for (const id of ['pre-commit-poison', 'rollback-confirmed', 'rollback-unconfirmed']) {
      const output = join(fixtures.directory, id);
      const launch = await launchNativeFixture(fixtures, { mode: 'install-poison', poisonScenario: id, output });
      const record = join(output, 'install-poison.json');
      const observation = { id, status: 'unavailable', launch: join(output, 'launch-result.json'), record };
      result.scenarios.push(observation);
      assert.equal(launch.timedOut, false);
      assert.equal(launch.signal, 'SIGKILL');
      assert.equal(launch.candidate, fixtures.consumer.candidate);
      const events = stages(launch);
      requireNativeLaunch(launch, events, { armed: true });
      assert.ok(events.some(event => event.stage === 'armed'));
      assert.ok(!events.some(event => event.stage === 'installed'));
      const report = JSON.parse(await readFile(record, 'utf8'));
      const { status, retryStatus, originals, returnedMethods, methods, journal } = report;
      assert.equal(report.scenario, id);
      assert.deepEqual(report.install, { error: 'native_install_failed' });
      assert.deepEqual(report.retry, { error: 'native_install_not_repeatable' });
      assert.equal(retryStatus.phase, 'poisoned');
      assert.deepEqual(report.retryMethods, methods);
      assert.deepEqual(report.admission.windows, []);
      assert.deepEqual(report.admission.webContents, []);
      assert.ok(report.admission.nativeImages.includes(addonPath));
      assert.equal(status.phase, 'poisoned');
      assert.equal(status.liveBindings, 0);
      const changed = Object.keys(originals).filter(key => JSON.stringify(originals[key]) !== JSON.stringify(methods[key]));
      if (id === 'pre-commit-poison') {
        assert.equal(status.reason, 'native_install_failed');
        assert.equal(status.hooks, 0);
        assert.equal(status.appliedHooks, 0);
        assert.deepEqual(returnedMethods, originals);
        assert.deepEqual(changed, []);
      } else {
        const unconfirmed = id === 'rollback-unconfirmed';
        assert.equal(status.reason, unconfirmed ? 'native_rollback_failed' : 'native_install_failed');
        assert.equal(status.hooks, Object.values(originals).filter(method => method !== '<absent>').length);
        assert.equal(status.appliedHooks, unconfirmed ? 1 : 0);
        const targets = ['accessibilityCustomActions', 'accessibilityPerformAction:', 'accessibilityPerformDecrement',
          'accessibilityPerformIncrement', 'accessibilityPerformPress'].map(selector => 'BrowserAccessibilityCocoa#' + selector);
        const originalIMPs = targets.map(key => originals[key].implementation);
        assert.equal(journal.commitBefore.length, targets.length);
        for (let index = 0; index < 3; index++) assert.notEqual(journal.commitBefore[index], originalIMPs[index]);
        assert.deepEqual(journal.commitBefore.slice(3), originalIMPs.slice(3));
        assert.deepEqual(journal.commitAfter, [...journal.commitBefore.slice(0, 4), returnedMethods[press].implementation]);
        assert.equal(journal.driftApplied, true);
        assert.equal(journal.confirmationFault, unconfirmed);
        assert.equal(journal.uncertain, false);
        assert.equal(journal.externalRestored, true);
        assert.deepEqual(changed, unconfirmed ? [decrement] : []);
        assert.deepEqual({ ...returnedMethods, [press]: originals[press] }, methods);
        assert.notEqual(returnedMethods[press].implementation, originals[press].implementation);
        assert.equal(returnedMethods[press].image, fixtures.record.callback.path);
        assert.equal(returnedMethods[press].encoding, originals[press].encoding);
        if (unconfirmed) {
          assert.deepEqual(journal.rollbackBefore, [journal.commitBefore[0], journal.commitBefore[1],
            originalIMPs[2], originalIMPs[3], returnedMethods[press].implementation]);
          assert.deepEqual(journal.rollbackAfter, [journal.commitBefore[0], journal.commitBefore[1],
            journal.commitBefore[2], originalIMPs[3], returnedMethods[press].implementation]);
          assert.equal(methods[decrement].image, addonPath);
          assert.equal(methods[decrement].encoding, originals[decrement].encoding);
          assert.equal(methods[decrement].implementation, journal.commitBefore[2]);
        }
      }
      observation.status = 'passed';
      observation.install = status;
      observation.retry = retryStatus;
      observation.changed = changed;
    }
    result.status = 'passed';
  } catch (error) { failure = error; result.status = 'incomplete'; result.error = String(error.stack ?? error); }
  assert.equal(digest(await readFile(bodyPath)), bodyDigest, 'Case source changed during observation');
  await writeFile(join(destination, 'case-result.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  if (failure) throw failure;
  return result;
}
