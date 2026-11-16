// Proposed native top body; independent review precedes inventory and gate admission.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { nativeConsumer, prepareNativeFixtures, prepareNativeTrustVariant, launchNativeFixture } from '../support/native.mjs';
const digest = value => createHash('sha256').update(value).digest('hex');
const stages = record => record.stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
export async function nativeTrustBoundary({ output }) {
  const destination = resolve(output);
  assert.ok(destination.startsWith('/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-8-20261115/'));
  await mkdir(destination, { mode: 0o700 });
  const bodyPath = fileURLToPath(import.meta.url), bodyDigest = digest(await readFile(bodyPath));
  const result = { format: 1, case: 'nativeTrustBoundary', status: 'incomplete', sourceBodyDigest: bodyDigest,
    nativeConsumer, scenarios: [], gateAdmission: 'pending independent actual-body review',
    unavailable: [] };
  let failure;
  try {
    const fixtures = await prepareNativeFixtures(join(destination, 'fixtures'));
    const positive = await launchNativeFixture(fixtures, { output: join(fixtures.directory, 'positive') });
    const events = stages(positive), installed = events.find(value => value.stage === 'installed');
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
    const variant = await prepareNativeTrustVariant(fixtures, join(fixtures.directory, 'sealed-resource-copy.app'));
    const signature = spawnSync('/usr/bin/codesign', ['--verify', '--strict', '--deep', variant.candidate],
      { encoding: 'utf8', timeout: 30000, env: { PATH: '/usr/bin:/bin' } });
    assert.equal(signature.error, undefined); assert.notEqual(signature.status, 0);
    const negative = await launchNativeFixture(fixtures, { output: join(fixtures.directory, 'sealed-resource-refusal'), variant });
    const refused = stages(negative), observation = refused.find(value => value.stage === 'trust-refusal-observation');
    assert.equal(negative.timedOut, false); assert.equal(negative.code, 70);
    assert.ok(refused.some(value => value.stage === 'unavailable' && value.error.includes('native_candidate_unavailable')));
    assert.ok(!refused.some(value => ['prepared', 'locks', 'armed', 'installed'].includes(value.stage)));
    assert.deepEqual(observation?.before.nativeImages, []); assert.deepEqual(observation.after.nativeImages, []);
    assert.deepEqual(observation.after.windows, []); assert.deepEqual(observation.after.webContents, []);
    assert.equal(observation.locks.owner.exists, false); assert.equal(observation.locks.build.exists, false);
    assert.equal(observation.retry.refused, true);
    assert.equal(negative.consumerRole, 'immutable baseline only; executing copy is explicitly derived');
    assert.equal(negative.derivation.changedResource.path, 'Contents/Resources/browser/metadata.json');
    result.scenarios.push({ id: 'sealed-resource-copy-refusal', status: 'passed', record: join(fixtures.directory, 'sealed-resource-refusal/launch-result.json'),
      derivation: { path: variant.manifest.path, sha256: variant.manifest.sha256, changedResource: variant.changedResource },
      signatureRefusal: { status: signature.status, stderr: signature.stderr }, observation });
    const frozen = await prepareNativeTrustVariant(fixtures, join(fixtures.directory, 'frozen-trust-copy.app'), { kind: 'frozen-trust' });
    const frozenOutput = join(fixtures.directory, 'frozen-trust-refusal');
    const drift = await launchNativeFixture(fixtures, { mode: 'frozen-trust', output: frozenOutput, variant: frozen });
    const driftEvents = stages(drift);
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
    const mismatch = await prepareNativeTrustVariant(fixtures, join(fixtures.directory, 'provider-mismatch-copy.app'),
      { kind: 'provider-mismatch' });
    const mismatchOutput = join(fixtures.directory, 'provider-mismatch-refusal');
    const refusedProvider = await launchNativeFixture(fixtures, { mode: 'provider-mismatch', output: mismatchOutput, variant: mismatch });
    const providerEvents = stages(refusedProvider);
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
