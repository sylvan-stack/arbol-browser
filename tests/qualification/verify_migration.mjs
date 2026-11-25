/** Explicit AFM-9 case scheduler. Importing executes nothing. A partial result
 * never constitutes the complete D44 gate or installed production evidence. */
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, chmod, lstat, readdir } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { canonical, exactFile, json, privateDirectory } from '../../scripts/package-host.mjs';
import { verifyIsolatedRelease } from '../../scripts/isolated-release.mjs';
import { installIsolatedRelease } from '../../scripts/install-release.mjs';
import { inventory } from '../../scripts/package-base.mjs';
import { assertFixture, authenticateInputs, evidence, harnessIdentity, metadataSnapshot, recordedChild } from '../support/migration-fixture.mjs';
import { loopback, until, family } from '../support/control.mjs';

const self = fileURLToPath(import.meta.url);
const groups = {
  preservation: ['default', 'alternate', 'bound', 'never-opened', 'empty-registry', 'absent-root',
    'normal-format2-creation', 'creation-replay', 'native-js-digest-parity'],
  admission: ['installed-authority', 'sibling-authority', 'runtime-mismatch', 'selection-mismatch',
    'replaced-profile', 'replaced-file', 'replaced-root', 'symlink', 'unknown-format', 'malformed-json',
    'duplicate-key', 'mixed-pair', 'incompatible-dirty-engine', 'busy-owner', 'busy-native', 'legacy-65536-boundary'],
  writers: ['stable', 'pinned', 'direct-historical-payload', 'rehearsal', 'stale-selection', 'delayed-start',
    'pending-start', 'surviving-helper', 'concurrent-create', 'concurrent-remove', 'empty-registry-create'],
  recovery: ['before-transaction', 'transaction-publication', 'current-publication', 'native-rename-excl',
    'empty-staging', 'partial-staging', 'staged-progress', 'marker-rename', 'record-rename', 'capture-receipt',
    'committed-progress', 'completion', 'final-verification', 'reopening', 'selection', 'journal-removal',
    'same-input-twice', 'mismatched-input-twice', 'completed-retry', 'old-old', 'old-record-new-marker',
    'fully-published', 'absent-marker', 'zero-profile', 'absent-root', 'unknown-chain', 'substituted-chain',
    'unlisted-profile', 'new-record-old-marker', 'incomplete-proof'],
  archives: ['mercury-original-backup', 'unavailable-archive', 'old-payload-pruning', 'copied-receipt',
    'replayed-receipt', 'substituted-receipt', 'superseded-receipt'],
  rollback: ['compatible-pre-journal-backup', 'compatible-update', 'format2-rollback', 'format1-refusal', 'forward-catalog'],
  binding: ['original-active', 'creation-replay', 'retired', 'replaced', 'ambiguous', 'unavailable', 'needs-rebind', 'known-restore'],
  installed: ['exact-image', 'selected-build', 'info', 'inventory-count', 'list', 'creation-replay', 'old-writer', 'catalog'],
};
export const caseInventory = Object.freeze(Object.entries(groups).flatMap(([group, names]) => names.map(name => ({
  id: `${group}/${name}`, group,
  oracle: group === 'preservation' ? 'Independent metadata identities, exact preserved values and page-visible fictional state where applicable' :
    group === 'admission' || group === 'writers' ? 'Named route reaches its intended refusal with unchanged metadata and native data-directory identity' :
    group === 'recovery' ? 'Authenticated exact durable boundary, real process death, original chain and two exact/mismatched retries' :
    group === 'archives' ? 'Actual Mercury identity and original backup or native rederived receipt proof' :
    group === 'rollback' ? 'Accepted shared dispatcher with authentic selected history, distinct eligible sources and retained images' :
    group === 'binding' ? 'Supported external authority with redacted tuple equality/disposition' : 'Ordinary installed signed entry and exact catalog agreement',
  dependency: group === 'binding' ? 'ABR17–19 external authority and known-restore' :
    group === 'rollback' ? 'AFM-9 step5.1.6 accepted shared dispatcher and exact source grants' :
    group === 'installed' ? 'All applicable signed disposable gates and coordinated closed installation' :
    group === 'recovery' ? 'Exact isolated observation/coordination mechanism; polling is insufficient' :
    'Exact signed fixture and case-specific preparation; unscheduled until independently reviewed',
}))));

async function authenticatedFixture(record, artifact) {
  const release = await verifyIsolatedRelease(artifact.options), layout = await assertFixture(record, release.build);
  assert.equal(canonical(release.fixture), canonical(layout));
  for (const key of ['build', 'source', 'productDigest', 'profileFormat', 'imageSha256', 'receiptSha256', 'payloadDigest'])
    assert.equal(release[key], artifact[key]);
  return release;
}

async function caseDirectory(record, name) {
  assert.match(name, /^[a-z][a-z0-9-]{0,70}$/);
  const directory = await mkdtemp(join(record.fixture, 'evidence', name + '-')); await chmod(directory, 0o700); return directory;
}

async function absent(path) {
  await assert.rejects(lstat(path), error => error.code === 'ENOENT');
}

/** Independent terminal observation only, never a native completion token. */
async function completionChain(record, artifact) {
  const release = await authenticatedFixture(record, artifact), layout = release.fixture;
  await absent(join(layout.fixture, 'support/install-transaction.json'));
  const selected = await json(join(layout.fixture, 'support/selected.json'));
  assert.deepEqual(selected.value, { format: 1, build: release.build, imageSha256: release.imageSha256 });
  const path = join(layout.runtime, 'browser-profile-migration');
  const current = await json(join(path, 'current'));
  assert.match(current.value.attempt, /^[0-9a-f]{32}$/);
  const transaction = await json(join(path, current.value.attempt, 'transaction.json'));
  const completed = await json(join(path, current.value.attempt, 'completed.json'));
  const proof = await json(join(layout.fixture, 'support/releases', release.build + '.migration.json'));
  assert.equal(transaction.sha256, current.value.transactionSha256);
  assert.equal(transaction.value.attempt, current.value.attempt);
  assert.equal(transaction.value.root.path, layout.stateRoot);
  assert.equal(transaction.value.sourceSha256, release.sourceDigest);
  assert.equal(transaction.value.productSha256, release.productDigest);
  assert.equal(completed.value.attempt, current.value.attempt);
  assert.equal(completed.value.transactionSha256, transaction.sha256);
  assert.equal(proof.value.kind, 'browser-profile-migration-reopen');
  assert.equal(proof.value.source.build, release.build); assert.equal(proof.value.source.git, release.source);
  assert.deepEqual(proof.value.after.selection, selected.value);
  assert.equal(proof.value.result.completionSha256, completed.sha256);
  assert.equal(proof.value.result.converted, transaction.value.profiles.length);
  assert.equal(proof.value.result.diagnostic, null); assert.deepEqual(proof.value.result.busy, []);
  const reference = file => ({ sha256: file.sha256, identity: file.identity, value: file.value });
  return { current: reference(current), transaction: reference(transaction), completed: reference(completed),
    proof: reference(proof), selected: reference(selected), files: await inventory(path), nativeAdmission: false };
}

async function preservationSnapshot(record, build) {
  const snapshot = await metadataSnapshot(record, build), layout = await assertFixture(record, build);
  for (const row of snapshot.profiles)
    row.userData = await privateDirectory(join(layout.stateRoot, 'profiles', row.id, 'userData'), true);
  return snapshot;
}

async function assertNeverOpened(record, build, snapshot, id) {
  const profile = snapshot.profiles.find(row => row.id === id);
  assert.ok(profile, 'Expected the original never-opened profile');
  assert.equal(profile['engine.json'], null);
  const layout = await assertFixture(record, build);
  const directory = join(layout.stateRoot, 'profiles', id);
  for (const name of ['data', 'userData', 'logs']) {
    const path = join(directory, name);
    await privateDirectory(path, true);
    assert.deepEqual(await readdir(path), [], `Never-opened profile has entries in ${name}`);
  }
  return profile;
}

/** Real shared installer in a separate process; input is reauthenticated by
 * the production-owned isolated factory, not a fixture-supplied verdict. */
export async function installerAttempt(record, artifact, predecessors = []) {
  await authenticatedFixture(record, artifact);
  for (const predecessor of predecessors) await authenticatedFixture(record, predecessor);
  const directory = await caseDirectory(record, 'installer');
  const input = await evidence(directory, 'input', { ...artifact.options, predecessors: predecessors.map(row => row.options) });
  const result = await recordedChild(directory, 'installer', process.execPath, [self, '--installer-worker', input.path], { timeout: 32 * 60 * 1000 });
  assert.equal(result.complete, true); assert.equal(result.exceeded, false);
  assert.equal(result.status, 0, 'Real installer failed; preserve its result and closed state');
  const value = JSON.parse(result.stdout);
  await authenticatedFixture(record, artifact); return { directory, value };
}

/** Selection is only a hint to the actual signed package and original guard.
 * Native/signed authority is obtained by the normal product implementation. */
async function cli(record, artifact, directory, name, args) {
  const layout = await assertFixture(record, artifact.build);
  const selected = (await json(join(layout.fixture, 'support/selected.json'))).value;
  assert.deepEqual(selected, { format: 1, build: artifact.build, imageSha256: artifact.imageSha256 });
  const guard = join(layout.registry, '.uses', artifact.build), st = await lstat(guard);
  assert.ok(st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && st.uid === process.getuid() && (st.mode & 0o7777) === 0o600);
  const selection = { format: 1, build: artifact.build, explicit: true, directory: dirname(dirname(layout.bundle)), guard };
  const result = await recordedChild(directory, name, join(layout.bundle, 'Contents/Resources/browser/bin/arbol-browser'), args,
    { env: { PATH: '/usr/bin:/bin', ARBOL_BROWSER_SELECTION: JSON.stringify(selection) }, timeout: 90000 });
  assert.ok(result.complete && !result.exceeded); assert.equal(result.status, 0, 'Normal signed CLI refused; inspect retained result');
  const lines = result.stdout.trim().split('\n'); assert.equal(lines.length, 1);
  return JSON.parse(lines[0]);
}

async function context(record, artifact, name) {
  await authenticatedFixture(record, artifact);
  const output = await caseDirectory(record, name), harness = await harnessIdentity(), inputs = await authenticateInputs(artifact.options.review);
  await evidence(output, 'identity', { artifact, harness, inputs, inventory: caseInventory });
  return { output, harness, inputs };
}
async function finishCase(record, artifact, c, passed, result) {
  assert.deepEqual(await harnessIdentity(), c.harness);
  assert.deepEqual(await authenticateInputs(artifact.options.review), c.inputs);
  await authenticatedFixture(record, artifact);
  const coverage = caseInventory.map(row => ({ ...row, status: passed.includes(row.id) ? 'observed-pass' : 'unqualified' }));
  return evidence(c.output, 'result', { result, coverage, scope: 'Only named disposable cases; AFM-9 incomplete' });
}

export async function absentRootJourney(record, artifact) {
  const c = await context(record, artifact, 'absent-root');
  try {
    assert.equal(artifact.profileFormat, 2);
    const before = await metadataSnapshot(record, artifact.build); assert.equal(before.root, null);
    for (const name of ['support/selected.json', 'support/install-transaction.json',
      `support/releases/${artifact.build}.migration.json`, 'runtime/browser-profile-migration/current'])
      await absent(join(record.fixture, name));
    await evidence(c.output, 'before', before);
    const installed = await installerAttempt(record, artifact);
    const chain = await completionChain(record, artifact);
    assert.equal(chain.transaction.value.root.initial, 'absent');
    assert.deepEqual(chain.transaction.value.profiles, []); assert.equal(chain.proof.value.result.converted, 0);
    assert.equal(chain.proof.value.before, null); await evidence(c.output, 'completion-chain', chain);
    const after = await metadataSnapshot(record, artifact.build); assert.equal(after.root, null);
    const info = await cli(record, artifact, c.output, 'info', ['info']); assert.equal(info.profileFormat, 2);
    const list = await cli(record, artifact, c.output, 'list', ['profiles', 'list']); assert.deepEqual(list.profiles, []);
    assert.deepEqual(await metadataSnapshot(record, artifact.build), after);
    await evidence(c.output, 'after', after);
    return await finishCase(record, artifact, c, ['preservation/absent-root'], { installed, info, count: list.profiles.length });
  } catch (error) { await evidence(c.output, 'failure', { error: String(error.stack ?? error), status: 'failed-or-unqualified' }); throw error; }
}

export async function creationReplayJourney(record, artifact) {
  const c = await context(record, artifact, 'creation-replay');
  try {
    const request = 'create_' + randomBytes(16).toString('base64url'), profile = 'afm9-' + randomBytes(8).toString('hex');
    const created = await cli(record, artifact, c.output, 'create', ['profiles', 'create', profile, '--creation-request', request]);
    const before = await metadataSnapshot(record, artifact.build);
    const row = before.profiles.find(item => item.id === profile); assert.ok(row); assert.equal(row['engine.json'], null);
    assert.equal(row['profile.json'].value.format, 2); assert.equal(row['profile.json'].value.creationRequest, request);
    assert.equal(created.created, true);
    const replay = await cli(record, artifact, c.output, 'replay', ['profiles', 'create', profile, '--creation-request', request]);
    assert.equal(replay.created, false); assert.equal(replay.profile.instance, created.profile.instance);
    assert.deepEqual(replay.profile, created.profile); assert.equal(created.profile.instance, row['profile.json'].value.instance);
    const after = await metadataSnapshot(record, artifact.build); assert.deepEqual(after, before);
    await evidence(c.output, 'metadata', { before, after });
    return await finishCase(record, artifact, c, ['preservation/normal-format2-creation', 'preservation/creation-replay'], { created, replay });
  } catch (error) { await evidence(c.output, 'failure', { error: String(error.stack ?? error), status: 'failed-or-unqualified' }); throw error; }
}

export async function completedRetryJourney(record, artifact, predecessors = []) {
  const c = await context(record, artifact, 'completed-retry');
  try {
    const before = await metadataSnapshot(record, artifact.build), chain = await completionChain(record, artifact), attempts = [];
    await evidence(c.output, 'completed-start', chain);
    for (let i = 0; i < 2; i++) {
      attempts.push(await installerAttempt(record, artifact, predecessors));
      assert.deepEqual(await completionChain(record, artifact), chain);
    }
    const after = await metadataSnapshot(record, artifact.build); assert.deepEqual(after, before);
    await evidence(c.output, 'metadata', { before, after });
    return await finishCase(record, artifact, c, ['recovery/completed-retry'], { attempts });
  } catch (error) { await evidence(c.output, 'failure', { error: String(error.stack ?? error), status: 'failed-or-unqualified' }); throw error; }
}

/** Requires separately authenticated actual historical selection first. The
 * same loopback origin survives conversion, preserving the storage oracle. */
export async function populatedPreservationJourney(record, predecessor, successor) {
  const c = await context(record, successor, 'populated-preservation');
  await authenticatedFixture(record, predecessor); assert.equal(predecessor.profileFormat, 1);
  const page = await loopback({ output: c.output });
  let selected = predecessor, sequence = 0, outcome;
  const profiles = ['default', 'afm9-alternate'];
  const neverOpened = 'afm9-never-opened';
  const call = args => cli(record, selected, c.output, 'page-' + (++sequence), args);
  const closed = async () => {
    for (const profile of profiles) await call(['close', '--profile', profile]);
    const buildRoot = dirname(dirname(record.layouts[selected.build].bundle));
    assert.deepEqual(await family({ buildRoot, output: c.output }, 'closed-' + sequence), []);
  };
  try {
    await call(['profiles', 'create', profiles[1]]);
    await call(['profiles', 'create', neverOpened]);
    for (const profile of profiles) await call(['open', '--profile', profile, '--url', page.url(profile + '-seed', profile + '-fictional')]);
    await until(() => profiles.every(profile => page.observations.some(row => row.name === profile + '-seed' &&
      row.stored === profile + '-fictional' && row.cookie === 'fictional=' + profile + '-fictional')));
    await closed();
    const before = await preservationSnapshot(record, predecessor.build);
    await assertNeverOpened(record, predecessor.build, before, neverOpened);
    await evidence(c.output, 'before', before);
    await installerAttempt(record, successor, [predecessor]); selected = successor;
    const after = await preservationSnapshot(record, successor.build);
    const unopenedAfter = await assertNeverOpened(record, successor.build, after, neverOpened);
    assert.deepEqual(after.profiles.map(row => row.id), before.profiles.map(row => row.id));
    for (let i = 0; i < before.profiles.length; i++) {
      const a = before.profiles[i], b = after.profiles[i]; assert.deepEqual(a.directory, b.directory); assert.deepEqual(a.data, b.data);
      assert.deepEqual(a.userData, b.userData);
      const records = a.id === neverOpened ? ['profile.json'] : ['profile.json', 'engine.json'];
      for (const name of records) {
        assert.ok(a[name] && b[name]); assert.equal(a[name].value.format, 1); assert.equal(b[name].value.format, 2);
        assert.deepEqual({ ...a[name].value, format: 2 }, b[name].value);
      }
    }
    await evidence(c.output, 'converted-before-reopen', after);
    for (const profile of profiles) await call(['open', '--profile', profile, '--url', page.url(profile + '-restored')]);
    await until(() => profiles.every(profile => page.observations.some(row => row.name === profile + '-restored' &&
      row.stored === profile + '-fictional' && row.cookie === 'fictional=' + profile + '-fictional')));
    await closed();
    const settled = await preservationSnapshot(record, successor.build);
    assert.deepEqual(await assertNeverOpened(record, successor.build, settled, neverOpened), unopenedAfter);
    outcome = { pageObservations: page.observations, neverOpenedPreserved: true };
  } catch (error) { await evidence(c.output, 'failure', { error: String(error.stack ?? error), status: 'failed-or-unqualified' }); throw error; }
  finally {
    // Actual supported close only. Never reinterpret a failed close as success.
    try { await closed(); } finally { await page.close(); }
  }
  return finishCase(record, successor, c,
    ['preservation/default', 'preservation/alternate', 'preservation/never-opened'], outcome);
}

if (process.argv[1] && resolve(process.argv[1]) === self) {
  const [action, input, ...extra] = process.argv.slice(2);
  assert.equal(action, '--installer-worker'); assert.equal(extra.length, 0);
  const options = (await json(resolve(input))).value;
  console.log(JSON.stringify(await installIsolatedRelease(options)));
}
