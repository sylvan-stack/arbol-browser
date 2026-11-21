import { readFile, lstat, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { assert, cli, success, create, open, runtime, closes, save, family, delay, loopback, until, agent, tool, listeners, load } from '../support/control.mjs';

async function waitingStarterRemoval(c, profile, runtimeBefore) {
  const { platform, location } = runtimeBefore;
  const original = location.profile, oldLock = await lstat(original.paths.owner);
  const [{ createOpenCommandObservation, verifyPackagedHost }, { createProductionProcessIntegration },
    { createProductionExitAuthority }, { createProcessService }] = await Promise.all([
    load(c, 'runtime/authorities'), load(c, 'runtime/process'), load(c, 'runtime/exit'), load(c, 'runtime/lifecycle'),
  ]);
  const cutoff = performance.now() + 60000;
  const host = await verifyPackagedHost(c.selection, c.payload, cutoff);
  const exits = createProductionExitAuthority(platform, c.selection, host);
  const observation = createOpenCommandObservation();
  const integration = createProductionProcessIntegration(host, c.selection, platform, exits, observation, cutoff);
  const starter = createProcessService({ selection: c.selection, state: c.state, platform: () => platform,
    integration, exits, observation, openCutoff: cutoff });
  const lockPath = join(location.leaf, 'startup.lock');
  const startup = platform.tryLock(lockPath);
  assert.ok(startup, 'Independent contender must own the original startup lock');
  const observed = [];
  let outcome;
  const waiter = starter.open({ profile }).then(value => { outcome = { value }; }, error => {
    outcome = { code: error.detail?.code, stage: observation.stage };
  });
  try {
    await until(() => {
      if (outcome) assert.fail('Starter returned before it reached contention');
      return observation.stage === 'open-startup-arbitration';
    }, Math.max(1, Math.floor(cutoff - performance.now() - 20000)));
    for (let i = 0; i < 3; ++i) {
      await delay(75);
      assert.equal(observation.stage, 'open-startup-arbitration');
      assert.equal(outcome, undefined);
      assert.equal(platform.tryLock(lockPath), null);
      const same = await lstat(original.paths.owner);
      assert.deepEqual([same.dev, same.ino], [oldLock.dev, oldLock.ino]);
      observed.push({ at: performance.now(), stage: observation.stage, lock: startup.assertIdentity() });
    }
    const removal = await cli(c, ['profiles', 'remove', profile, '--delete-data'], true);
    assert.match(removal.tty, /^\?+$/, 'Removal worker unexpectedly has a controlling terminal');
    assert.deepEqual(success(removal), { profile, dataRemoved: true });
    c.profiles.delete(profile);
    await assert.rejects(lstat(original.paths.root), { code: 'ENOENT' });
    const tombstones = [];
    for (const name of await readdir(original.paths.profiles)) {
      if (!/^\.deleting-[0-9a-f]{32}$/.test(name)) continue;
      const path = join(original.paths.profiles, name);
      const held = await lstat(join(path, 'owner.lock'));
      if (held.dev === oldLock.dev && held.ino === oldLock.ino) tombstones.push(path);
    }
    assert.equal(tombstones.length, 1);
    assert.deepEqual(await readdir(tombstones[0]), ['owner.lock']);
    await waiter;
    assert.ok(['profile_not_found', 'profile_unavailable'].includes(outcome?.code), JSON.stringify(outcome));
    assert.equal(outcome.stage, 'open-startup-arbitration');
    assert.deepEqual(await family(c, 'after-waiting-starter-removal'), []);
    await save(join(c.output, 'waiting-starter-removal.json'), { profile, original: original.record,
      owner: { device: oldLock.dev, inode: oldLock.ino }, observed, removal, tombstone: tombstones[0], outcome });
  } finally { startup.release(); await waiter; }
}

export async function controlStartupBoundary(c) {
  let absent; try { absent = await lstat(join(c.state, 'profiles/control-startup')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  assert.equal(absent, undefined);
  const before = await family(c, 'before-info');
  const info = success(await cli(c, ['info'])); assert.equal(info.stateDirectory, c.state); assert.equal(info.build, c.build);
  assert.deepEqual(await family(c, 'after-info'), before, 'info must not start a Browser');
  await assert.rejects(lstat(join(c.state, 'profiles/control-startup')), { code: 'ENOENT' });
  const profile = 'control-startup'; await create(c, profile);
  const results = await Promise.all([cli(c, ['open', '--profile', profile]), cli(c, ['open', '--profile', profile])]);
  const values = results.map(success); c.profiles.add(profile);
  assert.equal(values[0].instance, values[1].instance); assert.equal(values[0].process, values[1].process);
  assert.equal(values.filter(v => !v.alreadyRunning).length, 1, 'Exactly one original start must win');
  const r = await runtime(c, profile); assert.equal(r.record.phase, 'ready'); assert.equal(r.record.pid, values[0].process);
  const repeated = await open(c, profile); assert.equal(repeated.instance, r.record.instance); assert.equal(repeated.alreadyRunning, true);
  await listeners(c, r);
  const tree = await family(c, 'ready'); assert.ok(tree.length > 0);
  const result = await closes(c, profile);
  const noRestart = [];
  for (let i = 0; i < 6; ++i) {
    await delay(200);
    const identity = r.platform.processIdentity(r.record.pid);
    assert.notEqual(identity?.startId, r.identity.startId, 'Closed original remains alive');
    const current = await family(c, 'after-close-' + i); assert.deepEqual(current, [], 'A new package process implicitly restarted');
    const marker = JSON.parse(await readFile(r.location.record));
    assert.equal(marker.instance, r.record.instance); assert.notEqual(marker.phase, 'ready');
    noRestart.push({ monotonic: performance.now(), originalIdentity: identity, current, runtime: marker });
  }
  await save(join(c.output, 'observations.json'), { info, values, repeated, identity: r.identity, record: r.record, tree, result, noRestart });
  await waitingStarterRemoval(c, profile, r);
  return { boundary: 'actual sealed CLI Building allocation and single original arbitration', authenticFailedLaunchReplay: 'unavailable' };
}

export async function controlProfilePersistence(c) {
  const left = 'control-session-left', right = 'control-session-right';
  await create(c, left); await create(c, right);
  const page = await loopback(c);
  try {
    const a = await open(c, left, page.url('left-seed', 'left-fictional'));
    const b = await open(c, right, page.url('right-seed', 'right-fictional'));
    assert.notEqual(a.process, b.process); assert.notEqual(a.instance, b.instance);
    const seeded = await until(() => page.observations.length >= 2 && [...page.observations]);
    for (const [name, value] of [['left-seed', 'left-fictional'], ['right-seed', 'right-fictional']]) {
      const row = seeded.find(o => o.name === name); assert.ok(row); assert.equal(row.stored, value); assert.equal(row.cookie, 'fictional=' + value);
    }
    const ar = await runtime(c, left), br = await runtime(c, right);
    assert.notEqual(ar.location.agent, br.location.agent); assert.notEqual(ar.identity.startId + ':' + ar.identity.pid, br.identity.startId + ':' + br.identity.pid);
    await closes(c, left); await closes(c, right);
    for (const profile of [left, right]) assert.equal(JSON.parse(await readFile(join(c.state, 'profiles', profile, 'engine.json'))).cleanExit, true);
    await open(c, left, page.url('left-restored')); await open(c, right, page.url('right-restored'));
    await until(() => page.observations.some(o => o.name === 'left-restored') && page.observations.some(o => o.name === 'right-restored'));
    for (const [profile, name, value] of [[left, 'left-restored', 'left-fictional'], [right, 'right-restored', 'right-fictional']]) {
      const row = page.observations.find(o => o.name === name); assert.equal(row.stored, value); assert.equal(row.cookie, 'fictional=' + value);
      const peer = await agent(c, profile, 'fictional restart observer');
      assert.deepEqual((await tool(peer, 'browser_tabs_list')).tabs, [], 'Restart must not restore old grants');
    }
    await save(join(c.output, 'observations.json'), { a, b, firstIdentities: [ar.identity, br.identity], data: page.observations,
      dirtyRecovery: 'unavailable: no admitted engine transaction/force-close oracle' });
    return { boundary: 'two actual persistent website Sessions and clean restart', dirtyRecovery: 'unavailable' };
  } finally { await page.close(); }
}

export async function controlCompleteClose(c) {
  const profile = 'control-complete-close'; await create(c, profile);
  const page = await loopback(c), samples = [];
  try {
    await open(c, profile, page.url('close-seed', 'close-fictional'));
    await until(() => page.observations.some(o => o.name === 'close-seed'));
    const r = await runtime(c, profile), markerPath = join(c.state, 'profiles', profile, 'engine.json');
    assert.equal(JSON.parse(await readFile(markerPath)).cleanExit, false);
    const baseline = await family(c, 'before-close');
    const originals = baseline.map(line => {
      const pid = Number(line.trim().split(/\s+/)[0]), identity = r.platform.processIdentity(pid);
      assert.ok(identity, 'Baseline process disappeared before exact identity was captured');
      const role = pid === r.record.pid ? 'main' : line.includes(c.payload + '/native/watchdog') ? 'monitor' :
        line.includes(c.payload + '/runtime/Electron.app/') ? 'engine-helper' : 'unknown';
      assert.notEqual(role, 'unknown', 'Unclassified original cannot support complete close proof');
      return { ...identity, role };
    });
    assert.ok(originals.some(p => p.pid === r.record.pid)); assert.ok(originals.length > 1, 'No owned helper/monitor baseline observed');
    let done = false;
    let observerError;
    const observer = (async () => {
      do {
        const marker = JSON.parse(await readFile(markerPath));
        const live = originals.filter(p => { const now = r.platform.processIdentity(p.pid); return now?.startId === p.startId && now.uid === p.uid; });
        const row = { monotonic: performance.now(), clean: marker.cleanExit, live }; samples.push(row);
        if (marker.cleanExit) assert.deepEqual(live.filter(p => p.role !== 'monitor'), [], 'Clean marker observed before original main/engine helper disappearance');
        await delay(15);
      } while (!done);
    })().catch(error => { observerError = String(error.stack ?? error); });
    let result;
    try { result = await closes(c, profile); } finally { done = true; await observer; }
    assert.equal(observerError, undefined, observerError);
    assert.equal(result.closed, true); assert.equal(JSON.parse(await readFile(markerPath)).cleanExit, true);
    assert.deepEqual(await family(c, 'after-close'), []);
    for (const original of originals) assert.notEqual(r.platform.processIdentity(original.pid)?.startId, original.startId);
    await open(c, profile, page.url('close-restored'));
    const restored = await until(() => page.observations.find(o => o.name === 'close-restored'));
    assert.equal(restored.stored, 'close-fictional'); assert.equal(restored.cookie, 'fictional=close-fictional');
    await save(join(c.output, 'observations.json'), { result, originals, samples, restored,
      scope: 'Main/engine helpers must disappear before clean. Genuine final monitor may publish clean while retaining original guards, then every original must disappear before CLI success. Samples do not claim continuous pre-baseline confinement or genuine lost-ACK proof.' });
    return { boundary: 'actual normal close, sampled originals, clean publication and persistent restart', lostAcknowledgement: 'unavailable' };
  } finally { await save(join(c.output, 'close-samples.json'), samples); await page.close(); }
}
