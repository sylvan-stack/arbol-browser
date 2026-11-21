import { execFile } from 'node:child_process';
import { readFile, lstat, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { assert, cli, success, create, open, runtime, closes, save, family, delay, loopback, until, agent, tool, listeners, load } from '../support/control.mjs';
import { snapshot } from '../support/foundation.mjs';

const run = promisify(execFile);

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

async function retainedEngineStages(c, original, started, finished) {
  const { stdout: uuidReport } = await run('/usr/bin/dwarfdump', ['--uuid', join(c.payload, 'native/platform.node')]);
  const uuid = /^UUID: ([a-f0-9-]{36}) \(arm64\) /im.exec(uuidReport)?.[1].toLowerCase();
  assert.ok(uuid, 'No arm64 UUID for the sealed platform addon');
  const prefix = 'arbol-browser retained-stage ';
  const predicate = `processIdentifier == ${original.pid} AND eventMessage BEGINSWITH "${prefix}"`;
  let stages = [];
  for (let attempt = 0; attempt < 3; ++attempt) {
    const { stdout } = await run('/usr/bin/log', ['show', '--style', 'ndjson', '--last', '3m', '--predicate', predicate],
      { timeout: 5000, maxBuffer: 1024 * 1024 });
    stages = stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)).filter(row => {
      const time = Date.parse(row.timestamp?.replace(' ', 'T'));
      // Unified Log may reuse an image path from another load of an identical
      // Mach-O. Match its image UUID and the independently sampled PID/birth.
      return row.processID === original.pid && row.userID === original.uid && row.senderImageUUID?.toLowerCase() === uuid &&
        time >= started && time <= finished && row.eventMessage?.startsWith(prefix);
    }).map(row => ({ at: row.timestamp, name: row.eventMessage.slice(prefix.length), imageUUID: uuid }));
    if (stages.some(stage => stage.name === 'marker-read')) break;
    await delay(150);
  }
  return stages;
}

async function refusedUnmanagedEngine(c, platform) {
  const [{ readProfile }, { profilePaths }, { readRuntime, runtimeLocation }] = await Promise.all([
    load(c, 'profiles/records'), load(c, 'profiles/paths'), load(c, 'runtime/instance'),
  ]);
  const profile = 'control-reader-unmanaged-data';
  await create(c, profile);
  const paths = profilePaths(profile, c.state), original = await readProfile(paths);
  await writeFile(join(paths.data, 'reader-fixture'), 'fictional unmanaged data\n', { mode: 0o600, flag: 'wx' });
  const before = await snapshot(paths.root), started = Date.now();
  const identities = new Map();
  let finished = false;
  const attempt = cli(c, ['open', '--profile', profile]).finally(() => { finished = true; });
  const observe = async () => {
    const executable = join(c.payload, 'runtime/Electron.app/Contents/MacOS/Electron');
    while (!finished) {
      const location = await runtimeLocation(original);
      const record = location && await readRuntime(location);
      if (record) {
        const identity = platform.processProvenance(record.pid);
        if (identity?.startId === record.processStartId && identity.uid === process.getuid() && identity.executable === executable)
          identities.set(identity.startId, { identity, phase: record.phase });
      }
      await delay(75);
    }
  };
  const [result] = await Promise.all([attempt, observe()]);
  const after = await snapshot(paths.root), births = [...identities.values()];
  const stages = births.length === 1 ? await retainedEngineStages(c, births[0].identity, started, Date.now()) : [];
  await save(join(c.output, 'unmanaged-engine-refusal.json'), { profile, before, after, births, stages, result });
  assert.equal(result.status, 4, JSON.stringify(result));
  assert.ok(['browser_unavailable', 'profile_unavailable'].includes(result.value?.error?.code), JSON.stringify(result));
  assert.deepEqual(after, before, 'Reader refusal changed the unmanaged profile data');
  const location = await runtimeLocation(original);
  if (location) for (const socket of [location.agent, location.management]) await assert.rejects(lstat(socket), { code: 'ENOENT' });
  assert.deepEqual(await family(c, 'reader-unmanaged-after'), [], 'Refused original retained a package process');
  // Preserve the deliberately unmanaged fixture once the exact family is gone.
  c.profiles.delete(profile);
  assert.equal(births.length, 1, 'Exact refused original process was not observed');
  const [{ identity, phase }] = births;
  assert.equal(phase, 'starting');
  assert.notEqual(platform.processIdentity(identity.pid)?.startId, identity.startId);
  const names = stages.map(stage => stage.name);
  assert.ok(names.includes('fresh-marker-compatibility'), 'Refusal did not demonstrably reach the fresh reader transaction');
  for (const forbidden of ['verified-prior-exit', 'native-marker-permit', 'host-session-configure-before', 'host-session-configure-after'])
    assert.ok(!names.includes(forbidden), `Reader refusal reached ${forbidden}`);
}

export async function controlProfilePersistence(c) {
  const left = 'control-session-left', right = 'control-session-right';
  await create(c, left); await create(c, right);
  const page = await loopback(c);
  try {
    const leftStarted = Date.now();
    const a = await open(c, left, page.url('left-seed', 'left-fictional'));
    const b = await open(c, right, page.url('right-seed', 'right-fictional'));
    assert.notEqual(a.process, b.process); assert.notEqual(a.instance, b.instance);
    const seeded = await until(() => page.observations.length >= 2 && [...page.observations]);
    for (const [name, value] of [['left-seed', 'left-fictional'], ['right-seed', 'right-fictional']]) {
      const row = seeded.find(o => o.name === name); assert.ok(row); assert.equal(row.stored, value); assert.equal(row.cookie, 'fictional=' + value);
    }
    const ar = await runtime(c, left), br = await runtime(c, right);
    const engineStages = await retainedEngineStages(c, ar.identity, leftStarted, Date.now());
    for (const stage of ['marker-read', 'native-marker-permit', 'host-session-configure-after'])
      assert.ok(engineStages.some(row => row.name === stage), `Allowed reader was not observed at ${stage}`);
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
    await save(join(c.output, 'observations.json'), { a, b, firstIdentities: [ar.identity, br.identity], engineStages, data: page.observations,
      dirtyRecovery: 'unavailable: no admitted force-close oracle' });
    for (const peer of c.peers) peer.close();
    await closes(c, left); await closes(c, right);
    await refusedUnmanagedEngine(c, ar.platform);
    return { boundary: 'two actual persistent website Sessions, clean restart and unmanaged storage refusal',
      incompatibleWriter: 'unavailable: exact separately signed prior writer needed', dirtyRecovery: 'unavailable' };
  } finally { await page.close(); }
}

async function closeFamily(c, platform, original, label) {
  const candidates = (await family(c, label)).map(line => platform.processProvenance(Number(line.trim().split(/\s+/)[0])))
    .filter(value => value && value.executable.startsWith(c.payload + '/'));
  const descendants = new Map([[original.startId, original]]);
  let previousSize;
  do {
    previousSize = descendants.size;
    for (const candidate of candidates) {
      const parent = descendants.get(candidate.parentStartId);
      if (candidate.group === original.group || parent?.pidVersion === candidate.parentPidVersion)
        descendants.set(candidate.startId, candidate);
    }
  } while (descendants.size !== previousSize);
  return candidates.filter(value => descendants.has(value.startId));
}

export async function controlCompleteClose(c) {
  const profile = 'control-complete-close'; await create(c, profile);
  const page = await loopback(c), samples = [];
  try {
    await open(c, profile, page.url('close-seed', 'close-fictional'));
    await until(() => page.observations.some(o => o.name === 'close-seed'));
    const r = await runtime(c, profile), markerPath = join(c.state, 'profiles', profile, 'engine.json');
    assert.equal(JSON.parse(await readFile(markerPath)).cleanExit, false);
    const anchor = r.platform.processProvenance(r.record.pid);
    assert.equal(anchor?.startId, r.record.processStartId, 'Close must observe the current named profile original');
    const baseline = await closeFamily(c, r.platform, anchor, 'before-close');
    const originals = baseline.map(identity => {
      const role = identity.startId === anchor.startId ? 'main' : identity.executable === c.payload + '/native/watchdog' ? 'monitor' :
        identity.executable.startsWith(c.payload + '/runtime/Electron.app/') ? 'engine-helper' : 'unknown';
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
    assert.deepEqual(await closeFamily(c, r.platform, anchor, 'after-close'), []);
    for (const original of originals) assert.notEqual(r.platform.processIdentity(original.pid)?.startId, original.startId);
    await open(c, profile, page.url('close-restored'));
    const restored = await until(() => page.observations.find(o => o.name === 'close-restored'));
    assert.equal(restored.stored, 'close-fictional'); assert.equal(restored.cookie, 'fictional=close-fictional');
    await save(join(c.output, 'observations.json'), { result, originals, samples, restored,
      scope: 'Main/engine helpers must disappear before clean. Genuine final monitor may publish clean while retaining original guards, then every original must disappear before CLI success. Samples do not claim continuous pre-baseline confinement or genuine lost-ACK proof.' });
    return { boundary: 'actual normal close, sampled originals, clean publication and persistent restart', lostAcknowledgement: 'unavailable' };
  } finally { await save(join(c.output, 'close-samples.json'), samples); await page.close(); }
}
