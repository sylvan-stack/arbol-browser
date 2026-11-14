import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { assert, fixture, cli, load, privateDirectory, snapshot, worker, refused } from '../support/foundation.mjs';

export async function ownershipBoundary(context) {
  const f = await fixture(context, 'ownership');
  assert.equal((await cli(f, ['profiles', 'create', 'slow-owner'])).status, 0);
  assert.equal((await cli(f, ['profiles', 'create', 'contended'])).status, 0);
  const { loadPlatform } = await load(f, 'runtime/platform'), platform = loadPlatform();
  const { readProfile } = await load(f, 'profiles/records');
  const { profilePaths } = await load(f, 'profiles/paths');
  const { now, acquireInstance, neverOpenedExit, runtimeLocation, startupArbitration } = await load(f, 'runtime/instance');
  const profile = await readProfile(profilePaths('slow-owner', f.state));
  const owner = await worker(f, 'owner', { profile: 'slow-owner', state: f.state, build: 'a' });
  try {
    const before = await snapshot(owner.ready.runtime);
    assert.equal(await acquireInstance(profile, platform, 'b', neverOpenedExit, now() + 500), null);
    refused(await cli(f, ['close', '--profile', 'slow-owner']), 4, 'browser_unavailable');
    assert.ok(platform.processIdentity(owner.ready.pid), 'A slow live owner was killed');
    assert.deepEqual(await snapshot(owner.ready.runtime), before);
  } finally { await owner.stop(); }
  assert.equal(platform.processIdentity(owner.ready.pid), null);
  const stale = await snapshot(owner.ready.runtime);
  await assert.rejects(acquireInstance(profile, platform, 'b', neverOpenedExit, now() + 500));
  assert.deepEqual(await snapshot(owner.ready.runtime), stale, 'Main death cannot license stale cleanup without helper evidence');

  const component = await privateDirectory(join(f.root, 'registry/arbol-browser'));
  const directory = await privateDirectory(join(component, 'a'));
  await privateDirectory(join(component, '.uses'));
  const guard = join(component, '.uses/a'); await writeFile(guard, '', { mode: 0o600 });
  const selection = { build: 'a', directory, guard, explicit: false };
  const p = await readProfile(profilePaths('contended', f.state));
  const location = await runtimeLocation(p, true);
  const startup = await startupArbitration(location, platform, now() + 1000);
  let starters;
  try {
    starters = await Promise.all([worker(f, 'starter', { profile: p.record.id, state: f.state, selection }),
      worker(f, 'starter', { profile: p.record.id, state: f.state, selection })]);
    await Promise.all(starters.map(child => child.done));
    assert.ok(starters.every(child => child.ready.launches === 0 && child.ready.elapsed < 2000));
    assert.equal((await snapshot(location.leaf))['./runtime.json'], undefined);
  } finally { startup.release(); }
  const first = await worker(f, 'lease', { selection });
  const second = await worker(f, 'lease', { selection });
  try {
    assert.equal(platform.tryLock(guard), null, 'Exclusive pruner passed two independent shared guards');
    await first.stop();
    assert.equal(platform.tryLock(guard), null, 'One process releasing removed another guard');
  } finally { await first.stop(); await second.stop(); }
  const exclusive = platform.tryLock(guard); assert.ok(exclusive); exclusive.release();
  return { liveOwnerPreserved: true, staleMainRefused: true,
    starterModuleWorkers: starters.map(child => child.ready), independentBuildGuards: 2,
    successfulCliStartup: 'unavailable: production native/control authorities absent' };
}

export async function closeAcquisitionBoundary(context) {
  const { deadlineLifecycle } = await import('../support/foundation-deadlines.mjs');
  const { bounded } = await import('../support/foundation.mjs');
  const f = await fixture(context, 'close-acquisitions');
  const { loadPlatform } = await load(f, 'runtime/platform'), platform = loadPlatform();
  const { readProfile } = await load(f, 'profiles/records');
  const { profilePaths } = await load(f, 'profiles/paths');
  const { now, acquireInstance, neverOpenedExit } = await load(f, 'runtime/instance');
  const { listenTransport } = await load(f, 'runtime/transport');
  const { unavailable } = await load(f, 'contracts/errors');
  const selection = { build: 'a', explicit: false, directory: context.candidate, guard: '' };
  // No test provider claims complete shutdown, helper census or flush evidence.
  const exits = Object.freeze({ async assertCensus() { throw unavailable('browser'); },
    async assertExited() { throw unavailable('browser'); }, async force() { throw unavailable('browser'); } });
  const rejected = result => { assert.equal(result.ok, false, 'Faulted close returned success');
    assert.ok(['browser_unavailable', 'profile_unavailable'].includes(result.error?.detail?.code)); };
  const outcome = promise => promise.then(value => ({ ok: true, value }), error => ({ ok: false, error }));
  async function probe(path, expected) {
    const other = await worker(f, 'lock-probe', { path });
    try { assert.equal(other.ready.acquired, expected, `Independent kernel contender expected acquired=${expected}`); }
    finally { await other.stop(); }
  }
  const evidence = [];
  for (const branch of ['absent', 'dead']) {
    for (const mode of ['late', 'post-wait', 'transfer', 'ordinary', 'reject']) {
      const id = `${branch}-${mode}`;
      assert.equal((await cli(f, ['profiles', 'create', id])).status, 0);
      const profile = await readProfile(profilePaths(id, f.state));
      if (branch === 'dead') {
        const old = await worker(f, 'owner', { profile: id, state: f.state, build: 'a' });
        await old.stop(); assert.equal(platform.processIdentity(old.ready.pid), null);
      }
      const before = await snapshot(profile.paths.root);
      const seam = await deadlineLifecycle(f, 'lock', mode);
      try {
        const pending = outcome(seam.closeProfile(profile, selection, platform,
          branch === 'dead' ? exits : undefined, now() + (mode === 'late' ? 1500 : 10000)));
        if (mode !== 'reject') {
          await seam.acquired();
          await probe(profile.paths.owner, false);
          if (mode === 'late') rejected(await bounded(pending, 3000));
          seam.settle();
        }
        const result = await bounded(pending, 3000);
        if (mode === 'ordinary' && branch === 'absent') {
          assert.equal(result.ok, true); assert.equal(result.value.closed, false);
        } else rejected(result);
        // Strong lease references and this host remain alive during observation.
        await new Promise(resolve => setImmediate(resolve));
        await probe(profile.paths.owner, true);
        assert.deepEqual(await snapshot(profile.paths.root), before);
        evidence.push({ resource: 'kernel-owner', branch, mode, cleanupBeforeHostExit: true,
          retainedResourceReferences: seam.resources.length, postAcquisitionChecks: seam.clockChecks });
      } finally { await seam.cleanup(); }
    }
  }
  for (const mode of ['late', 'post-wait', 'transfer', 'ordinary', 'reject']) {
    const id = `connection-${mode}`;
    assert.equal((await cli(f, ['profiles', 'create', id])).status, 0);
    const profile = await readProfile(profilePaths(id, f.state));
    const instance = await acquireInstance(profile, platform, 'a', neverOpenedExit, now() + 2000);
    assert.ok(instance);
    let disconnected, disconnects = 0, executions = 0;
    const observedDisconnect = new Promise(resolve => { disconnected = resolve; });
    const server = await listenTransport(instance.location, instance.record, platform, {
      authorize() {}, async execute() { ++executions; throw unavailable('browser'); },
      commit() { throw new Error('No test close response can be committed'); },
      disconnect() { ++disconnects; disconnected(); }, cancel() {},
      fatal() { throw new Error('Unexpected transport fatal path'); },
    });
    const seam = await deadlineLifecycle(f, 'connection', mode);
    try {
      server.openAdmission(); await instance.phase('ready');
      const before = await snapshot(profile.paths.root);
      const pending = outcome(seam.closeProfile(profile, selection, platform, exits,
        now() + (mode === 'late' ? 3500 : 13000)));
      if (mode !== 'reject') {
        await seam.acquired(); assert.equal(disconnects, 0);
        if (mode === 'late') rejected(await bounded(pending, 2000));
        seam.settle();
      }
      rejected(await bounded(pending, 3000));
      if (mode === 'reject') assert.equal(disconnects, 0);
      else await bounded(observedDisconnect);
      assert.equal(executions, mode === 'ordinary' ? 1 : 0,
        'A refused acquisition must not dispatch close');
      // Closing a management connection must never release host custody.
      await probe(profile.paths.owner, false);
      assert.deepEqual(await snapshot(profile.paths.root), before);
      evidence.push({ resource: 'management-socket', mode, serverDisconnects: disconnects,
        retainedResourceReferences: seam.resources.length, hostOwnerStillHeld: true,
        postAcquisitionChecks: seam.clockChecks });
    } finally { await seam.cleanup(); await server.close(); instance.owner.release(); }
    await probe(profile.paths.owner, true);
  }
  return { resourcePaths: evidence, productionLifecycleBytes: 'unchanged packaged module',
    completeHostExit: 'not provided: refusal-only authority; no engine started' };
}
