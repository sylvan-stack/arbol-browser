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

export async function startupAcquisitionBoundary(context) {
  const { startupLifecycle } = await import('../support/foundation-startup-deadlines.mjs');
  const { bounded, opaque } = await import('../support/foundation.mjs');
  const { PassThrough } = await import('node:stream');
  const f = await fixture(context, 'startup-acquisitions');
  const { loadPlatform } = await load(f, 'runtime/platform'), platform = loadPlatform();
  const { readProfile } = await load(f, 'profiles/records');
  const { profilePaths } = await load(f, 'profiles/paths');
  const { now, acquireInstance, neverOpenedExit } = await load(f, 'runtime/instance');
  const { listenTransport, connectRuntime } = await load(f, 'runtime/transport');
  const { acquireBuildLease } = await load(f, 'runtime/build-lease');
  const { unavailable } = await load(f, 'contracts/errors');
  const component = await privateDirectory(join(f.root, 'registry/arbol-browser'));
  const directory = await privateDirectory(join(component, 'a'));
  await privateDirectory(join(component, '.uses'));
  const guard = join(component, '.uses/a'); await writeFile(guard, '', { mode: 0o600 });
  const selection = { build: 'a', explicit: false, directory, guard };
  const outcome = promise => promise.then(value => ({ ok: true, value }), error => ({ ok: false, error }));
  const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
  async function probe(path, expected) {
    const child = await worker(f, 'lock-probe', { path });
    try { assert.equal(child.ready.acquired, expected, 'Independent custody observation disagrees'); }
    finally { await child.stop(); }
  }
  const observations = [];
  for (const endpoint of ['management', 'agent']) {
    const modes = ['late', 'post-wait', 'transfer', 'ordinary', 'reject',
      ...(endpoint === 'agent' ? ['eof', 'input-close', 'input-error'] : [])];
    for (const mode of modes) {
      const id = `${endpoint}-${mode}`;
      assert.equal((await cli(f, ['profiles', 'create', id])).status, 0);
      const profile = await readProfile(profilePaths(id, f.state));
      const instance = await acquireInstance(profile, platform, 'a', neverOpenedExit, now() + 2000);
      assert.ok(instance);
      const hostBuild = await acquireBuildLease(selection, platform);
      const lost = deferred(), mcpExit = deferred(), transferred = deferred();
      let disconnects = 0, executions = 0;
      const server = await listenTransport(instance.location, instance.record, platform, {
        authorize() {}, async execute(_connection, request) {
          ++executions;
          // A synthetic transport reply only; no tab, page or host is opened.
          if (request.method === 'open') return { profile: id, instance: instance.record.instance,
            process: instance.record.pid, alreadyRunning: true };
          throw unavailable('browser');
        }, commit() {}, disconnect() { ++disconnects; lost.resolve(); }, cancel() {},
        fatal() { throw new Error('Unexpected synthetic transport fatal'); },
      });
      const seam = await startupLifecycle(f, mode, async (_profile, role, deadline, label) => ({
        client: await connectRuntime(instance.location, instance.record, role, selection, platform, deadline, label),
        record: instance.record, alreadyRunning: true,
      }));
      const io = { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() };
      io.stdin.resume();
      let pending;
      try {
        server.openAdmission(); await instance.phase('ready');
        const before = await snapshot(profile.paths.root);
        const service = seam.createProcessService({ selection, platform: () => platform, state: f.state,
          integration: {
            async assertAdmissionAvailable() { /* explicitly synthetic resource boundary */ },
            start: seam.start,
            async mcp(connect) { const client = await connect('Synthetic resource pipeline');
              transferred.resolve(client); await mcpExit.promise; },
          } });
        pending = outcome(endpoint === 'management' ? service.open({ profile: id }) : service.mcp(id, io));
        if (mode !== 'reject') {
          await seam.acquired(); assert.equal(disconnects, 0);
          if (mode === 'late') assert.equal((await bounded(pending, 2000)).ok, false);
          if (['eof', 'input-close', 'input-error'].includes(mode)) {
            const event = mode === 'eof' ? 'end' : mode === 'input-close' ? 'close' : 'error';
            const observed = new Promise(resolve => io.stdin.once(event, resolve));
            if (mode === 'eof') io.stdin.end();
            else io.stdin.destroy(mode === 'input-error' ? new Error('Synthetic stdin failure') : undefined);
            await bounded(observed);
          }
          seam.settle();
        }
        if (mode === 'ordinary' && endpoint === 'agent') {
          const client = await bounded(transferred.promise);
          for (let call = 0; call < 2; ++call) {
            await assert.rejects(client.call({ wire: 1, id: opaque('req'), method: 'tool',
              params: { name: 'browser_tabs_list', arguments: {} } }, now() + 1000));
            assert.equal(client.signal.aborted, false, 'Ordinary transferred connection stopped being usable');
          }
          assert.equal(executions, 2); assert.equal(disconnects, 0);
          mcpExit.resolve();
        }
        const result = await bounded(pending, 2000);
        assert.equal(result.ok, mode === 'ordinary', 'Unexpected lifecycle transfer outcome');
        if (mode !== 'reject') {
          await bounded(lost.promise, 500).catch(() => {
            throw new Error('Operation-owned startup socket remains connected after settlement with strong references alive');
          });
        } else assert.equal(disconnects, 0);
        assert.equal(executions, mode === 'ordinary' ? (endpoint === 'agent' ? 2 : 1) : 0,
          'Refused startup dispatched an open/tool call');
        await probe(profile.paths.owner, false); await probe(guard, false);
        assert.deepEqual(await snapshot(profile.paths.root), before);
        observations.push({ endpoint, mode, peerDisconnects: disconnects, executions,
          retainedClientReferences: seam.resources.length, postAcquisitionChecks: seam.clockChecks,
          hostOwnerAndBuildProtective: true });
      } finally {
        mcpExit.resolve(); await seam.cleanup();
        if (pending) await bounded(pending, 2000).catch(() => {});
        await server.close(); instance.owner.release(); hostBuild.release();
        io.stdin.destroy(); io.stdout.destroy(); io.stderr.destroy();
      }
      await probe(profile.paths.owner, true); await probe(guard, true);
    }
  }
  return { lifecycleTransfers: observations, starterTransfers: await starterTransferObservations(context),
    syntheticPredicates: 'admission and ProcessIntegration resource pipeline only; no production adapter or native readiness',
    realOracles: 'actual authenticated peer disconnect, usable client control and independent owner/Build lock contenders' };
}

async function starterTransferObservations(context) {
  const { startupStarter } = await import('../support/foundation-startup-deadlines.mjs');
  const { bounded, opaque } = await import('../support/foundation.mjs');
  const f = await fixture(context, 'starter-transfers');
  const { loadPlatform } = await load(f, 'runtime/platform'), platform = loadPlatform();
  const { readProfile } = await load(f, 'profiles/records');
  const { profilePaths } = await load(f, 'profiles/paths');
  const { now, acquireInstance, neverOpenedExit } = await load(f, 'runtime/instance');
  const { listenTransport } = await load(f, 'runtime/transport');
  const { acquireBuildLease } = await load(f, 'runtime/build-lease');
  const component = await privateDirectory(join(f.root, 'registry/arbol-browser'));
  const directory = await privateDirectory(join(component, 'a'));
  await privateDirectory(join(component, '.uses'));
  const guard = join(component, '.uses/a'); await writeFile(guard, '', { mode: 0o600 });
  const selection = { build: 'a', explicit: false, directory, guard };
  async function probe(path, expected) {
    const child = await worker(f, 'lock-probe', { path });
    try { assert.equal(child.ready.acquired, expected, 'Independent starter custody observation disagrees'); }
    finally { await child.stop(); }
  }
  const observations = [];
  for (const branch of ['existing', 'arbitrated', 'launched']) {
    for (const mode of ['readiness', 'final', 'guard-release', 'post-release', 'ordinary']) {
      const id = `${branch}-${mode}`;
      assert.equal((await cli(f, ['profiles', 'create', id])).status, 0);
      const profile = await readProfile(profilePaths(id, f.state));
      const hostBuild = await acquireBuildLease(selection, platform);
      let instance, server, seam, arbitrationPath, disconnects = 0, executions = 0, disconnected;
      const lost = new Promise(resolve => { disconnected = resolve; });
      async function publish() {
        assert.equal(instance, undefined, 'Synthetic launch unexpectedly repeated');
        instance = await acquireInstance(profile, platform, 'a', neverOpenedExit, now() + 2000);
        assert.ok(instance);
        server = await listenTransport(instance.location, instance.record, platform, {
          authorize() {}, async execute(_connection, request) {
            ++executions; assert.equal(request.method, 'open');
            // Only a synthetic resource reply: no browser, page or controller.
            return { profile: id, instance: instance.record.instance,
              process: instance.record.pid, alreadyRunning: true };
          }, commit() {}, disconnect() { ++disconnects; disconnected(); }, cancel() {},
          fatal() { throw new Error('Unexpected synthetic starter transport fatal'); },
        });
        server.openAdmission(); await instance.phase('ready');
      }
      try {
        if (branch === 'existing') await publish();
        seam = await startupStarter(f, { branch, mode, profile, selection, platform, publish });
        const before = await snapshot(profile.paths.root);
        const result = await seam.run().then(value => ({ ok: true, value }), error => ({ ok: false, error }));
        assert.equal(result.ok, mode === 'ordinary', 'Unexpected starter resource-transfer outcome');
        assert.equal(seam.resources.length, 1, 'Resource boundary was not reached with an actual client');
        assert.equal(seam.simulatedLaunches, branch === 'launched' ? 1 : 0);
        if (mode === 'ordinary') {
          const client = result.value.client;
          assert.equal(disconnects, 0);
          for (let call = 0; call < 2; ++call) {
            await client.call({ wire: 1, id: opaque('req'), method: 'open', params: {} }, now() + 1000);
            assert.equal(client.signal.aborted, false, 'Transferred starter client was not usable');
          }
          assert.equal(executions, 2); client.close();
        } else assert.equal(executions, 0, 'Refused starter dispatched application work');
        await bounded(lost, 500).catch(() => {
          throw new Error('Operation-owned starter socket remains connected after transfer failure with strong references alive');
        });
        await probe(profile.paths.owner, false); await probe(guard, false);
        assert.deepEqual(await snapshot(profile.paths.root), before);
        const retained = branch === 'launched' && ['readiness', 'final', 'guard-release'].includes(mode);
        assert.equal(seam.retainedAttempts, retained ? 1 : 0);
        const startupRetained = branch === 'launched' && ['readiness', 'final'].includes(mode);
        if (branch !== 'existing') {
          arbitrationPath = join(instance.location.leaf, 'startup.lock');
          await probe(arbitrationPath, !startupRetained);
        }
        observations.push({ branch, mode, actualPeerDisconnects: disconnects, executions,
          retainedClientReferences: seam.resources.length, postReadinessChecks: seam.clockChecks,
          hostOwnerAndBuildProtective: true, simulatedUpstreamPredicates: [...seam.predicates],
          noEngineLaunch: true, syntheticLaunches: seam.simulatedLaunches,
          failedAttemptAuthorityRefusals: seam.failedAttemptRefusals,
          retainedAttemptGuardsAtObservation: seam.retainedAttempts, startupLockRetainedAtObservation: startupRetained,
          genuineNativeReadinessAndExit: 'unqualified; fixture predicates and teardown are not production evidence' });
      } finally {
        // No fixture asserts production exit to release a retained attempt.
        // Shut down the test transport first; dispose only test-owned handles.
        if (server) await server.close();
        instance?.owner.release(); hostBuild.release();
        await seam?.cleanup();
      }
      await probe(profile.paths.owner, true); await probe(guard, true);
      if (arbitrationPath) await probe(arbitrationPath, true);
    }
  }
  return observations;
}
