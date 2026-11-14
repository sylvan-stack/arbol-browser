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
