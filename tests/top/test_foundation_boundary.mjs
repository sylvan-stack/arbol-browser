import { join } from 'node:path';
import { mkdir, readFile, readdir } from 'node:fs/promises';
import { assert, fixture, cli, opaque, load, snapshot, dataSentinel, refused, delay } from '../support/foundation.mjs';

export async function receiptRace(context) {
  const f = await fixture(context, 'receipt-race');
  const { loadPlatform } = await load(f, 'runtime/platform');
  const { registryLock } = await load(f, 'profiles/locking');
  const platform = loadPlatform();
  // Force independent CLI processes to overlap at the real registry flock.
  const lock = await registryLock(f.state, platform, true);
  const request = opaque('create'), args = ['profiles', 'create', 'alternate', '--creation-request', request];
  let results;
  try {
    const pending = [cli(f, args), cli(f, args)];
    await delay(300);
    lock.release();
    results = await Promise.all(pending);
  } finally { lock.release(); }
  assert.deepEqual(results.map(result => result.status), [0, 0]);
  assert.equal(results.filter(result => result.value.created).length, 1);
  const profile = join(f.state, 'profiles/alternate');
  const published = JSON.parse(await readFile(join(profile, 'profile.json'), 'utf8'));
  assert.equal(published.creationRequest, request);
  assert.deepEqual(results.map(result => result.value.profile.instance), [published.instance, published.instance]);
  assert.deepEqual((await readdir(join(f.state, 'profiles'))).filter(name => !name.startsWith('.')), ['alternate']);
  await dataSentinel(join(profile, 'data/retained'));
  const before = await snapshot(profile);
  const replay = await cli(f, args);
  assert.equal(replay.status, 0); assert.equal(replay.value.created, false);
  refused(await cli(f, ['profiles', 'create', 'alternate', '--creation-request', opaque('create')]), 4, 'profile_unavailable');
  assert.deepEqual(await snapshot(profile), before, 'Receipt retry/conflict replaced identity or payload');
  // A partially populated destination is not a receipt, even with an exact token.
  const unmanaged = join(f.state, 'profiles/unmanaged');
  await mkdir(unmanaged, { mode: 0o700 }); await dataSentinel(join(unmanaged, 'retained'));
  const partial = await snapshot(unmanaged);
  refused(await cli(f, ['profiles', 'create', 'unmanaged', '--creation-request', request]), 4, 'profile_unavailable');
  assert.deepEqual(await snapshot(unmanaged), partial);
  assert.equal((await snapshot(f.state))['./profiles/default'], undefined);
  return { concurrentCli: 2, publishedInstance: published.instance, exactReplay: true,
    preserved: ['record/data/lock inodes', 'conflicting receipt', 'unmanaged payload'], engineOpened: false };
}
