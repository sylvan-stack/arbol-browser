import { readFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { assert, cli, success, create, open, runtime, closes, save, family, delay } from '../support/control.mjs';

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
  const tree = await family(c, 'ready'); assert.ok(tree.length > 0);
  const result = await closes(c, profile);
  await delay(1200); assert.equal(r.platform.processIdentity(r.record.pid), null, 'Closed original must not restart');
  await save(join(c.output, 'observations.json'), { info, values, repeated, identity: r.identity, record: r.record, tree, result });
  return { boundary: 'actual sealed CLI Building allocation and single original arbitration', authenticFailedLaunchReplay: 'unavailable' };
}
