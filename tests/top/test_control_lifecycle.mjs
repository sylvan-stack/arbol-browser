import { readFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { assert, cli, success, create, open, runtime, closes, save, family, delay, loopback, until, agent, tool } from '../support/control.mjs';

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
