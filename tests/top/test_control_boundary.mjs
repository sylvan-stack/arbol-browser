import { assert, agent, create, open, tool, until, save } from '../support/control.mjs';

export async function controlConnectionBoundary(c) {
  const profile = 'control-connections'; await create(c, profile); await open(c, profile);
  // Keep only test operation names and timestamps in memory. Flush once after
  // the case settles so a lost host still leaves the last in-flight operation.
  const calls = [];
  async function observe(role, operation, execute) {
    const call = { role, operation, startedAt: new Date().toISOString() };
    calls.push(call);
    try {
      const result = await execute();
      call.status = 'returned';
      return result;
    } catch (error) {
      call.status = 'rejected';
      call.code = error?.detail?.code;
      throw error;
    } finally { call.finishedAt = new Date().toISOString(); }
  }
  const attach = role => observe(role, 'attach', () => agent(c, profile, 'fictional ' + role));
  const request = (role, client, name, args) => observe(role, name, () => tool(client, name, args));
  let completed = false;
  try {
    const owner = await attach('owner'), observer = await attach('observer');
    assert.notEqual(owner.hello.attachment.id, observer.hello.attachment.id);
    assert.deepEqual((await request('observer', observer, 'browser_tabs_list')).tabs, [], 'Ordinary private user tabs must be invisible');
    const opened = await request('owner', owner, 'browser_tab_open', {}), tab = opened.tab;
    assert.equal(tab.controller, 'agent');
    assert.deepEqual((await request('observer', observer, 'browser_tabs_list')).tabs, [], 'An ungranted connection must not inherit the owner grant');
    const target = { tab: tab.tab, controlGeneration: tab.controlGeneration };
    await assert.rejects(request('observer', observer, 'browser_release', target), e => ['tab_not_found', 'control_refused'].includes(e.detail?.code));
    const released = await request('owner', owner, 'browser_release', target);
    assert.equal(released.tab.controller, 'user'); assert.equal(released.tab.observationSuspended, true);
    assert.ok(released.tab.controlGeneration > tab.controlGeneration);
    const after = (await request('owner', owner, 'browser_tabs_list')).tabs.find(t => t.tab === tab.tab);
    assert.deepEqual(after, released.tab, 'Original grantee must receive the redacted private projection');
    assert.ok(!('url' in after) && !('title' in after));
    await assert.rejects(request('owner', owner, 'browser_tab_close', target), e => ['control_changed', 'control_refused'].includes(e.detail?.code));
    const pending = await request('owner', owner, 'browser_tab_open', {}); owner.close();
    calls.push({ role: 'owner', operation: 'disconnect', finishedAt: new Date().toISOString() });
    await until(async () => (await request('observer', observer, 'browser_tabs_list')).tabs.length === 0);
    const fresh = await attach('fresh'); assert.notEqual(fresh.hello.attachment.id, owner.hello.attachment.id);
    assert.deepEqual((await request('fresh', fresh, 'browser_tabs_list')).tabs, []);
    await assert.rejects(request('fresh', fresh, 'browser_release', { tab: pending.tab.tab, controlGeneration: pending.tab.controlGeneration }), e => ['tab_not_found', 'control_refused'].includes(e.detail?.code));
    await save(c.output + '/observations.json', { owner: owner.hello, observer: observer.hello, opened, released, after, fresh: fresh.hello });
    completed = true;
    return { boundary: 'actual signed host ungranted connection isolation and native release', shellPresentation: 'unavailable', actionDrain: 'unavailable:ABR-30', disconnectedControllerCleanup: 'unavailable: no independent shell/granted observer oracle' };
  } finally {
    try { await save(c.output + '/protected-calls.json', calls); }
    catch (error) { if (completed) throw error; }
  }
}
