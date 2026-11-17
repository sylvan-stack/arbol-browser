import { assert, agent, create, open, tool, until, save } from '../support/control.mjs';

export async function controlConnectionBoundary(c) {
  const profile = 'control-connections'; await create(c, profile); await open(c, profile);
  const owner = await agent(c, profile, 'fictional owner'), observer = await agent(c, profile, 'fictional observer');
  assert.notEqual(owner.hello.attachment.id, observer.hello.attachment.id);
  assert.deepEqual((await tool(observer, 'browser_tabs_list')).tabs, [], 'Ordinary private user tabs must be invisible');
  const opened = await tool(owner, 'browser_tab_open', {}), tab = opened.tab;
  assert.equal(tab.controller, 'agent');
  assert.deepEqual((await tool(observer, 'browser_tabs_list')).tabs, [], 'An ungranted connection must not inherit the owner grant');
  await assert.rejects(tool(observer, 'browser_release', { tab: tab.tab, controlGeneration: tab.controlGeneration }), e => ['tab_not_found', 'control_refused'].includes(e.detail?.code));
  const released = await tool(owner, 'browser_release', { tab: tab.tab, controlGeneration: tab.controlGeneration });
  assert.equal(released.tab.controller, 'user'); assert.equal(released.tab.observationSuspended, true);
  assert.ok(released.tab.controlGeneration > tab.controlGeneration);
  const after = (await tool(owner, 'browser_tabs_list')).tabs.find(t => t.tab === tab.tab);
  assert.deepEqual(after, released.tab, 'Original grantee must receive the redacted private projection');
  assert.ok(!('url' in after) && !('title' in after));
  await assert.rejects(tool(owner, 'browser_tab_close', { tab: tab.tab, controlGeneration: tab.controlGeneration }), e => ['control_changed', 'control_refused'].includes(e.detail?.code));
  const pending = await tool(owner, 'browser_tab_open', {}); owner.close();
  await until(async () => (await tool(observer, 'browser_tabs_list')).tabs.length === 0);
  const fresh = await agent(c, profile, 'fictional fresh'); assert.notEqual(fresh.hello.attachment.id, owner.hello.attachment.id);
  assert.deepEqual((await tool(fresh, 'browser_tabs_list')).tabs, []);
  await assert.rejects(tool(fresh, 'browser_release', { tab: pending.tab.tab, controlGeneration: pending.tab.controlGeneration }), e => ['tab_not_found', 'control_refused'].includes(e.detail?.code));
  await save(c.output + '/observations.json', { owner: owner.hello, observer: observer.hello, opened, released, after, fresh: fresh.hello });
  return { boundary: 'actual signed host ungranted connection isolation and native release', shellPresentation: 'unavailable', actionDrain: 'unavailable:ABR-30', disconnectedControllerCleanup: 'unavailable: no independent shell/granted observer oracle' };
}
