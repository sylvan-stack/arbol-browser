import { assert, agent, create, open, tool, until, loopback, save, delay } from '../support/control.mjs';

export async function controlHealthBoundary(c) {
  const profile = 'control-health'; await create(c, profile); await open(c, profile);
  const page = await loopback(c);
  try {
    const client = await agent(c, profile, 'fictional health observer');
    const opened = await tool(client, 'browser_tab_open', { url: page.url('health') });
    assert.equal(opened.tab.pageAvailability, 'ready'); assert.equal(opened.tab.inputReady, true);
    await until(() => page.observations.find(o => o.name === 'health'));
    const armedAt = performance.now(); await page.hang('health');
    const fault = await until(async () => {
      const tab = (await tool(client, 'browser_tabs_list')).tabs.find(t => t.tab === opened.tab.tab);
      return tab && tab.pageAvailability !== 'ready' ? tab : undefined;
    }, 8000);
    await save(c.output + '/fault-observed.json', { armedAt, observedAt: performance.now(), originalTab: opened.tab, fault });
    assert.equal(fault.pageAvailability, 'unresponsive', 'Generic unavailability is not proof of the injected hang diagnosis');
    assert.equal(fault.controller, 'user'); assert.equal(fault.inputReady, false);
    assert.equal(fault.observationSuspended, true); assert.ok(fault.controlGeneration > opened.tab.controlGeneration);
    await delay(1200);
    const latched = (await tool(client, 'browser_tabs_list')).tabs.find(t => t.tab === opened.tab.tab);
    assert.equal(latched.pageAvailability, fault.pageAvailability); assert.equal(latched.inputReady, false);
    await save(c.output + '/observations.json', { opened, fault, latched, explicitRecovery: 'unavailable: actual authenticated shell action required' });
    return { boundary: 'current signed host genuine renderer hang and latched private fault', recovery: 'unavailable', rendererReplacement: 'unavailable' };
  } finally { await page.close(); }
}
