import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { unavailable } from '../contracts/errors.js';
import { assertTabRegistry, type TabRegistry, type TabState } from './tabs.js';

export function clientLabel(value: string): string {
  return [...value.replace(/[\p{Cc}\p{Cf}]/gu, '')].slice(0, 80).join('').trim() || 'Agent';
}
/** Shell receives host facts, not private native handles or arbitrary record properties. */
export function projectShellTab(value: TabState, connected: (client: string) => boolean): TabState {
  const controller = value.controller.kind === 'user' ? { kind: 'user' as const } :
    { kind: 'agent' as const, client: value.controller.client, label: clientLabel(value.controller.label) };
  const result: TabState = { tab: value.tab, controller, generation: value.generation,
    handoff: value.handoff, visibleTo: [...value.visibleTo].filter(connected), inputReady: value.inputReady,
    observationSuspended: controller.kind === 'user', pageAvailability: value.pageAvailability,
    ...(value.navigation ? { navigation: value.navigation } : {}) };
  if (!validator('browser.ShellTab')(result)) throw unavailable('browser');
  return Object.freeze(result);
}
/** Recipient comes from the authenticated host connection, never request parameters.
 * Recompute at final delivery. Optional page metadata stays absent until the later
 * classified-content provider can prove BRW-3 redaction; raw getURL/getTitle is unsafe. */
export function projectAgentTabs(tabs: TabRegistry, recipient: string, connected: (client: string) => boolean): Contract<'browser.TabsResult'> {
  assertTabRegistry(tabs);
  if (!connected(recipient)) throw unavailable('browser');
  const result: Contract<'browser.TabsResult'> = { tabs: [] };
  for (const target of tabs.all()) {
    const value = tabs.state(target);
    if (!value.visibleTo.includes(recipient)) continue;
    if (value.controller.kind === 'user') {
      const privateTab: Contract<'browser.PrivateTab'> = { tab: target.id, controller: 'user',
        controlGeneration: value.generation, observationSuspended: true, inputReady: false,
        pageAvailability: value.pageAvailability };
      result.tabs.push(privateTab);
    } else {
      const observed: Contract<'browser.ObservedTab'> = { tab: target.id, controller: 'agent',
        controlGeneration: value.generation, observationSuspended: false,
        inputReady: value.handoff === 'idle' && value.pageAvailability === 'ready' && value.inputReady,
        pageAvailability: value.pageAvailability, ownsControl: value.controller.client === recipient,
        controllerLabel: clientLabel(value.controller.label) };
      result.tabs.push(observed);
    }
  }
  if (!connected(recipient) || !validator('browser.TabsResult')(result)) throw unavailable('browser');
  return result;
}
