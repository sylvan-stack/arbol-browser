import { randomBytes } from 'node:crypto';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, invalidInput, unavailable } from '../contracts/errors.js';
import { assertPageSurface, assertWindowHost, type PageSurface, type WindowHost } from './windows.js';

export type TabState = Readonly<Contract<'browser.ShellTab'>>;
export interface TabTarget { readonly id: string; readonly page: PageSurface }
/** ABR-10 supplies the sole authority; ABR-11 supplies current-document preparation.
 * No default implementation can register a grant or claim a ready document. */
export interface TabLifecycle {
  assertAdmission(): void;
  connected(client: string): boolean;
  register(target: TabTarget, initial: TabState): void;
  state(target: TabTarget): TabState;
  invalidate(target: TabTarget): void;
  removed(target: TabTarget): void;
  prepare(target: TabTarget, url: string): Promise<void>;
  changed(): void;
  exhausted(): never;
}
export function refused(code: 'control_refused' | 'control_changed' | 'tab_not_found', remedy = 'Read current browser state before trying again.'): BrowserFailure {
  return new BrowserFailure({ code, message: code === 'tab_not_found' ? 'Tab not found.' : 'The browser control request was refused.',
    retryable: true, remedy });
}
/** Shared user navigation policy. Never guess a scheme or use a search provider. */
export function userURL(value: string): string {
  if ([...value].length > 8192 || /[\u0000-\u0020\u007f]/u.test(value) || /[\uD800-\uDFFF]/u.test(value)) throw invalidInput();
  if (value === 'about:blank') return value;
  let url: URL; try { url = new URL(value); } catch { throw invalidInput(); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) throw invalidInput();
  return url.href;
}
export interface TabRegistry {
  all(): readonly TabTarget[];
  get(id: string): TabTarget;
  state(target: TabTarget): TabState;
  openUser(window: WindowHost, url?: string): Promise<TabTarget>;
  openAgent(window: WindowHost, client: string, label: string, url: string): Promise<TabTarget>;
  select(window: WindowHost, id: string): TabTarget;
  selected(window: WindowHost): TabTarget | undefined;
  closeUser(window: WindowHost, id: string, generation: number): Promise<void>;
  closeAgent(client: string, id: string, generation: number): Promise<void>;
  closeWindow(window: WindowHost): Promise<void>;
  beginPopupAction(target: TabTarget, generation: number): () => void;
}
const registries = new WeakSet<object>();
export function assertTabRegistry(value: TabRegistry): void {
  if (!registries.has(value)) throw unavailable('browser');
}
/** One registry per profile, shared by all its windows. IDs never repeat in this process. */
const issued = new Set<string>();
function tabId(exhausted: () => never): string {
  const id = `tab_${randomBytes(16).toString('base64url')}`;
  if (issued.size >= 1000000 || issued.has(id)) return exhausted(); issued.add(id); return id;
}
export function createTabRegistry(lifecycle: TabLifecycle): TabRegistry {
  const tabs = new Map<string, TabTarget>(), closing = new Set<TabTarget>();
  const selection = new Map<WindowHost, TabTarget>();
  interface PopupBudget { count: number; client: string; active: boolean }
  const actions = new Map<TabTarget, { generation: number; budget: PopupBudget }>();
  const finishBudget = (budget: PopupBudget) => {
    budget.active = false;
    for (const [target, action] of actions) if (action.budget === budget) actions.delete(target);
  };
  const assertTarget = (target: TabTarget) => {
    lifecycle.assertAdmission(); assertPageSurface(target.page);
    if (tabs.get(target.id) !== target || closing.has(target)) throw refused('tab_not_found');
  };
  const state = (target: TabTarget) => { assertTarget(target); return lifecycle.state(target); };
  const generation = (target: TabTarget, expected: number) => {
    const value = state(target); if (value.generation !== expected) throw refused('control_changed'); return value;
  };
  async function retire(target: TabTarget) {
    assertTarget(target); closing.add(target); actions.delete(target);
    lifecycle.invalidate(target); // close visibility and queued/content delivery before native teardown
    await target.page.retire();
    tabs.delete(target.id); lifecycle.removed(target);
    const window = target.page.window;
    if (selection.get(window) === target) {
      selection.delete(window);
      const next = [...tabs.values()].find(tab => tab.page.window === window && !closing.has(tab));
      if (next) { selection.set(window, next); window.select(next.page); }
    }
    lifecycle.changed();
  }
  async function open(window: WindowHost, url: string, creator?: Contract<'browser.ClientIdentity'>,
    inherited?: TabState, inheritedBudget?: PopupBudget): Promise<TabTarget> {
    lifecycle.assertAdmission(); assertWindowHost(window); url = userURL(url);
    if (tabs.size >= 64) throw refused('control_refused', 'Close an existing tab before opening another.');
    if (creator && !lifecycle.connected(creator.id)) throw refused('control_refused');
    const budget = creator ? inheritedBudget ?? { count: 0, client: creator.id, active: true } : undefined;
    if (budget && (!budget.active || budget.count >= 10 || budget.client !== creator?.id)) throw refused('control_refused');
    if (budget) budget.count++; // shared by every descendant; includes the initial agent-open tab
    const target = Object.freeze({ id: tabId(() => lifecycle.exhausted()), page: window.createPage() });
    const initial: TabState = { tab: target.id, generation: 1, controller: creator
      ? { kind: 'agent', client: creator.id, label: creator.label } : { kind: 'user' },
      visibleTo: creator ? [...(inherited?.visibleTo ?? [creator.id])].filter(id => lifecycle.connected(id)) : [],
      handoff: 'idle', inputReady: false, observationSuspended: !creator, pageAvailability: 'unavailable' };
    tabs.set(target.id, target);
    try {
      lifecycle.register(target, initial);
      if (budget) actions.set(target, { generation: 1, budget });
      target.page.view.webContents.setWindowOpenHandler(details => {
        // Always deny the engine route: frameName is never used to retarget an existing tab.
        void popup(target, details.url).catch(() => { /* redacted refusal; no content diagnostics */ });
        return { action: 'deny' };
      });
      target.page.view.webContents.on('will-navigate', event => {
        try { userURL(event.url); lifecycle.assertAdmission(); } catch { event.preventDefault(); }
      });
      target.page.view.webContents.on('will-redirect', (event, address) => {
        try { userURL(address); lifecycle.assertAdmission(); } catch { event.preventDefault(); }
      });
      target.page.view.webContents.on('will-prevent-unload', event => event.preventDefault());
      await lifecycle.prepare(target, url);
      assertTarget(target);
      if (creator && (!lifecycle.connected(creator.id) || state(target).controller.kind !== 'agent')) throw refused('control_changed');
      if (!creator) { selection.set(window, target); window.select(target.page); }
      lifecycle.changed(); return target;
    } catch (error) {
      // No failed open may retain an unreported lease. Retirement failures remain profile-fatal.
      if (tabs.has(target.id) && !closing.has(target)) await retire(target);
      throw error;
    } finally {
      if (budget && !inheritedBudget) finishBudget(budget);
    }
  }
  async function popup(opener: TabTarget, url: string) {
    const before = state(opener); userURL(url);
    if (before.handoff !== 'idle') throw refused('control_refused');
    if (before.controller.kind === 'user') return open(opener.page.window, url);
    const action = actions.get(opener);
    if (!action || action.generation !== before.generation || action.budget.client !== before.controller.client ||
        !action.budget.active || action.budget.count >= 10 || !lifecycle.connected(action.budget.client)) throw refused('control_refused');
    return open(opener.page.window, url, { id: action.budget.client, label: before.controller.label }, before, action.budget);
  }
  const registry: TabRegistry = Object.freeze({
    all: () => [...tabs.values()].filter(target => !closing.has(target)),
    get(id: string) { const target = tabs.get(id); if (!target) throw refused('tab_not_found'); assertTarget(target); return target; },
    state,
    openUser: (window: WindowHost, url = 'about:blank') => open(window, url),
    openAgent: (window: WindowHost, client: string, label: string, url: string) => open(window, url, { id: client, label }),
    select(window: WindowHost, id: string) {
      const target = registry.get(id); if (target.page.window !== window) throw refused('tab_not_found');
      selection.set(window, target); window.select(target.page); return target;
    },
    selected: (window: WindowHost) => selection.get(window),
    async closeUser(window: WindowHost, id: string, expected: number) {
      const target = registry.get(id); if (target.page.window !== window) throw refused('tab_not_found');
      generation(target, expected); await retire(target);
    },
    async closeAgent(client: string, id: string, expected: number) {
      const target = registry.get(id), current = state(target);
      if (!lifecycle.connected(client) || !current.visibleTo.includes(client)) throw refused('tab_not_found');
      generation(target, expected);
      if (current.controller.kind !== 'agent' || current.controller.client !== client) throw refused('control_refused');
      await retire(target);
    },
    async closeWindow(window: WindowHost) {
      assertWindowHost(window);
      await Promise.all([...tabs.values()].filter(target => target.page.window === window).map(retire));
      selection.delete(window); await window.close();
    },
    beginPopupAction(target: TabTarget, expected: number) {
      const current = generation(target, expected);
      if (actions.has(target) || current.controller.kind !== 'agent' || !lifecycle.connected(current.controller.client)) throw refused('control_refused');
      const action = { generation: expected, budget: { client: current.controller.client, count: 0, active: true } };
      actions.set(target, action);
      return () => finishBudget(action.budget);
    },
  });
  registries.add(registry); return registry;
}
