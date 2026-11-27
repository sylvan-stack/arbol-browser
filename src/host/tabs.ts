import { randomBytes } from 'node:crypto';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, invalidInput, unavailable } from '../contracts/errors.js';
import { assertPageRetirement, assertPageSurface, assertWindowHost, type PageSurface, type WindowHost } from './windows.js';
import { agentURL, AgentNavigationPolicy } from '../automation/navigation.js';

export type TabState = Readonly<Contract<'browser.ShellTab'>>;
export interface TabTarget { readonly id: string; readonly page: PageSurface }
/** Host-created pending-open transaction, carried only by the actual inherited
 * PopupBudget. Never reconstructed by scanning a client's unrelated tabs. */
export interface AgentOpenScope {
  assertCurrent(source?: TabTarget): void;
  registered(target: TabTarget, opener?: TabTarget): void;
  failed(target: TabTarget): Promise<void>;
}
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
  openUser(window: WindowHost, url?: string, background?: boolean): Promise<TabTarget>;
  openAgent(window: WindowHost, client: string, label: string, url: string, scope: AgentOpenScope): Promise<TabTarget>;
  select(window: WindowHost, id: string): TabTarget;
  selected(window: WindowHost): TabTarget | undefined;
  /** Only explicit recovery may publish a fresh physical page on this logical tab. */
  replace(target: TabTarget, original: PageSurface, replacement: PageSurface,
    assertCurrent: () => void, publish: () => void): void;
  closeUser(window: WindowHost, id: string, generation: number): Promise<void>;
  closeAgent(client: string, id: string, generation: number): Promise<void>;
  retireWindowTabs(window: WindowHost): Promise<void>;
  closeWindow(window: WindowHost): Promise<void>;
  beginPopupAction(target: TabTarget, generation: number): () => void;
}
const registries = new WeakSet<object>();
const assignedPages = new WeakSet<PageSurface>();
const replacementReservations = new WeakMap<PageSurface, object>();
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
  const bindings = new WeakMap<TabTarget, { page: PageSurface }>();
  const selection = new Map<WindowHost, TabTarget>();
  interface PendingRetirement { generation: number; promise: Promise<void>; ready: Promise<void>; start(): void }
  const retirements = new WeakMap<TabTarget, PendingRetirement>();
  const registered = new WeakSet<TabTarget>();
  const registrationAttempted = new WeakSet<TabTarget>();
  const windowClosures = new WeakMap<WindowHost, Promise<void>>();
  interface PopupBudget { count: number; client: string; active: boolean; scope?: AgentOpenScope }
  const actions = new Map<TabTarget, { generation: number; budget: PopupBudget }>();
  const finishBudget = (budget: PopupBudget) => {
    budget.active = false;
    for (const [target, action] of actions) if (action.budget === budget) actions.delete(target);
  };
  const assertTarget = (target: TabTarget) => {
    lifecycle.assertAdmission(); assertPageSurface(target.page);
    if (tabs.get(target.id) !== target || closing.has(target) || windowClosures.has(target.page.window)) throw refused('tab_not_found');
  };
  const state = (target: TabTarget) => { assertTarget(target); return lifecycle.state(target); };
  const generation = (target: TabTarget, expected: number) => {
    const value = state(target); if (value.generation !== expected) throw refused('control_changed'); return value;
  };
  function prepareRetirement(target: TabTarget): PendingRetirement {
    const pending = retirements.get(target);
    if (pending) return pending;
    if (tabs.get(target.id) !== target) throw refused('tab_not_found');
    const page = target.page, window = page.window;
    let currentGeneration = 1;
    if (registered.has(target)) window.guardRetirementTransition(() => { currentGeneration = lifecycle.state(target).generation; });
    let resolve!: () => void, reject!: (reason: unknown) => void, prepared!: () => void;
    const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
    const ready = new Promise<void>(yes => { prepared = yes; });
    let started = false;
    const record: PendingRetirement = { generation: currentGeneration, promise, ready,
      start() {
        if (started) return; started = true;
        void ready.then(() => {
          // This remains the one exact Native provider, after synchronous authority closure.
          void page.retire().then(() => {
            window.guardRetirementTransition(() => {
              tabs.delete(target.id); closing.delete(target); registered.delete(target);
              if (registrationAttempted.has(target)) lifecycle.removed(target);
              lifecycle.changed();
            });
            resolve();
          }, reject);
        });
      },
    };
    retirements.set(target, record);
    closing.add(target); actions.delete(target);
    // Publish guards/promises before any callback can re-enter. No native detach/close here.
    window.guardRetirementTransition(() => {
      const originalRetirement = page.retirement();
      if (originalRetirement) assertPageRetirement(page, originalRetirement);
      else page.setNativeBlocked(true);
      if (selection.get(window) === target) {
        const next = [...tabs.values()].find(tab => registered.has(tab) && tab.page.window === window && !closing.has(tab) && !tab.page.retirement());
        if (!windowClosures.has(window) && next) window.select(next.page, () => { selection.set(window, next); });
        else window.clearSelection(page, () => { if (selection.get(window) === target) selection.delete(window); });
      }
      // A native placement can lose before the first lifecycle registration.
      // Such a private blocked tentative has no grants/jobs/authority to revoke.
      // Its authentic physical retirement still uses this same once-only path.
      if (registrationAttempted.has(target)) return lifecycle.invalidate(target);
    });
    prepared(); return record;
  }
  function retire(target: TabTarget): Promise<void> {
    const pending = prepareRetirement(target); pending.start(); return pending.promise;
  }
  async function retireWindowTabs(window: WindowHost): Promise<void> {
    assertWindowHost(window);
    const pending = [...tabs.values()].filter(target => target.page.window === window).map(prepareRetirement);
    await Promise.all(pending.map(target => target.ready));
    for (const target of pending) target.start();
    await Promise.all(pending.map(target => target.promise));
    if ([...tabs.values()].some(target => target.page.window === window)) throw unavailable('profile');
    selection.delete(window);
  }
  function installPageEvents(target: TabTarget, page: PageSurface) {
    // Closures keep the originating page. A stale event cannot resolve the
    // logical target's newer page and acquire its authority or popup budget.
    const current = () => tabs.get(target.id) === target && target.page === page && !closing.has(target) &&
      !windowClosures.has(page.window) && !page.retirement();
    const policy = new AgentNavigationPolicy();
    const agent = () => lifecycle.state(target).controller.kind === 'agent';
    page.view.webContents.setWindowOpenHandler(details => {
      if (current()) void popup(target, page, details.url).catch(() => {});
      return { action: 'deny' };
    });
    page.view.webContents.on('will-navigate', event => {
      try { if (!current()) throw refused('control_changed');
        if (agent()) policy.start(event.url, page.view.webContents.getURL()); else userURL(event.url);
        lifecycle.assertAdmission(); }
      catch { event.preventDefault(); }
    });
    page.view.webContents.on('will-frame-navigate', event => {
      try { if (!current()) throw refused('control_changed');
        if (event.isMainFrame && agent()) agentURL(event.url, page.view.webContents.getURL());
        lifecycle.assertAdmission(); }
      catch { event.preventDefault(); }
    });
    page.view.webContents.on('did-start-navigation', event => {
      if (!current() || !event.isMainFrame) return;
      try { if (agent()) policy.start(event.url, page.view.webContents.getURL()); }
      catch { /* Cancellable barriers own refusal; document authority fences an issued load. */ }
    });
    page.view.webContents.on('will-redirect', (event, address, _inPlace, main) => {
      try { if (!current()) throw refused('control_changed');
        if (main && agent()) policy.redirect(address); else userURL(address);
        lifecycle.assertAdmission(); }
      catch { event.preventDefault(); }
    });
    page.view.webContents.on('will-prevent-unload', event => event.preventDefault());
  }
  async function open(window: WindowHost, url: string, creator?: Contract<'browser.ClientIdentity'>,
    inherited?: TabState, inheritedBudget?: PopupBudget, background = false, scope?: AgentOpenScope, opener?: TabTarget): Promise<TabTarget> {
    lifecycle.assertAdmission(); assertWindowHost(window); url = creator ? agentURL(url) : userURL(url);
    if (windowClosures.has(window)) throw refused('control_refused', 'This browser window is closing.');
    if (tabs.size >= 64 || [...tabs.values()].filter(tab => tab.page.window === window).length >= 7)
      throw refused('control_refused', 'A profile can have up to seven open tabs. Close a tab before opening another.');
    if (creator && !lifecycle.connected(creator.id)) throw refused('control_refused');
    if (creator && !inheritedBudget && !scope) throw refused('control_refused');
    const budget: PopupBudget | undefined = creator ? inheritedBudget ?? { count: 0, client: creator.id, active: true, ...(scope ? { scope } : {}) } : undefined;
    const scopeCurrent = (source: TabTarget | undefined = opener) => {
      if (budget?.scope) { const result: unknown = budget.scope.assertCurrent(source); if (result !== undefined) return lifecycle.exhausted(); }
    };
    if (budget && (!budget.active || budget.count >= 10 || budget.client !== creator?.id)) throw refused('control_refused');
    scopeCurrent();
    if (budget) budget.count++; // shared by every descendant; includes the initial agent-open tab
    const physical = { page: window.createPage() };
    const target: TabTarget = Object.freeze({ id: tabId(() => lifecycle.exhausted()), get page() { return physical.page; } });
    bindings.set(target, physical);
    assignedPages.add(physical.page);
    const initial: TabState = { tab: target.id, generation: 1, controller: creator
      ? { kind: 'agent', client: creator.id, label: creator.label } : { kind: 'user' },
      visibleTo: creator ? [...(inherited?.visibleTo ?? [creator.id])].filter(id => lifecycle.connected(id)) : [],
      handoff: 'idle', inputReady: false, observationSuspended: !creator, pageAvailability: 'unavailable' };
    tabs.set(target.id, target);
    try {
      const register = () => {
        registrationAttempted.add(target);
        lifecycle.register(target, initial); registered.add(target);
        if (budget?.scope) {
          const result: unknown = budget.scope.registered(target, opener);
          if (result !== undefined) return lifecycle.exhausted(); scopeCurrent(target);
        }
      };
      // Register before placement notifications can publish this new target.
      // Unregistered tentative records are never in the external registry view.
      if (!background && (!creator || !selection.has(window))) {
        const previous = selection.get(window);
        window.select(physical.page, () => {
          if (tabs.get(target.id) !== target || closing.has(target) || windowClosures.has(window) || target.page !== physical.page)
            throw refused('control_changed');
          selection.set(window, target);
          try { register(); }
          catch (error) {
            if (selection.get(window) === target) { if (previous) selection.set(window, previous); else selection.delete(window); }
            throw error;
          }
        });
      } else register();
      if (budget) actions.set(target, { generation: 1, budget });
      installPageEvents(target, physical.page);
      await lifecycle.prepare(target, url);
      scopeCurrent(target);
      assertTarget(target);
      if (creator && (!lifecycle.connected(creator.id) || state(target).controller.kind !== 'agent')) throw refused('control_changed');
      lifecycle.changed(); return target;
    } catch (error) {
      // No failed open may retain an unreported lease. Retirement failures remain profile-fatal.
      if (registered.has(target) && budget?.scope) await budget.scope.failed(target);
      else if (tabs.has(target.id) && !closing.has(target)) await retire(target);
      throw error;
    } finally {
      if (budget && !inheritedBudget) finishBudget(budget);
    }
  }
  async function popup(opener: TabTarget, page: PageSurface, url: string) {
    if (opener.page !== page || page.retirement()) throw refused('control_changed');
    const before = state(opener);
    if (before.controller.kind === 'agent') agentURL(url, page.view.webContents.getURL()); else userURL(url);
    if (before.handoff !== 'idle') throw refused('control_refused');
    // Popup creation does not silently change the shell's selected tab.
    if (before.controller.kind === 'user') return open(opener.page.window, url, undefined, undefined, undefined, true);
    const action = actions.get(opener);
    if (!action || action.generation !== before.generation || action.budget.client !== before.controller.client ||
        !action.budget.active || action.budget.count >= 10 || !lifecycle.connected(action.budget.client)) throw refused('control_refused');
    return open(opener.page.window, url, { id: action.budget.client, label: before.controller.label }, before, action.budget, false, undefined, opener);
  }
  const registry: TabRegistry = Object.freeze({
    all: () => [...tabs.values()].filter(target => registered.has(target) && !closing.has(target) && !windowClosures.has(target.page.window)),
    get(id: string) { const target = tabs.get(id); if (!target || !registered.has(target)) throw refused('tab_not_found'); assertTarget(target); return target; },
    state,
    openUser: (window: WindowHost, url = 'about:blank', background = false) =>
      open(window, url, undefined, undefined, undefined, background),
    openAgent: (window: WindowHost, client: string, label: string, url: string, scope: AgentOpenScope) => open(window, url, { id: client, label }, undefined, undefined, false, scope),
    select(window: WindowHost, id: string) {
      const target = registry.get(id); if (target.page.window !== window) throw refused('tab_not_found');
      const page = target.page;
      window.select(page, () => { assertTarget(target); if (target.page !== page) throw refused('control_changed'); selection.set(window, target); });
      return target;
    },
    selected: (window: WindowHost) => selection.get(window),
    replace(target: TabTarget, original: PageSurface, replacement: PageSurface, assertCurrent: () => void, publish: () => void) {
      assertTarget(target); assertPageSurface(replacement);
      const check = () => { const value: unknown = assertCurrent(); if (value !== undefined) return lifecycle.exhausted(); };
      check();
      const physical = bindings.get(target), retired = original.retirement(), state = lifecycle.state(target);
      if (!physical || physical.page !== original || original === replacement || !retired || closing.has(target) ||
          replacement.window !== original.window || replacement.session !== original.session || replacement.retirement() ||
          state.controller.kind !== 'user' || state.handoff !== 'idle') throw refused('control_changed');
      assertPageRetirement(original, retired);
      // The authentic receipt already owns original destroyed/detached proof.
      // Pinned WebContentsView clears its getter after destruction.
      if (retired.phase !== 'retired') throw refused('control_refused');
      if (assignedPages.has(replacement) || replacementReservations.has(replacement) || !original.window.owns(replacement))
        throw refused('control_refused');
      const reservation = Object.freeze({ target, original, replacement }); replacementReservations.set(replacement, reservation);
      const binding = replacement.binding();
      if (!binding.blocked || binding.retired || binding.webContentsId !== replacement.view.webContents.id ||
          binding.id === original.identity.id || binding.nonce === original.identity.nonce)
        return lifecycle.exhausted();
      installPageEvents(target, replacement); check();
      const window = original.window, selected = selection.get(window) === target;
      const commit = () => {
        check();
        if (tabs.get(target.id) !== target || closing.has(target) || windowClosures.has(window) || physical.page !== original ||
            replacementReservations.get(replacement) !== reservation || !window.owns(replacement) || assignedPages.has(replacement) ||
            (selection.get(window) === target) !== selected || (selected && window.selected() !== replacement)) throw refused('control_changed');
        const state = lifecycle.state(target);
        if (state.controller.kind !== 'user' || state.handoff !== 'idle') throw refused('control_changed');
        physical.page = replacement; assignedPages.add(replacement); replacementReservations.delete(replacement); actions.delete(target);
        // After publication starts, uncertainty is fatal rather than rollback.
        window.guardRetirementTransition(publish);
      };
      if (selected) window.select(replacement, commit);
      else commit();
      // A failed candidate stays reserved until authentic retirement/collection;
      // it can never be reused as another tab's fresh replacement.
    },
    closeUser(window: WindowHost, id: string, expected: number) {
      const target = tabs.get(id); if (!target || target.page.window !== window) throw refused('tab_not_found');
      const pending = retirements.get(target);
      if (pending) { if (pending.generation !== expected) throw refused('control_changed'); return pending.promise; }
      generation(target, expected); return retire(target);
    },
    async closeAgent(client: string, id: string, expected: number) {
      const target = registry.get(id), current = state(target);
      if (!lifecycle.connected(client) || !current.visibleTo.includes(client)) throw refused('tab_not_found');
      generation(target, expected);
      if (current.controller.kind !== 'agent' || current.controller.client !== client) throw refused('control_refused');
      await retire(target);
    },
    retireWindowTabs,
    closeWindow(window: WindowHost) {
      const pending = windowClosures.get(window); if (pending) return pending;
      assertWindowHost(window);
      let resolve!: () => void, reject!: (reason: unknown) => void;
      const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
      windowClosures.set(window, promise); // precedes every invalidation/native callback
      void retireWindowTabs(window).then(() => window.close()).then(resolve, reject);
      return promise;
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
