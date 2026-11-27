import type { Contract } from '../contracts/generated.js';
import type { ProfileNavigationRequest, ProfileNavigationState } from '../host/profile-navigation.js';
type State = Contract<'browser.ShellEvent'>;
type Request = Contract<'browser.ShellRequest'>;
interface ShellBridge {
  request(request: Request): Promise<Contract<'browser.ShellSuccess'> | Contract<'browser.ShellFailure'>>;
  subscribe(receive: (state: State) => void): () => void;
  resync(): Promise<State>;
  profiles(request: ProfileNavigationRequest): Promise<ProfileNavigationState | { error: string } | null>;
}
declare global { interface Window { browserShell: ShellBridge } }
const api = window.browserShell;
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const button = (id: string) => element<HTMLButtonElement>(id);
const address = element<HTMLInputElement>('address'), client = element<HTMLSelectElement>('client');
let state: State | undefined, selected = '', synchronized = false, pending = 0, recoveryTab = '';
let syncTask: Promise<void> | undefined, newestRevision = 0, selecting = false;
let tabOrder: string[] = [], focusKey = '';
const requests = new Set<string>();
const profileList = element('profile-list'), tabList = element('tabs');
const tabActions = element<HTMLDetailsElement>('tab-actions');
let tabListKey = '';
const profileStatus = element('profile-status');
const profileStatusHome = profileStatus.parentElement!;
let profiles: ProfileNavigationState | undefined, changingProfile = false, refreshingProfiles = false, profileRevision = 0;
let openingProfileKey = '';

function profileLabel(id: string): string {
  if (id === 'default') return 'Default';
  if (/^seqoya-[0-9a-f]{32}$/.test(id)) return `Seqoya · ${id.slice(-8)}`;
  return id.split('-').map(word => word ? word[0]!.toUpperCase() + word.slice(1) : '').join(' ');
}
function updateProfileControls(): void {
  profileList.setAttribute('aria-busy', String(changingProfile));
}
function renderProfiles(): void {
  if (!openingProfileKey && profileStatus.parentElement !== profileStatusHome) profileStatusHome.append(profileStatus);
  const entries = profiles?.profiles ?? [];
  if (!entries.length) return;
  const keys = new Set(entries.map(entry => entry.id + ':' + entry.instance));
  const chrome = new Map(state?.profileTabs?.map(profile => [profile.id + ':' + profile.instance, profile.tabs]));
  const existing = new Map<string, HTMLElement>();
  const focused = document.activeElement as HTMLElement | null;
  for (const row of profileList.querySelectorAll<HTMLElement>('[data-profile-key]')) {
    const key = row.dataset.profileKey!;
    if (keys.has(key)) existing.set(key, row);
    else row.remove();
  }
  let next = profileList.firstElementChild;
  for (const [index, entry] of entries.entries()) {
    const key = entry.id + ':' + entry.instance;
    const active = entry.id === profiles?.current;
    const opening = key === openingProfileKey;
    const name = entry.label ?? profileLabel(entry.id);
    const row = existing.get(key) ?? document.createElement('div');
    const choice = row.firstElementChild as HTMLButtonElement | null ?? document.createElement('button');
    const label = choice.firstElementChild ?? document.createElement('span');
    if (!existing.has(key)) row.className = 'profile-card';
    row.dataset.color = String(index % 12);
    row.toggleAttribute('data-active', active);
    const text = entry.unavailable ? name + ' (unavailable)' : name;
    if (label.textContent !== text) label.textContent = text;
    choice.title = text;
    choice.disabled = entry.unavailable === true;
    choice.setAttribute('aria-disabled', String(changingProfile || choice.disabled));
    choice.toggleAttribute('data-opening', opening);
    if (!existing.has(key)) {
      row.dataset.profileKey = key;
      choice.type = 'button';
      choice.className = 'profile';
      choice.append(label);
      row.append(choice);
    }
    if (active) {
      choice.setAttribute('aria-current', 'true');
      choice.setAttribute('aria-controls', 'tabs');
      choice.onclick = null;
      tabList.setAttribute('aria-label', 'Open tabs in ' + name);
      if (tabList.parentElement !== row) row.append(tabList);
    } else {
      choice.removeAttribute('aria-current');
      choice.removeAttribute('aria-controls');
      choice.onclick = () => { void profileAction({ method: 'open', profile: entry.id, instance: entry.instance }); };
    }
    let inactiveTabs = row.querySelector<HTMLDivElement>('.inactive-tabs');
    if (active) inactiveTabs?.remove();
    else {
      const links = chrome.get(key) ?? [];
      const signature = JSON.stringify(links);
      if (!inactiveTabs) {
        inactiveTabs = document.createElement('div');
        inactiveTabs.className = 'tabs inactive-tabs';
        inactiveTabs.setAttribute('role', 'group');
        row.append(inactiveTabs);
      }
      inactiveTabs.setAttribute('aria-label', 'Open tabs in ' + name);
      if (inactiveTabs.dataset.tabs !== signature) {
        inactiveTabs.dataset.tabs = signature;
        inactiveTabs.replaceChildren(...links.map(link => {
          const node = document.createElement('button');
          node.type = 'button';
          node.className = 'tab';
          node.textContent = link.title || 'New tab';
          node.title = node.textContent;
          node.dir = 'auto';
          node.dataset.key = link.id;
          node.onclick = () => { void profileAction({ method: 'open', profile: entry.id, instance: entry.instance, tab: link.id }); };
          return node;
        }));
      }
    }
    if (opening && profileStatus.parentElement !== row) row.append(profileStatus);
    if (row !== next) profileList.insertBefore(row, next);
    next = row.nextElementSibling;
  }
  if (focused && focused !== document.activeElement && profileList.contains(focused))
    focused.focus({ preventScroll: true });
}
async function profileAction(request: ProfileNavigationRequest): Promise<void> {
  if (request.method === 'create') return;
  const listing = request.method === 'list';
  if (changingProfile || (listing && refreshingProfiles) || state?.profileNavigationReady !== true) return;
  const revision = listing ? profileRevision : ++profileRevision;
  if (listing) refreshingProfiles = true;
  else {
    changingProfile = true;
    if (request.method === 'open' && !state?.profileTabs?.some(profile =>
      profile.id === request.profile && profile.instance === request.instance)) {
      openingProfileKey = request.profile + ':' + request.instance;
      renderProfiles();
    }
    updateProfileControls();
  }
  if (!listing || !profiles)
    profileStatus.textContent = request.method === 'open' ? openingProfileKey ? 'Opening profile…' : '' : 'Loading profiles…';
  try {
    const result = await api.profiles(request);
    if (revision !== profileRevision) return;
    if (!result) { profileStatus.textContent = ''; return; }
    if ('error' in result) { profileStatus.textContent = result.error; return; }
    if (JSON.stringify(result) !== JSON.stringify(profiles)) {
      profiles = result;
      renderProfiles();
    }
    profileStatus.textContent = '';
  } catch {
    if (revision === profileRevision) profileStatus.textContent = 'Could not load or change the Browser profiles.';
  }
  finally {
    if (listing) refreshingProfiles = false;
    else {
      changingProfile = false;
      if (openingProfileKey) {
        openingProfileKey = '';
        renderProfiles();
      }
    }
    updateProfileControls();
  }
}
const current = () => state?.tabs.find(tab => tab.tab === selected);
const problem = (text: string) => { element('problem').textContent = text; };
function accept(value: State, snapshot = false) {
  if (!value || value.ui !== 1 || value.event !== 'state' || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !Array.isArray(value.tabs) || !Array.isArray(value.attachments)) { synchronized = false; render(); return; }
  newestRevision = Math.max(newestRevision, value.revision);
  if (state && value.revision <= state.revision) { if (snapshot && value.revision === state.revision) synchronized = state.revision >= newestRevision; render(); return; }
  if (!snapshot && state && value.revision !== state.revision + 1) { synchronized = false; render(); void resync(); return; }
  const canLoadProfiles = value.profileNavigationReady && !state?.profileNavigationReady;
  const tabsChanged = JSON.stringify(state?.profileTabs) !== JSON.stringify(value.profileTabs);
  state = value; synchronized = value.revision >= newestRevision;
  if (tabsChanged && profiles) renderProfiles();
  const nextTab = value.tabs[0]?.tab ?? ''; // authoritative versioned native selection, never a reply
  if (nextTab !== selected) { tabActions.open = false; recoveryTab = ''; }
  selected = nextTab;
  const ids = value.tabs.map(tab => tab.tab);
  tabOrder = [...tabOrder.filter(id => ids.includes(id)), ...ids.filter(id => !tabOrder.includes(id))];
  render();
  if (canLoadProfiles) void profileAction({ method: 'list' });
}
async function resync(force = false): Promise<void> {
  if (syncTask) { await syncTask; if (!force) return; return resync(true); }
  const task = (async () => {
    try { do { accept(await api.resync(), true); } while (state && state.revision < newestRevision); }
    catch { synchronized = false; problem('Browser state is unavailable. Close and reopen this window.'); render(); }
  })();
  syncTask = task;
  try { await task; } finally { if (syncTask === task) syncTask = undefined; }
}
function requestId() {
  return `req_${btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')}`;
}
async function send(method: Request['method'], extra: Record<string, unknown> = {}) {
  const priority = ['take', 'close_tab', 'close_window'].includes(method);
  const key = `${selected}:${method}`;
  if ((method !== 'close_window' && (!synchronized || selecting)) || requests.has(key) || (pending > 0 && !priority)) return;
  const tab = current();
  const params = ['new_tab', 'close_window'].includes(method) ? extra : method === 'select' ? extra :
    { tab: tab?.tab, controlGeneration: tab?.generation, ...extra };
  const foreground = ['select', 'new_tab', 'close_tab'].includes(method);
  if (foreground) selecting = true;
  pending++; requests.add(key); problem(''); render();
  try {
    const reply = await api.request({ ui: 1, id: requestId(), method, params } as Request);
    if (!reply.ok) problem(`${reply.error.message} ${reply.error.remedy ?? ''}`);
    await resync(true); // a request begun before this transition cannot acknowledge its selection
  } catch { problem('The request did not complete. Read current state before trying again.'); synchronized = false; }
  finally { pending--; if (foreground) selecting = false; requests.delete(key); render(); }
}
function render() {
  const tab = current(), user = tab?.controller.kind === 'user', idle = tab?.handoff === 'idle';
  const enabled = synchronized && !selecting, idleRequest = enabled && pending === 0;
  const focus = document.activeElement as HTMLElement | null;
  if (focus && focus !== document.body) focusKey = focus.dataset.key ?? '';
  const entries = tabOrder.flatMap(id => {
    const index = state?.tabs.findIndex(tab => tab.tab === id) ?? -1;
    if (index < 0) return [];
    const title = state?.tabChrome?.[index]?.title || 'New tab';
    const generation = state!.tabs[index]!.generation;
    return [{ id, title, generation }];
  });
  const listKey = JSON.stringify({ entries, selected, enabled, idleRequest });
  if (tabListKey !== listKey) {
    tabListKey = listKey;
    tabList.replaceChildren(...entries.map(entry => {
      const row = document.createElement('div');
      row.className = 'tab-row';
      const node = document.createElement('button');
      node.type = 'button';
      node.className = 'tab';
      node.textContent = entry.title;
      node.title = entry.title;
      node.dir = 'auto';
      node.dataset.key = entry.id;
      if (entry.id === selected) node.setAttribute('aria-current', 'page');
      node.setAttribute('aria-disabled', String(!idleRequest));
      node.onclick = () => { if (entry.id !== selected) void send('select', { tab: entry.id }); };
      const close = document.createElement('button');
      close.type = 'button';
      close.className = 'icon tab-close';
      close.textContent = '×';
      close.title = 'Close tab';
      close.setAttribute('aria-label', 'Close tab: ' + entry.title);
      close.setAttribute('aria-disabled', String(!enabled));
      close.dataset.key = 'close-' + entry.id;
      close.onclick = () => { void send('close_tab', { tab: entry.id, controlGeneration: entry.generation }); };
      row.append(node, close);
      return row;
    }));
  }
  const chosen = client.value;
  client.replaceChildren(...(state?.attachments ?? []).map(entry => {
    const option = document.createElement('option'); option.value = entry.id; option.textContent = entry.label; return option;
  }));
  if (state?.attachments.some(entry => entry.id === chosen)) client.value = chosen;
  client.disabled = !idleRequest || !state?.attachments.length;
  const status = !synchronized ? (state ? 'Browser state unavailable' : 'Connecting to browser…') :
    selecting ? 'Updating tabs…' : tab?.handoff === 'taking' ? 'Taking control…' :
    tab?.controller.kind === 'agent' ? tab.controller.label + ' controls this tab' :
    tab && tab.pageAvailability !== 'ready' ? 'Page ' + tab.pageAvailability : '';
  element('state').textContent = status;
  button('new').disabled = !idleRequest || entries.length >= 7;
  button('new').title = entries.length >= 7 ? 'Close a tab before opening an eighth tab in this profile' : 'New tab';
  const canNavigate = idleRequest && !!user && idle;
  const chrome = state?.tabChrome?.[0];
  button('back').disabled = !canNavigate || !chrome?.back;
  button('forward').disabled = !canNavigate || !chrome?.forward;
  button('reload').disabled = !canNavigate;
  address.disabled = !idleRequest || (!!tab && !canNavigate);

  const hasClients = !!state?.attachments.length;
  tabActions.hidden = !tab || (!!user && !hasClients && tab.pageAvailability === 'ready');
  if (tabActions.hidden) tabActions.open = false;
  client.hidden = !user || !hasClients;
  button('share').hidden = button('return').hidden = client.hidden;
  button('take').hidden = !tab || !!user && tab.handoff !== 'taking';
  button('recover').hidden = !tab || !user || tab.pageAvailability === 'ready';
  button('share').disabled = !canNavigate || !client.value || !!tab?.visibleTo.includes(client.value);
  button('return').disabled = !canNavigate || tab?.pageAvailability !== 'ready' || !tab?.inputReady || !tab.visibleTo.includes(client.value);
  button('take').disabled = !enabled || !tab || !!user || !idle;
  button('recover').disabled = !canNavigate || tab?.pageAvailability === 'ready';
  element('recovery-confirmation').hidden = recoveryTab !== tab?.tab || !recoveryTab || button('recover').hidden;
  button('recover-confirm').disabled = button('recover').disabled;
  element('grants').replaceChildren(...(tab?.visibleTo ?? []).map(id => {
    const node = document.createElement('button'); node.type = 'button'; node.dataset.key = 'stop-' + id;
    node.textContent = 'Stop sharing with ' + (state?.attachments.find(entry => entry.id === id)?.label ?? 'disconnected agent');
    node.disabled = !idleRequest; node.onclick = () => { void send('stop_sharing', { client: id }); }; return node;
  }));
  if (focusKey) [...document.querySelectorAll<HTMLElement>('[data-key]')].find(node => node.dataset.key === focusKey)?.focus();
}
button('new').onclick = () => { void send('new_tab'); };
let profileRefresh: ReturnType<typeof setTimeout> | undefined;
window.addEventListener('focus', () => {
  clearTimeout(profileRefresh);
  profileRefresh = setTimeout(() => { if (document.hasFocus()) void profileAction({ method: 'list' }); }, 600);
});
for (const method of ['back', 'forward', 'reload', 'take'] as const) button(method).onclick = () => { void send(method); };
button('recover').onclick = () => { recoveryTab = selected; render(); button('recover-cancel').focus(); };
button('recover-confirm').onclick = () => { if (recoveryTab === selected) { recoveryTab = ''; void send('recover'); } };
button('recover-cancel').onclick = () => { recoveryTab = ''; render(); button('recover').focus(); };
for (const method of ['share', 'return'] as const) button(method).onclick = () => { void send(method, { client: client.value }); };
client.onchange = render;
element<HTMLFormElement>('navigate').onsubmit = event => {
  event.preventDefault();
  const draft = address.value.trim();
  if (!draft) return;
  const url = /^[a-z][a-z0-9+.-]*:/i.test(draft) ? draft : 'https://' + draft;
  void send(current() ? 'user_navigate' : 'new_tab', { url });
};
api.subscribe(value => accept(value));
render(); void resync();
