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
const profileCreate = element<HTMLDetailsElement>('profile-create-panel');
let tabListKey = '';
const profileName = element<HTMLInputElement>('profile-id'), profileStatus = element('profile-status');
let profiles: ProfileNavigationState | undefined, changingProfile = false;

function profileLabel(id: string): string {
  if (id === 'default') return 'Default';
  if (/^seqoya-[0-9a-f]{32}$/.test(id)) return `Seqoya · ${id.slice(-8)}`;
  return id.split('-').map(word => word ? word[0]!.toUpperCase() + word.slice(1) : '').join(' ');
}
function updateProfileControls(): void {
  profileCreate.hidden = !profiles;
  profileName.disabled = changingProfile || !profiles;
  button('profile-add').disabled = profileName.disabled;
  for (const choice of profileList.querySelectorAll<HTMLButtonElement>('button'))
    choice.setAttribute('aria-disabled', String(changingProfile || choice.disabled));
}
function renderProfiles(): void {
  const entries = profiles?.profiles ?? [];
  if (!entries.length) return;
  const active = entries.find(entry => entry.id === profiles?.current);
  const labels = entries.map(entry => {
    const name = entry.label ?? profileLabel(entry.id);
    const row = document.createElement('div');
    const choice = document.createElement('button');
    const label = document.createElement('span');
    label.textContent = entry.unavailable ? name + ' (unavailable)' : name;
    choice.append(label);
    choice.type = 'button';
    choice.className = 'profile';
    choice.title = label.textContent;
    choice.disabled = entry.unavailable === true;
    choice.setAttribute('aria-disabled', String(changingProfile || choice.disabled));
    choice.dataset.profile = entry.id;
    if (entry === active) {
      choice.setAttribute('aria-current', 'true');
      choice.setAttribute('aria-controls', 'tabs');
      choice.setAttribute('aria-expanded', 'true');
    } else {
      choice.setAttribute('aria-expanded', 'false');
      choice.onclick = () => { void profileAction({ method: 'open', profile: entry.id, instance: entry.instance }); };
    }
    row.append(choice);
    return row;
  });
  const focused = document.activeElement as HTMLElement | null;
  const previous = focused?.dataset.profile;
  profileList.replaceChildren(...labels);
  if (active) {
    const current = labels[entries.indexOf(active)]!;
    tabList.setAttribute('aria-label', 'Open tabs in ' + (active.label ?? profileLabel(active.id)));
    current.append(tabList);
  }
  if (previous) [...profileList.querySelectorAll<HTMLButtonElement>('[data-profile]')]
    .find(choice => choice.dataset.profile === previous)?.focus({ preventScroll: true });
  else if (focused && tabList.contains(focused)) focused.focus({ preventScroll: true });
}
async function profileAction(request: ProfileNavigationRequest): Promise<void> {
  if (changingProfile) return;
  changingProfile = true; updateProfileControls();
  if (request.method !== 'list' || !profiles)
    profileStatus.textContent = request.method === 'open' ? 'Opening profile…' : request.method === 'create' ? 'Creating profile…' : 'Loading profiles…';
  try {
    const result = await api.profiles(request);
    if (!result) { profileStatus.textContent = ''; return; }
    if ('error' in result) { profileStatus.textContent = result.error; return; }
    if (JSON.stringify(result) !== JSON.stringify(profiles)) {
      profiles = result;
      renderProfiles();
    }
    if (request.method === 'create') {
      profileName.value = '';
      profileCreate.open = false;
    }
    profileStatus.textContent = request.method === 'create' ? 'Profile created.' : '';
  } catch { profileStatus.textContent = 'Could not load or change the Browser profiles.'; }
  finally {
    changingProfile = false; updateProfileControls();
    if (request.method === 'create' && !profileCreate.open) profileCreate.querySelector('summary')?.focus();
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
  state = value; synchronized = value.revision >= newestRevision;
  const nextTab = value.tabs[0]?.tab ?? ''; // authoritative versioned native selection, never a reply
  if (nextTab !== selected) { tabActions.open = false; recoveryTab = ''; }
  selected = nextTab;
  const ids = value.tabs.map(tab => tab.tab);
  tabOrder = [...tabOrder.filter(id => ids.includes(id)), ...ids.filter(id => !tabOrder.includes(id))];
  render();
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
  button('new').disabled = !idleRequest;
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
window.addEventListener('focus', () => { void profileAction({ method: 'list' }); });
profileCreate.addEventListener('toggle', () => { if (profileCreate.open) profileName.focus(); });
element<HTMLFormElement>('profile-create').onsubmit = event => {
  event.preventDefault();
  void profileAction({ method: 'create', profile: profileName.value.trim() });
};
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
render(); void resync(); void profileAction({ method: 'list' });
