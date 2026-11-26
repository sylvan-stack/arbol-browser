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
const profilePanel = element('profile-panel'), profilePicker = element<HTMLSelectElement>('profile-select');
const profileName = element<HTMLInputElement>('profile-id'), profileStatus = element('profile-status');
let profiles: ProfileNavigationState | undefined, changingProfile = false;

function profileLabel(id: string): string {
  if (id === 'default') return 'Default';
  if (/^seqoya-[0-9a-f]{32}$/.test(id)) return `Seqoya · ${id.slice(-8)}`;
  return id.split('-').map(word => word ? word[0]!.toUpperCase() + word.slice(1) : '').join(' ');
}
function renderProfiles(): void {
  profilePicker.disabled = changingProfile || !profiles;
  profileName.disabled = changingProfile || !profiles;
  button('profile-add').disabled = profileName.disabled;
  button('profile-open').disabled = profilePicker.disabled || !profilePicker.value || profilePicker.value === profiles?.current;
}
async function profileAction(request: ProfileNavigationRequest): Promise<void> {
  if (changingProfile) return;
  changingProfile = true; renderProfiles();
  profileStatus.textContent = request.method === 'open' ? 'Opening profile…' : request.method === 'create' ? 'Creating profile…' : 'Loading profiles…';
  try {
    const result = await api.profiles(request);
    if (!result) { profilePanel.hidden = true; button('profiles').hidden = true; return; }
    if ('error' in result) { profileStatus.textContent = result.error; return; }
    profiles = result;
    const previous = request.method === 'create' ? request.profile : profilePicker.value;
    profilePicker.replaceChildren(...result.profiles.map(entry => {
      const option = document.createElement('option');
      option.value = entry.id;
      option.disabled = entry.unavailable === true;
      const status = entry.unavailable ? ' (unavailable)' : entry.id === result.current ? ' (current)' : '';
      option.textContent = (entry.label ?? profileLabel(entry.id)) + status;
      return option;
    }));
    profilePicker.value = result.profiles.some(entry => entry.id === previous && !entry.unavailable) ? previous : result.current;
    if (request.method === 'create') profileName.value = '';
    profileStatus.textContent = request.method === 'open' ? 'Profile window opened.' : request.method === 'create' ? 'Profile created.' : '';
  } catch { profileStatus.textContent = 'Could not load or change the Browser profiles.'; }
  finally { changingProfile = false; renderProfiles(); }
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
  selected = value.tabs[0]?.tab ?? ''; // authoritative versioned native selection, never a reply
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
  element('tabs').replaceChildren(...tabOrder.flatMap((id, index) => {
    const entry = state?.tabs.find(tab => tab.tab === id); if (!entry) return [];
    const node = document.createElement('button'); node.type = 'button'; node.textContent = `Tab ${index + 1}`;
    node.dataset.key = entry.tab; node.setAttribute('aria-current', entry.tab === selected ? 'page' : 'false');
    node.disabled = !idleRequest; node.onclick = () => { recoveryTab = ''; void send('select', { tab: entry.tab }); }; return [node];
  }));
  const chosen = client.value;
  client.replaceChildren(...(state?.attachments ?? []).map(entry => {
    const option = document.createElement('option'); option.value = entry.id; option.textContent = entry.label; return option;
  }));
  if (state?.attachments.some(entry => entry.id === chosen)) client.value = chosen;
  client.disabled = !idleRequest || !state?.attachments.length;
  const owner = !tab ? 'No open tabs' : tab.controller.kind === 'user' ? 'You control this tab · Private' : `${tab.controller.label} controls this tab`;
  element('state').textContent = `${owner}${tab ? ` · ${tab.pageAvailability} · ${tab.handoff === 'taking' ? 'Taking control…' : tab.inputReady ? 'Input ready' : 'Input unavailable'}` : ''}${selecting ? ' · Selecting tab…' : ''}${!synchronized ? ' · State unavailable' : ''}`;
  button('new').disabled = !idleRequest;
  button('close-window').disabled = false; // contains no tab identity/generation and stays independently authenticated
  for (const id of ['go', 'back', 'forward', 'reload']) button(id).disabled = !idleRequest || !user || !idle;
  address.disabled = !idleRequest || !user || !idle;
  button('close-tab').disabled = !enabled || !tab;
  button('share').disabled = !idleRequest || !user || !idle || !client.value || !!tab?.visibleTo.includes(client.value);
  button('return').disabled = !idleRequest || !user || !idle || tab?.pageAvailability !== 'ready' || !tab?.inputReady || !tab.visibleTo.includes(client.value);
  button('take').disabled = !enabled || !tab || user || !idle;
  button('recover').disabled = !idleRequest || !user || !idle || tab?.pageAvailability === 'ready';
  element('recovery-confirmation').hidden = recoveryTab !== tab?.tab || !recoveryTab;
  button('recover-confirm').disabled = button('recover').disabled;
  element('grants').replaceChildren(...(tab?.visibleTo ?? []).map(id => {
    const node = document.createElement('button'); node.type = 'button'; node.dataset.key = `stop-${id}`;
    node.textContent = `Stop sharing with ${state?.attachments.find(entry => entry.id === id)?.label ?? 'disconnected agent'}`;
    node.disabled = !idleRequest; node.onclick = () => { void send('stop_sharing', { client: id }); }; return node;
  }));
  if (focusKey) [...document.querySelectorAll<HTMLElement>('[data-key]')].find(node => node.dataset.key === focusKey)?.focus();
}
button('new').onclick = () => { void send('new_tab'); };
button('profiles').onclick = () => {
  profilePanel.hidden = !profilePanel.hidden;
  button('profiles').setAttribute('aria-expanded', String(!profilePanel.hidden));
  if (!profilePanel.hidden) void profileAction({ method: 'list' });
};
profilePicker.onchange = renderProfiles;
button('profile-open').onclick = () => {
  const profile = profiles?.profiles.find(entry => entry.id === profilePicker.value);
  if (profile && !profile.unavailable) void profileAction({ method: 'open', profile: profile.id, instance: profile.instance });
};
element<HTMLFormElement>('profile-create').onsubmit = event => {
  event.preventDefault();
  void profileAction({ method: 'create', profile: profileName.value.trim() });
};
button('close-window').onclick = () => { void send('close_window'); };
button('close-tab').onclick = () => { void send('close_tab'); };
for (const method of ['back', 'forward', 'reload', 'take'] as const) button(method).onclick = () => { void send(method); };
button('recover').onclick = () => { recoveryTab = selected; render(); button('recover-cancel').focus(); };
button('recover-confirm').onclick = () => { if (recoveryTab === selected) { recoveryTab = ''; void send('recover'); } };
button('recover-cancel').onclick = () => { recoveryTab = ''; render(); button('recover').focus(); };
for (const method of ['share', 'return'] as const) button(method).onclick = () => { void send(method, { client: client.value }); };
client.onchange = render;
element<HTMLFormElement>('navigate').onsubmit = event => { event.preventDefault(); void send('user_navigate', { url: address.value }); };
api.subscribe(value => accept(value));
renderProfiles(); render(); void resync();
