import type { Contract } from '../contracts/generated.js';
type State = Contract<'browser.ShellEvent'>;
type Request = Contract<'browser.ShellRequest'>;
interface ShellBridge {
  request(request: Request): Promise<Contract<'browser.ShellSuccess'> | Contract<'browser.ShellFailure'>>;
  subscribe(receive: (state: State) => void): () => void;
  resync(): Promise<State>;
}
declare global { interface Window { browserShell: ShellBridge } }
const api = window.browserShell;
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const button = (id: string) => element<HTMLButtonElement>(id);
const address = element<HTMLInputElement>('address'), client = element<HTMLSelectElement>('client');
let state: State | undefined, selected = '', synchronized = false, pending = 0, syncing = false, recoveryTab = '';
const requests = new Set<string>();
const current = () => state?.tabs.find(tab => tab.tab === selected);
const problem = (text: string) => { element('problem').textContent = text; };
function accept(value: State, snapshot = false) {
  if (!value || value.ui !== 1 || value.event !== 'state' || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !Array.isArray(value.tabs) || !Array.isArray(value.attachments)) { synchronized = false; render(); return; }
  if (state && value.revision <= state.revision) { if (snapshot && value.revision === state.revision) synchronized = true; render(); return; }
  if (!snapshot && state && value.revision !== state.revision + 1) { synchronized = false; render(); void resync(); return; }
  state = value; synchronized = true;
  if (!value.tabs.some(tab => tab.tab === selected)) selected = value.tabs[0]?.tab ?? '';
  render();
}
async function resync() {
  if (syncing) return; syncing = true;
  try { accept(await api.resync(), true); }
  catch { synchronized = false; problem('Browser state is unavailable. Close and reopen this window.'); render(); }
  finally { syncing = false; }
}
function requestId() {
  return `req_${btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')}`;
}
async function send(method: Request['method'], extra: Record<string, unknown> = {}) {
  const priority = ['take', 'close_tab', 'close_window'].includes(method);
  const key = `${selected}:${method}`;
  if (!synchronized || requests.has(key) || (pending > 0 && !priority)) return;
  const tab = current();
  const params = ['new_tab', 'close_window'].includes(method) ? extra : method === 'select' ? extra :
    { tab: tab?.tab, controlGeneration: tab?.generation, ...extra };
  pending++; requests.add(key); problem(''); render();
  try {
    const reply = await api.request({ ui: 1, id: requestId(), method, params } as Request);
    if (!reply.ok) problem(`${reply.error.message} ${reply.error.remedy ?? ''}`);
    else if (reply.state && ['select', 'new_tab'].includes(method)) selected = reply.state.tab;
    await resync();
  } catch { problem('The request did not complete. Read current state before trying again.'); synchronized = false; }
  finally { pending--; requests.delete(key); render(); }
}
function render() {
  const tab = current(), user = tab?.controller.kind === 'user', idle = tab?.handoff === 'idle';
  const enabled = synchronized, idleRequest = enabled && pending === 0;
  const focus = document.activeElement as HTMLElement | null;
  const key = focus?.dataset.key;
  element('tabs').replaceChildren(...(state?.tabs ?? []).map((entry, index) => {
    const node = document.createElement('button'); node.type = 'button'; node.textContent = `Tab ${index + 1}`;
    node.dataset.key = entry.tab; node.setAttribute('aria-current', entry.tab === selected ? 'page' : 'false');
    node.disabled = !idleRequest; node.onclick = () => { recoveryTab = ''; void send('select', { tab: entry.tab }); }; return node;
  }));
  const chosen = client.value;
  client.replaceChildren(...(state?.attachments ?? []).map(entry => {
    const option = document.createElement('option'); option.value = entry.id; option.textContent = entry.label; return option;
  }));
  if (state?.attachments.some(entry => entry.id === chosen)) client.value = chosen;
  client.disabled = !idleRequest || !state?.attachments.length;
  const owner = !tab ? 'No open tabs' : tab.controller.kind === 'user' ? 'You control this tab · Private' : `${tab.controller.label} controls this tab`;
  element('state').textContent = `${owner}${tab ? ` · ${tab.pageAvailability} · ${tab.handoff === 'taking' ? 'Taking control…' : tab.inputReady ? 'Input ready' : 'Input unavailable'}` : ''}${!synchronized ? ' · State unavailable' : ''}`;
  button('new').disabled = !idleRequest;
  button('close-window').disabled = !enabled;
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
  if (key) [...document.querySelectorAll<HTMLElement>('[data-key]')].find(node => node.dataset.key === key)?.focus();
}
button('new').onclick = () => { void send('new_tab'); };
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
render(); void resync();
