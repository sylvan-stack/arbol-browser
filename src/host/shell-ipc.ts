import { ipcMain, type IpcMainInvokeEvent, type WebContents } from 'electron';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { invalidInput, publicFailure, unavailable } from '../contracts/errors.js';
import { assertWindowHost, shellURL, type WindowHost } from './windows.js';
import { assertTabRegistry, refused, userURL, type TabRegistry, type TabTarget } from './tabs.js';

type Request = Contract<'browser.ShellRequest'>;
type Event = Contract<'browser.ShellEvent'>;
type Result = Contract<'browser.ShellSuccess'> | Contract<'browser.ShellFailure'>;
type State = Contract<'browser.ShellTab'>;
/** Required authoritative ABR-10/11 services, never renderer claims or a default stub.
 * execute owns atomic native/generation/settlement semantics, including reply fencing. */
export interface ShellAuthority {
  assertReady(): void;
  attachments(): readonly Contract<'browser.ClientIdentity'>[];
  execute(request: Request, target: TabTarget): Promise<{ state: State; settledAction?: Contract<'browser.SettledAction'> }>;
  subscribe(changed: () => void): () => void;
  exhausted(): never;
}
export interface ShellRegistration {
  /** The only supported loader; handlers and the initial projection already exist. */
  load(): Promise<void>;
  publish(): void;
  dispose(): void;
}
interface Registration {
  host: WindowHost;
  authority: ShellAuthority;
  snapshot(): Event;
  dispatch(request: Request): Promise<Result>;
}
const registrations = new WeakMap<ShellRegistration, Registration>();
const senders = new Map<WebContents, Registration>();
let installed = false;
const requestShape = validator('browser.ShellRequest'), eventShape = validator('browser.ShellEvent');
const successShape = validator('browser.ShellSuccess'), failureShape = validator('browser.ShellFailure');
function authenticated(event: IpcMainInvokeEvent): Registration {
  const current = senders.get(event.sender);
  if (!current) throw unavailable('browser');
  const { host, authority } = current;
  assertWindowHost(host); host.assertHealthy(); authority.assertReady();
  const contents = host.shell.webContents, frame = event.senderFrame;
  // file: origins serialize as null. Exact canonical URL and actual frame object are mandatory.
  if (contents.isDestroyed() || event.sender !== contents || !frame || frame !== contents.mainFrame || frame.parent !== null ||
      frame.url !== shellURL || contents.getURL() !== shellURL || host.origin !== shellURL ||
      !host.window.contentView.children.includes(host.shell)) throw unavailable('browser');
  return current;
}
function installTransport() {
  if (installed) return;
  // No request-supplied identity, role, sender or channel is accepted.
  ipcMain.handle('browser-shell:request', async (event, raw: unknown) => {
    const current = authenticated(event); // before inspecting privileged parameters
    if (!requestShape(raw)) throw invalidInput();
    let size: number;
    try { size = Buffer.byteLength(JSON.stringify(raw), 'utf8'); } catch { throw invalidInput(); }
    if (size > 1048576) throw invalidInput();
    const result = await current.dispatch(raw as Request);
    // Closing destroys the original sender; every other asynchronous reply is fenced again.
    if ((raw as Request).method !== 'close_window') {
      if (authenticated(event) !== current) throw unavailable('browser');
    }
    return result;
  });
  // Transport snapshot only: the exact ShellEvent, no additional renderer capability/data endpoint.
  ipcMain.handle('browser-shell:state', (event, ...args: unknown[]) => {
    const current = authenticated(event);
    if (args.length) throw invalidInput();
    return current.snapshot();
  });
  installed = true;
}
export function assertShellRegistration(value: ShellRegistration, host: WindowHost): void {
  const current = registrations.get(value);
  if (!current || current.host !== host || senders.get(host.shell.webContents) !== current) throw unavailable('browser');
  host.assertHealthy(); current.authority.assertReady();
}
/** Called only by trusted main-process assembly with a real authority. No fallback is supplied. */
export function registerShellIPC(host: WindowHost, tabs: TabRegistry, authority: ShellAuthority): ShellRegistration {
  assertWindowHost(host); assertTabRegistry(tabs); host.assertHealthy(); authority.assertReady();
  if (senders.has(host.shell.webContents)) throw unavailable('browser');
  let revision = 0, loaded = false, disposed = false;
  const ids = new Set<string>();
  const snapshot = (): Event => {
    host.assertHealthy(); authority.assertReady();
    if (disposed || revision >= Number.MAX_SAFE_INTEGER) return authority.exhausted();
    const value: Event = { ui: 1, event: 'state', revision: ++revision,
      tabs: tabs.all().filter(target => target.page.window === host).map(target => structuredClone(tabs.state(target))),
      attachments: authority.attachments().map(entry => ({ id: entry.id, label: entry.label })) };
    if (!eventShape(value)) throw unavailable('browser');
    return value;
  };
  const current: Registration = { host, authority, snapshot,
    async dispatch(request): Promise<Result> {
      host.assertHealthy(); authority.assertReady();
      if (ids.has(request.id) || ids.size >= 65536) throw refused('control_refused', 'Reopen the browser window to establish a fresh shell connection.');
      ids.add(request.id);
      try {
        let state: State | null = null, settledAction: Contract<'browser.SettledAction'> | undefined;
        if (request.method === 'new_tab') {
          const target = await tabs.openUser(host, userURL(request.params.url ?? 'about:blank'));
          state = tabs.state(target);
        } else if (request.method === 'select') {
          state = tabs.state(tabs.select(host, request.params.tab));
        } else if (request.method === 'close_window') {
          await tabs.closeWindow(host);
        } else {
          const target = tabs.get(request.params.tab);
          if (target.page.window !== host) throw refused('tab_not_found');
          const before = tabs.state(target);
          // Take coalescing belongs to the authority, which can identify its exact running transition.
          if (before.generation !== request.params.controlGeneration && request.method !== 'take') throw refused('control_changed');
          if (request.method === 'close_tab') await tabs.closeUser(host, target.id, before.generation);
          else {
            if (tabs.selected(host) !== target) throw refused('control_refused');
            if (['share', 'return', 'user_navigate', 'back', 'forward', 'reload', 'recover'].includes(request.method) &&
                (before.controller.kind !== 'user' || before.handoff !== 'idle')) throw refused('control_refused', 'Take control before using this action.');
            const recipient = 'client' in request.params ? request.params.client : undefined;
            if (recipient && !authority.attachments().some(entry => entry.id === recipient)) throw refused('control_refused');
            if (request.method === 'user_navigate') userURL(request.params.url);
            const result = await authority.execute(request, target);
            state = result.state; settledAction = result.settledAction;
            if (state.tab !== target.id || tabs.state(target).generation !== state.generation) throw refused('control_changed');
          }
        }
        const reply: Contract<'browser.ShellSuccess'> = { ui: 1, id: request.id, ok: true, state,
          ...(settledAction ? { settledAction } : {}) };
        if (!successShape(reply)) throw unavailable('browser');
        if (request.method !== 'close_window') { host.assertHealthy(); authority.assertReady(); registration.publish(); }
        return reply;
      } catch (error) {
        host.assertHealthy(); authority.assertReady();
        const reply: Contract<'browser.ShellFailure'> = { ui: 1, id: request.id, ok: false, error: publicFailure(error).detail };
        if (!failureShape(reply)) throw unavailable('browser'); return reply;
      }
    },
  };
  const registration: ShellRegistration = Object.freeze({
    async load() {
      assertShellRegistration(registration, host);
      if (loaded) throw unavailable('browser'); loaded = true;
      snapshot(); // initial authority/projection must validate before any load
      await host.shell.webContents.loadURL(shellURL);
      assertShellRegistration(registration, host);
      registration.publish(); host.window.show();
    },
    publish() {
      assertShellRegistration(registration, host);
      const value = snapshot();
      if (loaded && host.shell.webContents.getURL() === shellURL) host.shell.webContents.send('browser-shell:state', value);
    },
    dispose() {
      if (disposed) return; disposed = true;
      unsubscribe(); senders.delete(host.shell.webContents); registrations.delete(registration);
    },
  });
  installTransport(); senders.set(host.shell.webContents, current); registrations.set(registration, current);
  let unsubscribe: () => void = () => {};
  try {
    snapshot();
    unsubscribe = authority.subscribe(() => registration.publish());
    host.shell.webContents.once('destroyed', () => registration.dispose());
    return registration;
  } catch (error) { registration.dispose(); throw error; }
}
