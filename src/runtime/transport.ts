import { createServer, createConnection, type Socket, type Server } from 'node:net';
import { chmod } from 'node:fs/promises';
import type { Contract, ContractTypes } from '../contracts/generated.js';
import { validator, bundles } from '../contracts/schema.js';
import { BrowserFailure, unavailable, publicFailure } from '../contracts/errors.js';
import { ownerUid, profileUnavailable } from '../profiles/paths.js';
import type { PlatformPort, ProcessIdentity } from './platform.js';
import { assertSocket, now, token, originalAlive, sameProcess, recordProcess,
  type RuntimeRecord, type RuntimeLocation } from './instance.js';
import { expectedBuild, type BuildSelection } from './selection.js';

export type Endpoint = 'agent' | 'management';
export type Request = Contract<'wire.ToolRequest'> | Contract<'wire.ManagementRequest'>;
export interface ConnectionContext {
  readonly endpoint: Endpoint; readonly peer: ProcessIdentity;
  readonly attachment?: Readonly<Contract<'browser.ClientIdentity'>>;
  readonly signal: AbortSignal;
}
export interface DispatchPort {
  /** Synchronous authority checks precede scheduling; check again in execute. */
  authorize(context: ConnectionContext, request: Request): void;
  execute(context: ConnectionContext, request: Request, deadline: number, signal: AbortSignal): Promise<unknown>;
  /** Synchronous final privacy/integrity check immediately before socket.write. */
  commit(context: ConnectionContext, request: Request): void;
  /** Close grants/admission synchronously; drain/retire asynchronously elsewhere. */
  disconnect(context: ConnectionContext): void;
  /** Stops admission synchronously, then drains/retires actual dispatched work.
   * An acknowledgement of lookup never claims cancellation succeeded. */
  cancel(context: ConnectionContext, requestId: string): void;
  fatal(): void;
}
export function capacityFailure(): BrowserFailure {
  return new BrowserFailure({ code: 'control_refused', message: 'Browser capacity is exhausted.',
    retryable: true, remedy: 'Wait for outstanding work to settle, then inspect fresh state.' });
}
export function sanitizedLabel(value: string): string {
  return [...value.normalize('NFC').replace(/[\p{Cc}\p{Cf}\p{Cs}]/gu, '')].slice(0, 80).join('');
}
function fd(socket: Socket): number {
  // Node's libuv descriptor is private and version-pinned. Missing handle fails
  // closed; no peer identity inferred from a pathname or caller-supplied PID.
  const value = (socket as unknown as { _handle?: { fd?: number } })._handle?.fd;
  if (!Number.isInteger(value) || value! < 0) throw unavailable('browser');
  return value!;
}
function peer(socket: Socket, platform: PlatformPort): ProcessIdentity {
  const identity = platform.peerIdentity(fd(socket));
  if (identity.uid !== ownerUid()) throw unavailable('browser');
  return identity;
}
/** No decoded or aggregate buffer may grow past one bounded frame. */
function frames(socket: Socket, maximum: number, receive: (value: unknown) => void, fail: () => void): void {
  let pending: Buffer = Buffer.alloc(0);
  socket.on('data', (chunk: Buffer) => {
    try {
      let start = 0;
      while (start < chunk.length) {
        const newline = chunk.indexOf(10, start), end = newline < 0 ? chunk.length : newline;
        if (pending.length + end - start > maximum) throw new Error();
        pending = Buffer.concat([pending, chunk.subarray(start, end)]);
        if (newline < 0) break;
        if (!pending.length) throw new Error();
        const frame: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(pending));
        pending = Buffer.alloc(0);
        if (!frame || Array.isArray(frame) || typeof frame !== 'object') throw new Error();
        receive(frame); if (socket.destroyed) return;
        start = newline + 1;
      }
    } catch { fail(); }
  });
  socket.once('end', fail); socket.once('error', fail); socket.once('close', () => { pending = Buffer.alloc(0); fail(); });
}
function write(socket: Socket, value: unknown, maximum = 8 * 1024 * 1024): void {
  const bytes = Buffer.from(JSON.stringify(value) + '\n', 'utf8');
  if (bytes.length - 1 > maximum || socket.destroyed || socket.writableLength + bytes.length > 8 * 1024 * 1024)
    throw unavailable('browser');
  socket.write(bytes);
}
function resultValidator(request: Request): (value: unknown) => boolean {
  if (request.method === 'open') return validator('wire.OpenResult');
  if (request.method === 'close') return validator('wire.CloseResult');
  const name = request.params.name;
  if (name === 'browser_screenshot') return validator('browser.ScreenshotPayload');
  const reference = bundles.browser['x-tools'][name].success.$ref;
  return validator(`browser.${reference.split('/').at(-1)}` as keyof ContractTypes);
}
function duration(request: Request): number {
  if (request.method === 'close') return 8000;
  if (request.method === 'open') return 15000;
  switch (request.params.name) {
    case 'browser_info': case 'browser_tabs_list': return 2000;
    case 'browser_tab_open': case 'browser_navigate': return 15000;
    case 'browser_release': return 6000;
    default: return 5000;
  }
}
/** Shared across both sockets, so limits are per profile, never per adapter. */
class Scheduler {
  private reads = 0; private screenshots = 0;
  private readonly tabs = new Map<string, { busy: boolean; waiting: Array<() => void> }>();
  async run(request: Request, signal: AbortSignal, work: () => Promise<unknown>): Promise<unknown> {
    if (request.method !== 'tool') return work();
    const name = request.params.name;
    if (['browser_snapshot', 'browser_screenshot'].includes(name)) {
      const screenshot = name === 'browser_screenshot';
      if (this.reads >= 4 || (screenshot && this.screenshots >= 1)) throw capacityFailure();
      ++this.reads; if (screenshot) ++this.screenshots;
      try { if (signal.aborted) throw unavailable('browser'); return await work(); }
      finally { --this.reads; if (screenshot) --this.screenshots; }
    }
    const args = request.params.arguments;
    if (!('tab' in args) || ['browser_info', 'browser_tabs_list', 'browser_release'].includes(name)) return work();
    const key = args.tab;
    let slot = this.tabs.get(key);
    if (!slot) {
      if (this.tabs.size >= 64) throw capacityFailure();
      slot = { busy: false, waiting: [] }; this.tabs.set(key, slot);
    }
    const current = slot;
    if (current.busy) {
      if (current.waiting.length >= 4) throw capacityFailure();
      await new Promise<void>((resolve, reject) => {
        const wake = () => { signal.removeEventListener('abort', abort); resolve(); };
        const abort = () => {
          const index = current.waiting.indexOf(wake);
          if (index >= 0) current.waiting.splice(index, 1);
          reject(unavailable('browser'));
        };
        if (signal.aborted) { reject(unavailable('browser')); return; }
        current.waiting.push(wake); signal.addEventListener('abort', abort, { once: true });
      });
    }
    current.busy = true;
    try { if (signal.aborted) throw unavailable('browser'); return await work(); }
    finally {
      const next = current.waiting.shift();
      if (next) next(); else { current.busy = false; this.tabs.delete(key); }
    }
  }
}
export interface TransportServer { openAdmission(): void; closeAdmission(): void; close(): Promise<void> }
export async function listenTransport(location: RuntimeLocation, record: RuntimeRecord, platform: PlatformPort,
  dispatch: DispatchPort): Promise<TransportServer> {
  let admission = false, sealed = false, agents = 0, management = 0;
  const connections = new Set<() => void>(), servers: Server[] = [], scheduler = new Scheduler();
  function accepted(socket: Socket, endpoint: Endpoint): void {
    let context: ConnectionContext | undefined, dead = false, handshaking = true;
    let identity: ProcessIdentity;
    const connection = new AbortController();
    const active = new Map<string, AbortController>(), seen = new Set<string>();
    let helloTimer: NodeJS.Timeout, heartbeat: NodeJS.Timeout;
    let pingId: string | undefined, lastPong = now();
    const stop = () => {
      if (dead) return; dead = true; connections.delete(stop);
      clearTimeout(helloTimer); clearInterval(heartbeat);
      connection.abort(); for (const controller of active.values()) controller.abort();
      if (context) {
        if (endpoint === 'agent') --agents; else --management;
        try { dispatch.disconnect(context); } catch { dispatch.fatal(); }
      }
      socket.destroy();
    };
    connections.add(stop);
    try { if (!admission || connections.size > 64) throw capacityFailure(); identity = peer(socket, platform); }
    catch { stop(); return; }
    function response(id: string, value: unknown) { write(socket, { wire: 1, id, ok: true, result: value }); }
    function checkPeer() { if (!sameProcess(identity, peer(socket, platform))) throw unavailable('browser'); }
    helloTimer = setTimeout(stop, 5000);
    frames(socket, 1024 * 1024, value => {
      try {
        if (dead) return;
        if (!context) {
          if (!handshaking || !validator('wire.Hello')(value)) throw unavailable('browser');
          const p = value.params;
          if (p.instance !== record.instance || p.nonce !== record.nonce || p.profile !== record.profile ||
              p.profileInstance !== record.profileInstance || (p.expectedBuild !== undefined && p.expectedBuild !== record.build))
            throw unavailable('browser');
          if (!admission || (endpoint === 'agent' ? agents >= 32 : management >= 32)) throw capacityFailure();
          checkPeer(); seen.add(value.id); handshaking = false;
          const attachment = endpoint === 'agent' ? Object.freeze({ id: token('att'), label: sanitizedLabel(p.label) }) : undefined;
          context = Object.freeze({ endpoint, peer: identity, signal: connection.signal, ...(attachment ? { attachment } : {}) });
          if (endpoint === 'agent') ++agents; else ++management;
          const reply: Contract<'wire.HelloResult'> = { wire: 1, id: value.id, ok: true,
            result: { instance: record.instance, nonce: record.nonce, profile: record.profile,
              profileInstance: record.profileInstance, build: record.build, contract: 1, ...(attachment ? { attachment } : {}) } };
          if (!validator('wire.HelloResult')(reply)) throw unavailable('browser');
          write(socket, reply); clearTimeout(helloTimer);
          heartbeat = setInterval(() => {
            try {
              if (now() - lastPong >= 6000) { stop(); return; }
              if (!pingId) {
                if (seen.size >= 65536) { stop(); return; }
                pingId = token('req'); seen.add(pingId); write(socket, { wire: 1, id: pingId, method: 'ping', params: {} }); }
            } catch { stop(); }
          }, 2000);
          return;
        }
        checkPeer();
        if (validator('wire.Response')(value)) {
          if (!pingId || value.id !== pingId || !value.ok || Object.keys(value.result).length) throw unavailable('browser');
          pingId = undefined; lastPong = now(); return;
        }
        const valid = validator('wire.Ping')(value) || validator('wire.Cancel')(value) ||
          (endpoint === 'agent' ? validator('wire.ToolRequest')(value) : validator('wire.ManagementRequest')(value));
        if (!valid) throw unavailable('browser');
        const request = value as Request | Contract<'wire.Ping'> | Contract<'wire.Cancel'>;
        if (seen.has(request.id) || seen.size >= 65536) throw unavailable('browser');
        seen.add(request.id);
        if (request.method === 'ping') { response(request.id, {}); return; }
        if (request.method === 'cancel') {
          const target = active.get(request.params.request);
          if (target) { dispatch.cancel(context, request.params.request); target.abort(); }
          response(request.id, { request: request.params.request, found: Boolean(target) }); return;
        }
        if (!admission) throw unavailable('browser');
        if (active.size >= 32) {
          write(socket, { wire: 1, id: request.id, ok: false, error: capacityFailure().detail }); return;
        }
        const deadline = now() + duration(request), controller = new AbortController(), captured = context;
        const abort = () => controller.abort();
        connection.signal.addEventListener('abort', abort, { once: true });
        active.set(request.id, controller);
        // A timeout closes transport/admission and delegates actual drain/retire;
        // it never emits a synthetic successful cancellation or action outcome.
        const timer = setTimeout(() => {
          try { dispatch.cancel(captured, request.id); } catch { dispatch.fatal(); }
          controller.abort(); stop();
        }, Math.max(1, deadline - now()));
        void (async () => {
          try {
            dispatch.authorize(captured, request);
            const result = await scheduler.run(request, controller.signal, () => dispatch.execute(captured, request, deadline, controller.signal));
            if (dead || controller.signal.aborted || now() >= deadline) return;
            if (!resultValidator(request)(result)) throw unavailable('browser');
            checkPeer(); dispatch.commit(captured, request); response(request.id, result);
          } catch (error) {
            if (!dead && !controller.signal.aborted) {
              // Provider errors are public redacted BrowserFailure only.
              try { write(socket, { wire: 1, id: request.id, ok: false, error: publicFailure(error).detail }); }
              catch { stop(); }
            }
          } finally {
            clearTimeout(timer); active.delete(request.id); connection.signal.removeEventListener('abort', abort);
          }
        })();
      } catch { stop(); }
    }, stop);
  }
  try {
    for (const endpoint of ['agent', 'management'] as const) {
      await location.assert();
      const path = endpoint === 'agent' ? location.agent : location.management;
      const server = createServer(socket => accepted(socket, endpoint)); servers.push(server);
      server.on('error', () => { admission = false; for (const stop of [...connections]) stop(); dispatch.fatal(); });
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject); server.listen(path, () => { server.removeListener('error', reject); resolve(); });
      });
      await chmod(path, 0o600); await assertSocket(location, path);
    }
  } catch (error) {
    admission = false; for (const stop of [...connections]) stop();
    for (const server of servers) server.close(); throw error;
  }
  return Object.freeze({
    openAdmission() { if (sealed) throw unavailable('browser'); admission = true; },
    closeAdmission() { sealed = true; admission = false; for (const stop of [...connections]) stop(); },
    async close() {
      sealed = true; admission = false; for (const stop of [...connections]) stop();
      await Promise.all(servers.map(server => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))));
    },
  });
}

export interface RuntimeClient {
  readonly hello: Contract<'wire.HelloResult'>['result'];
  call(request: Request, deadline?: number): Promise<unknown>;
  close(): void;
}
/** One connection attempt only. Never reconnects or replays on loss. */
export async function connectRuntime(location: RuntimeLocation, record: RuntimeRecord, endpoint: Endpoint,
  selection: BuildSelection, platform: PlatformPort, deadline: number, label = 'Browser client'): Promise<RuntimeClient> {
  if (record.phase !== 'ready' || (selection.explicit && selection.build !== record.build) || !originalAlive(record, platform))
    throw profileUnavailable();
  const path = endpoint === 'agent' ? location.agent : location.management;
  await assertSocket(location, path);
  const socket = createConnection(path), helloId = token('req'), seen = new Set<string>([helloId]);
  let dead = false, hello: Contract<'wire.HelloResult'>['result'] | undefined;
  const pending = new Map<string, { request?: Request; resolve(value: unknown): void; reject(error: unknown): void; timer: NodeJS.Timeout }>();
  let heartbeat: NodeJS.Timeout, lastPong = now(), pingId: string | undefined;
  let resolveHello: (value: RuntimeClient) => void, rejectHello: (error: unknown) => void;
  const ready = new Promise<RuntimeClient>((resolve, reject) => { resolveHello = resolve; rejectHello = reject; });
  const timer = setTimeout(() => stop(), Math.max(1, Math.min(deadline, now() + 5000) - now()));
  function stop() {
    if (dead) return; dead = true; clearTimeout(timer); clearInterval(heartbeat); socket.destroy();
    rejectHello(unavailable('browser'));
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(unavailable('browser')); }
    pending.clear();
  }
  const verify = () => {
    if (!sameProcess(peer(socket, platform), recordProcess(record)) || !originalAlive(record, platform)) throw unavailable('browser');
  };
  socket.once('connect', () => {
    try {
      verify();
      write(socket, { wire: 1, id: helloId, method: 'hello', params: { profile: record.profile,
        profileInstance: record.profileInstance, instance: record.instance, nonce: record.nonce,
        contract: 1, label: sanitizedLabel(label), ...expectedBuild(selection) } });
    } catch { stop(); }
  });
  frames(socket, 8 * 1024 * 1024, value => {
    try {
      verify();
      if (!hello) {
        if (!validator('wire.HelloResult')(value) || value.id !== helloId) throw unavailable('browser');
        const result = value.result;
        if (result.instance !== record.instance || result.nonce !== record.nonce || result.profile !== record.profile ||
            result.profileInstance !== record.profileInstance || result.build !== record.build ||
            (endpoint === 'agent' ? !result.attachment : Boolean(result.attachment))) throw unavailable('browser');
        hello = Object.freeze(result); clearTimeout(timer);
        heartbeat = setInterval(() => {
          try {
            if (now() - lastPong >= 6000 || seen.size >= 65536) { stop(); return; }
            if (!pingId) { pingId = token('req'); seen.add(pingId); write(socket, { wire: 1, id: pingId, method: 'ping', params: {} }); }
          } catch { stop(); }
        }, 2000);
        resolveHello(Object.freeze({ hello, close: stop,
          call(request: Request, limit = now() + duration(request)): Promise<unknown> {
            if (dead || seen.has(request.id) || seen.size >= 65536 || pending.size >= 32 || now() >= limit ||
                !(endpoint === 'agent' ? validator('wire.ToolRequest')(request) : validator('wire.ManagementRequest')(request)))
              return Promise.reject(unavailable('browser'));
            seen.add(request.id);
            return new Promise((resolve, reject) => {
              const timeout = setTimeout(stop, Math.max(1, limit - now()));
              pending.set(request.id, { request, resolve, reject, timer: timeout });
              try { verify(); write(socket, request, 1024 * 1024); } catch { stop(); }
            });
          },
        })); return;
      }
      if (validator('wire.Ping')(value)) {
        if (seen.has(value.id) || seen.size >= 65536) throw unavailable('browser');
        seen.add(value.id); write(socket, { wire: 1, id: value.id, ok: true, result: {} }); return;
      }
      if (!validator('wire.Response')(value)) throw unavailable('browser');
      if (value.id === pingId) {
        if (!value.ok || Object.keys(value.result).length) throw unavailable('browser');
        pingId = undefined; lastPong = now(); return;
      }
      const entry = pending.get(value.id);
      if (!entry?.request) throw unavailable('browser');
      if (value.ok && !resultValidator(entry.request)(value.result)) throw unavailable('browser');
      pending.delete(value.id); clearTimeout(entry.timer);
      if (value.ok) entry.resolve(value.result); else entry.reject(new BrowserFailure(value.error));
    } catch { stop(); }
  }, stop);
  return ready;
}
