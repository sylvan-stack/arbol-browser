import { createServer, createConnection, type Socket, type Server } from 'node:net';
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { chmod, lstat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { Contract, ContractTypes } from '../contracts/generated.js';
import { validator, bundles } from '../contracts/schema.js';
import { BrowserFailure, unavailable, publicFailure, type BrowserError } from '../contracts/errors.js';
import { ownerUid, profileUnavailable } from '../profiles/paths.js';
import type { PlatformPort, ProcessIdentity } from './platform.js';
import { assertSocket, now, token, originalAlive, sameProcess, recordProcess,
  type RuntimeRecord, type RuntimeLocation } from './instance.js';
import { noteHostStartup } from './custody.js';
import { expectedBuild, type BuildSelection } from './selection.js';
import { isSeqoyaReply, isSeqoyaRequest, isSeqoyaResult, plain, seqoyaUsageLimit,
  type SeqoyaParameters, type SeqoyaReply, type SeqoyaRequest, type SeqoyaResult } from './seqoya-wire.js';

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
export type ControlFrameKind = 'hello' | 'ping' | 'pong' | 'cancel';
/** Actual production host port; never substituted with the infrastructure port.
 * Its queue is the one real mutation queue. All final guards are synchronous. */
export interface ProtectedDispatchPort extends Omit<DispatchPort, 'commit'> {
  enroll(context: ConnectionContext): void;
  guardControl(context: ConnectionContext, kind: ControlFrameKind, bytes: Uint8Array): void;
  commitResponse(context: ConnectionContext, request: Request, success: boolean, bytes: Uint8Array): void;
  redactedFailure(context: ConnectionContext, request: Request, error: unknown): BrowserError;
  forget(context: ConnectionContext, request: Request): void;
  closeManagement?(context: ConnectionContext, request: Extract<Request, { method: 'close' }>,
    write: (bytes: Uint8Array, commit: () => void, finished: () => void) => void): void;
}
export function capacityFailure(): BrowserFailure {
  return new BrowserFailure({ code: 'control_refused', message: 'Browser capacity is exhausted.',
    retryable: true, remedy: 'Wait for outstanding work to settle, then inspect fresh state.' });
}
export function sanitizedLabel(value: string): string {
  return [...value.normalize('NFC').replace(/[\p{Cc}\p{Cf}\p{Cs}]/gu, '')].slice(0, 80).join('') || 'Browser client';
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
function frames(socket: Socket, maximum: number, receive: (value: unknown) => void, fail: (reason?: 'malformed' | 'lost') => void): void {
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
    } catch { fail('malformed'); }
  });
  socket.once('end', () => fail(pending.length ? 'malformed' : 'lost'));
  socket.once('error', () => fail('lost')); socket.once('close', () => { pending = Buffer.alloc(0); fail('lost'); });
}
function write(socket: Socket, value: unknown, maximum = 8 * 1024 * 1024): void {
  const bytes = Buffer.from(JSON.stringify(value) + '\n', 'utf8');
  writeFrame(socket, bytes, maximum);
}
function writeFrame(socket: Socket, bytes: Buffer, maximum = 8 * 1024 * 1024, guard?: () => void): void {
  if (bytes.length - 1 > maximum || socket.destroyed || socket.writableLength + bytes.length > 8 * 1024 * 1024)
    throw unavailable('browser');
  if (guard) { const result: unknown = guard(); if (result !== undefined) throw unavailable('browser'); }
  if (socket.destroyed) throw unavailable('browser');
  // No serialization, provider callback or await after this exact-byte guard.
  socket.write(bytes);
}

function readBackendRecord(path: string, maximum: number, writable: number): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const original = fstatSync(fd);
    if (!original.isFile() || original.uid !== ownerUid() || original.nlink !== 1 ||
        (original.mode & writable) !== 0 || original.size < 1 || original.size > maximum) throw unavailable('browser');
    const bytes = Buffer.alloc(maximum + 1);
    const size = readSync(fd, bytes, 0, bytes.length, 0);
    const named = lstatSync(path);
    if (size !== original.size || size !== named.size || named.ino !== original.ino || named.dev !== original.dev ||
        named.mtimeMs !== original.mtimeMs) throw unavailable('browser');
    return bytes.subarray(0, size).toString('utf8');
  } finally { closeSync(fd); }
}

function assertSeqoyaBackend(platform: PlatformPort, home: string, runtime: string, socket: ProcessIdentity): void {
  const stable = join(home, '.local/lib/sylvan-stack/arbol/stable/arbol');
  const launcher = join(home, 'Applications/Arbol/bin/arbol');
  const selections = readBackendRecord(launcher, 16_384, 0o022).split('\n').filter(line => line.startsWith('# stable-payload '));
  if (selections.length !== 1) throw unavailable('browser');
  const selected = selections[0]!.slice('# stable-payload '.length);
  const build = selected.slice(stable.length + 1);
  if (!/^[1-9a-f][0-9a-f]{0,15}$/.test(build) || selected !== join(stable, build) || realpathSync(selected) !== selected)
    throw unavailable('browser');
  const record: unknown = JSON.parse(readBackendRecord(join(home, 'Builds/registries/arbol/arbol', build, 'build.json'), 16_384, 0o077));
  if (!plain(record) || record.component !== 'arbol' || record.build !== build || record.status !== 'working' ||
      record.installationLayout !== 2 || typeof record.promotedAt !== 'string') throw unavailable('browser');
  const lockPath = join(runtime, 'backend.lock');
  const python = join(selected, 'runtime/python/bin/python3.14'), entry = join(selected, 'bin/arbol_entry.py');
  if (realpathSync(python) !== python || realpathSync(entry) !== entry ||
      platform.seqoyaBackendArguments?.(socket, python, entry, lockPath) !== true)
    throw unavailable('browser');
}

/** Confirm the current proof at the Backend that issued this single-use claim. */
export async function admitSeqoyaCapture(platform: PlatformPort, binding: Pick<RuntimeRecord, 'profile' | 'profileInstance'>,
  params: SeqoyaParameters, deadline: number, stage: 'check' | 'claim', signal?: AbortSignal): Promise<void> {
  const home = homedir(), root = join(home, '.arbol'), runtime = join(root, 'runtime'), path = join(runtime, 'seqoya.sock');
  for (const folder of [root, runtime]) {
    const info = await lstat(folder);
    if (!info.isDirectory() || info.uid !== ownerUid() || (info.mode & 0o077) !== 0) throw unavailable('browser');
  }
  const info = await lstat(path);
  if (!info.isSocket() || info.uid !== ownerUid() || (info.mode & 0o077) !== 0 || signal?.aborted || now() >= deadline)
    throw unavailable('browser');
  await new Promise<void>((resolve, reject) => {
    const socket = createConnection(path), id = token('req');
    let connected: ProcessIdentity | undefined, hello = false, finished = false;
    const wait = setTimeout(cancel, Math.min(5000, Math.max(1, deadline - now())));
    function cancel() { finish(false); }
    function finish(accepted: boolean) {
      if (finished) return;
      finished = true; clearTimeout(wait); signal?.removeEventListener('abort', cancel); socket.destroy();
      if (accepted) resolve(); else reject(unavailable('browser'));
    }
    signal?.addEventListener('abort', cancel, { once: true });
    socket.once('connect', () => {
      try {
        const current = peer(socket, platform);
        assertSeqoyaBackend(platform, home, runtime, current);
        connected = current;
      } catch { cancel(); }
    });
    frames(socket, seqoyaUsageLimit, value => {
      try {
        if (!connected || !sameProcess(connected, peer(socket, platform)) || !plain(value) || now() >= deadline) return cancel();
        if (!hello) {
          if (value.type !== 'hello' || value.bridge !== 2 || !plain(value.installation)) return cancel();
          hello = true;
          write(socket, { type: 'call', id, method: 'seqoya.browser.usage.' + stage,
            params: { ...params, profile: binding.profile, instance: binding.profileInstance } }, seqoyaUsageLimit);
          return;
        }
        const named = lstatSync(path);
        if (!named.isSocket() || named.dev !== info.dev || named.ino !== info.ino) return cancel();
        assertSeqoyaBackend(platform, home, runtime, connected);
        finish(value.type === 'reply' && value.id === id && value.error === undefined && plain(value.result) &&
          Object.keys(value.result).length === 1 && value.result.admitted === true);
      } catch { cancel(); }
    }, cancel);
  });
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
export interface ManagementCloseOpportunity { readonly admission: import('./platform.js').CloseAdmission; readonly deadline: number; readonly grace: number }
interface ManagementConnection {
  socket: Socket; context: ConnectionContext; active: Map<string, Request>; stop(): void;
  reserve(request: Request, consume: (socket: number) => import('./platform.js').CloseAdmission): ManagementCloseOpportunity;
}
const managementConnections = new WeakMap<ConnectionContext, ManagementConnection>();
const closeOpportunities = new WeakMap<ManagementCloseOpportunity, { context: ConnectionContext; request: Request }>();
export function reserveManagementClose(context: ConnectionContext, request: Request,
  consume: (socket: number) => import('./platform.js').CloseAdmission): ManagementCloseOpportunity {
  const actual = managementConnections.get(context);
  if (!actual || context.endpoint !== 'management' || context.attachment || context.signal.aborted ||
      request.method !== 'close' || actual.active.get(request.id) !== request) throw unavailable('browser');
  return actual.reserve(request, consume);
}
export function assertManagementCloseOpportunity(value: ManagementCloseOpportunity, context: ConnectionContext, request: Request): void {
  const actual = closeOpportunities.get(value);
  if (!actual || actual.context !== context || actual.request !== request || now() >= value.grace) throw unavailable('browser');
}
interface ProtectedReadyServer {
  open(custody: import('./custody.js').HostCustody, record: RuntimeRecord, guard: () => void, control: () => void): void;
}
const protectedReadyServers = new WeakMap<TransportServer, ProtectedReadyServer>();
/** Actual bound protected listeners only. Native Claim commit and the guarded
 * JS gates occur in one synchronous turn, before any peer callback can run. */
export function openProtectedReady(server: TransportServer, custody: import('./custody.js').HostCustody,
  record: RuntimeRecord, guard: () => void, control: () => void): void {
  const actual = protectedReadyServers.get(server); if (!actual) return custody.terminate();
  actual.open(custody, record, guard, control);
}
/** Explicit injected infrastructure compatibility. This supplies no production
 * page authority. Existing Foundation callers keep their success-only commit. */
export function listenTransport(location: RuntimeLocation, record: RuntimeRecord, platform: PlatformPort,
  dispatch: DispatchPort): Promise<TransportServer> {
  if ('enroll' in dispatch || 'commitResponse' in dispatch) throw unavailable('browser');
  return listenServer(location, record, platform, dispatch);
}
/** Production assembly must choose this entry, with every real protected port. */
type PrivateUsage = (params: SeqoyaParameters, deadline: number, signal: AbortSignal) => Promise<SeqoyaResult>;
export function listenProtectedTransport(location: RuntimeLocation, record: RuntimeRecord, platform: PlatformPort,
  dispatch: ProtectedDispatchPort, privateUsage?: PrivateUsage): Promise<TransportServer> {
  for (const method of ['enroll', 'guardControl', 'commitResponse', 'redactedFailure', 'forget', 'authorize', 'execute', 'disconnect', 'cancel', 'fatal'] as const)
    if (typeof dispatch[method] !== 'function') throw unavailable('browser');
  return listenServer(location, record, platform, dispatch, dispatch, privateUsage);
}
async function listenServer(location: RuntimeLocation, record: RuntimeRecord, platform: PlatformPort,
  dispatch: DispatchPort | ProtectedDispatchPort, protectedPort?: ProtectedDispatchPort,
  privateUsage?: PrivateUsage): Promise<TransportServer> {
  let admission = false, sealed = false, agents = 0, management = 0;
  const connections = new Set<() => void>(), retainedCloseStops = new Map<() => void, () => void>(), servers: Server[] = [], scheduler = new Scheduler();
  let fatalLatched = false;
  const fatal = () => {
    sealed = true; admission = false;
    if (fatalLatched) return; fatalLatched = true;
    try { dispatch.fatal(); } catch { /* local admission is sealed; real native fatal remains armed */ }
    finally { if (protectedPort) for (const stop of [...connections]) stop(); }
  };
  function accepted(socket: Socket, endpoint: Endpoint): void {
    let context: ConnectionContext | undefined, dead = false, handshaking = true;
    let identity: ProcessIdentity;
    const connection = new AbortController();
    const active = new Map<string, AbortController>(), requestTimers = new Map<string, NodeJS.Timeout>(), actualRequests = new Map<string, Request>(), seen = new Set<string>();
    let closeOpportunity: ManagementCloseOpportunity | undefined, closeWritten = false;
    let closeDrain: NodeJS.Timeout | undefined;
    let helloTimer: NodeJS.Timeout, heartbeat: NodeJS.Timeout;
    let pingId: string | undefined, lastPong = now();
    let usageStarted = false;
    const stop = () => {
      if (dead) return; dead = true; connections.delete(stop); retainedCloseStops.delete(stop); clearTimeout(closeDrain);
      if (context) managementConnections.delete(context);
      clearTimeout(helloTimer); clearInterval(heartbeat);
      try {
      if (protectedPort) {
        // Revoke grants, queued and issued authority before any abort handler
        // can reenter. Also rolls back a partially failed enrollment/Hello once.
        if (context) { if (endpoint === 'agent') --agents; else --management;
          try { const returned: unknown = protectedPort.disconnect(context); if (returned !== undefined) fatal(); } catch { fatal(); } }
        connection.abort(); for (const controller of active.values()) controller.abort();
      } else {
        connection.abort(); for (const controller of active.values()) controller.abort();
        if (context) { if (endpoint === 'agent') --agents; else --management;
          try { dispatch.disconnect(context); } catch { fatal(); } }
      }
      } finally { socket.destroy(); }
    };
    connections.add(stop);
    try { if (!admission || connections.size > 64) throw capacityFailure(); identity = peer(socket, platform); }
    catch { stop(); return; }
    function control(value: unknown, kind: ControlFrameKind): void {
      if (!protectedPort) { write(socket, value); return; }
      if (!context) throw unavailable('browser');
      const captured = context, bytes = Buffer.from(JSON.stringify(value) + '\n', 'utf8');
      writeFrame(socket, bytes, 8 * 1024 * 1024, () => {
        checkPeer(); const returned: unknown = protectedPort.guardControl(captured, kind, bytes);
        if (returned !== undefined) { fatal(); throw unavailable('browser'); }
        if (dead || sealed || !admission || captured.signal.aborted || socket.destroyed) { stop(); throw unavailable('browser'); }
      });
    }
    function response(id: string, value: unknown, kind: 'pong' | 'cancel') { control({ wire: 1, id, ok: true, result: value }, kind); }
    function failure(captured: ConnectionContext, request: Request, error: unknown, deadline?: number): void {
      if (!protectedPort) { write(socket, { wire: 1, id: request.id, ok: false, error: publicFailure(error).detail }); return; }
      const detail = protectedPort.redactedFailure(captured, request, error);
      if (!validator('browser.BrowserError')(detail)) throw unavailable('browser');
      const bytes = Buffer.from(JSON.stringify({ wire: 1, id: request.id, ok: false, error: detail }) + '\n', 'utf8');
      writeFrame(socket, bytes, 8 * 1024 * 1024, () => {
        checkPeer(); const returned: unknown = protectedPort.commitResponse(captured, request, false, bytes);
        if (returned !== undefined) { fatal(); throw unavailable('browser'); }
        if (dead || sealed || !admission || captured.signal.aborted || active.get(request.id)?.signal.aborted || socket.destroyed ||
            (deadline !== undefined && now() >= deadline)) { stop(); throw unavailable('browser'); }
      });
    }
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
          if (protectedPort && endpoint === 'management') {
            const captured = context;
            managementConnections.set(captured, { socket, context: captured, active: actualRequests, stop,
              reserve(request, consume) {
                if (dead || sealed || !admission || closeOpportunity || captured.signal.aborted ||
                    actualRequests.get(request.id) !== request) throw unavailable('browser');
                checkPeer();
                // Actual native admission first, then retain this exact socket
                // before synchronous sealing can abort ordinary connections.
                const actualFd = fd(socket), sampled = now(), nativeNow = platform.continuousTime();
                const nativeAdmission = consume(actualFd);
                closeOpportunity = Object.freeze({ admission: nativeAdmission,
                  deadline: sampled + Math.max(0, nativeAdmission.overall - nativeNow),
                  grace: sampled + Math.max(0, nativeAdmission.grace - nativeNow) });
                closeOpportunities.set(closeOpportunity, { context: captured, request });
                retainedCloseStops.set(stop, () => {
                  for (const [id, controller] of active) if (id !== request.id) {
                    controller.abort(); clearTimeout(requestTimers.get(id)); requestTimers.delete(id);
                  }
                }); clearInterval(heartbeat);
                return closeOpportunity;
              },
            });
          }
          if (protectedPort) {
            const enrolled: unknown = protectedPort.enroll(context);
            if (enrolled !== undefined) { fatal(); throw unavailable('browser'); }
          }
          const reply: Contract<'wire.HelloResult'> = { wire: 1, id: value.id, ok: true,
            result: { instance: record.instance, nonce: record.nonce, profile: record.profile,
              profileInstance: record.profileInstance, build: record.build, contract: 1, ...(attachment ? { attachment } : {}) } };
          if (!validator('wire.HelloResult')(reply)) throw unavailable('browser');
          control(reply, 'hello'); clearTimeout(helloTimer);
          heartbeat = setInterval(() => {
            try {
              if (now() - lastPong >= 6000) { stop(); return; }
              if (!pingId) {
                if (seen.size >= 65536) { stop(); return; }
                pingId = token('req'); seen.add(pingId); control({ wire: 1, id: pingId, method: 'ping', params: {} }, 'ping'); }
            } catch { stop(); }
          }, 2000);
          return;
        }
        if (sealed || !admission) throw unavailable('browser');
        checkPeer();
        if (isSeqoyaRequest(value)) {
          if (endpoint !== 'management' || !privateUsage || usageStarted || seen.has(value.id) || seen.size >= 65536)
            throw unavailable('browser');
          usageStarted = true; seen.add(value.id);
          const id = value.id, deadline = now() + 35_000;
          void (async () => {
            let result: SeqoyaResult;
            try { result = await privateUsage(value.params, deadline, connection.signal); }
            catch { result = { status: 'dashboard_unavailable' }; }
            try {
              if (!isSeqoyaResult(result)) throw unavailable('browser');
              const reply: SeqoyaReply = { wire: 1, id, method: 'seqoya-usage-result', result };
              writeFrame(socket, Buffer.from(JSON.stringify(reply) + '\n', 'utf8'), seqoyaUsageLimit, () => {
                checkPeer();
                if (dead || sealed || !admission || connection.signal.aborted || now() >= deadline) throw unavailable('browser');
              });
            } catch { stop(); }
          })();
          return;
        }
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
        if (request.method === 'ping') { response(request.id, {}, 'pong'); return; }
        if (request.method === 'cancel') {
          const target = active.get(request.params.request);
          if (target) {
            const returned: unknown = dispatch.cancel(context, request.params.request);
            if (protectedPort && returned !== undefined) { fatal(); throw unavailable('browser'); } target.abort();
          }
          response(request.id, { request: request.params.request, found: Boolean(target) }, 'cancel'); return;
        }
        if (!admission) throw unavailable('browser');
        if (active.size >= 32) {
          failure(context, request, capacityFailure()); return;
        }
        const deadline = now() + duration(request), controller = new AbortController(), captured = context;
        const abort = () => controller.abort();
        connection.signal.addEventListener('abort', abort, { once: true });
        active.set(request.id, controller); actualRequests.set(request.id, request);
      if (request.method === 'close' && protectedPort?.closeManagement) {
        try {
          protectedPort.authorize(captured, request);
          protectedPort.closeManagement(captured, request, (bytes, commit, finished) => {
            try {
              if (!closeOpportunity || closeWritten || dead || socket.destroyed) throw unavailable('browser');
              assertManagementCloseOpportunity(closeOpportunity, captured, request); checkPeer();
              if (bytes.byteLength > 16384) throw unavailable('browser');
              commit(); closeWritten = true;
              // Guarded exact small frame, then bounded end/drain. Never destroy
              // a successfully accepted ordinary ACK before its write can flush.
              socket.write(bytes, error => { if (error) stop(); }); socket.end();
              closeDrain = setTimeout(stop, Math.max(1, closeOpportunity.deadline - now())); closeDrain.unref();
            } catch { stop(); }
            finally { finished(); }
          });
        } catch (error) {
          if (!dead && !sealed) { try { failure(captured, request, error, deadline); } catch { stop(); } }
          else stop();
        } finally {
          active.delete(request.id); actualRequests.delete(request.id);
          connection.signal.removeEventListener('abort', abort);
          try { protectedPort.forget(captured, request); } catch { fatal(); }
        }
        return;
      }
        // A timeout closes transport/admission and delegates actual drain/retire;
        // it never emits a synthetic successful cancellation or action outcome.
        const timer = setTimeout(() => {
          if (protectedPort) { stop(); return; }
          try { const returned: unknown = dispatch.cancel(captured, request.id); if (protectedPort && returned !== undefined) fatal(); } catch { fatal(); }
          controller.abort(); stop();
        }, Math.max(1, deadline - now()));
        requestTimers.set(request.id, timer);
        void (async () => {
          let committed = false;
          try {
            const authorized: unknown = dispatch.authorize(captured, request);
            if (protectedPort && authorized !== undefined) { fatal(); throw unavailable('browser'); }
            const result = await (protectedPort ? dispatch.execute(captured, request, deadline, controller.signal)
              : scheduler.run(request, controller.signal, () => dispatch.execute(captured, request, deadline, controller.signal)));
            if (controller.signal.aborted) return;
            if (protectedPort && now() >= deadline) { stop(); return; }
            if (dead || controller.signal.aborted || now() >= deadline) return;
            if (!resultValidator(request)(result)) {
              // Mismatched success is an internal protocol failure: close the
              // adapter and safely release, rather than forwarding an envelope.
              if (protectedPort) { stop(); return; }
              throw unavailable('browser');
            }
            if (protectedPort) {
              const bytes = Buffer.from(JSON.stringify({ wire: 1, id: request.id, ok: true, result }) + '\n', 'utf8');
              writeFrame(socket, bytes, 8 * 1024 * 1024, () => {
                checkPeer(); const returned: unknown = protectedPort.commitResponse(captured, request, true, bytes);
                if (returned !== undefined) { fatal(); throw unavailable('browser'); }
                if (dead || sealed || !admission || captured.signal.aborted || controller.signal.aborted || socket.destroyed || now() >= deadline) {
                  stop(); throw unavailable('browser');
                }
                committed = true;
              });
            } else {
              checkPeer(); (dispatch as DispatchPort).commit(captured, request);
              write(socket, { wire: 1, id: request.id, ok: true, result });
            }
          } catch (error) {
            if (controller.signal.aborted) return;
            // A write after final commitment may have reached the OS. Do not
            // manufacture another result; disconnect means uncertain delivery.
            if (protectedPort && committed) { stop(); return; }
            if (protectedPort && now() >= deadline) { stop(); return; }
            if (!dead && !controller.signal.aborted) {
              try { failure(captured, request, error, deadline); }
              catch { stop(); }
            }
          } finally {
            clearTimeout(timer); requestTimers.delete(request.id); active.delete(request.id); actualRequests.delete(request.id); connection.signal.removeEventListener('abort', abort);
            if (protectedPort) { try {
              const returned: unknown = protectedPort.forget(captured, request); if (returned !== undefined) { fatal(); stop(); }
            } catch { fatal(); stop(); } }
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
      server.on('error', () => {
        if (protectedPort) { fatal(); return; }
        admission = false; for (const stop of [...connections]) stop(); fatal();
      });
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject); server.listen(path, () => { server.removeListener('error', reject); resolve(); });
      });
      await chmod(path, 0o600); await assertSocket(location, path);
    }
  } catch (error) {
    admission = false; for (const stop of [...connections]) stop();
    for (const server of servers) server.close(); throw error;
  }
  const result: TransportServer = Object.freeze({
    openAdmission() { if (sealed || protectedPort) throw unavailable('browser'); admission = true; },
    closeAdmission() { sealed = true; admission = false; for (const stop of [...connections]) { const fence = retainedCloseStops.get(stop); if (fence) fence(); else stop(); } },
    async close() {
      sealed = true; admission = false; for (const stop of [...connections]) { const fence = retainedCloseStops.get(stop); if (fence) fence(); else stop(); }
      await Promise.all(servers.map(server => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))));
    },
  });
  if (protectedPort) protectedReadyServers.set(result, {
    open(custody, ready, guard, control) {
      try {
        noteHostStartup(custody, 'protected-ready-validate-before');
        if (sealed || admission || servers.length !== 2 || ready.phase !== 'ready' ||
            !sameProcess(recordProcess(ready), recordProcess(record)) || ready.instance !== record.instance || ready.nonce !== record.nonce ||
            ready.profileInstance !== record.profileInstance || ready.profilePathHash !== record.profilePathHash || ready.build !== record.build ||
            ready.agentSocket !== location.agent || ready.managementSocket !== location.management) return custody.terminate();
        const handles = servers.map(server => (server as unknown as { _handle?: { fd?: number } })._handle?.fd);
        if (handles.some(value => !Number.isSafeInteger(value) || value! < 3) || handles[0] === handles[1]) return custody.terminate();
        if (guard() !== undefined) return custody.terminate();
        noteHostStartup(custody, 'protected-ready-validate-after');
        noteHostStartup(custody, 'protected-claim-ready-before');
        custody.ready(ready, handles[0]!, handles[1]!);
        noteHostStartup(custody, 'protected-claim-ready-after');
        // No await, event-loop return or peer dispatch between durable native
        // attestation and this exact generation's actual gate opening.
        if (guard() !== undefined || control() !== undefined || guard() !== undefined || sealed) return custody.terminate();
        admission = true;
      } catch { fatal(); return custody.terminate(); }
    },
  });
  return result;
}

export interface RuntimeClient {
  readonly signal: AbortSignal;
  readonly hello: Contract<'wire.HelloResult'>['result'];
  call(request: Request, deadline?: number): Promise<unknown>;
  cancel(requestId: string, deadline?: number): Promise<Contract<'wire.CancelResult'>>;
  close(): void;
}
const usageCalls = new WeakMap<RuntimeClient, (params: SeqoyaParameters, deadline: number) => Promise<SeqoyaResult>>();
export function requestSeqoyaUsage(client: RuntimeClient, params: SeqoyaParameters, deadline: number): Promise<SeqoyaResult> {
  const call = usageCalls.get(client);
  if (!call) return Promise.reject(unavailable('browser'));
  return call(params, deadline);
}
export type RuntimeTermination = 'lost' | 'malformed' | 'refused' | 'timeout' | 'client-closed';
const terminations = new WeakMap<RuntimeClient, () => RuntimeTermination | undefined>();
export function runtimeTermination(client: RuntimeClient): RuntimeTermination | undefined {
  return terminations.get(client)?.();
}
class MalformedAgentReply extends BrowserFailure {}
const cancelledRequest = Object.freeze(new Error('Private request waiter cancelled'));
export function isMalformedAgentReply(error: unknown): boolean { return error instanceof MalformedAgentReply; }
export function isCancelledRequest(error: unknown): boolean { return error === cancelledRequest; }

interface PendingReply {
  check(value: unknown): boolean;
  resolve(value: unknown): void;
  reject(error: unknown): void;
  timer: NodeJS.Timeout;
  cancel?: Readonly<{ id: string; original: PendingReply | undefined }>;
}
export type ManagementCloseObservation =
  | Readonly<{ kind: 'ack' }>
  | Readonly<{ kind: 'refused'; error: unknown }>
  | Readonly<{ kind: 'malformed' }>
  | Readonly<{ kind: 'lost'; stamped: boolean; written: boolean }>;
const actualCloseClients = new WeakMap<RuntimeClient,
  (budget: import('./platform.js').CloseBudget, deadline: number) => Promise<ManagementCloseObservation>>();
/** Private actual client/socket boundary. The native one-use stamp binds this
 * exact connected peer and request before the sole Close frame is written. */
export function requestManagementClose(client: RuntimeClient, budget: import('./platform.js').CloseBudget,
  deadline: number): Promise<ManagementCloseObservation> {
  const actual = actualCloseClients.get(client); if (!actual) throw unavailable('browser');
  actualCloseClients.delete(client); return actual(budget, deadline);
}
/** One connection attempt only. Never reconnects or replays on loss. */
export async function connectRuntime(location: RuntimeLocation, record: RuntimeRecord, endpoint: Endpoint,
  selection: BuildSelection, platform: PlatformPort, deadline: number, label = 'Browser client',
  signal?: AbortSignal): Promise<RuntimeClient> {
  if (signal?.aborted) throw unavailable('browser');
  if (record.phase !== 'ready' || (selection.explicit && selection.build !== record.build) || !originalAlive(record, platform))
    throw profileUnavailable();
  const path = endpoint === 'agent' ? location.agent : location.management;
  await assertSocket(location, path);
  if (signal?.aborted || now() >= deadline) throw unavailable('browser');
  const socket = createConnection(path), helloId = token('req'), seen = new Set<string>([helloId]);
  const lost = new AbortController();
  let stopReason: RuntimeTermination = 'lost';
  let closeRequest: string | undefined, closeWritten = false, explicitCloseRefusal: BrowserFailure | undefined;
  let dead = false, hello: Contract<'wire.HelloResult'>['result'] | undefined;
  const pending = new Map<string, PendingReply>();
  let heartbeat: NodeJS.Timeout, lastPong = now(), pingId: string | undefined;
  let resolveHello: (value: RuntimeClient) => void, rejectHello: (error: unknown) => void;
  const ready = new Promise<RuntimeClient>((resolve, reject) => { resolveHello = resolve; rejectHello = reject; });
  const timer = setTimeout(() => stop('timeout'), Math.max(1, Math.min(deadline, now() + 5000) - now()));
  function cancelLocal() { stop('client-closed'); }
  function stop(reason: RuntimeTermination = 'lost') {
    if (dead) return; stopReason = reason; dead = true; clearTimeout(timer); clearInterval(heartbeat); socket.destroy();
    signal?.removeEventListener('abort', cancelLocal);
    lost.abort();
    const failure = unavailable('browser');
    rejectHello(endpoint === 'agent' && reason === 'malformed' ? new MalformedAgentReply(failure.detail) : failure);
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
      if (closeRequest && pending.has(closeRequest)) {
        if (!validator('wire.Response')(value) && !validator('wire.Ping')(value)) { stop('malformed'); return; }
        if (validator('wire.Response')(value) && value.id === closeRequest) {
          const entry = pending.get(closeRequest)!;
          if (!value.ok) {
            pending.delete(closeRequest); clearTimeout(entry.timer); explicitCloseRefusal = new BrowserFailure(value.error); entry.reject(explicitCloseRefusal); return;
          }
          if (!entry.check(value.result)) { stop('malformed'); return; }
          if (!originalAlive(record, platform)) { stop('lost'); return; }
        }
      }
      try { verify(); } catch (error) { if (endpoint === 'agent') { stop('lost'); return; } throw error; }
      if (!hello) {
        if (!validator('wire.HelloResult')(value) || value.id !== helloId) throw unavailable('browser');
        const result = value.result;
        if (result.instance !== record.instance || result.nonce !== record.nonce || result.profile !== record.profile ||
            result.profileInstance !== record.profileInstance || result.build !== record.build ||
            (endpoint === 'agent' ? !result.attachment : Boolean(result.attachment))) throw unavailable('browser');
        hello = Object.freeze(result); clearTimeout(timer);
        heartbeat = setInterval(() => {
          try {
            if (now() - lastPong >= 6000) { stop('timeout'); return; }
            if (seen.size >= 65536) { stop(); return; }
            if (!pingId) { pingId = token('req'); seen.add(pingId); write(socket, { wire: 1, id: pingId, method: 'ping', params: {} }); }
          } catch { stop(); }
        }, 2000);
        const send = (request: Request | SeqoyaRequest | Contract<'wire.Cancel'>, limit: number, check: (value: unknown) => boolean,
          cancel?: PendingReply['cancel']): Promise<unknown> => {
          const maximum = request.method === 'cancel' ? 64 : 32;
          if (endpoint === 'agent' && seen.size >= 65536) stop();
          if (dead || seen.has(request.id) || seen.size >= 65536 || pending.size >= maximum || now() >= limit)
            return Promise.reject(unavailable('browser'));
          seen.add(request.id);
          return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => stop('timeout'), Math.max(1, limit - now()));
            pending.set(request.id, { check, resolve, reject, timer: timeout, ...(cancel ? { cancel } : {}) });
            try { verify(); write(socket, request, 1024 * 1024); if (request.id === closeRequest) closeWritten = true; } catch { stop('refused'); }
          });
        };
        const client: RuntimeClient = Object.freeze({ hello, signal: lost.signal, close: () => stop('client-closed'),
          call(request: Request, limit = now() + duration(request)): Promise<unknown> {
            if (!(endpoint === 'agent' ? validator('wire.ToolRequest')(request) : validator('wire.ManagementRequest')(request)))
              return Promise.reject(unavailable('browser'));
            return send(request, limit, resultValidator(request));
          },
          cancel(requestId: string, limit = now() + 2000): Promise<Contract<'wire.CancelResult'>> {
            if (!validator('browser.RequestId')(requestId) || !seen.has(requestId)) return Promise.reject(unavailable('browser'));
            return send({ wire: 1, id: token('req'), method: 'cancel', params: { request: requestId } }, limit,
              value => validator('wire.CancelResult')(value) && value.request === requestId,
              endpoint === 'agent' ? { id: requestId, original: pending.get(requestId) } : undefined) as Promise<Contract<'wire.CancelResult'>>;
          },
        });
        if (endpoint === 'management') usageCalls.set(client, (params, limit) => {
          const request: SeqoyaRequest = { wire: 1, id: token('req'), method: 'seqoya-usage', params };
          if (!isSeqoyaRequest(request)) return Promise.reject(unavailable('browser'));
          return send(request, limit, isSeqoyaResult) as Promise<SeqoyaResult>;
        });
        if (endpoint === 'management') actualCloseClients.set(client, async (budget, limit) => {
          if (dead || closeRequest || pending.size || now() >= limit) return { kind: 'refused', error: unavailable('browser') };
          const request: Extract<Request, { method: 'close' }> = { wire: 1, id: token('req'), method: 'close', params: {} };
          closeRequest = request.id; let stamped = false;
          try {
            verify(); await platform.stampCloseRequest(budget, location.leaf, record, request.id, fd(socket)); stamped = true;
            if (dead || now() >= limit) return { kind: 'lost', stamped, written: false };
            await send(request, limit, value => validator('wire.CloseResult')(value) &&
              value.profile === record.profile && value.closed === false && value.dataRemoved === false); return { kind: 'ack' };
          } catch (error) {
            if (explicitCloseRefusal) return { kind: 'refused', error: explicitCloseRefusal };
            if (!stamped || !dead || stopReason === 'refused') return { kind: 'refused', error };
            if (stopReason === 'malformed') return { kind: 'malformed' };
            return { kind: 'lost', stamped, written: closeWritten };
          }
        });
        if (endpoint === 'agent') terminations.set(client, () => dead ? stopReason : undefined);
        resolveHello(client); return;
      }
      if (validator('wire.Ping')(value)) {
        if (seen.has(value.id) || seen.size >= 65536) throw unavailable('browser');
        seen.add(value.id); write(socket, { wire: 1, id: value.id, ok: true, result: {} }); return;
      }
      if (endpoint === 'management' && isSeqoyaReply(value)) {
        const entry = pending.get(value.id);
        if (!entry || entry.check !== isSeqoyaResult) throw unavailable('browser');
        pending.delete(value.id); clearTimeout(entry.timer); entry.resolve(value.result); return;
      }
      if (!validator('wire.Response')(value)) throw unavailable('browser');
      if (value.id === pingId) {
        if (!value.ok || Object.keys(value.result).length) throw unavailable('browser');
        pingId = undefined; lastPong = now(); return;
      }
      const entry = pending.get(value.id);
      if (!entry) throw unavailable('browser');
      if (value.ok && !entry.check(value.result)) throw unavailable('browser');
      pending.delete(value.id); clearTimeout(entry.timer);
      const cancellation = entry.cancel;
      if (value.ok && cancellation?.original && validator('wire.CancelResult')(value.result) && value.result.found &&
          pending.get(cancellation.id) === cancellation.original) {
        pending.delete(cancellation.id);
        clearTimeout(cancellation.original.timer);
        cancellation.original.reject(cancelledRequest);
      }
      if (value.ok) entry.resolve(value.result); else entry.reject(new BrowserFailure(value.error));
    } catch { stop('malformed'); }
  }, reason => stop(reason ?? 'lost'));
  signal?.addEventListener('abort', cancelLocal, { once: true });
  if (signal?.aborted) cancelLocal();
  return ready;
}
