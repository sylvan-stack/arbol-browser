import { createHash } from 'node:crypto';
import { JSONRPCMessageSchema, InitializeRequestSchema, InitializedNotificationSchema,
  ListToolsRequestSchema, CallToolRequestSchema, PingRequestSchema, CancelledNotificationSchema,
  type JSONRPCMessage, type RequestId } from '@modelcontextprotocol/sdk/types.js';
import type { Stdio } from '../runtime/ports.js';
import type { McpTransport } from './server.js';
import { validator } from '../contracts/schema.js';
import { toolParams } from './tools.js';

export const MCP_LIMITS = Object.freeze({ inbound: 1024 * 1024, outbound: 8 * 1024 * 1024,
  pending: 32, requests: 65536 });
interface Pending { readonly external: RequestId; readonly key: string; readonly method: string;
  readonly received: number; started: boolean; cancelled: boolean }
const messages: Record<number, string> = { [-32700]: 'Parse error', [-32600]: 'Invalid request',
  [-32601]: 'Method not found', [-32602]: 'Invalid params', [-32603]: 'Internal error' };
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function id(value: unknown): value is RequestId {
  return typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value));
}
function key(value: RequestId): string {
  return createHash('sha256').update(JSON.stringify([typeof value, value])).digest('hex');
}
function fields(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every(name => allowed.includes(name));
}
/** SDK Transport with no default stdin reader, unbounded write queue or bodies
 * in errors. Only correlation digests survive completion; no transcript exists. */
export class BoundedMcpTransport implements McpTransport {
  onmessage: McpTransport['onmessage'];
  onerror: McpTransport['onerror'];
  onclose: McpTransport['onclose'];
  private begun = false;
  private dead = false;
  private readonly frame = Buffer.alloc(MCP_LIMITS.inbound);
  private used = 0;
  private count = 0;
  private readonly seen = new Set<string>();
  private readonly pending = new Map<string, Pending>();
  private readonly external = new Map<string, string>();
  private initializationCommitted = false;
  private readyNotification = false;
  private queuedBytes = 0;
  private readonly writes = new Set<(error: Error) => void>();
  private heartbeat: NodeJS.Timeout | undefined;
  private ping: { id: string; sent: number } | undefined;
  private pingCount = 0;
  constructor(private readonly io: Stdio) {}
  receivedAt(request: RequestId): number | undefined { return this.pending.get(String(request))?.received; }
  /** Starting and cancellation are synchronous with respect to actual dispatch. */
  begin(request: RequestId): boolean {
    const entry = this.pending.get(String(request));
    if (!entry || entry.cancelled || this.dead) return false;
    entry.started = true; return true;
  }
  settled(request: RequestId): void {
    const entry = this.pending.get(String(request));
    if (entry?.cancelled) this.forget(String(request), entry);
    else if (entry) entry.started = false;
  }
  private forget(internal: string, entry: Pending): void {
    this.pending.delete(internal); this.external.delete(entry.key);
  }
  async start(): Promise<void> {
    if (this.begun || this.dead) throw new Error('Transport unavailable');
    this.begun = true;
    this.io.stdin.on('data', this.data);
    this.io.stdin.once('end', this.lost); this.io.stdin.once('close', this.lost); this.io.stdin.on('error', this.lost);
    this.io.stdout.on('error', this.lost); this.io.stdout.once('close', this.lost); this.io.stdout.once('finish', this.lost);
    if (this.io.stdin.readableEnded || this.io.stdin.destroyed || this.io.stdout.destroyed || this.io.stdout.writableEnded) {
      this.lost(); return;
    }
    if (this.dead) return;
    this.heartbeat = setInterval(() => {
      if (!this.initializationCommitted || this.dead) return;
      if (this.ping && performance.now() - this.ping.sent >= 6000) { this.lost(); return; }
      if (!this.ping) {
        if (this.pingCount >= MCP_LIMITS.requests) { this.lost(); return; }
        this.ping = { id: `server_${++this.pingCount}`, sent: performance.now() };
        void this.write({ jsonrpc: '2.0', id: this.ping.id, method: 'ping' }).catch(this.lost);
      }
    }, 2000);
  }
  private readonly lost = (): void => { void this.close(); };
  private readonly data = (chunk: unknown): void => {
    if (this.dead) return;
    if (!Buffer.isBuffer(chunk)) { this.lost(); return; }
    let start = 0;
    while (start < chunk.length && !this.dead) {
      const newline = chunk.indexOf(10, start), end = newline < 0 ? chunk.length : newline;
      if (this.used + end - start > MCP_LIMITS.inbound) { this.lost(); return; }
      chunk.copy(this.frame, this.used, start, end); this.used += end - start;
      if (newline < 0) return;
      const received = performance.now();
      let text: string, value: unknown;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(this.frame.subarray(0, this.used)); }
      catch { this.lost(); return; }
      try { value = JSON.parse(text); }
      catch { this.used = 0; void this.reject(null, -32700); start = newline + 1; continue; }
      this.used = 0;
      try { this.receive(value, received); } catch { this.lost(); }
      start = newline + 1;
    }
  };
  private receive(value: unknown, received: number): void {
    if (!object(value)) { void this.reject(null, -32600); return; }
    if (!('method' in value) && ('result' in value || 'error' in value)) {
      // Apparent peer responses may only answer the actual outstanding ping.
      // A missing method without a result/error is instead a malformed request.
      if (!this.ping || value.id !== this.ping.id || !JSONRPCMessageSchema.safeParse(value).success ||
          !object(value.result) || Object.keys(value.result).length !== 0) { this.lost(); return; }
      this.ping = undefined; return;
    }
    const requestId = id(value.id) ? value.id : null;
    const externalKey = requestId === null ? undefined : key(requestId);
    // Reserve before any echo, even for malformed method/envelope/params. A
    // second identifiable use closes before it can publish another result.
    if (externalKey !== undefined) {
      if (this.seen.has(externalKey) || this.count >= MCP_LIMITS.requests) { this.lost(); return; }
      this.seen.add(externalKey); ++this.count;
    }
    if (value.jsonrpc !== '2.0' || typeof value.method !== 'string' || !fields(value, ['jsonrpc', 'id', 'method', 'params']) ||
        ('params' in value && !object(value.params))) { void this.reject(requestId, -32600); return; }
    const params = object(value.params) ? value.params : {};
    if (!('id' in value)) {
      if (value.method === 'notifications/initialized') {
        if (!this.initializationCommitted || !fields(params, ['_meta']) || !InitializedNotificationSchema.safeParse(value).success) {
          this.lost(); return;
        }
        this.readyNotification = true; this.deliver(value); return;
      }
      if (value.method === 'notifications/cancelled') {
        if (!CancelledNotificationSchema.safeParse(value).success || !fields(params, ['requestId', 'reason', '_meta']) || !id(params.requestId)) {
          this.lost(); return;
        }
        const internal = this.external.get(key(params.requestId)), entry = internal && this.pending.get(internal);
        if (!internal || !entry) return;
        entry.cancelled = true;
        // SDK 1.32.2 ignores falsy requestId. All inbound IDs are normalized to
        // nonempty strings, and the client-provided reason is discarded.
        this.deliver({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: internal } });
        if (!entry.started) this.forget(internal, entry);
        if (entry.method === 'initialize') this.lost();
      }
      return; // Unknown notifications have no response and confer no capability.
    }
    if (!id(value.id) || externalKey === undefined) { void this.reject(null, -32600); return; }
    let valid = false;
    switch (value.method) {
      case 'initialize': valid = fields(params, ['protocolVersion', 'capabilities', 'clientInfo', '_meta']) && InitializeRequestSchema.safeParse(value).success; break;
      case 'tools/list': valid = fields(params, ['_meta']) && ListToolsRequestSchema.safeParse(value).success; break;
      case 'tools/call': valid = fields(params, ['name', 'arguments', '_meta']) && CallToolRequestSchema.safeParse(value).success; break;
      case 'ping': valid = fields(params, ['_meta']) && PingRequestSchema.safeParse(value).success; break;
      default: void this.reject(value.id, -32601); return;
    }
    if (!valid) { void this.reject(value.id, -32602); return; }
    if (value.method === 'tools/call') {
      try { toolParams(params as unknown as import('@modelcontextprotocol/sdk/types.js').CallToolRequest['params']); }
      catch { void this.reject(value.id, -32602); return; }
    }
    if ((value.method === 'tools/call' || value.method === 'tools/list') && !this.readyNotification) {
      void this.reject(value.id, -32600); return;
    }
    if (this.pending.size >= MCP_LIMITS.pending) {
      if (value.method === 'tools/call') void this.write({ jsonrpc: '2.0', id: value.id, result: refusal('control_refused') }).catch(this.lost);
      else void this.reject(value.id, -32600);
      return;
    }
    const internal = `client_${this.count}`;
    this.pending.set(internal, { external: value.id, key: externalKey, method: value.method,
      received, cancelled: false, started: false });
    this.external.set(externalKey, internal);
    this.deliver({ ...value, id: internal });
  }
  private deliver(value: unknown): void {
    const parsed = JSONRPCMessageSchema.safeParse(value);
    if (!parsed.success) { this.lost(); return; }
    this.onmessage?.(parsed.data);
  }
  private async reject(request: RequestId | null, code: number): Promise<void> {
    try { await this.write({ jsonrpc: '2.0', id: request, error: { code, message: messages[code] } }); }
    catch { this.lost(); }
  }
  async send(message: JSONRPCMessage): Promise<void> {
    if (this.dead) throw new Error('Transport unavailable');
    if ('method' in message || !('id' in message) || typeof message.id !== 'string') { this.lost(); throw new Error('Transport unavailable'); }
    const entry = this.pending.get(message.id);
    if (!entry) return; // Cancelled before handler admission, never replayed.
    this.forget(message.id, entry);
    if (entry.cancelled) return;
    let output: unknown = { ...message, id: entry.external };
    if ('error' in message) {
      const code = Object.hasOwn(messages, message.error.code) ? message.error.code : -32603;
      output = { jsonrpc: '2.0', id: entry.external, error: { code,
        message: entry.method === 'initialize' && code === -32603 ? 'Browser initialization failed' : messages[code] } };
    }
    let bytes = Buffer.from(JSON.stringify(output) + '\n');
    if (bytes.length - 1 > MCP_LIMITS.outbound) {
      output = entry.method === 'tools/call' && 'result' in message
        ? { jsonrpc: '2.0', id: entry.external, result: refusal('internal', message.result) }
        : { jsonrpc: '2.0', id: entry.external, error: { code: -32603, message: 'Internal error' } };
      bytes = Buffer.from(JSON.stringify(output) + '\n');
    }
    const written = this.writeBytes(bytes);
    if (entry.method === 'initialize' && 'result' in message) this.initializationCommitted = true;
    await written;
  }
  private write(value: unknown): Promise<void> { return this.writeBytes(Buffer.from(JSON.stringify(value) + '\n')); }
  private writeBytes(bytes: Buffer): Promise<void> {
    if (this.dead || bytes.length - 1 > MCP_LIMITS.outbound || this.queuedBytes + bytes.length > MCP_LIMITS.outbound + 1 ||
        this.io.stdout.writableLength + bytes.length > MCP_LIMITS.outbound + 1) {
      this.lost(); return Promise.reject(new Error('Transport unavailable'));
    }
    this.queuedBytes += bytes.length;
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(this.lost, 6000);
      const fail = (error: Error) => { clearTimeout(timer); this.writes.delete(fail); reject(error); };
      this.writes.add(fail);
      try {
        this.io.stdout.write(bytes, error => {
          clearTimeout(timer); this.writes.delete(fail); this.queuedBytes -= bytes.length;
          if (error || this.dead) { this.lost(); reject(new Error('Transport unavailable')); } else resolve();
        });
      } catch { this.lost(); }
    });
  }
  async close(): Promise<void> {
    if (this.dead) return;
    this.dead = true; clearInterval(this.heartbeat); this.used = 0; this.frame.fill(0);
    this.io.stdin.pause(); this.io.stdin.off('data', this.data);
    this.io.stdin.off('end', this.lost); this.io.stdin.off('close', this.lost);
    this.io.stdout.off('finish', this.lost);
    this.pending.clear(); this.external.clear(); this.seen.clear(); this.ping = undefined;
    for (const fail of [...this.writes]) fail(new Error('Transport unavailable'));
    this.onclose?.();
    // Keep fixed loss listeners for late stream errors; never inspect their data.
    this.io.stdout.destroy();
  }
}
function refusal(code: 'control_refused' | 'internal', result?: unknown) {
  const body = object(result) && object(result.structuredContent) ? result.structuredContent : undefined;
  const previous = body && object(body.error) ? body.error : body;
  const action = previous && validator('browser.ActionId')(previous.action) ? previous.action : undefined;
  const outcome = previous?.status === 'completed' ? 'completed' : previous?.dispatchOutcome;
  const structuredContent = { error: { code, message: code === 'internal' ? 'Browser response exceeds transport limits.' : 'Browser capacity is exhausted.',
    retryable: code !== 'internal', remedy: 'Wait for outstanding work, then inspect fresh state.',
    ...(action && validator('browser.Outcome')(outcome) ? { action, dispatchOutcome: outcome } : {}) } };
  return { isError: true, structuredContent, content: [{ type: 'text', text: JSON.stringify(structuredContent) }] };
}
