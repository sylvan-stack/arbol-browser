import { randomBytes } from 'node:crypto';
import { ErrorCode, type CallToolRequest, type CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { RuntimeClient } from '../runtime/transport.js';
import type { Stdio } from '../runtime/ports.js';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, type BrowserError } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { BoundedMcpTransport, MCP_LIMITS } from './framing.js';
import { serveMcp, type McpApplication, type McpCallContext, type McpIdentity } from './server.js';
import { protocolError } from './lifecycle.js';
import { advertisedTools, toolParams, toolDuration, validToolResult } from './tools.js';

export interface AgentAttachmentRequest {
  readonly profile: string; readonly label: string; readonly signal: AbortSignal; readonly deadline: number;
}
/** ABR-30 supplies actual process acquisition and connectRuntime(agent), honoring
 * cancellation/deadline through acquisition. It must never retry/reconnect or
 * substitute a management connection. RuntimeClient already verifies peer/hello. */
export type FreshAgentAttachmentFactory = (request: AgentAttachmentRequest) => Promise<RuntimeClient>;
function localId(): string { return `req_${randomBytes(16).toString('base64url')}`; }
function envelope(value: Record<string, unknown>, isError: boolean, png?: string): CallToolResult {
  return { isError, structuredContent: value, content: [
    { type: 'text', text: JSON.stringify(value) }, ...(png === undefined ? [] : [{ type: 'image' as const, mimeType: 'image/png', data: png }]),
  ] };
}
function boundedContent(name: string, value: unknown): void {
  if (name !== 'browser_snapshot') return;
  const snapshot = value as Contract<'browser.SnapshotResult'>;
  if (Buffer.byteLength(JSON.stringify(snapshot), 'utf8') > 512 * 1024) throw new Error();
  const work = snapshot.tree.map(node => ({ node, depth: 1 })); let count = 0;
  while (work.length) {
    const { node, depth } = work.pop()!;
    if (++count > 5000 || depth > 32) throw new Error();
    for (const child of node.children ?? []) work.push({ node: child, depth: depth + 1 });
  }
}
/** Decode only in memory; schema contentEncoding is an annotation, not a PNG
 * check. Validate canonical base64 and the bounded original PNG dimensions. */
function screenshot(value: Contract<'browser.ScreenshotPayload'>): CallToolResult {
  const { metadata, data } = value, bytes = Buffer.from(data, 'base64');
  if (!data.length || bytes.length > 4 * 1024 * 1024 || bytes.toString('base64') !== data || bytes.length < 33 ||
      !bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) ||
      bytes.readUInt32BE(8) !== 13 || bytes.toString('ascii', 12, 16) !== 'IHDR' ||
      bytes.readUInt32BE(16) !== metadata.width || bytes.readUInt32BE(20) !== metadata.height ||
      metadata.width * metadata.height > 2097152) throw new Error();
  return envelope(metadata, false, data);
}
/** One adapter owns exactly one fresh runtime socket and no host leases. */
export class BrowserMcpAdapter implements McpApplication {
  private attempted = false;
  private closed = false;
  private runtime: RuntimeClient | undefined;
  private removeLost: (() => void) | undefined;
  private readonly pending = new Map<string | number, string>();
  constructor(private readonly profile: string, private readonly factory: FreshAgentAttachmentFactory,
    private readonly transport: BoundedMcpTransport) {
    if (!validator('browser.ProfileId')(profile)) throw protocolError(ErrorCode.InvalidParams);
  }
  async initialize(label: string, signal: AbortSignal, deadline: number): Promise<void> {
    if (this.attempted || this.closed || signal.aborted) throw protocolError(ErrorCode.InvalidRequest);
    this.attempted = true;
    let cancel!: () => void;
    const cancelled = new Promise<never>((_, reject) => {
      cancel = () => { this.close(); reject(protocolError(ErrorCode.InternalError)); };
      signal.addEventListener('abort', cancel, { once: true });
    });
    try {
      if (signal.aborted || this.closed || performance.now() >= deadline) throw new Error();
      const attempt = this.factory({ profile: this.profile, label, signal, deadline }).then(runtime => {
        if (this.closed || signal.aborted || performance.now() >= deadline) { runtime.close(); throw new Error(); }
        try {
          if (!validator('wire.HelloResult')({ wire: 1, id: localId(), ok: true, result: runtime.hello }) ||
              runtime.hello.profile !== this.profile || !runtime.hello.attachment || runtime.signal.aborted)
            throw new Error();
          this.runtime = runtime;
          const lost = () => { this.close(); void this.transport.close(); };
          runtime.signal.addEventListener('abort', lost, { once: true });
          this.removeLost = () => runtime.signal.removeEventListener('abort', lost);
          if (runtime.signal.aborted) { lost(); throw new Error(); }
        } catch { runtime.close(); throw new Error(); }
      });
      await Promise.race([attempt, cancelled]);
      if (this.closed || signal.aborted || !this.runtime || this.runtime.signal.aborted) throw new Error();
    } catch { this.close(); throw protocolError(ErrorCode.InternalError); }
    finally { signal.removeEventListener('abort', cancel); }
  }
  list() { return advertisedTools(); }
  async call(params: CallToolRequest['params'], context: McpCallContext): Promise<CallToolResult> {
    const selected = toolParams(params), runtime = this.runtime;
    if (!this.transport.begin(context.requestId) || context.signal.aborted) throw protocolError(ErrorCode.InvalidRequest);
    const id = localId(), deadline = context.receivedAt + toolDuration(selected.name);
    let issued = false, cancelSent = false;
    const cancel = () => {
      if (!issued || cancelSent || !runtime || this.closed) return;
      cancelSent = true;
      void runtime.cancel(id).catch(() => { this.close(); void this.transport.close(); });
    };
    try {
      if (!runtime || runtime.signal.aborted || this.closed) throw new Error();
      if (this.pending.size >= MCP_LIMITS.pending) return envelope({ error: { code: 'control_refused',
        message: 'Browser capacity is exhausted.', retryable: true, remedy: 'Wait, then inspect fresh state.' } }, true);
      this.pending.set(context.requestId, id);
      context.signal.addEventListener('abort', cancel, { once: true });
      if (context.signal.aborted) throw protocolError(ErrorCode.InvalidRequest);
      if (performance.now() >= deadline) return envelope({ error: { code: 'control_refused',
        message: 'The request expired before dispatch.', retryable: true, remedy: 'Inspect fresh state.' } }, true);
      const operation = runtime.call({ wire: 1, id, method: 'tool', params: selected }, deadline);
      issued = true;
      if (context.signal.aborted) cancel();
      let value: unknown;
      try { value = await operation; }
      catch (error) {
        if (error instanceof BrowserFailure && validator('browser.BrowserError')(error.detail))
          return envelope({ error: error.detail }, true);
        throw error;
      }
      if (this.closed || runtime.signal.aborted || context.signal.aborted) throw new Error();
      try {
        if (!validToolResult(selected.name, value)) throw new Error();
        boundedContent(selected.name, value);
        return selected.name === 'browser_screenshot' ? screenshot(value as Contract<'browser.ScreenshotPayload'>)
          : envelope(value as Record<string, unknown>, false);
      } catch { this.close(); void this.transport.close(); throw protocolError(ErrorCode.InternalError); }
    } catch {
      this.close(); void this.transport.close(); throw protocolError(ErrorCode.InternalError);
    } finally {
      context.signal.removeEventListener('abort', cancel); this.pending.delete(context.requestId); this.transport.settled(context.requestId);
    }
  }
  close(): void {
    if (this.closed) return;
    this.closed = true; this.removeLost?.(); this.removeLost = undefined;
    const runtime = this.runtime; this.runtime = undefined; this.pending.clear(); runtime?.close();
  }
}
/** Source-only composition. No entrypoint, process acquisition or vendor config
 * mutation is installed here; production CLI composition belongs to ABR-30. */
export async function runMcp(io: Stdio, identity: McpIdentity, factory: FreshAgentAttachmentFactory,
  profile = 'default'): Promise<void> {
  const transport = new BoundedMcpTransport(io), adapter = new BrowserMcpAdapter(profile, factory, transport);
  try { await serveMcp(transport, identity, adapter); }
  finally { adapter.close(); await transport.close(); }
}
