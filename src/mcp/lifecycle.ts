import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { sanitizedLabel } from '../runtime/transport.js';

export const MCP_REVISIONS = ['2025-11-25', '2025-06-18'] as const;
export type McpRevision = typeof MCP_REVISIONS[number];
export function protocolError(code: ErrorCode): McpError {
  return new McpError(code, code === ErrorCode.InvalidParams ? 'Invalid params' :
    code === ErrorCode.InvalidRequest ? 'Invalid request' :
    code === ErrorCode.MethodNotFound ? 'Method not found' : 'Internal error');
}
/** Select the revision before the sole attachment attempt. Successful initialize
 * requires a verified connection; the subsequent notification opens tools only. */
export class McpLifecycle {
  private phase: 'new' | 'attaching' | 'attached' | 'ready' | 'closed' = 'new';
  private readonly connection = new AbortController();
  private removeCancellation: (() => void) | undefined;
  constructor(private readonly attach: (label: string, signal: AbortSignal, deadline: number) => Promise<void>,
    private readonly release: () => void, private readonly failed: () => void) {}
  async initialize(offered: string, name: string, signal: AbortSignal, receivedAt: number): Promise<McpRevision> {
    if (this.phase !== 'new') throw protocolError(ErrorCode.InvalidRequest);
    const revision = offered === MCP_REVISIONS[1] ? MCP_REVISIONS[1] : MCP_REVISIONS[0];
    const label = sanitizedLabel(name), deadline = receivedAt + 30000;
    this.phase = 'attaching';
    const cancel = () => { this.close(); this.failed(); };
    signal.addEventListener('abort', cancel, { once: true });
    this.removeCancellation = () => signal.removeEventListener('abort', cancel);
    const timer = setTimeout(cancel, Math.max(1, deadline - performance.now()));
    try {
      if (signal.aborted || this.connection.signal.aborted || performance.now() >= deadline) throw new Error();
      await this.attach(label, this.connection.signal, deadline);
      if (signal.aborted || this.connection.signal.aborted || performance.now() >= deadline) throw new Error();
      this.phase = 'attached';
      return revision;
    } catch {
      this.close();
      throw new McpError(ErrorCode.InternalError, 'Browser initialization failed');
    } finally { clearTimeout(timer); }
  }
  initialized(): void {
    if (this.phase !== 'attached') throw protocolError(ErrorCode.InvalidRequest);
    this.phase = 'ready'; this.removeCancellation?.(); this.removeCancellation = undefined;
  }
  assertReady(): void {
    if (this.phase !== 'ready') throw protocolError(ErrorCode.InvalidRequest);
  }
  close(): void {
    if (this.phase === 'closed') return;
    this.phase = 'closed'; this.removeCancellation?.(); this.removeCancellation = undefined;
    this.connection.abort(); this.release();
  }
}
