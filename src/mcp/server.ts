import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { InitializeRequestSchema, InitializedNotificationSchema, ListToolsRequestSchema,
  CallToolRequestSchema, ErrorCode, type Tool, type CallToolRequest, type CallToolResult,
  type RequestId } from '@modelcontextprotocol/sdk/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { McpLifecycle, protocolError } from './lifecycle.js';

export interface McpCallContext { readonly requestId: RequestId; readonly signal: AbortSignal; readonly receivedAt: number }
export interface McpApplication {
  initialize(label: string, signal: AbortSignal, deadline: number): Promise<void>;
  list(): Tool[];
  call(params: CallToolRequest['params'], context: McpCallContext): Promise<CallToolResult>;
  close(): void;
}
export interface McpTransport extends Transport { receivedAt(id: RequestId): number | undefined }
export interface McpIdentity { readonly version: string; readonly build: string }
/** No CLI/profile assembly here. The caller supplies a fresh application and
 * bounded Transport; SDK owns request execution, cancellation and final replies. */
export async function serveMcp(transport: McpTransport, identity: McpIdentity, application: McpApplication,
  diagnostic: (event: 'protocol_failure' | 'connection_closed') => void = () => {}): Promise<void> {
  const info = { name: 'arbol-browser', version: `${identity.version}+${identity.build}` };
  const server = new Server(info, { capabilities: { tools: {} } });
  let finish!: () => void;
  const closed = new Promise<void>(resolve => { finish = resolve; });
  const stop = () => { void server.close().catch(() => {}); };
  const lifecycle = new McpLifecycle((label, signal, deadline) => application.initialize(label, signal, deadline),
    () => application.close(), stop);
  server.onerror = () => { diagnostic('protocol_failure'); lifecycle.close(); stop(); };
  server.onclose = () => { lifecycle.close(); diagnostic('connection_closed'); finish(); };
  // Replace SDK's broad default version set. No private SDK state or raw stdin.
  server.setRequestHandler(InitializeRequestSchema, async (request, extra) => {
    const protocolVersion = await lifecycle.initialize(request.params.protocolVersion, request.params.clientInfo.name,
      extra.signal, transport.receivedAt(extra.requestId) ?? performance.now());
    return { protocolVersion, capabilities: { tools: {} }, serverInfo: info };
  });
  server.setNotificationHandler(InitializedNotificationSchema, () => lifecycle.initialized());
  server.setRequestHandler(ListToolsRequestSchema, request => {
    lifecycle.assertReady();
    if (request.params?.cursor !== undefined) throw protocolError(ErrorCode.InvalidParams);
    return { tools: application.list() };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    lifecycle.assertReady();
    return application.call(request.params, { requestId: extra.requestId, signal: extra.signal,
      receivedAt: transport.receivedAt(extra.requestId) ?? performance.now() });
  });
  server.fallbackRequestHandler = async () => { throw protocolError(ErrorCode.MethodNotFound); };
  try { await server.connect(transport); await closed; }
  finally { lifecycle.close(); await server.close(); }
}
