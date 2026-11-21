import type { Readable, Writable } from 'node:stream';
import { performance } from 'node:perf_hooks';
import { BrowserFailure, invalidInput, publicFailure, unavailable, type ExitCode } from '../contracts/errors.js';
import type { Contract } from '../contracts/generated.js';
import { agentToolValidator, validator } from '../contracts/schema.js';
import { token } from '../runtime/instance.js';
import type { ProcessPort } from '../runtime/ports.js';
import { isCancelledRequest, isMalformedAgentReply, runtimeTermination, type RuntimeClient } from '../runtime/transport.js';

const requestLimit = 1024 * 1024;
const responseLimit = 8 * 1024 * 1024;
const callerIdLimit = 65536;
const toolLimit = 32;
const combinedLimit = 64;
const startupMilliseconds = 60000;

export interface AgentSessionOptions {
  readonly profile: string;
  readonly label: string;
  readonly stdin: Readable;
  readonly stdout: Writable;
  readonly stderr: Writable;
  readonly cutoff?: number;
  attach: ProcessPort['attachAgent'];
}

const malformedReply = () => new BrowserFailure({ code: 'internal', message: 'Invalid Browser reply.', retryable: false }, 70);
const full = () => new BrowserFailure({ code: 'control_refused', message: 'Browser request capacity is exhausted.', retryable: false });

function encode(frame: Contract<'wire.CliAgentReady'> | Contract<'wire.CliAgentReply'> | Contract<'wire.CliAgentError'>): Buffer {
  return Buffer.from(JSON.stringify(frame) + '\n', 'utf8');
}

/** A single Node stdio session with an injected authenticated attachment. */
export function runAgentSession(options: AgentSessionOptions): Promise<ExitCode> {
  const { stdin, stdout, stderr, profile, label } = options;
  const deadline = Math.min(options.cutoff ?? Infinity, performance.now() + startupMilliseconds);
  const abort = new AbortController();
  const ids = new Set<string>();
  const calls = new Map<string, string>();
  const buffer = Buffer.alloc(requestLimit);
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let client: RuntimeClient | undefined;
  let length = 0, cancellations = 0;
  let ready = false, finished = false;
  let exitCode: ExitCode | undefined, settled = false;
  let terminalTimer: NodeJS.Timeout | undefined;
  let exit!: (code: ExitCode) => void;
  const result = new Promise<ExitCode>(resolve => { exit = resolve; });
  const initialTimer = setTimeout(() => finish(unavailable('browser')),
    Number.isFinite(deadline) ? Math.max(1, deadline - performance.now()) : 1);

  function disconnected() {
    finish(client && runtimeTermination(client) === 'malformed' ? malformedReply() : unavailable('browser'));
  }
  function inputEnd() { finish(length ? invalidInput() : undefined); }
  function outputClosed() { if (exitCode !== undefined) settle(exitCode); else finish(undefined, false); }
  function inputFailure() { finish(unavailable('browser')); }
  function outputDrain() { if (!finished) stdin.resume(); }
  function swallowDiagnosticFailure() { /* standard error is optional during release */ }

  function settle(code: ExitCode) {
    if (settled) return;
    settled = true;
    clearTimeout(terminalTimer);
    stdin.removeListener('error', inputFailure);
    stdout.removeListener('close', outputClosed);
    stdout.removeListener('finish', outputClosed);
    stdout.removeListener('error', outputClosed);
    stderr.removeListener('error', swallowDiagnosticFailure);
    exit(code);
  }

  function finish(failure?: BrowserFailure, outputAvailable = true) {
    if (finished) return;
    finished = true;
    exitCode = failure?.exitCode ?? 0;
    clearTimeout(initialTimer);
    stdin.pause();
    stdin.removeListener('data', input);
    stdin.removeListener('end', inputEnd);
    stdin.removeListener('close', inputEnd);
    stdout.removeListener('drain', outputDrain);
    client?.signal.removeEventListener('abort', disconnected);
    abort.abort();
    client?.close();
    calls.clear();
    ids.clear();
    length = 0;
    if (failure) {
      try { stderr.write(`arbol-browser: ${failure.detail.code}\n`); } catch { /* disconnected diagnostics */ }
    }
    if (!failure || !outputAvailable || !stdout.writable || stdout.destroyed) {
      setImmediate(() => settle(exitCode!));
      return;
    }
    const frame = encode({ event: 'error', error: failure.detail });
    if (stdout.writableLength + frame.length > responseLimit + 1) { setImmediate(() => settle(failure.exitCode)); return; }
    terminalTimer = setTimeout(() => settle(failure.exitCode), 1000);
    try { stdout.write(frame, () => { setImmediate(() => settle(failure.exitCode)); }); }
    catch { setImmediate(() => settle(failure.exitCode)); }
  }

  function emit(frame: Contract<'wire.CliAgentReady'> | Contract<'wire.CliAgentReply'>) {
    if (finished) return false;
    let bytes = encode(frame);
    if (bytes.length - 1 > responseLimit && 'id' in frame) {
      bytes = encode({ id: frame.id, ok: false, error: malformedReply().detail });
    }
    if (!stdout.writable || stdout.destroyed || stdout.writableLength + bytes.length > responseLimit + 1) {
      finish(unavailable('browser'), false); return false;
    }
    try { if (!stdout.write(bytes)) stdin.pause(); }
    catch { finish(unavailable('browser'), false); return false; }
    return true;
  }

  function replyError(id: string, error: unknown) {
    const detail = publicFailure(error).detail;
    if (!validator('browser.BrowserError')(detail)) { finish(malformedReply()); return; }
    emit({ id, ok: false, error: detail });
  }

  function dispatch(frame: unknown) {
    if (typeof frame !== 'object' || frame === null || Array.isArray(frame) || !Object.hasOwn(frame, 'id')) { finish(invalidInput()); return; }
    const id: unknown = (frame as { id: unknown }).id;
    if (!validator('wire.CliAgentId')(id) || ids.has(id)) { finish(invalidInput()); return; }
    if (ids.size >= callerIdLimit) { finish(full()); return; }
    ids.add(id);
    const attached = client;
    if (!attached || !ready || attached.signal.aborted) { disconnected(); return; }

    if (validator('wire.CliAgentCancel')(frame)) {
      const target = calls.get(frame.cancel);
      if (!target) { emit({ id, ok: true, result: { request: frame.cancel, found: false } }); return; }
      if (calls.size + cancellations >= combinedLimit) { replyError(id, full()); return; }
      ++cancellations;
      void attached.cancel(target).then(value => {
        --cancellations;
        if (finished) return;
        if (!validator('wire.CancelResult')(value) || value.request !== target) { finish(malformedReply()); return; }
        if (value.found && calls.get(frame.cancel) === target) calls.delete(frame.cancel);
        emit({ id, ok: true, result: { request: frame.cancel, found: value.found } });
      }, error => { --cancellations; if (!finished) replyError(id, error); }).catch(error => finish(publicFailure(error)));
      return;
    }

    if (!validator('wire.CliAgentCall')(frame) || !agentToolValidator(frame.tool, 'input')(frame.arguments) ||
        Object.values(frame.arguments).some(value => typeof value === 'string' && /[\0\p{Cs}]/u.test(value)) ||
        (typeof frame.arguments.text === 'string' && Buffer.byteLength(frame.arguments.text) > 64 * 1024)) {
      replyError(id, invalidInput()); return;
    }
    if (calls.size + cancellations >= toolLimit) { replyError(id, full()); return; }
    const privateId = token('req');
    const request = { wire: 1, id: privateId, method: 'tool', params: { name: frame.tool, arguments: frame.arguments } };
    if (!validator('wire.ToolRequest')(request)) { replyError(id, invalidInput()); return; }
    calls.set(id, privateId);
    void attached.call(request).then(value => {
      if (finished || calls.get(id) !== privateId) return;
      calls.delete(id);
      if (frame.tool === 'browser_screenshot' || !agentToolValidator(frame.tool, 'success')(value)) { finish(malformedReply()); return; }
      const response = { id, ok: true, result: value };
      if (!validator('wire.CliAgentReply')(response)) { finish(malformedReply()); return; }
      emit(response);
    }, error => {
      if (finished || calls.get(id) !== privateId) return;
      calls.delete(id);
      if (!isCancelledRequest(error)) replyError(id, error);
    }).catch(error => finish(publicFailure(error)));
  }

  function input(chunk: unknown) {
    if (finished) return;
    if (!ready || !Buffer.isBuffer(chunk)) { finish(invalidInput()); return; }
    let start = 0;
    while (start < chunk.length && !finished) {
      const newline = chunk.indexOf(10, start);
      const end = newline === -1 ? chunk.length : newline;
      if (length + end - start > requestLimit) { finish(invalidInput()); return; }
      length += chunk.copy(buffer, length, start, end);
      if (newline === -1) return;
      const line = buffer.subarray(0, length);
      length = 0;
      let frame: unknown;
      try {
        if (line.includes(13)) { finish(invalidInput()); return; }
        frame = JSON.parse(decoder.decode(line));
      } catch { finish(invalidInput()); return; }
      try { dispatch(frame); } catch (error) { finish(publicFailure(error)); return; }
      start = newline + 1;
    }
  }

  stdin.on('data', input); stdin.once('end', inputEnd); stdin.once('close', inputEnd); stdin.on('error', inputFailure);
  stdout.on('drain', outputDrain); stdout.once('close', outputClosed); stdout.once('finish', outputClosed); stdout.on('error', outputClosed);
  stderr.on('error', swallowDiagnosticFailure);
  if (stdin.readableEnded || stdin.destroyed || stdout.destroyed || stdout.writableEnded) { finish(); return result; }
  if (!Number.isFinite(deadline) || performance.now() >= deadline) { finish(unavailable('browser')); return result; }
  if (!validator('browser.ProfileId')(profile) || !validator('browser.ClientLabel')(label)) { finish(invalidInput()); return result; }
  void Promise.resolve().then(async () => {
    if (finished) return;
    const attached = await options.attach({ profile, label, deadline, signal: abort.signal });
    if (finished) { attached.close(); return; }
    client = attached;
    if (performance.now() >= deadline || attached.hello.contract !== 1 || !attached.hello.attachment || attached.hello.profile !== profile ||
        !validator('browser.Build')(attached.hello.build)) { finish(unavailable('browser')); return; }
    client.signal.addEventListener('abort', disconnected, { once: true });
    if (client.signal.aborted) { disconnected(); return; }
    clearTimeout(initialTimer);
    ready = emit({ event: 'ready', contract: 1, profile, build: attached.hello.build });
  }).catch(error => finish(isMalformedAgentReply(error) ? malformedReply() : publicFailure(error)));
  return result;
}
