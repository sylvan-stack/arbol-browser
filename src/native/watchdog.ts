/** Private protocol-1 client. No stop/disarm export or finally-based release. */
import { Socket } from 'node:net';
import { performance } from 'node:perf_hooks';
import { isMainThread } from 'node:worker_threads';
import { assertCandidateTrust, refuse, type CandidateTrust } from './manifest.js';
import { assertWatchdogCustody, type WatchdogCustody } from '../runtime/platform.js';
export interface NativeWatchdog {
  assertArmed(trust: CandidateTrust): void;
  readonly custody: WatchdogCustody;
  readonly fatal: boolean;
  quarantine(): void;
  terminate(): never;
}
let attempted = false;
const actualWatchdogs = new WeakSet<object>();
export function assertNativeWatchdog(value: NativeWatchdog): void {
  if (!actualWatchdogs.has(value)) refuse();
}
export async function startNativeWatchdog(trust: CandidateTrust, custody: WatchdogCustody): Promise<NativeWatchdog> {
  if (attempted || !isMainThread || process.type !== 'browser') refuse();
  attempted = true; assertCandidateTrust(trust); assertWatchdogCustody(custody);
  const launch = performance.now();
  if (!trust.manifest.files['Contents/Resources/browser/native/watchdog']) refuse();
  let phase: 'starting' | 'armed' | 'fatal' = 'starting', terminating = false, sequence = 0n;
  let buffer = '', lastAck = launch;
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  let readiness: ReturnType<typeof setTimeout> | undefined;
  const pending = new Map<bigint, number>();
  // Native owns the actual one-shot spawn and private capability/state FD
  // actions. Only this genuine transport's pipe endpoints cross into JS.
  let child: { pid: number; stdin: Socket; stdout: Socket };
  let readyResolve: (value: NativeWatchdog) => void, readyReject: (error: Error) => void;
  const ready = new Promise<NativeWatchdog>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  function lose(): never {
    phase = 'fatal'; if (heartbeat) clearInterval(heartbeat); if (readiness) clearTimeout(readiness);
    readyReject!(new Error('native_watchdog_unavailable'));
    // This real native capability retains original descriptions and waits for
    // actual engine/monitor exit. No app/input-addon cleanup precedes it.
    if (!terminating) { terminating = true; custody.terminate(); }
    return refuse();
  }
  function expired(now: number): boolean {
    const first = pending.values().next().value;
    return now - lastAck >= 1000 || (first !== undefined && now - first >= 1000);
  }
  function send(kind: 'H' | 'F'): void {
    if (phase !== 'starting' && expired(performance.now())) lose();
    if (!child.stdin || child.stdin.destroyed || sequence >= 0xffffffffffffffffn || pending.size >= 8) lose();
    const next = ++sequence; pending.set(next, performance.now());
    try { child.stdin!.write(`${kind} ${next}\n`, 'ascii', error => { if (error) lose(); }); } catch { lose(); }
  }
  const api: NativeWatchdog = Object.freeze({ custody,
    get fatal() { return phase === 'fatal'; },
    assertArmed(value: CandidateTrust): void {
      if (value !== trust || phase !== 'armed' || expired(performance.now())) lose();
      try { custody.assert(); } catch { lose(); }
    },
    quarantine(): void {
      if (phase === 'fatal') return;
      phase = 'fatal'; if (heartbeat) clearInterval(heartbeat);
      send('F'); // never await; the previously armed independent deadline survives
    },
    terminate(): never { return lose(); },
  });
  actualWatchdogs.add(api);
  try {
    const actual = custody.spawn();
    child = { pid: actual.pid, stdin: new Socket({ fd: actual.writer, readable: false, writable: true }),
      stdout: new Socket({ fd: actual.reader, readable: true, writable: false }) };
    if (performance.now() - launch >= 1000) return lose();
    custody.capture(child.pid);
  } catch { return lose(); }
  child.stdin.on('error', () => lose()); child.stdout.on('error', () => lose());
  child.stdout.once('end', () => lose());
  child.stdout.on('data', (chunk: Buffer) => {
    if (phase !== 'starting' && expired(performance.now())) lose();
    if (!Buffer.isBuffer(chunk) || chunk.some(byte => byte !== 10 && (byte < 32 || byte > 126))) lose();
    buffer += chunk.toString('ascii'); if (buffer.length > 4096) lose();
    for (;;) {
      const end = buffer.indexOf('\n'); if (end < 0) { if (buffer.length > 127) lose(); break; }
      if (end > 127) lose(); const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      if (phase === 'starting') {
        if (line !== `R 1 ${process.pid}` || performance.now() - launch >= 1000) lose();
        try { custody.bind(); custody.assert(); } catch { lose(); }
        if (performance.now() - launch >= 1000) lose();
        phase = 'armed'; lastAck = performance.now(); if (readiness) clearTimeout(readiness);
        send('H'); heartbeat = setInterval(() => { if (phase === 'armed') send('H'); }, 250); heartbeat.unref();
        readyResolve!(api);
      } else {
        const match = /^A (0|[1-9][0-9]{0,19})$/.exec(line); if (!match) lose();
        const value = BigInt(match![1]!); if (value > 0xffffffffffffffffn || pending.keys().next().value !== value) lose();
        const now = performance.now(), issued = pending.get(value);
        if (issued === undefined || now - issued >= 1000 || expired(now)) lose();
        pending.delete(value); lastAck = now;
      }
    }
  });
  readiness = setTimeout(() => lose(), Math.max(1, 1000 - (performance.now() - launch))); readiness.unref();
  const liveness = setInterval(() => {
    if (phase !== 'starting') {
      if (expired(performance.now())) lose();
      try { custody.assert(); } catch { lose(); }
    }
  }, 25);
  liveness.unref(); // not cleared on fatal or normal cleanup: coverage ends with the process
  return ready;
}
