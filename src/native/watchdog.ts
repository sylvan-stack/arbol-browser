/** Private protocol-1 client. No stop/disarm export or finally-based release. */
import { Socket } from 'node:net';
import { isMainThread } from 'node:worker_threads';
import { assertCandidateTrust, productionPublisher, refuse, type CandidateTrust } from './manifest.js';
import { assertWatchdogCustody, type WatchdogCustody, type HostLossStage } from '../runtime/platform.js';
export type ProfileFatalCause = Extract<HostLossStage, `native_${string}`>;
export interface NativeWatchdog {
  assertArmed(trust: CandidateTrust): void;
  readonly custody: WatchdogCustody;
  readonly fatal: boolean;
  quarantine(reason?: ProfileFatalCause): void;
  terminate(): never;
}
let attempted = false, lossObserved = false;
const actualWatchdogs = new WeakSet<object>();
export function assertNativeWatchdog(value: NativeWatchdog): void {
  if (!actualWatchdogs.has(value)) refuse();
}
export async function startNativeWatchdog(trust: CandidateTrust, custody: WatchdogCustody): Promise<NativeWatchdog> {
  if (attempted || !isMainThread || process.type !== 'browser') refuse();
  attempted = true; assertCandidateTrust(trust); assertWatchdogCustody(custody);
  const launch = custody.now();
  if (trust.manifest.bundleIdentifier !== productionPublisher.bundleIdentifier &&
      !trust.manifest.files['Contents/Resources/browser/native/watchdog']) refuse();
  let phase: 'starting' | 'armed' | 'fatal' = 'starting', terminating = false, sequence = 0n;
  let buffer = '', lastAck = launch;
  let firstLoss: HostLossStage | undefined;
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  let readiness: ReturnType<typeof setTimeout> | undefined;
  const pending = new Map<bigint, number>();
  // Native owns the actual one-shot spawn and private capability/state FD
  // actions. Only this genuine transport's pipe endpoints cross into JS.
  let child: { pid: number; stdin: Socket; stdout: Socket };
  let readyResolve: (value: NativeWatchdog) => void, readyReject: (error: Error) => void;
  const ready = new Promise<NativeWatchdog>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  function observeLoss(): void {
    try {
      if (!lossObserved && firstLoss) { lossObserved = true; custody.noteLoss?.(firstLoss); }
    } catch { /* Diagnostics cannot alter the original fatal path. */ }
  }
  function lose(reason: HostLossStage): never {
    try { custody.latchFatal(); } catch { return custody.terminate(); }
    firstLoss ??= reason;
    phase = 'fatal'; if (heartbeat) clearInterval(heartbeat); if (readiness) clearTimeout(readiness);
    readyReject!(new Error('native_watchdog_unavailable'));
    // This real native capability retains original descriptions and waits for
    // actual engine/monitor exit. No app/input-addon cleanup precedes it.
    if (!terminating) { terminating = true; observeLoss(); custody.terminate(); }
    return refuse();
  }
  function expired(now: number): boolean {
    const first = pending.values().next().value;
    return now - lastAck >= 1000 || (first !== undefined && now - first >= 1000);
  }
  function send(kind: 'H' | 'F'): void {
    if (phase !== 'starting' && expired(custody.now())) lose('watchdog-ack-expiry');
    if (!child.stdin || child.stdin.destroyed || sequence >= 0xffffffffffffffffn || pending.size >= 8) lose('watchdog-transport-loss');
    const next = ++sequence; pending.set(next, custody.now());
    try { child.stdin!.write(`${kind} ${next}\n`, 'ascii', error => { if (error) lose('watchdog-pipe-error'); }); } catch { lose('watchdog-pipe-error'); }
  }
  const api: NativeWatchdog = Object.freeze({ custody,
    get fatal() { return phase === 'fatal'; },
    assertArmed(value: CandidateTrust): void {
      if (value !== trust) lose('native_integrity_unavailable');
      if (phase !== 'armed') lose('watchdog-readiness-loss');
      if (expired(custody.now())) lose('watchdog-ack-expiry');
      try { custody.assert(); } catch { lose('watchdog-custody-refusal'); }
    },
    quarantine(reason: ProfileFatalCause = 'native_watchdog_unavailable'): void {
      if (phase === 'fatal') return;
      try { custody.latchFatal(); } catch { return custody.terminate(); }
      firstLoss ??= reason;
      phase = 'fatal'; if (heartbeat) clearInterval(heartbeat);
      send('F'); // never await; the previously armed independent deadline survives
      observeLoss();
    },
    terminate(): never { return lose('watchdog-termination'); },
  });
  actualWatchdogs.add(api);
  try {
    const actual = custody.spawn();
    child = { pid: actual.pid, stdin: new Socket({ fd: actual.writer, readable: false, writable: true }),
      stdout: new Socket({ fd: actual.reader, readable: true, writable: false }) };
    if (custody.now() - launch >= 1000) return lose('watchdog-readiness-loss');
    custody.capture(child.pid);
  } catch { return lose('watchdog-spawn-loss'); }
  child.stdin.on('error', () => lose('watchdog-pipe-error')); child.stdout.on('error', () => lose('watchdog-pipe-error'));
  child.stdout.once('end', () => lose('watchdog-pipe-end'));
  child.stdout.on('data', (chunk: Buffer) => {
    if (phase !== 'starting' && expired(custody.now())) lose('watchdog-ack-expiry');
    if (!Buffer.isBuffer(chunk) || chunk.some(byte => byte !== 10 && (byte < 32 || byte > 126))) lose('watchdog-ack-malformed');
    buffer += chunk.toString('ascii'); if (buffer.length > 4096) lose('watchdog-ack-malformed');
    for (;;) {
      const end = buffer.indexOf('\n'); if (end < 0) { if (buffer.length > 127) lose('watchdog-ack-malformed'); break; }
      if (end > 127) lose('watchdog-ack-malformed'); const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      if (phase === 'starting') {
        if (line !== `R 1 ${process.pid}` || custody.now() - launch >= 1000) lose('watchdog-readiness-loss');
        try { custody.bind(); custody.assert(); } catch { lose('watchdog-custody-refusal'); }
        if (custody.now() - launch >= 1000) lose('watchdog-readiness-loss');
        phase = 'armed'; lastAck = custody.now(); if (readiness) clearTimeout(readiness);
        send('H'); heartbeat = setInterval(() => { if (phase === 'armed') send('H'); }, 250); heartbeat.unref();
        readyResolve!(api);
      } else {
        const match = /^A (0|[1-9][0-9]{0,19})$/.exec(line); if (!match) lose('watchdog-ack-malformed');
        const value = BigInt(match![1]!); if (value > 0xffffffffffffffffn || pending.keys().next().value !== value) lose('watchdog-ack-order');
        const now = custody.now(), issued = pending.get(value);
        if (issued === undefined || now - issued >= 1000 || expired(now)) lose('watchdog-ack-expiry');
        pending.delete(value); lastAck = now;
      }
    }
  });
  readiness = setTimeout(() => lose('watchdog-readiness-loss'), Math.max(1, 1000 - (custody.now() - launch))); readiness.unref();
  const liveness = setInterval(() => {
    if (phase !== 'starting') {
      if (expired(custody.now())) lose('watchdog-ack-expiry');
      try { custody.assert(); } catch { lose('watchdog-custody-refusal'); }
    }
  }, 25);
  liveness.unref(); // not cleared on fatal or normal cleanup: coverage ends with the process
  return ready;
}
