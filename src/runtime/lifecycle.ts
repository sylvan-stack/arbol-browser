import { noteOpenCommand, type OpenCommandObservation } from './authorities.js';
import { setTimeout } from 'node:timers/promises';
import type { Contract } from '../contracts/generated.js';
import { unavailable, BrowserFailure } from '../contracts/errors.js';
import { preflightPageAdmission } from './bootstrap.js';
import { isHostCustody } from './custody.js';
import { isProductionExitAuthority, type ProductionExitAuthority } from './exit.js';
import { archiveRemovedRuntime, assertProductionCloseReady } from './process.js';
import { assertPlatform, type PlatformPort, type GroupProcess } from './platform.js';
import type { BuildSelection } from './selection.js';
import { requestManagementClose, reserveManagementClose, openProtectedReady, connectRuntime, type Request, type ManagementCloseOpportunity, type RuntimeClient, type Endpoint, type TransportServer, type ConnectionContext } from './transport.js';
import { runtimeLocation, readRuntime, originalAlive, now, startupDeadline, neverOpenedExit,
  token, assertTime, type RuntimeRecord, type PreviousExit } from './instance.js';
import { assertProfile, type ProfileSnapshot } from '../profiles/records.js';
import { profileUnavailable, statOrAbsent, stateDirectory } from '../profiles/paths.js';
import { selectProfile } from '../profiles/create.js';
import { ownerLock, type OwnerLease, type RegistryLease } from '../profiles/locking.js';
import type { ProfileRuntimePort } from '../profiles/manage.js';
import type { ProcessPort, Stdio } from './ports.js';
import type { HostPreparation } from './host-entry.js';
import { productionSessionShutdown, type ProfileSessions } from '../profiles/session.js';

/** Expiry is refusal only, never evidence that native work was cancelled. */
async function within<T>(deadline: number, operation: () => Promise<T>): Promise<T> {
  assertTime(deadline);
  let timer: NodeJS.Timeout | undefined;
  try {
    const result = await Promise.race([operation(), new Promise<never>((_resolve, reject) => {
      timer = globalThis.setTimeout(() => reject(unavailable('browser')), Math.max(1, deadline - now()));
    })]);
    assertTime(deadline); return result;
  } finally { clearTimeout(timer); }
}

/** Own an acquisition until the bounded wait has accepted its result. Expiry
 * abandons the wait, never the obligation to dispose an operation-owned value. */
async function acquireWithin<T>(deadline: number, operation: () => Promise<T>, dispose: (value: T) => void): Promise<T> {
  let accepting = true;
  let acquired: { value: T } | undefined;
  try {
    const result = await within(deadline, async () => {
      const value = await operation();
      if (!accepting || now() >= deadline) { dispose(value); throw unavailable('browser'); }
      acquired = { value };
      return value;
    });
    assertTime(deadline);
    // The caller takes responsibility immediately after this successful wait.
    accepting = false; acquired = undefined;
    return result;
  } catch (error) {
    accepting = false;
    if (acquired) { const { value } = acquired; acquired = undefined; dispose(value); }
    throw error;
  }
}

export interface ExitAuthority extends PreviousExit {
  /** Trusted confinement/provenance plus full owned-process census, including
   * escaped/orphaned helpers. A PID/group observation alone cannot satisfy it. */
  assertCensus(profile: ProfileSnapshot, original: RuntimeRecord, group: readonly GroupProcess[]): Promise<void>;
  /** Terminate verified original identities only; independently armed native
   * watchdog, never JavaScript PID-check-then-kill or a timer-as-proof. */
  force(profile: ProfileSnapshot, original: RuntimeRecord, deadline: number): Promise<void>;
}
async function assertNoSockets(profile: ProfileSnapshot): Promise<void> {
  const location = await runtimeLocation(profile);
  if (location && (await statOrAbsent(location.agent) || await statOrAbsent(location.management))) throw profileUnavailable();
}
export function createProfileRuntime(platform: PlatformPort, selection: BuildSelection,
  exits: PreviousExit = neverOpenedExit): ProfileRuntimePort {
  const production = isProductionExitAuthority(exits);
  const assertLeases = async (profile: ProfileSnapshot, owner: OwnerLease | undefined, registry: RegistryLease | undefined) => {
    if (!owner || !registry || owner.profile !== profile || registry.state !== profile.paths.state || registry.platform !== platform)
      throw profileUnavailable();
    await registry.assert(); await owner.assert(); await assertProfile(profile);
  };
  const assertClosed = async (profile: ProfileSnapshot, owner?: OwnerLease, registry?: RegistryLease, purpose?: 'remove') => {
    const deadline = now() + 10000;
    if (production) await assertLeases(profile, owner, registry);
    const location = await runtimeLocation(profile), record = location ? await readRuntime(location) : undefined;
    if (record && originalAlive(record, platform)) throw profileUnavailable();
    if (isProductionExitAuthority(exits)) {
      if (purpose === 'remove') await exits.withdraw(profile, owner!, deadline);
      // The caller's genuine Owner remains held. Native inspects duplicates of
      // that exact description; no reacquisition/deadlock or lock-as-exit proof.
      for (;;) {
        try { await exits.assertClosedUnderOwner(profile, record, owner!, deadline); break; }
        catch { assertTime(deadline); if (purpose !== 'remove') throw profileUnavailable(); }
        await setTimeout(Math.min(10, Math.max(1, deadline - now())));
      }
      await assertLeases(profile, owner, registry);
    } else await exits.assertExited(profile, record, owner);
    if (!record) await assertNoSockets(profile);
    await assertProfile(profile);
    if (location && JSON.stringify(record) !== JSON.stringify(await readRuntime(location))) throw profileUnavailable();
    if (record && originalAlive(record, platform)) throw profileUnavailable();
  };
  return Object.freeze({ assertClosed,
    ...(isProductionExitAuthority(exits) ? {
      async detach(profile: ProfileSnapshot, owner: OwnerLease, registry: RegistryLease, retired: string) {
        await assertLeases(profile, owner, registry);
        return archiveRemovedRuntime(profile, owner, registry, platform, exits, now() + 10000, retired);
      },
    } : {}),
    async running(profile: ProfileSnapshot, ownerAvailable: boolean, owner?: OwnerLease, registry?: RegistryLease) {
      if (production && (!registry || registry.state !== profile.paths.state || registry.platform !== platform)) throw profileUnavailable();
      if (registry) await registry.assert();
      if (ownerAvailable) { await assertClosed(profile, owner, registry); return false; }
      if (owner) throw profileUnavailable();
      const location = await runtimeLocation(profile), record = location ? await readRuntime(location) : undefined;
      if (!location || !record || !originalAlive(record, platform)) throw profileUnavailable();
      const deadline = now() + 5000;
      if (isProductionExitAuthority(exits)) await assertProductionCloseReady(profile, record, selection, platform, exits, deadline);
      const client = await connectRuntime(location, record, 'management', { ...selection, explicit: false }, platform, deadline, 'Profile inspection');
      try {
        await registry?.assert(); await assertProfile(profile);
        if (JSON.stringify(record) !== JSON.stringify(await readRuntime(location)) || !originalAlive(record, platform)) throw profileUnavailable();
        return true;
      } finally { client.close(); }
    },
  });
}
async function verifiedGone(profile: ProfileSnapshot, original: RuntimeRecord, platform: PlatformPort,
  exits: ExitAuthority, deadline: number): Promise<boolean> {
  if (now() >= deadline) throw profileUnavailable();
  // Observe group even after main death, then require independent containment
  // authority covering all helpers. PID reuse is never a target for signalling.
  const group = platform.groupCensus(original.pid);
  await within(deadline, () => exits.assertCensus(profile, original, group));
  if (originalAlive(original, platform) || group.length) return false;
  await within(deadline, () => exits.assertExited(profile, original));
  await within(deadline, () => assertProfile(profile));
  if (now() >= deadline) throw profileUnavailable();
  return !originalAlive(original, platform) && platform.groupCensus(original.pid).length === 0;
}
interface CommandClose {
  readonly native: import('./platform.js').CloseBudget; readonly deadline: number; readonly grace: number;
}
function receiveClose(platform: PlatformPort): CommandClose {
  const sampled = now(), native = platform.captureCloseBudget(), clock = platform.continuousTime();
  return Object.freeze({ native, deadline: sampled + Math.max(0, native.overall - clock),
    grace: sampled + Math.max(0, native.grace - clock) });
}
async function closeProductionProfile(profile: ProfileSnapshot, selection: BuildSelection, platform: PlatformPort,
  exits: ProductionExitAuthority, command: CommandClose): Promise<Contract<'wire.CloseResult'>> {
  const { deadline, grace } = command;
  const location = await within(deadline, () => runtimeLocation(profile));
  let original = location ? await within(deadline, () => readRuntime(location)) : undefined;
  if (!original) {
    // Withdraw while the genuine external Owner excludes data access. A late
    // already-attached original must still produce authentic no-use evidence
    // and disappear; cancellation itself is never a successful close.
    while (now() < deadline) {
      const owner = await acquireWithin(deadline, () => ownerLock(profile, platform, false, deadline), value => value?.release());
      if (owner) try {
        await exits.withdraw(profile, owner, deadline);
        await exits.assertClosedUnderOwner(profile, undefined, owner, deadline);
        await owner.assert(); await assertNoSockets(profile); await assertProfile(profile);
        if (location && await readRuntime(location)) throw profileUnavailable();
        assertTime(deadline); return { profile: profile.record.id, closed: false, dataRemoved: false };
      } catch { assertTime(deadline); }
      finally { owner.release(); }
      await setTimeout(Math.min(10, Math.max(1, deadline - now())));
    }
    throw profileUnavailable();
  }
  if (selection.explicit && original.build !== selection.build && originalAlive(original, platform)) throw profileUnavailable();
  while (original.phase === 'starting' && originalAlive(original, platform) && now() < grace) {
    await setTimeout(Math.min(10, Math.max(1, grace - now())));
    const observed = location ? await within(grace, () => readRuntime(location)) : undefined;
    if (!originalAlive(original, platform)) break;
    if (!observed || (['instance', 'nonce', 'pid', 'processStartId', 'profile', 'profileInstance', 'profilePathHash', 'build',
        'agentSocket', 'managementSocket'] as const).some(key => observed[key] !== original![key])) throw profileUnavailable();
    original = observed;
  }
  if (await exits.tryClosed(profile, original, deadline)) return { profile: profile.record.id, closed: false, dataRemoved: false };
  let requested = false;
  if (originalAlive(original, platform) && original.phase === 'ready' && location && now() < grace) {
    await within(grace, () => assertProductionCloseReady(profile, original, selection, platform, exits, grace));
    const client = await acquireWithin(grace,
      () => connectRuntime(location, original, 'management', selection, platform, grace, 'Explicit close'), value => value.close());
    try {
      const observed = await requestManagementClose(client, command.native, grace);
      if (observed.kind === 'refused') throw observed.error;
      if (observed.kind === 'malformed') throw unavailable('browser');
      if (observed.kind === 'lost' && (!observed.stamped || !observed.written)) throw unavailable('browser');
      requested = true; // ordinary ACK or separately classified genuine loss only
    } finally { client.close(); }
  }
  // In-flight native custody, including main-already-dead, is pending until the
  // independent exact complete family/marker inspection passes. No PID signals.
  while (now() < deadline) {
    if (await exits.tryClosed(profile, original, deadline))
      return { profile: profile.record.id, closed: requested, dataRemoved: false };
    await setTimeout(Math.min(10, Math.max(1, deadline - now())));
  }
  throw profileUnavailable();
}
export async function closeProfile(profile: ProfileSnapshot, selection: BuildSelection, platform: PlatformPort,
  exits: ExitAuthority | undefined, deadline = now() + 8000): Promise<Contract<'wire.CloseResult'>> {
  if (isProductionExitAuthority(exits)) {
    const command = receiveClose(platform);
    try { return await closeProductionProfile(profile, selection, platform, exits, command); }
    finally { await platform.retireCloseBudget(command.native); }
  }
  const graceful = deadline - 3000;
  const location = await within(deadline, () => runtimeLocation(profile));
  const original = location ? await within(deadline, () => readRuntime(location)) : undefined;
  if (!original) {
    const owner = await acquireWithin(deadline, () => ownerLock(profile, platform, false, deadline), owner => owner?.release());
    if (!owner) throw profileUnavailable();
    try {
      await within(deadline, () => createProfileRuntime(platform, selection, exits ?? neverOpenedExit).assertClosed(profile));
      await within(deadline, () => owner.assert()); return { profile: profile.record.id, closed: false, dataRemoved: false };
    } finally { owner.release(); }
  }
  if (originalAlive(original, platform) && selection.explicit && original.build !== selection.build) throw profileUnavailable();
  if (!exits) throw unavailable('browser');
  if (!originalAlive(original, platform)) {
    const owner = await acquireWithin(deadline, () => ownerLock(profile, platform, false, deadline), owner => owner?.release());
    if (!owner) throw profileUnavailable();
    try {
      if (await verifiedGone(profile, original, platform, exits, deadline)) {
        await within(deadline, () => owner.assert());
        if (!location || JSON.stringify(await within(deadline, () => readRuntime(location))) !== JSON.stringify(original))
          throw profileUnavailable();
        return { profile: profile.record.id, closed: false, dataRemoved: false };
      }
    } finally { owner.release(); }
  }
  let client: RuntimeClient | undefined;
  try {
    if (originalAlive(original, platform) && original.phase === 'ready' && location) {
      client = await acquireWithin(graceful,
        () => connectRuntime(location, original, 'management', selection, platform, graceful, 'Explicit close'), client => client.close());
      // This result acknowledges shutdown only. Never forward it as CLI success.
      await client.call({ wire: 1, id: token('req'), method: 'close', params: {} }, graceful);
    }
  } catch { /* Lost acknowledgement may succeed only after complete verified exit. */ }
  finally { client?.close(); }
  while (now() < graceful) {
    if (await verifiedGone(profile, original, platform, exits, deadline)) return { profile: profile.record.id, closed: true, dataRemoved: false };
    await setTimeout(Math.min(25, Math.max(1, graceful - now())));
  }
  if (!await verifiedGone(profile, original, platform, exits, deadline)) await within(deadline, () => exits.force(profile, original, deadline));
  while (now() < deadline) {
    if (await verifiedGone(profile, original, platform, exits, deadline)) return { profile: profile.record.id, closed: true, dataRemoved: false };
    await setTimeout(Math.min(25, Math.max(1, deadline - now())));
  }
  throw profileUnavailable();
}
export interface ProcessIntegration {
  assertAdmissionAvailable(deadline?: number): Promise<void>;
  start(profile: ProfileSnapshot, endpoint: Endpoint, deadline: number, contentionDeadline: number, label?: string): Promise<{
    client: RuntimeClient; record: RuntimeRecord; alreadyRunning: boolean;
  }>;
  /** Later MCP stage supplies protocol/SDK handling. It may connect once after
   * initialize and must never retry buffered calls across transport loss. */
  mcp(connect: (label: string) => Promise<RuntimeClient>, io: Stdio): Promise<void>;
}
export function createProcessService(options: { selection: BuildSelection; platform: () => PlatformPort;
  state?: string; integration?: ProcessIntegration; exits?: ExitAuthority; observation?: OpenCommandObservation }): ProcessPort {
  const state = options.state ?? stateDirectory();
  return Object.freeze<ProcessPort>({
    async open(input) {
      const integration = options.integration;
      if (!integration) return preflightPageAdmission();
      const deadline = startupDeadline(), contentionDeadline = Math.min(deadline, now() + 10000);
      noteOpenCommand(options.observation, 'open-dispatch-admission-trust');
      await within(deadline, () => integration.assertAdmissionAvailable(deadline));
      noteOpenCommand(options.observation, 'open-profile-selection');
      const profile = await within(deadline, () => selectProfile(input.profile, options.platform(), { state, createDefault: true, deadline: contentionDeadline }));
      noteOpenCommand(options.observation, 'open-current-signed-start');
      const attached = await acquireWithin(deadline,
        () => integration.start(profile, 'management', deadline, contentionDeadline), result => result.client.close());
      try {
        noteOpenCommand(options.observation, 'open-reply');
        const result = await attached.client.call({ wire: 1, id: token('req'), method: 'open',
          params: input.url === undefined ? {} : { url: input.url } }, Math.min(deadline, now() + 15000)) as Contract<'wire.OpenResult'>;
        noteOpenCommand(options.observation, 'open-reply-validation');
        if (result.instance !== attached.record.instance || result.process !== attached.record.pid || result.profile !== profile.record.id)
          throw unavailable('browser');
        return { ...result, alreadyRunning: attached.alreadyRunning };
      } finally { attached.client.close(); }
    },
    async close(id) {
      const platform = options.platform(), production = isProductionExitAuthority(options.exits);
      // Capture the original native +5/+8 budget before the first await,
      // including profile selection. Receiver work cannot renew that budget.
      const command = production ? receiveClose(platform) : undefined, deadline = command?.deadline ?? now() + 8000;
      try {
        let profile: ProfileSnapshot;
        try { profile = await within(deadline, () => selectProfile(id, platform, { state })); }
        catch (error) {
          if (id === 'default' && error instanceof BrowserFailure && error.detail.code === 'profile_not_found')
            return { profile: id, closed: false, dataRemoved: false };
          throw error;
        }
        if (command && isProductionExitAuthority(options.exits))
          return await closeProductionProfile(profile, options.selection, platform, options.exits, command);
        return await closeProfile(profile, options.selection, platform, options.exits, deadline);
      } finally { if (command) await platform.retireCloseBudget(command.native); }
    },
    async mcp(id, io) {
      const integration = options.integration;
      if (!integration) throw unavailable('browser');
      let attempted = false, client: RuntimeClient | undefined, disconnected = false;
      const stop = () => { disconnected = true; client?.close(); };
      io.stdin.once('end', stop); io.stdin.once('close', stop); io.stdin.once('error', stop);
      try {
        await integration.mcp(async label => {
          if (attempted || disconnected) throw unavailable('browser');
          attempted = true;
          const deadline = startupDeadline(), contentionDeadline = Math.min(deadline, now() + 10000);
          await within(deadline, () => integration.assertAdmissionAvailable(deadline));
          const profile = await within(deadline, () => selectProfile(id, options.platform(), { state, createDefault: true, deadline: contentionDeadline }));
          client = (await acquireWithin(deadline,
            () => integration.start(profile, 'agent', deadline, contentionDeadline, label), result => result.client.close())).client;
          if (disconnected) { client.close(); throw unavailable('browser'); }
          return client;
        }, io);
      } finally {
        stop(); io.stdin.removeListener('end', stop); io.stdin.removeListener('close', stop); io.stdin.removeListener('error', stop);
      }
    },
  });
}

export interface HostControlPort {
  assertPrepared(): void;
  /** Only actual lifecycle-ready may open operations and show prepared shells. */
  openAdmission(): void;
  /** Must synchronously invalidate ALL content, grants and admission. */
  closeAdmission(): void;
  disconnect(attachment: string): void;
  /** One concurrent all-tab cleanup, including drain/retire and destroyed proof. */
  settleDisconnect(attachment: string, deadline: number): Promise<void>;
  retireAll(deadline: number): Promise<void>;
  windowCount(): number;
}
export interface HostLifecycle {
  readonly phase: 'starting' | 'ready' | 'closing' | 'fatal';
  fatal(): void;
  ready(): Promise<void>;
  assertAdmission(): void;
  disconnect(context: ConnectionContext): void;
  close(): Promise<void>;
  beginManagementClose(context: ConnectionContext, request: Extract<Request, { method: 'close' }>): Readonly<{
    opportunity: ManagementCloseOpportunity; finished(): void;
  }>;
  lastWindowClosed(): void;
}
const hostLifecycles = new WeakSet<object>();
export function assertHostLifecycle(value: HostLifecycle): void {
  if (!hostLifecycles.has(value)) throw unavailable('browser');
}
/** Canonical host-only dynamic boundary: never import Electron through the Node
 * CLI static graph. No provider, profile or native capability is defaulted. */
export async function prepareOwnershipControl(boundary: import('./bootstrap.js').NativeFailureBoundary,
  documents: import('../host/authority.js').DocumentAuthority, operations: import('../host/handoff.js').OwnershipOperations,
  custody: import('./custody.js').HostCustody, deadline: number): Promise<import('../host/handoff.js').OwnershipHost> {
  const address = new URL('../host/handoff.js', import.meta.url).href;
  const host = await import(address) as typeof import('../host/handoff.js');
  const custodyURL = new URL('./custody.js', import.meta.url).href;
  const proofs = await import(custodyURL) as typeof import('./custody.js');
  const proof = await proofs.prepareArmedHostSnapshot(custody, boundary.native.trust, 'ownership', documents, deadline);
  return host.createOwnershipHost(boundary, documents, operations, proof, documents);
}
export interface HostNativeLifetime {
  /** Validate the already acknowledged native custody receipt against this exact
   * preparation; ABR-7 provides the primitive, ABR-29 the actual handle assembly. */
  armRetainedLifetime(prepared: HostPreparation): Promise<void>;
  assertReady(): Promise<void>;
  /** Stop watchdog renewal synchronously before any possibly blocking cleanup. */
  quarantine(): void;
  /** Exit is owned by the independently armed native path, retaining guards.
   * A bare Electron quit event is neither flush nor complete-exit evidence. */
  exit(deadline: number): Promise<void>;
}
/** One authoritative host; no automatic restart and no saved action/lease state. */
export function createHostLifecycle(prepared: HostPreparation, sessions: ProfileSessions, transport: TransportServer,
  control: HostControlPort, native: HostNativeLifetime, productionDeadline?: number, productionPlatform?: PlatformPort): HostLifecycle {
  const production = isHostCustody(prepared.custody);
  if (production && (productionDeadline === undefined || !Number.isFinite(productionDeadline) || now() >= productionDeadline))
    return prepared.custody.terminate();
  if (production) { if (!productionPlatform) return prepared.custody.terminate(); assertPlatform(productionPlatform); }
  if (!production && productionDeadline !== undefined) throw unavailable('browser');
  let phase: 'starting' | 'ready' | 'closing' | 'fatal' = 'starting';
  let admitted = false;
  let closing: Promise<void> | undefined;
  let arming: Promise<void> | undefined, readyPublication: Promise<void> | undefined;
  let readyAttempt: Promise<void> | undefined;
  const pending = new Set<Promise<void>>();
  const disconnected = new WeakSet<ConnectionContext>();
  const currentPhase = (): HostLifecycle['phase'] => phase;
  const arm = () => arming ??= Promise.resolve().then(() => native.armRetainedLifetime(prepared));
  function synchronous(work: () => void): void { const result: unknown = work(); if (result !== undefined) throw unavailable('browser'); }
  function closeAdmission() { admitted = false; synchronous(() => control.closeAdmission()); synchronous(() => transport.closeAdmission()); }
  function fatal(): void {
    if (phase === 'fatal') return;
    phase = 'fatal'; admitted = false;
    // Independent fatal enforcement comes first, even when control cleanup throws.
    try { native.quarantine(); } finally {
      try { synchronous(() => control.closeAdmission()); } finally { synchronous(() => transport.closeAdmission()); }
    }
  }
  const witness = production ? productionSessionShutdown(sessions, prepared.custody) : undefined;
  const shutdown = (opportunity?: ManagementCloseOpportunity, acknowledgement?: Promise<void>) => {
    if (closing) return closing;
    if (phase === 'fatal') return Promise.reject(unavailable('browser'));
    let deadline = now() + 8000, grace = deadline - 3000;
    if (production) {
      try {
        if (opportunity) { deadline = opportunity.deadline; grace = opportunity.grace; }
        else {
          const sampled = now(), nativeNow = productionPlatform!.continuousTime(), admitted = prepared.custody.localClose();
          deadline = sampled + Math.max(0, admitted.overall - nativeNow);
          grace = sampled + Math.max(0, admitted.grace - nativeNow);
        }
      } catch (error) { fatal(); return Promise.reject(error); }
    }
    let resolve!: () => void, reject!: (error: unknown) => void;
    const result = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
    closing = result; // before close/revoke/window callbacks may reenter
    phase = 'closing';
    // Close admission synchronously before the first await or queue operation.
    try { closeAdmission(); } catch (error) { try { fatal(); } finally { reject(error); } return result; }
    void (async () => {
      const timer = globalThis.setTimeout(() => { try { fatal(); } catch { /* native already armed */ } }, Math.max(1, grace - now()));
      try {
        // A genuine still-starting abandonment never publishes ready. Both
        // paths retain the same actual custody and arm native lifetime once.
        if (acknowledgement) await acknowledgement;
        await arm();
        if (readyPublication) await readyPublication;
        await prepared.instance.phase('closing');
        await Promise.all([control.retireAll(grace), ...pending]);
        witness?.pagesRetired();
        await sessions.flushStorage(); // necessary; explicitly insufficient to mark clean
        await prepared.instance.owner.assert(); await prepared.buildGuard.assert();
        await transport.close();
        await native.exit(deadline);
        // A returning exit port is not verified engine/helper disappearance.
        throw unavailable('browser');
        // Never release owner/Build or call completeExit from a window/quit event.
      } catch (error) { fatal(); throw error; }
      finally { clearTimeout(timer); }
    })().then(resolve, reject);
    return result;
  };
  const ready = (): Promise<void> => {
    if (readyAttempt) return readyAttempt;
    if (phase !== 'starting') return Promise.reject(unavailable('browser'));
    let resolve!: () => void, reject!: (error: unknown) => void;
    const result = new Promise<void>((yes, no) => { resolve = yes; reject = no; }); readyAttempt = result;
    void (async () => {
      try {
      if (phase !== 'starting' || control.windowCount() < 1) throw unavailable('browser');
      synchronous(() => control.assertPrepared());
      await arm(); if (phase !== 'starting') throw unavailable('browser');
      await native.assertReady(); if (phase !== 'starting') throw unavailable('browser');
      await prepared.engine.assertReady(); if (phase !== 'starting') throw unavailable('browser');
      await prepared.buildGuard.assert();
      if (phase !== 'starting') throw unavailable('browser');
      await prepared.instance.owner.assert();
      if (phase !== 'starting') throw unavailable('browser');
      // Real ready proofs have completed. Serialize its publication with any
      // later normal close so phase writes cannot race or resurrect readiness.
      phase = 'ready'; readyPublication = prepared.instance.phase('ready'); await readyPublication;
      if (phase !== 'ready') throw unavailable('browser');
      if (production) {
        if (productionDeadline === undefined) return prepared.custody.terminate();
        assertTime(productionDeadline);
        await prepared.custody.host.assertTrusted(productionDeadline);
        const generation = prepared.instance.record;
        const guard = () => {
          assertTime(productionDeadline);
          if (phase !== 'ready' || prepared.instance.record !== generation) return prepared.custody.terminate();
          prepared.custody.assertRetained();
        };
        guard(); openProtectedReady(transport, prepared.custody, generation, guard, () => control.openAdmission());
        admitted = true;
      } else {
        // Explicit Foundation infrastructure retains its existing contract.
        synchronous(() => control.openAdmission());
        if (phase !== 'ready') throw unavailable('browser');
        synchronous(() => transport.openAdmission()); admitted = true;
      }
      } catch (error) { if (currentPhase() !== 'closing') fatal(); throw error; }
    })().then(resolve, reject);
    return result;
  };
  const lifecycle: HostLifecycle = Object.freeze({
    get phase() { return phase; }, fatal, ready,
    assertAdmission() { if (phase !== 'ready' || !admitted) throw unavailable('browser'); },
    disconnect(context: ConnectionContext) {
      if (!context.attachment) return;
      if (disconnected.has(context)) return; disconnected.add(context);
      const id = context.attachment.id;
      try { synchronous(() => control.disconnect(id)); } catch { fatal(); return; }
      const deadline = now() + 6000;
      const timer = globalThis.setTimeout(() => { try { fatal(); } catch { /* native already armed */ } }, 6000);
      const cleanup = Promise.resolve().then(() => control.settleDisconnect(id, deadline));
      pending.add(cleanup);
      void cleanup.catch(() => fatal()).finally(() => { clearTimeout(timer); pending.delete(cleanup); }).catch(() => {});
    },
    close: () => shutdown(),
    beginManagementClose(context: ConnectionContext, request: Extract<Request, { method: 'close' }>) {
      if (!production || phase !== 'ready' || !admitted || closing) throw unavailable('browser');
      const opportunity = reserveManagementClose(context, request, socket => prepared.custody.consumeClose(request.id, socket));
      let finish!: () => void, finished = false;
      const acknowledgement = new Promise<void>(resolve => { finish = resolve; });
      // shutdown fences synchronously. Its first await is this exact writer's
      // barrier; no ordinary dispatch can intervene before the one ACK attempt.
      void shutdown(opportunity, acknowledgement).catch(() => {});
      return Object.freeze({ opportunity, finished() { if (!finished) { finished = true; finish(); } } });
    },
    lastWindowClosed() { if (control.windowCount() === 0) void shutdown().catch(() => {}); },
  });
  hostLifecycles.add(lifecycle); return lifecycle;
}
