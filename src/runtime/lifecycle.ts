import { assertHostStartupSnapshot, noteOpenCommand, type OpenCommandObservation, type VerifiedHost } from './authorities.js';
import { setTimeout } from 'node:timers/promises';
import type { Contract } from '../contracts/generated.js';
import { unavailable, BrowserFailure } from '../contracts/errors.js';
import { nativeLifetimeReadiness, preflightPageAdmission } from './bootstrap.js';
import { assertAdoptedBuildClosing } from './build-lease.js';
import { assertSharedProfileRuntime, noteHostStartup, isHostCustody, type SharedProfileRuntime } from './custody.js';
import { isProductionExitAuthority, type ProductionExitAuthority } from './exit.js';
import { archiveRemovedRuntime, assertProductionCloseReady } from './process.js';
import { assertPlatform, type PlatformPort, type GroupProcess } from './platform.js';
import type { BuildSelection } from './selection.js';
import { admitSeqoyaCapture, requestManagementClose, requestSeqoyaUsage, reserveManagementClose, openProtectedReady,
  openSharedProtectedReady, connectRuntime, type Request, type ManagementCloseOpportunity, type RuntimeClient,
  type Endpoint, type TransportServer, type ConnectionContext } from './transport.js';
import { runtimeLocation, readRuntime, originalAlive, now, startupDeadline, neverOpenedExit,
  token, assertTime, type RuntimeRecord, type PreviousExit } from './instance.js';
import { assertProfile, type ProfileSnapshot } from '../profiles/records.js';
import { profileUnavailable, statOrAbsent, stateDirectory } from '../profiles/paths.js';
import { selectProfile } from '../profiles/create.js';
import { ownerLock, type OwnerLease, type RegistryLease } from '../profiles/locking.js';
import type { ProfileRuntimePort } from '../profiles/manage.js';
import type { ProcessPort } from './ports.js';
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
  exits: PreviousExit = neverOpenedExit, listingHost?: VerifiedHost): ProfileRuntimePort {
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
      if (isProductionExitAuthority(exits)) await assertProductionCloseReady(profile, record, selection, platform, exits, deadline, listingHost);
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
  exits: ProductionExitAuthority, command: CommandClose, closeHost?: VerifiedHost): Promise<Contract<'wire.CloseResult'>> {
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
    await within(grace, () => assertProductionCloseReady(profile, original, selection, platform, exits, grace, closeHost));
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
    if (await exits.tryClosed(profile, original, deadline, requested ? closeHost : undefined))
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
  start(profile: ProfileSnapshot, endpoint: Endpoint, deadline: number, contentionDeadline: number,
    label?: string, signal?: AbortSignal, showEmptyWhenReady?: boolean): Promise<{
    client: RuntimeClient; record: RuntimeRecord; alreadyRunning: boolean;
  }>;
}
export function createProcessService(options: { selection: BuildSelection; platform: () => PlatformPort;
  state?: string; integration?: ProcessIntegration; exits?: ExitAuthority; closeHost?: VerifiedHost;
  observation?: OpenCommandObservation; openCutoff?: number }): ProcessPort {
  const state = options.state ?? stateDirectory();
  return Object.freeze<ProcessPort>({
    async open(input) {
      const integration = options.integration;
      if (!integration) return preflightPageAdmission();
      const deadline = Math.min(startupDeadline(), options.openCutoff ?? Infinity), contentionDeadline = Math.min(deadline, now() + 10000);
      if (!Number.isFinite(deadline)) throw unavailable('browser');
      noteOpenCommand(options.observation, 'open-dispatch-admission-trust');
      await within(deadline, () => integration.assertAdmissionAvailable(deadline));
      noteOpenCommand(options.observation, 'open-profile-selection');
      const profile = await within(deadline, () => selectProfile(input.profile, options.platform(),
        { state, createDefault: input.profileInstance === undefined, deadline: contentionDeadline }));
      if ((input.profileInstance !== undefined && profile.record.instance !== input.profileInstance) ||
          (input.creationRequest !== undefined && (input.profileInstance === undefined ||
            profile.record.creationRequest !== input.creationRequest))) throw profileUnavailable();
      noteOpenCommand(options.observation, 'open-current-signed-start');
      if (input.approve && (input.url === undefined || input.profileInstance === undefined ||
          input.creationRequest === undefined)) throw profileUnavailable();
      const attached = await acquireWithin(deadline,
        () => integration.start(profile, 'management', deadline, contentionDeadline, undefined, undefined,
          input.approve !== undefined), result => result.client.close());
      try {
        if (input.profileInstance !== undefined && attached.record.profileInstance !== input.profileInstance) throw profileUnavailable();
        noteOpenCommand(options.observation, 'open-reply');
        const requestOpen = async (params: Extract<Request, { method: 'open' }>['params']) => {
          const result = await attached.client.call({ wire: 1, id: token('req'), method: 'open', params },
            Math.min(deadline, now() + 15000)) as Contract<'wire.OpenResult'>;
          if (result.instance !== attached.record.instance || result.process !== attached.record.pid ||
              result.profile !== profile.record.id) throw unavailable('browser');
          return result;
        };
        if (input.approve) {
          await requestOpen({ showEmpty: true });
          await input.approve(deadline);
          assertTime(deadline);
        }
        const result = await requestOpen(input.url === undefined ? {} : { url: input.url });
        noteOpenCommand(options.observation, 'open-reply-validation');
        assertTime(deadline); return { ...result, alreadyRunning: attached.alreadyRunning };
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
          return await closeProductionProfile(profile, options.selection, platform, options.exits, command, options.closeHost);
        return await closeProfile(profile, options.selection, platform, options.exits, deadline);
      } finally { if (command) await platform.retireCloseBudget(command.native); }
    },
    async captureSeqoya(input) {
      const integration = options.integration;
      if (!integration) throw unavailable('browser');
      const deadline = Math.min(input.deadline, options.openCutoff ?? Infinity);
      const contentionDeadline = Math.min(deadline, now() + 10_000);
      assertTime(deadline);
      await integration.assertAdmissionAvailable(deadline);
      const platform = options.platform();
      const scope = { provider: input.provider, claim: input.claim };
      await admitSeqoyaCapture(platform, input, scope, deadline, 'check');
      const profile = await selectProfile(input.profile, platform, { state, deadline: contentionDeadline });
      if (profile.record.instance !== input.profileInstance) throw profileUnavailable();
      const { client, record } = await acquireWithin(deadline, () => integration.start(profile, 'management',
        deadline, contentionDeadline), result => result.client.close());
      try {
        if (record.profileInstance !== input.profileInstance || client.hello.profileInstance !== input.profileInstance)
          throw profileUnavailable();
        return await requestSeqoyaUsage(client, scope, deadline);
      } finally { client.close(); }
    },
    async attachAgent(input) {
      const integration = options.integration;
      if (!integration) return preflightPageAdmission();
      const deadline = Math.min(input.deadline, options.openCutoff ?? Infinity);
      const contentionDeadline = Math.min(deadline, now() + 10000);
      const current = () => {
        if (input.signal.aborted || !Number.isFinite(deadline)) throw unavailable('browser');
        assertTime(deadline);
      };
      current();
      await integration.assertAdmissionAvailable(deadline); current();
      const profile = await selectProfile(input.profile, options.platform(),
        { state, createDefault: true, deadline: contentionDeadline, signal: input.signal });
      current();
      const { client, record } = await integration.start(profile, 'agent', deadline, contentionDeadline, input.label, input.signal);
      try {
        current();
        const hello = client.hello;
        if (client.signal.aborted || !hello.attachment || record.profile !== profile.record.id ||
            record.profileInstance !== profile.record.instance || hello.profile !== record.profile ||
            hello.profileInstance !== record.profileInstance || hello.instance !== record.instance ||
            hello.nonce !== record.nonce || hello.build !== record.build ||
            (options.selection.explicit && record.build !== options.selection.build)) throw unavailable('browser');
        return client;
      } catch (error) { client.close(); throw error; }
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
function trackHostDisconnections(control: HostControlPort, fatal: () => void) {
  const pending = new Set<Promise<void>>();
  const disconnected = new WeakSet<ConnectionContext>();
  return {
    pending,
    disconnect(context: ConnectionContext) {
      if (!context.attachment || disconnected.has(context)) return;
      disconnected.add(context);
      const id = context.attachment.id;
      try {
        const result: unknown = control.disconnect(id);
        if (result !== undefined) throw unavailable('browser');
      } catch { fatal(); return; }
      const deadline = now() + 6000;
      const timer = globalThis.setTimeout(() => { try { fatal(); } catch { /* admission is fenced */ } }, 6000);
      const cleanup = Promise.resolve().then(() => control.settleDisconnect(id, deadline));
      pending.add(cleanup);
      void cleanup.catch(() => fatal()).finally(() => { clearTimeout(timer); pending.delete(cleanup); }).catch(() => {});
    },
  };
}

export interface SharedProfileLifecycle extends HostLifecycle {
  fence(): void;
  retire(deadline: number): Promise<void>;
}
export function createSharedProfileLifecycle(profile: SharedProfileRuntime, transport: TransportServer,
  control: HostControlPort, deadline: number): SharedProfileLifecycle {
  const primary = assertSharedProfileRuntime(profile);
  const { instance, sessions } = profile;
  let phase: HostLifecycle['phase'] = 'starting', admitted = false;
  let starting: Promise<void> | undefined, publication: Promise<void> | undefined, retirement: Promise<void> | undefined;
  const phaseNow = () => phase;
  const seal = () => {
    admitted = false;
    try { control.closeAdmission(); } finally { transport.closeAdmission(); }
  };
  function fatal() {
    if (phase === 'fatal') return;
    phase = 'fatal'; seal();
  }
  const disconnections = trackHostDisconnections(control, fatal);
  function fence() {
    if (phase === 'closing' || phase === 'fatal') return;
    phase = 'closing'; seal();
  }
  const retire = (limit: number) => {
    fence();
    return retirement ??= within(limit, async () => {
      const publishClosing = async () => {
        // A refused ready write must not prevent the target's cleanup.
        await publication?.catch(() => {});
        if (instance.record.phase !== 'closing') await instance.phase('closing');
      };
      const retirePages = async () => {
        await Promise.all([control.retireAll(limit), ...disconnections.pending]);
        await sessions.flushStorage();
        await instance.owner.assert();
      };
      const results = await Promise.allSettled([publishClosing(), retirePages(), transport.close()]);
      for (const result of results) if (result.status === 'rejected') throw result.reason;
      // Electron retains this Session. Native custody retains its Owner
      // until the whole original process family has ceased using the data.
    });
  };
  const lifecycle: SharedProfileLifecycle = Object.freeze({
    get phase() { return phase; }, fatal, disconnect: disconnections.disconnect, fence, retire,
    ready() {
      return starting ??= Promise.resolve().then(async () => {
        try {
          const beforePublication = () => {
            assertTime(deadline);
            if (phase !== 'starting' || primary.instance.record.phase !== 'ready') throw unavailable('profile');
            assertSharedProfileRuntime(profile);
          };
          beforePublication(); control.assertPrepared();
          if (control.windowCount() < 1 || instance.record.phase !== 'starting') throw unavailable('profile');
          await profile.engine.assertReady(); await instance.owner.assert();
          beforePublication(); publication = instance.phase('ready'); await publication;
          beforePublication();
          const generation = instance.record;
          phase = 'ready';
          const guard = () => {
            assertTime(deadline);
            if (phase !== 'ready' || instance.record !== generation || primary.instance.record.phase !== 'ready')
              throw unavailable('profile');
            assertSharedProfileRuntime(profile);
          };
          openSharedProtectedReady(transport, profile, guard, () => control.openAdmission());
          admitted = true;
        } catch (error) { if (phaseNow() !== 'closing') fatal(); throw error; }
      });
    },
    assertAdmission() {
      if (phase !== 'ready' || !admitted || primary.instance.record.phase !== 'ready') throw unavailable('profile');
      assertSharedProfileRuntime(profile);
    },
    close: () => retire(now() + 5000),
    beginManagementClose() { throw unavailable('profile'); },
    lastWindowClosed() { if (control.windowCount() === 0) void retire(now() + 5000).catch(() => fatal()); },
  });
  hostLifecycles.add(lifecycle); return lifecycle;
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
export interface HostLifetimeStartup {
  readonly deadline: number;
  stillStarting(): boolean;
}
export interface HostNativeLifetime {
  /** Validate the already acknowledged native custody receipt against this exact
   * preparation; ABR-7 provides the primitive, ABR-29 the actual handle assembly. */
  armRetainedLifetime(prepared: HostPreparation, startup?: HostLifetimeStartup): Promise<void>;
  assertReady(): Promise<void>;
  /** Stop watchdog renewal synchronously before any possibly blocking cleanup. */
  quarantine(): void;
  /** Exit is owned by the independently armed native path, retaining guards.
   * A bare Electron quit event is neither flush nor complete-exit evidence. */
  exit(deadline: number, closeGrace?: number): Promise<void>;
}
/** One authoritative host; no automatic restart and no saved action/lease state. */
export function createHostLifecycle(prepared: HostPreparation, sessions: ProfileSessions, transport: TransportServer,
  control: HostControlPort, native: HostNativeLifetime, productionDeadline?: number, productionPlatform?: PlatformPort,
  additional?: Readonly<{ fence(): void; retire(deadline: number): Promise<void> }>): HostLifecycle {
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
  const currentPhase = (): HostLifecycle['phase'] => phase;
  const arm = (startup = false) => arming ??= Promise.resolve().then(() => {
    if (!startup || phase !== 'starting' || productionDeadline === undefined) return native.armRetainedLifetime(prepared);
    return native.armRetainedLifetime(prepared, { deadline: productionDeadline, stillStarting: () => phase === 'starting' });
  });
  function synchronous(work: () => void): void { const result: unknown = work(); if (result !== undefined) throw unavailable('browser'); }
  function closeAdmission() {
    admitted = false;
    try { synchronous(() => additional?.fence()); }
    finally { try { synchronous(() => control.closeAdmission()); } finally { synchronous(() => transport.closeAdmission()); } }
  }
  function fatal(): void {
    if (phase === 'fatal') return;
    phase = 'fatal'; admitted = false;
    // Independent fatal enforcement comes first, even when control cleanup throws.
    try { native.quarantine(); } finally { closeAdmission(); }
  }
  const disconnections = trackHostDisconnections(control, fatal);
  const witness = production ? productionSessionShutdown(sessions, prepared.custody) : undefined;
  const shutdown = (opportunity?: ManagementCloseOpportunity, acknowledgement?: Promise<void>) => {
    if (closing) return closing;
    if (phase === 'fatal') return Promise.reject(unavailable('browser'));
    const retainedClose = production && phase === 'ready' && admitted;
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
        await Promise.all([control.retireAll(grace), additional?.retire(grace), ...disconnections.pending]);
        witness?.pagesRetired();
        await sessions.flushStorage(); // necessary; explicitly insufficient to mark clean
        await prepared.instance.owner.assert();
        if (retainedClose) await assertAdoptedBuildClosing(prepared.buildGuard, prepared.custody.host, grace);
        else await prepared.buildGuard.assert();
        await transport.close();
        if (retainedClose) await native.exit(deadline, grace);
        else await native.exit(deadline);
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
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-control-proof-before');
      synchronous(() => control.assertPrepared());
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-control-proof-after');
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-arm-before');
      await arm(true);
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-arm-after'); if (phase !== 'starting') throw unavailable('browser');
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-readiness-prepare-before');
      const readyOnly = await nativeLifetimeReadiness(native, prepared);
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-readiness-prepare-after');
      if (phase !== 'starting') throw unavailable('browser');
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-native-proof-before');
      if (readyOnly) await readyOnly(); else await native.assertReady();
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-native-proof-after');
      if (phase !== 'starting') throw unavailable('browser');
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-engine-proof-before');
      await prepared.engine.assertReady();
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-engine-proof-after'); if (phase !== 'starting') throw unavailable('browser');
      if (!readyOnly) {
        noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-build-proof-before');
        await prepared.buildGuard.assert();
        noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-build-proof-after');
      }
      if (phase !== 'starting') throw unavailable('browser');
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-owner-proof-before');
      await prepared.instance.owner.assert();
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-owner-proof-after');
      if (phase !== 'starting') throw unavailable('browser');
      // Real ready proofs have completed. Serialize its publication with any
      // later normal close so phase writes cannot race or resurrect readiness.
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-public-ready-before');
      phase = 'ready'; readyPublication = prepared.instance.phase('ready'); await readyPublication;
      noteHostStartup(production ? prepared.custody : undefined, 'lifecycle-public-ready-after');
      if (phase !== 'ready') throw unavailable('browser');
      if (production) {
        if (productionDeadline === undefined) return prepared.custody.terminate();
        assertTime(productionDeadline);
        noteHostStartup(prepared.custody, 'lifecycle-final-trust-before');
        await assertHostStartupSnapshot(prepared.custody.host, productionDeadline);
        noteHostStartup(prepared.custody, 'lifecycle-final-trust-after');
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
    disconnect: disconnections.disconnect,
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
