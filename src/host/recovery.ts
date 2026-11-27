import type { ArmedHostSnapshot, HostCustody } from '../runtime/custody.js';
import type { ProfileSessions } from '../profiles/session.js';
import { webFrameMain, type WebContents } from 'electron';
import { performance } from 'node:perf_hooks';
import { setTimeout as pause } from 'node:timers/promises';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { BrowserFailure, unavailable } from '../contracts/errors.js';
import { assertNativeFailureBoundary, type NativeFailureBoundary } from '../runtime/bootstrap.js';
import { staleSnapshot, type RecoveryTransition } from './authority.js';
import { bounded, createOwnershipHost, type OwnershipHost } from './handoff.js';
import { HostCapabilities } from './capabilities.js';
import { createHostToolOperations, createInspectionTools, createTrustedActionTools, type HostToolOperation } from './tool-dispatch.js';
import { physicalFrames, HostDocuments, type HostDocument, type PhysicalFrame } from './documents.js';
import { RendererHealth, type RecoveryAttempt } from './health.js';
import { assertPageRetirement, type PageSurface, type WindowHost } from './windows.js';
import { PageReadiness } from './readiness.js';
import type { ShellRegistration } from './shell-ipc.js';
import { assertTabRegistry, refused, userURL, type TabRegistry, type TabTarget } from './tabs.js';

export interface RecoveryReport {
  readonly tab: string; readonly generation: number; readonly status: 'recovered' | 'failed';
  readonly stop: 'already-retired' | 'already-gone' | 'terminated' | 'unproved';
  readonly affectedTabs: readonly string[];
  readonly changedDuringStop: readonly string[];
  readonly frameEffects: readonly Readonly<{ tab: string; observed: 'unavailable' | 'replaced' | 'uncertain' }>[];
  readonly error?: string;
}
interface Job {
  active: boolean; controller: AbortController; transition: RecoveryTransition; attempt: RecoveryAttempt;
  original: PageSurface; replacement?: PageSurface; deadline: number; workDeadline: number;
  committed: boolean;
}
interface SharedCandidate { target: TabTarget; page: PageSurface; contents: WebContents; receipt: HostDocument; frames: readonly PhysicalFrame[] }
class RecoveryFailure extends BrowserFailure {
  constructor(readonly recoveryReason: string) {
    super({ code: 'control_refused', message: 'The page could not be recovered.', retryable: true,
      remedy: `Recovery stopped (${recoveryReason}). The original failure is retained. Unsaved page state may be lost; try another explicit recovery.` });
  }
}
function recoveryFailed(reason: string): RecoveryFailure { return new RecoveryFailure(reason); }
/** Explicit trusted-shell replacement only. No reload of an original page,
 * POST/history restoration, action retry or agent lease is implemented here. */
export class PageRecovery {
  private registry?: TabRegistry;
  private readonly pending = new Map<TabTarget, Job>();
  private readonly reports = new Map<TabTarget, RecoveryReport>();
  constructor(readonly host: OwnershipHost, readonly documents: HostDocuments, readonly health: RendererHealth,
    readonly commit: (transition: RecoveryTransition, receipt: HostDocument, assertCurrent: () => void) => void,
    readonly preparePage: (target: TabTarget, guard: () => void, transition?: RecoveryTransition) => Promise<() => void>) {
    assertNativeFailureBoundary(host.authority.boundary);
    if (host.authority.documents !== documents || health.documents !== documents || health.owner !== host.authority)
      throw refused('control_refused');
  }
  bind(registry: TabRegistry): void {
    assertTabRegistry(registry); if (this.registry && this.registry !== registry) throw refused('control_refused'); this.registry = registry;
  }
  private tabs(): TabRegistry { if (!this.registry) throw refused('control_refused'); assertTabRegistry(this.registry); return this.registry; }
  private native(): void { assertNativeFailureBoundary(this.host.authority.boundary); }
  report(target: TabTarget): RecoveryReport | undefined {
    if (this.host.authority.wasClosed(target)) return; return this.reports.get(target);
  }
  cancel(target: TabTarget): void {
    const job = this.pending.get(target);
    if (job) { job.active = false; job.controller.abort(); }
    if (this.host.authority.wasClosed(target)) this.reports.delete(target);
  }
  closeAll(): void { for (const target of this.pending.keys()) this.cancel(target); this.reports.clear(); }
  private async within<T>(deadline: number, guard: () => void, work: () => Promise<T>, expire: () => void): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      guard();
      if (performance.now() >= deadline) { expire(); throw recoveryFailed('timeout'); }
      const result = await Promise.race([work(), new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { expire(); reject(recoveryFailed('timeout')); }, Math.max(1, deadline - performance.now()));
      })]);
      guard(); if (performance.now() >= deadline) { expire(); throw recoveryFailed('timeout'); } return result;
    } finally { if (timer) clearTimeout(timer); }
  }
  private async retirement(page: PageSurface, deadline: number): Promise<void> {
    try {
      let receipt = page.retirement();
      if (!receipt) { const started = page.retire(); void started.catch(() => {}); receipt = page.retirement(); }
      if (!receipt) return this.host.authority.exhausted();
      assertPageRetirement(page, receipt);
      const retired = () => receipt.phase === 'retired';
      if (retired()) return;
      await bounded(deadline, () => receipt.completion);
      assertPageRetirement(page, receipt);
      if (!retired()) return this.host.authority.exhausted();
    } catch { return this.host.authority.exhausted(); }
  }
  private shared(renderer: HostDocument['renderer'], original: TabTarget): readonly SharedCandidate[] {
    const candidates: SharedCandidate[] = [];
    for (const target of this.tabs().all()) {
      if (target === original || target.page.retirement()) continue;
      const page = target.page, receipt = this.documents.originalReceipt(target, page);
      if (!receipt) continue;
      try {
        const frames = physicalFrames(page).filter(frame => frame.process === renderer.process && frame.osProcess === renderer.osProcess);
        if (frames.length) candidates.push({ target, page, receipt, frames, contents: this.documents.originalContents(target, page) });
      } catch { /* No invented renderer membership or ready proof. Its own health owns this absence. */ }
    }
    return candidates;
  }
  private async stop(job: Job, guard: () => void, changed: Set<string>, effects: { tab: string; observed: 'unavailable' | 'replaced' | 'uncertain' }[]): Promise<RecoveryReport['stop']> {
    const { original, transition, attempt } = job, target = transition.target;
    if (original.retirement()) {
      await this.retirement(original, Math.min(job.workDeadline, performance.now() + 1000)); guard(); return 'already-retired';
    }
    const contents = this.documents.originalContents(target, original);
    if (contents.isDestroyed()) return this.host.authority.exhausted(); // no authentic retirement is not destruction authority
    const gone = this.documents.stopped(target, original);
    if (gone && contents.isCrashed() && contents.getOSProcessId() === 0) return 'already-gone';
    if (contents.isCrashed() && contents.getOSProcessId() === 0) {
      const deadline = Math.min(job.workDeadline, performance.now() + 2000);
      for (;;) {
        guard();
        const proof = this.documents.stopped(target, original);
        if (proof && contents.isCrashed() && contents.getOSProcessId() === 0) return 'already-gone';
        if (performance.now() >= deadline) throw recoveryFailed('renderer_gone_unproved');
        await pause(Math.max(1, Math.min(10, deadline - performance.now())), undefined, { signal: job.controller.signal });
      }
    }
    const frames = physicalFrames(original), main = frames.find(frame => frame.handle.parent === null);
    if (!main || contents.getProcessId() !== main.process || contents.getOSProcessId() !== main.osProcess) throw recoveryFailed('renderer_identity');
    const renderer = Object.freeze({ process: main.process, osProcess: main.osProcess });
    const candidates = this.shared(renderer, target), listeners: (() => void)[] = [];
    const affected = (candidate: SharedCandidate) => {
      if (this.host.authority.wasClosed(candidate.target) || candidate.target.page !== candidate.page) return;
      if (candidate.receipt.renderer.process !== renderer.process || candidate.receipt.renderer.osProcess !== renderer.osProcess ||
          this.documents.originalReceipt(candidate.target, candidate.page) !== candidate.receipt || candidate.contents.isDestroyed() ||
          !candidate.contents.isCrashed() || candidate.contents.getProcessId() !== renderer.process || candidate.contents.getOSProcessId() !== 0) return;
      const fault = this.documents.failure(candidate.target);
      if (fault?.page === candidate.page && fault.availability === 'crashed') this.health.affected(attempt, candidate.target, fault);
    };
    for (const candidate of candidates) {
      const listener = () => {
        if (!job.active || candidate.contents.isDestroyed() || !candidate.contents.isCrashed() || candidate.contents.getOSProcessId() !== 0) return;
        // The document producer registered first and latched this actual native gone event.
        try { affected(candidate); } catch { this.host.authority.assertHealthy(); }
      };
      candidate.contents.on('render-process-gone', listener);
      listeners.push(() => candidate.contents.removeListener('render-process-gone', listener));
    }
    const deadline = Math.min(job.workDeadline, performance.now() + 2000);
    let witnessedGone = false;
    const onGone = () => {
      if (!job.active || contents.isDestroyed()) return;
      if (contents.isCrashed() && contents.getProcessId() === renderer.process && contents.getOSProcessId() === 0) witnessedGone = true;
    };
    contents.on('render-process-gone', onGone); listeners.push(() => contents.removeListener('render-process-gone', onGone));
    try {
      guard(); this.health.stopping(attempt);
      // Subscribe before issue; compare immutable original frame/process facts
      // directly before the real supported engine API, never a supplied callback.
      const current = physicalFrames(original).find(frame => frame.node === main.node);
      if (!current || current.token !== main.token || current.process !== renderer.process || current.osProcess !== renderer.osProcess)
        throw recoveryFailed('renderer_changed');
      guard(); contents.forcefullyCrashRenderer();
      while (!witnessedGone) {
        guard();
        const proof = this.documents.stopped(target, original);
        if (proof?.renderer.process === renderer.process && proof.renderer.osProcess === renderer.osProcess &&
            contents.isCrashed() && contents.getOSProcessId() === 0) witnessedGone = true;
        if (witnessedGone) break;
        if (performance.now() >= deadline) throw recoveryFailed('renderer_stop_timeout');
        await pause(Math.max(1, Math.min(10, deadline - performance.now())), undefined, { signal: job.controller.signal });
      }
      guard();
      for (const candidate of candidates) {
        affected(candidate);
        if (this.host.authority.wasClosed(candidate.target) || candidate.target.page !== candidate.page || candidate.page.retirement()) continue;
        // Never use an old shared-renderer callback to poison a newer receipt.
        if (this.documents.originalReceipt(candidate.target, candidate.page) !== candidate.receipt) {
          changed.add(candidate.target.id); effects.push({ tab: candidate.target.id, observed: 'replaced' }); continue;
        }
        try {
          const live = physicalFrames(candidate.page);
          const changedFrame = candidate.frames.some(frame => !live.some(value => value.node === frame.node && value.token === frame.token &&
            value.process === frame.process && value.osProcess === frame.osProcess));
          if (changedFrame) {
            changed.add(candidate.target.id); effects.push({ tab: candidate.target.id, observed: 'replaced' });
            this.documents.fenceFrameObservation(candidate.target, candidate.page, candidate.receipt);
          }
        } catch {
          // A census exception is not a crash proof. Check the original copied
          // RFH/token itself, and never use a retargeted wrapper as the old frame.
          const unavailable = candidate.frames.some(frame => {
            try {
              if (frame.handle.isDestroyed() || frame.handle.detached) return true;
              return frame.handle.processId === frame.process && frame.handle.frameToken === frame.token && frame.handle.osProcessId === 0;
            } catch { return webFrameMain.fromFrameToken(frame.process, frame.token) === null; }
          });
          if (unavailable && this.documents.originalReceipt(candidate.target, candidate.page) === candidate.receipt) {
            effects.push({ tab: candidate.target.id, observed: 'unavailable' });
            this.documents.failPage(candidate.target, candidate.page, 'unavailable', 'frame_unavailable_during_renderer_stop');
          } else {
            effects.push({ tab: candidate.target.id, observed: 'uncertain' });
            this.documents.fenceFrameObservation(candidate.target, candidate.page, candidate.receipt);
          }
        }
      }
      return 'terminated';
    } finally { for (const remove of listeners) remove(); }
  }
  async recover(target: TabTarget, expected: number, context: { readonly deadline: number; assertCurrent(): void }): Promise<void> {
    this.native(); const tabs = this.tabs(), owner = this.host.authority, original = target.page;
    if (this.pending.has(target) || tabs.get(target.id) !== target || tabs.selected(original.window) !== target) throw refused('control_refused');
    const before = owner.expected(target, expected);
    if (before.controller.kind !== 'user' || before.handoff !== 'idle' || before.inputReady || before.pageAvailability === 'ready')
      throw refused('control_refused');
    const deadline = Math.min(context.deadline, performance.now() + 8000), workDeadline = deadline - 1000;
    if (performance.now() >= workDeadline) throw recoveryFailed('timeout');
    const checkContext = () => { const result: unknown = context.assertCurrent(); if (result !== undefined) return owner.exhausted(); };
    checkContext(); const address = userURL(this.documents.lastSafeURL(target));
    const transition = owner.beginRecovery(target, expected), attempt = this.health.beginRecovery(target, original, transition.generation);
    const job: Job = { active: true, controller: new AbortController(), transition, attempt, original, deadline, workDeadline, committed: false };
    this.pending.set(target, job); owner.changed();
    const guard = () => {
      checkContext(); this.native();
      if (!job.active || job.controller.signal.aborted || this.pending.get(target) !== job || performance.now() >= workDeadline ||
          tabs.get(target.id) !== target || tabs.selected(original.window) !== target) throw staleSnapshot();
      owner.assertRecovery(transition); this.health.assertAttempt(attempt);
    };
    let stop: RecoveryReport['stop'] = 'unproved', reason = 'preparation_failed';
    const changed = new Set<string>(), effects: { tab: string; observed: 'unavailable' | 'replaced' | 'uncertain' }[] = [];
    try {
      const receipt = await this.within(workDeadline, guard, async () => {
        guard();
        if (!original.retirement()) original.window.guardRetirementTransition(() => {
          const blocked = original.setNativeBlocked(true);
          if (!blocked.blocked || blocked.retired || blocked.id !== original.identity.id || blocked.nonce !== original.identity.nonce)
            return owner.exhausted();
        });
        guard(); reason = 'renderer_stop'; stop = await this.stop(job, guard, changed, effects); guard();
        reason = 'original_retirement'; await this.retirement(original, Math.min(workDeadline, performance.now() + 1000)); guard();
        reason = 'replacement_creation';
        const replacement = original.window.createPage(); job.replacement = replacement; guard();
        tabs.replace(target, original, replacement, guard, () => {
          owner.rebindRecovery(transition, replacement);
          this.health.replaced(attempt, replacement);
        });
        guard(); reason = 'load_failed';
        const consume = await this.preparePage(target, guard, transition);
        await this.within(workDeadline - 2000, guard, () => {
          guard(); consume();
          // Keep publication of renderer readiness held until the exact load succeeds.
          this.documents.watch(target, true);
          return this.documents.originalContents(target, replacement).loadURL(address);
        }, () => { job.active = false; });
        guard(); reason = 'readiness_failed';
        const receipt = this.documents.releasePreparation(target, replacement, workDeadline);
        await this.documents.waitReady(target, receipt, job.controller.signal, workDeadline, guard); guard();
        return receipt;
      }, () => { job.active = false; });
      guard(); const healthCommit = this.health.prepareRecoveryCompletion(attempt, receipt);
      const terminalGuard = () => { guard(); healthCommit.assertCurrent(); };
      terminalGuard(); const committed: unknown = this.commit(transition, receipt, terminalGuard);
      if (committed !== undefined) return owner.exhausted();
      job.committed = true; // before any post-commit readback/report/notification can reject
      healthCommit.commit();
      if (!owner.wasClosed(target)) {
        this.reports.set(target, Object.freeze({ tab: target.id, generation: transition.generation, status: 'recovered', stop,
          affectedTabs: this.health.affectedTabs(attempt), changedDuringStop: Object.freeze([...changed]),
          frameEffects: Object.freeze(effects.map(effect => Object.freeze(effect))) })); owner.changed();
      }
    } catch (error) {
      if (job.committed) throw error;
      if (error instanceof RecoveryFailure) reason = error.recoveryReason;
      job.active = false;
      // Close attempt state before abort listeners or cleanup can reenter. Every
      // later action keeps literal original/replacement pages, never target.page.
      if (job.replacement) this.documents.close(target, job.replacement);
      owner.failRecovery(transition); this.health.failRecovery(attempt, reason); job.controller.abort();
      if (job.replacement) await this.retirement(job.replacement, deadline);
      else if (!original.retirement() || original.retirement()!.phase !== 'retired') await this.retirement(original, deadline);
      if (!owner.wasClosed(target)) {
        this.reports.set(target, Object.freeze({ tab: target.id, generation: transition.generation, status: 'failed', stop, error: reason,
          affectedTabs: this.health.affectedTabs(attempt), changedDuringStop: Object.freeze([...changed]),
          frameEffects: Object.freeze(effects.map(effect => Object.freeze(effect))) })); owner.changed();
      }
      if (error instanceof BrowserFailure && error.detail.code === 'control_changed') throw error;
      throw recoveryFailed(reason);
    } finally {
      job.active = false; if (this.pending.get(target) === job) this.pending.delete(target);
      if (owner.wasClosed(target)) this.reports.delete(target);
    }
  }
}

export type ControlIdentity = Readonly<Omit<Contract<'browser.BrowserInfo'>, 'client'>>;
export interface RendererControl {
  readonly pageAdmission: false;
  readonly ownership: OwnershipHost;
  readonly documents: HostDocuments;
  readonly readiness: PageReadiness;
  readonly health: RendererHealth;
  readonly recovery: PageRecovery;
  /** Bind actual hidden shell resources before registration.load or page load. */
  bind(tabs: TabRegistry, host: WindowHost, registration: ShellRegistration): void;
}
/** Executable control-only contribution. The caller supplies genuine installed
 * Native custody and owned metadata. There is no EngineAuthority, normal launch
 * path, permissive engine operation or dependency on a later Tools adapter. */
export function createRendererControl(boundary: NativeFailureBoundary, identity: ControlIdentity,
  protection: { sessions: ProfileSessions; custody: HostCustody },
  proof: ArmedHostSnapshot): RendererControl {
  assertNativeFailureBoundary(boundary);
  if (identity.contract !== 1 || !validator('browser.ProfileId')(identity.profile) ||
      !validator('browser.InstanceId')(identity.instance) || !validator('browser.Build')(identity.build) ||
      Object.keys(identity).sort().join(',') !== 'build,contract,instance,profile') throw unavailable('browser');
  const info = Object.freeze({ contract: 1 as const, profile: identity.profile, instance: identity.instance, build: identity.build });
  const documents = new HostDocuments(boundary), readiness = new PageReadiness(boundary, documents);
  const registrations = new Map<WindowHost, ShellRegistration>();
  let ownership!: OwnershipHost, recovery!: PageRecovery, health!: RendererHealth, removeReady = () => {};
  let capabilities!: HostCapabilities;
  let dispatchTools!: HostToolOperation;
  let inspection!: ReturnType<typeof createInspectionTools>, mutation!: ReturnType<typeof createTrustedActionTools>;
  const preparePage = async (target: TabTarget, guard: () => void, transition?: RecoveryTransition) => {
    guard(); capabilities.bindPage(target, transition);
    await capabilities.armInitialPage(target, guard); guard();
    return () => capabilities.consumeInitialPageArm(target, guard);
  };
  const prepareCoverage = async (receipt: HostDocument, guard: () => void) => {
    const frames = await readiness.inspection(receipt, guard);
    for (const frame of frames) await capabilities.armFileChooser(frame, guard);
    await readiness.verifyInspection(frames, guard);
    const current = () => capabilities.assertAgentAdmission(receipt, frames, guard);
    current(); return current;
  };
  ownership = createOwnershipHost(boundary, documents, {
    info: () => info,
    async agent(request, execution, inspectionIdentity) {
      if (request.params.name !== 'browser_screenshot') {
        const guard = inspection.inspection.guard(execution, execution.action !== undefined);
        guard();
        await prepareCoverage(documents.current(execution.stamp.target), guard);
        guard();
      }
      return dispatchTools(request, execution, inspectionIdentity);
    },
    preparePage,
    async prepareReturn(target, document, guard) {
      guard();
      const receipt = documents.current(target);
      if (receipt !== document) throw staleSnapshot();
      return prepareCoverage(receipt, guard);
    },
    async user(request, target, job) {
      await documents.navigateUser(target, request.method === 'user_navigate' ? request.params.url : request.method, job);
    },
    recover: (target, expected, job) => recovery.recover(target, expected, job),
    leaveAgentMode: (target, document, deadline, job) => readiness.leaveAgentMode(target, document, deadline, job.assertCurrent),
    invalidate(target) {
      // Document/recipient invalidation fences authority, not the physical
      // debugger channel. Only terminal logical Close tears down producers.
      if (ownership.authority.wasClosed(target)) { recovery.cancel(target); documents.forget(target, target.page); }
    },
    shutdown() {
      // Authority is already sealed. Remove real shell observers before native
      // retirement can publish a selection event into closed admission.
      for (const registration of registrations.values()) registration.dispose(); registrations.clear();
      inspection.close(); mutation.close(); capabilities.close();
      recovery.closeAll(); documents.closeAll(); health.closeAll(); removeReady();
    },
  }, proof, identity);
  health = new RendererHealth(documents, readiness, ownership.authority, fault => ownership.healthFailure(fault.target, fault));
  recovery = new PageRecovery(ownership, documents, health, (transition, receipt, guard) => ownership.recovered(transition, receipt, guard),
    preparePage);
  documents.bind(ownership.authority, readiness, fault => health.failed(fault));
  capabilities = new HostCapabilities(ownership.authority, documents, readiness, protection.sessions,
    protection.custody);
  inspection = createInspectionTools(ownership.authority, documents, readiness);
  mutation = createTrustedActionTools(inspection.inspection);
  dispatchTools = createHostToolOperations({ inspection: inspection.agent, mutation: mutation.agent });
  removeReady = documents.subscribe(event => {
    if (event.kind !== 'ready' || !event.receipt || event.target.page !== event.page ||
        ownership.authority.wasClosed(event.target) || health.recovering(event.target)) return;
    try { ownership.documentReady(event.target, event.receipt); }
    catch (error) {
      ownership.authority.assertHealthy();
      // An actual Close, handoff, navigation or presentation event may supersede
      // readiness synchronously. Expected refusal cannot turn into profile fatal.
      if (!(error instanceof BrowserFailure)) return ownership.authority.exhausted();
    }
  });
  return Object.freeze({ pageAdmission: false as const, ownership, documents, readiness, health, recovery,
    bind(tabs: TabRegistry, host: WindowHost, registration: ShellRegistration) {
      ownership.bind(tabs, host, registration); documents.bindWindow(host); recovery.bind(tabs);
      registrations.set(host, registration);
      host.onClosed(() => { registrations.delete(host); });
    },
  });
}
