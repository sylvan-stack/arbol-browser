import { EventEmitter } from 'node:events';
import type { WebContents, WebFrameMain } from 'electron';
import { BrowserFailure } from '../contracts/errors.js';
import { assertProductionSessions, type ProfileSessions } from '../profiles/session.js';
import type { HostCustody } from '../runtime/custody.js';
import { assertNativeFailureBoundary } from '../runtime/bootstrap.js';
import { assertNativeFeatures } from '../native/features.js';
import { assertSystemClipboardProtection, type SystemClipboardProtection } from '../runtime/platform.js';
import { staleSnapshot, type TabAuthority } from './authority.js';
import type { HostDocument, HostDocuments } from './documents.js';
import type { InspectionFrame, PageReadiness } from './readiness.js';
import { assertPageSurface, type PageSurface } from './windows.js';
import type { TabTarget } from './tabs.js';

export type UserPermission = 'geolocation' | 'notifications' | 'clipboard-read' |
  'fullscreen' | 'pointerLock';
export interface UserPermissionScope {
  readonly target: TabTarget; readonly page: PageSurface; readonly document: HostDocument;
  readonly generation: number; readonly origin: string;
  assertCurrent(): void;
}
/** Host-only existing trusted-user consent. Never a website message, renderer
 * boolean, client label or agent permission upgrade. Missing consent denies. */
export type UserPermissionPolicy = (scope: UserPermissionScope, permission: UserPermission) => boolean;
interface ChooserAcknowledgement {
  readonly frame: InspectionFrame; readonly generation: number;
}
interface PageRecord {
  readonly target: TabTarget; readonly page: PageSurface; readonly contents: WebContents;
  readonly emitter: EventEmitter; readonly stockDialog: (...args: any[]) => unknown;
  readonly dialog: (...args: any[]) => void;
  readonly choosers: Map<string, ChooserAcknowledgement>;
  readonly modals: Set<object>; readonly denyModalReplies: Set<() => void>;
  initial: 'unarmed' | 'arming' | 'armed' | 'consumed' | 'failed';
  initialArm?: Promise<void>; initialChannel?: object; initialFrame?: string;
  active: boolean;
}
const installed = new WeakSet<object>();
// BRW-D36 denies write consent even to a current user-controlled tab. Read
// consent remains independent; no policy callback can approve clipboard writes.
const userPermissions = new Set<string>(['geolocation', 'notifications', 'clipboard-read', 'fullscreen', 'pointerLock']);
const chooserKey = (frame: InspectionFrame) => JSON.stringify([frame.session ?? null, frame.frameId]);
function unavailableBoundary(): BrowserFailure {
  return new BrowserFailure({ code: 'unsupported', message: 'The required agent capability boundary is unavailable.', retryable: false,
    remedy: 'Use Take control or a complete qualified browser Build.' });
}
function acknowledge(value: unknown): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length) throw staleSnapshot();
}

/** ABR-30 installs the genuine native process protection before any Session,
 * chrome or website, then binds this original-page provider. Consent handlers
 * alone never enforce transient-activation script copy/cut. This constructor
 * requires the native handle; no caller-created flag can open admission. */
export class HostCapabilities {
  private readonly records = new Map<TabTarget, PageRecord>();
  private readonly contents = new WeakMap<WebContents, PageRecord>();
  private closed = false;
  private readonly requestHandler;
  private readonly checkHandler;
  private readonly captureHandler;
  private readonly extensions;
  private readonly extensionList;
  private readonly removeDocuments: () => void;
  constructor(readonly authority: TabAuthority, readonly documents: HostDocuments, readonly readiness: PageReadiness,
    readonly sessions: ProfileSessions, readonly custody: HostCustody, private readonly clipboardProtection: SystemClipboardProtection,
    private readonly userPolicy?: UserPermissionPolicy) {
    if (authority.documents !== documents || readiness.documents !== documents || readiness.boundary !== authority.boundary ||
        sessions.website === sessions.shell || installed.has(sessions.website)) throw unavailableBoundary();
    const website = sessions.website;
    this.requestHandler = website.setPermissionRequestHandler;
    this.checkHandler = website.setPermissionCheckHandler;
    this.captureHandler = website.setDisplayMediaRequestHandler;
    this.extensions = website.extensions; this.extensionList = website.extensions.getAllExtensions;
    this.identity(); installed.add(website);
    // The actual engine calls these handlers. Neither handler supplies a raw
    // permission, filesystem, clipboard, capture or external-protocol tool.
    this.requestHandler.call(website, (contents, permission, callback, details) => {
      let allow = false;
      try {
        this.identity();
        const scope = this.requestScope(contents, details.isMainFrame, details.requestingUrl);
        if (userPermissions.has(permission) && this.userPolicy?.(scope, permission as UserPermission) === true) {
          scope.assertCurrent(); allow = true;
        }
      } catch { /* Agent, unknown frame, stale user consent or closed page: deny. */ }
      callback(allow);
    });
    this.checkHandler.call(website, (contents, permission, origin, details) => {
      try {
        this.identity();
        if (!contents || !userPermissions.has(permission)) return false;
        const scope = this.requestScope(contents, details.isMainFrame, details.requestingUrl);
        if (scope.origin !== origin || this.userPolicy?.(scope, permission as UserPermission) !== true) return false;
        scope.assertCurrent(); return true;
      } catch { return false; }
    });
    this.captureHandler.call(website, (_request, callback) => {
      // Camera/microphone consent is denied by the request/check handlers;
      // display capture has its own genuine engine path and no fallback picker.
      this.identity(); callback({});
    }, { useSystemPicker: false });
    website.on('will-download', (event) => {
      // Version 1 promises no OS file workflow in either mode. Refuse before
      // a Save dialog, without reading DownloadItem paths, URLs or content.
      this.identity(); event.preventDefault();
    });
    website.on('extension-loaded', () => {
      // The sealed host never installs an extension or exposes a loader. A real
      // unexpected load violates that closed feature configuration.
      this.identity(); return authority.boundary.fatal.fail('native_boundary_unavailable');
    });
    this.removeDocuments = documents.subscribe(event => {
      const record = this.records.get(event.target);
      if (!record || record.page !== event.page) return;
      if (event.kind === 'changed') record.choosers.clear();
      if (event.kind === 'closed') {
        record.active = false; record.choosers.clear();
        for (const deny of record.denyModalReplies) deny();
        this.records.delete(event.target); this.contents.delete(record.contents);
      }
    });
  }
  private identity(): void {
    try {
      assertNativeFailureBoundary(this.authority.boundary); assertNativeFeatures();
      assertProductionSessions(this.sessions, this.custody); this.authority.assertHealthy();
      assertSystemClipboardProtection(this.clipboardProtection, this.custody);
      const website = this.sessions.website;
      if (website.setPermissionRequestHandler !== this.requestHandler || website.setPermissionCheckHandler !== this.checkHandler ||
          website.setDisplayMediaRequestHandler !== this.captureHandler || website.extensions !== this.extensions ||
          website.extensions.getAllExtensions !== this.extensionList || this.extensionList.call(this.extensions).length !== 0)
        throw unavailableBoundary();
    } catch { return this.authority.boundary.fatal.fail('native_boundary_unavailable'); }
  }
  private original(record: PageRecord): void {
    this.identity(); assertPageSurface(record.page);
    if (this.closed || !record.active || this.records.get(record.target) !== record || this.contents.get(record.contents) !== record ||
        this.authority.wasClosed(record.target) || record.target.page !== record.page || record.page.retirement() || record.contents.isDestroyed() ||
        record.page.session !== this.sessions.website || record.contents.session !== this.sessions.website) throw unavailableBoundary();
    const binding = record.page.binding();
    if (binding.id !== record.page.identity.id || binding.nonce !== record.page.identity.nonce || binding.webContentsId !== record.contents.id || binding.retired)
      return this.authority.boundary.fatal.fail('native_boundary_unavailable');
  }
  private userScope(record: PageRecord): UserPermissionScope {
    this.original(record);
    const state = this.authority.state(record.target), receipt = this.documents.current(record.target);
    const generation = state.generation;
    const check = () => {
      this.original(record); this.documents.assertCurrent(record.target, receipt);
      const current = this.authority.state(record.target);
      if (current.controller.kind !== 'user' || current.handoff !== 'idle' || current.generation !== generation || !receipt.ready ||
          record.page.binding().blocked || record.page.window.selected() !== record.page || record.contents.mainFrame !== receipt.frame.handle)
        throw unavailableBoundary();
    };
    check(); const origin = new URL(receipt.frame.handle.url).origin;
    if (!['http:', 'https:'].includes(new URL(origin).protocol)) throw unavailableBoundary();
    return Object.freeze({ target: record.target, page: record.page, document: receipt, generation, origin, assertCurrent: check });
  }
  private requestScope(contents: WebContents, main: boolean, address: string | undefined): UserPermissionScope {
    const record = this.contents.get(contents);
    if (!record || main !== true || typeof address !== 'string') throw unavailableBoundary();
    const scope = this.userScope(record);
    if (address !== scope.document.frame.handle.url) throw unavailableBoundary(); scope.assertCurrent(); return scope;
  }
  /** Must run on the newly created genuine page, before website load/exposure.
   * The sealed stock constructor supplies the sole -run-dialog listener. Keep
   * its actual object identity, verify sole possession, and never clone/eval it. */
  bindPage(target: TabTarget): void {
    this.identity(); assertPageSurface(target.page);
    if (this.closed || this.records.has(target) || this.records.size >= 64 || target.page.session !== this.sessions.website || target.page.retirement()) throw unavailableBoundary();
    const page = target.page, contents = page.view.webContents, emitter = contents as unknown as EventEmitter;
    if (this.contents.has(contents) || contents.session !== this.sessions.website || !['', 'about:blank'].includes(contents.getURL())) throw unavailableBoundary();
    const binding = page.binding(), state = this.authority.state(target);
    if (binding.revision !== 0 || !binding.blocked || state.generation !== 1 || state.inputReady || state.navigation !== undefined ||
        this.documents.originalReceipt(target, page) !== undefined || contents.navigationHistory.length() > 1) throw unavailableBoundary();
    const raw = EventEmitter.prototype.rawListeners.call(emitter, '-run-dialog');
    const listeners = EventEmitter.prototype.listeners.call(emitter, '-run-dialog');
    if (raw.length !== 1 || listeners.length !== 1 || raw[0] !== listeners[0] || typeof raw[0] !== 'function') throw unavailableBoundary();
    const stock = raw[0] as (...args: any[]) => unknown, modals = new Set<object>(), denyModalReplies = new Set<() => void>();
    let record!: PageRecord;
    const dialog = (info: { frame?: WebFrameMain }, callback: (accepted: boolean, value: string) => void) => {
      let scope: UserPermissionScope;
      try {
        this.original(record);
        const current = EventEmitter.prototype.rawListeners.call(emitter, '-run-dialog');
        if (current.length !== 1 || current[0] !== dialog || typeof callback !== 'function') throw unavailableBoundary();
        scope = this.userScope(record);
        if (info?.frame !== scope.document.frame.handle || modals.size) throw unavailableBoundary();
        scope.assertCurrent();
      } catch { if (typeof callback === 'function') callback(false, ''); return; }
      const token = Object.freeze({}); modals.add(token);
      let replied = false;
      const reply = (accepted: boolean, value: string) => {
        if (replied) return; replied = true; denyModalReplies.delete(deny);
        let current = false; try { scope.assertCurrent(); current = true; } catch { /* no old dialog reply to a successor */ }
        callback(current && accepted === true, current && typeof value === 'string' ? value : '');
      };
      const deny = () => reply(false, ''); denyModalReplies.add(deny);
      // The actual retained stock listener owns its real GUI promise. A denial
      // callback alone never proves that a previously shown modal is terminal.
      let running: unknown;
      try { scope.assertCurrent(); running = Reflect.apply(stock, contents, [info, reply]); }
      catch { deny(); modals.delete(token); return; }
      if (!running || typeof (running as PromiseLike<unknown>).then !== 'function') {
        deny(); return this.authority.boundary.fatal.fail('native_boundary_unavailable');
      }
      void Promise.resolve(running).catch(deny).finally(() => {
        deny(); modals.delete(token); denyModalReplies.delete(deny);
      });
    };
    record = { target, page, contents, emitter, stockDialog: stock, dialog, choosers: new Map(), modals, denyModalReplies, active: true, initial: 'unarmed' };
    this.records.set(target, record); this.contents.set(contents, record);
    EventEmitter.prototype.removeListener.call(emitter, '-run-dialog', stock);
    EventEmitter.prototype.on.call(emitter, '-run-dialog', dialog);
    const current = EventEmitter.prototype.rawListeners.call(emitter, '-run-dialog');
    if (current.length !== 1 || current[0] !== dialog) return this.authority.boundary.fatal.fail('native_boundary_unavailable');
  }
  private initialGuard(record: PageRecord, guard: () => void): void {
    this.original(record); const result: unknown = guard(); if (result !== undefined) throw unavailableBoundary();
    const binding = record.page.binding(), state = this.authority.state(record.target);
    if (!['unarmed', 'arming', 'armed'].includes(record.initial) || binding.revision !== 0 || !binding.blocked || state.generation !== 1 ||
        state.inputReady || state.navigation !== undefined || this.documents.originalReceipt(record.target, record.page) !== undefined ||
        !['', 'about:blank'].includes(record.contents.getURL()) || record.contents.navigationHistory.length() > 1 || record.modals.size)
      throw unavailableBoundary();
  }
  /** Genuine pre-load ROOT restriction on the sole PageReadiness channel. This
   * does not need or invent a committed child receipt. There is no public/raw
   * session argument: ABR-48/30 must separately bind actual waiting children. */
  armInitialPage(target: TabTarget, guard: () => void): Promise<void> {
    const record = this.records.get(target); if (!record) throw unavailableBoundary();
    this.initialGuard(record, guard);
    if (record.initialArm) return record.initialArm;
    record.initial = 'arming';
    const check = () => this.initialGuard(record, guard);
    const running = (async () => {
      check(); const channel = this.readiness.channel(record.page); check();
      acknowledge(await this.readiness.command(record.page, check, 'Page.enable')); check();
      const before = await this.readiness.command(record.page, check, 'Page.getFrameTree') as {
        frameTree?: { frame?: { id?: string; url?: string }; childFrames?: unknown[] } };
      check(); const frame = before.frameTree?.frame;
      if (!frame?.id || frame.url !== 'about:blank' || before.frameTree?.childFrames?.length) throw unavailableBoundary();
      acknowledge(await this.readiness.command(record.page, check, 'Page.setInterceptFileChooserDialog', { enabled: true, cancel: true })); check();
      const after = await this.readiness.command(record.page, check, 'Page.getFrameTree') as {
        frameTree?: { frame?: { id?: string; url?: string }; childFrames?: unknown[] } };
      check();
      if (this.readiness.channel(record.page) !== channel || after.frameTree?.frame?.id !== frame.id ||
          after.frameTree?.frame?.url !== 'about:blank' || after.frameTree.childFrames?.length) throw unavailableBoundary();
      record.initialChannel = channel; record.initialFrame = frame.id; record.initial = 'armed';
    })();
    record.initialArm = running;
    void running.catch(() => { record.initial = 'failed'; });
    return running;
  }
  /** ABR-30 consumes this positive original pre-load proof immediately before
   * its initial website load. A late root ack or caller flag cannot mint it. */
  consumeInitialPageArm(target: TabTarget, guard: () => void): void {
    const record = this.records.get(target); if (!record) throw unavailableBoundary();
    this.initialGuard(record, guard);
    if (record.initial !== 'armed' || !record.initialFrame || record.initialChannel !== this.readiness.channel(record.page)) throw unavailableBoundary();
    record.initial = 'consumed';
  }
  /** Fixed renderer-session chooser refusal, including pinned Blink's HTML and
   * File System Access picker paths. ABR-30 must arm each genuine paused/new
   * renderer before website code; an acknowledgement after exposure is not
   * proof that no prior user picker exists. This never disables interception. */
  async armFileChooser(frame: InspectionFrame, guard: () => void): Promise<void> {
    this.readiness.assertInspection(frame, guard);
    const target = this.documents.target(frame.receipt), record = this.records.get(target);
    if (!record || record.page !== frame.receipt.page || !frame.physical) throw unavailableBoundary();
    const generation = this.authority.state(target).generation;
    const check = () => {
      this.original(record); this.readiness.assertInspection(frame, guard);
      if (this.authority.state(target).generation !== generation || frame.receipt.page !== record.page || this.documents.target(frame.receipt) !== target)
        throw staleSnapshot();
    };
    check(); acknowledge(await this.readiness.command(record.page, check, 'Page.setInterceptFileChooserDialog', { enabled: true, cancel: true }, frame.session));
    check(); if (record.choosers.size >= 256 && !record.choosers.has(chooserKey(frame))) throw unavailableBoundary();
    record.choosers.set(chooserKey(frame), Object.freeze({ frame, generation }));
  }
  assertChooserCoverage(receipt: HostDocument, frames: readonly InspectionFrame[], guard: () => void): void {
    const target = this.documents.target(receipt), record = this.records.get(target);
    if (!record || record.page !== receipt.page || record.initial !== 'consumed' || record.modals.size || frames.length !== receipt.frames.length) throw unavailableBoundary();
    this.original(record); const generation = this.authority.state(target).generation;
    const seen = new Set<object>();
    for (const frame of frames) {
      this.readiness.assertInspection(frame, guard); const ack = record.choosers.get(chooserKey(frame));
      if (!frame.physical || !receipt.frames.includes(frame.physical) || seen.has(frame.physical) || frame.receipt !== receipt || !ack ||
          ack.generation !== generation || ack.frame.receipt !== receipt || ack.frame.physical !== frame.physical || ack.frame.session !== frame.session)
        throw unavailableBoundary();
      seen.add(frame.physical);
    }
    if (seen.size !== receipt.frames.length) throw unavailableBoundary(); guard(); this.original(record);
  }
  /** The exact process guard is a capability prerequisite, not action/grant
   * authority. Original document/frame/chooser and execution guards still own
   * page admission. ABR-30 separately refuses Browser-owned destructive Cut. */
  assertAgentAdmission(receipt: HostDocument, frames: readonly InspectionFrame[], guard: () => void): void {
    this.assertChooserCoverage(receipt, frames, guard);
    guard(); assertSystemClipboardProtection(this.clipboardProtection, this.custody); guard();
    this.documents.assertCurrent(this.documents.target(receipt), receipt);
  }
  close(): void {
    if (this.closed) return; this.closed = true; this.removeDocuments();
    for (const record of this.records.values()) {
      record.active = false; record.choosers.clear(); for (const deny of record.denyModalReplies) deny();
      // Leave the original wrapper denying until genuine page destruction.
      // Restoring a permissive stock listener here would reopen a stale page.
    }
    this.records.clear();
  }
}
