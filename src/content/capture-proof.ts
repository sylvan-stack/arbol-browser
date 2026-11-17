import { performance } from 'node:perf_hooks';
import { owningQueue, type ActionExecution, type ActionQueue, type CaptureReservation } from '../host/actions.js';
import type { HostDocument, HostDocuments } from '../host/documents.js';
import type { InspectionFrame, PageReadiness } from '../host/readiness.js';
import { staleSnapshot } from '../host/authority.js';
import { classifiedRefusal, type ClassifiedDOM, type SensitiveFields } from './sensitive.js';

export interface CaptureLayout {
  readonly cssVisualViewport: { readonly pageX: number; readonly pageY: number;
    readonly offsetX: number; readonly offsetY: number; readonly zoom: number;
    readonly clientWidth: number; readonly clientHeight: number; readonly scale: number };
}
export interface RootViewport { readonly x: 0; readonly y: 0; readonly width: number; readonly height: number }
/** Pinned InspectorHighlight::GetBoxModel uses FrameQuadToViewport,
 * absolute-zoom adjustment and inverse page scale. At supported unit zoom and
 * scale with zero visual offset these are viewport CSS coordinates, already
 * scrolled. pageX/pageY are document scroll diagnostics, never mask offsets. */
function rootViewport(layout: CaptureLayout): RootViewport {
  const view = layout?.cssVisualViewport;
  if (!view || ![view.pageX, view.pageY, view.offsetX, view.offsetY, view.zoom, view.scale, view.clientWidth, view.clientHeight].every(Number.isFinite) ||
      view.offsetX !== 0 || view.offsetY !== 0 || view.zoom !== 1 || view.scale !== 1 ||
      view.clientWidth <= 0 || view.clientHeight <= 0 || view.clientWidth > 16384 || view.clientHeight > 16384 ||
      view.clientWidth * view.clientHeight > 33554432) throw classifiedRefusal();
  return Object.freeze({ x: 0, y: 0, width: view.clientWidth, height: view.clientHeight });
}
export interface CaptureStamp {
  readonly dom: ClassifiedDOM;
  readonly boxes: readonly number[][];
  readonly layout: CaptureLayout;
  readonly viewport: RootViewport;
  readonly activity: number;
  readonly placement: number;
  readonly surface: Readonly<{ epoch: number; width: number; height: number }>;
}
function acknowledge(value: unknown): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length) throw classifiedRefusal();
}
/** A capture transaction owns actual profile-wide capture exclusion, engine state and
 * temporary observations. Nothing here treats a CDP reply or two equal images
 * as an authenticated layout-to-pixel token. */
export class CaptureProof {
  readonly receipt: HostDocument;
  private readonly reservation: CaptureReservation;
  private frame?: InspectionFrame;
  private surface?: ReturnType<PageReadiness['watchSurface']>;
  private playback?: number;
  private touched = false;
  private active = true;
  private stamp?: CaptureStamp;
  readonly queue: ActionQueue;
  private restoration?: Promise<void>;
  private restoreDeadline?: number;
  constructor(readonly documents: HostDocuments, readonly readiness: PageReadiness,
    readonly fields: SensitiveFields, readonly execution: ActionExecution) {
    // Must precede debugger setup, animation/lifecycle operations and geometry.
    this.queue = owningQueue(execution);
    if (this.queue.authority.documents !== documents || readiness.documents !== documents || fields.readiness !== readiness) throw staleSnapshot();
    this.reservation = this.queue.reserveCapture(execution);
    this.receipt = this.reservation.original as HostDocument;
  }
  guard = (): void => {
    this.queue.authority.check(this.execution.stamp);
    if (!this.active || this.execution.signal.aborted || performance.now() >= this.execution.deadline) throw staleSnapshot();
    this.reservation.assertOriginal();
    if (this.frame) this.readiness.assertInspection(this.frame, () => this.reservation.assertOriginal());
  };
  private original = (): void => {
    if (!this.active || performance.now() >= (this.restoreDeadline ?? this.execution.deadline)) throw staleSnapshot();
    this.reservation.assertOriginal();
  };
  private async sample(): Promise<CaptureStamp> {
    this.guard(); const frame = this.frame; if (!frame || !this.surface) throw classifiedRefusal();
    const activity = this.readiness.observation(this.receipt);
    if (activity.unknownActivity || activity.sessions || activity.resources || activity.animations) throw classifiedRefusal();
    const placement = this.documents.presentedEpoch(this.receipt), surface = this.surface.sample();
    const dom = await this.execution.dispatch(() => this.fields.classify(frame, this.guard));
    const boxes = await this.execution.dispatch(() => this.fields.geometry(dom, this.guard));
    const layout = await this.execution.dispatch(() => this.readiness.inspect(frame, this.guard, 'Page.getLayoutMetrics')) as CaptureLayout;
    this.guard();
    const viewport = rootViewport(layout);
    if (this.readiness.observation(this.receipt).epoch !== activity.epoch ||
        this.documents.presentedEpoch(this.receipt) !== placement || this.surface.sample().epoch !== surface.epoch) throw classifiedRefusal();
    return Object.freeze({ dom, boxes, layout, viewport, activity: activity.epoch, placement, surface });
  }
  async quiesce(): Promise<CaptureStamp> {
    this.guard();
    const frames = await this.execution.dispatch(() => this.readiness.inspection(this.receipt, this.guard));
    this.guard(); const frame = frames[0];
    if (!frame?.physical || frames.length !== 1 || this.receipt.frames.length !== 1) throw classifiedRefusal();
    this.frame = frame; this.surface = this.readiness.watchSurface(this.receipt, this.guard);
    await this.execution.dispatch(() => this.readiness.barrier(this.receipt, this.execution.deadline, this.guard));
    this.guard(); this.surface.sample(); // no actual presented sample means refusal
    const rate = await this.execution.dispatch(() => this.readiness.inspect(frame, this.guard, 'Animation.getPlaybackRate')) as { playbackRate?: number };
    if (typeof rate.playbackRate !== 'number' || !Number.isFinite(rate.playbackRate) || rate.playbackRate < 0) throw classifiedRefusal();
    this.playback = rate.playbackRate;
    this.touched = true; // before any possibly applied command or callback
    acknowledge(await this.execution.dispatch(() => this.readiness.inspect(frame, this.guard, 'Animation.setPlaybackRate', { playbackRate: 0 })));
    acknowledge(await this.execution.dispatch(() => this.readiness.inspect(frame, this.guard, 'Page.setWebLifecycleState', { state: 'frozen' })));
    this.guard(); this.stamp = await this.sample(); return this.stamp;
  }
  async pixels(stamp: CaptureStamp): Promise<{ data: string }> {
    this.guard(); if (this.stamp !== stamp || !this.frame) throw classifiedRefusal();
    // Step 4 still owes the actual fresh root/whole-child paint producer and
    // renderer freeze/visibility restoration fit. Do not invoke an unproven
    // producer (including view-changing CDP clip) or return any pixel bytes.
    throw classifiedRefusal();
  }
  async assertSameSurface(stamp: CaptureStamp): Promise<void> {
    this.guard(); if (this.stamp !== stamp) throw classifiedRefusal();
    const after = await this.sample();
    if (stamp.dom.signature !== after.dom.signature || JSON.stringify(stamp.boxes) !== JSON.stringify(after.boxes) ||
        JSON.stringify(stamp.layout) !== JSON.stringify(after.layout) || stamp.activity !== after.activity ||
        JSON.stringify(stamp.viewport) !== JSON.stringify(after.viewport) ||
        stamp.placement !== after.placement || stamp.surface.epoch !== after.surface.epoch ||
        stamp.surface.width !== after.surface.width || stamp.surface.height !== after.surface.height) throw classifiedRefusal();
    // The pinned API returns PNG bytes without a presentation/layout token.
    // Quiescence, unchanged geometry and these invalidation epochs are necessary
    // but cannot by themselves exclude an older queued compositor surface.
    // No production evidence currently establishes that final coupling. Fail
    // closed instead of laundering a CDP reply/frame event/equal images into
    // proof. ABR-48 Step 4 still owns the actual producer and restoration fit;
    // ABR-16 then qualifies its useful output on the integrated pinned runtime.
    throw classifiedRefusal();
  }
  /** Restoration survives recipient revocation but never original-page or
   * document retirement. Its independent guard cannot act on a replacement.
   * A timeout poisons this job before late acknowledgements can continue. */
  restore(): Promise<void> {
    if (this.restoration) return this.restoration;
    let resolve!: () => void, reject!: (error: unknown) => void;
    const result = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
    this.restoration = result; // before native/renderer callbacks can reenter
    // Recipient/read expiry does not end original restoration ownership.
    // This separate bounded budget permits only restoration of that document.
    this.restoreDeadline = performance.now() + 3000;
    const remaining = this.restoreDeadline - performance.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async () => {
      this.original();
      if (this.touched) {
        const frame = this.frame, playback = this.playback;
        if (!frame || playback === undefined) throw classifiedRefusal();
        acknowledge(await this.readiness.inspect(frame, this.original, 'Page.setWebLifecycleState', { state: 'active' }));
        acknowledge(await this.readiness.inspect(frame, this.original, 'Animation.setPlaybackRate', { playbackRate: playback }));
        const observed = await this.readiness.inspect(frame, this.original, 'Animation.getPlaybackRate') as { playbackRate?: number };
        this.original(); if (observed.playbackRate !== playback) throw classifiedRefusal();
        // Actual original frame-queue service, isolated frame callbacks and
        // native presentation/binding observations verify resumed readiness.
        // Neither a lifecycle acknowledgement nor a timer releases exclusion.
        await this.readiness.barrier(this.receipt, this.restoreDeadline!, this.original); this.original();
        // This barrier is the released native/frame service observation. It is
        // not yet a proven original Chromium visibility/renderer restoration
        // receipt after capture freeze. Step 4 must replace this closed gate;
        // meanwhile retain exclusion through exact original retirement.
        throw classifiedRefusal();
      }
      this.surface?.close(); delete this.surface;
      this.original(); this.reservation.restored(); this.active = false;
    };
    void Promise.race([run(), new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => { this.active = false; reject(classifiedRefusal()); }, Math.max(1, remaining));
    })]).catch(() => {
      this.active = false;
      // The canonical producer authenticates literal original-page ownership,
      // latches RendererHealth.failed and invokes existing guarded Take/retire.
      // Keep the queue reservation until that real retirement is confirmed.
      this.documents.failPage(this.execution.stamp.target, this.receipt.page, 'unavailable', 'capture_restoration_failed');
      void this.receipt.page.retire().catch(() => this.readiness.boundary.fatal.fail('native_retirement_unavailable'));
      throw classifiedRefusal();
    }).finally(() => {
      if (timer) clearTimeout(timer);
      delete this.stamp;
      try { this.surface?.close(); } finally { delete this.surface; }
    }).then(resolve, reject);
    return result;
  }
}
