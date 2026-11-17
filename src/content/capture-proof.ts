import { performance } from 'node:perf_hooks';
import type { ActionExecution, ActionQueue, CaptureReservation } from '../host/actions.js';
import type { HostDocument, HostDocuments } from '../host/documents.js';
import type { InspectionFrame, PageReadiness } from '../host/readiness.js';
import { staleSnapshot } from '../host/authority.js';
import { classifiedRefusal, type ClassifiedDOM, type SensitiveFields } from './sensitive.js';

export interface CaptureLayout {
  readonly cssVisualViewport: { readonly pageX: number; readonly pageY: number;
    readonly clientWidth: number; readonly clientHeight: number; readonly scale: number };
}
export interface CaptureStamp {
  readonly dom: ClassifiedDOM;
  readonly boxes: readonly number[][];
  readonly layout: CaptureLayout;
  readonly activity: number;
  readonly placement: number;
  readonly surface: Readonly<{ epoch: number; width: number; height: number }>;
}
function acknowledge(value: unknown): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length) throw classifiedRefusal();
}
/** A capture transaction owns actual original-tab exclusion, engine state and
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
  constructor(readonly queue: ActionQueue, readonly documents: HostDocuments, readonly readiness: PageReadiness,
    readonly fields: SensitiveFields, readonly execution: ActionExecution) {
    // Must precede debugger setup, animation/lifecycle operations and geometry.
    this.reservation = queue.reserveCapture(execution);
    this.receipt = this.reservation.original as HostDocument;
  }
  guard = (): void => {
    this.queue.authority.check(this.execution.stamp);
    if (!this.active || this.execution.signal.aborted || performance.now() >= this.execution.deadline) throw staleSnapshot();
    this.reservation.assertOriginal();
    if (this.frame) this.readiness.assertInspection(this.frame, () => this.reservation.assertOriginal());
  };
  private original = (): void => {
    if (!this.active || performance.now() >= this.execution.deadline) throw staleSnapshot();
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
    const view = layout.cssVisualViewport;
    if (!view || ![view.pageX, view.pageY, view.clientWidth, view.clientHeight, view.scale].every(Number.isFinite) ||
        view.clientWidth <= 0 || view.clientHeight <= 0 || view.scale !== 1 ||
        this.readiness.observation(this.receipt).epoch !== activity.epoch ||
        this.documents.presentedEpoch(this.receipt) !== placement || this.surface.sample().epoch !== surface.epoch) throw classifiedRefusal();
    return Object.freeze({ dom, boxes, layout, activity: activity.epoch, placement, surface });
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
    const view = stamp.layout.cssVisualViewport;
    const scale = Math.min(1, 2048 / view.clientWidth, 2048 / view.clientHeight,
      Math.sqrt(2097152 / (view.clientWidth * view.clientHeight)));
    const result = await this.execution.dispatch(() => this.readiness.inspect(this.frame!, this.guard, 'Page.captureScreenshot',
      { format: 'png', fromSurface: true, captureBeyondViewport: false,
        clip: { x: view.pageX, y: view.pageY, width: view.clientWidth, height: view.clientHeight, scale } })) as { data?: unknown };
    this.guard(); if (typeof result.data !== 'string') throw classifiedRefusal(); return { data: result.data };
  }
  async assertSameSurface(stamp: CaptureStamp): Promise<void> {
    this.guard(); if (this.stamp !== stamp) throw classifiedRefusal();
    const after = await this.sample();
    if (stamp.dom.signature !== after.dom.signature || JSON.stringify(stamp.boxes) !== JSON.stringify(after.boxes) ||
        JSON.stringify(stamp.layout) !== JSON.stringify(after.layout) || stamp.activity !== after.activity ||
        stamp.placement !== after.placement || stamp.surface.epoch !== after.surface.epoch ||
        stamp.surface.width !== after.surface.width || stamp.surface.height !== after.surface.height) throw classifiedRefusal();
    // The pinned API returns PNG bytes without a presentation/layout token.
    // Quiescence, unchanged geometry and these invalidation epochs are necessary
    // but cannot by themselves exclude an older queued compositor surface.
    // No production evidence currently establishes that final coupling. Fail
    // closed instead of laundering a CDP reply/frame event/equal images into
    // proof. ABR-16 owns a positive pinned-runtime witness and any required
    // explicitly reviewed producer repair before useful screenshots qualify.
    throw classifiedRefusal();
  }
}
