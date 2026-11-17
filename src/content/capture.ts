import { nativeImage, type NativeImage } from 'electron';
import type { Contract } from '../contracts/generated.js';
import type { CaptureProof, CaptureStamp } from './capture-proof.js';
import { classifiedRefusal } from './sensitive.js';
import type { ActionExecution } from '../host/actions.js';
import type { SnapshotInspection } from './snapshot.js';

const pngSignature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
function dimensions(png: Buffer): { width: number; height: number } {
  if (png.length < 33 || !png.subarray(0, 8).equals(pngSignature) || png.toString('ascii', 12, 16) !== 'IHDR') throw classifiedRefusal();
  const width = png.readUInt32BE(16), height = png.readUInt32BE(20);
  if (!width || !height || width > 16384 || height > 16384 || width * height > 33554432) throw classifiedRefusal();
  return { width, height };
}
/** Mask the full conservative axis-aligned envelope of each root-frame quad,
 * with outward rounding/padding before any resize to avoid edge interpolation.
 * Unbound/OOPIF transforms never reach this function. */
function mask(bitmap: Buffer, width: number, height: number, stamp: CaptureStamp, guard: () => void): void {
  const view = stamp.viewport, sx = width / view.width, sy = height / view.height;
  if (bitmap.length !== width * height * 4 || ![sx, sy].every(Number.isFinite) || sx < 0.125 || sy < 0.125 || sx > 8 || sy > 8 ||
      Math.abs(sx - sy) > Math.max(1 / view.width, 1 / view.height) || stamp.boxes.length > 5000) throw classifiedRefusal();
  const rectangles: { left: number; right: number; top: number; bottom: number }[] = [];
  const clip = (value: number, limit: number) => Math.max(0, Math.min(limit, value));
  let work = 0;
  // Charge the product before the first bitmap write. Overlapping rectangles
  // consume work again; a large mask census cannot multiply a bounded bitmap
  // into unbounded synchronous CPU work past cancellation/watchdog deadlines.
  for (const quad of stamp.boxes) {
    guard(); if (quad.length !== 8 || !quad.every(Number.isFinite)) throw classifiedRefusal();
    const xs = quad.filter((_value, index) => index % 2 === 0), ys = quad.filter((_value, index) => index % 2 === 1);
    const left = clip(Math.floor((Math.min(...xs) - view.x) * sx) - 2, width);
    const right = clip(Math.ceil((Math.max(...xs) - view.x) * sx) + 2, width);
    const top = clip(Math.floor((Math.min(...ys) - view.y) * sy) - 2, height);
    const bottom = clip(Math.ceil((Math.max(...ys) - view.y) * sy) + 2, height);
    if (![left, right, top, bottom].every(Number.isSafeInteger) || right < left || bottom < top ||
        (work += (right - left) * (bottom - top)) > 33554432) throw classifiedRefusal();
    rectangles.push({ left, right, top, bottom });
  }
  for (const { left, right, top, bottom } of rectangles) {
    guard();
    for (let y = top; y < bottom; y++) {
      if ((y - top) % 64 === 0) guard();
      for (let x = left; x < right; x++) {
        const offset = (y * width + x) * 4;
        bitmap[offset] = 0; bitmap[offset + 1] = 0; bitmap[offset + 2] = 0; bitmap[offset + 3] = 255;
      }
    }
  }
  guard();
}

/** Private future provider consumer; the actual screenshot entry stays closed.
 * Only memory-owned buffers exist. In particular, no raw PNG/base64, cached
 * page data or unmasked fallback survives a failed proof or authority check. */
export async function captureViewport(proof: CaptureProof, stamp: CaptureStamp, snapshot: string): Promise<Contract<'browser.ScreenshotPayload'>> {
  let raw: Buffer | undefined, bitmap: Buffer | undefined, output: Buffer | undefined;
  let image: NativeImage | undefined, masked: NativeImage | undefined;
  const pixels = await proof.pixels(stamp);
  try {
    proof.guard();
    if (pixels.data.length > 44 * 1024 * 1024 || pixels.data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(pixels.data)) throw classifiedRefusal();
    raw = Buffer.from(pixels.data, 'base64'); pixels.data = '';
    if (raw.length > 32 * 1024 * 1024) throw classifiedRefusal();
    const { width, height } = dimensions(raw);
    image = nativeImage.createFromBuffer(raw); proof.guard();
    const actual = image.getSize();
    if (image.isEmpty() || actual.width !== width || actual.height !== height) throw classifiedRefusal();
    bitmap = image.toBitmap(); mask(bitmap, width, height, stamp, proof.guard);
    masked = nativeImage.createFromBitmap(bitmap, { width, height, scaleFactor: 1 });
    const scale = Math.min(1, 2048 / width, 2048 / height, Math.sqrt(2097152 / (width * height)));
    if (scale < 1) masked = masked.resize({ width: Math.max(1, Math.floor(width * scale)), height: Math.max(1, Math.floor(height * scale)), quality: 'best' });
    // Encoding for delivery is unreachable until the actual same-surface proof.
    await proof.assertSameSurface(stamp); proof.guard();
    output = masked.toPNG(); const final = dimensions(output);
    if (output.length > 4 * 1024 * 1024 || final.width > 2048 || final.height > 2048 || final.width * final.height > 2097152) throw classifiedRefusal();
    proof.guard(); const authority = proof.execution.stamp;
    return { metadata: { tab: authority.target.id, snapshot, navigation: authority.document.navigation,
      controlGeneration: authority.generation, mimeType: 'image/png', width: final.width, height: final.height, redacted: stamp.boxes.length > 0 },
      data: output.toString('base64') };
  } finally {
    pixels.data = ''; raw?.fill(0); bitmap?.fill(0); output?.fill(0); image = undefined; masked = undefined;
  }
}
/** Until an authenticated positive provider exists, refuse after the original
 * authority/snapshot checks and before reserving capture or touching a renderer.
 * Actual touched-operation restoration/retirement remains with CaptureProof. */
export async function inspectScreenshot(inspection: SnapshotInspection, execution: ActionExecution,
  snapshot: string): Promise<Contract<'browser.ScreenshotPayload'>> {
  const guard = inspection.guard(execution);
  guard(); inspection.authority.requireSnapshot(snapshot, execution.stamp, false);
  throw classifiedRefusal();
}
