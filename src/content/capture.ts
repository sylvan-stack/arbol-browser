import { nativeImage, type NativeImage } from 'electron';
import type { Contract } from '../contracts/generated.js';
import type { CaptureProof, CaptureStamp } from './capture-proof.js';
import { classifiedRefusal } from './sensitive.js';

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
function mask(bitmap: Buffer, width: number, height: number, stamp: CaptureStamp): void {
  const view = stamp.layout.cssVisualViewport, sx = width / view.clientWidth, sy = height / view.clientHeight;
  if (bitmap.length !== width * height * 4 || !Number.isFinite(sx) || !Number.isFinite(sy)) throw classifiedRefusal();
  for (const quad of stamp.boxes) {
    if (quad.length !== 8 || !quad.every(Number.isFinite)) throw classifiedRefusal();
    const xs = quad.filter((_value, index) => index % 2 === 0), ys = quad.filter((_value, index) => index % 2 === 1);
    const left = Math.max(0, Math.floor((Math.min(...xs) - view.pageX) * sx) - 2);
    const right = Math.min(width, Math.ceil((Math.max(...xs) - view.pageX) * sx) + 2);
    const top = Math.max(0, Math.floor((Math.min(...ys) - view.pageY) * sy) - 2);
    const bottom = Math.min(height, Math.ceil((Math.max(...ys) - view.pageY) * sy) + 2);
    for (let y = top; y < bottom; y++) for (let x = left; x < right; x++) {
      const offset = (y * width + x) * 4;
      bitmap[offset] = 0; bitmap[offset + 1] = 0; bitmap[offset + 2] = 0; bitmap[offset + 3] = 255;
    }
  }
}
/** Only memory-owned buffers exist. In particular, no raw PNG/base64, cached
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
    bitmap = image.toBitmap(); mask(bitmap, width, height, stamp);
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
