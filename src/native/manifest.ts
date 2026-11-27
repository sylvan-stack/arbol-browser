/** The publisher anchor is source policy, never derived from a running package. */
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { basename, join, dirname, resolve, sep, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { assertPlatform, type PlatformPort } from '../runtime/platform.js';

// Trust covers physical signed bytes, including ASAR archives, on every check.
// Browser verification uses the mandatory unpatched Electron builtin. The Node
// CLI has an unpatched filesystem already and never imports Electron code.
// NodeMain uses the same ASAR wrapper as the browser. Builtin-only access
// cannot resolve an ambient original-fs package; actual Electron must provide
// its genuine unpatched builtin or refuse. Plain Node retains its own fs.
const physicalFS = process.getBuiltinModule(typeof process.versions.electron === 'string' ? 'original-fs' : 'fs') as typeof import('node:fs') | undefined;
if (!physicalFS || typeof physicalFS.openSync !== 'function' || !physicalFS.promises ||
    typeof physicalFS.promises.open !== 'function') throw new Error('native_candidate_unavailable');
const { constants, lstatSync, openSync, fstatSync, readSync, writeSync, closeSync, opendirSync, readlinkSync, realpathSync } = physicalFS;

export const publisher = Object.freeze({ team: '7V372XL59S', bundleIdentifier: 'com.sylvan-stack.arbol-browser.native-candidate',
  requirement: 'anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' });
export const productionPublisher = Object.freeze({ ...publisher, bundleIdentifier: 'com.sylvan-stack.arbol-browser' });
type PublisherScope = 'isolated' | 'production';
export const pinnedRuntime = Object.freeze({ electron: '45.3.2', chromium: '156.0.8078.100', node: '24.22.2', napi: '10', modules: '150', platform: 'darwin', arch: 'arm64', macOS: '27.0.1' });
export const nativeLimit = 1048576;
export type Compatibility = Contract<'native.BuildCompatibility'>;
export function refuse(): never { throw new Error('native_candidate_unavailable'); }
export type SignedVerificationPhase = 'bundle-selection' | 'initial-snapshot' |
  'outer-signature-verification' | 'outer-signature-details' | 'outer-signature-entitlements' |
  'nested-signature-verification' | 'nested-signature-details' | 'nested-signature-entitlements' |
  'publisher' | 'compatibility' | 'inventory' | 'final-snapshot' | 'final-physical-comparison' |
  'repeated-snapshot' | 'repeated-physical' | 'repeated-manifest' | 'repeated-cutoff' | 'snapshot-receipt' | 'verification-cutoff' |
  'snapshot-root-identity' | 'snapshot-root-change-time' | 'snapshot-entry-identity' | 'snapshot-file-description' | 'snapshot-file-read' |
  'storage-context' | 'snapshot-symlink' | 'snapshot-directory-membership' | 'snapshot-encoded-mismatch' | 'snapshot-filesystem';
const verificationFailures = new WeakMap<Error, SignedVerificationPhase>();
function noteVerificationFailure(error: unknown, phase: SignedVerificationPhase): void {
  try { if (error instanceof Error && !verificationFailures.has(error)) verificationFailures.set(error, phase); }
  catch { /* Diagnostics cannot replace the original failure. */ }
}
/** Read only a genuine same-module failure; caller-created errors have no phase. */
export function readSignedVerificationPhase(error: unknown): SignedVerificationPhase | undefined {
  try { return error instanceof Error ? verificationFailures.get(error) : undefined; }
  catch { return undefined; }
}
/** Preserve each existing redaction's newly thrown Error, with its first phase. */
function refuseVerification(phase: SignedVerificationPhase, original?: unknown): never {
  try { return refuse(); }
  catch (error) { noteVerificationFailure(error, readSignedVerificationPhase(original) ?? phase); throw error; }
}
type SnapshotIdentityPhase = 'snapshot-root-identity' | 'snapshot-entry-identity';
interface SnapshotFailure { first?: SignedVerificationPhase }
/** Comparison-local observation only. Capture before poison/finally can replace
 * an Error. A peer's unbranded poison refusal cannot become the first cause. */
function noteSnapshotFailure(observed: SnapshotFailure | undefined, error: unknown, fallback?: SignedVerificationPhase): void {
  try {
    const phase = readSignedVerificationPhase(error) ?? observed?.first ?? fallback;
    if (!phase) return;
    noteVerificationFailure(error, phase);
    if (observed && observed.first === undefined) observed.first = phase;
  } catch { /* Observation cannot affect refusal, cleanup or authority. */ }
}
function refuseSnapshot(phase: SignedVerificationPhase, observed?: SnapshotFailure): never {
  try { return refuseVerification(phase); }
  catch (error) { noteSnapshotFailure(observed, error); throw error; }
}
function snapshotFilesystem<T>(operation: () => T, observed?: SnapshotFailure): T {
  try { return operation(); }
  catch (error) { noteSnapshotFailure(observed, error, 'snapshot-filesystem'); throw error; }
}
function rejectSnapshotFilesystem(error: unknown, observed?: SnapshotFailure): unknown {
  noteSnapshotFailure(observed, error, 'snapshot-filesystem'); return error;
}
export function boundedJson(path: string, deadline = Infinity, expectedDevice?: bigint): unknown {
  budget(deadline);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd), named = lstatSync(path);
    const mounted = expectedDevice === undefined ? undefined : fstatSync(fd, { bigint: true });
    if (!stat.isFile() || !named.isFile() || stat.dev !== named.dev || stat.ino !== named.ino ||
        stat.nlink !== 1 || named.nlink !== 1 || stat.size < 1 || stat.size > nativeLimit) return refuse();
    if (mounted && (mounted.dev !== expectedDevice ||
        physicalStamp(lstatSync(path, { bigint: true })) !== physicalStamp(mounted))) return refuse();
    const buffer = Buffer.alloc(stat.size + 1); let length = 0;
    while (length < buffer.length) {
      budget(deadline); const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (!n) break; length += n;
    }
    const raw = buffer.subarray(0, length), after = fstatSync(fd), lastName = lstatSync(path);
    budget(deadline);
    if (raw.length !== stat.size || after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size ||
        after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs || !lastName.isFile() ||
        lastName.dev !== after.dev || lastName.ino !== after.ino || lastName.nlink !== 1 ||
        lastName.size !== after.size || lastName.mtimeMs !== after.mtimeMs || lastName.ctimeMs !== after.ctimeMs) return refuse();
    if (mounted && (physicalStamp(fstatSync(fd, { bigint: true })) !== physicalStamp(mounted) ||
        physicalStamp(lstatSync(path, { bigint: true })) !== physicalStamp(mounted))) return refuse();
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } finally { closeSync(fd); }
}
export function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b, 'en')).map(([key, v]) => `${JSON.stringify(key)}:${stable(v)}`).join(',')}}`;
  return JSON.stringify(value);
}
function budget(deadline: number): number {
  if (deadline !== Infinity && (!Number.isFinite(deadline) || performance.now() >= deadline)) refuseVerification('verification-cutoff');
  return deadline === Infinity ? 5000 : Math.max(1, Math.min(5000, Math.floor(deadline - performance.now())));
}
// Only returned bytes are hashed. Keep tiny entries cheap while avoiding a
// filesystem request for every 64 KiB of the embedded runtime.
function fileReadBuffer(size: number): Buffer {
  return Buffer.allocUnsafe(Math.min(512 * 1024, Math.max(1, size)));
}
/** Hash and inspect one verified description, with exactly one overflow byte.
 * Nonblocking no-follow open must precede fstat so a substituted FIFO cannot
 * wait for a writer. Physical symlinks are handled separately by the caller. */
function physicalFile(path: string, named: import('node:fs').Stats, deadline: number, observed?: SnapshotFailure): { digest: string; magic: string } {
  budget(deadline);
  const fd = snapshotFilesystem(() => openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK), observed);
  try {
    const first = snapshotFilesystem(() => fstatSync(fd), observed);
    if (!first.isFile() || !named.isFile() || first.dev !== named.dev || first.ino !== named.ino ||
        first.nlink !== 1 || named.nlink !== 1 || first.mode !== named.mode || first.uid !== named.uid ||
        !Number.isSafeInteger(first.size) || first.size < 0 || snapshotFilesystem(() => realpathSync(path), observed) !== path) refuseSnapshot('snapshot-file-description', observed);
    const hash = createHash('sha256'), buffer = fileReadBuffer(first.size), header = Buffer.alloc(4);
    let offset = 0;
    while (offset < first.size) {
      budget(deadline);
      const n = snapshotFilesystem(() => readSync(fd, buffer, 0, Math.min(buffer.length, first.size - offset), null), observed);
      if (n < 1) refuseSnapshot('snapshot-file-read', observed);
      if (offset < 4) buffer.copy(header, offset, 0, Math.min(n, 4 - offset));
      hash.update(buffer.subarray(0, n)); offset += n;
    }
    if (snapshotFilesystem(() => readSync(fd, buffer, 0, 1, null), observed) !== 0) refuseSnapshot('snapshot-file-read', observed);
    const last = snapshotFilesystem(() => fstatSync(fd), observed), after = snapshotFilesystem(() => lstatSync(path), observed); budget(deadline);
    if (!after.isFile() || first.dev !== last.dev || first.ino !== last.ino || first.size !== last.size ||
        first.mode !== last.mode || first.uid !== last.uid || last.nlink !== 1 ||
        first.mtimeMs !== last.mtimeMs || first.ctimeMs !== last.ctimeMs ||
        after.dev !== last.dev || after.ino !== last.ino || after.size !== last.size || after.nlink !== 1 ||
        after.mode !== last.mode || after.uid !== last.uid || after.mtimeMs !== last.mtimeMs || after.ctimeMs !== last.ctimeMs ||
        snapshotFilesystem(() => realpathSync(path), observed) !== path) refuseSnapshot('snapshot-file-description', observed);
    return { digest: hash.digest('hex'), magic: header.subarray(0, Math.min(first.size, 4)).toString('hex') };
  } catch (error) { noteSnapshotFailure(observed, error); throw error; } finally { snapshotFilesystem(() => closeSync(fd), observed); }
}
function signature(path: string, outer: boolean, jit: boolean, deadline: number,
  expectedPublisher: typeof publisher | typeof productionPublisher): void {
  let phase: SignedVerificationPhase = outer ? 'outer-signature-verification' : 'nested-signature-verification';
  try {
    const requirement = expectedPublisher.requirement + (outer ? ` and identifier "${expectedPublisher.bundleIdentifier}"` : '');
    const result = spawnSync('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R', `=${requirement}`, path],
      { timeout: budget(deadline), maxBuffer: nativeLimit, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
    budget(deadline);
    if (result.error || result.status !== 0) refuse();
    phase = outer ? 'outer-signature-details' : 'nested-signature-details';
    const details = spawnSync('/usr/bin/codesign', ['-dvvv', '--entitlements', ':-', path],
      { timeout: budget(deadline), maxBuffer: nativeLimit, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
    budget(deadline);
    if (details.error || details.status !== 0 || !details.stderr.includes(`TeamIdentifier=${expectedPublisher.team}`) ||
        !details.stderr.includes('runtime)') || !details.stderr.includes('Timestamp=')) refuse();
    phase = outer ? 'outer-signature-entitlements' : 'nested-signature-entitlements';
    if (/com\.apple\.security\.(?:cs\.(?:disable-library-validation|allow-unsigned-executable-memory|allow-dyld-environment-variables)|get-task-allow)/.test(details.stdout + details.stderr)) refuse();
    const keys = [...details.stdout.matchAll(/<key>([^<]+)<\/key>/g)].map(match => match[1]);
    if (keys.length > 1 || keys.some(key => key !== 'com.apple.security.cs.allow-jit' || !jit) ||
        (keys.length && !/<key>com\.apple\.security\.cs\.allow-jit<\/key>\s*<true\s*\/>/.test(details.stdout))) refuse();
  } catch (error) { noteVerificationFailure(error, phase); throw error; }
}
export interface CandidateTrust {
  readonly bundle: string;
  readonly manifest: Readonly<Compatibility>;
  readonly snapshotDigest: string;
  /** Cryptographic identity only. It cannot assert previous exit or production qualification. */
  assertIdentity(deadline?: number, retainStartupBytes?: boolean): void;
}
/** Independently verified signed bytes, without the installed Native brand.
 * Node clients may verify two different retained Builds. Only the host's one
 * verifyNativeCandidate result is eligible for addon/watchdog installation. */
export type SignedBundle = CandidateTrust;
interface PhysicalEntry {
  readonly stamp: string;
  readonly kind: 'file' | 'directory' | 'symlink';
  readonly children?: readonly string[];
  readonly link?: string;
  readonly target?: string;
}
interface FrozenSnapshot {
  readonly storage: StorageContext | undefined;
  readonly mounted: MountedBundleRead | undefined;
  readonly encoded: string;
  readonly physical: Readonly<Record<string, PhysicalEntry>>;
  poisoned: boolean;
}
const signedSnapshots = new WeakMap<SignedBundle, FrozenSnapshot>();
export interface SignedSnapshotComparison { readonly deadline: number }
const comparisons = new WeakMap<SignedSnapshotComparison, {
  signed: SignedBundle; snapshot: FrozenSnapshot; nativeStartup: boolean; used: boolean; expiry: ReturnType<typeof setTimeout>;
}>();
function physicalStamp(stat: import('node:fs').BigIntStats): string {
  return stable([stat.dev, stat.ino, stat.mode, stat.uid, stat.gid, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs, stat.birthtimeNs].map(String));
}

/** Construction-only stock Apple metadata. No candidate Native or ambient
 * interpreter participates in pretrust identity. Later boundaries use only
 * captured original filesystem functions and never learn another baseline. */
const helperPath = '/System/Library/PrivateFrameworks/DiskImages.framework/Versions/A/Resources/diskimages-helper';
const kernelIdentityScript = String.raw`ObjC.import('Foundation');
ObjC.bindFunction('getpid', ['int', []]);
ObjC.bindFunction('getuid', ['unsigned int', []]);
ObjC.bindFunction('geteuid', ['unsigned int', []]);
ObjC.bindFunction('sysctl', ['int', ['pointer', 'unsigned int', 'pointer', 'pointer', 'pointer', 'unsigned long']]);
function enc(a) {
  const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let s = '';
  for (let i = 0; i < a.length; i += 3) {
    const n = (a[i] << 16) | ((a[i + 1] || 0) << 8) | (a[i + 2] || 0);
    s += c[(n >>> 18) & 63] + c[(n >>> 12) & 63] +
      (i + 1 < a.length ? c[(n >>> 6) & 63] : '=') + (i + 2 < a.length ? c[n & 63] : '=');
  }
  return s;
}
function dec(s) {
  const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let a = [], n = 0, b = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=') break;
    const v = c.indexOf(s[i]);
    if (v < 0) throw Error('non-base64 output');
    n = (n << 6) | v;
    b += 6;
    if (b >= 8) {
      b -= 8;
      a.push((n >>> b) & 255);
    }
  }
  return a;
}
function le(a, o, n) {
  let v = 0;
  for (let i = 0; i < n; i++) v += a[o + i] * Math.pow(256, i);
  return v;
}
function i32(a, o) {
  const v = le(a, o, 4);
  return v > 2147483647 ? v - 4294967296 : v;
}
function bytes(a, mutable) {
  const d = $.NSData.alloc.initWithBase64EncodedStringOptions($(enc(a)), 0);
  return mutable ? d.mutableCopy : d;
}
function run(argv) {
  const cutoff = Date.now() + 30000;
  const ownPid = Number($.getpid()), uid = Number($.getuid()), euid = Number($.geteuid());
  if (argv.length !== 1 || !/^[1-9][0-9]*$/.test(argv[0])) throw Error('one canonical PID input required');
  const pid = Number(argv[0]);
  if (!Number.isSafeInteger(pid) || pid > 2147483647) throw Error('PID range');
  const a = [];
  for (const v of [1, 14, 1, pid]) {
    for (let j = 0; j < 4; j++) a.push((v >>> 8 * j) & 255);
  }
  const mib = bytes(a, false), size = bytes([136, 2, 0, 0, 0, 0, 0, 0], true);
  const out = $.NSMutableData.dataWithLength(648);
  if (Number(mib.length) !== 16 || Number(size.length) !== 8 || Number(out.length) !== 648)
    throw Error('bounded buffer length mismatch');
  const rc = $.sysctl(mib.bytes, 4, out.mutableBytes, size.mutableBytes, null, 0);
  const n = le(dec(ObjC.unwrap(size.base64EncodedStringWithOptions(0))), 0, 8);
  const raw = ObjC.unwrap(out.base64EncodedStringWithOptions(0)), b = dec(raw);
  if (rc !== 0 || n !== 648 || b.length !== 648) throw Error('own PID sysctl refused rc=' + rc + ' length=' + n);
  const parsed = {
    pid: i32(b, 40), effectiveUid: le(b, 420, 4), realUid: le(b, 392, 4),
    startSeconds: le(b, 0, 8), startMicroseconds: i32(b, 8), padding12through15: b.slice(12, 16)
  };
  if (parsed.pid !== pid || parsed.effectiveUid !== euid || parsed.realUid !== uid ||
      parsed.startSeconds <= 0 || parsed.startSeconds > Date.now() / 1000 ||
      parsed.startMicroseconds < 0 || parsed.startMicroseconds >= 1000000) throw Error('own kernel identity/parse mismatch');
  if (Date.now() > cutoff) throw Error('original local cutoff exceeded');
  return JSON.stringify({
    format: 1, complete: true, route: 'stock Apple osascript JXA linked libc numeric-MIB sysctl',
    ownPid: ownPid, targetPid: pid, ownUid: uid, ownEffectiveUid: euid, mib: [1, 14, 1, pid],
    returnCode: rc, capacityBytes: 648, returnedBytes: n, rawBase64: raw, parsed: parsed,
    paddingIsNotMicroseconds: true, localCutoff: cutoff, finishedAt: Date.now(), queries: 1,
    attachments: 0, productionAddonLoaded: false, qualificationCredit: false
  });
}
`;
interface StorageDescription { readonly fd: number; readonly path: string; readonly stamp: string; readonly directory: boolean }
interface StorageContext {
  readonly descriptions: readonly [StorageDescription, StorageDescription];
  readonly mapping: string;
  readonly snapshotDigest?: string;
}
const installedStartupTopologies = new WeakMap<StorageContext, () => void>();
const storageFinalizer = new FinalizationRegistry<readonly StorageDescription[]>(descriptions => {
  for (const description of descriptions) {
    try { closeSync(description.fd); }
    catch { /* Resource disposal only. */ }
  }
});
function appleQuery(program: string, args: string[], deadline: number, input?: string): string {
  const result = spawnSync(program, args, { input, timeout: budget(deadline), maxBuffer: nativeLimit,
    encoding: 'utf8', env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } });
  budget(deadline);
  if (result.error || result.status !== 0 || Buffer.byteLength(result.stdout) > nativeLimit) refuseVerification('storage-context');
  return result.stdout;
}
function applePlist(program: string, args: string[], deadline: number): Record<string, unknown> {
  const raw = appleQuery(program, args, deadline);
  const value: unknown = JSON.parse(appleQuery('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], deadline, raw));
  if (!value || typeof value !== 'object' || Array.isArray(value)) return refuseVerification('storage-context');
  return value as Record<string, unknown>;
}
function storageAssert(context: StorageContext | undefined, deadline: number): void {
  if (!context) return;
  try {
    budget(deadline);
    for (const d of context.descriptions) {
      const held = fstatSync(d.fd, { bigint: true }), named = lstatSync(d.path, { bigint: true });
      if ((d.directory ? !held.isDirectory() || !named.isDirectory() : !held.isFile() || !named.isFile() || held.nlink !== 1n) ||
          physicalStamp(held) !== d.stamp || physicalStamp(named) !== d.stamp || realpathSync(d.path) !== d.path) refuse();
    }
    budget(deadline);
  } catch (error) { return refuseVerification('storage-context', error); }
}
function assertNativeStartupTopology(context: StorageContext | undefined, deadline: number): boolean {
  if (!context) return false;
  const check = installedStartupTopologies.get(context);
  if (!check) return false;
  storageAssert(context, deadline);
  check();
  storageAssert(context, deadline);
  return true;
}
function retainedDescription(path: string, directory: boolean): StorageDescription {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | (directory ? constants.O_DIRECTORY : 0));
  try {
    const held = fstatSync(fd, { bigint: true }), named = lstatSync(path, { bigint: true });
    if ((directory ? !held.isDirectory() : !held.isFile() || held.nlink !== 1n) ||
        physicalStamp(held) !== physicalStamp(named) || realpathSync(path) !== path) refuse();
    return Object.freeze({ fd, path, directory, stamp: physicalStamp(held) });
  } catch (error) { closeSync(fd); throw error; }
}
function containingVolume(path: string, deadline: number): Record<string, unknown> {
  const original = lstatSync(path, { bigint: true });
  if (realpathSync(path) !== path) return refuse();
  const rows = appleQuery('/bin/df', ['-P', path], deadline).trim().split('\n');
  if (rows.length !== 2 || !rows[0]?.startsWith('Filesystem')) return refuse();
  const fields = rows[1]?.trim().split(/\s+/);
  const devicePath = fields?.[0];
  if (!fields || fields.length < 6 || !devicePath || !/^\/dev\/disk[0-9]+(?:s[0-9]+)*$/.test(devicePath) ||
      fields.slice(1, 4).some(value => !/^[0-9]+$/.test(value)) || !/^[0-9]+%$/.test(fields[4] ?? '')) return refuse();
  const device = lstatSync(devicePath, { bigint: true });
  const volume = applePlist('/usr/sbin/diskutil', ['info', '-plist', devicePath], deadline);
  if (!device.isBlockDevice() || device.rdev !== original.dev || volume.DeviceNode !== devicePath ||
      typeof volume.MountPoint !== 'string' || realpathSync(volume.MountPoint) !== volume.MountPoint) return refuse();
  const mounted = lstatSync(volume.MountPoint, { bigint: true });
  if (!mounted.isDirectory() || mounted.dev !== original.dev ||
      physicalStamp(lstatSync(path, { bigint: true })) !== physicalStamp(original) || realpathSync(path) !== path) return refuse();
  return volume;
}
function storageMapping(root: string, deadline: number): { volume: Record<string, unknown>; image?: Record<string, unknown>; key: string } {
  const volume = containingVolume(root, deadline);
  const info = applePlist('/usr/bin/hdiutil', ['info', '-plist'], deadline);
  if (!Array.isArray(info.images) || typeof volume.MountPoint !== 'string' ||
      typeof volume.DeviceNode !== 'string' || !/^\/dev\/disk[0-9]+(?:s[0-9]+)*$/.test(volume.DeviceNode) ||
      !['apfs', 'hfs'].includes(String(volume.FilesystemType))) refuse();
  const matches: Record<string, unknown>[] = [];
  for (const item of info.images) {
    if (!item || typeof item !== 'object' || !Array.isArray(item['system-entities'])) refuse();
    for (const entity of item['system-entities']) {
      if (!entity || typeof entity !== 'object') refuse();
      if (entity['dev-entry'] === volume.DeviceNode || entity['mount-point'] === volume.MountPoint) {
        if (entity['dev-entry'] !== volume.DeviceNode || entity['mount-point'] !== volume.MountPoint || matches.includes(item)) refuse();
        matches.push(item);
      }
    }
  }
  const device = lstatSync(volume.DeviceNode, { bigint: true });
  const mounted = lstatSync(volume.MountPoint, { bigint: true });
  if (!device.isBlockDevice() || !mounted.isDirectory() || device.rdev !== mounted.dev ||
      mounted.dev !== lstatSync(root, { bigint: true }).dev || realpathSync(volume.MountPoint) !== volume.MountPoint) refuse();
  if (!matches.length) {
    // Absence of an hdiutil row alone never establishes ordinary storage.
    if (volume.Internal !== true || !['Apple Fabric', 'PCI-Express', 'SATA', 'NVMe'].includes(String(volume.BusProtocol))) refuse();
    return { volume, key: stable([volume.DeviceNode, volume.MountPoint, String(mounted.dev), volume.BusProtocol]) };
  }
  if (matches.length !== 1) return refuse();
  const image = matches[0];
  if (!image) return refuse();
  const pid = image['hdid-pid'];
  if (volume.BusProtocol !== 'Disk Image' || volume.FilesystemType !== 'apfs' || volume.Writable !== false ||
      volume.WritableMedia !== false || volume.WritableVolume !== false || image.diskimages2 !== false ||
      image['image-type'] !== 'UDIF read-only' || image.writeable !== false || image['image-encrypted'] !== false ||
      image['owner-uid'] !== process.getuid?.() || !Number.isSafeInteger(pid) || Number(pid) <= 0 || Number(pid) > 2147483647 ||
      typeof image['image-path'] !== 'string' || !image['image-path'].startsWith('/') ||
      realpathSync(image['image-path']) !== image['image-path'] ||
      Object.keys(image).some(key => /shadow|overlay/i.test(key))) refuse();
  return { volume, image, key: stable([volume.DeviceNode, volume.MountPoint, String(mounted.dev), image['image-path'],
    pid, image['owner-uid'], image.diskimages2, image['image-type'], image.writeable, image['system-entities']]) };
}
function helperKernel(pid: number, deadline: number): string {
  const value = JSON.parse(appleQuery('/usr/bin/osascript', ['-l', 'JavaScript', '-e', kernelIdentityScript, String(pid)], deadline));
  if (value.complete !== true || value.targetPid !== pid || value.capacityBytes !== 648 || value.returnedBytes !== 648 ||
      value.returnCode !== 0 || typeof value.rawBase64 !== 'string') refuse();
  const raw = Buffer.from(value.rawBase64, 'base64');
  if (raw.length !== 648 || raw.toString('base64') !== value.rawBase64) refuse();
  const seconds = raw.readBigInt64LE(0), micros = raw.readInt32LE(8), uid = process.getuid?.();
  if (raw.readInt32LE(40) !== pid || raw.readUInt32LE(420) !== uid || raw.readUInt32LE(392) !== uid ||
      seconds <= 0n || seconds > BigInt(Math.floor(Date.now() / 1000)) || micros < 0 || micros >= 1000000) refuse();
  return stable([pid, String(seconds), micros, uid]);
}
function helperBacking(image: Record<string, unknown>, backing: StorageDescription, deadline: number): void {
  const pid = Number(image['hdid-pid']);
  const before = helperKernel(pid, deadline);
  const text = lstatSync(helperPath, { bigint: true });
  if (!text.isFile() || text.uid !== 0n || (text.mode & 0o022n) !== 0n || (text.mode & 0o111n) === 0n || realpathSync(helperPath) !== helperPath) refuse();
  appleQuery('/usr/bin/codesign', ['--verify', '--strict', '-R=anchor apple', helperPath], deadline);
  const raw = appleQuery('/usr/sbin/lsof', ['-nP', '-a', '-p', String(pid), '-F0pucfatDin'], deadline);
  const processFields: Record<string, string> = {}, files: Record<string, string>[] = [];
  let current = processFields;
  for (let field of raw.split('\0')) {
    field = field.replace(/^\n/, '');
    if (!field) continue;
    const tag = field.charAt(0), value = field.slice(1);
    if (tag === 'f') {
      current = { f: value };
      files.push(current);
    } else {
      if (!'pucfatDin'.includes(tag) || Object.hasOwn(current, tag)) refuse();
      current[tag] = value;
    }
  }
  if (processFields.p !== String(pid) || processFields.u !== String(process.getuid?.()) || !processFields.c) refuse();
  const vnode = (row: Record<string, string>, st: import('node:fs').BigIntStats): boolean => {
    const device = row.D, inode = row.i;
    if (typeof device !== 'string' || typeof inode !== 'string' ||
        !/^0x[0-9a-f]+$/i.test(device) || !/^(0|[1-9][0-9]*)$/.test(inode)) return false;
    return BigInt(device) === st.dev && BigInt(inode) === st.ino;
  };
  const numeric = files.filter(row => /^[0-9]+$/.test(row.f ?? ''));
  if (new Set(numeric.map(row => row.f)).size !== numeric.length || numeric.some(row => !row.t || !row.a)) refuse();
  const regular = numeric.filter(row => row.t === 'REG');
  const held = fstatSync(backing.fd, { bigint: true });
  if (!regular.length || regular.some(row => row.a !== 'r' || !vnode(row, held)) ||
      !files.some(row => row.f === 'txt' && row.t === 'REG' && vnode(row, text)) ||
      physicalStamp(lstatSync(helperPath, { bigint: true })) !== physicalStamp(text) || helperKernel(pid, deadline) !== before) refuse();
}
function discoverStorage(root: string, deadline: number): StorageContext | undefined {
  const descriptions: StorageDescription[] = [];
  try {
    const mapping = storageMapping(root, deadline);
    if (!mapping.image) return undefined;
    const rootDescription = retainedDescription(root, true);
    descriptions.push(rootDescription);
    const backingDescription = retainedDescription(String(mapping.image['image-path']), false);
    descriptions.push(backingDescription);
    if (storageMapping(backingDescription.path, deadline).image) refuse();
    const backing = fstatSync(backingDescription.fd, { bigint: true });
    if (backing.uid !== BigInt(process.getuid?.() ?? -1) || (backing.mode & 0o022n)) refuse();
    const context = Object.freeze({ descriptions: Object.freeze([rootDescription, backingDescription] as const), mapping: mapping.key });
    helperBacking(mapping.image, backingDescription, deadline);
    if (storageMapping(root, deadline).key !== context.mapping) refuse();
    storageAssert(context, deadline);
    return context;
  } catch (error) {
    for (const d of descriptions) {
      try { closeSync(d.fd); }
      catch { /* Preserve refusal. */ }
    }
    return refuseVerification('storage-context', error);
  }
}
function revalidateStorage(root: string, context: StorageContext | undefined, deadline: number): void {
  if (!context) {
    if (storageMapping(root, deadline).image) refuseVerification('storage-context');
    return;
  }
  try {
    storageAssert(context, deadline);
    const mapping = storageMapping(root, deadline);
    if (!mapping.image || mapping.key !== context.mapping) refuse();
    helperBacking(mapping.image, context.descriptions[1], deadline);
    if (storageMapping(root, deadline).key !== context.mapping) refuse();
    storageAssert(context, deadline);
  } catch (error) { return refuseVerification('storage-context', error); }
}

// The signed release bootstrap is a thin arm64 Mach-O with a SHA-256
// CodeDirectory. Derive its live-code requirement from the original open
// description, so a different executable cannot supply the expected hash.
function startupCodeDirectoryHash(executable: StorageDescription, deadline: number): string {
  const original = fstatSync(executable.fd, { bigint: true });
  if (physicalStamp(original) !== executable.stamp || original.size < 32n || original.size > BigInt(nativeLimit)) return refuse();
  const bytes = Buffer.alloc(Number(original.size));
  for (let at = 0; at < bytes.length;) {
    budget(deadline);
    const count = readSync(executable.fd, bytes, at, bytes.length - at, at);
    if (count < 1) return refuse();
    at += count;
  }
  if (physicalStamp(fstatSync(executable.fd, { bigint: true })) !== executable.stamp ||
      bytes.readUInt32LE(0) !== 0xfeedfacf || bytes.readUInt32LE(4) !== 0x0100000c) return refuse();
  const end = 32 + bytes.readUInt32LE(20);
  const count = bytes.readUInt32LE(16);
  if (end > bytes.length || count < 1 || count > (end - 32) / 8) return refuse();
  let signature: Buffer | undefined;
  let at = 32;
  for (let index = 0; index < count; ++index) {
    if (at + 8 > end) return refuse();
    const kind = bytes.readUInt32LE(at), size = bytes.readUInt32LE(at + 4);
    if (size < 8 || size % 8 || at + size > end) return refuse();
    if (kind === 0x1d) { // LC_CODE_SIGNATURE
      if (signature || size !== 16) return refuse();
      const start = bytes.readUInt32LE(at + 8), length = bytes.readUInt32LE(at + 12);
      if (start < end || length < 12 || start + length > bytes.length) return refuse();
      signature = bytes.subarray(start, start + length);
    }
    at += size;
  }
  if (at !== end || !signature || signature.readUInt32BE(0) !== 0xfade0cc0) return refuse(); // Embedded signature SuperBlob
  const length = signature.readUInt32BE(4), slots = signature.readUInt32BE(8);
  const tableEnd = 12 + slots * 8;
  if (length > signature.length || tableEnd > length) return refuse();
  let hash: string | undefined;
  for (let index = 0; index < slots; ++index) {
    const slot = 12 + index * 8;
    if (signature.readUInt32BE(slot) !== 0) continue; // Primary CodeDirectory
    const offset = signature.readUInt32BE(slot + 4);
    if (hash || offset < tableEnd || offset + 44 > length || signature.readUInt32BE(offset) !== 0xfade0c02) return refuse();
    const size = signature.readUInt32BE(offset + 4);
    if (size < 44 || offset + size > length || signature[offset + 36] !== 32 || signature[offset + 37] !== 2) return refuse();
    hash = createHash('sha256').update(signature.subarray(offset, offset + size)).digest('hex').slice(0, 40);
  }
  return hash ?? refuse();
}

const installedVerifierBroker = `
ObjC.import('Foundation');
function run(argv) {
  const task = $.NSTask.alloc.init;
  const gate = $.NSPipe.pipe;
  const writer = gate.fileHandleForWriting;
  const discard = $.NSFileHandle.fileHandleWithNullDevice;
  task.launchPath = argv[0];
  const requestArgs = ['--arbol-verify-installed-package', argv[1]];
  if (argv[3]) requestArgs.push(argv[3]);
  task.arguments = $(requestArgs);
  task.environment = $({ PATH: '/usr/bin:/bin' });
  task.standardInput = gate;
  task.standardOutput = $.NSFileHandle.alloc.initWithFileDescriptorCloseOnDealloc(3, false);
  task.standardError = $.NSFileHandle.alloc.initWithFileDescriptorCloseOnDealloc(4, false);
  try {
    if (!task.launchAndReturnError(null)) return 'refused';
    const verification = $.NSTask.alloc.init;
    verification.launchPath = '/usr/bin/codesign';
    verification.arguments = $(['--verify', '--strict', '-R', '=' + argv[2], String(task.processIdentifier)]);
    verification.environment = task.environment;
    verification.standardInput = discard;
    verification.standardOutput = discard;
    verification.standardError = discard;
    if (!verification.launchAndReturnError(null)) return 'refused';
    verification.waitUntilExit;
    if (verification.terminationStatus !== 0 || !task.running) return 'refused';
    writer.writeData($('1').dataUsingEncoding($.NSUTF8StringEncoding));
    task.waitUntilExit;
    return task.terminationStatus === 0 ? 'verified' : 'refused';
  } finally {
    writer.closeFile;
    if (task.running) task.terminate;
  }
}
`;

// These earlier production releases use the same authenticated verifier
// contract. Identify its exact signed code by the original open descriptor.
const retainedStartupVerifiers: Readonly<Record<string, string>> = Object.freeze({
  '28': 'abf912a74384efe8fd2784796085a4d5cc570e2c',
  '29': '59afb189275a2aae342df4ae262658246d373390',
  '2a': '5c33202dc2553264b50a31dbc36c2aa2d96b9738',
  '2b': '2a0e22546be4a4ba6fc09752f6e4923bf713ee8c',
  '2c': 'f07c5c8ce0153ef94286ba3ac7a652e01485f920',
  '2d': '9fdb9ea348448ddbb73101fc64955600977cf5d7',
  '2e': '40b6b518a143ada94c05a0ec3a8cb9fb061bc416',
  '2f': 'efc1dab478035a09a3b7568fbfdbd1bfb67dfb1f',
  '30': '76b0146cea972552dd4849ec397ba70d8073d97f',
  '31': 'c0bd4507b630a86923bde6175efc9d8bcf8d3417',
  '32': '9935adb2bcb3bf2a2d12ba2dc55304545b8105a0',
  '33': '40ab8c42f66ab4f37b9f4d54fa29588a61f65cf9',
  '34': 'eee7a9de9611b2609a974172a730456c126f8c7b',
  '35': 'b9f5f3eb04d1cfe4fa59b6409870d23e036bb65f',
  '36': 'a90f94bfb9ed5acf7fa9199b3f7b1242b72b52c5',
  '37': '482637f33d3cf8f42c8e6561f1263b6b81d2cb84',
  '38': 'd5f8056a4c3a2078ab20ce69a9b93e019a6f93aa',
  '39': '6827f088c075f2db0383d4ca24c2f2273aede310',
  '3b': 'aad31757d27091a5b7eefb79ee74ddcf47155d7d',
  '3c': '717e5fff1b99fd373d2258457d072dd1b0936c6e',
  '3d': 'a12a32d12d677a7181741b14d52b4e1bcdc36e62',
  '3e': 'ffaaa7bdd2a04b30b96a11549e6f85cd0f203a62',
  '3f': '07e17dabcd66b4a0ccbbba251994364a73c9448c',
  '40': 'f604c038ac277243b061acd5fa9d05760b959d12',
});
const retainedDirectVerifiers = new Set(['31', '32', '33', '34', '35', '36', '37', '38', '39', '3b', '3c', '3d', '3e', '3f', '40']);
function hasRetainedStartupVerifier(root: string, deadline: number): boolean {
  const expected = retainedStartupVerifiers[basename(dirname(dirname(root)))];
  if (!expected) return false;
  const file = retainedDescription(join(root, 'Contents/MacOS/arbol-browser-native'), false);
  try { return startupCodeDirectoryHash(file, deadline) === expected; }
  finally { closeSync(file.fd); }
}

interface InstalledVerification { readonly verified: boolean; readonly snapshotDigest?: string }
const verifierRefusal: InstalledVerification = Object.freeze({ verified: false });

async function runInstalledVerifier(bootstrap: string, args: string[], requirement: string,
  bundle: StorageDescription, backing: StorageDescription, deadline: number,
  captureInventory?: (deadline: number) => void): Promise<InstalledVerification> {
  const started = performance.now();
  const remaining = budget(deadline);
  const environment = { PATH: '/usr/bin:/bin' };
  const reportsSnapshot = args[0] === '0';
  const child = spawn(bootstrap, ['--arbol-verify-installed-package', ...args, ...(reportsSnapshot ? ['--arbol-report-snapshot'] : [])], {
    env: environment, stdio: ['pipe', bundle.fd, backing.fd, reportsSnapshot ? 'pipe' : 'ignore'],
  });
  const report = child.stdio[3];
  let snapshotDigest = '', invalidReport = false;
  report?.on('error', () => { invalidReport = true; });
  report?.on('data', (chunk: Buffer) => {
    if (snapshotDigest.length + chunk.length > 64) { invalidReport = true; report?.destroy(); return; }
    snapshotDigest += chunk.toString('utf8');
  });
  const result = new Promise<InstalledVerification>(resolve => {
    child.once('error', () => resolve(verifierRefusal));
    child.once('close', code => {
      if (code !== 0 || invalidReport) resolve(verifierRefusal);
      else if (!snapshotDigest) resolve({ verified: true });
      else resolve(/^[0-9a-f]{64}$/.test(snapshotDigest) ? { verified: true, snapshotDigest } : verifierRefusal);
    });
  });
  const gate = child.stdin;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    if (!gate || !child.pid || (reportsSnapshot && !report)) return verifierRefusal;
    // The gated child receives approval only after stock Security verifies
    // this live exec against the original descriptor's exact CodeDirectory.
    const signatureArguments = ['--verify', '--strict', '-R', '=' + requirement, String(child.pid)];
    const signatureOptions = { timeout: budget(deadline), killSignal: 'SIGKILL' as const, env: environment, stdio: 'ignore' as const };
    let signed: boolean;
    if (captureInventory) {
      const signerDeadline = performance.now() + signatureOptions.timeout;
      const signature = spawn('/usr/bin/codesign', signatureArguments, signatureOptions);
      const completed = new Promise<boolean>(resolve => {
        signature.once('error', () => { if (!signature.pid) resolve(false); });
        signature.once('close', code => resolve(code === 0));
      });
      let signerTimer: ReturnType<typeof setTimeout> | undefined;
      const expired = new Promise<undefined>(resolve => {
        signerTimer = setTimeout(() => resolve(undefined), Math.max(1, signerDeadline - performance.now()));
      });
      // This stays a private read-only observation until the signed verifier
      // independently attests to the same mounted package and digest.
      try {
        try { captureInventory(Math.min(deadline, started + remaining, signerDeadline)); }
        catch { /* Keep the original serial inventory path available. */ }
        const outcome = await Promise.race([completed, expired]);
        if (outcome === undefined || performance.now() >= signerDeadline)
          return refuseVerification('verification-cutoff');
        signed = outcome;
      } finally { clearTimeout(signerTimer); signature.unref(); }
    } else {
      const signature = spawnSync('/usr/bin/codesign', signatureArguments, signatureOptions);
      signed = !signature.error && signature.status === 0;
    }
    budget(deadline);
    const wait = Math.floor(started + remaining - performance.now());
    if (wait < 1 || !signed || child.exitCode !== null) return verifierRefusal;
    const expired = new Promise<InstalledVerification>(resolve => {
      timer = setTimeout(() => { gate.destroy(); report?.destroy(); resolve(verifierRefusal); }, wait);
    });
    const delivered = new Promise<boolean>(resolve => {
      gate.once('error', () => resolve(false));
      gate.end('1', () => resolve(gate.writableFinished && !gate.errored));
    });
    const verification = Promise.all([delivered, result]).then(([approved, verified]) => approved ? verified : verifierRefusal);
    const verified = await Promise.race([expired, verification]);
    budget(deadline);
    return performance.now() < started + remaining ? verified : verifierRefusal;
  } finally {
    clearTimeout(timer);
    gate?.destroy();
    report?.destroy();
    // The native verifier has its own fixed cutoff. Closing the original
    // gate and releasing the wait never signals a process by a recycled PID.
    child.unref();
  }
}

async function verifyInstalledStartupStorage(root: string, image: string, deadline: number, retainedVerifier?: string,
  hostRequest?: string): Promise<StorageContext> {
  const descriptions: StorageDescription[] = [];
  try {
    // Pin the same original names and descriptions before running any checks.
    const bundle = retainedDescription(root, true);
    descriptions.push(bundle);
    const backing = retainedDescription(image, false);
    descriptions.push(backing);
    const held = Object.freeze([bundle, backing] as const);
    const bootstrap = join(root, 'Contents/MacOS/arbol-browser-native');
    const executable = retainedDescription(bootstrap, false);
    try {
      const cdhash = startupCodeDirectoryHash(executable, deadline);
      if (retainedVerifier !== undefined && cdhash !== retainedVerifier) return refuse();
      const requirement = productionPublisher.requirement +
        ` and identifier "${productionPublisher.bundleIdentifier}" and cdhash H"${cdhash}"`;
      const context = (mapping: string): StorageContext => Object.freeze({ descriptions: held, mapping });
      const preliminary = context('installed-startup');
      storageAssert(preliminary, deadline);
      if (fstatSync(executable.fd, { bigint: true }).dev !==
          fstatSync(bundle.fd, { bigint: true }).dev ||
          physicalStamp(lstatSync(bootstrap, { bigint: true })) !== executable.stamp ||
          realpathSync(bootstrap) !== bootstrap) return refuse();
      // Process identity, read-only backing, full code signatures and every
      // signed payload entry are checked inside the signed bootstrap.
      const verifyPrevious = (helper: string): boolean => {
        const result = spawnSync('/usr/bin/osascript', ['-l', 'JavaScript', '-e', installedVerifierBroker,
          bootstrap, helper, requirement, ...(hostRequest ? [hostRequest] : [])], {
          timeout: budget(deadline), killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'ignore', bundle.fd, backing.fd],
          encoding: 'utf8', maxBuffer: nativeLimit,
          env: { PATH: '/usr/bin:/bin' },
        });
        budget(deadline);
        return !result.error && result.status === 0 && result.stdout === 'verified\n';
      };
      const direct = retainedVerifier === undefined || retainedDirectVerifiers.has(basename(dirname(dirname(root))));
      const verify = async (helper: string): Promise<InstalledVerification> => direct
        ? runInstalledVerifier(bootstrap, [helper, ...(hostRequest ? [hostRequest] : [])], requirement, bundle, backing, deadline)
        : { verified: verifyPrevious(helper) };
      let verified = preliminary;
      let inventory: InstalledInventory | undefined;
      const cached = direct ? await runInstalledVerifier(bootstrap, ['0', ...(hostRequest ? [hostRequest] : [])],
        requirement, bundle, backing, deadline, retainedVerifier === undefined ? inventoryDeadline => {
          inventory = captureInstalledInventory(root, preliminary, inventoryDeadline);
        } : undefined) : verifierRefusal;
      if (!cached.verified) {
        const mapping = storageMapping(root, deadline);
        if (!mapping.image || mapping.image['image-path'] !== image || storageMapping(image, deadline).image ||
            !(await verify(String(mapping.image['hdid-pid']))).verified) return refuse();
        verified = context(mapping.key);
      } else if (cached.snapshotDigest) {
        verified = Object.freeze({ ...preliminary, snapshotDigest: cached.snapshotDigest });
        if (inventory && createHash('sha256').update(inventory.snapshot).digest('hex') === cached.snapshotDigest)
          installedInventories.set(verified, inventory);
      }
      if (physicalStamp(fstatSync(executable.fd, { bigint: true })) !== executable.stamp ||
          physicalStamp(lstatSync(bootstrap, { bigint: true })) !== executable.stamp) return refuse();
      storageAssert(verified, deadline);
      return verified;
    } finally { closeSync(executable.fd); }
  } catch (error) {
    for (const description of descriptions) {
      try { closeSync(description.fd); }
      catch { /* Preserve the original refusal. */ }
    }
    return refuseVerification('storage-context', error);
  }
}

/** Observe only the two stamps used by an existing failed comparison. Never
 * restat, retry or replace the original full-stamp verification predicate. */
function stampFailurePhase(identity: SnapshotIdentityPhase, before: string | undefined,
  after: string | undefined): SnapshotIdentityPhase | 'snapshot-root-change-time' {
  try {
    if (identity === 'snapshot-root-identity' && before !== undefined && after !== undefined && before !== after) {
      const a: unknown = JSON.parse(before), b: unknown = JSON.parse(after);
      if (Array.isArray(a) && Array.isArray(b) && a.length === 10 && b.length === 10 &&
          a.every(value => typeof value === 'string') && b.every(value => typeof value === 'string') &&
          a[8] !== b[8] && a.every((value, index) => index === 8 || value === b[index]))
        return 'snapshot-root-change-time';
    }
  } catch { /* Observation failure retains the original fixed phase. */ }
  return identity;
}
// Capture the actual unpatched implementation once, in this canonical module.
// These callbacks perform filesystem work off the browser heartbeat thread.
const originalAsyncFS = physicalFS;
const asynchronousFS = Object.freeze({ lstat: originalAsyncFS.lstat, fstat: originalAsyncFS.fstat, open: originalAsyncFS.open,
  close: originalAsyncFS.close, read: originalAsyncFS.read, opendir: originalAsyncFS.opendir, readlink: originalAsyncFS.readlink, realpath: originalAsyncFS.realpath });
function asyncLstat(path: string, observed?: SnapshotFailure): Promise<import('node:fs').BigIntStats> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => asynchronousFS.lstat(path, { bigint: true }, (error, stat) => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve(stat)), observed));
}
function asyncStat(fd: number, observed?: SnapshotFailure): Promise<import('node:fs').BigIntStats> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => asynchronousFS.fstat(fd, { bigint: true }, (error, stat) => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve(stat)), observed));
}
function asyncRealpath(path: string, observed?: SnapshotFailure): Promise<string> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => asynchronousFS.realpath(path, (error, value) => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve(value)), observed));
}
// macOS 27 SDK sys/syslimits.h: NAME_MAX=255 bytes, PATH_MAX=1024
// (including terminating NUL). The original complete-entry ceiling is 4096.
const completeEntryLimit = 4096, rawNameLimit = 255, rawPathLimit = 1024;
function directoryPath(path: string, observed?: SnapshotFailure): void {
  if (Buffer.byteLength(path, 'utf8') >= rawPathLimit || !path.startsWith('/') || path.includes('\0')) refuseSnapshot('snapshot-directory-membership', observed);
}
function directoryName(raw: unknown, directory: string, observed?: SnapshotFailure): string {
  if (!Buffer.isBuffer(raw) || !raw.length || raw.length > rawNameLimit || raw.includes(0) || raw.includes(47)) refuseSnapshot('snapshot-directory-membership', observed);
  if (Buffer.byteLength(directory, 'utf8') + 1 + raw.length >= rawPathLimit) refuseSnapshot('snapshot-directory-membership', observed);
  let name: string;
  try { name = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw); }
  catch (error) { noteSnapshotFailure(observed, error, 'snapshot-directory-membership'); throw error; }
  if (name === '.' || name === '..' || !Buffer.from(name, 'utf8').equals(raw)) refuseSnapshot('snapshot-directory-membership', observed);
  directoryPath(join(directory, name), observed); return name;
}
function sameDirectoryPath(dir: import('node:fs').Dir, path: string): boolean {
  const actual: unknown = dir.path;
  return Buffer.isBuffer(actual) ? actual.equals(Buffer.from(path)) : actual === path;
}
// Pinned Node24.22.2 internal/fs/utils.js getOptions expressly accepts
// encoding 'buffer'; its public DirOptions declaration omits that spelling.
// These narrow adapters preserve the original functions and raw-name checks.
const rawOpendirSync = opendirSync as unknown as (path: string,
  options: { encoding: 'buffer'; bufferSize: number }) => import('node:fs').Dir;
const rawOpendir = asynchronousFS.opendir as unknown as (path: string,
  options: { encoding: 'buffer'; bufferSize: number },
  callback: (error: NodeJS.ErrnoException | null, directory: import('node:fs').Dir) => void) => void;
function synchronousNames(path: string, deadline: number, maximum: number, observed?: SnapshotFailure, identity: SnapshotIdentityPhase = 'snapshot-entry-identity'): string[] {
  budget(deadline); directoryPath(path, observed);
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > completeEntryLimit) refuseSnapshot('snapshot-directory-membership', observed);
  const before = snapshotFilesystem(() => lstatSync(path, { bigint: true }), observed);
  if (!before.isDirectory() || snapshotFilesystem(() => realpathSync(path), observed) !== path) refuseSnapshot(identity, observed);
  const stamp = physicalStamp(before), names: string[] = [], seen = new Set<string>();
  let directory: import('node:fs').Dir | undefined;
  try {
    directory = snapshotFilesystem(() => rawOpendirSync(path, { encoding: 'buffer', bufferSize: 1 }), observed);
    if (!sameDirectoryPath(directory, path)) refuseSnapshot(identity, observed);
    // Read at most the bounded permitted count plus the one necessary EOF /
    // extra-entry observation. Never allocate or sort an unbounded census.
    for (let index = 0; index <= maximum; ++index) {
      budget(deadline); const entry = snapshotFilesystem(() => directory!.readSync(), observed); budget(deadline);
      if (!entry) {
        const afterStamp = physicalStamp(snapshotFilesystem(() => lstatSync(path, { bigint: true }), observed));
        if (afterStamp !== stamp || snapshotFilesystem(() => realpathSync(path), observed) !== path) refuseSnapshot(stampFailurePhase(identity, stamp, afterStamp), observed);
        return names.sort();
      }
      if (names.length === maximum) refuseSnapshot('snapshot-directory-membership', observed);
      const name = directoryName(entry.name, path, observed); if (seen.has(name)) refuseSnapshot('snapshot-directory-membership', observed);
      seen.add(name); names.push(name);
    }
    return refuseSnapshot('snapshot-directory-membership', observed);
  } catch (error) { noteSnapshotFailure(observed, error); throw error; } finally { if (directory) snapshotFilesystem(() => directory!.closeSync(), observed); budget(deadline); }
}
function asyncDirectory(path: string, maximum: number, observed?: SnapshotFailure): Promise<import('node:fs').Dir> {
  // Keep each native batch inside the existing entry limit plus the extra
  // entry checked for overflow, including the last batch of a large directory.
  const limit = maximum + 1;
  let bufferSize = Math.min(32, limit);
  while (limit % bufferSize !== 0) bufferSize--;
  return new Promise((resolve, reject) => snapshotFilesystem(() => rawOpendir(path, { encoding: 'buffer', bufferSize },
    (error, directory) => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve(directory)), observed));
}
function asyncDirectoryRead(directory: import('node:fs').Dir, observed?: SnapshotFailure): Promise<import('node:fs').Dirent | null> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => directory.read((error, entry) => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve(entry)), observed));
}
function asyncDirectoryClose(directory: import('node:fs').Dir, observed?: SnapshotFailure): Promise<void> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => directory.close(error => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve()), observed));
}
async function asynchronousNames(path: string, expected: PhysicalEntry, active: () => void, poison: () => void, observed?: SnapshotFailure, identity: SnapshotIdentityPhase = 'snapshot-entry-identity'): Promise<string[]> {
  active(); directoryPath(path, observed);
  const maximum = expected.children?.length;
  if (expected.kind !== 'directory' || maximum === undefined || maximum > completeEntryLimit) refuseSnapshot('snapshot-directory-membership', observed);
  const before = await asyncLstat(path, observed);
  let beforeStamp: string | undefined;
  if (!before.isDirectory() || (beforeStamp = physicalStamp(before)) !== expected.stamp || await asyncRealpath(path, observed) !== path) refuseSnapshot(stampFailurePhase(identity, expected.stamp, beforeStamp), observed);
  const names: string[] = [], seen = new Set<string>(); let directory: import('node:fs').Dir | undefined;
  try {
    active(); directory = await asyncDirectory(path, maximum, observed); active();
    if (!sameDirectoryPath(directory, path)) refuseSnapshot(identity, observed);
    for (let index = 0; index <= maximum; ++index) {
      active(); const entry = await asyncDirectoryRead(directory, observed); active();
      if (!entry) {
        const after = await asyncLstat(path, observed);
        let afterStamp: string | undefined;
        if (!after.isDirectory() || (afterStamp = physicalStamp(after)) !== expected.stamp || await asyncRealpath(path, observed) !== path) refuseSnapshot(stampFailurePhase(identity, expected.stamp, afterStamp), observed);
        active(); return names.sort();
      }
      if (names.length === maximum) refuseSnapshot('snapshot-directory-membership', observed);
      const name = directoryName(entry.name, path, observed); if (seen.has(name)) refuseSnapshot('snapshot-directory-membership', observed);
      seen.add(name); names.push(name);
    }
    return refuseSnapshot('snapshot-directory-membership', observed);
  } catch (error) { noteSnapshotFailure(observed, error); poison(); throw error; } finally { if (directory) await asyncDirectoryClose(directory, observed); active(); }
}

function asyncLink(path: string, observed?: SnapshotFailure): Promise<string> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => asynchronousFS.readlink(path, (error, value) => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve(value)), observed));
}
function asyncOpen(path: string, observed?: SnapshotFailure): Promise<number> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => asynchronousFS.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    (error, fd) => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve(fd)), observed));
}
function asyncClose(fd: number, observed?: SnapshotFailure): Promise<void> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => asynchronousFS.close(fd, error => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve()), observed));
}
function asyncRead(fd: number, buffer: Buffer, length: number, position: number, observed?: SnapshotFailure): Promise<number> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => asynchronousFS.read(fd, buffer, 0, length, position,
    (error, count) => error ? reject(rejectSnapshotFilesystem(error, observed)) : resolve(count)), observed));
}
/** Recompare every original byte and physical entry. Nothing here signs,
 * loads an addon, spawns a verifier or learns a replacement snapshot. */
async function compareCompleteSnapshot(signed: SignedBundle, snapshot: FrozenSnapshot, deadline: number,
  retainStartupBytes: boolean): Promise<void> {
  const observed: SnapshotFailure = {};
  const root = signed.bundle, entries: Record<string, string> = Object.create(null), keys = Object.keys(snapshot.physical).sort();
  if (keys.length > 4097) refuseSnapshot('snapshot-directory-membership', observed);
  const poison = (): void => {
    snapshot.poisoned = true; if (signed === trustedCandidate) poisonedTrust = true;
  };
  const active = (): void => {
    try { budget(deadline); } catch (error) { noteSnapshotFailure(observed, error); throw error; }
    if (snapshot.poisoned) refuse();
  };
  // Claim only original frozen keys. First failure closes admission; all active
  // jobs settle (including descriptor cleanup) before this phase can finish.
  const phase = async (job: (key: string) => Promise<void>): Promise<void> => {
    let next = 0;
    const worker = async (): Promise<void> => {
      try {
        while (next < keys.length) {
          active(); const key = keys[next++]!;
          await job(key);
        }
      } catch (error) { noteSnapshotFailure(observed, error); poison(); throw error; }
    };
    const outcomes = await Promise.allSettled(Array.from({ length: Math.min(4, keys.length) }, () => worker()));
    if (outcomes.some(outcome => outcome.status === 'rejected')) refuseVerification(observed.first ?? 'repeated-snapshot');
    active();
  };
  const check = async (key: string, topology: boolean): Promise<import('node:fs').BigIntStats> => {
    active();
    try {
      const expected = snapshot.physical[key]; if (!expected) refuseSnapshot('snapshot-entry-identity', observed);
      const path = key ? join(root, key) : root, stat = await asyncLstat(path, observed);
      active();
      const stamp = physicalStamp(stat);
      if (stamp !== expected.stamp ||
          (expected.kind === 'directory' ? !stat.isDirectory() : expected.kind === 'file' ? !stat.isFile() : !stat.isSymbolicLink())) refuseSnapshot(stampFailurePhase(key ? 'snapshot-entry-identity' : 'snapshot-root-identity', expected.stamp, stamp), observed);
      if (expected.kind === 'symlink') {
        const link = await asyncLink(path, observed), target = await asyncRealpath(path, observed); active();
        if (link !== expected.link || target !== expected.target || !target.startsWith(root + sep) ||
            !resolve(dirname(path), link).startsWith(root + sep) || await asyncLink(path, observed) !== link) refuseSnapshot('snapshot-symlink', observed);
      } else {
        if (await asyncRealpath(path, observed) !== path) refuseSnapshot(key ? 'snapshot-entry-identity' : 'snapshot-root-identity', observed);
        if (topology && expected.kind === 'directory' && stable(await asynchronousNames(path, expected, active, poison, observed, key ? 'snapshot-entry-identity' : 'snapshot-root-identity')) !== stable(expected.children)) refuseSnapshot('snapshot-directory-membership', observed);
      }
      active(); return stat;
    } catch (error) { noteSnapshotFailure(observed, error); poison(); throw error; }
  };
  // The caller holds the original read-only image and backing file. Stamps
  // include the device, and every captured path and directory is still checked.
  if (retainStartupBytes && snapshot.mounted) {
    await phase(async key => { await check(key, true); });
    return;
  }
  await phase(async key => {
    const expected = snapshot.physical[key]!, path = key ? join(root, key) : root;
    const named = await check(key, true);
    if (!key) return;
    if (expected.kind === 'directory') entries[key] = `directory:${named.mode & 0o7777n}`;
    else if (expected.kind === 'symlink') entries[key] = `symlink:${expected.link}`;
    else {
      let fd: number | undefined;
      try {
        fd = await asyncOpen(path, observed); active();
        const first = await asyncStat(fd, observed);
        if (!first.isFile() || first.nlink !== 1n || physicalStamp(first) !== expected.stamp || first.size < 0n || first.size > BigInt(Number.MAX_SAFE_INTEGER)) refuseSnapshot('snapshot-file-description', observed);
        const size = Number(first.size);
        const hash = createHash('sha256'), buffer = fileReadBuffer(size); let position = 0;
        while (position < size) {
          active(); const count = await asyncRead(fd, buffer, Math.min(buffer.length, size - position), position, observed);
          active(); if (count < 1) refuseSnapshot('snapshot-file-read', observed); hash.update(buffer.subarray(0, count)); position += count;
        }
        if (await asyncRead(fd, buffer, 1, position, observed) !== 0) refuseSnapshot('snapshot-file-read', observed);
        if (physicalStamp(await asyncStat(fd, observed)) !== expected.stamp) refuseSnapshot('snapshot-file-description', observed);
        await check(key, false); active();
        entries[key] = `file:${first.mode & 0o7777n}:${hash.digest('hex')}`;
      } catch (error) { noteSnapshotFailure(observed, error); poison(); throw error; } finally { if (fd !== undefined) await asyncClose(fd, observed); }
    }
    await check(key, true);
  });
  active();
  if (stable(entries) !== snapshot.encoded) refuseSnapshot('snapshot-encoded-mismatch', observed);
  // Full final physical/topology sweep after hashing, not a partial prefix or
  // an early metadata sample accepted after a slow file operation.
  await phase(async key => { await check(key, true); });
  active();
}
export async function compareSignedSnapshot(signed: SignedBundle, deadline: number,
  retainStartupBytes = false): Promise<SignedSnapshotComparison> {
  const snapshot = signedSnapshots.get(signed);
  if (!snapshot || snapshot.poisoned || (signed === trustedCandidate && poisonedTrust)) refuseVerification('repeated-snapshot');
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    budget(deadline); storageAssert(snapshot.storage, deadline);
    const nativeStartup = retainStartupBytes && assertNativeStartupTopology(snapshot.storage, deadline);
    if (!nativeStartup) {
      await Promise.race([compareCompleteSnapshot(signed, snapshot, deadline, retainStartupBytes), new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          const error = new Error('native_snapshot_timeout');
          noteVerificationFailure(error, 'verification-cutoff');
          reject(error);
        }, Math.max(1, deadline - performance.now()));
      })]);
    }
    budget(deadline); if (snapshot.poisoned) refuse();
    storageAssert(snapshot.storage, deadline);
    const receipt: SignedSnapshotComparison = Object.freeze({ deadline });
    const expiry = setTimeout(() => {
      const actual = comparisons.get(receipt);
      if (actual && !actual.used) { snapshot.poisoned = true; if (signed === trustedCandidate) poisonedTrust = true; }
    }, Math.max(1, deadline - performance.now())); expiry.unref();
    comparisons.set(receipt, { signed, snapshot, nativeStartup, used: false, expiry }); return receipt;
  } catch (error) {
    snapshot.poisoned = true; if (signed === trustedCandidate) poisonedTrust = true; return refuseVerification('repeated-snapshot', error);
  } finally { if (timer) clearTimeout(timer); }
}
/** One synchronous consumer, original local object and absolute deadline only.
 * Custody/purpose/operation binding is supplied by the actual host integration. */
export function consumeSignedSnapshot(receipt: SignedSnapshotComparison, signed: SignedBundle, deadline: number): void {
  const actual = comparisons.get(receipt), snapshot = signedSnapshots.get(signed);
  try {
    if (!actual || actual.used || actual.signed !== signed || actual.snapshot !== snapshot || !snapshot || snapshot.poisoned ||
        receipt.deadline !== deadline || (signed === trustedCandidate && poisonedTrust)) refuse();
    actual.used = true; clearTimeout(actual.expiry); budget(deadline); storageAssert(snapshot.storage, deadline);
    if (actual.nativeStartup && !assertNativeStartupTopology(snapshot.storage, deadline)) refuse();
  } catch (error) {
    if (actual) actual.snapshot.poisoned = true;
    if (snapshot) snapshot.poisoned = true;
    if (signed === trustedCandidate) poisonedTrust = true;
    return refuseVerification('snapshot-receipt', error);
  }
}

/** The original read-only mapping is verified at initial trust. Keep its
 * retained descriptions current without minting a complete comparison receipt. */
export function assertRetainedReadOnlyStorage(signed: SignedBundle, deadline: number): boolean {
  const snapshot = signedSnapshots.get(signed);
  if (!snapshot || snapshot.poisoned || (signed === trustedCandidate && poisonedTrust))
    return refuseVerification('storage-context');
  if (!snapshot.storage) return false;
  try {
    storageAssert(snapshot.storage, deadline);
    assertNativeStartupTopology(snapshot.storage, deadline);
    return true;
  } catch (error) {
    snapshot.poisoned = true;
    if (signed === trustedCandidate) poisonedTrust = true;
    throw error;
  }
}

export function assertInstalledImage(signed: SignedBundle, image: string, deadline: number): void {
  const snapshot = signedSnapshots.get(signed);
  if (snapshot?.storage?.descriptions[1].path !== image || !assertRetainedReadOnlyStorage(signed, deadline))
    refuseVerification('storage-context');
}

export function bindInstalledStartupTopology(signed: SignedBundle, image: string, platform: PlatformPort, deadline: number): void {
  assertPlatform(platform);
  assertInstalledImage(signed, image, deadline);
  const storage = signedSnapshots.get(signed)?.storage;
  const inspect = platform.inspectInstalledMountTopology;
  if (!storage || !inspect || installedStartupTopologies.has(storage)) return refuseVerification('storage-context');
  const root = storage.descriptions[0];
  const original = inspect.call(platform, root.path, root.fd);
  storageAssert(storage, deadline);
  installedStartupTopologies.set(storage, () => {
    if (inspect.call(platform, root.path, root.fd) !== original) refuseVerification('storage-context');
  });
}

/** Publish only the exact binding already verified by the child of the
 * signed installed launcher. Losing this acceleration keeps the full path. */
export function publishInstalledStartupProof(signed: SignedBundle, deadline: number): void {
  const offered = process.env.ARBOL_BROWSER_STARTUP_PROOF;
  delete process.env.ARBOL_BROWSER_STARTUP_PROOF;
  if (offered !== '1') return;
  const pipe = 12;
  try {
    const snapshot = signedSnapshots.get(signed), storage = snapshot?.storage;
    if (!snapshot || snapshot.poisoned || !storage || !assertNativeStartupTopology(storage, deadline) ||
        !fstatSync(pipe).isFIFO()) return;
    const [root, backing] = storage.descriptions;
    const encoded = JSON.stringify({ format: 1, bundle: signed.bundle, root: JSON.parse(root.stamp),
      backing: JSON.parse(backing.stamp), snapshot: signed.snapshotDigest });
    if (Buffer.byteLength(encoded) <= 4096) writeSync(pipe, encoded, null, 'utf8');
  } catch { /* The original signed verifier is still available to the host. */ }
  finally { try { if (fstatSync(pipe).isFIFO()) closeSync(pipe); } catch { /* Already closed or not inherited. */ } }
}

let attemptedTrust = false, poisonedTrust = false;
let trustedCandidate: CandidateTrust | undefined;
/** Complete physical signed bundle, including the outer seal and directories.
 * No subprocess, expected-byte learning, or symlink traversal on later checks. */
interface MountedBundleRead {
  readonly device: bigint;
  readonly files: Map<string, ReturnType<typeof physicalFile>>;
}
interface InstalledInventory {
  readonly mounted: MountedBundleRead;
  readonly physical: Record<string, PhysicalEntry>;
  readonly snapshot: string;
}
const installedInventories = new WeakMap<StorageContext, InstalledInventory>();

function captureInstalledInventory(root: string, storage: StorageContext, deadline: number,
  observed: SnapshotFailure = {}): InstalledInventory {
  storageAssert(storage, deadline);
  const mounted = { device: fstatSync(storage.descriptions[0].fd, { bigint: true }).dev, files: new Map() };
  const compiled = boundedJson(join(root, 'Contents/Resources/native-compatibility.json'), deadline, mounted.device);
  if (!validator('native.BuildCompatibility')(compiled)) return refuse();
  const physical: Record<string, PhysicalEntry> = Object.create(null);
  const snapshot = completeSnapshot(root, deadline, physical, observed, mounted, false, compiled.files);
  storageAssert(storage, deadline);
  return { mounted, physical, snapshot };
}

function completeSnapshot(root: string, deadline = Infinity, physical?: Record<string, PhysicalEntry>,
  observed: SnapshotFailure = {}, mounted?: MountedBundleRead, confirmOnly = false,
  verifiedPayload?: Readonly<Record<string, string>>): string {
  const entries: Record<string, string> = Object.create(null); let count = 0;
  function walk(directory: string): void {
    budget(deadline);
    const original = snapshotFilesystem(() => lstatSync(directory), observed);
    const identity = snapshotFilesystem(() => lstatSync(directory, { bigint: true }), observed);
    if (mounted && identity.dev !== mounted.device)
      refuseSnapshot(directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity', observed);
    const originalStamp = physicalStamp(identity);
    const names = synchronousNames(directory, deadline, completeEntryLimit - count, observed, directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity');
    count += names.length;
    if (snapshotFilesystem(() => realpathSync(directory), observed) !== directory || !original.isDirectory()) return refuseSnapshot(directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity', observed);
    if (physical) physical[relative(root, directory)] = Object.freeze({ stamp: originalStamp, kind: 'directory', children: Object.freeze(names) });
    for (const name of names) {
      budget(deadline);
      const path = join(directory, name), key = relative(root, path), before = snapshotFilesystem(() => lstatSync(path), observed);
      const identity = snapshotFilesystem(() => lstatSync(path, { bigint: true }), observed);
      if (mounted && identity.dev !== mounted.device) refuseSnapshot('snapshot-entry-identity', observed);
      const beforeStamp = physicalStamp(identity);
      if (before.isSymbolicLink()) {
        const link = snapshotFilesystem(() => readlinkSync(path), observed), target = snapshotFilesystem(() => realpathSync(path), observed);
        if (!target.startsWith(root + sep) || !resolve(dirname(path), link).startsWith(root + sep) || snapshotFilesystem(() => readlinkSync(path), observed) !== link) refuseSnapshot('snapshot-symlink', observed);
        entries[key] = `symlink:${link}`;
        if (physical) physical[key] = Object.freeze({ stamp: beforeStamp, kind: 'symlink', link, target });
      } else if (before.isDirectory()) { entries[key] = `directory:${before.mode & 0o7777}`; walk(path); }
      else if (before.isFile()) {
        const verifiedDigest = verifiedPayload && Object.hasOwn(verifiedPayload, key) ? verifiedPayload[key] : undefined;
        const bytes = confirmOnly ? mounted?.files.get(key) : verifiedDigest
          ? { digest: verifiedDigest, magic: '' }
          : physicalFile(path, before, deadline, observed);
        if (!bytes) return refuseSnapshot('snapshot-entry-identity', observed);
        if (!confirmOnly) mounted?.files.set(key, bytes);
        entries[key] = `file:${before.mode & 0o7777}:${bytes.digest}`;
        if (physical) physical[key] = Object.freeze({ stamp: beforeStamp, kind: 'file' });
      } else refuseSnapshot('snapshot-entry-identity', observed);
      const after = snapshotFilesystem(() => lstatSync(path), observed);
      if (after.dev !== before.dev || after.ino !== before.ino || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || physicalStamp(snapshotFilesystem(() => lstatSync(path, { bigint: true }), observed)) !== beforeStamp) refuseSnapshot('snapshot-entry-identity', observed);
    }
    const afterStamp = physicalStamp(snapshotFilesystem(() => lstatSync(directory, { bigint: true }), observed));
    if (afterStamp !== originalStamp) refuseSnapshot(stampFailurePhase(directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity', originalStamp, afterStamp), observed);
    if (stable(synchronousNames(directory, deadline, names.length, observed, directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity')) !== stable(names)) refuseSnapshot('snapshot-directory-membership', observed);
  }
  walk(root); budget(deadline); return stable(entries);
}
export function assertCandidateTrust(value: CandidateTrust): void {
  if (poisonedTrust || value !== trustedCandidate) refuse();
  value.assertIdentity();
}
export function assertStartupCandidateTrust(value: CandidateTrust, deadline: number): void {
  if (poisonedTrust || value !== trustedCandidate) refuse();
  value.assertIdentity(deadline, true);
}
export function verifySignedBundle(bundle: string, deadline = Infinity, scope: PublisherScope = 'isolated'): SignedBundle {
  return assembleSignedBundle(bundle, deadline, scope);
}

export async function verifyInstalledStartupBundle(bundle: string, image: string, deadline: number,
  hostRequest?: string): Promise<SignedBundle> {
  const root = resolve(bundle);
  try {
    budget(deadline);
    if (!bundle.endsWith('.app') || realpathSync(bundle) !== root) return refuse();
  } catch (error) { return refuseVerification('bundle-selection', error); }
  const payloadRoot = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const exactCurrent = root === dirname(dirname(dirname(payloadRoot)));
  if (process.platform !== 'darwin' || (!exactCurrent && !hasRetainedStartupVerifier(root, deadline)))
    return verifySignedBundle(root, deadline, 'production');
  const storage = await verifyInstalledStartupStorage(root, image, deadline,
    exactCurrent ? undefined : retainedStartupVerifiers[basename(dirname(dirname(root)))],
    exactCurrent ? hostRequest : undefined);
  return assembleSignedBundle(root, deadline, 'production', storage);
}

function assembleSignedBundle(bundle: string, deadline: number, scope: PublisherScope,
  startupStorage?: StorageContext): SignedBundle {
  const observed: SnapshotFailure = {};
  let phase: SignedVerificationPhase = 'bundle-selection';
  let storage = startupStorage, retained = false;
  try {
    budget(deadline);
    if (!bundle.endsWith('.app') || realpathSync(bundle) !== resolve(bundle)) refuse();
    const root = resolve(bundle);
    const expectedPublisher = scope === 'production' ? productionPublisher : publisher;
    const installedStartup = startupStorage !== undefined;
    storage ??= discoverStorage(root, deadline);
    phase = 'initial-snapshot';
    // Installed verification may have captured the original descriptors'
    // inventory in parallel. Only a witnessed digest admits that observation.
    const installedInventory = startupStorage && (installedInventories.get(startupStorage) ??
      captureInstalledInventory(root, startupStorage, deadline, observed));
    const mounted: MountedBundleRead | undefined = installedInventory?.mounted ?? (scope === 'production' && storage
      ? { device: fstatSync(storage.descriptions[0].fd, { bigint: true }).dev, files: new Map() }
      : undefined);
    const physical: Record<string, PhysicalEntry> = installedInventory?.physical ?? Object.create(null);
    const afterPhysical: Record<string, PhysicalEntry> = Object.create(null);
    const check = (): Compatibility => {
      if (!installedStartup) signature(root, true, false, deadline, expectedPublisher);
      phase = 'publisher';
      const verifiedDevice = installedStartup ? mounted?.device : undefined;
      if (stable(boundedJson(join(root, 'Contents/Resources/publisher-requirement.json'), deadline, verifiedDevice)) !== stable(expectedPublisher)) refuse();
      phase = 'compatibility';
      const value = boundedJson(join(root, 'Contents/Resources/native-compatibility.json'), deadline, verifiedDevice);
      if (!validator('native.BuildCompatibility')(value)) return refuse();
      if (value.publisherTeam !== expectedPublisher.team || value.bundleIdentifier !== expectedPublisher.bundleIdentifier ||
          stable(value.runtime) !== stable(pinnedRuntime) || value.nativeABI.compiledNapi !== 8 ||
          stable(value.featureConfiguration) !== stable({ sitePerProcess: true, disabledFeatures: ['MacAccessibilityTextOperation'], extraChromiumArguments: [] })) refuse();
      phase = 'inventory';
      const inventory: Record<string, string> = Object.create(null); let count = 0;
      const payload = 'Contents/Resources/browser';
      function verifyFile(path: string, key: string, bytes: ReturnType<typeof physicalFile>): void {
        inventory[key] = bytes.digest;
        if (!installedStartup && ['cffaedfe', 'cefaedfe', 'feedfacf', 'cafebabe', 'bebafeca'].includes(bytes.magic))
          signature(path, false, key.startsWith(payload + '/runtime/Electron.app/') && key.includes('/Contents/MacOS/'),
            deadline, expectedPublisher);
      }
      function walk(directory: string): void {
        const names = synchronousNames(directory, deadline, completeEntryLimit - count, observed); count += names.length;
        for (const name of names) {
          budget(deadline);
          const path = join(directory, name), key = relative(root, path), stat = snapshotFilesystem(() => lstatSync(path), observed);
          if (stat.isSymbolicLink()) {
            const link = snapshotFilesystem(() => readlinkSync(path), observed), target = snapshotFilesystem(() => realpathSync(path), observed);
            if (!target.startsWith(root + sep) || !resolve(dirname(path), link).startsWith(root + sep)) refuseSnapshot('snapshot-symlink', observed);
            inventory[key] = createHash('sha256').update(`symlink\0${link}`).digest('hex');
          } else if (stat.isDirectory()) walk(path);
          else if (stat.isFile()) verifyFile(path, key, physicalFile(path, stat, deadline, observed));
          else refuseSnapshot('snapshot-entry-identity', observed);
        }
      }
      if (mounted) {
        if (physical[payload]?.kind !== 'directory') return refuseSnapshot('snapshot-entry-identity', observed);
        for (const [key, entry] of Object.entries(physical)) {
          if (!key.startsWith(payload + '/')) continue;
          budget(deadline);
          if (entry.kind === 'symlink') inventory[key] = createHash('sha256').update(`symlink\0${entry.link}`).digest('hex');
          else if (entry.kind === 'file') {
            const path = join(root, key), bytes = mounted.files.get(key);
            const named = snapshotFilesystem(() => lstatSync(path, { bigint: true }), observed);
            if (!bytes || named.dev !== mounted.device || physicalStamp(named) !== entry.stamp)
              return refuseSnapshot('snapshot-entry-identity', observed);
            verifyFile(path, key, bytes);
          }
        }
      } else walk(join(root, payload));
      if (stable(inventory) !== stable(value.files)) refuseSnapshot('snapshot-encoded-mismatch', observed);
      return value;
    };
    const before = installedInventory?.snapshot ?? completeSnapshot(root, deadline, physical, observed, mounted);
    const snapshotDigest = createHash('sha256').update(before).digest('hex');
    if (mounted) storageAssert(storage, deadline);
    const initial = check(), encoded = stable(initial);
    phase = 'final-snapshot';
    // The retained read-only image and backing file make the verified bytes
    // immutable. The final pass still checks every name, link and file stamp.
    if (mounted) storageAssert(storage, deadline);
    phase = 'final-physical-comparison';
    if (storage?.snapshotDigest) {
      // The authenticated native verifier retained this exact read-only
      // image and the App's complete previously verified inventory digest.
      if (snapshotDigest !== storage.snapshotDigest) refuseSnapshot('snapshot-encoded-mismatch', observed);
    } else {
      const after = completeSnapshot(root, deadline, afterPhysical, observed, mounted, mounted !== undefined);
      if (before !== after) refuseSnapshot('snapshot-encoded-mismatch', observed);
      if (stable(physical) !== stable(afterPhysical))
        refuseSnapshot(stampFailurePhase(physical['']?.stamp !== afterPhysical['']?.stamp ? 'snapshot-root-identity' : 'snapshot-entry-identity', physical['']?.stamp, afterPhysical['']?.stamp), observed);
    }
    if (installedStartup) storageAssert(storage, deadline);
    else revalidateStorage(root, storage, deadline);
    // Snapshot validation cannot be bypassed by mutation through a caller-held object.
    function frozen<T>(value: T): T { if (value && typeof value === 'object') { for (const entry of Object.values(value)) frozen(entry); Object.freeze(value); } return value; }
    const manifest = frozen(initial);
    const snapshot: FrozenSnapshot = { storage, mounted, encoded: before, physical: Object.freeze(physical), poisoned: false };
    const result: SignedBundle = Object.freeze({ bundle: root, manifest,
      snapshotDigest,
      assertIdentity(limit = Infinity, retainStartupBytes = false) {
        const observed: SnapshotFailure = {};
        let repeatedPhase: SignedVerificationPhase = 'repeated-snapshot';
        try {
          budget(limit); storageAssert(storage, limit);
          if (snapshot.poisoned) refuse();
          if (snapshotFilesystem(() => realpathSync(root), observed) !== root) refuseSnapshot('snapshot-root-identity', observed);
          if (!retainStartupBytes || !assertNativeStartupTopology(storage, limit)) {
            const currentPhysical: Record<string, PhysicalEntry> = Object.create(null);
            const retained = retainStartupBytes ? snapshot.mounted : undefined;
            if (completeSnapshot(root, limit, currentPhysical, observed, retained, retained !== undefined) !== before)
              refuseSnapshot('snapshot-encoded-mismatch', observed);
            repeatedPhase = 'repeated-physical';
            if (stable(currentPhysical) !== stable(snapshot.physical))
              refuseSnapshot(stampFailurePhase(currentPhysical['']?.stamp !== snapshot.physical['']?.stamp ? 'snapshot-root-identity' : 'snapshot-entry-identity', snapshot.physical['']?.stamp, currentPhysical['']?.stamp), observed);
          }
          repeatedPhase = 'repeated-manifest';
          if (stable(boundedJson(join(root, 'Contents/Resources/native-compatibility.json'), limit)) !== encoded) refuse();
          repeatedPhase = 'repeated-cutoff';
          budget(limit); storageAssert(storage, limit);
        } catch (error) { snapshot.poisoned = true; return refuseVerification(observed.first ?? repeatedPhase, observed.first ? undefined : error); }
      } });
    signedSnapshots.set(result, snapshot);
    if (storage) storageFinalizer.register(result, storage.descriptions);
    retained = true; return result;
  } catch (error) { noteSnapshotFailure(observed, error, phase); throw error; }
  finally { if (!retained && storage) for (const d of storage.descriptions) { try { closeSync(d.fd); } catch { /* Preserve construction refusal. */ } } }
}
function existingNativeCandidate(bundle: string, deadline: number, scope: PublisherScope): CandidateTrust | undefined {
  if (poisonedTrust) refuse();
  if (trustedCandidate) {
    const expectedPublisher = scope === 'production' ? productionPublisher : publisher;
    if (resolve(bundle) !== trustedCandidate.bundle || trustedCandidate.manifest.bundleIdentifier !== expectedPublisher.bundleIdentifier) {
      poisonedTrust = true; return refuse();
    }
    trustedCandidate.assertIdentity(deadline); return trustedCandidate;
  }
  if (attemptedTrust) refuse(); attemptedTrust = true;
  return undefined;
}

export function verifyNativeCandidate(bundle: string, deadline = Infinity, scope: PublisherScope = 'isolated'): CandidateTrust {
  const existing = existingNativeCandidate(bundle, deadline, scope);
  if (existing) return existing;
  try { trustedCandidate = verifySignedBundle(bundle, deadline, scope); return trustedCandidate; }
  catch (error) { poisonedTrust = true; return refuseVerification('bundle-selection', error); }
}

export async function verifyInstalledNativeCandidate(bundle: string, image: string, deadline: number,
  hostRequest?: string): Promise<CandidateTrust> {
  const existing = existingNativeCandidate(bundle, deadline, 'production');
  if (existing) return existing;
  try { trustedCandidate = await verifyInstalledStartupBundle(bundle, image, deadline, hostRequest); return trustedCandidate; }
  catch (error) { poisonedTrust = true; return refuseVerification('bundle-selection', error); }
}

/** The bootstrap already verified and loaded this exact Native candidate.
 * Read-only continuity covers package metadata preparation. The host still
 * checks the complete signed snapshot before beginning ownership. */
export function reuseNativeCandidateForHost(bundle: string, candidate: CandidateTrust, deadline: number): CandidateTrust {
  if (!trustedCandidate || poisonedTrust) return refuseVerification('bundle-selection');
  if (resolve(bundle) !== trustedCandidate.bundle) { poisonedTrust = true; return refuseVerification('bundle-selection'); }
  if (candidate !== trustedCandidate) return refuseVerification('bundle-selection');
  if (!assertRetainedReadOnlyStorage(candidate, deadline)) candidate.assertIdentity(deadline);
  return candidate;
}

