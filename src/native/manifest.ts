/** The publisher anchor is source policy, never derived from a running package. */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { join, dirname, resolve, sep, relative } from 'node:path';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';

// Trust covers physical signed bytes, including ASAR archives, on every check.
// Browser verification uses the mandatory unpatched Electron builtin. The Node
// CLI has an unpatched filesystem already and never imports Electron code.
// NodeMain uses the same ASAR wrapper as the browser. Builtin-only access
// cannot resolve an ambient original-fs package; actual Electron must provide
// its genuine unpatched builtin or refuse. Plain Node retains its own fs.
const physicalFS = process.getBuiltinModule(typeof process.versions.electron === 'string' ? 'original-fs' : 'fs') as typeof import('node:fs') | undefined;
if (!physicalFS || typeof physicalFS.openSync !== 'function' || !physicalFS.promises ||
    typeof physicalFS.promises.open !== 'function') throw new Error('native_candidate_unavailable');
const { constants, lstatSync, openSync, fstatSync, readSync, closeSync, opendirSync, readlinkSync, realpathSync } = physicalFS;

export const publisher = Object.freeze({ team: '7V372XL59S', bundleIdentifier: 'com.sylvan-stack.arbol-browser.native-candidate',
  requirement: 'anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' });
export const pinnedRuntime = Object.freeze({ electron: '45.3.2', chromium: '156.0.8078.100', node: '24.22.2', napi: '10', modules: '150', platform: 'darwin', arch: 'arm64', macOS: '27.0.1' });
export const nativeLimit = 1048576;
export type Compatibility = Contract<'native.BuildCompatibility'>;
export function refuse(): never { throw new Error('native_candidate_unavailable'); }
export type SignedVerificationPhase = 'bundle-selection' | 'initial-snapshot' |
  'outer-signature-verification' | 'outer-signature-details' | 'outer-signature-entitlements' |
  'nested-signature-verification' | 'nested-signature-details' | 'nested-signature-entitlements' |
  'publisher' | 'compatibility' | 'inventory' | 'final-snapshot' | 'final-physical-comparison' |
  'repeated-snapshot' | 'repeated-physical' | 'repeated-manifest' | 'repeated-cutoff' | 'snapshot-receipt' | 'verification-cutoff' |
  'snapshot-root-identity' | 'snapshot-entry-identity' | 'snapshot-file-description' | 'snapshot-file-read' |
  'snapshot-symlink' | 'snapshot-directory-membership' | 'snapshot-encoded-mismatch' | 'snapshot-filesystem';
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
export function boundedJson(path: string, deadline = Infinity): unknown {
  budget(deadline);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd), named = lstatSync(path);
    if (!stat.isFile() || !named.isFile() || stat.dev !== named.dev || stat.ino !== named.ino ||
        stat.nlink !== 1 || named.nlink !== 1 || stat.size < 1 || stat.size > nativeLimit) return refuse();
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
    const hash = createHash('sha256'), buffer = Buffer.alloc(65536), header = Buffer.alloc(4);
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
function signature(path: string, outer = false, jit = false, deadline = Infinity): void {
  let phase: SignedVerificationPhase = outer ? 'outer-signature-verification' : 'nested-signature-verification';
  try {
    const requirement = publisher.requirement + (outer ? ` and identifier "${publisher.bundleIdentifier}"` : '');
    const result = spawnSync('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R', `=${requirement}`, path],
      { timeout: budget(deadline), maxBuffer: nativeLimit, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
    budget(deadline);
    if (result.error || result.status !== 0) refuse();
    phase = outer ? 'outer-signature-details' : 'nested-signature-details';
    const details = spawnSync('/usr/bin/codesign', ['-dvvv', path], { timeout: budget(deadline), maxBuffer: nativeLimit, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
    budget(deadline);
    if (details.error || details.status !== 0 || !details.stderr.includes(`TeamIdentifier=${publisher.team}`) ||
        !details.stderr.includes('runtime)') || !details.stderr.includes('Timestamp=')) refuse();
    phase = outer ? 'outer-signature-entitlements' : 'nested-signature-entitlements';
    const ent = spawnSync('/usr/bin/codesign', ['-d', '--entitlements', ':-', path], { timeout: budget(deadline), maxBuffer: nativeLimit, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
    budget(deadline);
    if (ent.error || ent.status !== 0 || /com\.apple\.security\.(?:cs\.(?:disable-library-validation|allow-unsigned-executable-memory|allow-dyld-environment-variables)|get-task-allow)/.test(ent.stdout + ent.stderr)) refuse();
    const keys = [...ent.stdout.matchAll(/<key>([^<]+)<\/key>/g)].map(match => match[1]);
    if (keys.length > 1 || keys.some(key => key !== 'com.apple.security.cs.allow-jit' || !jit) ||
        (keys.length && !/<key>com\.apple\.security\.cs\.allow-jit<\/key>\s*<true\s*\/>/.test(ent.stdout))) refuse();
  } catch (error) { noteVerificationFailure(error, phase); throw error; }
}
export interface CandidateTrust {
  readonly bundle: string;
  readonly manifest: Readonly<Compatibility>;
  readonly snapshotDigest: string;
  /** Cryptographic identity only. It cannot assert previous exit or production qualification. */
  assertIdentity(deadline?: number): void;
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
  readonly encoded: string;
  readonly physical: Readonly<Record<string, PhysicalEntry>>;
  poisoned: boolean;
}
const signedSnapshots = new WeakMap<SignedBundle, FrozenSnapshot>();
export interface SignedSnapshotComparison { readonly deadline: number }
const comparisons = new WeakMap<SignedSnapshotComparison, { signed: SignedBundle; snapshot: FrozenSnapshot; used: boolean; expiry: ReturnType<typeof setTimeout> }>();
function physicalStamp(stat: import('node:fs').BigIntStats): string {
  return stable([stat.dev, stat.ino, stat.mode, stat.uid, stat.gid, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs, stat.birthtimeNs].map(String));
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
        if (physicalStamp(snapshotFilesystem(() => lstatSync(path, { bigint: true }), observed)) !== stamp || snapshotFilesystem(() => realpathSync(path), observed) !== path) refuseSnapshot(identity, observed);
        return names.sort();
      }
      if (names.length === maximum) refuseSnapshot('snapshot-directory-membership', observed);
      const name = directoryName(entry.name, path, observed); if (seen.has(name)) refuseSnapshot('snapshot-directory-membership', observed);
      seen.add(name); names.push(name);
    }
    return refuseSnapshot('snapshot-directory-membership', observed);
  } catch (error) { noteSnapshotFailure(observed, error); throw error; } finally { if (directory) snapshotFilesystem(() => directory!.closeSync(), observed); budget(deadline); }
}
function asyncDirectory(path: string, observed?: SnapshotFailure): Promise<import('node:fs').Dir> {
  return new Promise((resolve, reject) => snapshotFilesystem(() => rawOpendir(path, { encoding: 'buffer', bufferSize: 1 },
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
  if (!before.isDirectory() || physicalStamp(before) !== expected.stamp || await asyncRealpath(path, observed) !== path) refuseSnapshot(identity, observed);
  const names: string[] = [], seen = new Set<string>(); let directory: import('node:fs').Dir | undefined;
  try {
    active(); directory = await asyncDirectory(path, observed); active();
    if (!sameDirectoryPath(directory, path)) refuseSnapshot(identity, observed);
    for (let index = 0; index <= maximum; ++index) {
      active(); const entry = await asyncDirectoryRead(directory, observed); active();
      if (!entry) {
        const after = await asyncLstat(path, observed);
        if (!after.isDirectory() || physicalStamp(after) !== expected.stamp || await asyncRealpath(path, observed) !== path) refuseSnapshot(identity, observed);
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
async function compareCompleteSnapshot(signed: SignedBundle, snapshot: FrozenSnapshot, deadline: number): Promise<void> {
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
      if (physicalStamp(stat) !== expected.stamp ||
          (expected.kind === 'directory' ? !stat.isDirectory() : expected.kind === 'file' ? !stat.isFile() : !stat.isSymbolicLink())) refuseSnapshot(key ? 'snapshot-entry-identity' : 'snapshot-root-identity', observed);
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
        const hash = createHash('sha256'), buffer = Buffer.alloc(65536); let position = 0;
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
export async function compareSignedSnapshot(signed: SignedBundle, deadline: number): Promise<SignedSnapshotComparison> {
  const snapshot = signedSnapshots.get(signed);
  if (!snapshot || snapshot.poisoned || (signed === trustedCandidate && poisonedTrust)) refuseVerification('repeated-snapshot');
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    budget(deadline);
    await Promise.race([compareCompleteSnapshot(signed, snapshot, deadline), new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('native_snapshot_timeout')), Math.max(1, deadline - performance.now()));
    })]);
    budget(deadline); if (snapshot.poisoned) refuse();
    const receipt: SignedSnapshotComparison = Object.freeze({ deadline });
    const expiry = setTimeout(() => {
      const actual = comparisons.get(receipt);
      if (actual && !actual.used) { snapshot.poisoned = true; if (signed === trustedCandidate) poisonedTrust = true; }
    }, Math.max(1, deadline - performance.now())); expiry.unref();
    comparisons.set(receipt, { signed, snapshot, used: false, expiry }); return receipt;
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
    actual.used = true; clearTimeout(actual.expiry); budget(deadline);
  } catch (error) {
    if (actual) actual.snapshot.poisoned = true;
    if (snapshot) snapshot.poisoned = true;
    if (signed === trustedCandidate) poisonedTrust = true;
    return refuseVerification('snapshot-receipt', error);
  }
}

let attemptedTrust = false, poisonedTrust = false;
let trustedCandidate: CandidateTrust | undefined;
/** Complete physical signed bundle, including the outer seal and directories.
 * No subprocess, expected-byte learning, or symlink traversal on later checks. */
function completeSnapshot(root: string, deadline = Infinity, physical?: Record<string, PhysicalEntry>, observed: SnapshotFailure = {}): string {
  const entries: Record<string, string> = Object.create(null); let count = 0;
  function walk(directory: string): void {
    budget(deadline);
    const original = snapshotFilesystem(() => lstatSync(directory), observed), originalStamp = physicalStamp(snapshotFilesystem(() => lstatSync(directory, { bigint: true }), observed)), names = synchronousNames(directory, deadline, completeEntryLimit - count, observed, directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity');
    count += names.length;
    if (snapshotFilesystem(() => realpathSync(directory), observed) !== directory || !original.isDirectory()) return refuseSnapshot(directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity', observed);
    if (physical) physical[relative(root, directory)] = Object.freeze({ stamp: originalStamp, kind: 'directory', children: Object.freeze(names) });
    for (const name of names) {
      budget(deadline);
      const path = join(directory, name), key = relative(root, path), before = snapshotFilesystem(() => lstatSync(path), observed), beforeStamp = physicalStamp(snapshotFilesystem(() => lstatSync(path, { bigint: true }), observed));
      if (before.isSymbolicLink()) {
        const link = snapshotFilesystem(() => readlinkSync(path), observed), target = snapshotFilesystem(() => realpathSync(path), observed);
        if (!target.startsWith(root + sep) || !resolve(dirname(path), link).startsWith(root + sep) || snapshotFilesystem(() => readlinkSync(path), observed) !== link) refuseSnapshot('snapshot-symlink', observed);
        entries[key] = `symlink:${link}`;
        if (physical) physical[key] = Object.freeze({ stamp: beforeStamp, kind: 'symlink', link, target });
      } else if (before.isDirectory()) { entries[key] = `directory:${before.mode & 0o7777}`; walk(path); }
      else if (before.isFile()) {
        entries[key] = `file:${before.mode & 0o7777}:${physicalFile(path, before, deadline, observed).digest}`;
        if (physical) physical[key] = Object.freeze({ stamp: beforeStamp, kind: 'file' });
      } else refuseSnapshot('snapshot-entry-identity', observed);
      const after = snapshotFilesystem(() => lstatSync(path), observed);
      if (after.dev !== before.dev || after.ino !== before.ino || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || physicalStamp(snapshotFilesystem(() => lstatSync(path, { bigint: true }), observed)) !== beforeStamp) refuseSnapshot('snapshot-entry-identity', observed);
    }
    if (physicalStamp(snapshotFilesystem(() => lstatSync(directory, { bigint: true }), observed)) !== originalStamp) refuseSnapshot(directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity', observed);
    if (stable(synchronousNames(directory, deadline, names.length, observed, directory === root ? 'snapshot-root-identity' : 'snapshot-entry-identity')) !== stable(names)) refuseSnapshot('snapshot-directory-membership', observed);
  }
  walk(root); budget(deadline); return stable(entries);
}
export function assertCandidateTrust(value: CandidateTrust): void {
  if (poisonedTrust || value !== trustedCandidate) refuse();
  value.assertIdentity();
}
export function verifySignedBundle(bundle: string, deadline = Infinity): SignedBundle {
  const observed: SnapshotFailure = {};
  let phase: SignedVerificationPhase = 'bundle-selection';
  try {
    budget(deadline);
    if (!bundle.endsWith('.app') || realpathSync(bundle) !== resolve(bundle)) refuse();
    const root = resolve(bundle);
    const check = (): Compatibility => {
      signature(root, true, false, deadline);
      phase = 'publisher';
      if (stable(boundedJson(join(root, 'Contents/Resources/publisher-requirement.json'), deadline)) !== stable(publisher)) refuse();
      phase = 'compatibility';
      const value = boundedJson(join(root, 'Contents/Resources/native-compatibility.json'), deadline);
      if (!validator('native.BuildCompatibility')(value)) return refuse();
      if (value.publisherTeam !== publisher.team || value.bundleIdentifier !== publisher.bundleIdentifier ||
          stable(value.runtime) !== stable(pinnedRuntime) || value.nativeABI.compiledNapi !== 8 ||
          stable(value.featureConfiguration) !== stable({ sitePerProcess: true, disabledFeatures: ['MacAccessibilityTextOperation'], extraChromiumArguments: [] })) refuse();
      phase = 'inventory';
      const inventory: Record<string, string> = Object.create(null); let count = 0;
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
          else if (stat.isFile()) {
            const physical = physicalFile(path, stat, deadline, observed); inventory[key] = physical.digest;
            if (['cffaedfe', 'cefaedfe', 'feedfacf', 'cafebabe', 'bebafeca'].includes(physical.magic))
              signature(path, false, key.startsWith('Contents/Resources/browser/runtime/Electron.app/') && key.includes('/Contents/MacOS/'), deadline);
          } else refuseSnapshot('snapshot-entry-identity', observed);
        }
      }
      walk(join(root, 'Contents/Resources/browser'));
      if (stable(inventory) !== stable(value.files)) refuseSnapshot('snapshot-encoded-mismatch', observed);
      return value;
    };
    const physical: Record<string, PhysicalEntry> = Object.create(null), afterPhysical: Record<string, PhysicalEntry> = Object.create(null);
    phase = 'initial-snapshot';
    const before = completeSnapshot(root, deadline, physical, observed);
    const initial = check(), encoded = stable(initial);
    phase = 'final-snapshot';
    const after = completeSnapshot(root, deadline, afterPhysical, observed);
    phase = 'final-physical-comparison';
    if (before !== after) refuseSnapshot('snapshot-encoded-mismatch', observed);
    if (stable(physical) !== stable(afterPhysical))
      refuseSnapshot(physical['']?.stamp !== afterPhysical['']?.stamp ? 'snapshot-root-identity' : 'snapshot-entry-identity', observed);
    // Snapshot validation cannot be bypassed by mutation through a caller-held object.
    function frozen<T>(value: T): T { if (value && typeof value === 'object') { for (const entry of Object.values(value)) frozen(entry); Object.freeze(value); } return value; }
    const manifest = frozen(initial);
    const snapshot: FrozenSnapshot = { encoded: before, physical: Object.freeze(physical), poisoned: false };
    const result: SignedBundle = Object.freeze({ bundle: root, manifest,
      snapshotDigest: createHash('sha256').update(before).digest('hex'),
      assertIdentity(limit = Infinity) {
        const observed: SnapshotFailure = {};
        let repeatedPhase: SignedVerificationPhase = 'repeated-snapshot';
        try {
          budget(limit);
          const currentPhysical: Record<string, PhysicalEntry> = Object.create(null);
          if (snapshot.poisoned) refuse();
          if (snapshotFilesystem(() => realpathSync(root), observed) !== root) refuseSnapshot('snapshot-root-identity', observed);
          if (completeSnapshot(root, limit, currentPhysical, observed) !== before) refuseSnapshot('snapshot-encoded-mismatch', observed);
          repeatedPhase = 'repeated-physical';
          if (stable(currentPhysical) !== stable(snapshot.physical))
            refuseSnapshot(currentPhysical['']?.stamp !== snapshot.physical['']?.stamp ? 'snapshot-root-identity' : 'snapshot-entry-identity', observed);
          repeatedPhase = 'repeated-manifest';
          if (stable(boundedJson(join(root, 'Contents/Resources/native-compatibility.json'), limit)) !== encoded) refuse();
          repeatedPhase = 'repeated-cutoff';
          budget(limit);
        } catch (error) { snapshot.poisoned = true; return refuseVerification(observed.first ?? repeatedPhase, observed.first ? undefined : error); }
      } });
    signedSnapshots.set(result, snapshot); return result;
  } catch (error) { noteSnapshotFailure(observed, error, phase); throw error; }
}
export function verifyNativeCandidate(bundle: string, deadline = Infinity): CandidateTrust {
  if (poisonedTrust) refuse();
  if (trustedCandidate) {
    if (resolve(bundle) !== trustedCandidate.bundle) { poisonedTrust = true; return refuse(); }
    trustedCandidate.assertIdentity(deadline); return trustedCandidate;
  }
  if (attemptedTrust) refuse(); attemptedTrust = true;
  try { trustedCandidate = verifySignedBundle(bundle, deadline); return trustedCandidate; }
  catch (error) { poisonedTrust = true; return refuseVerification('bundle-selection', error); }
}

