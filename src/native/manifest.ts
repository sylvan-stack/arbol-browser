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
  'repeated-snapshot' | 'repeated-physical' | 'repeated-manifest' | 'repeated-cutoff' | 'snapshot-receipt' | 'verification-cutoff';
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
function physicalFile(path: string, named: import('node:fs').Stats, deadline: number): { digest: string; magic: string } {
  budget(deadline);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const first = fstatSync(fd);
    if (!first.isFile() || !named.isFile() || first.dev !== named.dev || first.ino !== named.ino ||
        first.nlink !== 1 || named.nlink !== 1 || first.mode !== named.mode || first.uid !== named.uid ||
        !Number.isSafeInteger(first.size) || first.size < 0 || realpathSync(path) !== path) refuse();
    const hash = createHash('sha256'), buffer = Buffer.alloc(65536), header = Buffer.alloc(4);
    let offset = 0;
    while (offset < first.size) {
      budget(deadline);
      const n = readSync(fd, buffer, 0, Math.min(buffer.length, first.size - offset), null);
      if (n < 1) refuse();
      if (offset < 4) buffer.copy(header, offset, 0, Math.min(n, 4 - offset));
      hash.update(buffer.subarray(0, n)); offset += n;
    }
    if (readSync(fd, buffer, 0, 1, null) !== 0) refuse();
    const last = fstatSync(fd), after = lstatSync(path); budget(deadline);
    if (!after.isFile() || first.dev !== last.dev || first.ino !== last.ino || first.size !== last.size ||
        first.mode !== last.mode || first.uid !== last.uid || last.nlink !== 1 ||
        first.mtimeMs !== last.mtimeMs || first.ctimeMs !== last.ctimeMs ||
        after.dev !== last.dev || after.ino !== last.ino || after.size !== last.size || after.nlink !== 1 ||
        after.mode !== last.mode || after.uid !== last.uid || after.mtimeMs !== last.mtimeMs || after.ctimeMs !== last.ctimeMs ||
        realpathSync(path) !== path) refuse();
    return { digest: hash.digest('hex'), magic: header.subarray(0, Math.min(first.size, 4)).toString('hex') };
  } finally { closeSync(fd); }
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
function asyncLstat(path: string): Promise<import('node:fs').BigIntStats> {
  return new Promise((resolve, reject) => asynchronousFS.lstat(path, { bigint: true }, (error, stat) => error ? reject(error) : resolve(stat)));
}
function asyncStat(fd: number): Promise<import('node:fs').BigIntStats> {
  return new Promise((resolve, reject) => asynchronousFS.fstat(fd, { bigint: true }, (error, stat) => error ? reject(error) : resolve(stat)));
}
function asyncRealpath(path: string): Promise<string> {
  return new Promise((resolve, reject) => asynchronousFS.realpath(path, (error, value) => error ? reject(error) : resolve(value)));
}
// macOS 27 SDK sys/syslimits.h: NAME_MAX=255 bytes, PATH_MAX=1024
// (including terminating NUL). The original complete-entry ceiling is 4096.
const completeEntryLimit = 4096, rawNameLimit = 255, rawPathLimit = 1024;
function directoryPath(path: string): void {
  if (Buffer.byteLength(path, 'utf8') >= rawPathLimit || !path.startsWith('/') || path.includes('\0')) refuse();
}
function directoryName(raw: unknown, directory: string): string {
  if (!Buffer.isBuffer(raw) || !raw.length || raw.length > rawNameLimit || raw.includes(0) || raw.includes(47)) refuse();
  if (Buffer.byteLength(directory, 'utf8') + 1 + raw.length >= rawPathLimit) refuse();
  const name = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
  if (name === '.' || name === '..' || !Buffer.from(name, 'utf8').equals(raw)) refuse();
  directoryPath(join(directory, name)); return name;
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
function synchronousNames(path: string, deadline: number, maximum: number): string[] {
  budget(deadline); directoryPath(path);
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > completeEntryLimit) refuse();
  const before = lstatSync(path, { bigint: true });
  if (!before.isDirectory() || realpathSync(path) !== path) refuse();
  const stamp = physicalStamp(before), names: string[] = [], seen = new Set<string>();
  let directory: import('node:fs').Dir | undefined;
  try {
    directory = rawOpendirSync(path, { encoding: 'buffer', bufferSize: 1 });
    if (!sameDirectoryPath(directory, path)) refuse();
    // Read at most the bounded permitted count plus the one necessary EOF /
    // extra-entry observation. Never allocate or sort an unbounded census.
    for (let index = 0; index <= maximum; ++index) {
      budget(deadline); const entry = directory.readSync(); budget(deadline);
      if (!entry) {
        if (physicalStamp(lstatSync(path, { bigint: true })) !== stamp || realpathSync(path) !== path) refuse();
        return names.sort();
      }
      if (names.length === maximum) refuse();
      const name = directoryName(entry.name, path); if (seen.has(name)) refuse();
      seen.add(name); names.push(name);
    }
    return refuse();
  } finally { if (directory) directory.closeSync(); budget(deadline); }
}
function asyncDirectory(path: string): Promise<import('node:fs').Dir> {
  return new Promise((resolve, reject) => rawOpendir(path, { encoding: 'buffer', bufferSize: 1 },
    (error, directory) => error ? reject(error) : resolve(directory)));
}
function asyncDirectoryRead(directory: import('node:fs').Dir): Promise<import('node:fs').Dirent | null> {
  return new Promise((resolve, reject) => directory.read((error, entry) => error ? reject(error) : resolve(entry)));
}
function asyncDirectoryClose(directory: import('node:fs').Dir): Promise<void> {
  return new Promise((resolve, reject) => directory.close(error => error ? reject(error) : resolve()));
}
async function asynchronousNames(path: string, expected: PhysicalEntry, active: () => void, poison: () => void): Promise<string[]> {
  active(); directoryPath(path);
  const maximum = expected.children?.length;
  if (expected.kind !== 'directory' || maximum === undefined || maximum > completeEntryLimit) refuse();
  const before = await asyncLstat(path);
  if (!before.isDirectory() || physicalStamp(before) !== expected.stamp || await asyncRealpath(path) !== path) refuse();
  const names: string[] = [], seen = new Set<string>(); let directory: import('node:fs').Dir | undefined;
  try {
    active(); directory = await asyncDirectory(path); active();
    if (!sameDirectoryPath(directory, path)) refuse();
    for (let index = 0; index <= maximum; ++index) {
      active(); const entry = await asyncDirectoryRead(directory); active();
      if (!entry) {
        const after = await asyncLstat(path);
        if (!after.isDirectory() || physicalStamp(after) !== expected.stamp || await asyncRealpath(path) !== path) refuse();
        active(); return names.sort();
      }
      if (names.length === maximum) refuse();
      const name = directoryName(entry.name, path); if (seen.has(name)) refuse();
      seen.add(name); names.push(name);
    }
    return refuse();
  } catch (error) { poison(); throw error; } finally { if (directory) await asyncDirectoryClose(directory); active(); }
}

function asyncLink(path: string): Promise<string> {
  return new Promise((resolve, reject) => asynchronousFS.readlink(path, (error, value) => error ? reject(error) : resolve(value)));
}
function asyncOpen(path: string): Promise<number> {
  return new Promise((resolve, reject) => asynchronousFS.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    (error, fd) => error ? reject(error) : resolve(fd)));
}
function asyncClose(fd: number): Promise<void> {
  return new Promise((resolve, reject) => asynchronousFS.close(fd, error => error ? reject(error) : resolve()));
}
function asyncRead(fd: number, buffer: Buffer, length: number, position: number): Promise<number> {
  return new Promise((resolve, reject) => asynchronousFS.read(fd, buffer, 0, length, position,
    (error, count) => error ? reject(error) : resolve(count)));
}
/** Recompare every original byte and physical entry. Nothing here signs,
 * loads an addon, spawns a verifier or learns a replacement snapshot. */
async function compareCompleteSnapshot(signed: SignedBundle, snapshot: FrozenSnapshot, deadline: number): Promise<void> {
  const root = signed.bundle, entries: Record<string, string> = Object.create(null), keys = Object.keys(snapshot.physical).sort();
  if (keys.length > 4097) refuse();
  const poison = (): void => {
    snapshot.poisoned = true; if (signed === trustedCandidate) poisonedTrust = true;
  };
  const active = (): void => { budget(deadline); if (snapshot.poisoned) refuse(); };
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
      } catch (error) { poison(); throw error; }
    };
    const outcomes = await Promise.allSettled(Array.from({ length: Math.min(4, keys.length) }, () => worker()));
    if (outcomes.some(outcome => outcome.status === 'rejected')) refuse();
    active();
  };
  const check = async (key: string, topology: boolean): Promise<import('node:fs').BigIntStats> => {
    active();
    try {
      const expected = snapshot.physical[key]; if (!expected) refuse();
      const path = key ? join(root, key) : root, stat = await asyncLstat(path);
      active();
      if (physicalStamp(stat) !== expected.stamp ||
          (expected.kind === 'directory' ? !stat.isDirectory() : expected.kind === 'file' ? !stat.isFile() : !stat.isSymbolicLink())) refuse();
      if (expected.kind === 'symlink') {
        const link = await asyncLink(path), target = await asyncRealpath(path); active();
        if (link !== expected.link || target !== expected.target || !target.startsWith(root + sep) ||
            !resolve(dirname(path), link).startsWith(root + sep) || await asyncLink(path) !== link) refuse();
      } else {
        if (await asyncRealpath(path) !== path) refuse();
        if (topology && expected.kind === 'directory' && stable(await asynchronousNames(path, expected, active, poison)) !== stable(expected.children)) refuse();
      }
      active(); return stat;
    } catch (error) { poison(); throw error; }
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
        fd = await asyncOpen(path); active();
        const first = await asyncStat(fd);
        if (!first.isFile() || first.nlink !== 1n || physicalStamp(first) !== expected.stamp || first.size < 0n || first.size > BigInt(Number.MAX_SAFE_INTEGER)) refuse();
        const size = Number(first.size);
        const hash = createHash('sha256'), buffer = Buffer.alloc(65536); let position = 0;
        while (position < size) {
          active(); const count = await asyncRead(fd, buffer, Math.min(buffer.length, size - position), position);
          active(); if (count < 1) refuse(); hash.update(buffer.subarray(0, count)); position += count;
        }
        if (await asyncRead(fd, buffer, 1, position) !== 0 || physicalStamp(await asyncStat(fd)) !== expected.stamp) refuse();
        await check(key, false); active();
        entries[key] = `file:${first.mode & 0o7777n}:${hash.digest('hex')}`;
      } catch (error) { poison(); throw error; } finally { if (fd !== undefined) await asyncClose(fd); }
    }
    await check(key, true);
  });
  active();
  if (stable(entries) !== snapshot.encoded) refuse();
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
function completeSnapshot(root: string, deadline = Infinity, physical?: Record<string, PhysicalEntry>): string {
  const entries: Record<string, string> = Object.create(null); let count = 0;
  function walk(directory: string): void {
    budget(deadline);
    const original = lstatSync(directory), originalStamp = physicalStamp(lstatSync(directory, { bigint: true })), names = synchronousNames(directory, deadline, completeEntryLimit - count);
    count += names.length;
    if (realpathSync(directory) !== directory || !original.isDirectory()) return refuse();
    if (physical) physical[relative(root, directory)] = Object.freeze({ stamp: originalStamp, kind: 'directory', children: Object.freeze(names) });
    for (const name of names) {
      budget(deadline);
      const path = join(directory, name), key = relative(root, path), before = lstatSync(path), beforeStamp = physicalStamp(lstatSync(path, { bigint: true }));
      if (before.isSymbolicLink()) {
        const link = readlinkSync(path), target = realpathSync(path);
        if (!target.startsWith(root + sep) || !resolve(dirname(path), link).startsWith(root + sep) || readlinkSync(path) !== link) refuse();
        entries[key] = `symlink:${link}`;
        if (physical) physical[key] = Object.freeze({ stamp: beforeStamp, kind: 'symlink', link, target });
      } else if (before.isDirectory()) { entries[key] = `directory:${before.mode & 0o7777}`; walk(path); }
      else if (before.isFile()) {
        entries[key] = `file:${before.mode & 0o7777}:${physicalFile(path, before, deadline).digest}`;
        if (physical) physical[key] = Object.freeze({ stamp: beforeStamp, kind: 'file' });
      } else refuse();
      const after = lstatSync(path);
      if (after.dev !== before.dev || after.ino !== before.ino || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || physicalStamp(lstatSync(path, { bigint: true })) !== beforeStamp) refuse();
    }
    if (physicalStamp(lstatSync(directory, { bigint: true })) !== originalStamp || stable(synchronousNames(directory, deadline, names.length)) !== stable(names)) refuse();
  }
  walk(root); budget(deadline); return stable(entries);
}
export function assertCandidateTrust(value: CandidateTrust): void {
  if (poisonedTrust || value !== trustedCandidate) refuse();
  value.assertIdentity();
}
export function verifySignedBundle(bundle: string, deadline = Infinity): SignedBundle {
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
        const names = synchronousNames(directory, deadline, completeEntryLimit - count); count += names.length;
        for (const name of names) {
          budget(deadline);
          const path = join(directory, name), key = relative(root, path), stat = lstatSync(path);
          if (stat.isSymbolicLink()) {
            const link = readlinkSync(path), target = realpathSync(path);
            if (!target.startsWith(root + sep) || !resolve(dirname(path), link).startsWith(root + sep)) refuse();
            inventory[key] = createHash('sha256').update(`symlink\0${link}`).digest('hex');
          } else if (stat.isDirectory()) walk(path);
          else if (stat.isFile()) {
            const physical = physicalFile(path, stat, deadline); inventory[key] = physical.digest;
            if (['cffaedfe', 'cefaedfe', 'feedfacf', 'cafebabe', 'bebafeca'].includes(physical.magic))
              signature(path, false, key.startsWith('Contents/Resources/browser/runtime/Electron.app/') && key.includes('/Contents/MacOS/'), deadline);
          } else refuse();
        }
      }
      walk(join(root, 'Contents/Resources/browser'));
      if (stable(inventory) !== stable(value.files)) refuse();
      return value;
    };
    const physical: Record<string, PhysicalEntry> = Object.create(null), afterPhysical: Record<string, PhysicalEntry> = Object.create(null);
    phase = 'initial-snapshot';
    const before = completeSnapshot(root, deadline, physical);
    const initial = check(), encoded = stable(initial);
    phase = 'final-snapshot';
    const after = completeSnapshot(root, deadline, afterPhysical);
    phase = 'final-physical-comparison';
    if (before !== after || stable(physical) !== stable(afterPhysical)) refuse();
    // Snapshot validation cannot be bypassed by mutation through a caller-held object.
    function frozen<T>(value: T): T { if (value && typeof value === 'object') { for (const entry of Object.values(value)) frozen(entry); Object.freeze(value); } return value; }
    const manifest = frozen(initial);
    const snapshot: FrozenSnapshot = { encoded: before, physical: Object.freeze(physical), poisoned: false };
    const result: SignedBundle = Object.freeze({ bundle: root, manifest,
      snapshotDigest: createHash('sha256').update(before).digest('hex'),
      assertIdentity(limit = Infinity) {
        let repeatedPhase: SignedVerificationPhase = 'repeated-snapshot';
        try {
          budget(limit);
          const currentPhysical: Record<string, PhysicalEntry> = Object.create(null);
          if (snapshot.poisoned || realpathSync(root) !== root || completeSnapshot(root, limit, currentPhysical) !== before) refuse();
          repeatedPhase = 'repeated-physical';
          if (stable(currentPhysical) !== stable(snapshot.physical)) refuse();
          repeatedPhase = 'repeated-manifest';
          if (stable(boundedJson(join(root, 'Contents/Resources/native-compatibility.json'), limit)) !== encoded) refuse();
          repeatedPhase = 'repeated-cutoff';
          budget(limit);
        } catch (error) { snapshot.poisoned = true; return refuseVerification(repeatedPhase, error); }
      } });
    signedSnapshots.set(result, snapshot); return result;
  } catch (error) { noteVerificationFailure(error, phase); throw error; }
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

