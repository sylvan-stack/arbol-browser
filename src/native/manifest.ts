/** The publisher anchor is source policy, never derived from a running package. */
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { join, dirname, resolve, sep, relative } from 'node:path';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';

// Trust covers physical signed bytes, including ASAR archives, on every check.
// Browser verification uses the mandatory unpatched Electron builtin. The Node
// CLI has an unpatched filesystem already and never imports Electron code.
const { constants, lstatSync, openSync, fstatSync, readSync, closeSync, readdirSync, readlinkSync, realpathSync } =
  createRequire(import.meta.url)(process.type === 'browser' ? 'original-fs' : 'node:fs') as typeof import('node:fs');

export const publisher = Object.freeze({ team: '7V372XL59S', bundleIdentifier: 'com.sylvan-stack.arbol-browser.native-candidate',
  requirement: 'anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' });
export const pinnedRuntime = Object.freeze({ electron: '45.3.2', chromium: '156.0.8078.100', node: '24.22.2', napi: '10', modules: '150', platform: 'darwin', arch: 'arm64', macOS: '27.0.1' });
export const nativeLimit = 1048576;
export type Compatibility = Contract<'native.BuildCompatibility'>;
export function refuse(): never { throw new Error('native_candidate_unavailable'); }
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
  if (deadline !== Infinity && (!Number.isFinite(deadline) || performance.now() >= deadline)) refuse();
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
  const requirement = publisher.requirement + (outer ? ` and identifier "${publisher.bundleIdentifier}"` : '');
  const result = spawnSync('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R', `=${requirement}`, path],
    { timeout: budget(deadline), maxBuffer: nativeLimit, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
  budget(deadline);
  if (result.error || result.status !== 0) refuse();
  const details = spawnSync('/usr/bin/codesign', ['-dvvv', path], { timeout: budget(deadline), maxBuffer: nativeLimit, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  budget(deadline);
  if (details.error || details.status !== 0 || !details.stderr.includes(`TeamIdentifier=${publisher.team}`) ||
      !details.stderr.includes('runtime)') || !details.stderr.includes('Timestamp=')) refuse();
  const ent = spawnSync('/usr/bin/codesign', ['-d', '--entitlements', ':-', path], { timeout: budget(deadline), maxBuffer: nativeLimit, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  budget(deadline);
  if (ent.error || ent.status !== 0 || /com\.apple\.security\.(?:cs\.(?:disable-library-validation|allow-unsigned-executable-memory|allow-dyld-environment-variables)|get-task-allow)/.test(ent.stdout + ent.stderr)) refuse();
  const keys = [...ent.stdout.matchAll(/<key>([^<]+)<\/key>/g)].map(match => match[1]);
  if (keys.length > 1 || keys.some(key => key !== 'com.apple.security.cs.allow-jit' || !jit) ||
      (keys.length && !/<key>com\.apple\.security\.cs\.allow-jit<\/key>\s*<true\s*\/>/.test(ent.stdout))) refuse();
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
const originalAsyncFS = createRequire(import.meta.url)(process.type === 'browser' ? 'original-fs' : 'node:fs') as typeof import('node:fs');
const asynchronousFS = Object.freeze({ lstat: originalAsyncFS.lstat, fstat: originalAsyncFS.fstat, open: originalAsyncFS.open,
  close: originalAsyncFS.close, read: originalAsyncFS.read, readdir: originalAsyncFS.readdir, readlink: originalAsyncFS.readlink, realpath: originalAsyncFS.realpath });
function asyncLstat(path: string): Promise<import('node:fs').BigIntStats> {
  return new Promise((resolve, reject) => asynchronousFS.lstat(path, { bigint: true }, (error, stat) => error ? reject(error) : resolve(stat)));
}
function asyncStat(fd: number): Promise<import('node:fs').BigIntStats> {
  return new Promise((resolve, reject) => asynchronousFS.fstat(fd, { bigint: true }, (error, stat) => error ? reject(error) : resolve(stat)));
}
function asyncRealpath(path: string): Promise<string> {
  return new Promise((resolve, reject) => asynchronousFS.realpath(path, (error, value) => error ? reject(error) : resolve(value)));
}
function asyncNames(path: string): Promise<string[]> {
  return new Promise((resolve, reject) => asynchronousFS.readdir(path, (error, value) => error ? reject(error) : resolve(value.sort())));
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
  const root = signed.bundle, entries: Record<string, string> = {}, keys = Object.keys(snapshot.physical).sort();
  if (keys.length > 4097) refuse();
  const check = async (key: string, topology: boolean): Promise<import('node:fs').BigIntStats> => {
    budget(deadline); if (snapshot.poisoned) refuse();
    const expected = snapshot.physical[key]; if (!expected) refuse();
    const path = key ? join(root, key) : root, stat = await asyncLstat(path);
    budget(deadline);
    if (physicalStamp(stat) !== expected.stamp ||
        (expected.kind === 'directory' ? !stat.isDirectory() : expected.kind === 'file' ? !stat.isFile() : !stat.isSymbolicLink())) refuse();
    if (expected.kind === 'symlink') {
      const link = await asyncLink(path), target = await asyncRealpath(path); budget(deadline);
      if (link !== expected.link || target !== expected.target || !target.startsWith(root + sep) ||
          !resolve(dirname(path), link).startsWith(root + sep) || await asyncLink(path) !== link) refuse();
    } else {
      if (await asyncRealpath(path) !== path) refuse();
      if (topology && expected.kind === 'directory' && stable(await asyncNames(path)) !== stable(expected.children)) refuse();
    }
    budget(deadline); return stat;
  };
  for (const key of keys) {
    const expected = snapshot.physical[key]!, path = key ? join(root, key) : root;
    const named = await check(key, true);
    if (!key) continue;
    if (expected.kind === 'directory') entries[key] = `directory:${named.mode & 0o7777n}`;
    else if (expected.kind === 'symlink') entries[key] = `symlink:${expected.link}`;
    else {
      let fd: number | undefined;
      try {
        fd = await asyncOpen(path); budget(deadline);
        const first = await asyncStat(fd);
        if (!first.isFile() || first.nlink !== 1n || physicalStamp(first) !== expected.stamp || first.size < 0n || first.size > BigInt(Number.MAX_SAFE_INTEGER)) refuse();
        const size = Number(first.size);
        const hash = createHash('sha256'), buffer = Buffer.alloc(65536); let position = 0;
        while (position < size) {
          budget(deadline); const count = await asyncRead(fd, buffer, Math.min(buffer.length, size - position), position);
          budget(deadline); if (count < 1) refuse(); hash.update(buffer.subarray(0, count)); position += count;
        }
        if (await asyncRead(fd, buffer, 1, position) !== 0 || physicalStamp(await asyncStat(fd)) !== expected.stamp) refuse();
        await check(key, false); budget(deadline);
        entries[key] = `file:${first.mode & 0o7777n}:${hash.digest('hex')}`;
      } finally { if (fd !== undefined) await asyncClose(fd); }
    }
    await check(key, true);
  }
  if (stable(entries) !== snapshot.encoded) refuse();
  // Full final physical/topology sweep after hashing, not a partial prefix or
  // an early metadata sample accepted after a slow file operation.
  for (const key of keys) await check(key, true);
  budget(deadline); if (snapshot.poisoned) refuse();
}
export async function compareSignedSnapshot(signed: SignedBundle, deadline: number): Promise<SignedSnapshotComparison> {
  const snapshot = signedSnapshots.get(signed);
  if (!snapshot || snapshot.poisoned || (signed === trustedCandidate && poisonedTrust)) refuse();
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
  } catch {
    snapshot.poisoned = true; if (signed === trustedCandidate) poisonedTrust = true; return refuse();
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
  } catch {
    if (actual) actual.snapshot.poisoned = true;
    if (snapshot) snapshot.poisoned = true;
    if (signed === trustedCandidate) poisonedTrust = true;
    return refuse();
  }
}

let attemptedTrust = false, poisonedTrust = false;
let trustedCandidate: CandidateTrust | undefined;
/** Complete physical signed bundle, including the outer seal and directories.
 * No subprocess, expected-byte learning, or symlink traversal on later checks. */
function completeSnapshot(root: string, deadline = Infinity, physical?: Record<string, PhysicalEntry>): string {
  const entries: Record<string, string> = {};
  function walk(directory: string): void {
    budget(deadline);
    const original = lstatSync(directory), originalStamp = physicalStamp(lstatSync(directory, { bigint: true })), names = readdirSync(directory).sort();
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
      if (after.dev !== before.dev || after.ino !== before.ino || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || physicalStamp(lstatSync(path, { bigint: true })) !== beforeStamp || Object.keys(entries).length > 4096) refuse();
    }
    if (physicalStamp(lstatSync(directory, { bigint: true })) !== originalStamp || stable(readdirSync(directory).sort()) !== stable(names)) refuse();
  }
  walk(root); budget(deadline); return stable(entries);
}
export function assertCandidateTrust(value: CandidateTrust): void {
  if (poisonedTrust || value !== trustedCandidate) refuse();
  value.assertIdentity();
}
export function verifySignedBundle(bundle: string, deadline = Infinity): SignedBundle {
  budget(deadline);
  if (!bundle.endsWith('.app') || realpathSync(bundle) !== resolve(bundle)) refuse();
  const root = resolve(bundle);
  const check = (): Compatibility => {
    signature(root, true, false, deadline);
    if (stable(boundedJson(join(root, 'Contents/Resources/publisher-requirement.json'), deadline)) !== stable(publisher)) refuse();
    const value = boundedJson(join(root, 'Contents/Resources/native-compatibility.json'), deadline);
    if (!validator('native.BuildCompatibility')(value)) return refuse();
    if (value.publisherTeam !== publisher.team || value.bundleIdentifier !== publisher.bundleIdentifier ||
        stable(value.runtime) !== stable(pinnedRuntime) || value.nativeABI.compiledNapi !== 8 ||
        stable(value.featureConfiguration) !== stable({ sitePerProcess: true, disabledFeatures: ['MacAccessibilityTextOperation'], extraChromiumArguments: [] })) refuse();
    const inventory: Record<string, string> = {};
    function walk(directory: string): void {
      for (const name of readdirSync(directory).sort()) {
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
        if (Object.keys(inventory).length > 4096) refuse();
      }
    }
    walk(join(root, 'Contents/Resources/browser'));
    if (stable(inventory) !== stable(value.files)) refuse();
    return value;
  };
  const physical: Record<string, PhysicalEntry> = {}, afterPhysical: Record<string, PhysicalEntry> = {};
  const before = completeSnapshot(root, deadline, physical);
  const initial = check(), encoded = stable(initial);
  const after = completeSnapshot(root, deadline, afterPhysical);
  if (before !== after || stable(physical) !== stable(afterPhysical)) refuse();
  // Snapshot validation cannot be bypassed by mutation through a caller-held object.
  function frozen<T>(value: T): T { if (value && typeof value === 'object') { for (const entry of Object.values(value)) frozen(entry); Object.freeze(value); } return value; }
  const manifest = frozen(initial);
  const snapshot: FrozenSnapshot = { encoded: before, physical: Object.freeze(physical), poisoned: false };
  const result: SignedBundle = Object.freeze({ bundle: root, manifest,
    snapshotDigest: createHash('sha256').update(before).digest('hex'),
    assertIdentity(limit = Infinity) {
      try {
        budget(limit);
        const currentPhysical: Record<string, PhysicalEntry> = {};
        if (snapshot.poisoned || realpathSync(root) !== root || completeSnapshot(root, limit, currentPhysical) !== before ||
            stable(currentPhysical) !== stable(snapshot.physical) ||
            stable(boundedJson(join(root, 'Contents/Resources/native-compatibility.json'), limit)) !== encoded) refuse();
        budget(limit);
      } catch { snapshot.poisoned = true; return refuse(); }
    } });
  signedSnapshots.set(result, snapshot); return result;
}
export function verifyNativeCandidate(bundle: string, deadline = Infinity): CandidateTrust {
  if (poisonedTrust) refuse();
  if (trustedCandidate) {
    if (resolve(bundle) !== trustedCandidate.bundle) { poisonedTrust = true; return refuse(); }
    trustedCandidate.assertIdentity(deadline); return trustedCandidate;
  }
  if (attemptedTrust) refuse(); attemptedTrust = true;
  try { trustedCandidate = verifySignedBundle(bundle, deadline); return trustedCandidate; }
  catch { poisonedTrust = true; return refuse(); }
}

