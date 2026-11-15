/** The publisher anchor is source policy, never derived from a running package. */
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join, dirname, resolve, sep, relative } from 'node:path';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';

// Trust covers physical signed bytes, including ASAR archives, on every check.
// This mandatory Electron builtin leaves the process-wide filesystem view alone.
const { constants, lstatSync, openSync, fstatSync, readFileSync, closeSync, readdirSync, readlinkSync, realpathSync } =
  createRequire(import.meta.url)('original-fs') as typeof import('node:fs');

export const publisher = Object.freeze({ team: '7V372XL59S', bundleIdentifier: 'com.sylvan-stack.arbol-browser.native-candidate',
  requirement: 'anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' });
export const pinnedRuntime = Object.freeze({ electron: '45.3.2', chromium: '156.0.8078.100', node: '24.22.2', napi: '10', modules: '150', platform: 'darwin', arch: 'arm64', macOS: '27.0.1' });
export const nativeLimit = 1048576;
export type Compatibility = Contract<'native.BuildCompatibility'>;
export function refuse(): never { throw new Error('native_candidate_unavailable'); }
export function boundedJson(path: string): unknown {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > nativeLimit) return refuse();
    const raw = readFileSync(fd);
    if (raw.length !== stat.size) return refuse();
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } finally { closeSync(fd); }
}
export function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b, 'en')).map(([key, v]) => `${JSON.stringify(key)}:${stable(v)}`).join(',')}}`;
  return JSON.stringify(value);
}
function signature(path: string, outer = false): void {
  const requirement = publisher.requirement + (outer ? ` and identifier "${publisher.bundleIdentifier}"` : '');
  const result = spawnSync('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R', `=${requirement}`, path],
    { timeout: 5000, maxBuffer: nativeLimit, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
  if (result.error || result.status !== 0) refuse();
  const details = spawnSync('/usr/bin/codesign', ['-dvvv', path], { timeout: 5000, maxBuffer: nativeLimit, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (details.error || details.status !== 0 || !details.stderr.includes(`TeamIdentifier=${publisher.team}`) ||
      !details.stderr.includes('runtime)') || !details.stderr.includes('Timestamp=')) refuse();
  const ent = spawnSync('/usr/bin/codesign', ['-d', '--entitlements', ':-', path], { timeout: 5000, maxBuffer: nativeLimit, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (ent.error || ent.status !== 0 || /com\.apple\.security\.(?:cs\.(?:disable-library-validation|allow-unsigned-executable-memory|allow-dyld-environment-variables)|get-task-allow)/.test(ent.stdout + ent.stderr)) refuse();
}
export interface CandidateTrust {
  readonly bundle: string;
  readonly manifest: Readonly<Compatibility>;
  readonly snapshotDigest: string;
  /** Cryptographic identity only. It cannot assert previous exit or production qualification. */
  assertIdentity(): void;
}
let attemptedTrust = false, poisonedTrust = false;
let trustedCandidate: CandidateTrust | undefined;
/** Complete physical signed bundle, including the outer seal and directories.
 * No subprocess, expected-byte learning, or symlink traversal on later checks. */
function completeSnapshot(root: string): string {
  const entries: Record<string, string> = {};
  function walk(directory: string): void {
    if (realpathSync(directory) !== directory) return refuse();
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name), key = relative(root, path), before = lstatSync(path);
      if (before.isSymbolicLink()) {
        const link = readlinkSync(path), target = realpathSync(path);
        if (!target.startsWith(root + sep) || !resolve(dirname(path), link).startsWith(root + sep) || readlinkSync(path) !== link) refuse();
        entries[key] = `symlink:${link}`;
      } else if (before.isDirectory()) { entries[key] = `directory:${before.mode & 0o7777}`; walk(path); }
      else if (before.isFile()) {
        const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          const first = fstatSync(fd), bytes = readFileSync(fd), last = fstatSync(fd);
          if (first.dev !== before.dev || first.ino !== before.ino || last.ino !== first.ino || last.dev !== first.dev ||
              first.size !== bytes.length || first.size !== last.size || first.mtimeMs !== last.mtimeMs || first.ctimeMs !== last.ctimeMs) refuse();
          entries[key] = `file:${first.mode & 0o7777}:${createHash('sha256').update(bytes).digest('hex')}`;
        } finally { closeSync(fd); }
      } else refuse();
      const after = lstatSync(path);
      if (after.dev !== before.dev || after.ino !== before.ino || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || Object.keys(entries).length > 4096) refuse();
    }
  }
  walk(root); return stable(entries);
}
export function assertCandidateTrust(value: CandidateTrust): void {
  if (poisonedTrust || value !== trustedCandidate) refuse();
  value.assertIdentity();
}
export function verifyNativeCandidate(bundle: string): CandidateTrust {
  if (poisonedTrust) refuse();
  if (trustedCandidate) {
    if (resolve(bundle) !== trustedCandidate.bundle) { poisonedTrust = true; return refuse(); }
    trustedCandidate.assertIdentity(); return trustedCandidate;
  }
  if (attemptedTrust) refuse(); attemptedTrust = true;
  try {
  if (!bundle.endsWith('.app') || realpathSync(bundle) !== resolve(bundle)) refuse();
  const root = resolve(bundle);
  const check = (): Compatibility => {
    signature(root, true);
    if (stable(boundedJson(join(root, 'Contents/Resources/publisher-requirement.json'))) !== stable(publisher)) refuse();
    const value = boundedJson(join(root, 'Contents/Resources/native-compatibility.json'));
    if (!validator('native.BuildCompatibility')(value)) return refuse();
    if (value.publisherTeam !== publisher.team || value.bundleIdentifier !== publisher.bundleIdentifier ||
        stable(value.runtime) !== stable(pinnedRuntime) || value.nativeABI.compiledNapi !== 8 ||
        stable(value.featureConfiguration) !== stable({ sitePerProcess: true, disabledFeatures: ['MacAccessibilityTextOperation'], extraChromiumArguments: [] })) refuse();
    const inventory: Record<string, string> = {};
    function walk(directory: string): void {
      for (const name of readdirSync(directory).sort()) {
        const path = join(directory, name), key = relative(root, path), stat = lstatSync(path);
        if (stat.isSymbolicLink()) {
          const link = readlinkSync(path), target = realpathSync(path);
          if (!target.startsWith(root + sep) || !resolve(dirname(path), link).startsWith(root + sep)) refuse();
          inventory[key] = createHash('sha256').update(`symlink\0${link}`).digest('hex');
        } else if (stat.isDirectory()) walk(path);
        else if (stat.isFile()) {
          inventory[key] = createHash('sha256').update(readFileSync(path)).digest('hex');
          const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
          try {
            const magic = readFileSync(fd).subarray(0, 4).toString('hex');
            if (['cffaedfe', 'cefaedfe', 'feedfacf', 'cafebabe', 'bebafeca'].includes(magic)) signature(path);
          } finally { closeSync(fd); }
        } else refuse();
        if (Object.keys(inventory).length > 4096) refuse();
      }
    }
    walk(join(root, 'Contents/Resources/browser'));
    if (stable(inventory) !== stable(value.files)) refuse();
    return value;
  };
  const before = completeSnapshot(root);
  const initial = check(), encoded = stable(initial);
  const after = completeSnapshot(root);
  if (before !== after) refuse();
  // Snapshot validation cannot be bypassed by mutation through a caller-held object.
  function frozen<T>(value: T): T { if (value && typeof value === 'object') { for (const entry of Object.values(value)) frozen(entry); Object.freeze(value); } return value; }
  const manifest = frozen(initial);
  trustedCandidate = Object.freeze({ bundle: root, manifest,
    snapshotDigest: createHash('sha256').update(before).digest('hex'),
    assertIdentity() {
      try {
        if (poisonedTrust || realpathSync(root) !== root || completeSnapshot(root) !== before ||
            stable(boundedJson(join(root, 'Contents/Resources/native-compatibility.json'))) !== encoded) refuse();
      } catch { poisonedTrust = true; return refuse(); }
    } });
  return trustedCandidate;
  } catch { poisonedTrust = true; return refuse(); }
}

