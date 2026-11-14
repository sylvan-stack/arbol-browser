/** The publisher anchor is source policy, never derived from a running package. */
import { constants, lstatSync, openSync, fstatSync, readFileSync, closeSync, readdirSync, readlinkSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join, dirname, resolve, sep, relative } from 'node:path';
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';

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
  /** Cryptographic identity only. It cannot assert previous exit or production qualification. */
  assertIdentity(): void;
}
export function verifyNativeCandidate(bundle: string): CandidateTrust {
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
  const initial = check(), encoded = stable(initial);
  // Snapshot validation cannot be bypassed by mutation through a caller-held object.
  function frozen<T>(value: T): T { if (value && typeof value === 'object') { for (const entry of Object.values(value)) frozen(entry); Object.freeze(value); } return value; }
  const manifest = frozen(initial);
  return Object.freeze({ bundle: root, manifest, assertIdentity() { if (stable(check()) !== encoded) refuse(); } });
}
