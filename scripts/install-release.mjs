import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, open, opendir, readdir, readlink, realpath, rename, rmdir, symlink,
  unlink } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { Socket } from 'node:net';
import { tmpdir, userInfo } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { addAbortSignal } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { inventory, inventoryDigest } from './package-base.mjs';
import { assertPhysicalCap, canonical, exactFile, hash, json, profileMigrationPredecessor, privateDirectory, writeExclusive } from './package-host.mjs';
import { prepareIsolatedMount, verifyIsolatedRelease, withIsolatedVerificationDeadline } from './isolated-release.mjs';
import { maintenanceFixtureLayout } from './package-host.mjs';
import installation from '../src/runtime/installation-paths.json' with { type: 'json' };
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import browserContract from '../src/contracts/browser.schema.json' with { type: 'json' };
import wireContract from '../src/contracts/wire.schema.json' with { type: 'json' };
import profileContract from '../src/contracts/profile.schema.json' with { type: 'json' };
import profile2Contract from '../src/contracts/profile-format-2.schema.json' with { type: 'json' };
import migrationContract from '../src/contracts/migration.schema.json' with { type: 'json' };
import nativeContract from '../src/contracts/native.schema.json' with { type: 'json' };
import publisher from '../native/production-publisher-requirement.json' with { type: 'json' };

const imageLimit = 1073741824;
const launcherLimit = 67108864;
const launcherIdentifier = 'com.sylvan-stack.arbol-browser.launcher';
const relativeLauncher = 'Contents/Resources/browser/native/stable-launch';
const relativePlatform = 'Contents/Resources/browser/native/platform.node';
const relativePolicy = 'Contents/Resources/host-policy.json';
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const buildNumber = value => typeof value === 'string' && /^[1-9a-f][0-9a-f]{0,15}$/.test(value);

const transactionLimit = 4096 * (4 * 87384 + 8192) + 65536;
const proofLimit = 256 * 1024 * 1024;
const schemas = { browser: browserContract, wire: wireContract, profile: profileContract,
  profile2: profile2Contract, migration: migrationContract, native: nativeContract };
const ajv = new Ajv2020({ strict: true, strictRequired: false, strictTypes: false, coerceTypes: false });
ajv.addKeyword('x-tools'); addFormats(ajv);
for (const schema of Object.values(schemas)) ajv.addSchema(schema);
function valid(name, value) {
  const [bundle, definition] = name.split('.');
  return ajv.getSchema(`${schemas[bundle].$id}#/$defs/${definition}`)(value);
}
function keys(value, names) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...names].sort().join(',');
}
/** Bounded management JSON. Detect duplicate decoded names before JSON.parse. */
function parseStrictJson(bytes, limit = 65536) {
  if (!Number.isSafeInteger(limit) || limit < 1 || bytes.byteLength > limit) throw new Error('Invalid management JSON');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let at = 0;
  const fail = () => { throw new Error('Invalid management JSON'); };
  const space = () => { while (at < text.length && /[\x20\x09\x0a\x0d]/.test(text[at])) at++; };
  const string = () => {
    if (text[at] !== '"') return fail();
    const start = at++;
    while (at < text.length) {
      const char = text[at++];
      if (char === '"') {
        const result = JSON.parse(text.slice(start, at));
        return typeof result === 'string' ? result : fail();
      }
      if (char === '\\') { if (at >= text.length) return fail(); at++; }
      else if (char.charCodeAt(0) < 0x20) return fail();
    }
    return fail();
  };
  const value = (depth) => {
    if (depth > 128) return fail();
    space();
    if (text[at] === '"') { string(); return; }
    if (text[at] === '{') {
      at++; space();
      const keys = new Set();
      if (text[at] === '}') { at++; return; }
      for (;;) {
        space(); const key = string();
        if (keys.has(key)) return fail();
        keys.add(key); space();
        if (text[at++] !== ':') return fail();
        value(depth + 1); space();
        const delimiter = text[at++];
        if (delimiter === '}') return;
        if (delimiter !== ',') return fail();
      }
    }
    if (text[at] === '[') {
      at++; space();
      if (text[at] === ']') { at++; return; }
      for (;;) {
        value(depth + 1); space();
        const delimiter = text[at++];
        if (delimiter === ']') return;
        if (delimiter !== ',') return fail();
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
    if (!token) return fail();
    at += token[0].length;
  };
  value(0); space();
  if (at !== text.length) return fail();
  return JSON.parse(text);
}

async function privateJson(path, limit = 8388608) {
  const file = await exactFile(path, limit);
  if (file.identity.mode !== 0o600 || file.identity.uid !== userInfo().uid) throw new Error('Installer management file is unsafe');
  return { ...file, value: parseStrictJson(file.bytes, limit) };
}
function sameFile(a, b) { return a && b && a.sha256 === b.sha256 && canonical(a.identity) === canonical(b.identity); }

function run(program, args, input, deadline = Infinity) {
  const timeout = Math.min(120000, Math.floor(deadline - performance.now()));
  if (timeout <= 0) throw new InstallationOperationError('Observation verifier deadline exceeded', 5);
  const result = spawnSync(program, args, { input, encoding: 'utf8', timeout, maxBuffer: 1048576,
    ...(Number.isFinite(deadline) && { killSignal: 'SIGKILL' }),
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } });
  if (performance.now() >= deadline) throw new InstallationOperationError('Observation verifier deadline exceeded', 5);
  if (result.error || result.status !== 0) throw new Error(`${basename(program)} refused release verification`);
  return result;
}

function plist(program, args, deadline) {
  const input = run(program, args, undefined, deadline).stdout;
  return JSON.parse(run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], input, deadline).stdout);
}

function checkSignature(path, identifier, deep = false, deadline) {
  const requirement = publisher.requirement + (identifier ? ` and identifier "${identifier}"` : '');
  run('/usr/bin/codesign', ['--verify', '--strict', ...(deep ? ['--deep'] : []), '-R', `=${requirement}`, path], undefined, deadline);
}

async function signedReceipt(path) {
  const signed = await json(path), { value } = signed;
  if (value.format !== 1 || value.kind !== 'signed-production-candidate' || value.image !== 'ArbolBrowser.dmg' ||
      !buildNumber(value.build) || !/^[0-9a-f]{40}$/.test(value.source) || !digest(value.productDigest) ||
      !digest(value.imageSha256) || !digest(value.payloadDigest) || !digest(value.launcherDigest) ||
      !digest(value.reviewDigest) || canonical(value.publisher) !== canonical(publisher) ||
      value.files?.[relativeLauncher] !== value.launcherDigest || !digest(value.files?.[relativePolicy]) ||
      !digest(value.files?.[relativePlatform]) ||
      !value.policy || value.policy.purpose !== 'production' || value.policy.build !== value.build ||
      value.policy.buildRoot !== join(...installation.stableBuilds, value.build) ||
      value.policy.stateRoot !== join(installation.root, installation.browser) ||
      value.policy.productDigest !== value.productDigest || value.policy.reviewDigest !== value.reviewDigest) {
    throw new Error('Invalid signed production receipt');
  }
  return signed;
}

async function mountedApplication(image, mount, attached, deadline) {
  const rows = attached['system-entities']?.filter(row => row['mount-point'] === mount);
  const device = rows?.[0]?.['dev-entry'];
  if (rows?.length !== 1 || !/^\/dev\/disk[0-9]+s[0-9]+$/.test(device)) throw new Error('Image mount mapping is incomplete');
  const images = plist('/usr/bin/hdiutil', ['info', '-plist'], deadline).images;
  const mappings = images.filter(row => row['image-path'] === image ||
    row['system-entities']?.some(entity => entity['mount-point'] === mount));
  const volume = plist('/usr/sbin/diskutil', ['info', '-plist', device], deadline);
  const node = await lstat(device, { bigint: true }), actual = await lstat(mount, { bigint: true });
  if (mappings.length !== 1 || mappings[0]['image-path'] !== image || mappings[0]['owner-uid'] !== userInfo().uid ||
      mappings[0]['image-type'] !== 'UDIF read-only' || mappings[0].writeable !== false ||
      !mappings[0]['system-entities'].some(row => row['mount-point'] === mount && row['dev-entry'] === device) ||
      volume.MountPoint !== mount || volume.DeviceNode !== device || volume.FilesystemType !== 'apfs' ||
      volume.BusProtocol !== 'Disk Image' || volume.WritableVolume !== false || volume.WritableMedia !== false ||
      !node.isBlockDevice() || node.rdev !== actual.dev || await realpath(mount) !== mount ||
      (await readdir(mount)).join(',') !== 'ArbolBrowser.app') throw new Error('Release is not the expected read-only APFS image');
  return join(mount, 'ArbolBrowser.app');
}

/** Retain the opened object and its physical name. This is read-only continuity
 * evidence, not installed selection or native custody. */
async function retainReadIdentity(path, directory = false) {
  if (resolve(path) !== path || await realpath(path) !== path) throw new Error('Nonphysical release input');
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK |
    (directory ? constants.O_DIRECTORY : 0));
  try {
    const first = await fd.stat({ bigint: true });
    const same = value => value.dev === first.dev && value.ino === first.ino && value.mode === first.mode &&
      value.uid === first.uid && value.size === first.size && value.mtimeNs === first.mtimeNs &&
      value.ctimeNs === first.ctimeNs && (directory || value.nlink === 1n);
    const assert = async () => {
      if (!(directory ? first.isDirectory() : first.isFile()) || (first.mode & 0o022n) ||
          ![0n, BigInt(userInfo().uid)].includes(first.uid) || !same(await fd.stat({ bigint: true })) ||
          !same(await lstat(path, { bigint: true })) || await realpath(path) !== path)
        throw new Error('Original release descriptor or path changed');
    };
    await assert();
    return { assert, close: () => fd.close() };
  } catch (error) { await fd.close(); throw error; }
}

/** Pre-lock callers get only authenticated byte observations. Installed format
 * readers additionally hold their original selection/Build/mount locks at the
 * call site. This helper creates no installed path, guard or context. */
async function withProductionImage(image, build, expectedSha256, inspect) {
  if (!buildNumber(build) || !digest(expectedSha256)) throw new Error('Invalid production image identity');
  const home = userInfo().homedir;
  if (await realpath(home) !== home) throw new Error('Account home must be physical');
  const canonicalMount = join(home, ...installation.stableBuilds, build, 'app');
  const canonicalImage = join(home, ...installation.stableUses.slice(0, -1), 'images', `${build}.dmg`);
  const original = await retainReadIdentity(image);
  let mount, directory, attached = false, temporary = false;
  try {
    const before = await exactFile(image, imageLimit);
    if (before.sha256 !== expectedSha256) throw new Error('Signed image digest differs');
    checkSignature(image); await original.assert();
    const mappings = plist('/usr/bin/hdiutil', ['info', '-plist']).images.filter(row =>
      row['image-path'] === image || (image === canonicalImage &&
        row['system-entities']?.some(entity => entity['mount-point'] === canonicalMount)));
    let mapping;
    if (mappings.length) {
      const volumes = mappings[0]['system-entities']?.filter(row => typeof row['mount-point'] === 'string');
      if (image !== canonicalImage || mappings.length !== 1 || mappings[0]['image-path'] !== image ||
          volumes?.length !== 1 || volumes[0]['mount-point'] !== canonicalMount)
        throw new Error('Existing image is not its unique canonical installed mount');
      mount = canonicalMount; mapping = mappings[0];
      await privateDirectory(mount, true);
    } else {
      mount = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-release-')); temporary = true;
      await privateDirectory(mount);
      mapping = plist('/usr/bin/hdiutil', ['attach', image, '-readonly', '-nokernel', '-mountpoint', mount,
        '-noautoopen', '-nobrowse', '-plist']); attached = true;
    }
    directory = await retainReadIdentity(mount, true);
    const app = await mountedApplication(image, mount, mapping);
    const result = await inspect(app);
    if (await mountedApplication(image, mount, mapping) !== app || !sameFile(await exactFile(image, imageLimit), before))
      throw new Error('Production image or mount changed during inspection');
    await directory.assert(); await original.assert();
    return result;
  } finally {
    try { if (directory) await directory.close(); }
    finally {
      try {
        if (temporary) {
          if (attached) run('/usr/bin/hdiutil', ['detach', mount]);
          await rmdir(mount);
        }
      } finally { await original.close(); }
    }
  }
}

/** Verify the original signed image and its sealed app before local activation. */
export async function verifySignedRelease({ image, signedReceiptPath }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Release installation requires Darwin arm64');
  const signed = await signedReceipt(signedReceiptPath), expected = signed.value;
  let launcher, platform, metadata;
  await withProductionImage(image, expected.build, expected.imageSha256, async app => {
    checkSignature(app, publisher.bundleIdentifier, true);
    await assertPhysicalCap(app);
    const files = await inventory(app);
    const policy = await json(join(app, relativePolicy));
    if (inventoryDigest(files) !== expected.payloadDigest || canonical(files) !== canonical(expected.files) ||
        policy.sha256 !== expected.files[relativePolicy] || canonical(policy.value) !== canonical(expected.policy)) {
      throw new Error('Application differs from its recorded signed inventory');
    }
    metadata = await json(join(app, 'Contents/Resources/browser/metadata.json'));
    const component = metadata.value.component;
    if (!keys(component, ['name', 'version', 'build', 'contract', 'profileFormat']) ||
        !valid('profile2.ComponentInfo', { ...component, stateDirectory: expected.policy.stateRoot }) ||
        component.build !== expected.build || metadata.sha256 !== expected.policy.metadataDigest ||
        metadata.value.sourceDigest !== expected.policy.sourceDigest ||
        metadata.value.host?.productDigest !== expected.productDigest) throw new Error('Signed release management format or identity differs');
    const path = join(app, relativeLauncher);
    checkSignature(path, launcherIdentifier);
    launcher = await exactFile(path, launcherLimit);
    if (launcher.sha256 !== expected.launcherDigest) throw new Error('Signed launcher digest differs');
    const addon = join(app, relativePlatform);
    checkSignature(addon);
    platform = await exactFile(addon, launcherLimit);
    if (platform.sha256 !== expected.files[relativePlatform]) throw new Error('Signed installer lock provider differs');
    if (!sameFile(await json(signedReceiptPath), signed)) throw new Error('Release receipt changed during verification');
  });
  return { build: expected.build, source: expected.source, imageSha256: expected.imageSha256,
    payloadDigest: expected.payloadDigest, sourceDigest: metadata.value.sourceDigest,
    productDigest: expected.productDigest, profileFormat: 2, launcher, platform };
}

/** Narrow historical input for the reviewed isolated predecessor adapter.
 * Current verify/install remains format2-only. No historical payload executes. */
export async function withVerifiedMigrationPredecessor(options, consume) {
  const signed = await signedReceipt(options.signedReceiptPath), expected = signed.value, pinned = profileMigrationPredecessor;
  for (const key of ['build', 'source', 'productDigest', 'imageSha256', 'payloadDigest'])
    requireEqual(expected[key], pinned[key], 'Historical release is not the pinned predecessor');
  if (expected.launcherDigest !== pinned.launcherSha256 || expected.policy.sourceDigest !== pinned.sourceDigest ||
      (await exactFile(options.image, imageLimit)).sha256 !== pinned.imageSha256) throw new Error('Historical release differs');
  checkSignature(options.image);
  const mount = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-historical-input-'));
  await privateDirectory(mount); let attached = false;
  try {
    const data = plist('/usr/bin/hdiutil', ['attach', options.image, '-readonly', '-nokernel', '-mountpoint', mount,
      '-noautoopen', '-nobrowse', '-plist']); attached = true;
    const app = await mountedApplication(options.image, mount, data);
    checkSignature(app, publisher.bundleIdentifier, true); await assertPhysicalCap(app);
    const files = await inventory(app), policy = await json(join(app, relativePolicy));
    const metadata = await json(join(app, 'Contents/Resources/browser/metadata.json'));
    const compatibility = await json(join(app, 'Contents/Resources/native-compatibility.json'));
    if (inventoryDigest(files) !== pinned.payloadDigest || !equal(files, expected.files) || !equal(policy.value, expected.policy) ||
        policy.sha256 !== expected.files[relativePolicy] || metadata.sha256 !== policy.value.metadataDigest ||
        compatibility.sha256 !== policy.value.compatibilityDigest || metadata.value.component?.profileFormat !== 1 ||
        metadata.value.component?.contract !== 1 || metadata.value.component?.build !== pinned.build ||
        metadata.value.sourceDigest !== pinned.sourceDigest || metadata.value.host?.productDigest !== pinned.productDigest ||
        metadata.value.sourceIdentity?.commit !== pinned.source || files[relativeLauncher] !== pinned.launcherSha256)
      throw new Error('Historical sealed payload provenance differs');
    const result = await consume({ app, signed: expected, files, metadata: metadata.value, compatibility: compatibility.value,
      policy: policy.value, receiptSha256: signed.sha256 });
    if ((await exactFile(options.image, imageLimit)).sha256 !== pinned.imageSha256 ||
        (await signedReceipt(options.signedReceiptPath)).sha256 !== signed.sha256 || !equal(await inventory(app), files))
      throw new Error('Historical input changed during staging');
    return result;
  } finally { if (attached) run('/usr/bin/hdiutil', ['detach', mount]); await rmdir(mount); }
}

async function safeDirectories(home, parts, privateFrom) {
  let path = home;
  if (await realpath(home) !== home) throw new Error('Account home must be physical');
  for (const [index, name] of parts.entries()) {
    path = join(path, name);
    try { await mkdir(path, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    if (index >= privateFrom) await privateDirectory(path, true);
    else {
      const stat = await lstat(path);
      if (!stat.isDirectory() || stat.uid !== userInfo().uid || (stat.mode & 0o022) || await realpath(path) !== path)
        throw new Error('Installed directory ancestry is unsafe');
    }
  }
  return path;
}

async function syncPath(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}

async function publishExact(path, maximum, sha256, stage, publication) {
  if (!publication) throw new Error('Native EX publication authority required');
  if (publication) {
    const existing = await optionalFile(path, maximum);
    if (existing) {
      if (existing.sha256 !== sha256 || existing.identity.uid !== userInfo().uid) throw new Error('Installed immutable file differs');
      await syncPath(path); await syncPath(dirname(path));
      const current = await exactFile(path, maximum);
      if (!sameFile(current, existing)) throw new Error('Installed immutable file changed during synchronization');
      return current;
    }
  }
  const tmp = join(dirname(path), `.install-${randomBytes(12).toString('hex')}`);
  await stage(tmp);
  try {
    if ((await exactFile(tmp, maximum)).sha256 !== sha256) throw new Error('Installed input changed while copying');
    await syncPath(tmp);
    if (publication) {
      const staged = await exactFile(tmp, maximum);
      publication.provider.assertLock(publication.selection);
      publication.provider.publishInstallerFile(publication.selection, JSON.stringify({ source: tmp, destination: path,
        identity: staged.identity, sha256 }));
    }
  } finally {
    try { await unlink(tmp); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await syncPath(dirname(path));
  }
  const result = await exactFile(path, maximum);
  if (result.sha256 !== sha256 || result.identity.uid !== userInfo().uid) throw new Error('Installed path already holds different content');
  return result;
}

async function optionalFile(path, maximum) {
  try { return await exactFile(path, maximum); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return undefined;
}

async function optionalSelection(path) {
  const file = await optionalFile(path, 4096);
  if (!file) return null;
  const value = parseStrictJson(file.bytes, 4096);
  if (value?.scope === 'rehearsal') throw new Error('Withdraw the guarded Browser rehearsal before installing a release');
  if (Object.keys(value).sort().join(',') !== 'build,format,imageSha256' || value.format !== 1 ||
      !buildNumber(value.build) || !digest(value.imageSha256) || file.identity.mode !== 0o600 ||
      file.identity.uid !== userInfo().uid) throw new Error('Installed Browser selection is unsafe');
  return value;
}

function encode(value) { return Buffer.from(JSON.stringify(value) + '\n'); }

async function replaceFile(path, bytes, mode) {
  const tmp = join(dirname(path), `.replace-${randomBytes(12).toString('hex')}`);
  await writeExclusive(tmp, bytes, mode);
  try {
    await rename(tmp, path);
    await syncPath(dirname(path));
  } finally {
    try { await unlink(tmp); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

async function checkedGuard(path, create = true) {
  if (create) {
    try { await writeExclusive(path, ''); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  const guard = await lstat(path, { bigint: true });
  if (!guard.isFile() || guard.uid !== BigInt(userInfo().uid) || guard.nlink !== 1n || (guard.mode & 0o7777n) !== 0o600n ||
      await realpath(path) !== path) throw new Error('Installed Build guard is unsafe');
  return guard;
}

const installerLocks = new WeakMap();
class InstallationOperationError extends Error {
  constructor(message, qualificationExitCode, options) {
    super(message, options);
    this.qualificationExitCode = qualificationExitCode;
  }
}
class PendingMigrationCandidateMismatch extends Error {}

async function withLock(provider, path, work, create = true, acquire = 'tryLock') {
  const expected = await checkedGuard(path, create);
  const held = provider[acquire](path);
  if (!held) throw new InstallationOperationError('The Browser installation or selected Build is in use', 4);
  installerLocks.set(provider, (installerLocks.get(provider) ?? 0) + 1);
  try {
    const current = provider.assertLock(held);
    if (current.device !== String(expected.dev) || current.inode !== String(expected.ino)) throw new Error('Browser Build guard changed');
    return await work(held);
  }
  finally {
    provider.releaseLock(held);
    installerLocks.set(provider, installerLocks.get(provider) - 1);
  }
}

async function withLockProvider(platform, work, budget = null) {
  const tmp = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-installer-'));
  const path = join(tmp, 'platform.node');
  try {
    await writeExclusive(path, platform.bytes);
    budget?.check(platform.bytes.length);
    if ((await exactFile(path, launcherLimit)).sha256 !== platform.sha256) throw new Error('Installer lock provider changed');
    budget?.check(platform.bytes.length);
    checkSignature(path, undefined, false, budget?.deadline);
    const provider = createRequire(import.meta.url)(path);
    return await work(provider);
  } finally {
    try { await unlink(path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await rmdir(tmp);
  }
}

async function installedImageReceipt(support, selected) {
  const receipt = await json(join(support, 'releases', `${selected.build}.json`)), { value } = receipt;
  if (receipt.identity.mode !== 0o600 || receipt.identity.uid !== userInfo().uid || value.format !== 1 ||
      value.build !== selected.build || value.imageSha256 !== selected.imageSha256 ||
      !digest(value.launcherSha256) || !digest(value.payloadDigest)) throw new Error('Installed release receipt differs from selection');
  return value;
}

async function installedAlias(alias, executable) {
  let info;
  try { info = await lstat(alias, { bigint: true }); } catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
  if (!info.isSymbolicLink() || info.uid !== BigInt(userInfo().uid) || await readlink(alias) !== executable)
    throw new Error('Browser PATH entry has a different owner or target');
  return { device: info.dev, inode: info.ino };
}

async function ensureAlias(alias, executable) {
  if (await installedAlias(alias, executable)) return;
  await symlink(executable, alias);
  if (!await installedAlias(alias, executable)) throw new Error('Published Browser PATH entry disappeared');
  await syncPath(dirname(alias));
}

async function recoverInstall(context, provider, existingOnly = false) {
  const { support, executable, alias, uses } = context;
  await assertContext(context);
  const journal = join(support, 'install-transaction.json'), backup = join(support, 'install-previous-launcher');
  const pending = await optionalFile(journal, 4096);
  if (!pending) return;
  const decoded = parseStrictJson(pending.bytes, 4096);
  if (decoded.format === 3) throw new Error('Journal3 requires forward signed maintenance; legacy rollback cannot consume it');
  const { format, before, after, aliasBefore } = decoded;
  const checked = item => item && item.selection?.format === 1 && buildNumber(item.selection.build) &&
    digest(item.selection.imageSha256) && digest(item.launcherSha256);
  if (pending.identity.mode !== 0o600 || pending.identity.uid !== userInfo().uid ||
      ![1, 2].includes(format) || (format === 2 && typeof aliasBefore !== 'boolean') ||
      (before !== null && !checked(before)) || !checked(after) ||
      before?.selection.build === after.selection.build) throw new Error('Browser installation journal is unsafe');
  const selectionPath = join(support, 'selected.json');
  const selected = await optionalSelection(selectionPath);
  if (![before?.selection ?? null, after.selection].some(value => canonical(value) === canonical(selected))) {
    throw new Error('Browser selection changed outside its installation transaction');
  }
  const current = await optionalFile(executable, launcherLimit);
  const target = canonical(selected) === canonical(after.selection) ? after : before;
  const unchanged = target && current?.sha256 === target.launcherSha256;
  await withLock(provider, join(uses, selected?.build ?? after.selection.build), async () => {
    if (format === 2) {
      const entry = await installedAlias(alias, executable);
      if ((target === after || aliasBefore) && !entry) throw new Error('Browser PATH entry changed during installation');
      if (target !== after && !aliasBefore && entry) {
        const observed = await installedAlias(alias, executable);
        if (!observed || entry.device !== observed.device || entry.inode !== observed.inode)
          throw new Error('Browser PATH entry changed during rollback');
        await unlink(alias);
        await syncPath(dirname(alias));
      }
    }
    if (target && !unchanged) {
      if (target === after || (current && current.sha256 !== after.launcherSha256)) throw new Error('Uncertain installed launcher identity');
      const original = await exactFile(backup, launcherLimit);
      if (original.sha256 !== target.launcherSha256) throw new Error('Previous launcher recovery bytes differ');
      checkContextLauncher(context, backup, target.launcherSha256);
      await replaceFile(executable, original.bytes, contextLauncherMode(context, target.launcherSha256));
    } else if (!target && current) {
      if (current.sha256 !== after.launcherSha256) throw new Error('Uncertain first installation');
      await unlink(executable);
      await syncPath(dirname(executable));
    }
    if (target) checkContextLauncher(context, executable, target.launcherSha256);
    await unlink(journal);
    try { await unlink(backup); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await syncPath(support);
  }, false, existingOnly ? 'tryExistingQualificationObserverLock' : 'tryLock');
}

/** Read the predecessor format from its exact signed installed image, never
 * from a Build number, rehearsal selection or editable format hint. */
async function installedProfileFormat(context, selected, custody) {
  const { support } = context;
  await custody.assertBuild(selected.build);
  const receiptPath = join(support, 'releases', `${selected.build}.json`);
  const originalReceipt = await privateJson(receiptPath, 4096);
  const receipt = await installedImageReceipt(support, selected);
  requireEqual(receipt, originalReceipt.value);
  if (!keys(receipt, ['format', 'build', 'imageSha256', 'source', 'payloadDigest', 'launcherSha256']) ||
      !/^[0-9a-f]{40}$/.test(receipt.source)) throw new Error('Installed release receipt is incomplete');
  const image = join(support, 'images', `${selected.build}.dmg`);
  const provider = custody.publication.provider, mountGuard = join(context.uses, `${selected.build}.mount`);
  return withLock(provider, mountGuard, async held => {
    const originalMountGuard = await guardRecord(provider, mountGuard, held);
    await custody.assertBuild(selected.build);
    const format = await withProductionImage(image, selected.build, selected.imageSha256, async app => {
      checkSignature(app, publisher.bundleIdentifier, true);
      if (inventoryDigest(await inventory(app)) !== receipt.payloadDigest) throw new Error('Installed predecessor inventory differs');
      const metadata = await json(join(app, 'Contents/Resources/browser/metadata.json'));
      const policy = await json(join(app, relativePolicy));
      const component = metadata.value.component;
      if (!keys(component, ['name', 'version', 'build', 'contract', 'profileFormat']) ||
          !valid('wire.ComponentInfo', { ...component, stateDirectory: policy.value.stateRoot }) ||
          component.build !== selected.build || policy.value.purpose !== 'production' ||
          policy.value.build !== selected.build || policy.value.buildRoot !== join(...installation.stableBuilds, selected.build) ||
          policy.value.stateRoot !== join(installation.root, installation.browser) ||
          policy.value.metadataDigest !== metadata.sha256 || policy.value.sourceDigest !== metadata.value.sourceDigest ||
          policy.value.productDigest !== metadata.value.host?.productDigest ||
          metadata.value.sourceIdentity?.commit !== receipt.source) throw new Error('Installed predecessor metadata differs');
      if (!sameFile(await privateJson(receiptPath, 4096), originalReceipt)) throw new Error('Installed predecessor receipt changed');
      return component.profileFormat;
    });
    requireEqual(await guardRecord(provider, mountGuard, held), originalMountGuard);
    await custody.assertBuild(selected.build);
    return format;
  }, false);
}
async function installationJournal(support) {
  const path = join(support, 'install-transaction.json');
  if (!await optionalFile(path, 16384)) return null;
  const file = await privateJson(path, 16384);
  if (file.value.format === 3 && (!valid('migration.Journal', file.value) ||
      file.value.before?.selection.build === file.value.after.selection.build)) throw new Error('Journal3 is unsafe');
  if (![1, 2, 3].includes(file.value.format)) throw new Error('Unknown installation journal');
  return file;
}
async function installationRoute(context, release, custody, expectedMismatch = null) {
  if (release.profileFormat !== 2) throw new Error('Current release must operate profile format2');
  const pending = await installationJournal(context.support);
  const selected = await optionalSelection(context.selectionPath);
  const after = { selection: { format: 1, build: release.build, imageSha256: release.imageSha256 },
    launcherSha256: release.launcher.sha256 };
  if (pending) {
    if (pending.value.format !== 3) return { kind: 'legacy', pending };
    if (![pending.value.before?.selection ?? null, pending.value.after.selection].some(value => equal(value, selected)))
      throw new Error('Pending conversion requires its exact signed candidate and selection');
    if (!equal(pending.value.after, after)) {
      const reason = 'Pending conversion requires its exact signed candidate and selection';
      if (expectedMismatch && sameFile(pending, expectedMismatch.journal) &&
          equal(pending.value.before, expectedMismatch.before) && equal(pending.value.after, expectedMismatch.after))
        throw new PendingMigrationCandidateMismatch(reason);
      throw new Error(reason);
    }
    return { kind: 'migration', pending, previous: pending.value.before?.selection ?? null };
  }
  if (canonical(selected) === canonical(after.selection)) return { kind: 'same', previous: selected };
  if (selected && BigInt(`0x${selected.build}`) >= BigInt(`0x${release.build}`)) throw new Error('Release number cannot move backwards');
  const format = selected ? await contextProfileFormat(context, selected, custody) : null;
  if (format === 2) return { kind: 'ordinary', previous: selected };
  // Completed migration evidence is immutable, not reusable for a new
  // candidate or permission to select an old writer again.
  const cutovers = (await readdir(join(context.support, 'releases'))).filter(name => /^[1-9a-f][0-9a-f]{0,15}\.migration\.json$/.test(name));
  if (cutovers.length || await optionalFile(join(context.runtime, 'browser-profile-migration/current'), 16384))
    throw new Error('Format1 selection contradicts retained cutover evidence');
  return { kind: 'migration', pending: null, previous: selected };
}

async function releaseContext(release) {
  const { homedir: home } = userInfo(), supportParts = installation.stableUses.slice(0, -1);
  const privateFrom = supportParts.length - 1;
  const support = await safeDirectories(home, supportParts, privateFrom);
  const uses = await safeDirectories(home, installation.stableUses, privateFrom);
  const bin = await safeDirectories(home, [...installation.stableBuilds.slice(0, 2), 'bin'], 1);
  const executable = join(bin, 'arbol-browser');
  const alias = join(await safeDirectories(home, ['.local', 'bin'], 2), 'arbol-browser');
  const images = await safeDirectories(home, [...supportParts, 'images'], privateFrom);
  const receipts = await safeDirectories(home, [...supportParts, 'releases'], privateFrom);
  const mount = await safeDirectories(home, [...installation.stableBuilds, release.build, 'app'], 1);
  return { home, support, uses, executable, alias, images, receipts, mount,
    image: join(images, `${release.build}.dmg`), selectionPath: join(support, 'selected.json'),
    runtime: join(home, installation.root, 'runtime'), state: join(home, installation.root, installation.browser),
    journalPath: join(support, 'install-transaction.json'), backup: join(support, 'install-previous-launcher'),
    proofPath: join(receipts, `${release.build}.migration.json`) };
}

// Only the private factory below can associate a context with isolated
// authority. Neither public installer accepts a caller-created context,
// verifier, native result or completion observation.
const isolatedAuthorities = new WeakMap();
function verifyInIsolatedContext(context, verify) {
  const authority = isolatedAuthorities.get(context);
  return authority?.boundedVerification
    ? withIsolatedVerificationDeadline(performance.now() + 480000, verify)
    : verify();
}

async function assertContext(context) {
  const authority = isolatedAuthorities.get(context);
  if (!authority) return;
  const { release, directories, inputs, releases, observationBudget } = authority;
  requireEqual(await maintenanceFixtureLayout(dirname(dirname(release.fixture.bundle)), context.state), release.fixture);
  for (const [path, identity] of directories) requireEqual(await privateDirectory(path, true), identity);
  for (const [build, input] of inputs) {
    const receipt = observationBudget ? await observeFile(input.signedReceiptPath, 8388608n, observationBudget) :
      await exactFile(input.signedReceiptPath, 8388608);
    if (receipt.sha256 !== releases.get(build).receiptSha256)
      throw new Error('Original isolated receipt changed');
  }
}
function contextLauncher(context, sha256) {
  const authority = isolatedAuthorities.get(context);
  if (!authority) return { launcherIdentifier, launcherMode: 0o755 };
  const release = [...authority.releases.values()].find(item => item.launcher.sha256 === sha256);
  if (!release) throw new Error('Launcher is outside the authenticated isolated cohort');
  return release;
}
function contextLauncherMode(context, sha256) { return contextLauncher(context, sha256).launcherMode; }
function checkContextLauncher(context, path, sha256, deadline) {
  checkSignature(path, contextLauncher(context, sha256).launcherIdentifier, false, deadline);
}
function contextPredecessor(context) {
  const authority = isolatedAuthorities.get(context);
  if (!authority) return profileMigrationPredecessor;
  const release = authority.releases.get(profileMigrationPredecessor.build);
  return release?.profileFormat === 1 ? { ...release, launcherSha256: release.launcher.sha256 } : null;
}
async function contextProfileFormat(context, selected, custody) {
  const authority = isolatedAuthorities.get(context);
  if (!authority) return installedProfileFormat(context, selected, custody);
  await assertContext(context);
  const input = authority.inputs.get(selected.build), expected = authority.releases.get(selected.build);
  if (!input || expected.imageSha256 !== selected.imageSha256) throw new Error('Selected isolated release is outside the cohort');
  const verified = await verifyInIsolatedContext(context,
    () => verifyIsolatedRelease({ ...input, image: join(context.images, `${selected.build}.dmg`) }));
  requireEqual(await installedImageReceipt(context.support, selected), { format: 1, build: expected.build,
    imageSha256: expected.imageSha256, source: expected.source, payloadDigest: expected.payloadDigest,
    launcherSha256: expected.launcher.sha256 });
  if (verified.receiptSha256 !== expected.receiptSha256 || verified.imageSha256 !== expected.imageSha256)
    throw new Error('Original isolated release changed');
  return verified.profileFormat;
}
async function isolatedContext(options) {
  const predecessors = options.predecessors ?? [];
  if (!Array.isArray(predecessors) || predecessors.length > 4096) throw new Error('Invalid isolated release cohort');
  const inputs = new Map(), releases = new Map(); let release;
  for (const value of [options, ...predecessors]) {
    const input = { image: value.image, signedReceiptPath: value.signedReceiptPath, review: value.review };
    const verified = await verifyIsolatedRelease(input);
    if (releases.has(verified.build)) throw new Error('Duplicate isolated release identity');
    release ??= verified;
    for (const key of ['fixture', 'directories', 'stateRoot', 'runtime', 'registry', 'launcher'])
      requireEqual(verified.fixture[key], release.fixture[key], 'Isolated releases name different physical authority');
    releases.set(verified.build, verified); inputs.set(verified.build, input);
  }
  if (release.profileFormat !== 2) throw new Error('Isolated installer requires a current format2 candidate');
  return createIsolatedContext(release, inputs, releases);
}
function isolatedLayout(release) {
  const { fixture } = release, support = join(fixture.fixture, 'support');
  const images = join(support, 'images'), receipts = join(support, 'releases');
  const aliases = join(fixture.fixture, 'aliases'), mount = dirname(fixture.bundle);
  return { support, uses: join(fixture.registry, '.uses'), executable: fixture.launcher,
    alias: join(aliases, 'arbol-browser'), images, receipts, mount,
    image: join(images, `${release.build}.dmg`), selectionPath: join(support, 'selected.json'),
    runtime: fixture.runtime, state: fixture.stateRoot, journalPath: join(support, 'install-transaction.json'),
    backup: join(support, 'install-previous-launcher'), proofPath: join(receipts, `${release.build}.migration.json`) };
}

/** Private layout factory. Its only historical caller authenticates the fixed
 * four-role authority and performs separate pristine/partial setup checks. */
async function createIsolatedContext(release, inputs, releases, boundedVerification = false) {
  const context = isolatedLayout(release);
  const { images, receipts, alias, executable, mount } = context;
  const directories = new Map();
  for (const path of [images, receipts, dirname(alias), dirname(executable)]) {
    try { await mkdir(path, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const identity = await privateDirectory(path, true);
    if (identity.device !== release.fixture.directories.fixture.device) throw new Error('Isolated installer directories crossed filesystems');
    directories.set(path, identity);
  }
  await privateDirectory(dirname(mount), true);
  try { await mkdir(mount, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  await privateDirectory(mount, true);
  isolatedAuthorities.set(context, { release, inputs, releases, directories, boundedVerification });
  await assertContext(context);
  return { context, release };
}

/** Explicit disposable entry. All paths and launcher identities derive from
 * real signed images. Its common lifecycle cannot manufacture native custody. */
export async function installIsolatedRelease(options) {
  const { context, release } = await isolatedContext(options);
  return installVerifiedRelease(context, release, options);
}
async function mountIsolatedCandidate(context, release, provider, initialization = null) {
  const authority = isolatedAuthorities.get(context);
  if (!authority) return;
  await withLock(provider, join(context.uses, `${release.build}.mount`), async handle => {
    if (initialization) requireEqual(await guardRecord(provider, join(context.uses, `${release.build}.mount`), handle), initialization.guards.mount);
    await assertContext(context);
    const mounted = await verifyInIsolatedContext(context,
      () => prepareIsolatedMount({ ...authority.inputs.get(release.build), image: context.image }));
    requireEqual(mounted, { build: release.build, imageSha256: release.imageSha256,
      bundle: release.fixture.bundle, mount: context.mount });
    await assertContext(context);
    if (initialization) requireEqual(await guardRecord(provider, join(context.uses, `${release.build}.mount`), handle), initialization.guards.mount);
  }, false, initialization ? 'tryExistingInitializationLock' : 'tryLock');
}
async function guardRecord(provider, path, handle) {
  const expected = await checkedGuard(path, false), actual = provider.assertLock(handle);
  if (actual.device !== String(expected.dev) || actual.inode !== String(expected.ino) || actual.uid !== Number(expected.uid))
    throw new Error('Original installation guard changed');
  return { path, identity: { ...actual, mode: 0o600 }, heldMode: 2 };
}
/** Every handle is closed before returning. The result of work must contain
 * observations only, never these native EX descriptions or publication cap. */
async function withInstallationGuards(context, provider, previous, build, work, createNew = false, existingOnly = false) {
  await assertContext(context);
  const acquire = existingOnly ? 'tryExistingQualificationObserverLock' : 'tryLock';
  return withLock(provider, join(context.support, 'selection.lock'), async selection => {
    const candidate = async old => withLock(provider, join(context.uses, build), async next => {
      const guards = { selection: await guardRecord(provider, join(context.support, 'selection.lock'), selection),
        oldBuild: old ? await guardRecord(provider, join(context.uses, previous.build), old) : null,
        newBuild: await guardRecord(provider, join(context.uses, build), next) };
      const assert = async () => {
        await assertContext(context);
        const current = { selection: await guardRecord(provider, guards.selection.path, selection),
          oldBuild: old ? await guardRecord(provider, guards.oldBuild.path, old) : null,
          newBuild: await guardRecord(provider, guards.newBuild.path, next) };
        if (canonical(current) !== canonical(guards)) throw new Error('Installation custody changed');
      };
      const assertBuild = async build => {
        await assert();
        const path = join(context.uses, build);
        if (!buildNumber(build) || ![guards.oldBuild, guards.newBuild].some(guard => guard?.path === path))
          throw new Error('Installed image reader lacks original matching Build custody');
      };
      await assert();
      return work({ guards, assert, assertBuild, publication: { provider, selection } });
    }, createNew, createNew ? 'tryLock' : acquire);
    return previous && previous.build !== build
      ? withLock(provider, join(context.uses, previous.build), candidate, false, acquire) : candidate(null);
  }, !existingOnly, acquire);
}
function fileReference(file) { return file ? { identity: file.identity, sha256: file.sha256 } : null; }
async function selectionFile(context) {
  const file = await optionalFile(context.selectionPath, 4096);
  const value = await optionalSelection(context.selectionPath);
  if (Boolean(file) !== Boolean(value) || (file && canonical(parseStrictJson(file.bytes, 4096)) !== canonical(value)))
    throw new Error('Selection changed during observation');
  return { value, file: fileReference(file) };
}
async function stageReleaseAssets(context, release, options, custody, createMountGuard = true) {
  await custody.assert();
  const image = await publishExact(context.image, imageLimit, release.imageSha256, async path => {
    await copyFile(options.image, path, constants.COPYFILE_EXCL); await chmod(path, 0o600);
  }, custody.publication);
  if (image.identity.mode !== 0o600) throw new Error('Installed image mode differs');
  await checkedGuard(join(context.uses, `${release.build}.mount`), createMountGuard); await syncPath(context.uses);
  const bytes = encode({ format: 1, build: release.build, imageSha256: release.imageSha256,
    source: release.source, payloadDigest: release.payloadDigest, launcherSha256: release.launcher.sha256 });
  const receipt = await publishExact(join(context.receipts, `${release.build}.json`), 4096, hash(bytes),
    path => writeExclusive(path, bytes), custody.publication);
  if (receipt.identity.mode !== 0o600) throw new Error('Installed release receipt mode differs');
  await custody.assert(); return { image: fileReference(image), release: fileReference(receipt) };
}
/** Idempotently finish journal-before-launcher preparation while still under
 * the original EX. This helper never switches selection or opens admission. */
async function prepareMigrationRelease(context, release, options, route, custody, retry = false) {
  await privateDirectory(context.runtime, true); await privateDirectory(dirname(context.state), true);
  await custody.assert();
  const selected = await selectionFile(context);
  if (canonical(selected.value) !== canonical(route.previous)) throw new Error('Original Browser selection changed');
  const assets = retry ? await existingQualificationReleaseAssets(context, release, custody) :
    await stageReleaseAssets(context, release, options, custody);
  const old = route.previous ? await installedImageReceipt(context.support, route.previous) : null;
  const after = { selection: { format: 1, build: release.build, imageSha256: release.imageSha256 },
    launcherSha256: release.launcher.sha256 };
  const before = old ? { selection: route.previous, launcherSha256: old.launcherSha256 } : null;
  let journal = route.pending;
  let launcher = await optionalFile(context.executable, launcherLimit);
  if (!journal) {
    if (old ? launcher?.sha256 !== old.launcherSha256 : Boolean(launcher)) throw new Error('Original launcher differs');
    if (launcher) {
      checkContextLauncher(context, context.executable, old.launcherSha256);
      await publishExact(context.backup, launcherLimit, launcher.sha256,
        path => writeExclusive(path, launcher.bytes, 0o755), custody.publication);
    } else if (await optionalFile(context.backup, launcherLimit)) throw new Error('Unexpected first-install launcher backup');
    const value = { format: 3, aliasBefore: Boolean(await installedAlias(context.alias, context.executable)), before, after,
      migration: { fromProfileFormat: 1, toProfileFormat: 2 } };
    if (!valid('migration.Journal', value)) throw new Error('Invalid maintenance journal');
    const bytes = encode(value);
    await publishExact(context.journalPath, 16384, hash(bytes), path => writeExclusive(path, bytes), custody.publication);
    journal = await privateJson(context.journalPath, 16384);
  }
  if (!valid('migration.Journal', journal.value) || canonical(journal.value.before) !== canonical(before) ||
      canonical(journal.value.after) !== canonical(after) || !sameFile(await privateJson(context.journalPath, 16384), journal))
    throw new Error('Original maintenance journal changed');
  if (before) {
    const backup = await exactFile(context.backup, launcherLimit);
    if (backup.sha256 !== before.launcherSha256 || backup.identity.mode !== 0o755) throw new Error('Original launcher backup differs');
    checkContextLauncher(context, context.backup, before.launcherSha256);
  }
  launcher = await optionalFile(context.executable, launcherLimit);
  if (launcher?.sha256 !== after.launcherSha256) {
    if (retry) throw new Error('Retry requires the original prepared launcher');
    if (before ? launcher?.sha256 !== before.launcherSha256 : Boolean(launcher)) throw new Error('Unknown launcher preparation state');
    await replaceFile(context.executable, release.launcher.bytes, contextLauncherMode(context, release.launcher.sha256));
  }
  launcher = await exactFile(context.executable, launcherLimit);
  if (launcher.sha256 !== after.launcherSha256 || launcher.identity.mode !== contextLauncherMode(context, release.launcher.sha256)) throw new Error('Prepared launcher differs');
  checkContextLauncher(context, context.executable, release.launcher.sha256);
  if (retry) {
    if (!await installedAlias(context.alias, context.executable)) throw new Error('Retry requires the original prepared alias');
  } else await ensureAlias(context.alias, context.executable);
  await custody.assert();
  const current = await selectionFile(context);
  if (canonical(current) !== canonical(selected) || !sameFile(await privateJson(context.journalPath, 16384), journal))
    throw new Error('Maintenance preparation changed original admission');
  return { journal: { ...fileReference(journal), value: journal.value }, guards: custody.guards,
    selection: selected, assets, launcher: fileReference(launcher),
    state: { parent: await privateDirectory(dirname(context.state), true), runtime: await privateDirectory(context.runtime, true) },
    oldAssets: before ? { image: fileReference(await exactFile(join(context.images, `${before.selection.build}.dmg`), imageLimit)),
      release: fileReference(await privateJson(join(context.receipts, `${before.selection.build}.json`))),
      launcher: fileReference(await exactFile(context.backup, launcherLimit)) } : null };
}

/** The signed launcher acquires its OWN EX descriptions. The installer
 * must have left every lock scope before this call: retaining another EX
 * description would conflict with native acquisition, not transfer custody. */
async function invokeSignedMaintenance(context, release, prepared, provider, engineInterruption = null, retry = false) {
  if ((installerLocks.get(provider) ?? 0) !== 0) throw new Error('Installer custody must end before maintenance handoff');
  const launcher = await exactFile(context.executable, launcherLimit);
  const journal = await privateJson(context.journalPath, 16384);
  if (!sameFile(launcher, prepared.launcher) || launcher.sha256 !== release.launcher.sha256 ||
      !sameFile(journal, prepared.journal) || !valid('migration.Journal', journal.value))
    throw new Error('Signed maintenance handoff changed');
  checkContextLauncher(context, context.executable, release.launcher.sha256);
  const isolated = isolatedAuthorities.get(context);
  if (retry) await verifyQualificationRetryMount(context, release);
  else await mountIsolatedCandidate(context, release, provider);
  await assertContext(context);
  if (!sameFile(await exactFile(context.executable, launcherLimit), prepared.launcher) ||
      !sameFile(await privateJson(context.journalPath, 16384), prepared.journal))
    throw new Error('Signed maintenance inputs changed while preparing the mount');
  if ((installerLocks.get(provider) ?? 0) !== 0) throw new Error('Mount custody must end before native handoff');
  // Production accepts no policy/root/runtime/environment selector. Isolated
  // arguments come only from this call's authenticated signed fixture.
  const args = isolated ? ['--isolated-maintenance-migrate-profiles', '--policy',
    join(release.fixture.bundle, 'Contents/Resources/maintenance-fixture.json'), '--runtime', context.runtime,
    '--bundle', release.fixture.bundle] : ['--maintenance-migrate-profiles'];
  if (engineInterruption) {
    if (!isolated) throw new Error('Controlled maintenance requires the authenticated isolated route');
    return invokeControlledQualificationLauncher(context, release, journal, args, provider, engineInterruption);
  }
  const child = spawnSync(context.executable, args, {
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, timeout: 31 * 60 * 1000, maxBuffer: 1048576,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let result;
  try { result = parseStrictJson(child.stdout ?? Buffer.alloc(0), 1048576); }
  catch (cause) {
    throw new InstallationOperationError('Signed maintenance returned no valid result; installation remains closed', 5, { cause });
  }
  const validResult = valid('migration.Result', result);
  if (child.error || child.status !== 0 || !validResult || result.completionSha256 === null ||
      result.diagnostic !== null || result.busy.length || result.converted > 4096 || result.neverOpened > result.converted) {
    const exitCode = !child.error && !child.signal && validResult && result.busy.length ? 4 : 5;
    throw new InstallationOperationError('Signed maintenance did not complete; installation remains closed', exitCode);
  }
  if ((installerLocks.get(provider) ?? 0) !== 0 || !sameFile(await privateJson(context.journalPath, 16384), journal) ||
      !sameFile(await exactFile(context.executable, launcherLimit), launcher)) throw new Error('Maintenance handoff continuity changed');
  const accepted = Object.freeze({ ...result, busy: Object.freeze([...result.busy]) });
  nativeResults.add(accepted); return accepted;
}

const nativeResults = new WeakSet();
const completionObservations = new WeakSet();
const equal = (a, b) => canonical(a) === canonical(b);
function requireEqual(a, b, message = 'Migration binding changed') { if (!equal(a, b)) throw new Error(message); }
async function absent(path) {
  try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  throw new Error('Expected absent migration path exists');
}
const identityOf = st => ({ device: String(st.dev), inode: String(st.ino), uid: Number(st.uid), mode: Number(st.mode & 0o7777n) });
/** Streaming observations include empty locks and native LLONG_MAX ledgers.
 * No data directory contents or Chromium files are read. */
async function observeFile(path, maximum = 8388608n, budget = null) {
  if (resolve(path) !== path || await realpath(path) !== path) throw new Error('Nonphysical migration evidence');
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const first = await fd.stat({ bigint: true });
    const same = st => st.isFile() && st.nlink === 1n && st.uid === BigInt(userInfo().uid) &&
      st.mode === first.mode && (st.mode & 0o7777n) === 0o600n && st.dev === first.dev && st.ino === first.ino &&
      st.gid === first.gid && st.size === first.size && st.mtimeNs === first.mtimeNs && st.ctimeNs === first.ctimeNs;
    if (!same(first) || first.size < 0n || first.size > BigInt(maximum) || !same(await lstat(path, { bigint: true })))
      throw new Error('Unsafe migration evidence');
    budget?.check(Number(first.size));
    const sha = createHash('sha256'), buffer = Buffer.alloc(1048576); let count = 0n;
    for (;;) {
      budget?.check();
      const part = await fd.read(buffer, 0, buffer.length, null);
      if (!part.bytesRead) break;
      count += BigInt(part.bytesRead); if (count > first.size) throw new Error('Evidence grew during observation');
      sha.update(buffer.subarray(0, part.bytesRead));
    }
    if (count !== first.size || !same(await fd.stat({ bigint: true })) || !same(await lstat(path, { bigint: true })) ||
        await realpath(path) !== path) throw new Error('Migration evidence changed');
    return { identity: identityOf(first), sha256: sha.digest('hex'), size: String(count),
      gid: String(first.gid), mtimeNs: String(first.mtimeNs), ctimeNs: String(first.ctimeNs) };
  } finally { await fd.close(); }
}
function evidencePath(context, scope, path) {
  if (!['migration', 'state'].includes(scope) || typeof path !== 'string' || path.length > 512 ||
      !/^[A-Za-z0-9_.\/-]*$/.test(path) || path.split('/').some(p => p === '.' || p === '..') || path.startsWith('/') ||
      (path && path.split('/').some(p => !p))) throw new Error('Invalid evidence reference');
  return join(scope === 'migration' ? join(context.runtime, 'browser-profile-migration') : context.state, path);
}
async function evidenceCollector(context, budget = null) {
  const files = new Map(), directories = new Map();
  async function directory(scope, path, expected) {
    budget?.check();
    const value = await privateDirectory(evidencePath(context, scope, path), true);
    if (expected) requireEqual(value, expected);
    const entry = { scope, path, identity: value }, key = `${scope}:${path}`;
    if (directories.has(key)) requireEqual(directories.get(key), entry);
    directories.set(key, entry);
    if (directories.size > 65536) throw new Error('Too many evidence directories');
    if (path) await directory(scope, path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');
    return value;
  }
  async function file(scope, path, maximum = 8388608, parse = true) {
    await directory(scope, path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');
    const full = evidencePath(context, scope, path), observation = await observeFile(full, BigInt(maximum), budget);
    const entry = { scope, path, ...observation }, key = `${scope}:${path}`;
    if (files.has(key)) requireEqual(files.get(key), entry);
    files.set(key, entry); if (files.size > 131072) throw new Error('Too many evidence files');
    if (!parse) return observation;
    budget?.check(Number(observation.size));
    const decoded = await privateJson(full, maximum);
    if (!sameFile(decoded, observation)) throw new Error('Evidence changed while decoding');
    requireEqual(await observeFile(full, BigInt(maximum), budget), observation);
    return decoded;
  }
  return { directory, file, finish: () => ({
    directories: [...directories.values()].sort((a, b) => `${a.scope}:${a.path}`.localeCompare(`${b.scope}:${b.path}`, 'en')),
    files: [...files.values()].sort((a, b) => `${a.scope}:${a.path}`.localeCompare(`${b.scope}:${b.path}`, 'en')),
  }) };
}
async function preparedBindings(context, release, prepared, custody, after = false) {
  await custody.assert(); requireEqual(custody.guards, prepared.guards);
  if (prepared.assets.image.sha256 !== release.imageSha256 || prepared.launcher.sha256 !== release.launcher.sha256)
    throw new Error('Reopening references do not name the verified signed candidate');
  const candidateReceipt = await privateJson(join(context.receipts, `${release.build}.json`));
  requireEqual(candidateReceipt.value, { format: 1, build: release.build, imageSha256: release.imageSha256,
    source: release.source, payloadDigest: release.payloadDigest, launcherSha256: release.launcher.sha256 });
  if (!sameFile(await privateJson(context.journalPath, 16384), prepared.journal) ||
      !sameFile(await exactFile(context.executable, launcherLimit), prepared.launcher) ||
      !sameFile(await exactFile(context.image, imageLimit), prepared.assets.image) ||
      !sameFile(await privateJson(join(context.receipts, `${release.build}.json`)), prepared.assets.release))
    throw new Error('Original installation inputs changed');
  const selected = await selectionFile(context);
  if (after) requireEqual(selected.value, prepared.journal.value.after.selection);
  else requireEqual(selected, prepared.selection);
  requireEqual(await privateDirectory(context.runtime, true), prepared.state.runtime);
  requireEqual(await privateDirectory(dirname(context.state), true), prepared.state.parent);
  const before = prepared.journal.value.before;
  if (Boolean(prepared.oldAssets) !== Boolean(before)) throw new Error('Original predecessor references are incomplete');
  if (prepared.oldAssets) {
    if (!keys(prepared.oldAssets, ['image', 'release', 'launcher']) ||
        prepared.oldAssets.image.sha256 !== before.selection.imageSha256 || prepared.oldAssets.launcher.sha256 !== before.launcherSha256)
      throw new Error('Original predecessor references differ from journal');
    const build = before.selection.build;
    const receipt = await installedImageReceipt(context.support, before.selection);
    if (receipt.launcherSha256 !== before.launcherSha256) throw new Error('Original predecessor release differs from journal');
    if (!sameFile(await exactFile(join(context.images, `${build}.dmg`), imageLimit), prepared.oldAssets.image) ||
        !sameFile(await privateJson(join(context.receipts, `${build}.json`)), prepared.oldAssets.release) ||
        !sameFile(await exactFile(context.backup, launcherLimit), prepared.oldAssets.launcher))
      throw new Error('Original predecessor artifacts changed');
  }
  checkContextLauncher(context, context.executable, release.launcher.sha256);
  if (!await installedAlias(context.alias, context.executable)) throw new Error('Installed alias disappeared');
  await custody.assert();
}
function targetValue(content, schema) {
  const bytes = Buffer.from(content.base64, 'base64');
  if (bytes.toString('base64') !== content.base64 || hash(bytes) !== content.sha256) throw new Error('Migration content hash differs');
  const value = parseStrictJson(bytes, 65536);
  if (!valid(schema, value)) throw new Error('Migration content grammar differs');
  return value;
}
// Read-only semantic reconstruction is shared by fresh completion and recovery.
// It cannot mint a publication observation or a native success verdict.
async function collectCompletion(context, release, prepared, result, custody, after = false) {
  await preparedBindings(context, release, prepared, custody, after);
  const observation = await collectCompletionEvidence(context, release, prepared, result);
  await preparedBindings(context, release, prepared, custody, after);
  return observation;
}

async function collectCompletionEvidence(context, release, prepared, result, budget = null) {
  const collector = await evidenceCollector(context, budget), { file, directory } = collector;
  const current = await file('migration', 'current', 16384), pointer = current.value;
  if (!keys(pointer, ['format', 'attempt', 'transactionSha256']) || pointer.format !== 1 ||
      !/^[0-9a-f]{32}$/.test(pointer.attempt) || !digest(pointer.transactionSha256)) throw new Error('Invalid migration pointer');
  const transaction = await file('migration', `${pointer.attempt}/transaction.json`, transactionLimit), tx = transaction.value;
  if (!valid('migration.Transaction', tx) || transaction.sha256 !== pointer.transactionSha256 || tx.attempt !== pointer.attempt ||
      tx.root.path !== context.state || tx.sourceSha256 !== release.sourceDigest || tx.productSha256 !== release.productDigest)
    throw new Error('Migration transaction differs from signed candidate');
  requireEqual(tx.runtime, prepared.state.runtime); requireEqual(tx.journal, fileReference(prepared.journal));
  requireEqual(tx.selection, prepared.selection.value); requireEqual(tx.selectionFile, prepared.selection.file);
  requireEqual(tx.oldBuild, prepared.journal.value.before); requireEqual(tx.newBuild, prepared.journal.value.after);
  const completion = await file('migration', `${tx.attempt}/completed.json`), done = completion.value;
  if (!valid('migration.Completion', done) || completion.sha256 !== result.completionSha256 || done.attempt !== tx.attempt ||
      done.transactionSha256 !== transaction.sha256 || result.converted !== tx.profiles.length ||
      result.neverOpened !== tx.profiles.filter(p => p.evidence.classification === 'never-opened').length)
    throw new Error('Native completion does not bind this transaction');
  if (tx.root.initial === 'absent') {
    await absent(context.state);
    if (tx.profiles.length || tx.root.identity || tx.root.profiles || tx.root.registry) throw new Error('Absent root transaction differs');
  } else {
    await directory('state', '', tx.root.identity); await directory('state', 'profiles', tx.root.profiles);
    requireEqual((await file('state', 'registry.lock', 8388608, false)).identity, tx.root.registry);
    requireEqual((await readdir(join(context.state, 'profiles'))).sort(), tx.profiles.map(p => p.id).sort());
  }
  const completed = [];
  for (const entry of tx.profiles) {
    const path = `profiles/${entry.id}`, profile = join(context.state, path), h = entry.pathSha256;
    if (hash(profile) !== h) throw new Error('Profile path digest differs');
    await directory('state', path, entry.directory);
    await directory('state', `${path}/data`, entry.dataDirectory);
    await directory('state', `${path}/userData`, entry.userDataDirectory);
    requireEqual((await file('state', `${path}/owner.lock`, 8388608, false)).identity, entry.ownerLock);
    const record = await file('state', `${path}/profile.json`, 65536), original = targetValue(entry.originalRecord, 'profile.ProfileRecord');
    const target = targetValue(entry.targetRecord, 'profile2.ProfileRecord');
    requireEqual(target, { ...original, format: 2 }); requireEqual(record.value, target);
    if (record.sha256 !== entry.targetRecord.sha256 || target.id !== entry.id || target.instance !== entry.instance)
      throw new Error('Converted profile differs');
    let marker = null;
    if (entry.originalMarker) {
      const old = targetValue(entry.originalMarker, 'profile.EngineMarker'), next = targetValue(entry.targetMarker, 'profile2.EngineMarker');
      requireEqual(next, { ...old, format: 2 }); marker = await file('state', `${path}/engine.json`, 65536);
      requireEqual(marker.value, next); if (marker.sha256 !== entry.targetMarker.sha256) throw new Error('Converted marker differs');
    } else { if (entry.targetMarker) throw new Error('Unexpected target marker'); await absent(join(profile, 'engine.json')); }
    const staged = (await file('migration', `${tx.attempt}/progress/${h}.staged.json`)).value;
    if (!valid('migration.Staged', staged) || staged.attempt !== tx.attempt || staged.profileSha256 !== h ||
        !sameFile(staged.record, record) || !equal(staged.marker, fileReference(marker))) throw new Error('Staged pair differs');
    const receipt = await file('migration', `receipts/${h}.json`), r = receipt.value;
    if (!valid('migration.Receipt', r) || r.attempt !== tx.attempt || r.transactionSha256 !== transaction.sha256 ||
        r.profilePath !== profile || r.profileSha256 !== h || r.instance !== entry.instance ||
        !sameFile(r.originalRecord, entry.originalRecord) || !sameFile(r.convertedRecord, record) ||
        !equal(r.originalMarker, entry.originalMarker) || !equal(fileReference(r.convertedMarker), fileReference(marker)))
      throw new Error('Native receipt differs from converted pair');
    requireEqual(r.directory, entry.directory); requireEqual(r.evidence, entry.evidence);
    if (r.convertedMarker) requireEqual(targetValue(r.convertedMarker, 'profile2.EngineMarker'), marker.value);
    for (const key of ['sourceSha256', 'productSha256', 'candidateSha256']) requireEqual(r[key], tx[key]);
    const committed = (await file('migration', `${tx.attempt}/progress/${h}.committed.json`)).value;
    if (!valid('migration.Committed', committed) || committed.attempt !== tx.attempt || committed.profileSha256 !== h ||
        !sameFile(committed.receipt, receipt)) throw new Error('Committed native receipt differs');
    const base = `exit-evidence/${h}`, capture = (await file('state', `${base}/migration/${receipt.sha256}.json`)).value;
    if (!keys(capture, ['format', 'kind', 'receiptSha256', 'transactionSha256', 'attempt', 'epoch', 'profileSha256', 'instance', 'directory', 'closed', 'data']) ||
        capture.format !== 1 || capture.kind !== 'native-migration-evidence' || capture.receiptSha256 !== receipt.sha256 || capture.epoch !== tx.epoch)
      throw new Error('Retained native capture differs');
    for (const key of ['transactionSha256', 'attempt', 'profileSha256', 'instance', 'directory']) requireEqual(capture[key], r[key]);
    for (const role of ['closed', 'data']) {
      const claimHash = entry.evidence[`${role}ClaimSha256`];
      if (!claimHash) { requireEqual(capture[role], null); continue; }
      const claimFile = await file('state', `${base}/claims/${claimHash}.json`), claim = claimFile.value;
      if (claimFile.sha256 !== claimHash || capture[role]?.claimSha256 !== claimHash || claim.phase !== 'closed' ||
          claim.profile !== profile || claim.profileInstance !== entry.instance || claim.profilePathHash !== h ||
          typeof claim.request !== 'string' || !/^[A-Za-z0-9_-]+$/.test(claim.request)) throw new Error('Retained native Claim differs');
      const request = `${base}/${claim.request}`, terminal = claim.terminal;
      if (!terminal || !['activation.json', 'terminal.json', 'unused.json'].includes(basename(terminal.path)) ||
          terminal.path !== join(context.state, request, basename(terminal.path))) throw new Error('Native terminal path differs');
      const terminalFile = await file('state', `${request}/${basename(terminal.path)}`);
      if (terminalFile.sha256 !== terminal.digest) throw new Error('Native terminal changed');
      if (role === 'data') { requireEqual(terminal.path, entry.evidence.terminalPath); requireEqual(terminal.digest, entry.evidence.terminalSha256); }
      if (basename(terminal.path) === 'activation.json') {
        const proof = await file('state', `${request}/proof.json`);
        if (proof.sha256 !== terminalFile.value.journal?.digest) throw new Error('Native exit journal changed');
      }
      if (basename(terminal.path) !== 'unused.json')
        for (const name of ['family-main.log', 'family-primary.log', 'family-custody.log'])
          await file('state', `${request}/${name}`, 9223372036854775807n, false);
    }
    completed.push({ profileSha256: h, receiptSha256: receipt.sha256 });
  }
  requireEqual(done.profiles, completed);
  return { prepared, result, epoch: tx.epoch, root: tx.root, ...collector.finish() };
}
async function verifyCompletion(context, release, prepared, result, custody) {
  if (!nativeResults.has(result)) throw new Error('A genuine signed maintenance return is required');
  const observation = await collectCompletion(context, release, prepared, result, custody);
  completionObservations.add(observation); return observation;
}

async function recheckEvidence(context, proof) {
  if (!Array.isArray(proof.files) || proof.files.length > 131072 || !Array.isArray(proof.directories) ||
      proof.directories.length > 65536 || !valid('migration.Root', proof.state.root)) throw new Error('Invalid reopening inventory');
  requireEqual(await privateDirectory(dirname(context.state), true), proof.state.parent);
  requireEqual(await privateDirectory(context.runtime, true), proof.state.runtime);
  if (proof.state.root.path !== context.state) throw new Error('Reopening state root differs');
  if (proof.state.root.initial === 'absent') await absent(context.state);
  else {
    requireEqual(await privateDirectory(context.state, true), proof.state.root.identity);
    const transactionRef = proof.files.find(f => f.scope === 'migration' && /^[0-9a-f]{32}\/transaction\.json$/.test(f.path));
    if (!transactionRef) throw new Error('Reopening transaction missing');
    const transaction = await privateJson(evidencePath(context, transactionRef.scope, transactionRef.path), transactionLimit);
    if (!sameFile(transaction, transactionRef) || !valid('migration.Transaction', transaction.value)) throw new Error('Reopening transaction changed');
    requireEqual((await readdir(join(context.state, 'profiles'))).sort(), transaction.value.profiles.map(p => p.id).sort());
    for (const p of transaction.value.profiles) if (!p.targetMarker) await absent(join(context.state, 'profiles', p.id, 'engine.json'));
  }
  for (const [entries, isFile] of [[proof.directories, false], [proof.files, true]]) {
    let previous = '';
    for (const entry of entries) {
      const path = evidencePath(context, entry.scope, entry.path), key = `${entry.scope}:${entry.path}`;
      if (previous && previous.localeCompare(key, 'en') >= 0) throw new Error('Reopening inventory is not unique and ordered');
      previous = key;
      if (isFile) {
        if (!keys(entry, ['scope', 'path', 'identity', 'sha256', 'size', 'gid', 'mtimeNs', 'ctimeNs']) ||
            !/^(0|[1-9][0-9]{0,18})$/.test(entry.size) || !digest(entry.sha256)) throw new Error('Invalid reopening file');
        const maximum = /\/family-(main|primary|custody)\.log$/.test(entry.path) ? 9223372036854775807n :
          /^[0-9a-f]{32}\/transaction\.json$/.test(entry.path) && entry.scope === 'migration' ? BigInt(transactionLimit) : 8388608n;
        const { scope, path: ignored, ...expected } = entry;
        requireEqual(await observeFile(path, maximum), expected);
      } else {
        if (!keys(entry, ['scope', 'path', 'identity'])) throw new Error('Invalid reopening directory');
        requireEqual(await privateDirectory(path, true), entry.identity);
      }
    }
  }
}
function proofPrepared(proof) {
  return { journal: { ...proof.journal, value: { format: 3, aliasBefore: proof.source.aliasBefore, before: proof.before,
    after: proof.after, migration: { fromProfileFormat: 1, toProfileFormat: 2 } } }, guards: proof.guards,
    selection: { value: proof.before?.selection ?? null, file: proof.source.selectionFile },
    assets: proof.source.assets, launcher: proof.source.launcher, oldAssets: proof.source.oldAssets,
    state: { parent: proof.state.parent, runtime: proof.state.runtime } };
}
function validateReopeningProof(context, release, proof) {
  if (!keys(proof, ['format', 'kind', 'journal', 'before', 'after', 'source', 'result', 'epoch', 'guards', 'state', 'directories', 'files', 'rollback']) ||
      proof.format !== 1 || proof.kind !== 'browser-profile-migration-reopen' || !digest(proof.epoch) ||
      !valid('migration.Result', proof.result) || !digest(proof.result.completionSha256) || proof.result.diagnostic !== null || proof.result.busy.length ||
      !keys(proof.state, ['root', 'parent', 'runtime']) || !keys(proof.journal, ['path', 'identity', 'sha256']) ||
      proof.journal.path !== context.journalPath || !keys(proof.source, ['build', 'git', 'sourceDigest', 'productDigest', 'aliasBefore', 'selectionFile', 'assets', 'launcher', 'oldAssets']) ||
      proof.source.build !== release.build || proof.source.git !== release.source || proof.source.sourceDigest !== release.sourceDigest ||
      proof.source.productDigest !== release.productDigest || typeof proof.source.aliasBefore !== 'boolean' ||
      !equal(proof.after, { selection: { format: 1, build: release.build, imageSha256: release.imageSha256 }, launcherSha256: release.launcher.sha256 }))
    throw new Error('Reopening proof does not bind exact signed release');
  const prepared = proofPrepared(proof);
  if (!valid('migration.Journal', prepared.journal.value)) throw new Error('Reopening journal grammar differs');
  return prepared;
}

async function readReopeningProof(context, release, custody) {
  if (!await optionalFile(context.proofPath, proofLimit)) return null;
  const file = await privateJson(context.proofPath, proofLimit), proof = file.value;
  const prepared = validateReopeningProof(context, release, proof);
  const journal = await privateJson(context.journalPath, 16384);
  requireEqual(journal.value, prepared.journal.value);
  const selected = await optionalSelection(context.selectionPath), after = equal(selected, proof.after.selection);
  await preparedBindings(context, release, prepared, custody, after);
  await recheckEvidence(context, proof);
  const actual = await collectCompletion(context, release, prepared, proof.result, custody, after);
  requireEqual(actual.epoch, proof.epoch); requireEqual(actual.root, proof.state.root);
  requireEqual(actual.files, proof.files); requireEqual(actual.directories, proof.directories);
  await recheckRollback(context, proof.rollback, custody, after);
  if (!sameFile(await privateJson(context.proofPath, proofLimit), file)) throw new Error('Reopening proof changed');
  return file;
}
async function publishReopeningProof(context, release, observation, custody) {
  if (!completionObservations.has(observation)) throw new Error('Native completion observation is required');
  const { prepared, result, epoch, root, directories, files } = observation;
  await preparedBindings(context, release, prepared, custody);
  const proof = { format: 1, kind: 'browser-profile-migration-reopen',
    journal: { path: context.journalPath, ...fileReference(prepared.journal) }, before: prepared.journal.value.before,
    after: prepared.journal.value.after,
    source: { build: release.build, git: release.source, sourceDigest: release.sourceDigest, productDigest: release.productDigest,
      aliasBefore: prepared.journal.value.aliasBefore, selectionFile: prepared.selection.file,
      assets: prepared.assets, launcher: prepared.launcher, oldAssets: prepared.oldAssets },
    result, epoch, guards: prepared.guards, state: { ...prepared.state, root }, directories, files,
    rollback: await observeRollback(context, custody) };
  await recheckEvidence(context, proof);
  await recheckRollback(context, proof.rollback, custody);
  const bytes = encode(proof); if (bytes.length > proofLimit) throw new Error('Reopening proof exceeds bound');
  await publishExact(context.proofPath, proofLimit, hash(bytes), path => writeExclusive(path, bytes), custody.publication);
  return readReopeningProof(context, release, custody);
}

async function optionalDirectory(path) {
  try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  return privateDirectory(path, true);
}
async function rollbackInventory(context, name, identity, custody) {
  const path = join(context.support, name);
  requireEqual(await privateDirectory(path, true), identity);
  const names = (await readdir(path)).sort();
  if (names.length > 4096 || names.some(n => !buildNumber(n))) throw new Error('Unsupported rollback namespace inventory');
  const entries = [];
  for (const build of names) {
    const launcherPath = join(path, build), launcher = await exactFile(launcherPath, launcherLimit);
    if (launcher.identity.mode !== 0o755 || launcher.identity.uid !== userInfo().uid) throw new Error('Unsafe archived launcher');
    const receiptFile = await privateJson(join(context.receipts, `${build}.json`)), receipt = receiptFile.value;
    const selected = { format: 1, build, imageSha256: receipt.imageSha256 };
    const pinned = contextPredecessor(context);
    if (!pinned || build !== pinned.build || receipt.source !== pinned.source || receipt.imageSha256 !== pinned.imageSha256 ||
        receipt.payloadDigest !== pinned.payloadDigest || receipt.launcherSha256 !== pinned.launcherSha256 ||
        launcher.sha256 !== pinned.launcherSha256 || await contextProfileFormat(context, selected, custody) !== 1)
      throw new Error('Rollback archive is not the supported authentic predecessor');
    checkContextLauncher(context, launcherPath, launcher.sha256);
    const image = await exactFile(join(context.images, `${build}.dmg`), imageLimit);
    if (image.sha256 !== selected.imageSha256) throw new Error('Rollback image changed');
    entries.push({ build, launcher: { ...fileReference(launcher), size: launcher.bytes.length },
      release: fileReference(receiptFile), image: fileReference(image) });
  }
  requireEqual((await readdir(path)).sort(), names);
  requireEqual(await privateDirectory(path, true), identity);
  return entries;
}
async function observeRollback(context, custody) {
  await custody.assert(); const parent = await privateDirectory(context.support, true);
  const active = await optionalDirectory(join(context.support, 'rollback-launchers'));
  await absent(join(context.support, 'pre-format-2-rollback-launchers'));
  if (active && active.device !== parent.device) throw new Error('Rollback namespace crossed filesystems');
  const observation = { parent, active, entries: active ? await rollbackInventory(context, 'rollback-launchers', active, custody) : [] };
  requireEqual(await privateDirectory(context.support, true), parent); await custody.assert(); return observation;
}
async function recheckRollback(context, observation, custody, requireRetired = false) {
  if (!keys(observation, ['parent', 'active', 'entries']) || !Array.isArray(observation.entries) || observation.entries.length > 4096)
    throw new Error('Invalid rollback namespace proof');
  await custody.assert(); requireEqual(await privateDirectory(context.support, true), observation.parent);
  const active = await optionalDirectory(join(context.support, 'rollback-launchers'));
  const retired = await optionalDirectory(join(context.support, 'pre-format-2-rollback-launchers'));
  if (!observation.active) {
    if (active || retired || observation.entries.length) throw new Error('Originally absent rollback namespace changed');
    return 'absent';
  }
  if (Boolean(active) === Boolean(retired) || (requireRetired && !retired)) throw new Error('Unknown rollback retirement state');
  requireEqual(active ?? retired, observation.active);
  requireEqual(await rollbackInventory(context, active ? 'rollback-launchers' : 'pre-format-2-rollback-launchers', observation.active, custody), observation.entries);
  await custody.assert(); return active ? 'active' : 'retired';
}
async function retireRollback(context, proof, custody, afterSelection) {
  const state = await recheckRollback(context, proof.rollback, custody, afterSelection);
  if (state === 'active') {
    custody.publication.provider.retireInstallerRollback(custody.publication.selection,
      JSON.stringify({ parent: proof.rollback.parent, directory: proof.rollback.active }));
  }
  await recheckRollback(context, proof.rollback, custody, true);
}

async function finalizeMigration(context, release, custody) {
  let proofFile = await readReopeningProof(context, release, custody);
  if (!proofFile) throw new Error('No durable native completion proof; admission remains closed');
  const proof = proofFile.value, prepared = proofPrepared(proof);
  let after = equal(await optionalSelection(context.selectionPath), proof.after.selection);
  await retireRollback(context, proof, custody, after);
  await preparedBindings(context, release, prepared, custody, after);
  await recheckEvidence(context, proof);
  if (!sameFile(await privateJson(context.proofPath, proofLimit), proofFile)) throw new Error('Reopening authority changed');
  await recheckRollback(context, proof.rollback, custody, true);
  if (!after) {
    await replaceFile(context.selectionPath, encode(proof.after.selection), 0o600);
    after = true;
  }
  proofFile = await readReopeningProof(context, release, custody);
  if (!proofFile) throw new Error('Reopening proof disappeared');
  await preparedBindings(context, release, prepared, custody, after);
  await recheckRollback(context, proof.rollback, custody, true);
  if (!sameFile(await privateJson(context.journalPath, 16384), proof.journal)) throw new Error('Journal changed before final removal');
  await custody.assert();
  await unlink(context.journalPath); await syncPath(context.support);
  await absent(context.journalPath); await custody.assert();
  return installationResult(context, release);
}
function installationResult(context, release) {
  return { build: release.build, source: release.source, imageSha256: release.imageSha256,
    executable: context.executable, image: context.image, mount: context.mount, alias: context.alias };
}

async function verifySameInstallation(context, release, launcher, format, custody, readOnly = false) {
  if (format !== 2 || launcher.sha256 !== release.launcher.sha256) throw new Error('Same candidate is not selected format2');
  if (readOnly) {
    if (!await installedAlias(context.alias, context.executable)) throw new Error('Same retry requires the original alias');
  } else await ensureAlias(context.alias, context.executable);
  await custody.assert();
  return installationResult(context, release);
}

/** Compatible updates never reuse, remove or reinterpret migration evidence. */
async function ordinaryInstall(context, release, options, route, custody, retry = null) {
  await custody.assert(); requireEqual(await optionalSelection(context.selectionPath), route.previous);
  if (await installationJournal(context.support)) throw new Error('Pending installation requires recovery first');
  if (retry) {
    await existingQualificationReleaseAssets(context, release, custody);
    await verifyQualificationRetryMount(context, release);
  } else {
    await stageReleaseAssets(context, release, options, custody);
    await mountIsolatedCandidate(context, release, custody.publication.provider);
  }
  await custody.assert();
  const old = await installedImageReceipt(context.support, route.previous);
  const current = await exactFile(context.executable, launcherLimit);
  if (current.sha256 !== old.launcherSha256 || current.identity.mode !== contextLauncherMode(context, old.launcherSha256)) throw new Error('Selected launcher changed');
  checkContextLauncher(context, context.executable, old.launcherSha256);
  if (route.kind === 'same') {
    const format = retry ? release.profileFormat : await contextProfileFormat(context, route.previous, custody);
    return verifySameInstallation(context, release, current, format, custody, Boolean(retry));
  }
  // Preserve an earlier conversion backup before reusing the legacy slot for
  // a later compatible transaction. Existing immutable release bytes remain.
  const prior = await optionalFile(context.backup, launcherLimit);
  if (retry?.backup) {
    if (!sameFile(prior, retry.backup) || prior.sha256 !== current.sha256)
      throw new Error('Exact compatible retry backup changed');
    await syncPath(context.backup); await syncPath(context.support);
    if (!sameFile(await exactFile(context.backup, launcherLimit), retry.backup))
      throw new Error('Exact compatible retry backup changed during synchronization');
  } else if (prior && prior.sha256 === current.sha256) {
    if (prior.identity.mode !== 0o755 || prior.identity.uid !== userInfo().uid) throw new Error('Unsafe current launcher backup');
    checkContextLauncher(context, context.backup, current.sha256);
  } else if (prior) {
    const pinned = contextPredecessor(context);
    if (!pinned || prior.sha256 !== pinned.launcherSha256 || prior.identity.mode !== 0o755) throw new Error('Unknown retained launcher backup');
    checkContextLauncher(context, context.backup, prior.sha256);
    await publishExact(join(context.receipts, `${pinned.build}.launcher`), launcherLimit, prior.sha256,
      path => writeExclusive(path, prior.bytes, 0o755), custody.publication);
    if (!sameFile(await exactFile(context.backup, launcherLimit), prior)) throw new Error('Retained backup changed');
    await unlink(context.backup); await syncPath(context.support);
  }
  if (!retry?.backup)
    await publishExact(context.backup, launcherLimit, current.sha256, path => writeExclusive(path, current.bytes, 0o755), custody.publication);
  const transaction = { format: 2, aliasBefore: Boolean(await installedAlias(context.alias, context.executable)),
    before: { selection: route.previous, launcherSha256: old.launcherSha256 },
    after: { selection: { format: 1, build: release.build, imageSha256: release.imageSha256 }, launcherSha256: release.launcher.sha256 } };
  const bytes = encode(transaction);
  if (retry?.backup && !sameFile(await exactFile(context.backup, launcherLimit), retry.backup))
    throw new Error('Exact compatible retry backup changed before journal publication');
  retry?.beginJournal();
  await publishExact(context.journalPath, 4096, hash(bytes), path => writeExclusive(path, bytes), custody.publication);
  await replaceFile(context.executable, release.launcher.bytes, contextLauncherMode(context, release.launcher.sha256));
  if ((await exactFile(context.executable, launcherLimit)).sha256 !== release.launcher.sha256) throw new Error('Installed launcher differs');
  checkContextLauncher(context, context.executable, release.launcher.sha256); await ensureAlias(context.alias, context.executable);
  await custody.assert(); await replaceFile(context.selectionPath, encode(transaction.after.selection), 0o600);
  return installationResult(context, release);
}
/** Publish the exact selected binary and image under native installation guards.
 * Journal3 is never consumed by rollback, including any exceptional path. */
export async function installRelease(options) {
  const release = await verifySignedRelease(options), context = await releaseContext(release);
  return installVerifiedRelease(context, release, options);
}

async function recoverCompatibleInstallation(context, provider, release, qualification) {
  const pending = await installationJournal(context.support);
  if (!pending || pending.value.format === 3) return false;
  if (qualification) {
    const predecessor = qualification.predecessor;
    const before = { selection: { format: 1, build: predecessor.build, imageSha256: predecessor.image.sha256 },
      launcherSha256: predecessor.launcherSha256 };
    const after = { selection: { format: 1, build: release.build, imageSha256: release.imageSha256 },
      launcherSha256: release.launcher.sha256 };
    if (qualification.mode === 'interrupt' || qualification.role !== 'B' || pending.value.format !== 2 ||
        !equal(pending.value.before, before) || !equal(pending.value.after, after))
      throw new Error('Pending installation is outside the fixed qualification route');
  }
  await recoverInstall(context, provider, Boolean(qualification?.mode));
  return true;
}

async function installVerifiedRelease(context, release, options, qualification = null) {
  await assertContext(context);
  return withLockProvider(release.platform, async provider => {
    const existingOnly = Boolean(qualification?.mode);
    const retry = qualification?.mode === 'retry';
    if (qualification?.interruption) bindQualificationInterruption(provider, qualification.interruption);
    // Legacy recovery runs under selection EX before taking any Build EX;
    // its own Build guard must not conflict with a caller-held description.
    const recover = () => withLock(provider, join(context.support, 'selection.lock'),
      () => recoverCompatibleInstallation(context, provider, release, qualification), !existingOnly,
      existingOnly ? 'tryExistingQualificationObserverLock' : 'tryLock');
    const recoveredCompatible = await recover();
    const initialJournal = await installationJournal(context.support);
    const previous = initialJournal?.value.format === 3 ? initialJournal.value.before?.selection ?? null :
      await optionalSelection(context.selectionPath);
    const completedRetry = retry && qualification.role === 'A' && !initialJournal && previous?.build === release.build;
    const predecessor = completedRetry ? qualification.predecessor : previous;
    const expectedMismatch = qualification?.expectedMismatch && initialJournal?.value.format === 3 ?
      { ...qualification.expectedMismatch, journal: initialJournal } : null;
    let prepared, route, compatibleStarted = false;
    try {
      const completed = await withInstallationGuards(context, provider, predecessor, release.build, async custody => {
        route = await installationRoute(context, release, custody, expectedMismatch);
        requireEqual(route.previous, previous);
        if (existingOnly) {
          const expectedJournal = initialJournal?.value.format === 3 ? initialJournal : null;
          if (Boolean(route.pending) !== Boolean(expectedJournal) || (expectedJournal && !sameFile(route.pending, expectedJournal)))
            throw new Error('Original qualification journal changed while taking custody');
        }
        if (route.kind === 'legacy') throw new Error('Installation changed while taking original guards');
        if (qualification) requireQualificationInstallRoute(route, release, qualification);
        if (completedRetry) return verifyCompletedQualificationRetry(context, release, qualification.predecessor, custody);
        let retryBackup = null;
        if (retry && qualification.role === 'B' && route.kind === 'ordinary' && !recoveredCompatible) {
          const backup = await exactFile(context.backup, launcherLimit);
          if (backup.identity.mode !== 0o755 || backup.identity.uid !== userInfo().uid ||
              backup.sha256 !== qualification.predecessor.launcherSha256)
            throw new Error('Compatible retry requires the original signed pre-journal backup');
          checkContextLauncher(context, context.backup, backup.sha256);
          retryBackup = fileReference(backup);
        }
        if (route.kind === 'same' || route.kind === 'ordinary')
          return ordinaryInstall(context, release, options, route, custody, retry ? {
            backup: retryBackup, beginJournal: () => { compatibleStarted = true; },
          } : null);
        const proof = await readReopeningProof(context, release, custody);
        if (proof) {
          if (qualification && !retry) throw new Error('Qualification A requires the original prepared-journal observation');
          if (retry) await verifyQualificationRetryMount(context, release);
          return finalizeMigration(context, release, custody);
        }
        if (equal(await optionalSelection(context.selectionPath), route.pending?.value.after.selection))
          throw new Error('After selection without native-bound proof stays closed');
        prepared = await prepareMigrationRelease(context, release, options, route, custody, retry);
        return null;
      }, !initialJournal && previous?.build !== release.build && (!existingOnly ||
        (qualification.mode === 'interrupt' && qualification.role === 'A')), existingOnly);
      if (completed) return completed;
      // All installer-held descriptions have closed. Native acquires its own
      // original EX set, and journal3 closes admission throughout the handoff.
      if (qualification && !retry) {
        await assertContext(context);
        if ((installerLocks.get(provider) ?? 0) !== 0 ||
            !sameFile(await privateJson(context.journalPath, 16384), prepared.journal))
          throw new Error('Original qualification journal is not ready for observation');
        const interruption = qualification.mode === 'interrupt';
        await acknowledgeQualificationPreparation(qualification, interruption ? 5 : 3, interruption ? 6 : 4);
      }
      const engineInterruption = qualification?.interruption?.writer === 'engine' ? qualification.interruption : null;
      const result = await invokeSignedMaintenance(context, release, prepared, provider, engineInterruption, retry);
      return await withInstallationGuards(context, provider, previous, release.build, async custody => {
        const observation = await verifyCompletion(context, release, prepared, result, custody);
        await publishReopeningProof(context, release, observation, custody);
        return finalizeMigration(context, release, custody);
      }, false, existingOnly);
    } finally {
      // Only legacy transactions may roll back. Format3 persists on every
      // failure. Fixed A can leave the observer holding selection EX. Fixed
      // retry refusals before compatible installation have no cleanup to do.
      if (qualification?.role !== 'A' && (!existingOnly || compatibleStarted)) await recover();
    }
  });
}

function qualificationReleaseInput({ image, signedReceipt, review }) {
  return { image, signedReceiptPath: signedReceipt, review };
}

function fixedQualificationOptions(cohort, role) {
  const input = name => qualificationReleaseInput(cohort.originals[name].input);
  return { ...input(role), predecessors: ['historical', 'A', 'B', 'C'].filter(name => name !== role).map(input) };
}

function qualificationCohort(cohort, role) {
  const originals = Object.values(cohort.originals);
  const inputs = new Map(originals.map(({ input, release }) => [release.build, qualificationReleaseInput(input)]));
  const releases = new Map(originals.map(({ release }) => [release.build, release]));
  return { release: cohort.originals[role].release, inputs, releases };
}

function authenticatedQualificationContext(cohort, role) {
  const { release, inputs, releases } = qualificationCohort(cohort, role);
  return createIsolatedContext(release, inputs, releases, true);
}

function requireQualificationInstallRoute(route, release, { role, predecessor, mode }) {
  const followsPredecessor = route.previous?.build === predecessor.build &&
    route.previous.imageSha256 === predecessor.image.sha256;
  const same = route.kind === 'same' && route.previous.build === release.build;
  const migration = route.kind === 'migration' && followsPredecessor;
  const ordinary = route.kind === 'ordinary' && followsPredecessor;
  const allowed = role === 'A'
    ? mode === 'retry' ? (migration && route.pending) || same : migration && (mode !== 'interrupt' || !route.pending)
    : ordinary || (mode !== 'interrupt' && same);
  if (!allowed) throw new Error('Installation is outside the fixed qualification route');
}

function privateQualificationPipe(fd, wire, access) {
  let info;
  try { info = fstatSync(fd, { bigint: true }); } catch {
    wire.qualificationRequire(false, 'Missing private qualification pipes', 2);
  }
  // Darwin anonymous pipes have no directory entry and report mode 0660.
  wire.qualificationRequire(info.isFIFO() && info.nlink === 0n && info.uid === BigInt(userInfo().uid),
    'Unsafe qualification pipe', 2);
  if (access !== undefined) {
    // Darwin fdesc duplicates the existing description only when the requested
    // access is a subset. It reads or writes no bytes on the original pipe.
    let duplicate;
    try { duplicate = openSync(`/dev/fd/${fd}`, access); } catch {
      wire.qualificationRequire(false, 'Qualification pipe access differs', 2);
    }
    try {
      const held = fstatSync(duplicate, { bigint: true });
      wire.qualificationRequire(held.dev === info.dev && held.ino === info.ino, 'Qualification pipe identity changed', 2);
    } finally { closeSync(duplicate); }
  }
  return `${info.dev}:${info.ino}`;
}

async function readQualificationPipe(input, expiry, limit, wire) {
  const chunks = [];
  let size = 0;
  const stream = addAbortSignal(expiry, input);
  try {
    for await (const chunk of stream) {
      size += chunk.length;
      wire.qualificationRequire(size <= limit, 'Qualification pipe input too large', 2);
      chunks.push(chunk);
    }
  } catch (cause) {
    if (cause.exitCode === 2) throw cause;
    throw new InstallationOperationError('Qualification pipe read stopped', 5, { cause });
  } finally { stream.destroy(); }
  return Buffer.concat(chunks, size);
}

async function acknowledgeQualificationPreparation({ requestSha256, wire }, ackFd = 3, noticeFd = 4) {
  const timeout = 120000;
  const deadline = performance.now() + timeout;
  const expiry = AbortSignal.timeout(timeout);
  let bytes;
  try {
    const notification = addAbortSignal(expiry, new Socket({ fd: noticeFd, readable: false, writable: true }));
    try {
      const message = encode({ schema: 1, phase: 'prepared-journal', requestSha256 });
      await new Promise((resolve, reject) => {
        notification.once('error', reject);
        notification.write(message, error => error ? reject(error) : resolve());
      });
    } finally { notification.destroy(); }

    // The harness writes after observing the journal and closes its writer to
    // frame the single ACK. Reject trailing or duplicate lines.
    const input = new Socket({ fd: ackFd, readable: true, writable: false });
    bytes = await readQualificationPipe(input, expiry, 1024, wire);
  } catch (cause) {
    if (cause.exitCode === 2 || cause instanceof InstallationOperationError) throw cause;
    throw new InstallationOperationError('Prepared-journal acknowledgement transport stopped', 5, { cause });
  }
  wire.qualificationRequire(performance.now() < deadline && bytes.length > 0,
    'Qualification acknowledgement was lost or expired', 5);
  wire.qualificationRequire(bytes.indexOf(0x0a) === bytes.length - 1,
    'Expected one qualification acknowledgement line', 2);
  const value = wire.qualificationJson(bytes, 1024);
  wire.qualificationKeys(value, ['schema', 'phase', 'requestSha256']);
  wire.qualificationRequire(value.schema === 1 && value.phase === 'continue' &&
    value.requestSha256 === requestSha256, 'Qualification acknowledgement differs', 2);
}

const engineInterruptionPoints = new Set(['before-transaction', 'transaction-publication', 'current-publication',
  'native-rename-excl', 'empty-staging', 'partial-staging', 'staged-record', 'staged-marker', 'staged-progress',
  'marker-rename', 'marker-durable', 'record-rename', 'record-durable', 'claim-retained', 'capture-durable',
  'receipt-durable', 'committed-progress', 'completion']);
const installerInterruptionPoints = new Set(['final-verification', 'reopening-proof', 'archive-retired', 'selection',
  'journal-unlinked', 'journal-removal', 'compatible-pre-journal-backup']);
// A point joins this set in the same source step that binds its actual writer.
const enabledQualificationInterruptionPoints = new Set(['before-transaction', 'transaction-publication',
  'current-publication', 'native-rename-excl']);
const controlledMaintenanceLimit = 31 * 60 * 1000;
const controlledCleanupLimit = 30000;

function bindQualificationInterruption(provider, interruption) {
  const { wire, endpoints, needsPreparation } = interruption;
  // The signed launcher handoff step provides native access-mode and CLOEXEC
  // checks. Missing native support is an immediate refusal before installation.
  wire.qualificationRequire(typeof provider.prepareQualificationInterruptionPipes === 'function' &&
    provider.prepareQualificationInterruptionPipes(needsPreparation) === true, 'Controlled maintenance transport is unavailable');
  requireEqual(privateQualificationPipe(3, wire), endpoints.stop);
  requireEqual(privateQualificationPipe(4, wire), endpoints.event);
  if (needsPreparation) {
    requireEqual(privateQualificationPipe(5, wire), endpoints.preparationAck);
    requireEqual(privateQualificationPipe(6, wire), endpoints.preparationEvent);
  }
  const actor = provider.processProvenance(process.pid);
  wire.qualificationRequire(actor?.pid === process.pid && actor.uid === userInfo().uid && actor.executable === process.execPath);
  interruption.actor = Object.freeze(actor);
}

async function qualificationInterruptionCapsule(packet) {
  const bytes = encode(packet);
  if (bytes.length > 16384) throw new Error('Controlled launcher capsule exceeds its bound');
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-interrupt-'));
  const path = join(directory, 'capsule');
  let reader;
  try {
    await writeExclusive(path, bytes);
    reader = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const named = await lstat(path, { bigint: true }), held = await reader.stat({ bigint: true });
    if (!held.isFile() || held.nlink !== 1n || held.uid !== BigInt(userInfo().uid) || (held.mode & 0o7777n) !== 0o600n ||
        held.size !== BigInt(bytes.length) || observerFileStamp(named) !== observerFileStamp(held))
      throw new Error('Controlled launcher capsule changed before opening');
    await unlink(path);
    const unlinked = await reader.stat({ bigint: true });
    const copy = Buffer.alloc(bytes.length);
    const { bytesRead } = await reader.read(copy, 0, copy.length, 0);
    if (unlinked.nlink !== 0n || !equal(identityOf(unlinked), identityOf(held)) || bytesRead !== bytes.length || !copy.equals(bytes) ||
        observerFileStamp(await reader.stat({ bigint: true })) !== observerFileStamp(unlinked))
      throw new Error('Controlled launcher capsule differs after unlink');
    await rmdir(directory);
    return reader;
  } catch (error) {
    try { if (reader) await reader.close(); }
    finally {
      try { await unlink(path); } catch (failure) { if (failure.code !== 'ENOENT') throw failure; }
      await rmdir(directory);
    }
    throw error;
  }
}

async function awaitControlledQualificationLauncher(child, remaining) {
  // The signed launcher supervises and reaps its own engine. The producer
  // never sends a supervisory signal or interprets a launcher exit as success.
  let timer;
  try {
    return await new Promise(resolve => {
      let stdoutBytes = 0, stderrBytes = 0, failed = false;
      child.stdout.on('data', bytes => { stdoutBytes += bytes.length; });
      child.stderr.on('data', bytes => { stderrBytes += bytes.length; });
      child.stdout.on('error', () => { failed = true; });
      child.stderr.on('error', () => { failed = true; });
      child.once('error', () => { failed = true; });
      child.once('close', (code, signal) => resolve({ code, signal,
        complete: !failed && stdoutBytes <= 1048576 && stderrBytes <= 4096 }));
      timer = setTimeout(() => {
        failed = true;
        // The run is now incomplete. Keep the direct child referenced until
        // Node has waited it out, even if a downstream stream failed to close.
        child.stdout.destroy(); child.stderr.destroy();
      }, Math.max(1, Math.ceil(remaining + controlledCleanupLimit)));
    });
  } finally { clearTimeout(timer); }
}

async function invokeControlledQualificationLauncher(context, release, journal, args, provider, interruption) {
  const { wire, actor, point, requestSha256, nonce, endpoints } = interruption;
  requireEqual(provider.processProvenance(process.pid), actor);
  requireEqual(privateQualificationPipe(3, wire), endpoints.stop);
  requireEqual(privateQualificationPipe(4, wire), endpoints.event);
  const deadline = Math.floor(provider.continuousTime() + controlledMaintenanceLimit);
  const capsule = await qualificationInterruptionCapsule({ schema: 1, kind: 'qualification-interrupt',
    parent: actor, requestSha256, nonce, point, stopPipe: endpoints.stop, eventPipe: endpoints.event,
    journal: fileReference(journal), build: release.build, imageSha256: release.imageSha256, deadline });
  let outcome;
  try {
    requireEqual(provider.processProvenance(process.pid), actor);
    requireEqual(privateQualificationPipe(3, wire), endpoints.stop);
    requireEqual(privateQualificationPipe(4, wire), endpoints.event);
    if (!sameFile(await privateJson(context.journalPath, 16384), journal)) throw new Error('Controlled maintenance journal changed');
    const remaining = deadline - provider.continuousTime();
    if (remaining <= 0) throw new InstallationOperationError('Controlled maintenance deadline expired before spawn', 5);
    const child = spawn(context.executable, ['--isolated-qualification-interrupt', ...args.slice(1)], {
      env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe', 3, 4, 'ignore', 'ignore', capsule.fd],
    });
    outcome = awaitControlledQualificationLauncher(child, remaining);
    closeSync(3); closeSync(4);
  } finally {
    try { await capsule.close(); }
    finally { if (outcome) await outcome; }
  }
  const result = await outcome;
  await writeObserverResult(process.stderr, { schema: 1, event: 'launcher-exit', requestSha256, nonce,
    code: result.code, signal: result.signal, complete: result.complete }, wire);
  // Only the controller consumes the private park/stop/reap transcript. No
  // controlled run, including an unexpected exit zero, can brand a result.
  throw new InstallationOperationError(result.complete ? 'Controlled maintenance ended without admitting a native result' :
    'Controlled maintenance launcher did not settle within its bounds', 5);
}

async function qualificationInterruptEntry() {
  const wire = await import('./qualification-authority.mjs');
  let requestSha256;
  try {
    wire.qualificationRequire(process.argv.length === 3, 'Invalid fixed interruption entry', 2);
    const requestPipe = privateQualificationPipe(0, wire, constants.O_RDONLY);
    const resultPipe = privateQualificationPipe(1, wire, constants.O_WRONLY);
    wire.qualificationRequire(requestPipe !== resultPipe, 'Qualification request and result pipes must be distinct', 2);
    const bytes = await readQualificationPipe(process.stdin, AbortSignal.timeout(120000), 16384, wire);
    wire.qualificationRequire(bytes.indexOf(0x0a) === bytes.length - 1, 'Expected one qualification request line', 2);
    const value = wire.qualificationJson(bytes), interrupt = value?.action === 'interrupt';
    wire.qualificationKeys(value, interrupt ? ['schema', 'action', 'role', 'authoritySha256', 'point'] :
      ['schema', 'action', 'role', 'authoritySha256']);
    const { action, role, authoritySha256, point } = value;
    wire.qualificationRequire(value.schema === 1 && (interrupt || action === 'retry') && (role === 'A' || role === 'B') &&
      wire.qualificationSha(authoritySha256), 'Invalid fixed interruption request', 2);
    requestSha256 = hash(bytes);
    let interruption;
    if (interrupt) {
      const writer = engineInterruptionPoints.has(point) ? 'engine' : 'installer';
      wire.qualificationRequire((engineInterruptionPoints.has(point) || installerInterruptionPoints.has(point)) &&
        ((role === 'B') === (point === 'compatible-pre-journal-backup')), 'Interruption point differs from its fixed role', 2);
      wire.qualificationRequire(enabledQualificationInterruptionPoints.has(point), 'Interruption point has no enabled writer');
      const endpoints = { stop: privateQualificationPipe(3, wire, constants.O_RDONLY), event: privateQualificationPipe(4, wire, constants.O_WRONLY) };
      if (role === 'A') {
        endpoints.preparationAck = privateQualificationPipe(5, wire, constants.O_RDONLY);
        endpoints.preparationEvent = privateQualificationPipe(6, wire, constants.O_WRONLY);
      }
      const pipes = [requestPipe, resultPipe, ...Object.values(endpoints)];
      wire.qualificationRequire(new Set(pipes).size === pipes.length, 'Qualification pipes must be distinct', 2);
      interruption = { wire, writer, point, nonce: randomBytes(16).toString('hex'), requestSha256, endpoints,
        needsPreparation: role === 'A' };
    }
    const before = await wire.authenticateQualification(authoritySha256);
    const predecessor = before.observation.releases[role === 'A' ? 'historical' : 'A'];
    const expected = before.observation.releases[role];
    const options = qualificationReleaseInput(before.originals[role].input);
    const { context, release } = await existingQualificationContext(before, role);
    requireEqual(release.fixture.fixture, wire.qualificationFixture);
    requireEqual(release.build, expected.build);
    requireEqual(release.imageSha256, expected.image.sha256);
    requireEqual(release.receiptSha256, expected.signedReceipt.sha256);
    const binding = ({ release }) => ({ selection: observerSelection(release), launcherSha256: release.launcher.sha256 });
    const expectedMismatch = !interrupt && role === 'B' ? {
      before: binding(before.originals.historical), after: binding(before.originals.A),
    } : null;
    const result = await installVerifiedRelease(context, release, options,
      { role, predecessor, requestSha256, wire, mode: action, interruption, expectedMismatch });
    if (interrupt) throw new InstallationOperationError('The selected interruption writer was not reached', 5);
    requireEqual(result.build, expected.build);
    const after = await wire.authenticateQualification(authoritySha256);
    requireEqual(after.observation, before.observation, 'Qualification authority changed during retry');
    const selected = await fixedQualificationSelection(after, role, true, true);
    await writeObserverResult(process.stdout, { schema: 1, authoritySha256, selected }, wire);
  } catch (error) {
    if (error instanceof PendingMigrationCandidateMismatch) {
      wire.qualificationOutput({ schema: 1, requestSha256, refusal: 'pending-journal-candidate-mismatch' });
    }
    if (error instanceof InstallationOperationError) error.exitCode = error.qualificationExitCode;
    wire.qualificationFailure(error);
  }
}

async function qualificationInstallEntry() {
  const wire = await import('./qualification-authority.mjs');
  try {
    wire.qualificationRequire(process.argv.length === 3, 'Invalid fixed install entry', 2);
    const requestPipe = privateQualificationPipe(0, wire);
    const bytes = await readQualificationPipe(process.stdin, AbortSignal.timeout(120000), 16384, wire);
    const value = wire.qualificationJson(bytes);
    wire.qualificationKeys(value, ['schema', 'action', 'role', 'authoritySha256']);
    const { role, authoritySha256 } = value;
    wire.qualificationRequire(value.schema === 1 && value.action === 'install' &&
      (role === 'A' || role === 'B'), 'Invalid fixed install request', 2);
    if (role === 'A') {
      const endpoints = [requestPipe, privateQualificationPipe(3, wire), privateQualificationPipe(4, wire)];
      wire.qualificationRequire(new Set(endpoints).size === 3, 'Qualification pipes must be distinct', 2);
    }
    const before = await wire.authenticateQualification(authoritySha256);
    const predecessor = before.observation.releases[role === 'A' ? 'historical' : 'A'];
    const expected = before.observation.releases[role];
    const options = qualificationReleaseInput(before.originals[role].input);
    const { context, release } = await authenticatedQualificationContext(before, role);
    requireEqual(release.fixture.fixture, wire.qualificationFixture);
    requireEqual(release.build, expected.build);
    requireEqual(release.imageSha256, expected.image.sha256);
    requireEqual(release.receiptSha256, expected.signedReceipt.sha256);
    const result = await installVerifiedRelease(context, release, options,
      { role, predecessor, requestSha256: hash(bytes), wire });
    requireEqual(result.build, expected.build);
    const after = await wire.authenticateQualification(authoritySha256);
    requireEqual(after.observation, before.observation, 'Qualification authority changed during install');
    const selected = await fixedQualificationSelection(after, role, true);
    wire.qualificationOutput({ schema: 1, authoritySha256, selected });
  } catch (error) {
    if (error instanceof InstallationOperationError) error.exitCode = error.qualificationExitCode;
    wire.qualificationFailure(error);
  }
}

/** A result is an observation following the real install, not a selector or
 * substitute for the shared owner's common eligibility/lock/postcheck. */
async function fixedQualificationSelection(cohort, role, authenticated = false, existingOnly = false) {
  const { context, release } = existingOnly ? await existingQualificationContext(cohort, role) :
    authenticated ? await authenticatedQualificationContext(cohort, role) :
    await isolatedContext(fixedQualificationOptions(cohort, role));
  requireEqual(release.build, cohort.observation.releases[role].build);
  return withLockProvider(release.platform, provider => withInstallationGuards(context, provider, null, release.build, async custody => {
    if (existingOnly) {
      const handles = new Set(), budget = observerBudget(performance.now() + 480000);
      try {
        await absent(context.journalPath);
        const { selected, mount } = await observeQualificationMountedSelection(context, release, handles, budget, custody);
        await custody.assert();
        await recheckQualificationMountedSelection(context, release, selected, mount, budget);
        await absent(context.journalPath);
        budget.check();
        return release.build;
      } finally { await closeObserverHandles(handles); }
    }
    const selected = { format: 1, build: release.build, imageSha256: release.imageSha256 };
    requireEqual(await optionalSelection(context.selectionPath), selected);
    if (await installationJournal(context.support) || await contextProfileFormat(context, selected, custody) !== 2)
      throw new Error('Qualification installation has not completed');
    const launcher = await exactFile(context.executable, launcherLimit);
    if (launcher.sha256 !== release.launcher.sha256 || launcher.identity.mode !== release.launcherMode ||
        !await installedAlias(context.alias, context.executable)) throw new Error('Qualification selected entry differs');
    checkContextLauncher(context, context.executable, release.launcher.sha256);
    await custody.assert(); requireEqual(await optionalSelection(context.selectionPath), selected);
    return release.build;
  }, false, existingOnly));
}

async function qualificationForwardEntry() {
  const wire = await import('./qualification-authority.mjs');
  try {
    wire.qualificationRequire(process.argv.length === 3, 'Invalid fixed forward entry', 2);
    const { value } = await wire.qualificationInput(['schema', 'action', 'authoritySha256']);
    wire.qualificationRequire(value.schema === 1 && value.action === 'forward', 'Invalid fixed forward request', 2);
    const before = await wire.authenticateQualification(value.authoritySha256);
    const result = await installIsolatedRelease(fixedQualificationOptions(before, 'C'));
    requireEqual(result.build, before.observation.releases.C.build);
    const after = await wire.authenticateQualification(value.authoritySha256);
    requireEqual(after.observation, before.observation, 'Qualification authority changed during forward');
    const selected = await fixedQualificationSelection(after, 'C');
    wire.qualificationOutput({ schema: 1, authoritySha256: value.authoritySha256, selected });
  } catch (error) { wire.qualificationFailure(error); }
}

/** Only matching published historical assets may be present on a setup retry.
 * No profile contents, catalog, rollback history or proof are initialized. */
async function historicalSetupState(fixture, release) {
  const support = join(fixture.fixture, 'support');
  for (const path of [fixture.stateRoot, join(fixture.runtime, 'browser-profile-migration'),
    join(support, 'install-transaction.json'), join(support, 'install-previous-launcher'),
    join(support, 'rollback-launchers'), join(support, 'pre-format-2-rollback-launchers'), join(support, 'build-tool')]) await absent(path);
  const permitted = new Map([
    [support, ['images', 'releases', 'selection.lock', 'selected.json', 'historical-initialization.json']],
    [join(support, 'images'), [`${release.build}.dmg`]],
    [join(support, 'releases'), [`${release.build}.json`]],
    [dirname(fixture.launcher), ['arbol-browser']],
    [join(fixture.fixture, 'aliases'), ['arbol-browser']],
  ]);
  for (const [path, allowed] of permitted) {
    try {
      await privateDirectory(path, true);
      if ((await readdir(path)).some(name => !allowed.includes(name))) throw new Error('Unknown retained historical initialization state');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const selected = await optionalSelection(join(support, 'selected.json'));
  if (selected) requireEqual(selected, { format: 1, build: release.build, imageSha256: release.imageSha256 });
  const image = await optionalFile(join(support, 'images', `${release.build}.dmg`), imageLimit);
  if (image && (image.sha256 !== release.imageSha256 || image.identity.mode !== 0o600)) throw new Error('Historical image setup differs');
  const receipt = await optionalFile(join(support, 'releases', `${release.build}.json`), 4096);
  if (receipt) {
    if (!image || receipt.identity.mode !== 0o600) throw new Error('Historical receipt lacks its original image');
    requireEqual(parseStrictJson(receipt.bytes, 4096), { format: 1, build: release.build, imageSha256: release.imageSha256,
      source: release.source, payloadDigest: release.payloadDigest, launcherSha256: release.launcher.sha256 });
  }
  const launcher = await optionalFile(fixture.launcher, launcherLimit);
  if (launcher) {
    if (!receipt || launcher.sha256 !== release.launcher.sha256 || launcher.identity.mode !== 0o755)
      throw new Error('Historical launcher setup differs');
    checkSignature(fixture.launcher, release.launcherIdentifier);
  }
  const alias = await installedAlias(join(fixture.fixture, 'aliases/arbol-browser'), fixture.launcher);
  if (alias && !launcher || selected && (!launcher || !alias)) throw new Error('Historical setup publication order differs');
  const record = await optionalFile(join(support, 'historical-initialization.json'), 65536);
  if (!record && (selected || image || receipt || launcher || alias)) throw new Error('Historical assets lack their original initialization record');
  if (record && record.identity.mode !== 0o600) throw new Error('Historical initialization record mode differs');
  return { selected, record };
}

function historicalInitializationInputs(cohort) {
  const release = cohort.originals.historical.release;
  return { format: 1, kind: 'historical-isolated-initialization',
    authoritySha256: cohort.observation.authoritySha256, producerManifestSha256: cohort.observation.producerManifestSha256,
    historical: { build: release.build, source: release.source, imageSha256: release.imageSha256,
      signedReceiptSha256: release.receiptSha256, launcherSha256: release.launcher.sha256 } };
}
function historicalInitializationRecord(file, cohort) {
  if (!file) return null;
  const value = parseStrictJson(file.bytes, 65536), fixture = cohort.originals.historical.release.fixture.fixture;
  if (file.identity.mode !== 0o600 || !value.guards || Object.keys(value.guards).sort().join(',') !== 'build,mount,selection')
    throw new Error('Historical initialization guard record differs');
  requireEqual(value, { ...historicalInitializationInputs(cohort), guards: value.guards });
  for (const [name, path] of Object.entries({ selection: join(fixture, 'support/selection.lock'),
    build: join(fixture, 'arbol-browser/.uses/1'), mount: join(fixture, 'arbol-browser/.uses/1.mount') })) {
    const guard = value.guards[name];
    if (!guard?.identity || guard.path !== path || guard.heldMode !== 2 || guard.identity.mode !== 0o600 ||
        guard.identity.uid !== userInfo().uid || !/^[0-9]+$/.test(guard.identity.device) || !/^[0-9]+$/.test(guard.identity.inode))
      throw new Error('Historical initialization guard identity differs');
    requireEqual(guard, { path, heldMode: 2, identity: { device: guard.identity.device,
      inode: guard.identity.inode, uid: userInfo().uid, mode: 0o600 } });
  }
  return value;
}

async function initializeHistoricalQualification(cohort) {
  const historical = cohort.originals.historical, release = historical.release, providerRelease = cohort.originals.A.release;
  if (release.build !== profileMigrationPredecessor.build || release.profileFormat !== 1 || providerRelease.profileFormat !== 2)
    throw new Error('Fixed historical initialization roles differ');
  const signed = await privateJson(historical.input.signedReceipt, 8388608);
  const audit = parseStrictJson(Buffer.from(signed.value.auditBytes, 'base64'), 8388608);
  const originalReceipt = await exactFile('/Volumes/Mercury/Arbol/backups/browser-format-2-historical-inputs-9bbfd76/signed-release.json', 8388608);
  if (originalReceipt.sha256 !== 'cb41a7873dc63a8cde960b3d5df0d2122c712c35a380fe016d32c7d1e5af147f' ||
      audit.originalReceiptSha256 !== originalReceipt.sha256 || signed.sha256 !== release.receiptSha256)
    throw new Error('Authentic historical receipt provenance differs');
  const initial = await historicalSetupState(release.fixture, release);
  historicalInitializationRecord(initial.record, cohort);
  const inputs = new Map(), releases = new Map();
  for (const { input, release: member } of Object.values(cohort.originals)) {
    inputs.set(member.build, { image: input.image, signedReceiptPath: input.signedReceipt, review: input.review });
    releases.set(member.build, member);
  }
  const { context } = await createIsolatedContext(release, inputs, releases);
  // Directory preparation is durable, but cannot establish a selected release.
  for (const path of [context.images, context.receipts, dirname(context.alias), dirname(context.executable), context.mount]) {
    await syncPath(path); await syncPath(dirname(path));
  }
  return withLockProvider(providerRelease.platform, provider => withLock(provider, join(context.support, 'selection.lock'), async selectionHandle => {
    // Once selection is held, reobserve the durable preparation before creating
    // either subordinate guard. Every native acquisition itself is no-create.
    const locked = await historicalSetupState(release.fixture, release);
    let recordFile = locked.record, record = historicalInitializationRecord(recordFile, cohort);
    if (initial.record && (!recordFile || !sameFile(initial.record, recordFile))) throw new Error('Historical preparation record changed');
    const selectionGuard = await guardRecord(provider, join(context.support, 'selection.lock'), selectionHandle);
    if (record) requireEqual(selectionGuard, record.guards.selection);
    return withLock(provider, join(context.uses, release.build), async buildHandle => {
      const buildGuard = await guardRecord(provider, join(context.uses, release.build), buildHandle);
      if (record) requireEqual(buildGuard, record.guards.build);
      const publication = { provider, selection: selectionHandle };
      const recordPath = join(context.support, 'historical-initialization.json');
      await withLock(provider, join(context.uses, `${release.build}.mount`), async mountHandle => {
        const mountGuard = await guardRecord(provider, join(context.uses, `${release.build}.mount`), mountHandle);
        const expected = { ...historicalInitializationInputs(cohort), guards: { selection: selectionGuard, build: buildGuard, mount: mountGuard } };
        if (record) requireEqual(record, expected);
        else {
          // No selected or partial assets can precede this real, durable record.
          const before = await historicalSetupState(release.fixture, release);
          if (before.record) throw new Error('Unexpected historical preparation record');
          for (const path of [context.support, context.uses]) await syncPath(path);
          const bytes = encode(expected);
          recordFile = await publishExact(recordPath, 65536, hash(bytes), path => writeExclusive(path, bytes), publication);
          record = historicalInitializationRecord(recordFile, cohort);
        }
      }, !record, 'tryExistingInitializationLock');
      const assert = async () => {
        await assertContext(context);
        if (!sameFile(recordFile, await exactFile(recordPath, 65536))) throw new Error('Original historical preparation record changed');
        requireEqual(await guardRecord(provider, selectionGuard.path, selectionHandle), record.guards.selection);
        requireEqual(await guardRecord(provider, buildGuard.path, buildHandle), record.guards.build);
        const mount = await checkedGuard(record.guards.mount.path, false);
        requireEqual(record.guards.mount.identity, { device: String(mount.dev), inode: String(mount.ino), uid: Number(mount.uid), mode: 0o600 });
      };
      const custody = { publication, assert, guards: { selection: selectionGuard, oldBuild: null, newBuild: buildGuard },
        assertBuild: async build => { if (build !== release.build) throw new Error('Historical custody Build differs'); await assert(); } };
      await assert(); await stageReleaseAssets(context, release, inputs.get(release.build), custody, false);
      await mountIsolatedCandidate(context, release, provider, record); await assert();
      const current = await optionalFile(context.executable, launcherLimit);
      if (!current) await replaceFile(context.executable, release.launcher.bytes, 0o755);
      const launcher = await exactFile(context.executable, launcherLimit);
      if (launcher.sha256 !== release.launcher.sha256 || launcher.identity.mode !== 0o755) throw new Error('Historical installed launcher differs');
      checkContextLauncher(context, context.executable, release.launcher.sha256);
      await ensureAlias(context.alias, context.executable); await assert();
      const selection = { format: 1, build: release.build, imageSha256: release.imageSha256 };
      const existing = await optionalSelection(context.selectionPath);
      if (existing) requireEqual(existing, selection);
      else await replaceFile(context.selectionPath, encode(selection), 0o600);
      await assert(); requireEqual((await historicalSetupState(release.fixture, release)).selected, selection);
      if (await contextProfileFormat(context, selection, custody) !== 1) throw new Error('Historical selected format differs');
      await assert(); return release.build;
    }, !record, 'tryExistingInitializationLock');
  }, !initial.record, 'tryExistingInitializationLock'));
}

async function qualificationInitializeEntry() {
  const wire = await import('./qualification-authority.mjs');
  try {
    wire.qualificationRequire(process.argv.length === 3, 'Invalid fixed initializer entry', 2);
    const { value } = await wire.qualificationInput(['schema', 'action', 'authoritySha256']);
    wire.qualificationRequire(value.schema === 1 && value.action === 'initialize', 'Invalid fixed initializer request', 2);
    const before = await wire.authenticateQualification(value.authoritySha256);
    const selected = await initializeHistoricalQualification(before);
    const after = await wire.authenticateQualification(value.authoritySha256);
    requireEqual(after.observation, before.observation, 'Qualification authority changed during historical setup');
    requireEqual(selected, after.observation.releases.historical.build);
    wire.qualificationOutput({ schema: 1, authoritySha256: value.authoritySha256, selected });
  } catch (error) { wire.qualificationFailure(error); }
}

const qualificationPhases = ['A', 'B', 'rollback-A', 'C'];
const historicalArchive = 'rollback-launchers';
const retiredArchive = 'pre-format-2-rollback-launchers';

function observerBudget(deadline) {
  let remaining = 8 * 1024 ** 3;
  return { deadline, check(size = 0) {
    remaining -= size;
    if (remaining < 0 || performance.now() >= deadline)
      throw new InstallationOperationError('Terminal observation exhausted its budget', 5);
  } };
}

async function existingQualificationContext(cohort, role, budget = null) {
  const { release, inputs, releases } = qualificationCohort(cohort, role);
  const context = isolatedLayout(release), directories = new Map();
  for (const path of [context.images, context.receipts, dirname(context.alias), dirname(context.executable)]) {
    const identity = await privateDirectory(path, true);
    requireEqual(identity.device, cohort.observation.fixture.directories.fixture.device);
    directories.set(path, identity);
  }
  isolatedAuthorities.set(context, { release, inputs, releases, directories, boundedVerification: true, observationBudget: budget });
  await assertContext(context);
  return { context, release, releases };
}

function observerFileStamp(info) {
  return [info.dev, info.ino, info.uid, info.gid, info.mode, info.nlink, info.size, info.mtimeNs, info.ctimeNs].join(':');
}

async function checkObserverPath(record, path = record.path) {
  const info = await record.fd.stat({ bigint: true });
  requireEqual(identityOf(info), record.identity, 'Retained observer descriptor changed');
  if (record.directory ? !info.isDirectory() : !info.isFile() || info.nlink > 1n)
    throw new Error('Retained observer descriptor is unsafe');
  if (path !== null) {
    if (await realpath(path) !== path) throw new Error('Nonphysical observer evidence');
    const named = await lstat(path, { bigint: true });
    requireEqual(identityOf(named), record.identity, 'Observer path no longer names its retained descriptor');
    if (!record.directory && (named.nlink !== 1n || observerFileStamp(named) !== observerFileStamp(info)))
      throw new Error('Observer path changed while checking its descriptor');
  }
  return info;
}

async function holdObserverPath(handles, path, mode, directory = false) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK |
    (directory ? constants.O_DIRECTORY : 0));
  try {
    const identity = identityOf(await fd.stat({ bigint: true }));
    const record = { path, fd, identity, directory };
    if (identity.uid !== userInfo().uid || identity.mode !== mode) throw new Error('Unsafe observer evidence mode or owner');
    await checkObserverPath(record);
    handles.add(fd);
    return record;
  } catch (error) { await fd.close(); throw error; }
}

async function observerFile(record, maximum, budget, { path = record.path, includeBytes = false } = {}) {
  const first = await checkObserverPath(record, path);
  if (first.size < 0n || first.size > BigInt(maximum)) throw new Error('Observer file exceeds its bound');
  const size = Number(first.size), digest = createHash('sha256'), chunks = [];
  budget.check(size);
  const buffer = Buffer.alloc(Math.min(1024 * 1024, Math.max(size, 1)));
  let offset = 0;
  while (offset < size) {
    budget.check();
    const { bytesRead } = await record.fd.read(buffer, 0, Math.min(buffer.length, size - offset), offset);
    if (!bytesRead) throw new Error('Observer evidence was truncated');
    const bytes = buffer.subarray(0, bytesRead);
    digest.update(bytes);
    if (includeBytes) chunks.push(Buffer.from(bytes));
    offset += bytesRead;
  }
  const stamp = observerFileStamp(first);
  requireEqual(observerFileStamp(await checkObserverPath(record, path)), stamp);
  const reference = { path: record.path, identity: record.identity, size: String(size), sha256: digest.digest('hex') };
  return { record, path, stamp, reference, ...(includeBytes ? { bytes: Buffer.concat(chunks, size) } : {}) };
}

async function recheckObserverFile({ record, path, stamp }) {
  requireEqual(observerFileStamp(await checkObserverPath(record, path)), stamp, 'Observer file changed after observation');
}

async function closeObserverHandles(handles) {
  const results = await Promise.allSettled([...handles].map(fd => fd.close()));
  handles.clear();
  if (results.some(result => result.status === 'rejected'))
    throw new InstallationOperationError('Could not close all observer descriptors', 5);
}

async function withObserverGuards(context, provider, builds, retained, work) {
  const paths = [join(context.support, 'selection.lock'), ...[...new Set(builds)].sort().map(build => join(context.uses, build))];
  const acquired = new Map();
  async function next(index) {
    if (index === paths.length) {
      const assertGuards = async () => {
        for (const [path, { handle, record }] of acquired) {
          requireEqual(await guardRecord(provider, path, handle), record);
          if (retained.has(path)) {
            await checkObserverPath(retained.get(path));
            requireEqual(retained.get(path).identity, record.identity);
          }
        }
      };
      const assert = async () => { await assertContext(context); await assertGuards(); };
      const assertBuild = async build => {
        if (!acquired.has(join(context.uses, build))) throw new Error('Observer lacks matching Build custody');
        await assert();
      };
      await assert();
      const result = await work({ assert, assertBuild, guards: new Map([...acquired].map(([path, value]) => [path, value.record])) });
      await assertGuards();
      return result;
    }
    const path = paths[index];
    return withLock(provider, path, async handle => {
      acquired.set(path, { handle, record: await guardRecord(provider, path, handle) });
      return next(index + 1);
    }, false, 'tryExistingQualificationObserverLock');
  }
  return next(0);
}

async function keepObserverGuards(custody, state) {
  for (const [path, expected] of custody.guards) {
    if (!state.guards.has(path)) state.guards.set(path, await holdObserverPath(state.handles, path, 0o600));
    requireEqual(state.guards.get(path).identity, expected.identity);
  }
}

function observerSelection(release) {
  return { format: 1, build: release.build, imageSha256: release.imageSha256 };
}

function checkObserverLauncher(context, path, reference, budget) {
  budget.check(Number(reference.size));
  checkContextLauncher(context, path, reference.sha256, budget.deadline);
}

async function observeReleaseAssets(context, release, handles, budget) {
  const image = await holdObserverPath(handles, join(context.images, release.build + '.dmg'), 0o600);
  const receipt = await holdObserverPath(handles, join(context.receipts, release.build + '.json'), 0o600);
  const imageFile = await observerFile(image, imageLimit, budget);
  const receiptFile = await observerFile(receipt, 4096, budget, { includeBytes: true });
  requireEqual(imageFile.reference.sha256, release.imageSha256);
  requireEqual(parseStrictJson(receiptFile.bytes, 4096), { ...observerSelection(release),
    source: release.source, payloadDigest: release.payloadDigest, launcherSha256: release.launcher.sha256 });
  return { image, receipt, imageFile: imageFile.reference, releaseFile: receiptFile.reference, receiptBytes: receiptFile.bytes,
    files: [imageFile, receiptFile] };
}

async function existingQualificationReleaseAssets(context, release, custody) {
  await custody.assertBuild(release.build);
  const budget = observerBudget(performance.now() + 480000), handles = new Set();
  try {
    const assets = await observeReleaseAssets(context, release, handles, budget);
    await custody.assertBuild(release.build);
    for (const file of assets.files) await recheckObserverFile(file);
    budget.check();
    return { image: fileReference(assets.imageFile), release: fileReference(assets.releaseFile) };
  } finally { await closeObserverHandles(handles); }
}

async function observeSelectedRelease(context, release, handles, budget, custody) {
  await custody.assertBuild(release.build);
  const selected = await holdObserverPath(handles, context.selectionPath, 0o600);
  const file = await observerFile(selected, 4096, budget, { includeBytes: true });
  requireEqual(parseStrictJson(file.bytes, 4096), observerSelection(release));
  const launcher = await holdObserverPath(handles, context.executable, release.launcherMode);
  const live = await observerFile(launcher, launcherLimit, budget);
  requireEqual(live.reference.sha256, release.launcher.sha256);
  checkObserverLauncher(context, context.executable, live.reference, budget);
  const alias = await installedAlias(context.alias, context.executable);
  if (!alias) throw new Error('Observer requires the original selected alias');
  // The cohort verifier already authenticated the signed role and its format.
  // Under custody, bind the installed image and receipt to that exact role.
  const assets = await observeReleaseAssets(context, release, handles, budget);
  const files = [file, live, ...assets.files];
  for (const witness of files) await recheckObserverFile(witness);
  return { selected, launcher, selection: file.reference, selectionBytes: file.bytes, live: live.reference, alias, files, assets };
}

async function observerArchiveNames(path, budget) {
  const names = [];
  for await (const entry of await opendir(path)) {
    budget.check();
    if (names.length === 4096) throw new Error('Observer archive has too many entries');
    names.push(entry.name);
  }
  return names.sort();
}

async function observeArchive(context, directory, releases, handles, budget, custody) {
  const path = join(context.support, directory);
  const root = await holdObserverPath(handles, path, 0o700, true);
  requireEqual(root.identity.device, releases.values().next().value.fixture.directories.fixture.device);
  const names = await observerArchiveNames(path, budget);
  const records = [];
  let launcherBytes = 0;
  for (const build of names) {
    const release = releases.get(build);
    if (!release) throw new Error('Archived release is outside the expected observer cohort');
    const launcher = await holdObserverPath(handles, join(path, build), 0o755);
    const file = await observerFile(launcher, launcherLimit, budget);
    const { reference } = file;
    launcherBytes += Number(reference.size);
    if (launcherBytes > 256 * 1024 ** 2) throw new Error('Observer archive exceeds its byte bound');
    requireEqual(reference.sha256, release.launcher.sha256);
    checkObserverLauncher(context, launcher.path, reference, budget);
    await custody.assertBuild(build);
    const assets = await observeReleaseAssets(context, release, handles, budget);
    records.push({ build, launcher, reference, ...assets, files: [file, ...assets.files] });
  }
  await recheckObserverArchive(root, path, records, records.flatMap(record => record.files), budget);
  return { root, records };
}

function archiveView(records) {
  return records.map(record => ({ build: record.build, launcher: record.reference,
    release: record.releaseFile, image: record.imageFile }));
}

async function recheckObserverArchive(root, path, records, files, budget) {
  const stamp = observerFileStamp(await checkObserverPath(root, path));
  requireEqual(await observerArchiveNames(path, budget), records.map(record => record.build));
  for (const file of files) {
    budget.check();
    await recheckObserverFile(file);
  }
  requireEqual(observerFileStamp(await checkObserverPath(root, path)), stamp, 'Observer archive changed during final recheck');
}

async function observeOriginalArchive(context, original, budget, retired) {
  const path = join(context.support, retired ? retiredArchive : historicalArchive);
  const { root, records } = original.archive;
  await checkObserverPath(root, path);
  requireEqual(await observerArchiveNames(path, budget), records.map(record => record.build));
  const files = [];
  for (const record of records) {
    const launcher = await observerFile(record.launcher, launcherLimit, budget, { path: join(path, record.build) });
    requireEqual(launcher.reference, record.reference);
    const receipt = await observerFile(record.receipt, 4096, budget, { includeBytes: true });
    requireEqual(receipt.reference, record.releaseFile);
    if (!receipt.bytes.equals(record.receiptBytes)) throw new Error('Original archived release bytes changed');
    const image = await observerFile(record.image, imageLimit, budget);
    requireEqual(image.reference, record.imageFile);
    files.push(launcher, receipt, image);
  }
  // Retiring a directory changes its path, while the original file identities
  // and the canonical archive inventory continue to use their original names.
  await recheckObserverArchive(root, path, records, files, budget);
  return { files, inventorySha256: hash(canonical(archiveView(records))) };
}

async function openOriginalObserver(context, cohort, state, budget, custody) {
  await absent(context.journalPath);
  await absent(join(context.support, retiredArchive));
  await keepObserverGuards(custody, state);
  const historical = cohort.originals.historical.release;
  const support = await holdObserverPath(state.handles, context.support, 0o700, true);
  const initializer = await holdObserverPath(state.handles, join(context.support, 'historical-initialization.json'), 0o600);
  const initializerFile = await observerFile(initializer, 65536, budget, { includeBytes: true });
  const initialization = historicalInitializationRecord({ ...initializerFile.reference, bytes: initializerFile.bytes }, cohort);
  requireEqual(custody.guards.get(initialization.guards.selection.path), initialization.guards.selection);
  requireEqual(custody.guards.get(initialization.guards.build.path), initialization.guards.build);
  const mountGuard = await holdObserverPath(state.handles, initialization.guards.mount.path, 0o600);
  requireEqual(mountGuard.identity, initialization.guards.mount.identity);
  const current = await observeSelectedRelease(context, historical, state.handles, budget, custody);
  const archive = await observeArchive(context, historicalArchive, new Map([[historical.build, historical]]), state.handles, budget, custody);
  if (archive.records.length !== 1) throw new Error('The original historical archive is missing');
  const inventorySha256 = hash(canonical(archiveView(archive.records)));
  const original = { support, current, archive, inventorySha256, initializer, initializerFile, mountGuard };
  await custody.assert();
  requireEqual((await observeOriginalArchive(context, original, budget, false)).inventorySha256, inventorySha256);
  for (const file of current.files) await recheckObserverFile(file);
  const originalObservationSha256 = hash(canonical({ support: support.identity, archive: archive.root.identity,
    selection: current.selection, launcher: current.live, inventorySha256, initialization: initializerFile.reference,
    guards: [...custody.guards.values(), initialization.guards.mount] }));
  return { ...original, originalObservationSha256 };
}

async function recheckOriginalSelection(original, budget, retainedOnly = false) {
  await checkObserverPath(original.support);
  await checkObserverPath(original.mountGuard);
  const initialization = await observerFile(original.initializer, 65536, budget, { includeBytes: true });
  requireEqual(initialization.reference, original.initializerFile.reference);
  if (!initialization.bytes.equals(original.initializerFile.bytes)) throw new Error('Original historical initialization bytes changed');
  const { selected, selection, selectionBytes, launcher, live } = original.current;
  const observed = await observerFile(selected, 4096, budget, { path: retainedOnly ? null : selected.path, includeBytes: true });
  requireEqual(observed.reference, selection);
  if (!observed.bytes.equals(selectionBytes)) throw new Error('Original selection bytes changed');
  const executable = await observerFile(launcher, launcherLimit, budget, { path: null });
  requireEqual(executable.reference, live);
  return [initialization, observed, executable];
}

async function bindPreparedObserver(context, cohort, state, budget, custody) {
  const { original, handles } = state;
  await recheckOriginalSelection(original, budget);
  await keepObserverGuards(custody, state);
  const historical = cohort.originals.historical.release, release = cohort.originals.A.release;
  await absent(join(context.support, retiredArchive));
  requireEqual((await observeOriginalArchive(context, original, budget, false)).inventorySha256, original.inventorySha256);
  const journal = await holdObserverPath(handles, context.journalPath, 0o600);
  const journalFile = await observerFile(journal, 16384, budget, { includeBytes: true });
  const value = parseStrictJson(journalFile.bytes, 16384);
  if (!valid('migration.Journal', value)) throw new Error('Observer requires the real prepared format-3 journal');
  const binding = member => ({ selection: observerSelection(member), launcherSha256: member.launcher.sha256 });
  requireEqual(value.before, binding(historical));
  requireEqual(value.after, binding(release));
  const launcher = await holdObserverPath(handles, context.executable, release.launcherMode);
  const backup = await holdObserverPath(handles, context.backup, 0o755);
  const launcherFile = (await observerFile(launcher, launcherLimit, budget)).reference;
  const backupFile = (await observerFile(backup, launcherLimit, budget)).reference;
  requireEqual(backupFile.sha256, original.current.live.sha256);
  const assets = await observeReleaseAssets(context, release, handles, budget);
  const [archived] = original.archive.records;
  const prepared = {
    journal: { path: journal.path, ...fileReference(journalFile.reference), value },
    guards: { selection: custody.guards.get(join(context.support, 'selection.lock')),
      oldBuild: custody.guards.get(join(context.uses, historical.build)), newBuild: custody.guards.get(join(context.uses, release.build)) },
    selection: { value: observerSelection(historical), file: fileReference(original.current.selection) },
    launcher: fileReference(launcherFile),
    assets: { image: fileReference(assets.imageFile), release: fileReference(assets.releaseFile) },
    oldAssets: { image: fileReference(archived.imageFile), release: fileReference(archived.releaseFile), launcher: fileReference(backupFile) },
    state: { parent: await privateDirectory(dirname(context.state), true), runtime: await privateDirectory(context.runtime, true) },
  };
  await preparedBindings(context, release, prepared, { ...custody, guards: prepared.guards, assert: custody.assert });
  requireEqual((await observerFile(journal, 16384, budget)).reference, journalFile.reference);
  return { prepared, journal, journalFile, launcher, launcherFile, backup, backupFile, assets,
    preparedObservationSha256: hash(canonical(prepared)) };
}

function reopeningArchiveView(original) {
  return { parent: original.support.identity, active: original.archive.root.identity,
    entries: original.archive.records.map(record => ({ build: record.build,
      launcher: { ...fileReference(record.reference), size: Number(record.reference.size) },
      release: fileReference(record.releaseFile), image: fileReference(record.imageFile) })) };
}

async function observerProofFile(path, maximum, budget, handles, retained, evidence) {
  const record = retained ?? await holdObserverPath(handles, path, 0o600);
  requireEqual(record.path, path);
  const file = await observerFile(record, maximum, budget, { includeBytes: !evidence });
  if (evidence) {
    requireEqual(fileReference(file.reference), fileReference(evidence));
    requireEqual(file.reference.size, evidence.size);
  }
  return file;
}

async function recheckObserverEvidence(context, actual, budget) {
  if (actual.root.initial === 'absent') await absent(context.state);
  else {
    const profiles = actual.directories.filter(entry => entry.scope === 'state' && /^profiles\/[^/]+$/.test(entry.path));
    requireEqual((await readdir(join(context.state, 'profiles'))).sort(), profiles.map(entry => basename(entry.path)).sort());
    const stateFiles = new Set(actual.files.filter(file => file.scope === 'state').map(file => file.path));
    for (const { path } of profiles) {
      budget.check();
      if (!stateFiles.has(`${path}/engine.json`)) await absent(join(context.state, path, 'engine.json'));
    }
  }
  for (const { scope, path, identity } of actual.directories) {
    budget.check();
    requireEqual(await privateDirectory(evidencePath(context, scope, path), true), identity);
  }
  for (const { scope, path, identity, size, gid, mtimeNs, ctimeNs } of actual.files) {
    budget.check();
    const full = evidencePath(context, scope, path), info = await lstat(full, { bigint: true });
    if (!info.isFile() || info.nlink !== 1n || await realpath(full) !== full)
      throw new Error('Observer completion evidence is no longer physical');
    requireEqual({ identity: identityOf(info), size: String(info.size), gid: String(info.gid),
      mtimeNs: String(info.mtimeNs), ctimeNs: String(info.ctimeNs) }, { identity, size, gid, mtimeNs, ctimeNs });
  }
}

async function collectProvedCompletion(context, release, proof, prepared, budget) {
  const actual = await collectCompletionEvidence(context, release, prepared, proof.result, budget);
  requireEqual(actual.epoch, proof.epoch);
  requireEqual(actual.root, proof.state.root);
  requireEqual(actual.files, proof.files);
  requireEqual(actual.directories, proof.directories);
  return actual;
}

async function assertExistingQualificationMount(context, release, mount, budget) {
  const matches = plist('/usr/bin/hdiutil', ['info', '-plist'], budget.deadline).images
    .filter(row => row['image-path'] === context.image);
  if (matches.length !== 1) throw new Error('Completed retry requires the original installed image mapping');
  requireEqual(await mountedApplication(context.image, context.mount, matches[0], budget.deadline), release.fixture.bundle);
  await checkObserverPath(mount);
}

async function verifyQualificationRetryMount(context, release) {
  const budget = observerBudget(performance.now() + 480000), handles = new Set();
  try {
    const guard = await holdObserverPath(handles, join(context.uses, `${release.build}.mount`), 0o600);
    const mount = await holdObserverPath(handles, context.mount, 0o700, true);
    await assertExistingQualificationMount(context, release, mount, budget);
    await checkObserverPath(guard);
    budget.check();
  } finally { await closeObserverHandles(handles); }
}

async function observeQualificationMountedSelection(context, release, handles, budget, custody) {
  const selected = await observeSelectedRelease(context, release, handles, budget, custody);
  const mount = await holdObserverPath(handles, context.mount, 0o700, true);
  await assertExistingQualificationMount(context, release, mount, budget);
  return { selected, mount };
}

async function recheckQualificationMountedSelection(context, release, selected, mount, budget) {
  await assertExistingQualificationMount(context, release, mount, budget);
  for (const file of selected.files) await recheckObserverFile(file);
  const alias = await installedAlias(context.alias, context.executable);
  if (!alias || alias.device !== selected.alias.device || alias.inode !== selected.alias.inode)
    throw new Error('Qualification retry alias changed');
}

/** The same signed selection is already installed. Keep this retry read-only,
 * including when a normally repairable launcher alias or mount disappeared. */
async function verifyCompletedQualificationRetry(context, release, predecessor, custody) {
  if (release.profileFormat !== 2) throw new Error('Completed retry requires a signed format2 candidate');
  const historical = isolatedAuthorities.get(context).releases.get(predecessor.build);
  const budget = observerBudget(performance.now() + 480000), handles = new Set();
  try {
    await absent(context.journalPath);
    const { selected, mount } = await observeQualificationMountedSelection(context, release, handles, budget, custody);
    const mountGuard = await holdObserverPath(handles, join(context.uses, `${release.build}.mount`), 0o600);
    const support = await holdObserverPath(handles, context.support, 0o700, true);
    const proofFile = await observerProofFile(context.proofPath, proofLimit, budget, handles);
    const proof = parseStrictJson(proofFile.bytes, proofLimit);
    const prepared = validateReopeningProof(context, release, proof);
    requireEqual(prepared.journal.value.before, { selection: observerSelection(historical), launcherSha256: historical.launcher.sha256 });
    requireEqual(prepared.guards, custody.guards);
    requireEqual(prepared.launcher, fileReference(selected.live));
    requireEqual(prepared.assets, { image: fileReference(selected.assets.imageFile), release: fileReference(selected.assets.releaseFile) });
    requireEqual(prepared.state, { parent: await privateDirectory(dirname(context.state), true), runtime: await privateDirectory(context.runtime, true) });

    const activePath = join(context.support, historicalArchive);
    const archive = await observeArchive(context, retiredArchive, new Map([[historical.build, historical]]), handles, budget, custody);
    requireEqual(archive.records.map(record => record.build), [historical.build]);
    requireEqual(proof.rollback, reopeningArchiveView({ support, archive }));
    const active = await optionalDirectory(activePath) ?
      await observeArchive(context, historicalArchive, new Map([[release.build, release]]), handles, budget, custody) : null;
    if (active && equal(active.root.identity, archive.root.identity)) throw new Error('Active archive aliases the retired original');
    const [archived] = archive.records;
    const backup = await observerFile(await holdObserverPath(handles, context.backup, 0o755), launcherLimit, budget);
    requireEqual(backup.reference.sha256, historical.launcher.sha256);
    requireEqual(prepared.oldAssets, { image: fileReference(archived.imageFile), release: fileReference(archived.releaseFile),
      launcher: fileReference(backup.reference) });

    const actual = await collectProvedCompletion(context, release, proof, prepared, budget);
    const result = await verifySameInstallation(context, release, selected.live, release.profileFormat, custody, true);
    await recheckQualificationMountedSelection(context, release, selected, mount, budget);
    await checkObserverPath(mountGuard);
    await checkObserverPath(support);
    await recheckObserverEvidence(context, actual, budget);
    for (const file of [proofFile, backup]) await recheckObserverFile(file);
    await recheckObserverArchive(archive.root, archive.root.path, archive.records, archived.files, budget);
    if (active) await recheckObserverArchive(active.root, activePath, active.records, active.records.flatMap(record => record.files), budget);
    else await absent(activePath);
    await absent(context.journalPath);
    budget.check();
    return result;
  } finally { await closeObserverHandles(handles); }
}

async function terminalObserverEvidence(context, release, state, budget, custody) {
  const original = state.original, bound = state.prepared;
  const sources = await recheckOriginalSelection(original, budget, true);
  await absent(context.journalPath);
  if ((await checkObserverPath(bound.journal, null)).nlink !== 0n)
    throw new Error('Original prepared journal still has a directory entry');
  const journal = await observerFile(bound.journal, 16384, budget, { path: null, includeBytes: true });
  requireEqual(journal.reference, bound.journalFile.reference);
  if (!journal.bytes.equals(bound.journalFile.bytes)) throw new Error('Original journal bytes changed after unlink');
  sources.push(journal);
  for (const [record, reference, maximum, path] of [
    [bound.launcher, bound.launcherFile, launcherLimit, null], [bound.backup, bound.backupFile, launcherLimit, null],
    [bound.assets.image, bound.assets.imageFile, imageLimit, bound.assets.image.path],
    [bound.assets.receipt, bound.assets.releaseFile, 4096, bound.assets.receipt.path],
  ]) {
    const file = await observerFile(record, maximum, budget, { path });
    requireEqual(file.reference, reference);
    sources.push(file);
  }
  for (const guard of Object.values(bound.prepared.guards)) requireEqual(custody.guards.get(guard.path), guard);
  requireEqual(await privateDirectory(context.runtime, true), bound.prepared.state.runtime);
  requireEqual(await privateDirectory(dirname(context.state), true), bound.prepared.state.parent);

  const retained = state.terminal;
  const proofFile = await observerProofFile(context.proofPath, proofLimit, budget, state.handles, retained?.proof.record);
  const proof = parseStrictJson(proofFile.bytes, proofLimit);
  const prepared = validateReopeningProof(context, release, proof);
  requireEqual(prepared, bound.prepared);
  requireEqual(proof.rollback, reopeningArchiveView(original));
  const actual = await collectProvedCompletion(context, release, proof, bound.prepared, budget);

  const transaction = actual.files.find(file => file.scope === 'migration' && /^[0-9a-f]{32}\/transaction\.json$/.test(file.path));
  if (!transaction) throw new Error('Observer could not locate the validated migration transaction');
  const completionPath = transaction.path.replace(/transaction\.json$/, 'completed.json');
  const completion = actual.files.find(file => file.scope === 'migration' && file.path === completionPath);
  if (!completion) throw new Error('Observer could not locate the validated migration completion');
  const transactionFile = await observerProofFile(evidencePath(context, 'migration', transaction.path),
    transactionLimit, budget, state.handles, retained?.transaction.record, transaction);
  const completionFile = await observerProofFile(evidencePath(context, 'migration', completionPath),
    8388608, budget, state.handles, retained?.completion.record, completion);
  const { bytes: _proofBytes, ...proofWitness } = proofFile;
  const firstTerminal = { proof: proofWitness,
    transaction: transactionFile, completion: completionFile };
  if (retained) {
    for (const [name, observed] of Object.entries(firstTerminal))
      requireEqual(observed.reference, retained[name].reference);
  }
  return { terminal: firstTerminal, actual, sources };
}

async function terminalObserver(context, release, cohort, request, state, budget, custody) {
  await keepObserverGuards(custody, state);
  const roles = ['A', 'B', 'C'].map(role => cohort.originals[role].release);
  const compatible = new Map(roles.map(member => [member.build, member]));
  const expected = cohort.originals[request.phase === 'rollback-A' ? 'A' : request.phase].release;
  const handles = new Set();
  try {
    const selected = await observeSelectedRelease(context, expected, handles, budget, custody);
    const { terminal, actual, sources } = await terminalObserverEvidence(context, release, state, budget, custody);
    const old = state.original.archive;
    const retiredPath = join(context.support, retiredArchive);
    const { files: retiredFiles, inventorySha256: retiredInventorySha256 } =
      await observeOriginalArchive(context, state.original, budget, true);
    requireEqual(retiredInventorySha256, state.original.inventorySha256);
    for (const record of old.records)
      checkObserverLauncher(context, join(retiredPath, record.build), record.reference, budget);
    const activePath = join(context.support, historicalArchive);
    const active = await optionalDirectory(activePath) ?
      await observeArchive(context, historicalArchive, compatible, handles, budget, custody) : null;
    if (active && (equal(active.root.identity, old.root.identity) ||
        active.records.some(record => old.records.some(retired => equal(record.reference.identity, retired.reference.identity)))))
      throw new Error('Compatible archive aliases the retired original');
    if (request.phase === 'B' && !active?.records.some(record => record.build === cohort.originals.A.release.build))
      throw new Error('Terminal B requires the archived role A launcher');

    await custody.assert();
    await recheckObserverEvidence(context, actual, budget);
    await checkObserverPath(state.original.support);
    await checkObserverPath(state.original.mountGuard);
    for (const file of sources) await recheckObserverFile(file);
    for (const file of Object.values(terminal)) await recheckObserverFile(file);
    await recheckObserverArchive(old.root, retiredPath, old.records, retiredFiles, budget);
    await absent(context.journalPath);
    for (const file of selected.files) await recheckObserverFile(file);
    const alias = await installedAlias(context.alias, context.executable);
    if (!alias || alias.device !== selected.alias.device || alias.inode !== selected.alias.inode)
      throw new Error('Selected alias changed during terminal observation');
    if (active) {
      await recheckObserverArchive(active.root, activePath, active.records, active.records.flatMap(record => record.files), budget);
    } else await absent(activePath);
    budget.check();
    state.terminal = terminal;
    return { schema: 1, sequence: request.sequence, phase: request.phase, kind: 'observed-terminal-retirement',
      authoritySha256: cohort.observation.authoritySha256, producerManifestSha256: cohort.observation.producerManifestSha256,
      originalObservationSha256: state.original.originalObservationSha256, preparedObservationSha256: state.prepared.preparedObservationSha256,
      originalDirectory: old.root.identity, retiredDirectory: old.root.identity,
      originalInventorySha256: state.original.inventorySha256, retiredInventorySha256,
      proof: terminal.proof.reference, transaction: terminal.transaction.reference, completion: terminal.completion.reference,
      journalDisposition: 'absent', activeDirectory: active?.root.identity ?? null,
      activeInventorySha256: active ? hash(canonical(archiveView(active.records))) : null,
      selected: expected.build, nativeAdmission: false };
  } finally { await closeObserverHandles(handles); }
}

async function* qualificationObserverRequests(input, wire) {
  const limit = 16384;
  let pending = Buffer.alloc(0);
  for await (const chunk of input) {
    let start = 0;
    while (start < chunk.length) {
      const end = chunk.indexOf(0x0a, start);
      const part = chunk.subarray(start, end < 0 ? chunk.length : end);
      wire.qualificationRequire(pending.length + part.length <= limit, 'Observer request exceeds its byte limit', 2);
      pending = Buffer.concat([pending, part]);
      if (end < 0) break;
      yield wire.qualificationJson(pending, limit);
      pending = Buffer.alloc(0);
      start = end + 1;
    }
  }
  wire.qualificationRequire(!pending.length, 'Observer request ended in a partial frame', 2);
}

async function writeObserverResult(output, value, wire) {
  const bytes = encode(value);
  wire.qualificationRequire(bytes.length <= 65536, 'Observer output exceeds its byte limit');
  await new Promise((resolve, reject) => {
    output.once('error', reject);
    output.write(bytes, error => {
      output.off('error', reject);
      if (error) reject(error);
      else resolve();
    });
  });
}

async function dispatchObserverRequest(request, state, wire, deadline) {
  // The fixed authentication budget allows up to ten minutes including mount
  // cleanup. Reserve a separate bounded observation interval before starting it.
  const binding = request.action === 'bind-prepared-journal';
  const reserve = binding ? 120000 : 1200000;
  wire.qualificationRequire(deadline - performance.now() > reserve, 'Observer lifetime cannot cover another observation', 5);
  if (!state.authoritySha256) {
    const path = join(wire.qualificationDirectory, 'qualification/authority.json');
    state.authoritySha256 = (await wire.qualificationFile(path, 16384, 0o600, false, deadline - reserve)).sha256;
  }
  // Bind within the installer's ACK window using the already authenticated
  // cohort and its held original witnesses. Every terminal reauthenticates it.
  const cohort = binding ? state.cohort : await wire.authenticateQualification(state.authoritySha256);
  if (state.cohort) requireEqual(cohort.observation, state.cohort.observation, 'Observer authority changed between requests');
  else state.cohort = cohort;
  const budget = observerBudget(Math.min(deadline - (binding ? 5000 : 120000), performance.now() + (binding ? 105000 : 480000)));
  const { context, release, releases } = await existingQualificationContext(cohort, 'A', budget);
  const historical = cohort.originals.historical.release.build;
  const terminal = request.action === 'terminal';
  const builds = terminal ? [...releases.keys()] : request.action === 'open-original' ? [historical] : [historical, release.build];
  return withLockProvider(release.platform, provider => withObserverGuards(context, provider, builds, state.guards, async custody => {
    if (terminal) return terminalObserver(context, release, cohort, request, state, budget, custody);
    if (request.action === 'open-original') {
      // The shared harness checks catalog history before taking this independent
      // selection custody. No mutable catalog row supplies Browser authority.
      state.original = await openOriginalObserver(context, cohort, state, budget, custody);
      return { schema: 1, sequence: request.sequence, kind: 'observed-original', authoritySha256: state.authoritySha256,
        producerManifestSha256: state.cohort.observation.producerManifestSha256,
        originalObservationSha256: state.original.originalObservationSha256 };
    }
    state.prepared = await bindPreparedObserver(context, cohort, state, budget, custody);
    return { schema: 1, sequence: request.sequence, kind: 'observed-prepared-journal', authoritySha256: state.authoritySha256,
      producerManifestSha256: state.cohort.observation.producerManifestSha256,
      preparedObservationSha256: state.prepared.preparedObservationSha256 };
  }), budget);
}

async function qualificationObserveEntry() {
  const wire = await import('./qualification-authority.mjs');
  const state = { handles: new Set(), guards: new Map() };
  const lifetime = 7200000, deadline = performance.now() + lifetime, expiry = AbortSignal.timeout(lifetime);
  let input, output;
  try {
    wire.qualificationRequire(process.argv.length === 3, 'Invalid fixed observer entry', 2);
    const requestPipe = privateQualificationPipe(0, wire), resultPipe = privateQualificationPipe(1, wire);
    wire.qualificationRequire(requestPipe !== resultPipe, 'Observer pipes must be distinct', 2);
    input = addAbortSignal(expiry, process.stdin);
    output = addAbortSignal(expiry, process.stdout);
    // Keep output errors handled while a request is being processed.
    output.on('error', () => input.destroy(new InstallationOperationError('Observer result pipe stopped', 5)));
    const actions = ['open-original', 'bind-prepared-journal', ...qualificationPhases.map(() => 'terminal'), 'close'];
    let sequence = 0;
    for await (const request of qualificationObserverRequests(input, wire)) {
      wire.qualificationRequire(sequence < 16 && request && typeof request === 'object', 'Observer request limit or shape differs', 2);
      const action = actions[sequence];
      wire.qualificationKeys(request, action === 'terminal' ? ['schema', 'sequence', 'action', 'phase'] : ['schema', 'sequence', 'action']);
      wire.qualificationRequire(request.schema === 1 && request.sequence === sequence && request.action === action &&
        (action !== 'terminal' || request.phase === qualificationPhases[sequence - 2]), 'Observer request is out of sequence', 2);
      if (action === 'close') {
        await closeObserverHandles(state.handles);
        await writeObserverResult(output, { schema: 1, sequence, kind: 'observer-closed' }, wire);
        return;
      }
      const result = await dispatchObserverRequest(request, state, wire, deadline);
      wire.qualificationRequire(performance.now() < deadline, 'Observer observation expired', 5);
      await writeObserverResult(output, result, wire);
      sequence++;
    }
    throw new InstallationOperationError('Observer request pipe closed before completion', 5);
  } catch (error) {
    if (error instanceof InstallationOperationError) error.exitCode = error.qualificationExitCode;
    else if (expiry.aborted || output?.destroyed || input?.errored === error) error.exitCode = 5;
    wire.qualificationFailure(error);
  } finally {
    input?.destroy();
    try { await closeObserverHandles(state.handles); }
    catch (error) { wire.qualificationFailure(Object.assign(error, { exitCode: 5 })); }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === 'qualification-interrupt-v1') {
    await qualificationInterruptEntry();
  } else if (process.argv[2] === 'qualification-observe-v1') {
    await qualificationObserveEntry();
  } else if (process.argv[2] === 'qualification-install-v1') {
    await qualificationInstallEntry();
  } else if (process.argv[2] === 'qualification-forward-v1') {
    await qualificationForwardEntry();
  } else if (process.argv[2] === 'qualification-initialize-v1') {
    await qualificationInitializeEntry();
  } else {
  const [action, imageFlag, image, signedFlag, signedReceiptPath, ...extra] = process.argv.slice(2);
  if (!['verify', 'install'].includes(action) || imageFlag !== '--image' || signedFlag !== '--signed-receipt' ||
      !image || !signedReceiptPath || extra.length) {
    throw new Error('Usage: install-release.mjs <verify|install> --image <signed.dmg> --signed-receipt <signed-release.json>');
  }
  const options = { image: resolve(image), signedReceiptPath: resolve(signedReceiptPath) };
  const result = await (action === 'verify' ? verifySignedRelease(options) : installRelease(options));
  delete result.launcher;
  delete result.platform;
  console.log(JSON.stringify(result));
  }
}
