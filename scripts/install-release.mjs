import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, link, lstat, mkdir, mkdtemp, open, readdir, readlink, realpath, rename, rmdir, symlink,
  unlink } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir, userInfo } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventory, inventoryDigest } from './package-base.mjs';
import { assertPhysicalCap, canonical, exactFile, hash, json, privateDirectory, writeExclusive } from './package-host.mjs';
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

function run(program, args, input) {
  const result = spawnSync(program, args, { input, encoding: 'utf8', timeout: 120000, maxBuffer: 1048576,
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } });
  if (result.error || result.status !== 0) throw new Error(`${basename(program)} refused release verification`);
  return result;
}

function plist(program, args) {
  return JSON.parse(run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], run(program, args).stdout).stdout);
}

function checkSignature(path, identifier, deep = false) {
  const requirement = publisher.requirement + (identifier ? ` and identifier "${identifier}"` : '');
  run('/usr/bin/codesign', ['--verify', '--strict', ...(deep ? ['--deep'] : []), '-R', `=${requirement}`, path]);
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

async function mountedApplication(image, mount, attached) {
  const rows = attached['system-entities']?.filter(row => row['mount-point'] === mount);
  const device = rows?.[0]?.['dev-entry'];
  if (rows?.length !== 1 || !/^\/dev\/disk[0-9]+s[0-9]+$/.test(device)) throw new Error('Image mount mapping is incomplete');
  const images = plist('/usr/bin/hdiutil', ['info', '-plist']).images;
  const mappings = images.filter(row => row['system-entities']?.some(entity => entity['mount-point'] === mount));
  const volume = plist('/usr/sbin/diskutil', ['info', '-plist', device]);
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

/** Verify the original signed image and its sealed app before local activation. */
export async function verifySignedRelease({ image, signedReceiptPath }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Release installation requires Darwin arm64');
  const signed = await signedReceipt(signedReceiptPath), expected = signed.value;
  if ((await exactFile(image, imageLimit)).sha256 !== expected.imageSha256) throw new Error('Signed image digest differs');
  checkSignature(image);

  const mount = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-release-'));
  await privateDirectory(mount);
  let attached;
  let launcher, platform, metadata;
  try {
    attached = run('/usr/bin/hdiutil', ['attach', image, '-readonly', '-nokernel', '-mountpoint', mount,
      '-noautoopen', '-nobrowse', '-plist']).stdout;
    const data = JSON.parse(run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], attached).stdout);
    const app = await mountedApplication(image, mount, data);
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
    if ((await exactFile(image, imageLimit)).sha256 !== expected.imageSha256 ||
        (await json(signedReceiptPath)).sha256 !== signed.sha256) throw new Error('Release inputs changed during verification');
  } finally {
    if (attached) run('/usr/bin/hdiutil', ['detach', mount]);
    await rmdir(mount);
  }
  return { build: expected.build, source: expected.source, imageSha256: expected.imageSha256,
    payloadDigest: expected.payloadDigest, sourceDigest: metadata.value.sourceDigest,
    productDigest: expected.productDigest, profileFormat: 2, launcher, platform };
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
    } else {
      // Historical journal1/2 path only. New lifecycle callers always supply
      // the genuine EX selector and use native single-link RENAME_EXCL.
      try { await link(tmp, path); } catch (error) { if (error.code !== 'EEXIST') throw error; }
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
async function withLock(provider, path, work, create = true) {
  const expected = await checkedGuard(path, create);
  const held = provider.tryLock(path);
  if (!held) throw new Error('The Browser installation or selected Build is in use');
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

async function withLockProvider(platform, work) {
  const tmp = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-installer-'));
  const path = join(tmp, 'platform.node');
  try {
    await writeExclusive(path, platform.bytes);
    if ((await exactFile(path, launcherLimit)).sha256 !== platform.sha256) throw new Error('Installer lock provider changed');
    checkSignature(path);
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

async function recoverInstall(support, executable, alias, provider, uses) {
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
      checkSignature(backup, launcherIdentifier);
      await replaceFile(executable, original.bytes, 0o755);
    } else if (!target && current) {
      if (current.sha256 !== after.launcherSha256) throw new Error('Uncertain first installation');
      await unlink(executable);
      await syncPath(dirname(executable));
    }
    if (target) checkSignature(executable, launcherIdentifier);
    await unlink(journal);
    try { await unlink(backup); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await syncPath(support);
  }, false);
}

/** Read the predecessor format from its exact signed installed image, never
 * from a Build number, rehearsal selection or editable format hint. */
async function installedProfileFormat(support, selected) {
  const receipt = await installedImageReceipt(support, selected);
  if (!keys(receipt, ['format', 'build', 'imageSha256', 'source', 'payloadDigest', 'launcherSha256']) ||
      !/^[0-9a-f]{40}$/.test(receipt.source)) throw new Error('Installed release receipt is incomplete');
  const image = join(support, 'images', `${selected.build}.dmg`);
  if ((await exactFile(image, imageLimit)).sha256 !== selected.imageSha256) throw new Error('Installed predecessor image differs');
  checkSignature(image);
  const mount = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-predecessor-'));
  await privateDirectory(mount); let attached = false;
  try {
    const data = plist('/usr/bin/hdiutil', ['attach', image, '-readonly', '-nokernel', '-mountpoint', mount,
      '-noautoopen', '-nobrowse', '-plist']); attached = true;
    const app = await mountedApplication(image, mount, data);
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
    if ((await exactFile(image, imageLimit)).sha256 !== selected.imageSha256) throw new Error('Installed predecessor changed');
    return component.profileFormat;
  } finally {
    if (attached) run('/usr/bin/hdiutil', ['detach', mount]);
    await rmdir(mount);
  }
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
async function installationRoute(context, release) {
  if (release.profileFormat !== 2) throw new Error('Current release must operate profile format2');
  const pending = await installationJournal(context.support);
  const selected = await optionalSelection(context.selectionPath);
  const after = { selection: { format: 1, build: release.build, imageSha256: release.imageSha256 },
    launcherSha256: release.launcher.sha256 };
  if (pending) {
    if (pending.value.format !== 3) return { kind: 'legacy', pending };
    if (canonical(pending.value.after) !== canonical(after) ||
        ![pending.value.before?.selection ?? null, after.selection].some(value => canonical(value) === canonical(selected)))
      throw new Error('Pending conversion requires its exact signed candidate and selection');
    return { kind: 'migration', pending, previous: pending.value.before?.selection ?? null };
  }
  if (canonical(selected) === canonical(after.selection)) return { kind: 'same', previous: selected };
  if (selected && BigInt(`0x${selected.build}`) >= BigInt(`0x${release.build}`)) throw new Error('Release number cannot move backwards');
  const format = selected ? await installedProfileFormat(context.support, selected) : null;
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
async function guardRecord(provider, path, handle) {
  const expected = await checkedGuard(path, false), actual = provider.assertLock(handle);
  if (actual.device !== String(expected.dev) || actual.inode !== String(expected.ino) || actual.uid !== Number(expected.uid))
    throw new Error('Original installation guard changed');
  return { path, identity: { ...actual, mode: 0o600 }, heldMode: 2 };
}
/** Every handle is closed before returning. The result of work must contain
 * observations only, never these native EX descriptions or publication cap. */
async function withInstallationGuards(context, provider, previous, build, work, createNew = false) {
  return withLock(provider, join(context.support, 'selection.lock'), async selection => {
    const candidate = async old => withLock(provider, join(context.uses, build), async next => {
      const guards = { selection: await guardRecord(provider, join(context.support, 'selection.lock'), selection),
        oldBuild: old ? await guardRecord(provider, join(context.uses, previous.build), old) : null,
        newBuild: await guardRecord(provider, join(context.uses, build), next) };
      const assert = async () => {
        const current = { selection: await guardRecord(provider, guards.selection.path, selection),
          oldBuild: old ? await guardRecord(provider, guards.oldBuild.path, old) : null,
          newBuild: await guardRecord(provider, guards.newBuild.path, next) };
        if (canonical(current) !== canonical(guards)) throw new Error('Installation custody changed');
      };
      await assert();
      return work({ guards, assert, publication: { provider, selection } });
    }, createNew);
    return previous && previous.build !== build
      ? withLock(provider, join(context.uses, previous.build), candidate, false) : candidate(null);
  });
}
function fileReference(file) { return file ? { identity: file.identity, sha256: file.sha256 } : null; }
async function selectionFile(context) {
  const file = await optionalFile(context.selectionPath, 4096);
  const value = await optionalSelection(context.selectionPath);
  if (Boolean(file) !== Boolean(value) || (file && canonical(parseStrictJson(file.bytes, 4096)) !== canonical(value)))
    throw new Error('Selection changed during observation');
  return { value, file: fileReference(file) };
}
async function stageReleaseAssets(context, release, options, custody) {
  await custody.assert();
  const image = await publishExact(context.image, imageLimit, release.imageSha256, async path => {
    await copyFile(options.image, path, constants.COPYFILE_EXCL); await chmod(path, 0o600);
  }, custody.publication);
  if (image.identity.mode !== 0o600) throw new Error('Installed image mode differs');
  await checkedGuard(join(context.uses, `${release.build}.mount`)); await syncPath(context.uses);
  const bytes = encode({ format: 1, build: release.build, imageSha256: release.imageSha256,
    source: release.source, payloadDigest: release.payloadDigest, launcherSha256: release.launcher.sha256 });
  const receipt = await publishExact(join(context.receipts, `${release.build}.json`), 4096, hash(bytes),
    path => writeExclusive(path, bytes), custody.publication);
  if (receipt.identity.mode !== 0o600) throw new Error('Installed release receipt mode differs');
  await custody.assert(); return { image: fileReference(image), release: fileReference(receipt) };
}
/** Idempotently finish journal-before-launcher preparation while still under
 * the original EX. This helper never switches selection or opens admission. */
async function prepareMigrationRelease(context, release, options, route, custody) {
  await privateDirectory(context.runtime, true); await privateDirectory(dirname(context.state), true);
  await custody.assert();
  const selected = await selectionFile(context);
  if (canonical(selected.value) !== canonical(route.previous)) throw new Error('Original Browser selection changed');
  const assets = await stageReleaseAssets(context, release, options, custody);
  const old = route.previous ? await installedImageReceipt(context.support, route.previous) : null;
  const after = { selection: { format: 1, build: release.build, imageSha256: release.imageSha256 },
    launcherSha256: release.launcher.sha256 };
  const before = old ? { selection: route.previous, launcherSha256: old.launcherSha256 } : null;
  let journal = route.pending;
  let launcher = await optionalFile(context.executable, launcherLimit);
  if (!journal) {
    if (old ? launcher?.sha256 !== old.launcherSha256 : Boolean(launcher)) throw new Error('Original launcher differs');
    if (launcher) {
      checkSignature(context.executable, launcherIdentifier);
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
    checkSignature(context.backup, launcherIdentifier);
  }
  launcher = await optionalFile(context.executable, launcherLimit);
  if (launcher?.sha256 !== after.launcherSha256) {
    if (before ? launcher?.sha256 !== before.launcherSha256 : Boolean(launcher)) throw new Error('Unknown launcher preparation state');
    await replaceFile(context.executable, release.launcher.bytes, 0o755);
  }
  launcher = await exactFile(context.executable, launcherLimit);
  if (launcher.sha256 !== after.launcherSha256 || launcher.identity.mode !== 0o755) throw new Error('Prepared launcher differs');
  checkSignature(context.executable, launcherIdentifier); await ensureAlias(context.alias, context.executable);
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
async function invokeSignedMaintenance(context, release, prepared, provider) {
  if ((installerLocks.get(provider) ?? 0) !== 0) throw new Error('Installer custody must end before maintenance handoff');
  const launcher = await exactFile(context.executable, launcherLimit);
  const journal = await privateJson(context.journalPath, 16384);
  if (!sameFile(launcher, prepared.launcher) || launcher.sha256 !== release.launcher.sha256 ||
      !sameFile(journal, prepared.journal) || !valid('migration.Journal', journal.value))
    throw new Error('Signed maintenance handoff changed');
  checkSignature(context.executable, launcherIdentifier);
  // No caller policy/root/runtime, inherited custody descriptor, environment
  // selector or rehearsal flag enters the installed maintenance route.
  const child = spawnSync(context.executable, ['--maintenance-migrate-profiles'], {
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, timeout: 31 * 60 * 1000, maxBuffer: 1048576,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let result;
  try { result = parseStrictJson(child.stdout ?? Buffer.alloc(0), 1048576); }
  catch { throw new Error('Signed maintenance returned no valid result; installation remains closed'); }
  if (child.error || child.status !== 0 || !valid('migration.Result', result) || result.completionSha256 === null ||
      result.diagnostic !== null || result.busy.length || result.converted > 4096 || result.neverOpened > result.converted)
    throw new Error('Signed maintenance did not complete; installation remains closed');
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
async function observeFile(path, maximum = 8388608n) {
  if (resolve(path) !== path || await realpath(path) !== path) throw new Error('Nonphysical migration evidence');
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const first = await fd.stat({ bigint: true });
    const same = st => st.isFile() && st.nlink === 1n && st.uid === BigInt(userInfo().uid) &&
      st.mode === first.mode && (st.mode & 0o7777n) === 0o600n && st.dev === first.dev && st.ino === first.ino &&
      st.gid === first.gid && st.size === first.size && st.mtimeNs === first.mtimeNs && st.ctimeNs === first.ctimeNs;
    if (!same(first) || first.size < 0n || first.size > BigInt(maximum) || !same(await lstat(path, { bigint: true })))
      throw new Error('Unsafe migration evidence');
    const sha = createHash('sha256'), buffer = Buffer.alloc(1048576); let count = 0n;
    for (;;) {
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
async function evidenceCollector(context) {
  const files = new Map(), directories = new Map();
  async function directory(scope, path, expected) {
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
    const full = evidencePath(context, scope, path), observation = await observeFile(full, BigInt(maximum));
    const entry = { scope, path, ...observation }, key = `${scope}:${path}`;
    if (files.has(key)) requireEqual(files.get(key), entry);
    files.set(key, entry); if (files.size > 131072) throw new Error('Too many evidence files');
    if (!parse) return observation;
    const decoded = await privateJson(full, maximum);
    if (!sameFile(decoded, observation)) throw new Error('Evidence changed while decoding');
    requireEqual(await observeFile(full, BigInt(maximum)), observation);
    return decoded;
  }
  return { directory, file, finish: () => ({
    directories: [...directories.values()].sort((a, b) => `${a.scope}:${a.path}`.localeCompare(`${b.scope}:${b.path}`, 'en')),
    files: [...files.values()].sort((a, b) => `${a.scope}:${a.path}`.localeCompare(`${b.scope}:${b.path}`, 'en')),
  }) };
}
async function preparedBindings(context, release, prepared, custody, after = false) {
  await custody.assert(); requireEqual(custody.guards, prepared.guards);
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
  if (prepared.oldAssets) {
    const build = prepared.journal.value.before.selection.build;
    if (!sameFile(await exactFile(join(context.images, `${build}.dmg`), imageLimit), prepared.oldAssets.image) ||
        !sameFile(await privateJson(join(context.receipts, `${build}.json`)), prepared.oldAssets.release) ||
        !sameFile(await exactFile(context.backup, launcherLimit), prepared.oldAssets.launcher))
      throw new Error('Original predecessor artifacts changed');
  }
  checkSignature(context.executable, launcherIdentifier);
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
async function verifyCompletion(context, release, prepared, result, custody) {
  if (!nativeResults.has(result)) throw new Error('A genuine signed maintenance return is required');
  await preparedBindings(context, release, prepared, custody);
  const collector = await evidenceCollector(context), { file, directory } = collector;
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
  await preparedBindings(context, release, prepared, custody);
  const observation = { prepared, result, epoch: tx.epoch, root: tx.root, ...collector.finish() };
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
async function readReopeningProof(context, release, custody) {
  if (!await optionalFile(context.proofPath, proofLimit)) return null;
  const file = await privateJson(context.proofPath, proofLimit), proof = file.value;
  if (!keys(proof, ['format', 'kind', 'journal', 'before', 'after', 'source', 'result', 'epoch', 'guards', 'state', 'directories', 'files']) ||
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
  const journal = await privateJson(context.journalPath, 16384);
  requireEqual(journal.value, prepared.journal.value);
  const selected = await optionalSelection(context.selectionPath), after = equal(selected, proof.after.selection);
  await preparedBindings(context, release, prepared, custody, after);
  await recheckEvidence(context, proof);
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
    result, epoch, guards: prepared.guards, state: { ...prepared.state, root }, directories, files };
  await recheckEvidence(context, proof);
  const bytes = encode(proof); if (bytes.length > proofLimit) throw new Error('Reopening proof exceeds bound');
  await publishExact(context.proofPath, proofLimit, hash(bytes), path => writeExclusive(path, bytes), custody.publication);
  return readReopeningProof(context, release, custody);
}

/** Publish the exact selected binary and image under the same guards used by launch and retirement. */
export async function installRelease(options) {
  const release = await verifySignedRelease(options);
  const { homedir: home } = userInfo();
  const supportParts = installation.stableUses.slice(0, -1);
  const privateFrom = supportParts.length - 1;
  const support = await safeDirectories(home, supportParts, privateFrom);
  const uses = await safeDirectories(home, installation.stableUses, privateFrom);
  const bin = await safeDirectories(home, [...installation.stableBuilds.slice(0, 2), 'bin'], 1);
  const executable = join(bin, 'arbol-browser');
  const alias = join(await safeDirectories(home, ['.local', 'bin'], 2), 'arbol-browser');
  const selectionPath = join(support, 'selected.json');
  const selected = { format: 1, build: release.build, imageSha256: release.imageSha256 };
  return withLockProvider(release.platform, provider => withLock(provider, join(support, 'selection.lock'), async () => {
    await recoverInstall(support, executable, alias, provider, uses);
    const previous = await optionalSelection(selectionPath);
    const aliasBefore = Boolean(await installedAlias(alias, executable));
    const same = canonical(previous) === canonical(selected);
    if (previous && !same && BigInt(`0x${previous.build}`) >= BigInt(`0x${release.build}`)) {
      throw new Error('Browser release number is older or already belongs to different signed bytes');
    }
    const update = async () => {
      const images = await safeDirectories(home, [...supportParts, 'images'], privateFrom);
      const receipts = await safeDirectories(home, [...supportParts, 'releases'], privateFrom);
      const mount = await safeDirectories(home, [...installation.stableBuilds, release.build, 'app'], 1);
      const image = join(images, `${release.build}.dmg`);
      const saved = await publishExact(image, imageLimit, release.imageSha256, async path => {
        await copyFile(options.image, path, constants.COPYFILE_EXCL);
        await chmod(path, 0o600);
      });
      if (saved.identity.mode !== 0o600) throw new Error('Installed image permissions differ');
      await checkedGuard(join(uses, `${release.build}.mount`));
      await syncPath(uses);
      const receipt = encode({ ...selected, source: release.source, payloadDigest: release.payloadDigest,
        launcherSha256: release.launcher.sha256 });
      await publishExact(join(receipts, `${release.build}.json`), 4096, hash(receipt), path => writeExclusive(path, receipt));

      const current = await optionalFile(executable, launcherLimit);
      const old = previous ? await installedImageReceipt(support, previous) : undefined;
      if (old ? current?.sha256 !== old.launcherSha256 : current !== undefined) throw new Error('Existing launcher differs from its release receipt');
      if (!same) {
        const journal = join(support, 'install-transaction.json');
        const backup = join(support, 'install-previous-launcher');
        if (current) {
          checkSignature(executable, launcherIdentifier);
          await publishExact(backup, launcherLimit, current.sha256, path => writeExclusive(path, current.bytes, 0o755));
        }
        const transaction = encode({ format: 2, aliasBefore,
          before: old ? { selection: previous, launcherSha256: old.launcherSha256 } : null,
          after: { selection: selected, launcherSha256: release.launcher.sha256 } });
        await publishExact(journal, 4096, hash(transaction), path => writeExclusive(path, transaction));
        await replaceFile(executable, release.launcher.bytes, 0o755);
        if ((await exactFile(executable, launcherLimit)).sha256 !== release.launcher.sha256) throw new Error('Installed launcher differs');
        checkSignature(executable, launcherIdentifier);
        await ensureAlias(alias, executable);
        await replaceFile(selectionPath, encode(selected), 0o600);
      } else {
        checkSignature(executable, launcherIdentifier);
        await ensureAlias(alias, executable);
      }
      return { build: release.build, source: release.source, imageSha256: release.imageSha256, executable, image, mount, alias };
    };
    const candidate = () => withLock(provider, join(uses, release.build), update, !same);
    let result;
    try {
      result = previous && !same ? await withLock(provider, join(uses, previous.build), candidate, false) : await candidate();
    } finally {
      await recoverInstall(support, executable, alias, provider, uses);
    }
    return result;
  }));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
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
