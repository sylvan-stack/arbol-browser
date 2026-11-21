import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
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
import publisher from '../native/production-publisher-requirement.json' with { type: 'json' };

const imageLimit = 1073741824;
const launcherLimit = 67108864;
const launcherIdentifier = 'com.sylvan-stack.arbol-browser.launcher';
const relativeLauncher = 'Contents/Resources/browser/native/stable-launch';
const relativePlatform = 'Contents/Resources/browser/native/platform.node';
const relativePolicy = 'Contents/Resources/host-policy.json';
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const buildNumber = value => typeof value === 'string' && /^[1-9a-f][0-9a-f]{0,15}$/.test(value);

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
  let launcher, platform;
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
    payloadDigest: expected.payloadDigest, launcher, platform };
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

async function publishExact(path, maximum, sha256, stage) {
  const tmp = join(dirname(path), `.install-${randomBytes(12).toString('hex')}`);
  await stage(tmp);
  try {
    if ((await exactFile(tmp, maximum)).sha256 !== sha256) throw new Error('Installed input changed while copying');
    await syncPath(tmp);
    try { await link(tmp, path); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  } finally {
    await unlink(tmp);
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
  const value = JSON.parse(file.bytes.toString('utf8'));
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

async function withLock(provider, path, work, create = true) {
  const expected = await checkedGuard(path, create);
  const held = provider.tryLock(path);
  if (!held) throw new Error('The Browser installation or selected Build is in use');
  try {
    const current = provider.assertLock(held);
    if (current.device !== String(expected.dev) || current.inode !== String(expected.ino)) throw new Error('Browser Build guard changed');
    return await work();
  }
  finally { provider.releaseLock(held); }
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
  const { format, before, after, aliasBefore } = JSON.parse(pending.bytes.toString('utf8'));
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
