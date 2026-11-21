import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, link, lstat, mkdir, mkdtemp, open, readdir, realpath, rmdir, unlink } from 'node:fs/promises';
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

/** Check the exact post-staple bytes and the app sealed before submission. This never activates a release. */
export async function verifyPostStapleRelease({ image, signedReceiptPath, deliveryReceiptPath }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Release installation requires Darwin arm64');
  const signed = await signedReceipt(signedReceiptPath), expected = signed.value;
  const delivered = await json(deliveryReceiptPath), receipt = delivered.value;
  if (receipt.format !== 1 || receipt.kind !== 'notarized-production-release' || receipt.status !== 'Accepted' ||
      typeof receipt.submission !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(receipt.submission) ||
      receipt.signedReceiptSha256 !== signed.sha256 || receipt.signedImageSha256 !== expected.imageSha256 ||
      receipt.build !== expected.build || receipt.source !== expected.source || receipt.productDigest !== expected.productDigest ||
      receipt.payloadDigest !== expected.payloadDigest || !digest(receipt.imageSha256)) throw new Error('Delivery receipt does not bind the signed release');
  if ((await exactFile(image, imageLimit)).sha256 !== receipt.imageSha256) throw new Error('Delivered image digest differs');
  checkSignature(image);
  run('/usr/bin/xcrun', ['stapler', 'validate', image]);
  run('/usr/sbin/spctl', ['--assess', '--type', 'open', '--context', 'context:primary-signature', image]);

  const mount = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-release-'));
  await privateDirectory(mount);
  let attached;
  let launcher;
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
      throw new Error('Notarized application differs from its independently recorded signed inventory');
    }
    const path = join(app, relativeLauncher);
    checkSignature(path, launcherIdentifier);
    launcher = await exactFile(path, launcherLimit);
    if (launcher.sha256 !== expected.launcherDigest) throw new Error('Signed launcher digest differs');
    if ((await exactFile(image, imageLimit)).sha256 !== receipt.imageSha256 || (await json(signedReceiptPath)).sha256 !== signed.sha256 ||
        (await json(deliveryReceiptPath)).sha256 !== delivered.sha256) throw new Error('Release inputs changed during verification');
  } finally {
    if (attached) run('/usr/bin/hdiutil', ['detach', mount]);
    await rmdir(mount);
  }
  return { build: expected.build, source: expected.source, imageSha256: receipt.imageSha256,
    payloadDigest: expected.payloadDigest, launcher };
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

/** First installation or idempotent reinstall of this exact release. Selection is published last. */
export async function installRelease(options) {
  const release = await verifyPostStapleRelease(options);
  const { homedir: home } = userInfo();
  const supportParts = installation.stableUses.slice(0, -1);
  const support = await safeDirectories(home, supportParts, supportParts.length - 1);
  const selectionPath = join(support, 'selected.json');
  const selected = { format: 1, build: release.build, imageSha256: release.imageSha256 };
  try {
    const current = await json(selectionPath);
    if (canonical(current.value) !== canonical(selected)) throw new Error('Installed selection requires a guarded upgrade');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const images = await safeDirectories(home, [...supportParts, 'images'], supportParts.length - 1);
  const uses = await safeDirectories(home, installation.stableUses, supportParts.length - 1);
  const mount = await safeDirectories(home, [...installation.stableBuilds, release.build, 'app'], 1);
  const bin = await safeDirectories(home, [...installation.stableBuilds.slice(0, 2), 'bin'], 1);
  const image = join(images, `${release.build}.dmg`);
  const saved = await publishExact(image, imageLimit, release.imageSha256, async path => {
    await copyFile(options.image, path, constants.COPYFILE_EXCL);
    await chmod(path, 0o600);
  });
  if (saved.identity.mode !== 0o600) throw new Error('Installed image permissions differ');
  const guard = join(uses, release.build);
  try { await writeExclusive(guard, ''); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const g = await lstat(guard);
  if (!g.isFile() || g.uid !== userInfo().uid || g.nlink !== 1 || (g.mode & 0o7777) !== 0o600)
    throw new Error('Installed Build guard is unsafe');
  await syncPath(uses);
  const executable = join(bin, 'arbol-browser');
  const launcher = await publishExact(executable, launcherLimit, release.launcher.sha256,
    path => writeExclusive(path, release.launcher.bytes, 0o755));
  if (launcher.identity.mode !== 0o755) throw new Error('Installed launcher permissions differ');
  checkSignature(executable, launcherIdentifier);
  const selection = Buffer.from(JSON.stringify(selected) + '\n');
  await publishExact(selectionPath, 4096, hash(selection), path => writeExclusive(path, selection));
  return { build: release.build, source: release.source, imageSha256: release.imageSha256,
    executable, image, mount };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [action, imageFlag, image, signedFlag, signedReceiptPath, deliveryFlag, deliveryReceiptPath, ...extra] = process.argv.slice(2);
  if (!['verify', 'install'].includes(action) || imageFlag !== '--image' || signedFlag !== '--signed-receipt' ||
      deliveryFlag !== '--delivery-receipt' || !image || !signedReceiptPath || !deliveryReceiptPath || extra.length) {
    throw new Error('Usage: install-release.mjs <verify|install> --image <post-staple.dmg> --signed-receipt <signed-release.json> --delivery-receipt <delivery.json>');
  }
  const options = { image: resolve(image), signedReceiptPath: resolve(signedReceiptPath), deliveryReceiptPath: resolve(deliveryReceiptPath) };
  const result = await (action === 'verify' ? verifyPostStapleRelease(options) : installRelease(options));
  delete result.launcher;
  console.log(JSON.stringify(result));
}
