import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readdir, realpath, rmdir } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { basename, join } from 'node:path';
import { inventory, inventoryDigest } from '../../scripts/package-base.mjs';
import { canonical, exactFile, json, privateDirectory } from '../../scripts/package-host.mjs';
import publisher from '../../native/production-publisher-requirement.json' with { type: 'json' };

const imageLimit = 1024 ** 3;
const appName = 'ArbolBrowser.app';
const resources = 'Contents/Resources';
const payload = `${resources}/browser`;
const sha256 = /^[0-9a-f]{64}$/;

export function runReleaseTool(executable, args, input) {
  const result = spawnSync(executable, args, { input, encoding: 'utf8', timeout: 90000, maxBuffer: 1048576,
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } });
  if (result.error || result.status !== 0) throw new Error(`${basename(executable)} failed release verification`);
  return result;
}

function plist(executable, args) {
  return JSON.parse(runReleaseTool('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'],
    runReleaseTool(executable, args).stdout).stdout);
}

function strictSignature(path, identifier, deep = false) {
  const requirement = publisher.requirement + (identifier ? ` and identifier "${identifier}"` : '');
  runReleaseTool('/usr/bin/codesign', ['--verify', '--strict', ...(deep ? ['--deep'] : []), '-R', `=${requirement}`, path]);
}

function gatekeeper(path, type) {
  const context = type === 'open' ? ['--context', 'context:primary-signature'] : [];
  const result = runReleaseTool('/usr/sbin/spctl', ['--assess', '--type', type, ...context, '-vv', path]);
  const decision = result.stdout + result.stderr;
  assert.match(decision, /\baccepted\s*$/m, 'Gatekeeper must affirmatively accept the exact delivery');
  assert.match(decision, /^source=Notarized Developer ID$/m, 'Gatekeeper must observe a notarized Developer ID');
}

export async function readSignedRelease(path) {
  const input = await json(path), { value } = input;
  assert.equal(value.format, 1);
  assert.equal(value.kind, 'signed-production-candidate');
  assert.equal(value.image, 'ArbolBrowser.dmg');
  assert.match(value.build, /^[1-9a-f][0-9a-f]{0,15}$/);
  assert.match(value.source, /^[0-9a-f]{40}$/);
  for (const field of ['imageSha256', 'productDigest', 'payloadDigest', 'launcherDigest', 'reviewDigest']) assert.match(value[field], sha256);
  assert.deepEqual(value.publisher, publisher);
  assert.ok(value.files && typeof value.files === 'object' && !Array.isArray(value.files));
  return input;
}

async function verifiedMountedApp(image, mount, attached) {
  const locations = attached['system-entities'].filter(entity => entity['mount-point'] === mount);
  assert.equal(locations.length, 1);
  const device = locations[0]['dev-entry'];
  assert.match(device, /^\/dev\/disk\d+s\d+$/);
  const info = plist('/usr/bin/hdiutil', ['info', '-plist']);
  const images = info.images.filter(row => row['system-entities'].some(entity => entity['mount-point'] === mount));
  assert.equal(images.length, 1);
  assert.equal(images[0]['image-path'], image);
  assert.equal(images[0]['owner-uid'], userInfo().uid);
  assert.equal(images[0]['image-type'], 'UDIF read-only');
  assert.equal(images[0].writeable, false);
  assert.ok(images[0]['system-entities'].some(entity => entity['mount-point'] === mount && entity['dev-entry'] === device));
  const volume = plist('/usr/sbin/diskutil', ['info', '-plist', device]);
  assert.equal(volume.MountPoint, mount);
  assert.equal(volume.DeviceNode, device);
  assert.equal(volume.FilesystemType, 'apfs');
  assert.equal(volume.WritableVolume, false);
  const actualDevice = await lstat(device, { bigint: true });
  assert.ok(actualDevice.isBlockDevice());
  assert.equal(actualDevice.rdev, (await lstat(mount, { bigint: true })).dev);
  assert.deepEqual(await readdir(mount), [appName]);
  const app = join(mount, appName);
  assert.equal(await realpath(app), app);
  return app;
}

/** Read the exact mounted signed app independently of the installed path. This never runs its code. */
export async function verifyReleaseImage({ image, expected, imageSha256, stapled }) {
  assert.equal((await exactFile(image, imageLimit)).sha256, imageSha256);
  strictSignature(image);
  if (stapled) {
    const status = runReleaseTool('/usr/sbin/spctl', ['--status']);
    assert.match(status.stdout + status.stderr, /\bassessments enabled\b/);
    runReleaseTool('/usr/bin/xcrun', ['stapler', 'validate', image]);
    gatekeeper(image, 'open');
  }
  const mount = await mkdtemp(join(await realpath(tmpdir()), 'browser-release-verification-'));
  await privateDirectory(mount);
  let attached = false;
  try {
    const output = runReleaseTool('/usr/bin/hdiutil', ['attach', image, '-readonly', '-nokernel', '-nobrowse', '-noautoopen',
      '-mountpoint', mount, '-plist']).stdout;
    attached = true;
    const locations = JSON.parse(runReleaseTool('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], output).stdout);
    const app = await verifiedMountedApp(image, mount, locations);
    strictSignature(app, publisher.bundleIdentifier, true);
    if (stapled) gatekeeper(app, 'exec');
    const files = await inventory(app);
    assert.equal(inventoryDigest(files), expected.payloadDigest, 'Mounted signed app differs from the independently recorded inventory');
    assert.equal(canonical(files), canonical(expected.files));
    const { value: metadata } = await json(join(app, payload, 'metadata.json'));
    const { value: policy } = await json(join(app, resources, 'host-policy.json'));
    const { value: compatibility } = await json(join(app, resources, 'native-compatibility.json'));
    assert.equal(metadata.component.build, expected.build);
    assert.equal(metadata.sourceIdentity.commit, expected.source);
    assert.equal(metadata.sourceIdentity.uncommittedChanges, false);
    assert.equal(metadata.host.productDigest, expected.productDigest);
    assert.deepEqual(metadata.runtime, expected.runtime);
    assert.deepEqual(policy, expected.policy);
    assert.equal(policy.purpose, 'production');
    assert.equal(compatibility.bundleIdentifier, publisher.bundleIdentifier);
    assert.equal(compatibility.publisherTeam, publisher.team);
    assert.deepEqual(compatibility.runtime, expected.runtime);
    const launcher = `${payload}/native/stable-launch`;
    strictSignature(join(app, launcher), 'com.sylvan-stack.arbol-browser.launcher');
    assert.equal(files[launcher], expected.launcherDigest);
    for (const native of ['platform.node', 'ownership.node', 'host-launch', 'watchdog']) strictSignature(join(app, payload, 'native', native));
    assert.ok(Object.keys(files).some(name => name === `${payload}/lib/cli/agent-session.js`), 'Direct CLI compiled session missing');
    assert.ok(!Object.keys(files).some(name => /\/node_modules\/@modelcontextprotocol\/sdk\/|\/lib\/mcp\//.test(name)), 'Legacy MCP surface in release');
    assert.equal((await exactFile(image, imageLimit)).sha256, imageSha256, 'Read-only verification altered the input image');
    return { imageSha256, signedFileCount: Object.keys(files).length, payloadDigest: expected.payloadDigest,
      build: expected.build, source: expected.source, productDigest: expected.productDigest, runtime: metadata.runtime,
      publisher: expected.publisher, launcherDigest: files[launcher] };
  } finally {
    if (attached) runReleaseTool('/usr/bin/hdiutil', ['detach', mount]);
    await rmdir(mount);
  }
}
