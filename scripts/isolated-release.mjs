/** Signed disposable migration images. Importing never signs, mounts, launches
 * or changes an installation. Production admission is deliberately separate. */
import { spawnSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readdir, realpath, rmdir } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { inventory, inventoryDigest, root } from './package-base.mjs';
import { acceptedHostProduct, assertHostIsolation, assertPhysicalCap, canonical, currentHostCompilation,
  exactFile, hash, hostRuntime, maintenanceFixtureLayout, privateDirectory, profileMigrationPredecessor,
  writeExclusive } from './package-host.mjs';
import publisher from '../native/publisher-requirement.json' with { type: 'json' };

const signingIdentity = 'F1B6782A3BACC18E73FE08CA424C0A81450A982C';
const imageLimit = 1073741824, codeLimit = 67108864, documentLimit = 8388608;
const resources = 'Contents/Resources';
const launcherPath = `${resources}/browser/native/stable-launch`;
const platformPath = `${resources}/browser/native/platform.node`;
const currentLauncher = 'com.sylvan-stack.arbol-browser.isolated-maintenance-launcher';
const historicalLauncher = 'com.sylvan-stack.arbol-browser.launcher';
const equal = (left, right) => canonical(left) === canonical(right);
const fail = () => { throw new Error('Exact signed isolated migration release differs; preserve this attempt'); };
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const commit = value => typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);

function command(program, args, input) {
  const result = spawnSync(program, args, { cwd: root, input, encoding: 'utf8', timeout: 120000,
    maxBuffer: documentLimit, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } });
  if (result.error || result.status !== 0) fail();
  return result.stdout;
}
function plist(program, args) {
  return JSON.parse(command('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], command(program, args)));
}
function signature(path, identifier, deep = false) {
  command('/usr/bin/codesign', ['--verify', '--strict', ...(deep ? ['--deep'] : []), '-R',
    `=${publisher.requirement}${identifier ? ` and identifier "${identifier}"` : ''}`, path]);
}

/** Reject duplicate decoded JSON names as well as malformed/oversized UTF-8.
 * Sidecars are observations, never permission to reinterpret signed resources. */
function parse(bytes) {
  if (bytes.length > documentLimit) fail();
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let at = 0;
  const space = () => { while (at < text.length && /[\x20\x09\x0a\x0d]/.test(text[at])) at++; };
  const string = () => {
    if (text[at++] !== '"') fail();
    const start = at - 1;
    while (at < text.length) {
      const ch = text[at++];
      if (ch === '"') return JSON.parse(text.slice(start, at));
      if (ch === '\\') { if (at >= text.length) fail(); at++; }
      else if (ch.charCodeAt(0) < 32) fail();
    }
    fail();
  };
  const value = depth => {
    if (depth > 128) fail();
    space();
    if (text[at] === '"') { string(); return; }
    if (text[at] === '{') {
      at++; space(); const names = new Set();
      if (text[at] === '}') { at++; return; }
      for (;;) {
        space(); const name = string(); if (names.has(name)) fail(); names.add(name);
        space(); if (text[at++] !== ':') fail(); value(depth + 1); space();
        const end = text[at++]; if (end === '}') return; if (end !== ',') fail();
      }
    }
    if (text[at] === '[') {
      at++; space(); if (text[at] === ']') { at++; return; }
      for (;;) { value(depth + 1); space(); const end = text[at++]; if (end === ']') return; if (end !== ',') fail(); }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
    if (!token) fail(); at += token[0].length;
  };
  value(0); space(); if (at !== text.length) fail();
  return JSON.parse(text);
}
async function document(path) {
  const file = await exactFile(path, documentLimit);
  return { ...file, value: parse(file.bytes) };
}
function ancestry(ancestor, descendant) {
  if (!commit(ancestor) || !commit(descendant)) fail();
  command('/usr/bin/git', ['merge-base', '--is-ancestor', ancestor, descendant]);
}
async function admitted(review) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') fail();
  const compiled = await currentHostCompilation();
  return { compiled, accepted: await acceptedHostProduct(review, compiled) };
}

/** The signed policy is the authority. The full audit must agree with the
 * actual sealed bytes and the genuine published adapter/product admission. */
async function inspectBundle(bundle, audit, review, admission) {
  const { compiled, accepted } = admission;
  if (resolve(bundle) !== bundle || await realpath(bundle) !== bundle ||
      !equal(audit.publisher, publisher) || audit.format !== 1 || audit.reviewHandover !== review ||
      audit.reviewDigest !== accepted.digest || !digest(audit.payloadDigest)) fail();
  signature(bundle, publisher.bundleIdentifier, true); await assertPhysicalCap(bundle);
  const files = await inventory(bundle);
  if (!equal(files, audit.files) || inventoryDigest(files) !== audit.payloadDigest) fail();
  const metadata = await document(join(bundle, resources, 'browser/metadata.json'));
  const policy = await document(join(bundle, resources, 'host-policy.json'));
  const compatibility = await document(join(bundle, resources, 'native-compatibility.json'));
  const m = metadata.value, p = policy.value, c = compatibility.value;
  if (p.purpose !== 'isolated-qualification' || p.format !== 1 || p.reviewDigest !== accepted.digest ||
      p.metadataDigest !== metadata.sha256 || p.compatibilityDigest !== compatibility.sha256 ||
      p.sourceDigest !== m.sourceDigest || p.productDigest !== m.host?.productDigest ||
      p.build !== m.component?.build || m.component?.name !== 'arbol-browser' || m.component?.contract !== 1 ||
      !equal(m.runtime, hostRuntime) || !equal(c.runtime, hostRuntime) ||
      c.publisherTeam !== publisher.team || c.bundleIdentifier !== publisher.bundleIdentifier ||
      !equal(c.compatibleReaderKeys, p.readableReaderKeys) || !equal(c.readableDataEpochs, p.readableDataEpochs) ||
      c.writerKey !== p.readerKey || c.qualification !== p.readerKey) fail();
  await assertHostIsolation(p.buildRoot, p.stateRoot);
  const fixture = await maintenanceFixtureLayout(p.buildRoot, p.stateRoot);
  if (!fixture || fixture.build !== p.build) fail();
  const payload = join(bundle, resources, 'browser');
  const payloadFiles = await inventory(payload);
  const withoutMetadata = { ...payloadFiles }; delete withoutMetadata['metadata.json'];
  if (!equal(m.files, withoutMetadata) || !equal(c.files,
    Object.fromEntries(Object.entries(payloadFiles).map(([path, sha]) => [`${resources}/browser/${path}`, sha])))) fail();
  let launcherIdentifier;
  if (audit.kind === 'signed-current-host') {
    if (m.component.profileFormat !== 2 || p.productDigest !== compiled.record.productDigest ||
        !equal(audit.productSources, compiled.productSources) || !equal(audit.productOutputs, compiled.productOutputs) ||
        !equal(audit.compilerInputs, compiled.record.compilerInputs) || audit.productDigest !== p.productDigest ||
        audit.sourceDigest !== m.sourceDigest || !equal(audit.sourceIdentity, m.sourceIdentity) ||
        audit.compileDigest !== m.host.compileDigest || audit.policyDigest !== policy.sha256 ||
        audit.metadataDigest !== metadata.sha256 || audit.compatibilityDigest !== compatibility.sha256 ||
        p.readerKey !== `host-isolated:1:${p.productDigest}`) fail();
    ancestry(accepted.value.sourceGit, m.sourceIdentity?.commit);
    ancestry(m.sourceIdentity.commit, compiled.sourceIdentity.commit);
    const seal = await document(join(bundle, resources, 'maintenance-fixture.json'));
    if (!equal(seal.value, { format: 1, purpose: 'isolated-qualification', ...fixture,
      launcherSha256: files[launcherPath], hostPolicySha256: policy.sha256 }) || !equal(audit.maintenanceFixture, seal.value)) fail();
    launcherIdentifier = currentLauncher;
  } else if (audit.kind === 'signed-historical-isolated-predecessor') {
    const pinned = profileMigrationPredecessor;
    if (m.component.profileFormat !== 1 || p.build !== pinned.build || p.productDigest !== pinned.productDigest ||
        m.sourceDigest !== pinned.sourceDigest || m.sourceIdentity?.commit !== pinned.source ||
        !equal(audit.original, pinned) || !digest(audit.originalReceiptSha256) || !equal(audit.fixture, fixture) ||
        audit.adapterProductDigest !== compiled.record.productDigest ||
        p.readerKey !== `host-isolated:1:${pinned.productDigest}` ||
        p.qualificationDigest !== hash(canonical({ kind: 'historical-isolated-adapter', fixture,
          original: pinned, adapter: accepted.digest, adapterSource: audit.adapterSource,
          originalReceiptSha256: audit.originalReceiptSha256 }))) fail();
    ancestry(accepted.value.sourceGit, audit.adapterSource?.commit);
    ancestry(audit.adapterSource.commit, compiled.sourceIdentity.commit);
    launcherIdentifier = historicalLauncher;
  } else fail();
  signature(join(bundle, launcherPath), launcherIdentifier);
  signature(join(bundle, platformPath));
  const launcher = await exactFile(join(bundle, launcherPath), codeLimit);
  const platform = await exactFile(join(bundle, platformPath), codeLimit);
  if (launcher.sha256 !== files[launcherPath] || platform.sha256 !== files[platformPath] ||
      !equal(await maintenanceFixtureLayout(p.buildRoot, p.stateRoot), fixture)) fail();
  return { build: p.build, source: m.sourceIdentity.commit, sourceDigest: m.sourceDigest,
    productDigest: p.productDigest, profileFormat: m.component.profileFormat, payloadDigest: audit.payloadDigest,
    launcher, platform, launcherIdentifier, launcherMode: m.component.profileFormat === 2 ? 0o700 : 0o755,
    fixture, review, reviewDigest: accepted.digest };
}

async function mountedBundle(image, mount, attached) {
  const entities = attached['system-entities']?.filter(row => row['mount-point'] === mount);
  const device = entities?.[0]?.['dev-entry'];
  if (entities?.length !== 1 || !/^\/dev\/disk[0-9]+s[0-9]+$/.test(device)) fail();
  const mappings = plist('/usr/bin/hdiutil', ['info', '-plist']).images
    .filter(row => row['system-entities']?.some(entity => entity['mount-point'] === mount));
  const volume = plist('/usr/sbin/diskutil', ['info', '-plist', device]);
  const node = await lstat(device, { bigint: true }), mounted = await lstat(mount, { bigint: true });
  if (mappings.length !== 1 || mappings[0]['image-path'] !== image || mappings[0]['owner-uid'] !== userInfo().uid ||
      mappings[0]['image-type'] !== 'UDIF read-only' || mappings[0].writeable !== false ||
      !mappings[0]['system-entities'].some(row => row['mount-point'] === mount && row['dev-entry'] === device) ||
      volume.MountPoint !== mount || volume.DeviceNode !== device || volume.FilesystemType !== 'apfs' ||
      volume.BusProtocol !== 'Disk Image' || volume.WritableVolume !== false || volume.WritableMedia !== false ||
      !node.isBlockDevice() || node.rdev !== mounted.dev || await realpath(mount) !== mount ||
      (await readdir(mount)).join(',') !== 'ArbolBrowser.app') fail();
  return join(mount, 'ArbolBrowser.app');
}

/** Verify an original signed isolated image without publishing any selection,
 * launcher, guard or native result. Temporary attachment is always readonly. */
export async function verifyIsolatedRelease({ image, signedReceiptPath, review }) {
  const admission = await admitted(review), receipt = await document(signedReceiptPath), signed = receipt.value;
  if (signed.format !== 1 || signed.kind !== 'signed-isolated-migration-release' ||
      signed.review !== review || signed.reviewDigest !== admission.accepted.digest ||
      !digest(signed.imageSha256) || !digest(signed.auditSha256) || typeof signed.auditBytes !== 'string' ||
      signed.auditSha256 !== hash(Buffer.from(signed.auditBytes ?? '', 'base64')) ||
      Buffer.from(signed.auditBytes, 'base64').toString('base64') !== signed.auditBytes) fail();
  const audit = parse(Buffer.from(signed.auditBytes, 'base64'));
  const original = await exactFile(image, imageLimit);
  if (original.sha256 !== signed.imageSha256) fail();
  signature(image);
  const mount = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-isolated-release-'));
  await privateDirectory(mount); let attached = false;
  try {
    const data = plist('/usr/bin/hdiutil', ['attach', image, '-readonly', '-nokernel', '-mountpoint', mount,
      '-noautoopen', '-nobrowse', '-plist']); attached = true;
    const bundle = await mountedBundle(image, mount, data);
    const release = await inspectBundle(bundle, audit, review, admission);
    const observed = await exactFile(image, imageLimit);
    if (release.build !== signed.build || release.source !== signed.source || release.productDigest !== signed.productDigest ||
        release.payloadDigest !== signed.payloadDigest || release.launcher.sha256 !== signed.launcherSha256 ||
        release.profileFormat !== signed.profileFormat || !equal(release.fixture, signed.fixture) ||
        observed.sha256 !== original.sha256 || !equal(observed.identity, original.identity) ||
        (await document(signedReceiptPath)).sha256 !== receipt.sha256) fail();
    return { ...release, imageSha256: signed.imageSha256, receiptSha256: receipt.sha256 };
  } finally {
    if (attached) command('/usr/bin/hdiutil', ['detach', mount]);
    await rmdir(mount);
  }
}

/** Seal only an authenticated output of the existing genuine signing recipes.
 * It is not a release allocation, production receipt or qualification verdict. */
export async function sealIsolatedRelease({ bundle, out, review }) {
  const admission = await admitted(review), auditFile = await document(bundle + '.signature-audit.json');
  const inside = (path, parent) => path === parent || path.startsWith(parent + '/');
  if (auditFile.value.bundle !== bundle || resolve(out) !== out || inside(out, bundle) || inside(bundle, out)) fail();
  const release = await inspectBundle(bundle, auditFile.value, review, admission);
  await assertHostIsolation(dirname(dirname(release.fixture.bundle)), release.fixture.stateRoot, out);
  await privateDirectory(dirname(out), true); await mkdir(out, { mode: 0o700 });
  const source = await mkdtemp(join(out, '.image-source-')), copy = join(source, 'ArbolBrowser.app');
  command('/bin/cp', ['-pR', bundle, copy]);
  if ((await readdir(source)).join(',') !== 'ArbolBrowser.app' || !equal(await inventory(copy), auditFile.value.files)) fail();
  await assertPhysicalCap(source);
  const image = join(out, 'ArbolBrowser.dmg'), account = userInfo();
  command('/usr/bin/hdiutil', ['create', '-fs', 'APFS', '-srcfolder', source, '-volname', 'ArbolBrowser',
    '-uid', String(account.uid), '-gid', String(account.gid), '-mode', '0700', '-format', 'UDRO', '-plist', image]);
  await chmod(image, 0o600);
  command('/usr/bin/codesign', ['--sign', signingIdentity, '--timestamp', image]); signature(image);
  const signedReceiptPath = join(out, 'signed-release.json');
  const signed = { format: 1, kind: 'signed-isolated-migration-release', review, reviewDigest: admission.accepted.digest,
    build: release.build, source: release.source, productDigest: release.productDigest, profileFormat: release.profileFormat,
    payloadDigest: release.payloadDigest, launcherSha256: release.launcher.sha256,
    imageSha256: (await exactFile(image, imageLimit)).sha256, fixture: release.fixture,
    auditSha256: auditFile.sha256, auditBytes: auditFile.bytes.toString('base64'), qualification: 'unexecuted' };
  if ((await document(bundle + '.signature-audit.json')).sha256 !== auditFile.sha256 ||
      !equal(await inventory(bundle), auditFile.value.files) || (await currentHostCompilation()).digest !== admission.compiled.digest) fail();
  await writeExclusive(signedReceiptPath, JSON.stringify(signed, null, 2) + '\n');
  await verifyIsolatedRelease({ image, signedReceiptPath, review });
  return { image, signedReceiptPath, imageSha256: signed.imageSha256, payloadDigest: signed.payloadDigest,
    qualification: 'unexecuted' };
}
