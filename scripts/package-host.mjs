/** Fresh unsigned host preparation. Importing this module never stages/signs,
 * starts a product or changes the Build registry. ABR-12 owns actual execution. */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readFile, writeFile, lstat, realpath, readdir, mkdir, mkdtemp, cp, chmod } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { join, dirname, resolve, sep, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { root, inventory, inventoryDigest, sourceInventory, productInventory } from './package-base.mjs';
import { validateNativeCompilation } from './compile-native.mjs';
import { validateWatchdogCompilation } from './compile-watchdog.mjs';

export const hostRuntime = Object.freeze({ electron: '45.3.2', chromium: '156.0.8078.100', node: '24.22.2',
  napi: '10', modules: '150', platform: 'darwin', arch: 'arm64', macOS: '27.0.1' });
export const stockElectronArchive = Object.freeze({ name: 'electron-v45.3.2-darwin-arm64.zip',
  sha256: '8bdf5d55fbcc2c348b5d34b9e87a364cd2947d00b7c8bfadc6cc50233cd79ac6' });
// These are source policy. A packaging argument cannot invent an old reader or
// epoch. Compatible recovery of this exact product uses its explicit reader.
const priorReaderKeys = Object.freeze([]), readableDataEpochs = Object.freeze([1]);
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b, 'en'))) : item);
const fail = message => { throw new Error(message); };
const inside = (path, parent) => path === parent || path.startsWith(parent + sep);
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

/** Physical bounded same-description inputs, never ASAR, FIFO or a final link. */
export async function exactFile(path, maximum = 1048576) {
  if (resolve(path) !== path || await realpath(path) !== path) fail('Nonphysical host input');
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const first = await fd.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    const same = (a, b) => a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mode === b.mode &&
      a.uid === b.uid && a.nlink === 1n && b.nlink === 1n && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
    if (!first.isFile() || !same(first, named) || first.size < 1n || first.size > BigInt(maximum) ||
        (first.mode & 0o022n) || (first.uid !== 0n && first.uid !== BigInt(userInfo().uid))) fail('Unsafe host input');
    const bytes = Buffer.alloc(Number(first.size) + 1); let at = 0;
    while (at < bytes.length) { const part = await fd.read(bytes, at, bytes.length - at, null); if (!part.bytesRead) break; at += part.bytesRead; }
    const last = await fd.stat({ bigint: true }), after = await lstat(path, { bigint: true });
    if (BigInt(at) !== first.size || !same(first, last) || !same(last, after)) fail('Host input changed');
    return { bytes: bytes.subarray(0, at), sha256: hash(bytes.subarray(0, at)), identity: {
      device: String(last.dev), inode: String(last.ino), uid: Number(last.uid), mode: Number(last.mode & 0o7777n),
    } };
  } finally { await fd.close(); }
}
export async function json(path) { const file = await exactFile(path); return { ...file, value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(file.bytes)) }; }
export function command(program, args, maximum = 1048576) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' },
    timeout: 120000, maxBuffer: maximum, stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error || result.status !== 0) fail('Host preparation command failed');
  return result.stdout;
}
export async function privateDirectory(path) {
  if (await realpath(path) !== path) fail('Host directory must be physical');
  const st = await lstat(path);
  if (!st.isDirectory() || st.uid !== userInfo().uid || (st.mode & 0o7777) !== 0o700) fail('Host directory must be private');
  for (let parent = dirname(path); parent !== dirname(parent); parent = dirname(parent)) {
    const ancestor = await lstat(parent);
    const systemTemporary = parent === '/private/tmp' && ancestor.uid === 0 && (ancestor.mode & 0o1777) === 0o1777;
    if (!ancestor.isDirectory() || ancestor.isSymbolicLink() || (![0, userInfo().uid].includes(ancestor.uid)) ||
        (!systemTemporary && (ancestor.mode & 0o022))) fail('Unsafe host directory ancestry');
  }
  return { device: String(st.dev), inode: String(st.ino), uid: st.uid, mode: 0o700 };
}
async function protectedPath(path) {
  let current = path; const tail = [];
  for (;;) {
    try { await lstat(current); }
    catch (error) { if (error.code !== 'ENOENT' || current === dirname(current)) throw error; tail.unshift(basename(current)); current = dirname(current); continue; }
    return join(await realpath(current), ...tail); // dangling existing aliases refuse
  }
}
export async function assertHostIsolation(buildRoot, stateRoot) {
  if (resolve(buildRoot) !== buildRoot || resolve(stateRoot) !== stateRoot || basename(dirname(buildRoot)) !== 'arbol-browser' ||
      !/^[1-9a-f][0-9a-f]{0,15}$/.test(basename(buildRoot))) fail('Invalid isolated Build layout');
  const account = userInfo(), home = await realpath(account.homedir);
  if (!process.geteuid || process.geteuid() !== account.uid) fail('Qualification OS account differs');
  for (const path of [join(home, 'Library/Application Support/Arbol/builds'), join(home, 'Library/Application Support/Arbol/browser')]) {
    const protectedRoot = await protectedPath(path);
    for (const actual of [buildRoot, stateRoot]) if (inside(actual, protectedRoot) || inside(protectedRoot, actual)) fail('Owner installation/data is not qualification state');
  }
  for (const path of [dirname(buildRoot), buildRoot, stateRoot]) await privateDirectory(path);
  if (inside(stateRoot, buildRoot) || inside(buildRoot, stateRoot)) fail('Qualification state overlaps product');
  // One separately prepared disposable state per isolated registry scope. It
  // can survive same-scope compatible Build changes without copying profiles.
  if (stateRoot !== join(dirname(dirname(dirname(buildRoot))), 'browser-state')) fail('State is outside the isolated registry scope');
}
export async function currentHostCompilation() {
  const compiled = await json(join(root, 'dist/compile-record.json'));
  const record = compiled.value, productSources = await productInventory();
  const actualOutputs = { libraryDigest: inventoryDigest(await inventory(join(root, 'dist/lib'))),
    entryDigest: (await exactFile(join(root, 'dist/cli/main.mjs'), 16777216)).sha256,
    hostDigest: (await exactFile(join(root, 'dist/host/main.mjs'), 16777216)).sha256, native: {} };
  for (const name of ['ownership.node', 'platform.node', 'host-bootstrap', 'host-launch', 'watchdog'])
    actualOutputs.native[name] = (await exactFile(join(root, 'dist/native', name), 67108864)).sha256;
  if (!sha(record.productDigest) || record.productDigest !== inventoryDigest(productSources) ||
      canonical(record.productSources) !== canonical(productSources) ||
      record.sourceDigest !== inventoryDigest(await sourceInventory()) ||
      record.libraryDigest !== actualOutputs.libraryDigest || record.entryDigest !== actualOutputs.entryDigest || record.hostDigest !== actualOutputs.hostDigest ||
      record.nativeDigest !== inventoryDigest(await inventory(join(root, 'dist/native'))) ||
      canonical(record.productOutputs) !== canonical(actualOutputs) || !record.compilerInputs) fail('Host needs fresh complete test-free compilation');
  const git = args => command('/usr/bin/git', args).trim();
  const sourceIdentity = { repositoryDigest: hash(await realpath(root)), branch: git(['rev-parse', '--abbrev-ref', 'HEAD']),
    commit: git(['rev-parse', 'HEAD']), uncommittedChanges: git(['status', '--porcelain']) !== '' };
  if (sourceIdentity.uncommittedChanges || canonical(record.sourceIdentity) !== canonical(sourceIdentity)) fail('Host source is not the exact compiled committed Build source');
  await validateNativeCompilation(); await validateWatchdogCompilation();
  const platformURL = new URL('./compile-platform.mjs', import.meta.url).href;
  const platform = await import(platformURL);
  if (typeof platform.validatePlatformCompilation !== 'function') fail('Platform compiler closure unavailable');
  await platform.validatePlatformCompilation();
  return { record, digest: compiled.sha256, sourceIdentity, productSources, productOutputs: actualOutputs };
}
// Review authority is an already published exact Forester hand-over, never
// a caller-written JSON file or the source checkout's current HEAD itself.
const foresterRoot = '/Users/msix/Artifacts/forester';
const handoverPath = 'sagas/sylvan-stack/arbol-browser/browser-control-health/ABR-29.md';
export async function acceptedHostProduct(commit, compiled) {
  if (typeof commit !== 'string' || !/^[0-9a-f]{40}$/.test(commit)) fail('Exact published review hand-over commit required');
  if (await realpath(foresterRoot) !== foresterRoot) fail('Nonphysical review repository');
  const git = args => command('/usr/bin/git', ['-C', foresterRoot, ...args]).trim();
  if (git(['rev-parse', '--show-toplevel']) !== foresterRoot ||
      !['git@github.com:sylvan-stack/forester-artifacts.git', 'https://github.com/sylvan-stack/forester-artifacts.git'].includes(git(['remote', 'get-url', 'origin'])))
    fail('Wrong independent hand-over authority');
  git(['merge-base', '--is-ancestor', commit, 'refs/remotes/origin/main']);
  const text = git(['show', `${commit}:${handoverPath}`]);
  const blocks = [...text.matchAll(/<!-- ABR-29-HOST-SOURCE-ADMISSION:BEGIN -->\s*([\s\S]*?)\s*<!-- ABR-29-HOST-SOURCE-ADMISSION:END -->/g)];
  if (blocks.length !== 1) fail('Published hand-over has no unique accepted host source admission');
  const value = JSON.parse(blocks[0][1]);
  if (value.format !== 1 || value.status !== 'accepted' || !Number.isSafeInteger(value.acceptedSourceOrdinal) || value.acceptedSourceOrdinal < 1 ||
      !/^[0-9a-f]{40}$/.test(value.sourceGit) || !sha(value.productDigest) || value.productDigest !== compiled.record.productDigest ||
      canonical(value.productSources) !== canonical(compiled.productSources) ||
      canonical(value.productOutputs) !== canonical(compiled.productOutputs) ||
      canonical(value.compilerInputs) !== canonical(compiled.record.compilerInputs)) fail('Exact independently accepted product identity differs');
  const checkpoint = await json(value.sourceCheckpoint.path), verdict = await exactFile(value.sourceVerdict.path);
  if (checkpoint.sha256 !== value.sourceCheckpoint.sha256 || verdict.sha256 !== value.sourceVerdict.sha256 ||
      checkpoint.value.ordinal !== value.acceptedSourceOrdinal || checkpoint.value.source !== value.sourceGit ||
      checkpoint.value.productDigest !== value.productDigest || canonical(checkpoint.value.productSources) !== canonical(value.productSources) ||
      canonical(checkpoint.value.productOutputs) !== canonical(value.productOutputs) ||
      canonical(checkpoint.value.compilerInputs) !== canonical(value.compilerInputs) ||
      !/^Accepted\.?\s*$/mi.test(verdict.bytes.toString('utf8')) || !verdict.bytes.includes(Buffer.from(checkpoint.sha256)))
    fail('Independent exact source verdict/checkpoint binding differs');
  // A later testing-only commit is eligible only with unchanged complete
  // product/compiler/output maps, proved above, and actual reviewed ancestry.
  command('/usr/bin/git', ['merge-base', '--is-ancestor', value.sourceGit, compiled.sourceIdentity.commit]);
  return { digest: hash(canonical({ foresterCommit: commit, handoverPath, admission: value })), value, foresterCommit: commit };
}
export async function writeExclusive(path, value, mode = 0o600) {
  const fd = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_NONBLOCK, mode);
  try { await fd.chmod(mode); await fd.writeFile(value); await fd.sync(); } finally { await fd.close(); }
}
async function verifiedArchive(path, expected, scratch, name, maximum = 536870912) {
  const source = await exactFile(path, maximum);
  if (source.sha256 !== expected) fail('Pinned runtime archive differs');
  const snapshot = join(scratch, name); await writeExclusive(snapshot, source.bytes); return snapshot;
}
async function stockRuntime(archive, scratch) {
  const zip = await verifiedArchive(archive, stockElectronArchive.sha256, scratch, stockElectronArchive.name);
  const out = join(scratch, 'stock'); await mkdir(out, { mode: 0o700 });
  command('/usr/bin/ditto', ['-x', '-k', zip, out]);
  if ((await exactFile(join(out, 'version'))).bytes.toString('utf8').trim().replace(/^v/, '') !== hostRuntime.electron) fail('Stock Electron version differs');
  await inventory(out); return out; // validates every symlink remains in extraction
}
async function productionDependencies(payload, scratch) {
  const lock = (await json(join(root, 'package-lock.json'))).value, archives = [];
  for (const [name, entry] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b, 'en'))) {
    if (!name || entry.dev) continue;
    if (!/^node_modules\/(?:@[^/]+\/)?[^/]+(?:\/node_modules\/(?:@[^/]+\/)?[^/]+)*$/.test(name) || name.includes('..') ||
        !/^https:\/\/registry\.npmjs\.org\/[^?#]+\.tgz$/.test(entry.resolved) || !/^sha512-[A-Za-z0-9+/]+=*$/.test(entry.integrity)) fail('Unpinned production dependency');
    const response = await fetch(entry.resolved, { redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(120000) });
    if (!response.ok || Number(response.headers.get('content-length') || 0) > 33554432) fail('Dependency archive unavailable');
    const parts = []; let length = 0;
    for await (const part of response.body) { length += part.length; if (length > 33554432) fail('Dependency archive exceeds bound'); parts.push(part); }
    const bytes = Buffer.concat(parts);
    if (`sha512-${createHash('sha512').update(bytes).digest('base64')}` !== entry.integrity) fail('Dependency integrity differs');
    const archive = join(scratch, `dependency-${archives.length}.tgz`); await writeExclusive(archive, bytes);
    const listing = command('/usr/bin/tar', ['-tzf', archive]);
    if (listing.split('\n').filter(Boolean).some(path => !path.startsWith('package/') || path.split('/').includes('..'))) fail('Unsafe pinned archive path');
    const target = join(payload, name); await mkdir(target, { recursive: true, mode: 0o700 });
    command('/usr/bin/tar', ['-xzf', archive, '--strip-components', '1', '-C', target]);
    archives.push({ name, resolved: entry.resolved, integrity: entry.integrity, sha256: hash(bytes) });
  }
  return archives;
}
function outerPlist(policy) {
  return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${policy.bundleIdentifier}</string><key>CFBundleName</key><string>Arbol Browser</string><key>CFBundleExecutable</key><string>arbol-browser-native</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSMinimumSystemVersion</key><string>27.0.1</string><key>LSMultipleInstancesProhibited</key><false/></dict></plist>\n`;
}
export async function refreshHostRecords(bundle, staged) {
  const payload = join(bundle, 'Contents/Resources/browser'), readerKey = `host-${staged.purpose === 'isolated-qualification' ? 'isolated' : 'blocked'}:1:${staged.productDigest}`;
  const metadata = { format: 1, component: staged.component, runtime: hostRuntime, sourceDigest: staged.sourceDigest,
    sourceIdentity: staged.sourceIdentity, host: { layout: 1, compileDigest: staged.compileDigest, productDigest: staged.productDigest },
    files: await inventory(payload, (await readdir(payload)).filter(name => name !== 'metadata.json')) };
  await writeFile(join(payload, 'metadata.json'), JSON.stringify(metadata, null, 2) + '\n', { mode: 0o600 });
  const nativeABI = (await json(join(root, 'native/expected-inventory.json'))).value;
  const publisher = (await json(join(root, 'native/publisher-requirement.json'))).value;
  const compatibility = { abi: 1, runtime: hostRuntime, nativeABI, publisherTeam: publisher.team, bundleIdentifier: publisher.bundleIdentifier,
    featureConfiguration: { sitePerProcess: true, disabledFeatures: ['MacAccessibilityTextOperation'], extraChromiumArguments: [] },
    files: Object.fromEntries(Object.entries(await inventory(payload)).map(([path, digest]) => [`Contents/Resources/browser/${path}`, digest])),
    dataEpoch: 1, compatibleReaderKeys: [readerKey, ...priorReaderKeys], writerKey: readerKey, readableDataEpochs: [...readableDataEpochs], qualification: readerKey };
  const compatibilityBytes = JSON.stringify(compatibility, null, 2) + '\n';
  if (Buffer.byteLength(compatibilityBytes) > 1048576 || Object.keys(compatibility.files).length > 4096) fail('Host manifest exceeds actual verifier bounds');
  await writeFile(join(bundle, 'Contents/Resources/native-compatibility.json'), compatibilityBytes, { mode: 0o600 });
  const policy = { format: 1, purpose: staged.purpose, build: staged.component.build, buildRoot: staged.buildRoot, stateRoot: staged.stateRoot,
    sourceDigest: staged.sourceDigest, productDigest: staged.productDigest,
    metadataDigest: (await exactFile(join(payload, 'metadata.json'))).sha256,
    compatibilityDigest: (await exactFile(join(bundle, 'Contents/Resources/native-compatibility.json'))).sha256,
    reviewDigest: staged.reviewDigest, qualificationDigest: hash(canonical({ qualification: 'unexecuted', purpose: staged.purpose,
      buildRoot: staged.buildRoot, stateRoot: staged.stateRoot, productDigest: staged.productDigest, originalProviderGates: 'unchanged' })),
    readerKey, readableReaderKeys: compatibility.compatibleReaderKeys, readableDataEpochs: compatibility.readableDataEpochs };
  await writeFile(join(bundle, 'Contents/Resources/host-policy.json'), JSON.stringify(policy, null, 2) + '\n', { mode: 0o600 });
  return { metadata, compatibility, policy };
}
/** One new private outer, never an older signed candidate/registered payload.
 * Stage only; the separate signer and allocated-Build adapter own later steps. */
export async function prepareUnsignedHost({ out, buildRoot, stateRoot, runtimeArchive, review, purpose = 'blocked' }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || !['blocked', 'isolated-qualification'].includes(purpose)) fail('Unsupported host preparation');
  await assertHostIsolation(buildRoot, stateRoot);
  const bundle = resolve(out);
  if (bundle !== out || !bundle.endsWith('/ArbolBrowser.app') || inside(bundle, root) || inside(bundle, stateRoot) || inside(stateRoot, bundle)) fail('Invalid fresh outer destination');
  await privateDirectory(dirname(bundle));
  const compiled = await currentHostCompilation();
  const accepted = purpose === 'isolated-qualification' ? await acceptedHostProduct(review, compiled) : undefined;
  const publisher = (await json(join(root, 'native/publisher-requirement.json'))).value;
  if (publisher.team !== '7V372XL59S' || publisher.bundleIdentifier !== 'com.sylvan-stack.arbol-browser.native-candidate') fail('Publisher differs');
  // mkdir is exclusive: preserve failed attempts rather than overwriting them.
  await mkdir(bundle, { mode: 0o700 });
  const scratch = await mkdtemp(join(dirname(bundle), '.host-inputs-')); await chmod(scratch, 0o700);
  const stock = await stockRuntime(runtimeArchive, scratch), payload = join(bundle, 'Contents/Resources/browser');
  await mkdir(payload, { recursive: true, mode: 0o700 });
  const copy = { recursive: true, force: false, errorOnExist: true, verbatimSymlinks: true };
  await cp(join(root, 'dist/lib'), join(payload, 'lib'), copy); await cp(join(root, 'dist/native'), join(payload, 'native'), copy);
  for (const name of ['cli', 'host']) await cp(join(root, 'dist', name, 'main.mjs'), join(payload, 'lib', name, 'main.mjs'), copy);
  await mkdir(join(payload, 'runtime')); await cp(join(stock, 'Electron.app'), join(payload, 'runtime/Electron.app'), copy);
  for (const name of ['LICENSE', 'LICENSES.chromium.html']) await cp(join(stock, name), join(payload, 'runtime', name), copy);
  const dependencies = await productionDependencies(payload, scratch);
  const pkg = (await json(join(root, 'package.json'))).value;
  await writeExclusive(join(payload, 'package.json'), JSON.stringify({ name: pkg.name, version: pkg.version, type: 'module', private: true }) + '\n');
  await mkdir(join(payload, 'bin')); await writeExclusive(join(payload, 'bin/arbol-browser'), hostLauncher('..'), 0o755);
  await mkdir(join(bundle, 'Contents/MacOS')); await cp(join(root, 'dist/native/host-bootstrap'), join(bundle, 'Contents/MacOS/arbol-browser-native'), copy);
  await writeExclusive(join(bundle, 'Contents/Info.plist'), outerPlist(publisher));
  await writeExclusive(join(bundle, 'Contents/Resources/publisher-requirement.json'), JSON.stringify(publisher, null, 2) + '\n');
  const staged = { format: 1, kind: 'unsigned-current-host', purpose, buildRoot, stateRoot,
    component: { name: 'arbol-browser', version: pkg.version, build: basename(buildRoot), contract: pkg.arbolBrowser.contract, profileFormat: pkg.arbolBrowser.profileFormat },
    sourceDigest: compiled.record.sourceDigest, sourceIdentity: compiled.sourceIdentity, productDigest: compiled.record.productDigest,
    productSources: compiled.productSources, productOutputs: compiled.productOutputs, compilerInputs: compiled.record.compilerInputs, compileDigest: compiled.digest,
    reviewHandover: accepted?.foresterCommit ?? null,
    reviewDigest: accepted?.digest ?? hash('blocked; no host source admission'), runtimeArchive: stockElectronArchive,
    dependencies, qualification: 'unexecuted' };
  await refreshHostRecords(bundle, staged);
  if ((await currentHostCompilation()).digest !== compiled.digest) fail('Source/compile changed during preparation');
  await assertHostIsolation(buildRoot, stateRoot);
  const record = { ...staged, files: await inventory(bundle) };
  await writeExclusive(bundle + '.unsigned.json', JSON.stringify(record, null, 2) + '\n');
  return Object.freeze({ bundle, record, scratch });
}
export function hostLauncher(payloadRelative = '../ArbolBrowser.app/Contents/Resources/browser') {
  if (!['..', '../ArbolBrowser.app/Contents/Resources/browser'].includes(payloadRelative)) fail('Invalid fixed launcher');
  return `#!/bin/sh
set -eu
payload=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/${payloadRelative}" && pwd)
if [ "\${ARBOL_BROWSER_SELECTION+x}" = x ]; then
  exec /usr/bin/env -i PATH=/usr/bin:/bin ELECTRON_RUN_AS_NODE=1 ARBOL_BROWSER_SELECTION="$ARBOL_BROWSER_SELECTION" "$payload/runtime/Electron.app/Contents/MacOS/Electron" "$payload/lib/cli/main.mjs" "$@"
fi
exec /usr/bin/env -i PATH=/usr/bin:/bin ELECTRON_RUN_AS_NODE=1 "$payload/runtime/Electron.app/Contents/MacOS/Electron" "$payload/lib/cli/main.mjs" "$@"
`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 12 || args.filter((_arg, index) => index % 2 === 0).join(',') !==
      '--out,--build-root,--state-root,--runtime-archive,--review-handover,--purpose')
    fail('Usage: package-host.mjs --out <fresh.app> --build-root <allocated-Build> --state-root <isolated-state> --runtime-archive <pinned.zip> --review-handover <Forester-commit> --purpose <blocked|isolated-qualification>');
  const result = await prepareUnsignedHost({ out: args[1], buildRoot: args[3], stateRoot: args[5], runtimeArchive: args[7], review: args[9], purpose: args[11] });
  console.log(JSON.stringify({ bundle: result.bundle, qualification: 'unexecuted', purpose: result.record.purpose }));
}
