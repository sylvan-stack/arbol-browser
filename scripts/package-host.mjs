/** Fresh unsigned host preparation. Importing this module never stages/signs,
 * starts a product or changes the Build registry. ABR-12 owns actual execution. */
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { transform } from 'esbuild';
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readFile, writeFile, lstat, realpath, readdir, mkdir, mkdtemp, cp, chmod, link, unlink } from 'node:fs/promises';
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
async function checkedDirectory(path, privateLeaf, registered) {
  if (await realpath(path) !== path) fail('Host directory must be physical');
  const st = await lstat(path);
  if (!st.isDirectory() || ![0, userInfo().uid].includes(st.uid) || (st.mode & 0o022) ||
      (privateLeaf && (st.uid !== userInfo().uid || (st.mode & 0o7777) !== 0o700))) fail('Unsafe host directory');
  for (let parent = dirname(path); parent !== dirname(parent); parent = dirname(parent)) {
    const ancestor = await lstat(parent);
    const systemTemporary = !registered && parent === '/private/tmp' && ancestor.uid === 0 && (ancestor.mode & 0o1777) === 0o1777;
    if (!ancestor.isDirectory() || ancestor.isSymbolicLink() || (![0, userInfo().uid].includes(ancestor.uid)) ||
        (!systemTemporary && (ancestor.mode & 0o022))) fail('Unsafe host directory ancestry');
  }
  return { device: String(st.dev), inode: String(st.ino), uid: st.uid, mode: st.mode & 0o7777 };
}
export function privateDirectory(path, registered = false) { return checkedDirectory(path, true, registered); }
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
  for (const path of [dirname(buildRoot), buildRoot, stateRoot]) await privateDirectory(path, true);
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
  const native = await validateNativeCompilation(), watchdog = await validateWatchdogCompilation();
  const platformURL = new URL('./compile-platform.mjs', import.meta.url).href;
  const platform = await import(platformURL);
  if (typeof platform.validatePlatformCompilation !== 'function') fail('Platform compiler closure unavailable');
  const support = await platform.validatePlatformCompilation();
  // Purpose-limited large private compiler evidence, distinct from every small
  // policy/command and actual runtime manifest bound. Compare complete bytes
  // through compact reviewed frontiers, not editable summary assertions.
  const details = JSON.parse((await exactFile(join(root, 'dist/compiler-input-details.json'), 8388608)).bytes.toString('utf8'));
  const nativeSources = ['ownership', 'integrity', 'bindings', 'accessibility', 'text-input', 'responder', 'interaction'].map(name => `native/${name}.mm`);
  const nativeSDK = await platform.captureCompilerInputs(nativeSources), runtimeProjection = await installedRuntimeProjection();
  const frontier = input => ({ digest: hash(canonical(input)), files: Object.keys(input.files).length, policy: input.policy, providers: input.providers });
  if (canonical(details.native) !== canonical(native.input) || canonical(details.platform) !== canonical(support.input) ||
      canonical(details.watchdog) !== canonical(watchdog.input) || canonical(details.nativeSDK) !== canonical(nativeSDK) ||
      canonical(details.runtimeProjection) !== canonical(runtimeProjection)) fail('Actual compiler/package input evidence changed');
  for (const [name, digest] of Object.entries(details.vendorInputs)) {
    if (!name.startsWith('node_modules/') || name.split('/').includes('..') || hash(await readFile(join(root, name))) !== digest)
      fail('Actual vendor compiler input changed');
  }
  const actualInputs = { native: native.input, nativeSDK: frontier(nativeSDK), platform: frontier(support.input), watchdog: frontier(watchdog.input),
    runtimeProjection: compactRuntimeProjection(runtimeProjection), vendorInputs: { digest: hash(canonical(details.vendorInputs)), files: Object.keys(details.vendorInputs).length } };
  if (canonical(record.compilerInputs) !== canonical(actualInputs)) fail('Reviewed compiler frontier differs');
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
export const runtimeMetadataOnly = name => /(?:\.d\.(?:ts|cts|mts)|\.(?:js|cjs|mjs|ts|cts|mts)\.map)$/.test(name);
/** Preserve every JS/JSON/unknown asset and original package/provider path.
 * Only audited declarations and explicit compiler source maps are omitted. */
export async function dependencyProjection(directory) {
  const pkg = (await json(join(directory, 'package.json'))).value;
  const targets = [];
  function inspect(value, types = false) {
    if (typeof value === 'string') {
      if (!types) { targets.push(value); if (runtimeMetadataOnly(value)) fail('Metadata class is a live package target'); }
    } else if (Array.isArray(value)) for (const item of value) inspect(item, types);
    else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) {
      const typeCondition = types || /^(?:types|typings)(?:@|$)/.test(key);
      if (!typeCondition && runtimeMetadataOnly(key)) fail('Metadata class is a live package alias');
      inspect(item, typeCondition);
    }
  }
  for (const name of ['main', 'module', 'bin', 'exports', 'imports', 'browser']) inspect(pkg[name]);
  const kept = Object.create(null), omitted = Object.create(null), entries = [];
  async function walk(path) {
    for (const name of (await readdir(path)).sort()) {
      if (path === directory && name === 'node_modules') continue; // each locked nested package is independently projected
      const full = join(path, name), local = full.slice(directory.length + 1), stat = await lstat(full);
      if (stat.isDirectory()) { entries.push(local); await walk(full); }
      else if (stat.isSymbolicLink()) {
        if (!(await realpath(full)).startsWith(directory + sep) || runtimeMetadataOnly(local)) fail('Unsupported projected dependency link');
        entries.push(local); kept[local] = hash('symlink\0' + await (await import('node:fs/promises')).readlink(full));
      } else if (stat.isFile()) {
        const raw = await readFile(full), digest = hash(raw);
        if (runtimeMetadataOnly(local)) { omitted[local] = digest; continue; }
        if (/\.(?:js|cjs|mjs)$/.test(local)) {
          // Parse/print strips sourceMappingURL comments. A remaining reference
          // is a possible real dynamic side asset and must be preserved/reviewed.
          const code = (await transform(raw.toString('utf8'), { loader: 'js', format: 'esm', legalComments: 'none', minifyWhitespace: true })).code;
          for (const match of code.matchAll(/["']([^"'\r\n]+)["']/g))
            if (runtimeMetadataOnly(match[1])) fail('Possible live metadata side asset requires exact review');
        }
        entries.push(local); kept[local] = digest;
      } else fail('Unsupported dependency object');
    }
  }
  await walk(directory);
  return { manifest: hash(canonical(pkg)), targets, kept, omitted, entries };
}
export function dependencyFrontier(proof) {
  return { digest: hash(canonical(proof)), manifest: proof.manifest, kept: Object.keys(proof.kept).length,
    omitted: Object.keys(proof.omitted).length, entries: proof.entries.length };
}
export function compactRuntimeProjection(proof) {
  return { digest: hash(canonical(proof)), physicalEntries: proof.physicalEntries, entriesDigest: proof.entriesDigest,
    packages: Object.fromEntries(Object.entries(proof.packages).map(([name, value]) => [name, dependencyFrontier(value)])) };
}
export async function installedRuntimeProjection() {
  const lock = (await json(join(root, 'package-lock.json'))).value, packages = {}, paths = new Set(['node_modules']);
  for (const [name, entry] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b, 'en'))) {
    if (!name || entry.dev) continue;
    const proof = await dependencyProjection(join(root, name)); packages[name] = proof;
    for (const local of ['', ...proof.entries]) {
      let path = local ? `${name}/${local}` : name;
      for (;;) { paths.add(path); const parent = dirname(path); if (parent === '.' || parent === path) break; path = parent; }
    }
  }
  return { packages, physicalEntries: paths.size, entriesDigest: hash(canonical([...paths].sort())) };
}
export async function assertPhysicalCap(directory) {
  let count = 0;
  async function walk(path) {
    for (const name of await readdir(path)) {
      if (++count > 4096) fail('Actual host physical entry cap exceeded');
      const full = join(path, name), stat = await lstat(full);
      if (stat.isDirectory()) await walk(full);
      else if (stat.isSymbolicLink()) { if (!(await realpath(full)).startsWith(directory + sep)) fail('Escaping host link'); }
      else if (!stat.isFile()) fail('Unsupported physical host entry');
    }
  }
  await walk(directory); return count;
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
    const extracted = join(scratch, `dependency-${archives.length}`); await mkdir(extracted, { mode: 0o700 });
    command('/usr/bin/tar', ['-xzf', archive, '--strip-components', '1', '-C', extracted]);
    const projection = await dependencyProjection(extracted);
    const target = join(payload, name); await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await cp(extracted, target, { recursive: true, force: false, errorOnExist: true, verbatimSymlinks: true,
      filter: async path => !(await lstat(path)).isFile() || !runtimeMetadataOnly(path) });
    await writeExclusive(join(scratch, `dependency-${archives.length}.projection.json`), JSON.stringify(projection, null, 2) + '\n');
    archives.push({ name, resolved: entry.resolved, integrity: entry.integrity, sha256: hash(bytes), projection: dependencyFrontier(projection) });
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
  if (bundle !== out || !(basename(bundle) === 'ArbolBrowser.app' || (dirname(bundle) === buildRoot && /^\.host-preparation-[A-Za-z0-9_-]{22}\.app$/.test(basename(bundle)))) || inside(bundle, root) || inside(bundle, stateRoot) || inside(stateRoot, bundle)) fail('Invalid fresh outer destination');
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
  const projected = Object.fromEntries(dependencies.map(entry => [entry.name, entry.projection]));
  if (canonical(projected) !== canonical(compiled.record.compilerInputs.runtimeProjection.packages)) fail('Pinned package projection differs from reviewed compiler inputs');
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
  const physicalEntries = { bundle: await assertPhysicalCap(bundle), payload: await assertPhysicalCap(payload) };
  const record = { ...staged, physicalEntries, files: await inventory(bundle) };
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

export const preservedStockArchive = '/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-47-20261116-n5ckcn_3/build-attempt-02/electron-cache/d6975f2bc592464edd7378c436d8aab1d9d0bf7a48a3619bbd8b006d1490565a/electron-v45.3.2-darwin-arm64.zip';
/** Ordinary authentic Arbol Building adapter. Only its two actual injected
 * inputs are accepted; source comes from original build.json, never invented
 * environment metadata. Does not select, activate or mark a Build working. */
export async function prepareAllocatedHost(environment = process.env) {
  const buildRoot = environment.ARBOL_BUILD_DIR, build = environment.ARBOL_BUILD_NUMBER;
  if (typeof buildRoot !== 'string' || typeof build !== 'string' || resolve(buildRoot) !== buildRoot ||
      basename(buildRoot) !== build || basename(dirname(buildRoot)) !== 'arbol-browser' || !/^[1-9a-f][0-9a-f]{0,15}$/.test(build))
    fail('Authentic allocated Arbol Building inputs required');
  await privateDirectory(buildRoot, true); await privateDirectory(dirname(buildRoot), true);
  if ((await readdir(buildRoot)).sort().join(',') !== 'build.json,build.log') fail('Allocated Build is not fresh and unselected');
  const allocation = await json(join(buildRoot, 'build.json')), record = allocation.value;
  const pkg = (await json(join(root, 'package.json'))).value, compiled = await currentHostCompilation();
  if (record.component !== 'arbol-browser' || record.build !== build || record.status !== 'building' || record.entry !== 'bin/arbol-browser' ||
      record.packageVersion !== pkg.version || record.contract !== 1 || record.dataFormat !== 1 || !Array.isArray(record.checks) || record.checks.length ||
      !record.source || Object.keys(record.source).sort().join(',') !== 'branch,commit,repository,uncommittedChanges' ||
      record.source.repository !== await realpath(root) || record.source.branch !== compiled.sourceIdentity.branch ||
      record.source.commit !== compiled.sourceIdentity.commit || record.source.uncommittedChanges !== false || compiled.sourceIdentity.uncommittedChanges)
    fail('Allocated Building/source does not match current committed compilation');
  const stateRoot = join(dirname(dirname(dirname(buildRoot))), 'browser-state');
  const account = userInfo(), home = await realpath(account.homedir);
  for (const name of ['builds', 'browser']) {
    const protectedRoot = await protectedPath(join(home, 'Library/Application Support/Arbol', name));
    for (const path of [buildRoot, stateRoot]) if (inside(path, protectedRoot) || inside(protectedRoot, path)) fail('Owner installation is not isolated qualification');
  }
  await checkedDirectory(dirname(stateRoot), false, true);
  try { await mkdir(stateRoot, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  await assertHostIsolation(buildRoot, stateRoot);
  const review = command('/usr/bin/git', ['-C', foresterRoot, 'rev-parse', 'refs/remotes/origin/main']).trim();
  await acceptedHostProduct(review, compiled);
  // Load only the exact just-validated compiled private lock provider. This
  // branch is actual future Build execution, never invoked by static compile.
  const support = createRequire(import.meta.url)(join(root, 'dist/native/platform.node'));
  for (const name of ['trySharedLock', 'assertLock', 'releaseLock', 'publishDirectory']) if (typeof support[name] !== 'function') fail('Actual native Build provider unavailable');
  const uses = join(dirname(buildRoot), '.uses');
  try { await mkdir(uses, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const usesIdentity = await privateDirectory(uses), guardPath = join(uses, build);
  const creator = await open(guardPath, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
  let log, held, guardIdentity, logIdentity, ownEntry, published = false, failure, signed, staged;
  const same = (a, b) => a.dev === b.dev && a.ino === b.ino && a.uid === b.uid && a.mode === b.mode && a.nlink === b.nlink;
  async function assertAllocation() {
    await assertHostIsolation(buildRoot, stateRoot);
    if ((await json(join(buildRoot, 'build.json'))).sha256 !== allocation.sha256 || canonical(await privateDirectory(uses)) !== canonical(usesIdentity))
      fail('Original Building/guard directory changed');
    const named = await lstat(guardPath, { bigint: true }), actual = await creator.stat({ bigint: true });
    if (!same(guardIdentity, named) || !same(guardIdentity, actual)) fail('Original stable Build guard changed');
    const kernel = support.assertLock(held);
    if (kernel.device !== String(actual.dev) || kernel.inode !== String(actual.ino) || kernel.uid !== Number(actual.uid)) fail('Actual shared kernel guard differs');
    const currentLog = await log.stat({ bigint: true }), namedLog = await lstat(join(buildRoot, 'build.log'), { bigint: true });
    if (!same(logIdentity, currentLog) || !same(logIdentity, namedLog) || currentLog.size < logIdentity.size) fail('Original append-only Build log changed');
    if ((await currentHostCompilation()).digest !== compiled.digest) fail('Compiled source changed while preparing Build');
  }
  async function syncDirectory(path) { const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); try { await fd.sync(); } finally { await fd.close(); } }
  async function withdrawOwnEntry() {
    if (!published || !ownEntry) return;
    const path = join(buildRoot, 'bin/arbol-browser'), current = await lstat(path, { bigint: true });
    if (current.dev !== ownEntry.dev || current.ino !== ownEntry.ino || current.uid !== ownEntry.uid || !current.isFile()) fail('Entry withdrawal identity uncertain');
    await unlink(path); await syncDirectory(dirname(path)); published = false;
  }
  try {
    log = await open(join(buildRoot, 'build.log'), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    guardIdentity = await creator.stat({ bigint: true }); logIdentity = await log.stat({ bigint: true });
    if (!guardIdentity.isFile() || guardIdentity.uid !== BigInt(account.uid) || guardIdentity.nlink !== 1n || (guardIdentity.mode & 0o7777n) !== 0o600n ||
        !logIdentity.isFile() || logIdentity.uid !== BigInt(account.uid) || logIdentity.nlink !== 1n || (logIdentity.mode & 0o7777n) !== 0o600n)
      fail('Unsafe original Building guard/log');
    held = support.trySharedLock(guardPath); if (!held) fail('Build is exclusively protected');
    await assertAllocation();
    const bundle = join(buildRoot, `.host-preparation-${randomBytes(16).toString('base64url')}.app`);
    staged = await prepareUnsignedHost({ out: bundle, buildRoot, stateRoot, runtimeArchive: preservedStockArchive, review, purpose: 'isolated-qualification' });
    const signerURL = new URL('./sign-host.mjs', import.meta.url).href;
    const signer = await import(signerURL);
    signed = await signer.signHost({ bundle, runtimeArchive: preservedStockArchive, review });
    await assertAllocation();
    const source = await lstat(bundle, { bigint: true }), parent = await lstat(buildRoot, { bigint: true });
    if (!source.isDirectory() || source.dev !== parent.dev) fail('Sealed app is not on actual Building device');
    // Protect the exact original root after signing/metadata mutation and the
    // same-parent RENAME_EXCL, before CLI publication or any trust snapshot.
    // ABR-24 must clear/read back this owned flag under exclusive Build-use
    // protection in production pruning before release/distribution.
    const installed = join(buildRoot, 'ArbolBrowser.app'); support.publishDirectory(bundle, installed, held);
    await syncDirectory(buildRoot);
    const actual = await lstat(installed, { bigint: true });
    if (actual.dev !== source.dev || actual.ino !== source.ino || actual.uid !== source.uid ||
        canonical(await inventory(installed)) !== canonical(signed.files)) fail('Installed outer differs from sealed original');
    command('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R', `=anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and identifier "com.sylvan-stack.arbol-browser.native-candidate"`, installed]);
    const payload = join(installed, 'Contents/Resources/browser');
    const metadata = await json(join(payload, 'metadata.json')), policy = await json(join(installed, 'Contents/Resources/host-policy.json'));
    if (metadata.value.component.build !== build || metadata.value.sourceDigest !== compiled.record.sourceDigest ||
        policy.value.buildRoot !== buildRoot || policy.value.stateRoot !== stateRoot || policy.value.reviewDigest !== signed.reviewDigest ||
        policy.value.productDigest !== compiled.record.productDigest) fail('Installed Build metadata differs');
    await assertPhysicalCap(installed); await assertPhysicalCap(payload); await assertAllocation();
    const bin = join(buildRoot, 'bin'); await mkdir(bin, { mode: 0o700 });
    const temporary = join(bin, `.entry-${randomBytes(16).toString('hex')}`), entry = join(bin, 'arbol-browser');
    await writeExclusive(temporary, hostLauncher(), 0o755); ownEntry = await lstat(temporary, { bigint: true });
    await assertAllocation();
    // Atomic no-replacement publication of complete synced entry bytes, last.
    await link(temporary, entry); published = true;
    await unlink(temporary); await syncDirectory(bin); await syncDirectory(buildRoot);
    const final = await lstat(entry, { bigint: true });
    if (final.dev !== ownEntry.dev || final.ino !== ownEntry.ino || final.nlink !== 1n || (final.mode & 0o7777n) !== 0o755n ||
        (await exactFile(entry)).sha256 !== hash(hostLauncher())) fail('Final own entry identity differs');
    await assertAllocation();
  } catch (error) { failure = error; }
  // No finally error may leave this writer's entry visible on a failed Build.
  try { if (held) support.releaseLock(held); } catch (error) { failure ??= error; }
  try { await creator.close(); } catch (error) { failure ??= error; }
  try { await log?.close(); } catch (error) { failure ??= error; }
  if (failure) { await withdrawOwnEntry(); throw failure; }
  return { build, buildRoot, source: record.source, productDigest: compiled.record.productDigest, reviewHandover: review,
    sealedFiles: signed.payloadDigest, qualification: 'unexecuted', status: 'building' };
}
async function runPackageCommand(args) {
  if (args.length === 1 && args[0] === '--allocated') {
    console.log(JSON.stringify(await prepareAllocatedHost()));
  } else {
    if (args.length !== 12 || args.filter((_arg, index) => index % 2 === 0).join(',') !==
        '--out,--build-root,--state-root,--runtime-archive,--review-handover,--purpose')
      fail('Usage: package-host.mjs --out <fresh.app> --build-root <allocated-Build> --state-root <isolated-state> --runtime-archive <pinned.zip> --review-handover <Forester-commit> --purpose <blocked|isolated-qualification>');
    const result = await prepareUnsignedHost({ out: args[1], buildRoot: args[3], stateRoot: args[5], runtimeArchive: args[7], review: args[9], purpose: args[11] });
    console.log(JSON.stringify({ bundle: result.bundle, qualification: 'unexecuted', purpose: result.record.purpose }));
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Settle this recipe module before the signer imports it during CLI dispatch.
  void runPackageCommand(process.argv.slice(2)).catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}
