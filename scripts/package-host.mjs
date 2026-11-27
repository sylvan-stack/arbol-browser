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
import installation from '../src/runtime/installation-paths.json' with { type: 'json' };

export const hostRuntime = Object.freeze({ electron: '45.3.2', chromium: '156.0.8078.100', node: '24.22.2',
  napi: '10', modules: '150', platform: 'darwin', arch: 'arm64', macOS: '27.0.1' });
export const stockElectronArchive = Object.freeze({ name: 'electron-v45.3.2-darwin-arm64.zip',
  sha256: '8bdf5d55fbcc2c348b5d34b9e87a364cd2947d00b7c8bfadc6cc50233cd79ac6' });
// These are source policy. A packaging argument cannot invent an old reader or
// epoch. Compatible recovery of this exact product uses its explicit reader.
// Exact released Build1 product, read from its sealed production policy and
// retained verified release receipt. This declares a compatibility candidate;
// AFM-9 must qualify it with actual native closure and data continuity.
export const profileMigrationPredecessor = Object.freeze({
  build: '1', source: '9bbfd76d4926309d151897a28396af4e2e1fe0d7',
  sourceDigest: '66b6144d07a583dd3667fb6dbb006477f7f2f259d6f96229c25fd15c8aa7ae80',
  productDigest: '5ef6453874bcb930c746fdb802c206ed9c3e4c2c48b7789fe6756507f5ea445a',
  imageSha256: 'fe91ff2db13a5d2399e33eddf640de95b7142274d6642d41926d6a6c4d71748a',
  payloadDigest: 'cb0548905bed76e8ec203dbc9679b142996123212601c5c8dcd8757017014b61',
  launcherSha256: '1cb4b88f12fe7f8c157c272cf284f0effa798fa74ad1338e9826851304501bcf',
});
const readableDataEpochs = Object.freeze([1]);
// Signed format-2 predecessors use the same pinned Electron/Chromium data epoch.
const productionFormat2Predecessors = [
  '2f5768753521620b7fe65f0726fc4898df44abb781d1e1adc0bf86cbb4f5f70d',
  '8a6879d72a0f89306ac4f54f6919ca20e149b45019771b93083c4615dd78eb64',
  '9df13c6dc36502305fdd6d605e259efeeefde89b150f63ae17109a60ba47afe2',
  'e7145e2e37e81bdebe0565d01d2383ff6198f8131d135ca845c1490359f88cd6',
  'c5f1de722ba84e74973c8d7415fc012d7e292acf7748f4b21fa3b341d50958a6',
  '20b1f19e5f1e1010f9e127cf1f656a3a2d27a4aacfeed4ee1bf16c43014ec446',
  'e667ffaf4e711776c9056ba2bd71d0639010fda742d5baba77e3d8d4d1f7e295',
  '1bdd14388a0e96f4a2457f538c8557b37495197651315f68f79a53b0933b9782',
  'f2788d611572adc2d212c0ddb913e419cca82ae5d5231bd56194bf55a447250a',
  '31d98b88551a09a5b55f083b439c154b304872535b7963de57419212df549d13',
  'c586118aeae7227f7c2796be7ed9d9b9098614a9f0c9006855c47628f6740e4c',
  '788b671eacc6a928d7dbd8d913e9165c3c9620e6f6a373d38b2017b391ad2194',
  '1611cd4cbd76cc6f132522a4a08b20052c9d2c705ec5828cb9b49b031d51c869',
  '88d9b59684223f542808a581e63cf01421d2f19174a36490b23c791f21b07939',
  '20c66ddd6ab2f36c8953fa7888f2c0f1dbf50652394beb3caf96ef9bf5756ddb',
  'a98a60d485b48faa19325c17945ceaa4538d7fb8b6f253e1a7c155ac64e171c4',
  '05294e2c42b37d6af9d6ea8b2ceed51af20ce7d6bd8536ff14b04350d92a7cc2',
  '63dcfdf71207318eb7486e93252b6ad3f10b9ca29be0eaa3e5c99b4ecb68b941',
  '61b880e397eb043dea5e596cc4e2f87249eb4659692b194339d63435a55211b2',
  '8bc42750d72b9251bdadb06527b53bdaaf7ab05932f16baaa6625a45a605765f',
  'ab8056226723c8fa9118371171e3de50fd1f62020aad8f9925dd134d4206d31c',
  '39fff18622d24c0d9877befa867d2b3cd58100372cbc1fc1af8b59f71e437a27',
  'c8a673108c238e5c3d5647e1d18e0f528465d40092184433f93f4ae0b8257455',
  '3864118c5dcf00ddc07a1079127d9fe3caf1dd31e461586c66b468fb61385a48',
  '13a6ce38ff03a00c68c2362b17c3a4fe89efedfa4921e5b545538beff26c2a9b',
  '1e18ee2d154180bb501e2b7dcaf97b97a9e9cc92d7a8d3adbd44e703805eb23a',
  '2320e9de213fbcb313d559c677c3224d2b6740c048d0d8383b8e770d7ef1d712',
  '0164d0260dd69cb79dd21b8bc21d0cd7b26e8a75086795d63355da21e950cd98',
  '96f86530df9db898bc6a58028541a252ad0082329a2f00d3a1c61da3f3465096',
  '5151557a78e4e4f3684fe8ae5b4c4ddc05cf08cd875da12433b1f8d36f16809b',
  '4e86664d8fec9b162f1be27dc3b99efcd04eaf8980f8ad62faead601c734bffa',
  'e852e1993ad17189dae70db9500b5d2f23049b825a21229cf89a141ff0ac6ec7',
  'e812fa10004877e46c6a32ed15d5d783b5a4befcf4c1a2814d9242c6a49576c7',
  '90b0aad61acad7f2d4c07241483bccf0e2556d2a3c4dbde25f1b6c89bd0a9e3e',
  '0c6891d5c01afdeb80af0b2448aa10cb7bb2daef48cf55de596ef5717f6bb8c8',
  'fdec670a13c50358d4a5a50389a9d3f37ddcb2b6aa18a31b3b5119242d8f4d4e',
  '188396449d4fd1ffaad3f4d23704187f2ec9d86bb4178e062e26b52115800e70',
  'c9b96e2ac78ae644794719094e5153632a674e551f7bb23d6e7cc4ee92eab0b2',
  '447eca1eb61f3b5000c9313fa7359ef473cd9db15346e2126ee16e1ddd025d10',
  '835944ae8fc1e9b83c8203458a8e6146e21a2681dcbaf845cce12a845eb0b8d4',
  'e9f5d543131bc86599f0186f7d0c8c0c1cadd9800c03a6b972d3c5aed5b08d26',
  'b52d74d9c7e42dd41039afba41281e49cdb325524b820e65701115ebf1eabe59',
  'ee67ac6a4824e069b120527638572358c64420e5b4ee9e2b9df80ed6752c71fa',
  '488e9696766d8a3e739c17b63e5c93c90c582e11314f80e0370c0c92794c0e27',
  '1ad7469155c5c18aa3b8701c9b366ad4a28079edbeb9fc31010d6961b95c6e67',
  'b665ef007f2ae1ab690587463de09cc473405c6b5ec360bd67ba61e28699d534',
  '6eae4fe9b79d05c7aa8e869d0d1a3fccc942bed040bd062c2b508344171bce5d',
  '77bdb95c9d844cad9004d8793e25dc03c228b3addf0c55c3c749be285b3e1d0d',
  '3c5f56bbd9eb934cf55fb4775158670fae273e4e63194b9ecda52661954edd9b',
  'a46e2f7a7f9c9a3b8444edf775d086ed28c61bdc1e8224f9bec4c6a0243e110e',
  '9e159ae80ffaf62e52a80416e470724e082ae74c470404f89335faac0a9b509a',
  '42e3f2d4f7c4118860fdef2f0cdba4bf767663ccda230ad8b7b12a3a8200b284',
  '6247e35382ae2391ef59d754684c04e2a545be4183085d2113db5959dc3ee81a',
];
function predecessorReaderKeys(scope) {
  const keys = ['production', 'isolated'].includes(scope)
    ? [`host-${scope}:1:${profileMigrationPredecessor.productDigest}`] : [];
  if (scope === 'production') keys.push(...productionFormat2Predecessors.map(digest => `host-production:1:${digest}`));
  return keys;
}
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b, 'en'))) : item);
const fail = message => { throw new Error(message); };
const inside = (path, parent) => path === parent || path.startsWith(parent === sep ? sep : parent + sep);
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
function protectedLocations(home) {
  return [join(home, ...installation.builds), join(home, ...installation.payloads),
    join(home, installation.root, installation.browser)];
}
/** Exact AFM isolated authority. The caller prepares directories; this only
 * observes them and never creates state or supplies native custody. */
export async function maintenanceFixtureLayout(buildRoot, stateRoot) {
  const fixture = dirname(dirname(buildRoot));
  if (stateRoot !== join(fixture, 'state/browser')) return null;
  if (resolve(fixture) !== fixture || dirname(buildRoot) !== join(fixture, 'arbol-browser') ||
      !/^[1-9a-f][0-9a-f]{0,15}$/.test(basename(buildRoot))) fail('Invalid maintenance fixture layout');
  const home = await realpath(userInfo().homedir);
  for (const path of [...protectedLocations(home), join(home, installation.root),
    join(home, ...installation.stableBuilds), join(home, ...installation.stableUses)]) {
    const protectedRoot = (await protectedPath(path)).normalize('NFC').toLowerCase();
    const actual = fixture.normalize('NFC').toLowerCase();
    if (inside(actual, protectedRoot) || inside(protectedRoot, actual)) fail('Maintenance fixture overlaps installed authority');
  }
  const paths = { fixture, support: join(fixture, 'support'), registry: join(fixture, 'arbol-browser'),
    uses: join(fixture, 'arbol-browser/.uses'), runtime: join(fixture, 'runtime'), stateParent: join(fixture, 'state') };
  const directories = {}, seen = new Set();
  for (const [key, path] of Object.entries(paths)) {
    const id = await privateDirectory(path, true), name = `${id.device}:${id.inode}`;
    if (seen.has(name) || (key !== 'fixture' && id.device !== directories.fixture.device)) fail('Fixture directory identity overlaps');
    seen.add(name); directories[key] = id;
  }
  const bin = await privateDirectory(join(fixture, 'bin'), true);
  if (seen.has(`${bin.device}:${bin.inode}`) || bin.device !== directories.fixture.device) fail('Fixture bin identity differs');
  try {
    await lstat(stateRoot); const state = await privateDirectory(stateRoot, true);
    if (state.device !== directories.fixture.device || seen.has(`${state.device}:${state.inode}`)) fail('Fixture state identity differs');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return { fixture, directories, stateRoot, runtime: paths.runtime, registry: paths.registry,
    launcher: join(fixture, 'bin/arbol-browser'), bundle: join(buildRoot, 'app/ArbolBrowser.app'), build: basename(buildRoot) };
}

export async function assertHostIsolation(buildRoot, stateRoot, output) {
  if (resolve(buildRoot) !== buildRoot || resolve(stateRoot) !== stateRoot || basename(dirname(buildRoot)) !== 'arbol-browser' ||
      !/^[1-9a-f][0-9a-f]{0,15}$/.test(basename(buildRoot))) fail('Invalid isolated Build layout');
  const account = userInfo(), home = await realpath(account.homedir);
  if (!process.geteuid || process.geteuid() !== account.uid) fail('Qualification OS account differs');
  const protectedRoots = [];
  for (const path of protectedLocations(home)) {
    const protectedRoot = await protectedPath(path);
    protectedRoots.push(protectedRoot);
    for (const actual of [buildRoot, stateRoot]) if (inside(actual, protectedRoot) || inside(protectedRoot, actual)) fail('Owner installation/data is not qualification state');
  }
  if (output !== undefined) {
    if (resolve(output) !== output || await protectedPath(output) !== output) fail('Staging output must be physical');
    protectedRoots.push(await realpath(root), buildRoot, stateRoot,
      await protectedPath(join(home, 'Applications', 'Arbol Browser')));
    // A prospective leaf has no inode yet. Conservatively compare spellings
    // that can refer to the same path on macOS volumes that fold case or Unicode.
    const comparable = path => path.normalize('NFC').toLowerCase();
    const candidate = comparable(output);
    for (const path of protectedRoots) {
      const protectedRoot = comparable(path);
      if (inside(candidate, protectedRoot) || inside(protectedRoot, candidate)) fail('Staging output overlaps protected Browser files');
    }
  }
  const maintenance = await maintenanceFixtureLayout(buildRoot, stateRoot);
  for (const path of [dirname(buildRoot), buildRoot, ...(maintenance ? [] : [stateRoot])]) await privateDirectory(path, true);
  if (inside(stateRoot, buildRoot) || inside(buildRoot, stateRoot)) fail('Qualification state overlaps product');
  // One separately prepared disposable state per isolated registry scope. It
  // can survive same-scope compatible Build changes without copying profiles.
  if (!maintenance && stateRoot !== join(dirname(dirname(dirname(buildRoot))), 'browser-state')) fail('State is outside the isolated registry scope');
}
export async function currentHostCompilation() {
  const compiled = await json(join(root, 'dist/compile-record.json'));
  const record = compiled.value, productSources = await productInventory();
  const actualOutputs = { libraryDigest: inventoryDigest(await inventory(join(root, 'dist/lib'))),
    entryDigest: (await exactFile(join(root, 'dist/cli/main.mjs'), 16777216)).sha256,
    hostDigest: (await exactFile(join(root, 'dist/host/main.mjs'), 16777216)).sha256, native: {} };
  for (const name of ['ownership.node', 'platform.node', 'host-bootstrap', 'host-launch', 'watchdog', 'stable-launch'])
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
function strictAdmissionJson(bytes, limit = 65536) {
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

const migrationAdmissionPath = 'sagas/sylvan-stack/arbol-format-2-migration/browser-profile-migration/AFM-9.md';
const migrationAdmissionMarkers = { production: 'AFM-9-RELEASE-SOURCE-ADMISSION', isolated: 'AFM-9-ISOLATED-MIGRATION-SOURCE-ADMISSION' };
function admittedBlock(text, marker) {
  const comments = [...text.matchAll(/<!--[\s\S]*?(?:-->|$)/g)].filter(m => m[0].includes(marker));
  if (!comments.length) return null;
  if (comments.length !== 2 || comments[0][0] !== `<!-- ${marker}:BEGIN -->` || comments[1][0] !== `<!-- ${marker}:END -->`)
    fail('Malformed or duplicate migration admission delimiters');
  return strictAdmissionJson(Buffer.from(text.slice(comments[0].index + comments[0][0].length, comments[1].index).trim()), 8388608);
}
const admissionObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

async function acceptedProduct(commit, compiled, production) {
  const handoverPath = migrationAdmissionPath;
  const marker = production ? migrationAdmissionMarkers.production : migrationAdmissionMarkers.isolated;
  const scope = production ? 'production-candidate' : 'isolated-migration-candidate';
  if (typeof commit !== 'string' || !/^[0-9a-f]{40}$/.test(commit)) fail('Exact published review hand-over commit required');
  if (await realpath(foresterRoot) !== foresterRoot) fail('Nonphysical review repository');
  const git = args => command('/usr/bin/git', ['-C', foresterRoot, ...args]).trim();
  if (git(['rev-parse', '--show-toplevel']) !== foresterRoot ||
      !['git@github.com:sylvan-stack/forester-artifacts.git', 'https://github.com/sylvan-stack/forester-artifacts.git'].includes(git(['remote', 'get-url', 'origin'])))
    fail('Wrong independent hand-over authority');
  git(['merge-base', '--is-ancestor', commit, 'refs/remotes/origin/main']);
  const text = git(['show', `${commit}:${handoverPath}`]);
  const blocks = Object.fromEntries(Object.entries(migrationAdmissionMarkers).map(([role, name]) => [name, admittedBlock(text, name)]));
  for (const [name, block] of Object.entries(blocks)) {
    if (block && (!admissionObject(block) || block.format !== 1 || block.status !== 'accepted' ||
        block.scope !== (name === migrationAdmissionMarkers.production ? 'production-candidate' : 'isolated-migration-candidate')))
      fail('Wrong migration admission role or status');
  }
  const value = blocks[marker];
  if (!value) fail('Exact published AFM-9 source admission is absent');
  if (value.format !== 1 || value.status !== 'accepted' || value.scope !== scope ||
      ![value.productSources, value.productOutputs, value.compilerInputs, value.sourceCheckpoint, value.sourceVerdict].every(admissionObject) ||
      !sha(value.sourceCheckpoint?.sha256) || !sha(value.sourceVerdict?.sha256) ||
      ![value.sourceCheckpoint?.path, value.sourceVerdict?.path].every(path => typeof path === 'string' && path.length <= 4096 && resolve(path) === path) ||
      !Number.isSafeInteger(value.acceptedSourceOrdinal) || value.acceptedSourceOrdinal < 1 ||
      !/^[0-9a-f]{40}$/.test(value.sourceGit) || !sha(value.productDigest) || value.productDigest !== compiled.record.productDigest ||
      canonical(value.productSources) !== canonical(compiled.productSources) ||
      canonical(value.productOutputs) !== canonical(compiled.productOutputs) ||
      canonical(value.compilerInputs) !== canonical(compiled.record.compilerInputs)) fail('Exact independently accepted product identity differs');
  const checkpointFile = await exactFile(value.sourceCheckpoint.path);
  const checkpoint = { ...checkpointFile, value: strictAdmissionJson(checkpointFile.bytes, 1048576) }, verdict = await exactFile(value.sourceVerdict.path);
  if (checkpoint.sha256 !== value.sourceCheckpoint.sha256 || verdict.sha256 !== value.sourceVerdict.sha256 ||
      checkpoint.value.scope !== scope ||
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
export function acceptedHostProduct(commit, compiled) { return acceptedProduct(commit, compiled, false); }
export function acceptedReleaseProduct(commit, compiled) { return acceptedProduct(commit, compiled, true); }
export async function verifyReleaseAllocation(buildRoot, compiled, review) {
  const build = basename(buildRoot), account = userInfo();
  const canonicalRoot = join(account.homedir, ...installation.builds, 'arbol-browser');
  const stateRoot = join(dirname(dirname(dirname(buildRoot))), 'browser-state');
  await assertHostIsolation(buildRoot, stateRoot);
  const reservationRoot = join(canonicalRoot, build);
  await privateDirectory(reservationRoot, true);
  const allocation = await json(join(buildRoot, 'build.json'));
  const proof = await json(join(reservationRoot, 'production-reservation.json'));
  const record = allocation.value, release = record.productionRelease;
  const source = { repository: await realpath(root), branch: compiled.sourceIdentity.branch,
    commit: compiled.sourceIdentity.commit, uncommittedChanges: false };
  if (allocation.identity.uid !== account.uid || allocation.identity.mode !== 0o600 ||
      proof.identity.uid !== account.uid || proof.identity.mode !== 0o600 ||
      record.component !== 'arbol-browser' || record.build !== build || record.status !== 'building' ||
      record.contract !== 1 || record.dataFormat !== 2 ||
      !Array.isArray(record.checks) || record.checks.length || canonical(record.source) !== canonical(source) ||
      release?.review !== review || !/^[0-9a-f]{32}$/.test(release?.reservation) ||
      canonical(proof.value) !== canonical({ format: 1, component: 'arbol-browser', build, folder: buildRoot,
        source, review, reservation: release.reservation })) fail('Production release does not hold its canonical Build allocation');
  return canonical({ allocation: allocation.sha256, proof: proof.sha256 });
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
export function outerPlist(policy) {
  return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${policy.bundleIdentifier}</string><key>CFBundleName</key><string>Arbol Browser</string><key>CFBundleIconFile</key><string>ArbolBrowser.icns</string><key>CFBundleExecutable</key><string>arbol-browser-native</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string><key>LSMinimumSystemVersion</key><string>27.0.1</string><key>LSMultipleInstancesProhibited</key><false/></dict></plist>\n`;
}
export async function refreshMaintenanceFixture(bundle, staged) {
  if (!staged.maintenanceFixture) return null;
  if (staged.purpose !== 'isolated-qualification' || staged.delivery === 'production') fail('Invalid maintenance fixture purpose');
  const actual = await maintenanceFixtureLayout(staged.buildRoot, staged.stateRoot);
  if (!actual || canonical(actual) !== canonical(staged.maintenanceFixture)) fail('Maintenance fixture identity changed');
  const launcher = await exactFile(join(bundle, 'Contents/Resources/browser/native/stable-launch'), 67108864);
  const policy = await exactFile(join(bundle, 'Contents/Resources/host-policy.json'));
  const value = { format: 1, purpose: 'isolated-qualification', ...actual,
    launcherSha256: launcher.sha256, hostPolicySha256: policy.sha256 };
  await writeFile(join(bundle, 'Contents/Resources/maintenance-fixture.json'), JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  if (canonical(await maintenanceFixtureLayout(staged.buildRoot, staged.stateRoot)) !== canonical(actual)) fail('Fixture changed during sealing');
  return value;
}

export async function refreshHostRecords(bundle, staged) {
  const payload = join(bundle, 'Contents/Resources/browser');
  if (staged.component.contract !== 1 || staged.component.profileFormat !== 2) fail('Current host metadata must select profile format2');
  const scope = staged.purpose === 'isolated-qualification' ? 'isolated' : staged.purpose;
  const readerKey = `host-${scope}:1:${staged.productDigest}`;
  const metadata = { format: 1, component: staged.component, runtime: hostRuntime, sourceDigest: staged.sourceDigest,
    sourceIdentity: staged.sourceIdentity, host: { layout: 1, compileDigest: staged.compileDigest, productDigest: staged.productDigest },
    files: await inventory(payload, (await readdir(payload)).filter(name => name !== 'metadata.json')) };
  await writeFile(join(payload, 'metadata.json'), JSON.stringify(metadata, null, 2) + '\n', { mode: 0o600 });
  const nativeABI = (await json(join(root, 'native/expected-inventory.json'))).value;
  const publisher = (await json(join(root, staged.delivery === 'production' ?
    'native/production-publisher-requirement.json' : 'native/publisher-requirement.json'))).value;
  const compatibility = { abi: 1, runtime: hostRuntime, nativeABI, publisherTeam: publisher.team, bundleIdentifier: publisher.bundleIdentifier,
    featureConfiguration: { sitePerProcess: true, disabledFeatures: ['MacAccessibilityTextOperation'], extraChromiumArguments: [] },
    files: Object.fromEntries(Object.entries(await inventory(payload)).map(([path, digest]) => [`Contents/Resources/browser/${path}`, digest])),
    dataEpoch: 1, compatibleReaderKeys: [readerKey, ...predecessorReaderKeys(scope)], writerKey: readerKey, readableDataEpochs: [...readableDataEpochs], qualification: readerKey };
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
  const maintenanceFixture = await refreshMaintenanceFixture(bundle, staged);
  return { metadata, compatibility, policy, maintenanceFixture };
}
/** One new private outer, never an older signed candidate/registered payload.
 * Stage only; the separate signer and allocated-Build adapter own later steps. */
export async function prepareUnsignedHost({ out, buildRoot, stateRoot, runtimeArchive, review, purpose = 'blocked' }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || !['blocked', 'isolated-qualification'].includes(purpose)) fail('Unsupported host preparation');
  await assertHostIsolation(buildRoot, stateRoot);
  const bundle = resolve(out);
  if (bundle !== out || !(basename(bundle) === 'ArbolBrowser.app' || (dirname(bundle) === buildRoot && /^\.host-preparation-[A-Za-z0-9_-]{22}\.app$/.test(basename(bundle)))) || inside(bundle, root) || inside(bundle, stateRoot) || inside(stateRoot, bundle)) fail('Invalid fresh outer destination');
  await privateDirectory(dirname(bundle));
  const maintenanceFixture = await maintenanceFixtureLayout(buildRoot, stateRoot);
  if (maintenanceFixture && purpose !== 'isolated-qualification') fail('Maintenance fixture requires isolated source admission');
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
  await cp(join(root, 'dist/lib'), join(payload, 'lib'), copy);
  await cp(join(root, 'dist/native'), join(payload, 'native'), {
    ...copy, filter: path => Boolean(maintenanceFixture) || path !== join(root, 'dist/native/stable-launch'),
  });
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
  const icon = join(bundle, 'Contents/Resources/ArbolBrowser.icns');
  const dockIcon = join(bundle, 'Contents/Resources/ArbolBrowser.png');
  await cp(join(root, 'src/runtime/ArbolBrowser.icns'), icon, copy);
  command('/usr/bin/sips', ['-z', '256', '256', '-s', 'format', 'png', icon, '--out', dockIcon]);
  await writeExclusive(join(bundle, 'Contents/Resources/publisher-requirement.json'), JSON.stringify(publisher, null, 2) + '\n');
  const staged = { format: 1, kind: 'unsigned-current-host', purpose, buildRoot, stateRoot, maintenanceFixture,
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
export function hostLauncher(payloadRelative = '../app/ArbolBrowser.app/Contents/Resources/browser') {
  if (!['..', '../app/ArbolBrowser.app/Contents/Resources/browser'].includes(payloadRelative)) fail('Invalid fixed launcher');
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

// This isolated adapter creates no production installation policy. ABR-24 owns
// installation/remount after reboot, final image protection/notarization and
// exclusive guarded unmount/pruning before release. Successful volumes remain
// mounted for the real host lifetime; no process or candidate starts here.
const imageKernelScript = String.raw`ObjC.import('Foundation');
ObjC.bindFunction('getpid', ['int', []]);
ObjC.bindFunction('getuid', ['unsigned int', []]);
ObjC.bindFunction('geteuid', ['unsigned int', []]);
ObjC.bindFunction('sysctl', ['int', ['pointer', 'unsigned int', 'pointer', 'pointer', 'pointer', 'unsigned long']]);
function enc(a) {
  const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let s = '';
  for (let i = 0; i < a.length; i += 3) {
    const n = (a[i] << 16) | ((a[i + 1] || 0) << 8) | (a[i + 2] || 0);
    s += c[(n >>> 18) & 63] + c[(n >>> 12) & 63] +
      (i + 1 < a.length ? c[(n >>> 6) & 63] : '=') + (i + 2 < a.length ? c[n & 63] : '=');
  }
  return s;
}
function dec(s) {
  const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let a = [], n = 0, b = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=') break;
    const v = c.indexOf(s[i]);
    if (v < 0) throw Error('non-base64 output');
    n = (n << 6) | v;
    b += 6;
    if (b >= 8) {
      b -= 8;
      a.push((n >>> b) & 255);
    }
  }
  return a;
}
function le(a, o, n) {
  let v = 0;
  for (let i = 0; i < n; i++) v += a[o + i] * Math.pow(256, i);
  return v;
}
function i32(a, o) {
  const v = le(a, o, 4);
  return v > 2147483647 ? v - 4294967296 : v;
}
function bytes(a, mutable) {
  const d = $.NSData.alloc.initWithBase64EncodedStringOptions($(enc(a)), 0);
  return mutable ? d.mutableCopy : d;
}
function run(argv) {
  const cutoff = Date.now() + 30000;
  const ownPid = Number($.getpid()), uid = Number($.getuid()), euid = Number($.geteuid());
  if (argv.length !== 1 || !/^[1-9][0-9]*$/.test(argv[0])) throw Error('one canonical PID input required');
  const pid = Number(argv[0]);
  if (!Number.isSafeInteger(pid) || pid > 2147483647) throw Error('PID range');
  const a = [];
  for (const v of [1, 14, 1, pid]) {
    for (let j = 0; j < 4; j++) a.push((v >>> 8 * j) & 255);
  }
  const mib = bytes(a, false), size = bytes([136, 2, 0, 0, 0, 0, 0, 0], true);
  const out = $.NSMutableData.dataWithLength(648);
  if (Number(mib.length) !== 16 || Number(size.length) !== 8 || Number(out.length) !== 648)
    throw Error('bounded buffer length mismatch');
  const rc = $.sysctl(mib.bytes, 4, out.mutableBytes, size.mutableBytes, null, 0);
  const n = le(dec(ObjC.unwrap(size.base64EncodedStringWithOptions(0))), 0, 8);
  const raw = ObjC.unwrap(out.base64EncodedStringWithOptions(0)), b = dec(raw);
  if (rc !== 0 || n !== 648 || b.length !== 648) throw Error('own PID sysctl refused rc=' + rc + ' length=' + n);
  const parsed = {
    pid: i32(b, 40), effectiveUid: le(b, 420, 4), realUid: le(b, 392, 4),
    startSeconds: le(b, 0, 8), startMicroseconds: i32(b, 8), padding12through15: b.slice(12, 16)
  };
  if (parsed.pid !== pid || parsed.effectiveUid !== euid || parsed.realUid !== uid ||
      parsed.startSeconds <= 0 || parsed.startSeconds > Date.now() / 1000 ||
      parsed.startMicroseconds < 0 || parsed.startMicroseconds >= 1000000) throw Error('own kernel identity/parse mismatch');
  if (Date.now() > cutoff) throw Error('original local cutoff exceeded');
  return JSON.stringify({
    format: 1, complete: true, route: 'stock Apple osascript JXA linked libc numeric-MIB sysctl',
    ownPid: ownPid, targetPid: pid, ownUid: uid, ownEffectiveUid: euid, mib: [1, 14, 1, pid],
    returnCode: rc, capacityBytes: 648, returnedBytes: n, rawBase64: raw, parsed: parsed,
    paddingIsNotMicroseconds: true, localCutoff: cutoff, finishedAt: Date.now(), queries: 1,
    attachments: 0, productionAddonLoaded: false, qualificationCredit: false
  });
}
`;
const imageHelper = '/System/Library/PrivateFrameworks/DiskImages.framework/Versions/A/Resources/diskimages-helper';
const fullStamp = st => canonical([st.dev, st.ino, st.mode, st.uid, st.gid, st.nlink, st.size, st.mtimeNs, st.ctimeNs, st.birthtimeNs].map(String));
async function syncDirectory(path) { const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); try { await fd.sync(); } finally { await fd.close(); } }
const imageStampFields = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs', 'birthtimeNs'];
const stampFields = stamp => Object.fromEntries(imageStampFields.map((name, i) => [name, JSON.parse(stamp)[i]]));
async function imageReceipt(owned, name, value) {
  if (owned.image.length > 4096 || owned.installed.length > 4096 || owned.mount.length > 4096) fail('Owned evidence path bound');
  const bytes = canonical({ format: 1, image: owned.image, mount: owned.mount, installed: owned.installed, ...value }) + '\n';
  if (Buffer.byteLength(bytes) > 16384) fail('Owned evidence record bound');
  await writeExclusive(join(dirname(owned.image), name), bytes);
  await syncDirectory(dirname(owned.image));
}
async function imageOperand(owned, label, expected, current) {
  if (canonical(current) === canonical(expected)) return;
  // Diagnostic failure cannot replace the original fixed-operand refusal.
  try { await imageReceipt(owned, 'identity-refusal.json', { operand: label, expected, current }); } catch {}
  fail(`Owned image/root identity changed: ${label}`);
}
async function constructionImage(owned, afterAttach) {
  const { image, imageFD, originalImageStamp, imageDigest, deadline } = owned;
  const phase = afterAttach ? 'attach-bridge' : 'pre-attach';
  const actual = fullStamp(await imageFD.stat({ bigint: true }));
  await imageOperand(owned, `${phase}-canonical-image`, true, await realpath(image) === image);
  await imageOperand(owned, `${phase}-named-image`, actual, fullStamp(await lstat(image, { bigint: true })));
  const original = stampFields(originalImageStamp), current = stampFields(actual);
  // Only this one documented construction operation may change image ctime.
  for (const field of imageStampFields) {
    if (afterAttach && field === 'ctimeNs') continue;
    await imageOperand(owned, `${phase}-image-${field}`, original[field], current[field]);
  }
  await imageOperand(owned, `${phase}-image-digest`, imageDigest, await imageHash(imageFD, deadline));
  await imageOperand(owned, `${phase}-image-fd-final`, actual, fullStamp(await imageFD.stat({ bigint: true })));
  await imageOperand(owned, `${phase}-image-name-final`, actual, fullStamp(await lstat(image, { bigint: true })));
  await imageOperand(owned, `${phase}-image-canonical-final`, true, await realpath(image) === image);
  await imageReceipt(owned, afterAttach ? 'attachment-bridge.json' : 'attachment-preparation.json', {
    phase, original, current, imageSha256: imageDigest,
    changedFields: imageStampFields.filter(field => original[field] !== current[field]),
    historicalAttempt19OperandAndWriter: 'unknown'
  });
  return actual;
}
function imageCommand(program, args, deadline, input) {
  const remaining = deadline - performance.now();
  if (remaining <= 0) fail('Read-only volume operation cutoff');
  const result = spawnSync(program, args, { input, encoding: 'utf8', timeout: Math.max(1, Math.floor(remaining)),
    maxBuffer: 1048576, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' } });
  if (result.error || result.status !== 0 || performance.now() >= deadline) fail('Read-only volume command refused');
  return result.stdout;
}
function imagePlist(program, args, deadline) {
  return JSON.parse(imageCommand('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', '-'], deadline,
    imageCommand(program, args, deadline)));
}
async function imageContainingVolume(path, fd, deadline) {
  const original = await fd.stat({ bigint: true });
  if (await realpath(path) !== path || fullStamp(await lstat(path, { bigint: true })) !== fullStamp(original))
    fail('Original image path changed before volume discovery');
  const rows = imageCommand('/bin/df', ['-P', path], deadline).trim().split('\n');
  if (rows.length !== 2 || !rows[0].startsWith('Filesystem')) fail('Ambiguous containing volume');
  const fields = rows[1].trim().split(/\s+/), devicePath = fields[0];
  if (fields.length < 6 || !/^\/dev\/disk[0-9]+(?:s[0-9]+)*$/.test(devicePath) ||
      fields.slice(1, 4).some(value => !/^[0-9]+$/.test(value)) || !/^[0-9]+%$/.test(fields[4]))
    fail('Malformed containing volume device');
  const device = await lstat(devicePath, { bigint: true });
  const volume = imagePlist('/usr/sbin/diskutil', ['info', '-plist', devicePath], deadline);
  if (!device.isBlockDevice() || device.rdev !== original.dev || volume.DeviceNode !== devicePath ||
      typeof volume.MountPoint !== 'string' || await realpath(volume.MountPoint) !== volume.MountPoint)
    fail('Containing volume physical device differs');
  const mounted = await lstat(volume.MountPoint, { bigint: true });
  if (!mounted.isDirectory() || mounted.dev !== original.dev || fullStamp(await fd.stat({ bigint: true })) !== fullStamp(original) ||
      fullStamp(await lstat(path, { bigint: true })) !== fullStamp(original) || await realpath(path) !== path)
    fail('Original image containing volume changed');
  return volume;
}
function imageKernel(pid, deadline) {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 2147483647) fail('Invalid image helper locator');
  const value = JSON.parse(imageCommand('/usr/bin/osascript', ['-l', 'JavaScript', '-e', imageKernelScript, String(pid)], deadline));
  if (value.complete !== true || value.targetPid !== pid || value.capacityBytes !== 648 || value.returnedBytes !== 648 ||
      value.returnCode !== 0 || typeof value.rawBase64 !== 'string') fail('Image helper kernel receipt refused');
  const raw = Buffer.from(value.rawBase64, 'base64'), account = userInfo();
  if (raw.length !== 648 || raw.toString('base64') !== value.rawBase64 || raw.readInt32LE(40) !== pid ||
      raw.readUInt32LE(420) !== account.uid || raw.readUInt32LE(392) !== account.uid || raw.readBigInt64LE(0) <= 0n ||
      raw.readBigInt64LE(0) > BigInt(Math.floor(Date.now() / 1000)) || raw.readInt32LE(8) < 0 || raw.readInt32LE(8) >= 1000000)
    fail('Image helper kernel identity refused');
  return canonical([pid, String(raw.readBigInt64LE(0)), raw.readInt32LE(8), account.uid]);
}
async function imageHash(fd, deadline) {
  const before = await fd.stat({ bigint: true }), h = createHash('sha256'), buffer = Buffer.alloc(65536);
  if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > 1073741824n) fail('Unsafe owned image');
  let at = 0;
  for (;;) {
    if (performance.now() >= deadline) fail('Image hashing cutoff');
    const { bytesRead } = await fd.read(buffer, 0, buffer.length, at);
    if (!bytesRead) break;
    h.update(buffer.subarray(0, bytesRead)); at += bytesRead;
    if (BigInt(at) > before.size) fail('Owned image grew');
  }
  if (BigInt(at) !== before.size || fullStamp(await fd.stat({ bigint: true })) !== fullStamp(before)) fail('Owned image changed');
  return h.digest('hex');
}
async function readOnlyImageProof(owned, deadline) {
  const { image, mount, installed, imageFD, mountFD, rootFD, imageStamp, mountStamp, rootStamp, imageDigest, parentIdentity, buildRoot } = owned;
  const account = userInfo(), actualImage = await imageFD.stat({ bigint: true }), actualRoot = await rootFD.stat({ bigint: true });
  const actualMount = await mountFD.stat({ bigint: true });
  await imageOperand(owned, 'closed-application-child', join(buildRoot, 'app/ArbolBrowser.app'), installed);
  await imageOperand(owned, 'closed-mount-root', join(buildRoot, 'app'), mount);
  await imageOperand(owned, 'application-parent', mount, dirname(installed));
  await imageOperand(owned, 'mount-canonical', true, await realpath(mount) === mount);
  await imageOperand(owned, 'mount-fd-full-stamp', mountStamp, fullStamp(actualMount));
  await imageOperand(owned, 'mount-name-full-stamp', mountStamp, fullStamp(await lstat(mount, { bigint: true })));
  await imageOperand(owned, 'mount-directory', true, actualMount.isDirectory());
  await imageOperand(owned, 'mount-owner', String(account.uid), String(actualMount.uid));
  await imageOperand(owned, 'mount-group', String(account.gid), String(actualMount.gid));
  await imageOperand(owned, 'mount-mode', '448', String(actualMount.mode & 0o7777n));
  await imageOperand(owned, 'application-mount-device', String(actualMount.dev), String(actualRoot.dev));
  await imageOperand(owned, 'distinct-mount-application', true, actualMount.dev !== actualRoot.dev || actualMount.ino !== actualRoot.ino);
  await imageOperand(owned, 'image-canonical', true, await realpath(image) === image);
  await imageOperand(owned, 'root-canonical', true, await realpath(installed) === installed);
  await imageOperand(owned, 'image-fd-full-stamp', imageStamp, fullStamp(actualImage));
  await imageOperand(owned, 'image-name-full-stamp', imageStamp, fullStamp(await lstat(image, { bigint: true })));
  await imageOperand(owned, 'image-owner', String(account.uid), String(actualImage.uid));
  await imageOperand(owned, 'image-mode', '384', String(actualImage.mode & 0o7777n));
  await imageOperand(owned, 'root-fd-full-stamp', rootStamp, fullStamp(actualRoot));
  await imageOperand(owned, 'root-name-full-stamp', rootStamp, fullStamp(await lstat(installed, { bigint: true })));
  await imageOperand(owned, 'root-directory', true, actualRoot.isDirectory());
  await imageOperand(owned, 'root-owner', String(account.uid), String(actualRoot.uid));
  await imageOperand(owned, 'root-group', String(account.gid), String(actualRoot.gid));
  await imageOperand(owned, 'root-mode', '448', String(actualRoot.mode & 0o7777n));
  await imageOperand(owned, 'build-parent-identity', parentIdentity, await privateDirectory(buildRoot, true));
  await imageOperand(owned, 'image-byte-digest', imageDigest, await imageHash(imageFD, deadline));
  const select = () => {
    const info = imagePlist('/usr/bin/hdiutil', ['info', '-plist'], deadline);
    if (!Array.isArray(info.images)) fail('Missing image records');
    const matches = info.images.filter(row => row['image-path'] === image);
    if (matches.length !== 1) fail('Ambiguous owned image');
    const row = matches[0];
    if (row.diskimages2 !== false || row['image-type'] !== 'UDIF read-only' || row.writeable !== false ||
        row['image-encrypted'] !== false || row['owner-uid'] !== account.uid || !Array.isArray(row['system-entities']) ||
        Object.keys(row).some(key => /shadow|overlay/i.test(key))) fail('Unsupported owned image');
    const mounted = row['system-entities'].filter(entity => entity['mount-point'] === mount);
    if (mounted.length !== 1 || !/^\/dev\/disk[0-9]+s[0-9]+$/.test(mounted[0]['dev-entry'])) fail('Owned mount mapping refused');
    return { pid: row['hdid-pid'], device: mounted[0]['dev-entry'], image, mount, application: installed, owner: row['owner-uid'],
      entities: row['system-entities'], diskimages2: row.diskimages2, type: row['image-type'], writable: row.writeable };
  };
  const selected = select();
  if (owned.mapping && canonical(selected) !== canonical(owned.mapping)) fail('Original owned mount mapping changed');
  const volume = imagePlist('/usr/sbin/diskutil', ['info', '-plist', selected.device], deadline);
  const device = await lstat(selected.device, { bigint: true });
  if (!device.isBlockDevice() || device.rdev !== actualMount.dev || volume.DeviceNode !== selected.device ||
      volume.MountPoint !== mount || volume.FilesystemType !== 'apfs' || volume.BusProtocol !== 'Disk Image' ||
      volume.Writable !== false || volume.WritableMedia !== false || volume.WritableVolume !== false) fail('Volume is not the owned read-only APFS root');
  const before = imageKernel(selected.pid, deadline), text = await lstat(imageHelper, { bigint: true });
  if (!text.isFile() || text.uid !== 0n || (text.mode & 0o022n) !== 0n || (text.mode & 0o111n) === 0n || await realpath(imageHelper) !== imageHelper) fail('Unsafe Apple helper');
  imageCommand('/usr/bin/codesign', ['--verify', '--strict', '-R=anchor apple', imageHelper], deadline);
  const raw = imageCommand('/usr/sbin/lsof', ['-nP', '-a', '-p', String(selected.pid), '-F0pucfatDin'], deadline);
  const processFields = {}, files = []; let current = processFields;
  for (let field of raw.split('\0')) {
    field = field.replace(/^\n/, ''); if (!field) continue;
    const tag = field[0], value = field.slice(1);
    if (tag === 'f') { current = { f: value }; files.push(current); }
    else { if (!'pucfatDin'.includes(tag) || Object.hasOwn(current, tag)) fail('Malformed helper vnode records'); current[tag] = value; }
  }
  const vnode = (row, st) => /^0x[0-9a-f]+$/i.test(row.D ?? '') && /^(0|[1-9][0-9]*)$/.test(row.i ?? '') &&
    BigInt(row.D) === st.dev && BigInt(row.i) === st.ino;
  const numeric = files.filter(row => /^[0-9]+$/.test(row.f)), regular = numeric.filter(row => row.t === 'REG');
  if (processFields.p !== String(selected.pid) || processFields.u !== String(account.uid) || !processFields.c ||
      new Set(numeric.map(row => row.f)).size !== numeric.length || numeric.some(row => !row.t || !row.a) ||
      !regular.length || regular.some(row => row.a !== 'r' || !vnode(row, actualImage)) ||
      !files.some(row => row.f === 'txt' && row.t === 'REG' && vnode(row, text)) ||
      fullStamp(await lstat(imageHelper, { bigint: true })) !== fullStamp(text) || imageKernel(selected.pid, deadline) !== before ||
      canonical(select()) !== canonical(selected)) fail('Owned helper/backing continuity refused');
  await imageOperand(owned, 'continuity-image-fd-full-stamp', imageStamp, fullStamp(await imageFD.stat({ bigint: true })));
  await imageOperand(owned, 'continuity-image-name-full-stamp', imageStamp, fullStamp(await lstat(image, { bigint: true })));
  await imageOperand(owned, 'continuity-root-fd-full-stamp', rootStamp, fullStamp(await rootFD.stat({ bigint: true })));
  await imageOperand(owned, 'continuity-root-name-full-stamp', rootStamp, fullStamp(await lstat(installed, { bigint: true })));
  await imageOperand(owned, 'continuity-mount-fd-full-stamp', mountStamp, fullStamp(await mountFD.stat({ bigint: true })));
  await imageOperand(owned, 'continuity-mount-name-full-stamp', mountStamp, fullStamp(await lstat(mount, { bigint: true })));
  return selected;
}

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
      record.packageVersion !== pkg.version || record.contract !== 1 || record.dataFormat !== pkg.arbolBrowser.profileFormat || pkg.arbolBrowser.profileFormat !== 2 || !Array.isArray(record.checks) || record.checks.length ||
      !record.source || Object.keys(record.source).sort().join(',') !== 'branch,commit,repository,uncommittedChanges' ||
      record.source.repository !== await realpath(root) || record.source.branch !== compiled.sourceIdentity.branch ||
      record.source.commit !== compiled.sourceIdentity.commit || record.source.uncommittedChanges !== false || compiled.sourceIdentity.uncommittedChanges)
    fail('Allocated Building/source does not match current committed compilation');
  const stateRoot = join(dirname(dirname(dirname(buildRoot))), 'browser-state');
  const account = userInfo(), home = await realpath(account.homedir);
  for (const path of protectedLocations(home)) {
    const protectedRoot = await protectedPath(path);
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
  let log, held, guardIdentity, logIdentity, ownEntry, ownedVolume, published = false, failure, signed, staged;
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
    const mount = join(buildRoot, 'app'), installed = join(mount, 'ArbolBrowser.app');
    const parentIdentity = await privateDirectory(buildRoot, true);
    await assertAllocation();
    const volumeRoot = await mkdtemp(join(buildRoot, '.host-volume-')); await privateDirectory(volumeRoot, true);
    const image = join(volumeRoot, 'host.dmg'), deadline = performance.now() + 120000;
    // One plain source parent contains exactly one fixed application child.
    // The existing bounded copy preserves every original signed root entry.
    const sourceIdentity = await privateDirectory(bundle, true), sourceStamp = fullStamp(source);
    const sourceEntries = (await readdir(bundle)).sort();
    if (!sourceEntries.length || canonical(await inventory(bundle)) !== canonical(signed.files)) fail('Sealed source differs before copying');
    await assertPhysicalCap(bundle);
    const plain = await mkdtemp(join(buildRoot, '.host-image-source-')), plainIdentity = await privateDirectory(plain, true);
    if ((await readdir(plain)).length) fail('Image source is not empty');
    const application = join(plain, 'ArbolBrowser.app'); await mkdir(application, { mode: 0o700 });
    const applicationIdentity = await privateDirectory(application, true);
    if ((await readdir(application)).length) fail('Image application child is not empty');
    await assertAllocation();
    imageCommand('/bin/cp', ['-pR', ...sourceEntries.map(name => join(bundle, name)), application], deadline);
    if (canonical(await privateDirectory(plain, true)) !== canonical(plainIdentity) ||
        canonical((await readdir(plain)).sort()) !== canonical(['ArbolBrowser.app']) ||
        canonical(await privateDirectory(application, true)) !== canonical(applicationIdentity) ||
        canonical((await readdir(application)).sort()) !== canonical(sourceEntries) ||
        canonical(await inventory(application)) !== canonical(signed.files)) fail('Plain image source differs from sealed original');
    await assertPhysicalCap(plain);
    if (canonical(await privateDirectory(bundle, true)) !== canonical(sourceIdentity) ||
        fullStamp(await lstat(bundle, { bigint: true })) !== sourceStamp ||
        canonical((await readdir(bundle)).sort()) !== canonical(sourceEntries) ||
        canonical(await inventory(bundle)) !== canonical(signed.files)) fail('Sealed source changed while copying');
    await assertAllocation();
    imageCommand('/usr/bin/hdiutil', ['create', '-fs', 'APFS', '-srcfolder', plain, '-volname', 'ArbolBrowser',
      '-uid', String(account.uid), '-gid', String(account.gid), '-mode', '0700', '-format', 'UDRO', '-plist', image], deadline);
    await assertAllocation(); await chmod(image, 0o600);
    const imageFD = await open(image, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    ownedVolume = { image, mount, installed, imageFD, buildRoot, parentIdentity, deadline };
    ownedVolume.originalImageStamp = fullStamp(await imageFD.stat({ bigint: true }));
    ownedVolume.imageDigest = await imageHash(imageFD, deadline);
    const imageHost = await imageContainingVolume(image, imageFD, deadline);
    if (imageHost.Internal !== true || !['Apple Fabric', 'PCI-Express', 'SATA', 'NVMe'].includes(imageHost.BusProtocol))
      fail('Image backing is not an ordinary internal filesystem');
    if (canonical(await inventory(bundle)) !== canonical(signed.files) ||
        (await lstat(bundle, { bigint: true })).ino !== source.ino) fail('Sealed source changed before attachment');
    const mountpoint = await mkdtemp(join(buildRoot, '.host-mount-'));
    if ((await readdir(mountpoint)).length) fail('Mountpoint is not empty');
    await assertAllocation(); support.publishDirectory(mountpoint, mount); await syncDirectory(buildRoot); await assertAllocation();
    // Non-kernel mode provides the actual userspace helper/backing-vnode proof.
    await constructionImage(ownedVolume, false);
    ownedVolume.attachmentAttempted = true;
    imagePlist('/usr/bin/hdiutil', ['attach', image, '-readonly', '-nokernel', '-mountpoint', mount, '-noautoopen', '-plist'], deadline);
    // Seal once after construction; every subsequent full-stamp check includes ctime.
    ownedVolume.imageStamp = await constructionImage(ownedVolume, true);
    await assertAllocation();
    ownedVolume.mountFD = await open(mount, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    ownedVolume.mountStamp = fullStamp(await ownedVolume.mountFD.stat({ bigint: true }));
    ownedVolume.rootFD = await open(installed, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    ownedVolume.rootStamp = fullStamp(await ownedVolume.rootFD.stat({ bigint: true }));
    ownedVolume.mapping = await readOnlyImageProof(ownedVolume, deadline);
    if (canonical(await inventory(installed)) !== canonical(signed.files)) fail('Mounted outer differs from sealed original');
    command('/usr/bin/codesign', ['--verify', '--strict', '--deep', '-R', `=anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and identifier "com.sylvan-stack.arbol-browser.native-candidate"`, installed]);
    const payload = join(installed, 'Contents/Resources/browser');
    const metadata = await json(join(payload, 'metadata.json')), policy = await json(join(installed, 'Contents/Resources/host-policy.json'));
    if (metadata.value.component.build !== build || metadata.value.sourceDigest !== compiled.record.sourceDigest ||
        policy.value.buildRoot !== buildRoot || policy.value.stateRoot !== stateRoot || policy.value.reviewDigest !== signed.reviewDigest ||
        policy.value.productDigest !== compiled.record.productDigest) fail('Installed Build metadata differs');
    await assertPhysicalCap(installed); await assertPhysicalCap(payload); await assertAllocation();
    await readOnlyImageProof(ownedVolume, ownedVolume.deadline);
    await writeExclusive(join(dirname(ownedVolume.image), 'mount-provenance.json'), canonical({ format: 1,
      image: ownedVolume.image, imageStamp: ownedVolume.imageStamp, imageSha256: ownedVolume.imageDigest,
      mount: ownedVolume.mount, application: ownedVolume.installed, mountStamp: ownedVolume.mountStamp,
      rootStamp: ownedVolume.rootStamp, mapping: ownedVolume.mapping, parentIdentity: ownedVolume.parentIdentity,
      productionLifecycle: 'ABR-24 installation/remount/protection/notarization/exclusive-unmount-prune required' }) + '\n');
    await syncDirectory(dirname(ownedVolume.image)); await assertAllocation();
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
    await assertAllocation(); await readOnlyImageProof(ownedVolume, ownedVolume.deadline);
  } catch (error) { failure = error; }
  // Withdraw our own entry while the original shared guard still holds.
  // Never force detach, delete an image, or claim success for uncertain cleanup.
  if (failure) {
    try {
      await assertAllocation(); await withdrawOwnEntry();
      if (ownedVolume?.mapping && ownedVolume.rootFD && ownedVolume.mountFD) {
        const deadline = performance.now() + 120000;
        await readOnlyImageProof(ownedVolume, deadline); await assertAllocation();
        await ownedVolume.rootFD.close(); ownedVolume.rootFD = undefined;
        await ownedVolume.mountFD.close(); ownedVolume.mountFD = undefined;
        // No product child has been launched by this adapter, the CLI entry is
        // withdrawn and the original allocation/guard remains held. Busy mounts
        // refuse ordinary detach and remain as diagnostic artifacts.
        imageCommand('/usr/bin/hdiutil', ['detach', ownedVolume.mapping.device], deadline);
      } else if (ownedVolume?.attachmentAttempted) fail('Attachment cleanup identity uncertain; artifacts retained');
    } catch (cleanup) { failure = new Error('Owned read-only volume cleanup uncertain; artifacts retained', { cause: failure }); }
  }
  try { await ownedVolume?.rootFD?.close(); } catch (error) { failure ??= error; }
  try { await ownedVolume?.mountFD?.close(); } catch (error) { failure ??= error; }
  try { await ownedVolume?.imageFD?.close(); } catch (error) { failure ??= error; }
  // A failure closing a description also withdraws only this writer's entry.
  try { if (failure) { await assertAllocation(); await withdrawOwnEntry(); } } catch (error) { failure ??= error; }
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
