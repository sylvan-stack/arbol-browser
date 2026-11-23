/** Fixed, read-only AFM-9 delivery and signed cohort authentication. No import
 * performs I/O. A delivery declaration is necessary, never signed authority. */
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants, fstatSync } from 'node:fs';
import { lstat, open, readdir, readlink, realpath } from 'node:fs/promises';
import { release as kernelRelease, userInfo } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { root } from './package-base.mjs';
import { acceptedHostProduct, acceptedReleaseProduct, canonical, currentHostCompilation, hash } from './package-host.mjs';
import { verifyIsolatedRelease, withIsolatedVerificationDeadline } from './isolated-release.mjs';

export const qualificationDirectory = '/Users/msix/Builds/afm9-rollback-plan.49cXVsFk';
export const qualificationFixture = join(qualificationDirectory, 'qualification/fixture');
const producerRoot = join(qualificationDirectory, 'delivery/browser-producer');
const toolRoot = join(qualificationDirectory, 'delivery/bin');
const authorityPath = join(qualificationDirectory, 'qualification/authority.json');
const forester = '/Users/msix/Artifacts/forester';
const arbol = '/Users/msix/repos/sylvan-stack/arbol';
const plan = 'sagas/sylvan-stack/arbol-format-2-migration/browser-profile-migration/AFM-9.md';
const node = '/Users/msix/.nvm/versions/node/v24.22.1/bin/node';
const nodeSha = '6f32069480ec14d52b6d7b1f3c7124cfbbc46203abf5ddf5c65b127435f3f329';
const sourceFiles = ['README.md', 'baseline.json', 'prepare.py', 'install.py', 'common.patch', 'browser_qualification.py'];
export const qualificationRoles = Object.freeze(['historical', 'A', 'B', 'C']);
export const qualificationSha = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const commit = value => typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
const equal = (a, b) => canonical(a) === canonical(b);
export function qualificationRequire(ok, message = 'Fixed qualification authority differs', exitCode = 3) {
  if (!ok) throw Object.assign(new Error(message), { exitCode });
}
export function qualificationKeys(value, names) {
  qualificationRequire(value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join('\0') === [...names].sort().join('\0'), 'Invalid qualification grammar', 2);
}

/** Reject duplicate decoded keys before parsing, integer spelling drift and
 * unpaired surrogates. Maps use null prototypes until the final JSON parse. */
export function qualificationJson(bytes, limit = 16384) {
  const bad = () => qualificationRequire(false, 'Invalid bounded qualification JSON', 2);
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > limit || bytes.includes(0) ||
      bytes.subarray(0, 3).equals(Buffer.from([239, 187, 191]))) bad();
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { bad(); }
  let at = 0;
  const space = () => { while (at < text.length && /[\x20\x09\x0a\x0d]/.test(text[at])) at++; };
  const string = () => {
    if (text[at++] !== '"') bad();
    const start = at - 1;
    while (at < text.length) {
      const ch = text[at++];
      if (ch === '"') {
        let value; try { value = JSON.parse(text.slice(start, at)); } catch { bad(); }
        if (value.includes('\0') || !value.isWellFormed()) bad();
        return value;
      }
      if (ch === '\\') at++;
      else if (ch.charCodeAt(0) < 32) bad();
    }
    bad();
  };
  const value = depth => {
    if (depth > 16) bad();
    space();
    if (text[at] === '"') { string(); return; }
    if (text[at] === '{') {
      at++; space(); const names = new Set();
      if (text[at] === '}') { at++; return; }
      for (;;) {
        space(); const name = string(); if (names.has(name)) bad(); names.add(name);
        space(); if (text[at++] !== ':') bad(); value(depth + 1); space();
        const end = text[at++]; if (end === '}') return; if (end !== ',') bad();
      }
    }
    if (text[at] === '[') {
      at++; space(); if (text[at] === ']') { at++; return; }
      for (;;) { value(depth + 1); space(); const end = text[at++]; if (end === ']') return; if (end !== ',') bad(); }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*))/.exec(text.slice(at));
    if (!token || /^-?\d/.test(token[0]) && !Number.isSafeInteger(Number(token[0]))) bad();
    at += token[0].length;
  };
  value(0); space(); if (at !== text.length) bad();
  try { return JSON.parse(text); } catch { bad(); }
}

export function qualificationPath(path) {
  qualificationRequire(typeof path === 'string' && Buffer.byteLength(path) <= 1024 && path.startsWith('/') &&
    resolve(path) === path && path.normalize('NFC') === path && !path.includes('\0'), 'Noncanonical qualification path', 2);
  return path;
}
const stamp = info => [info.dev, info.ino, info.uid, info.mode, info.nlink, info.size, info.mtimeNs, info.ctimeNs].join(':');
export const qualificationIdentity = info => ({ device: String(info.dev), inode: String(info.ino),
  uid: Number(info.uid), mode: Number(info.mode & 0o7777n) });
async function ancestors(path) {
  qualificationPath(path);
  qualificationRequire(await realpath(path) === path);
  const parents = []; for (let current = path;; current = dirname(current)) { parents.unshift(current); if (current === '/') break; }
  for (const current of parents) {
    const info = await lstat(current, { bigint: true });
    qualificationRequire(info.isDirectory() && [0n, BigInt(userInfo().uid)].includes(info.uid) && !(info.mode & 0o022n));
  }
}
/** Read one original descriptor, streaming large images and retaining no
 * authorization. Empty files in a sealed dependency tree are legitimate. */
export async function qualificationFile(path, maximum, mode, bytes = false, deadline = Infinity) {
  qualificationRequire(performance.now() < deadline, 'Qualification read deadline exceeded');
  qualificationPath(path); await ancestors(dirname(path));
  qualificationRequire(await realpath(path) === path);
  const parent = await lstat(dirname(path), { bigint: true });
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await fd.stat({ bigint: true });
    qualificationRequire(info.isFile() && info.nlink === 1n && info.size >= 0n && info.size <= BigInt(maximum) &&
      [0n, BigInt(userInfo().uid)].includes(info.uid) && !(info.mode & 0o022n) &&
      (mode === undefined || (info.mode & 0o7777n) === BigInt(mode)) && stamp(info) === stamp(await lstat(path, { bigint: true })));
    const digest = createHash('sha256'), chunks = []; let count = 0;
    const buffer = Buffer.alloc(1024 * 1024);
    for (;;) {
      qualificationRequire(performance.now() < deadline, 'Qualification read deadline exceeded');
      const { bytesRead } = await fd.read(buffer, 0, buffer.length, null); if (!bytesRead) break;
      count += bytesRead; qualificationRequire(count <= maximum && BigInt(count) <= info.size);
      digest.update(buffer.subarray(0, bytesRead)); if (bytes) chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    const afterParent = await lstat(dirname(path), { bigint: true });
    qualificationRequire(BigInt(count) === info.size && stamp(info) === stamp(await fd.stat({ bigint: true })) &&
      stamp(info) === stamp(await lstat(path, { bigint: true })) && parent.dev === afterParent.dev && parent.ino === afterParent.ino &&
      await realpath(path) === path);
    const reference = { path, identity: qualificationIdentity(info), size: String(info.size), sha256: digest.digest('hex') };
    return bytes ? { reference, bytes: Buffer.concat(chunks) } : reference;
  } finally { await fd.close(); }
}
async function checkReference(ref, path, maximum, mode, deadline = Infinity) {
  qualificationKeys(ref, ['path', 'identity', 'size', 'sha256']);
  qualificationRequire(equal(ref, await qualificationFile(path, maximum, mode, false, deadline)), 'Pinned qualification file changed');
}
async function document(path, limit, mode) {
  const file = await qualificationFile(path, limit, mode, true);
  return { ...file, value: qualificationJson(file.bytes, limit) };
}
async function tree(directory, deadline) {
  await ancestors(directory); const result = Object.create(null); let count = 0;
  async function walk(parent) {
    const before = await lstat(parent, { bigint: true }), names = (await readdir(parent)).sort();
    for (const name of names) {
      qualificationRequire(performance.now() < deadline, 'Qualification verification deadline exceeded');
      const path = join(parent, name), key = relative(directory, path), info = await lstat(path, { bigint: true });
      qualificationRequire(++count <= 65536 && Buffer.byteLength(key) <= 512 && key.normalize('NFC') === key &&
        [0n, BigInt(userInfo().uid)].includes(info.uid));
      if (info.isSymbolicLink()) {
        const target = await realpath(path); qualificationRequire(target.startsWith(directory + '/'));
        result[key] = { kind: 'link', target: await readlink(path) };
      } else if (info.isDirectory()) {
        qualificationRequire(!(info.mode & 0o022n)); result[key] = { kind: 'directory', mode: Number(info.mode & 0o7777n) };
        await walk(path);
      } else {
        const ref = await qualificationFile(path, 1073741824, undefined, false, deadline);
        result[key] = { kind: 'file', mode: ref.identity.mode, sha256: ref.sha256 };
      }
      qualificationRequire(stamp(info) === stamp(await lstat(path, { bigint: true })));
    }
    qualificationRequire(stamp(before) === stamp(await lstat(parent, { bigint: true })) && equal(names, (await readdir(parent)).sort()));
  }
  await walk(directory); return result;
}
function command(program, args, deadline, maximum = 16 * 1024 * 1024) {
  const remaining = Math.floor(deadline - performance.now()); qualificationRequire(remaining > 0, 'Qualification verification deadline exceeded');
  const result = spawnSync(program, args, { cwd: producerRoot, encoding: 'buffer', timeout: Math.min(120000, remaining),
    maxBuffer: maximum, env: { PATH: '/usr/bin:/bin', HOME: '/Users/msix', LANG: 'C.UTF-8', GIT_OPTIONAL_LOCKS: '0' } });
  qualificationRequire(!result.error && result.status === 0 && result.stderr.length <= 4096, 'Pinned qualification child refused');
  return result.stdout;
}
function git(repo, args, deadline) { return command('/usr/bin/git', ['--no-replace-objects', '-C', repo, ...args], deadline); }
/** Original compiler/role validators run in a fixed read-only child so their
 * nested synchronous OS commands cannot overrun this operation's deadline.
 * No eval/import/path/compiled object is accepted over this internal pipe. */
export async function boundedQualificationCompilation(isolated, production, deadline) {
  qualificationRequire(commit(isolated) && (production === null || commit(production)) && performance.now() < deadline);
  const child = spawn(node, [join(producerRoot, 'scripts/qualification-authority.mjs'), 'qualification-compile-v1'], {
    cwd: producerRoot, detached: true, stdio: ['pipe', 'pipe', 'pipe'],
    env: { PATH: '/usr/bin:/bin', HOME: '/Users/msix', LANG: 'C.UTF-8', GIT_OPTIONAL_LOCKS: '0' } });
  const output = []; let outputSize = 0, errorSize = 0, failed = false, settled = false;
  const kill = () => { failed = true; if (!settled && child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Still require observed child close below. */ } } };
  const timer = setTimeout(kill, Math.max(1, deadline - performance.now()));
  child.stdout.on('data', bytes => { outputSize += bytes.length; if (outputSize > 1048576) kill(); else output.push(bytes); });
  child.stderr.on('data', bytes => { errorSize += bytes.length; if (errorSize > 4096) kill(); });
  child.stdin.on('error', kill);
  const stopped = new Promise(resolve => { child.once('error', () => { failed = true; }); child.once('close', code => { settled = true; resolve(code); }); });
  child.stdin.end(JSON.stringify({ schema: 1, action: 'compile', isolated, production }) + '\n');
  let code; try { code = await stopped; } finally { clearTimeout(timer); }
  qualificationRequire(!failed && code === 0 && performance.now() < deadline, 'Original compiler/role child refused or exceeded deadline');
  const value = qualificationJson(Buffer.concat(output), 1048576);
  qualificationKeys(value, ['compiled', 'isolated', 'production']); return value;
}
function published(marker, deadline, at) {
  const tip = at ?? git(forester, ['rev-parse', 'refs/remotes/origin/main'], deadline).toString('utf8').trim();
  qualificationRequire(commit(tip));
  const text = git(forester, ['show', `${tip}:${plan}`], deadline).toString('utf8');
  const begin = `<!-- ${marker}:BEGIN -->`, end = `<!-- ${marker}:END -->`;
  qualificationRequire(text.split(begin).length === 2 && text.split(end).length === 2 && text.indexOf(begin) < text.indexOf(end),
    'Missing exact published qualification declaration');
  return { value: qualificationJson(Buffer.from(text.split(begin)[1].split(end)[0].trim()), 16 * 1024 * 1024), tip };
}
async function delivery(deadline) {
  qualificationRequire(root === producerRoot && process.cwd() === producerRoot && await realpath(root) === producerRoot &&
    process.execPath === node && !process.execArgv.length && !Object.keys(process.env).some(key => key.startsWith('NODE_')),
    'Qualification requires the fixed physical producer and Node');
  for (const [repository, urls] of [[forester, ['git@github.com:sylvan-stack/forester-artifacts.git', 'https://github.com/sylvan-stack/forester-artifacts.git']],
    [arbol, ['git@github.com:sylvan-stack/arbol.git', 'https://github.com/sylvan-stack/arbol.git']],
    [producerRoot, ['git@github.com:sylvan-stack/arbol-browser.git', 'https://github.com/sylvan-stack/arbol-browser.git']]]) {
    await ancestors(repository);
    qualificationRequire(git(repository, ['rev-parse', '--show-toplevel'], deadline).toString().trim() === repository &&
      urls.includes(git(repository, ['remote', 'get-url', 'origin'], deadline).toString().trim()));
  }
  const source = published('AFM-9-QUALIFICATION-SOURCE-DELIVERY', deadline), grant = source.value;
  qualificationKeys(grant, ['schema', 'status', 'scope', 'sourceGit', 'sourceFiles', 'sourceCheckpoint', 'sourceVerdict', 'producerManifestSha256', 'bootstrap']);
  qualificationRequire(grant.schema === 1 && grant.status === 'accepted' && grant.scope === 'isolated-tool-source' && commit(grant.sourceGit) && qualificationSha(grant.producerManifestSha256));
  qualificationKeys(grant.sourceFiles, sourceFiles); qualificationKeys(grant.bootstrap, ['python', 'uv']);
  git(arbol, ['merge-base', '--is-ancestor', grant.sourceGit, 'refs/remotes/origin/main'], deadline);
  for (const name of sourceFiles) qualificationRequire(qualificationSha(grant.sourceFiles[name]) &&
    hash(git(arbol, ['show', `${grant.sourceGit}:tools/browser_rollback_qualification/${name}`], deadline)) === grant.sourceFiles[name]);
  for (const field of ['sourceCheckpoint', 'sourceVerdict']) {
    qualificationRequire(qualificationPath(grant[field]?.path).startsWith('/Users/msix/Builds/'));
    await checkReference(grant[field], grant[field].path, 16 * 1024 * 1024);
  }
  for (const ref of Object.values(grant.bootstrap)) {
    await checkReference(ref, qualificationPath(ref.path), 256 * 1024 * 1024);
    qualificationRequire(ref.identity.mode & 0o111);
  }
  const manifest = await document(join(qualificationDirectory, 'delivery/producer-manifest.json'), 16 * 1024 * 1024, 0o600);
  qualificationRequire(manifest.reference.sha256 === grant.producerManifestSha256);
  const producer = manifest.value;
  qualificationKeys(producer, ['schema', 'kind', 'sourceGit', 'files', 'compileRecord', 'productSources', 'productOutputs', 'compilerInputs', 'roleReviews', 'executables', 'osVersion']);
  qualificationRequire(producer.schema === 1 && producer.kind === 'afm9-browser-producer' && commit(producer.sourceGit));
  qualificationKeys(producer.executables, ['node', 'codesign', 'hdiutil', 'diskutil', 'plutil', 'git']);
  for (const [name, path] of Object.entries({ node, codesign: '/usr/bin/codesign', hdiutil: '/usr/bin/hdiutil', diskutil: '/usr/sbin/diskutil', plutil: '/usr/bin/plutil', git: '/usr/bin/git' })) {
    await checkReference(producer.executables[name], path, 256 * 1024 * 1024); qualificationRequire(producer.executables[name].identity.mode & 0o111);
  }
  qualificationRequire(producer.executables.node.sha256 === nodeSha && equal(producer.osVersion,
    { macOS: command('/usr/bin/sw_vers', ['-productVersion'], deadline).toString().trim(), kernel: kernelRelease(), machine: process.arch === 'arm64' ? 'arm64' : process.arch }));
  qualificationRequire(equal(producer.files, await tree(producerRoot, deadline)), 'Complete producer tree changed');
  await checkReference(producer.compileRecord, join(producerRoot, 'dist/compile-record.json'), 8 * 1024 * 1024);
  qualificationKeys(producer.roleReviews, ['production', 'isolated']);
  const { compiled } = await boundedQualificationCompilation(producer.roleReviews.isolated, producer.roleReviews.production, deadline);
  qualificationRequire(compiled.sourceIdentity.commit === producer.sourceGit && equal(producer.productSources, compiled.productSources) &&
    equal(producer.productOutputs, compiled.productOutputs) && equal(producer.compilerInputs, compiled.record.compilerInputs));
  git(producerRoot, ['merge-base', '--is-ancestor', producer.sourceGit, 'refs/remotes/origin/main'], deadline);
  const runtime = published('AFM-9-QUALIFICATION-RUNTIME-DELIVERY', deadline), environment = runtime.value;
  qualificationKeys(environment, ['schema', 'status', 'scope', 'sourceReview', 'toolManifestSha256', 'producerManifestSha256']);
  qualificationRequire(environment.schema === 1 && environment.status === 'accepted' && environment.scope === 'isolated-tool-runtime' &&
    commit(environment.sourceReview) && qualificationSha(environment.toolManifestSha256) && environment.producerManifestSha256 === manifest.reference.sha256);
  git(forester, ['merge-base', '--is-ancestor', environment.sourceReview, runtime.tip], deadline);
  qualificationRequire(equal(published('AFM-9-QUALIFICATION-SOURCE-DELIVERY', deadline, environment.sourceReview).value, grant));
  const toolFile = await document(join(qualificationDirectory, 'delivery/tool-manifest.json'), 16 * 1024 * 1024, 0o600), tool = toolFile.value;
  qualificationRequire(toolFile.reference.sha256 === environment.toolManifestSha256);
  qualificationKeys(tool, ['schema', 'kind', 'sourceGit', 'sourceFiles', 'files', 'executables', 'pythonArchiveSha256']);
  qualificationRequire(tool.schema === 1 && tool.kind === 'afm9-browser-private-tool' && tool.sourceGit === grant.sourceGit &&
    equal(tool.sourceFiles, grant.sourceFiles) && tool.pythonArchiveSha256 === 'd15291f940cfecd2e54010d5e37d2e03aa192f076a65d26ab741372fff2dabfe' &&
    equal(tool.files, await tree(toolRoot, deadline)));
  qualificationKeys(tool.executables, ['python', 'launcher']);
  await checkReference(tool.executables.python, join(toolRoot, '.arbol-builds/runtime/3.14.8-d15291f940cf/python/bin/python3.14'), 256 * 1024 * 1024);
  await checkReference(tool.executables.launcher, join(toolRoot, 'arbol-builds'), 1024 * 1024, 0o755);
  return { manifest: manifest.reference, toolManifest: toolFile.reference, source, runtime, compiled };
}

/** This is called only by fixed trusted entries, never with a caller context or
 * verifier callback. All four real releases are authenticated afresh. */
export async function authenticateQualification(authoritySha256) {
  qualificationRequire(qualificationSha(authoritySha256), 'Invalid authority digest', 2);
  // Two minutes remain for bounded owned-image cleanup before the shared
  // parent's ten-minute hard deadline. Successful work must finish in eight.
  const deadline = performance.now() + 480000, pinned = await delivery(deadline);
  const authority = await document(authorityPath, 16384, 0o600), value = authority.value;
  qualificationRequire(authority.reference.sha256 === authoritySha256);
  qualificationKeys(value, ['schema', 'kind', 'releases']); qualificationKeys(value.releases, qualificationRoles);
  qualificationRequire(value.schema === 1 && value.kind === 'afm9-browser-rollback-qualification');
  const originals = Object.create(null), views = Object.create(null), identities = new Set(), builds = new Set();
  await withIsolatedVerificationDeadline(deadline, async () => {
    for (const role of qualificationRoles) {
      const input = value.releases[role], directory = join(qualificationDirectory, 'qualification/artifacts', role);
      qualificationKeys(input, ['image', 'signedReceipt', 'review']);
      qualificationRequire(input.image === join(directory, 'ArbolBrowser.dmg') && input.signedReceipt === join(directory, 'signed-release.json') && commit(input.review));
      const image = await qualificationFile(input.image, 1073741824, 0o600, false, deadline), signedReceipt = await qualificationFile(input.signedReceipt, 8388608, 0o600, false, deadline);
      for (const file of [image, signedReceipt]) {
        const id = `${file.identity.device}:${file.identity.inode}`; qualificationRequire(!identities.has(id)); identities.add(id);
      }
      const release = await verifyIsolatedRelease({ image: input.image, signedReceiptPath: input.signedReceipt, review: input.review });
      qualificationRequire(release.fixture.fixture === qualificationFixture && !builds.has(release.build) &&
        release.imageSha256 === image.sha256 && release.receiptSha256 === signedReceipt.sha256 &&
        release.profileFormat === (role === 'historical' ? 1 : 2)); builds.add(release.build);
      originals[role] = { input, release };
      views[role] = { role, build: release.build, source: release.source, sourceDigest: release.sourceDigest, productDigest: release.productDigest,
        payloadDigest: release.payloadDigest, profileFormat: release.profileFormat, review: input.review, reviewDigest: release.reviewDigest,
        signedReceipt, image, launcherSha256: release.launcher.sha256,
        launcherRole: role === 'historical' ? 'historical-launcher' : 'isolated-maintenance-launcher', liveMode: release.launcherMode };
      await checkReference(image, image.path, 1073741824, 0o600, deadline); await checkReference(signedReceipt, signedReceipt.path, 8388608, 0o600, deadline);
    }
  });
  qualificationRequire(views.historical.build === '1' && BigInt('0x' + views.A.build) > 1n &&
    BigInt('0x' + views.B.build) > BigInt('0x' + views.A.build) && BigInt('0x' + views.C.build) > BigInt('0x' + views.B.build) &&
    views.A.source !== views.B.source && views.C.source !== views.B.source);
  const directories = Object.create(null), directoryIds = new Set();
  const directoryPaths = { fixture: qualificationFixture, support: join(qualificationFixture, 'support'),
    registry: join(qualificationFixture, 'arbol-browser'), uses: join(qualificationFixture, 'arbol-browser/.uses'), runtime: join(qualificationFixture, 'runtime'),
    stateParent: join(qualificationFixture, 'state'), bin: join(qualificationFixture, 'bin') };
  for (const [name, path] of Object.entries(directoryPaths)) {
    await ancestors(path); const info = await lstat(path, { bigint: true });
    const id = `${info.dev}:${info.ino}`;
    qualificationRequire(info.uid === BigInt(userInfo().uid) && (info.mode & 0o7777n) === 0o700n && !directoryIds.has(id) &&
      (name === 'fixture' || String(info.dev) === directories.fixture.device));
    directoryIds.add(id); directories[name] = qualificationIdentity(info);
  }
  const { bin, ...signedDirectories } = directories;
  for (const original of Object.values(originals)) qualificationRequire(equal(original.release.fixture.directories, signedDirectories));
  const repeated = await delivery(deadline);
  qualificationRequire(equal(pinned.manifest, repeated.manifest) && equal(pinned.toolManifest, repeated.toolManifest) &&
    equal(pinned.source, repeated.source) && equal(pinned.runtime, repeated.runtime) && performance.now() < deadline);
  await checkReference(authority.reference, authorityPath, 16384, 0o600);
  for (const view of Object.values(views)) {
    await checkReference(view.image, view.image.path, 1073741824, 0o600, deadline); await checkReference(view.signedReceipt, view.signedReceipt.path, 8388608, 0o600, deadline);
  }
  for (const [name, path] of Object.entries(directoryPaths)) {
    await ancestors(path); qualificationRequire(equal(directories[name], qualificationIdentity(await lstat(path, { bigint: true }))));
  }
  qualificationRequire(performance.now() < deadline, 'Qualification verification deadline exceeded');
  return { originals, observation: { schema: 1, authoritySha256, producerManifestSha256: pinned.manifest.sha256,
    fixture: { root: qualificationFixture, directories }, releases: views } };
}

export async function qualificationInput(names, internalCompilerPipe = false) {
  const pipe = fstatSync(0);
  qualificationRequire(pipe.uid === userInfo().uid && ((pipe.isFIFO() && !(pipe.mode & 0o077)) ||
    (internalCompilerPipe && pipe.isSocket())), 'Missing private request pipe', 2);
  const chunks = []; let size = 0;
  const timer = setTimeout(() => process.stdin.destroy(new Error('Qualification request deadline exceeded')), 120000);
  try {
    for await (const chunk of process.stdin) { size += chunk.length; qualificationRequire(size <= 16384, 'Qualification request too large', 2); chunks.push(chunk); }
  } finally { clearTimeout(timer); }
  const bytes = Buffer.concat(chunks), value = qualificationJson(bytes); qualificationKeys(value, names);
  return { bytes, value };
}
export function qualificationOutput(value) {
  const bytes = Buffer.from(JSON.stringify(value) + '\n'); qualificationRequire(bytes.length <= 65536, 'Qualification output bound exceeded');
  process.stdout.write(bytes);
}
export function qualificationFailure(error) {
  process.stderr.write('Fixed qualification operation refused; preserve its original evidence.\n');
  process.exitCode = [2, 3, 4, 5].includes(error.exitCode) ? error.exitCode : 3;
}

// This internal child reports only the original read-only validators. It has
// no signing, fixture, installation, native-result or caller-selected import.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    qualificationRequire(root === producerRoot && process.cwd() === producerRoot && process.execPath === node &&
      !process.execArgv.length && !Object.keys(process.env).some(key => key.startsWith('NODE_')) &&
      process.argv.length === 3 && process.argv[2] === 'qualification-compile-v1', 'Invalid compiler child', 2);
    // Node's private stdio pair may be an unnamed socket. Only this read-only
    // internal child accepts it; all externally documented entries require FIFO.
    const { value } = await qualificationInput(['schema', 'action', 'isolated', 'production'], true);
    qualificationRequire(value.schema === 1 && value.action === 'compile' && commit(value.isolated) && (value.production === null || commit(value.production)), 'Invalid compiler request', 2);
    const compiled = await currentHostCompilation(), isolated = await acceptedHostProduct(value.isolated, compiled);
    const production = value.production === null ? null : await acceptedReleaseProduct(value.production, compiled);
    const bytes = Buffer.from(JSON.stringify({ compiled, isolated, production }) + '\n');
    qualificationRequire(bytes.length <= 1048576); process.stdout.write(bytes);
  } catch (error) { qualificationFailure(error); }
}
