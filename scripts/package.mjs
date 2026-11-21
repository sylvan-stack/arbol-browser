import { createHash, randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readdir, realpath, rm, unlink, writeFile } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventory, inventoryDigest, root } from './package-base.mjs';
import {
  acceptedReleaseProduct, assertHostIsolation, assertPhysicalCap, canonical, command, currentHostCompilation,
  exactFile, json, outerPlist, prepareUnsignedHost, preservedStockArchive, privateDirectory, refreshHostRecords,
  verifyReleaseAllocation, writeExclusive,
} from './package-host.mjs';
import { signBundle } from './sign.mjs';
import installation from '../src/runtime/installation-paths.json' with { type: 'json' };
import publisher from '../native/production-publisher-requirement.json' with { type: 'json' };

const payloadPath = 'Contents/Resources/browser';
const launcherPath = `${payloadPath}/native/stable-launch`;
const identity = 'F1B6782A3BACC18E73FE08CA424C0A81450A982C';
const productionResources = new Set(['Contents/Info.plist', 'Contents/Resources/publisher-requirement.json']);
const compilationRecords = new Set([
  'native/ownership-compile.json', 'native/platform-compile.json', 'native/watchdog-compile.json',
]);
const rewrittenRecords = new Set([
  `${payloadPath}/metadata.json`, 'Contents/Resources/native-compatibility.json',
  'Contents/Resources/host-policy.json',
]);

// Paths within the locked packages, rather than a blanket "test" basename rule.
const vendorDevelopmentDirectories = [
  ...[
    'call-bind-apply-helpers', 'call-bound', 'dunder-proto', 'es-define-property',
    'es-errors', 'es-object-atoms', 'fast-uri', 'function-bind', 'get-intrinsic',
    'get-proto', 'gopd', 'has-symbols', 'isexe', 'math-intrinsics', 'object-inspect',
    'qs', 'setprototypeof', 'side-channel', 'side-channel-list', 'side-channel-map',
    'side-channel-weakmap',
  ].map(name => `${name}/test`),
  '@modelcontextprotocol/sdk/dist/cjs/examples',
  '@modelcontextprotocol/sdk/dist/esm/examples',
  'fast-uri/benchmark', 'json-schema-traverse/spec', 'object-inspect/example',
  'zod/src/v3/benchmarks', 'zod/src/v3/tests', 'zod/src/v4/classic/tests',
  'zod/src/v4/core/tests', 'zod/src/v4/mini/tests',
].map(name => `node_modules/${name}`);

function compilationOnly(path) {
  const prefix = `${payloadPath}/`;
  if (!path.startsWith(prefix)) return false;
  const name = path.slice(prefix.length);
  return compilationRecords.has(name) || (name.startsWith('lib/') && name.endsWith('.d.ts'));
}

async function removeVendorDevelopmentFiles(bundle, record) {
  const detail = await exactFile(join(root, 'dist/compiler-input-details.json'), 8388608);
  const { vendorInputs } = JSON.parse(detail.bytes.toString('utf8'));
  const inputs = Object.keys(vendorInputs);
  const digest = createHash('sha256').update(canonical(vendorInputs)).digest('hex');
  const expected = record.compilerInputs.vendorInputs;
  if (digest !== expected.digest || inputs.length !== expected.files) {
    throw new Error('Release vendor input evidence differs from compilation.');
  }
  const excluded = [];
  const files = Object.keys(record.files);
  for (const name of vendorDevelopmentDirectories) {
    if (inputs.some(input => input.startsWith(`${name}/`))) {
      throw new Error(`Release exclusion overlaps a compiled vendor input: ${name}`);
    }
    const relative = `${payloadPath}/${name}`;
    const members = files.filter(file => file.startsWith(`${relative}/`));
    if (!members.length) continue;
    const directory = join(bundle, relative);
    if (await realpath(directory) !== directory) throw new Error('Release exclusion is not a physical directory.');
    await rm(directory, { recursive: true });
    excluded.push(...members);
  }
  return excluded;
}

/** Stage a release payload for source and signing review. Its policy remains blocked. */
export async function prepareReleasePayload({ out, buildRoot, runtimeArchive }) {
  const run = dirname(dirname(dirname(buildRoot)));
  const managedRoot = join(userInfo().homedir, 'Builds', 'sylvan-stack', 'arbol-browser');
  const stateRoot = join(run, 'browser-state');
  if (!run.startsWith(`${managedRoot}${sep}`) || resolve(out) !== out || dirname(out) !== run ||
      out === stateRoot || out === dirname(dirname(buildRoot))) {
    throw new Error('Release staging needs a fresh output directory in a managed temporary Browser run.');
  }
  await assertHostIsolation(buildRoot, stateRoot, out);
  await privateDirectory(run);
  await mkdir(out, { mode: 0o700 });

  const bundle = join(out, 'ArbolBrowser.app');
  const staged = await prepareUnsignedHost({ out: bundle, buildRoot, stateRoot, runtimeArchive, purpose: 'blocked' });
  const compilerFiles = Object.keys(staged.record.files).filter(compilationOnly);
  const excluded = new Set([...compilerFiles, ...await removeVendorDevelopmentFiles(bundle, staged.record)]);
  for (const file of compilerFiles) await unlink(join(bundle, file));
  const production = { ...staged.record, delivery: 'production',
    buildRoot: join(...installation.stableBuilds, basename(buildRoot)),
    stateRoot: join(installation.root, installation.browser) };
  const launcher = await exactFile(join(root, 'dist/native/stable-launch'), 67108864);
  if (launcher.sha256 !== production.productOutputs.native['stable-launch']) {
    throw new Error('Release launcher differs from the compiled output');
  }
  await writeExclusive(join(bundle, launcherPath), launcher.bytes, 0o755);
  await writeFile(join(bundle, 'Contents/Info.plist'), outerPlist(publisher));
  await writeFile(join(bundle, 'Contents/Resources/publisher-requirement.json'), JSON.stringify(publisher, null, 2) + '\n');
  const { metadata } = await refreshHostRecords(bundle, production);
  const files = await inventory(bundle);
  const expected = Object.entries(staged.record.files).filter(([name]) => !excluded.has(name));
  if (Object.keys(files).length !== expected.length + 1 || files[launcherPath] !== launcher.sha256 ||
      expected.some(([name, digest]) => !Object.hasOwn(files, name) ||
        (!rewrittenRecords.has(name) && !productionResources.has(name) && files[name] !== digest))) {
    throw new Error('Release staging changed a file outside the recorded changes');
  }
  const runtime = join(bundle, payloadPath);
  const physicalEntries = { bundle: await assertPhysicalCap(bundle), payload: await assertPhysicalCap(runtime) };
  await assertHostIsolation(buildRoot, stateRoot, out);
  if (dirname(staged.scratch) !== out || !staged.scratch.startsWith(`${out}${sep}.host-inputs-`)) {
    throw new Error('Release staging produced an unexpected scratch path.');
  }
  await rm(staged.scratch, { recursive: true });
  await unlink(`${bundle}.unsigned.json`);
  const record = { ...production, kind: 'unsigned-release-payload', runtime: metadata.runtime,
    physicalEntries, excluded: [...excluded].sort(), files, payloadDigest: inventoryDigest(files) };
  await writeExclusive(join(out, 'release-payload.json'), `${JSON.stringify(record, null, 2)}\n`);
  return { bundle, productDigest: record.productDigest, payloadDigest: record.payloadDigest };
}

/** Produce one reviewed signed candidate. Qualification and Apple distribution are separate operations. */
export async function sealReleaseImage({ out, buildRoot, runtimeArchive, review }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Release signing requires Darwin arm64');
  const compiled = await currentHostCompilation();
  const lock = (await json(join(root, 'package-lock.json'))).value;
  if (!compiled.productSources['src/cli/agent-session.ts'] ||
      Object.entries(lock.packages).some(([path, record]) => !record.dev && path.endsWith('/@modelcontextprotocol/sdk'))) {
    throw new Error('Production signing requires the direct agent CLI and removal of the packaged MCP SDK');
  }
  const accepted = await acceptedReleaseProduct(review, compiled);
  const allocation = await verifyReleaseAllocation(buildRoot, compiled, review);
  const { bundle } = await prepareReleasePayload({ out, buildRoot, runtimeArchive });
  const replay = join(dirname(out), `.release-replay-${randomBytes(12).toString('hex')}`);
  await prepareReleasePayload({ out: replay, buildRoot, runtimeArchive });
  const receipt = await json(join(out, 'release-payload.json'));
  const reproduced = (await json(join(replay, 'release-payload.json'))).value;
  if (canonical(receipt.value) !== canonical(reproduced) || reproduced.purpose !== 'blocked' ||
      reproduced.compileDigest !== compiled.digest || canonical(await inventory(bundle)) !== canonical(reproduced.files)) {
    throw new Error('Production signing input did not reproduce exactly');
  }
  const production = { ...reproduced, purpose: 'production', reviewHandover: review, reviewDigest: accepted.digest };
  const changed = new Set(rewrittenRecords);
  const signatureResource = name => /(?:^|\/)_CodeSignature\/CodeResources$/.test(name);
  async function checkSignedFiles() {
    const files = await inventory(bundle);
    if (Object.entries(reproduced.files).some(([name, digest]) => !Object.hasOwn(files, name) ||
        (!changed.has(name) && !signatureResource(name) && files[name] !== digest)) ||
        Object.keys(files).some(name => !Object.hasOwn(reproduced.files, name) && !signatureResource(name))) {
      throw new Error('Signing changed an input outside the permitted code and signature records');
    }
    return files;
  }
  const { audit, records } = await signBundle({ bundle, identity, publisher, async sealResources(code) {
    for (const name of code) changed.add(name);
    const records = await refreshHostRecords(bundle, production);
    await checkSignedFiles();
    await assertPhysicalCap(bundle);
    await assertPhysicalCap(join(bundle, payloadPath));
    return records;
  } });
  const files = await checkSignedFiles();
  if ((await currentHostCompilation()).digest !== compiled.digest ||
      (await verifyReleaseAllocation(buildRoot, compiled, review)) !== allocation ||
      (await json(join(out, 'release-payload.json'))).sha256 !== receipt.sha256 ||
      records.policy.reviewDigest !== accepted.digest || records.policy.productDigest !== compiled.record.productDigest) {
    throw new Error('Production signing evidence changed');
  }

  const source = await mkdtemp(join(out, '.image-source-'));
  const copy = join(source, basename(bundle));
  command('/bin/cp', ['-pR', bundle, copy]);
  if ((await readdir(source)).join(',') !== basename(bundle) ||
      canonical(await inventory(copy)) !== canonical(files)) throw new Error('Image source differs from the signed app');
  await assertPhysicalCap(source);
  const image = join(out, 'ArbolBrowser.dmg');
  const { uid, gid } = userInfo();
  command('/usr/bin/hdiutil', ['create', '-fs', 'APFS', '-srcfolder', source, '-volname', 'ArbolBrowser',
    '-uid', String(uid), '-gid', String(gid), '-mode', '0700', '-format', 'UDRO', '-plist', image]);
  await chmod(image, 0o600);
  command('/usr/bin/codesign', ['--sign', identity, '--timestamp', image]);
  command('/usr/bin/codesign', ['--verify', '--strict', '-R', `=${publisher.requirement}`, image]);
  const { sha256: imageSha256 } = await exactFile(image, 1073741824);
  if ((await verifyReleaseAllocation(buildRoot, compiled, review)) !== allocation) throw new Error('Production Build allocation changed');
  const signed = { format: 1, kind: 'signed-production-candidate', source: production.sourceIdentity.commit,
    productDigest: production.productDigest, runtime: production.runtime, publisher, build: production.component.build,
    review, reviewDigest: accepted.digest, image: basename(image), imageSha256,
    payloadDigest: inventoryDigest(files), files, policy: records.policy, launcherDigest: files[launcherPath], audit,
    qualification: 'unexecuted' };
  await writeExclusive(join(out, 'signed-release.json'), JSON.stringify(signed, null, 2) + '\n');
  await rm(source, { recursive: true });
  await rm(replay, { recursive: true });
  return { image, imageSha256, payloadDigest: signed.payloadDigest, qualification: signed.qualification };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--allocated') {
    const { ARBOL_BUILD_DIR: buildRoot, ARBOL_BUILD_NUMBER: build } = process.env;
    if (!buildRoot || !build || resolve(buildRoot) !== buildRoot || basename(buildRoot) !== build)
      throw new Error('Release staging requires the normal Build allocation');
    const { value: record } = await json(join(buildRoot, 'build.json'));
    if (record.productionRelease !== undefined) {
      const out = join(dirname(dirname(dirname(buildRoot))), `release-${build}`);
      console.log(JSON.stringify(await sealReleaseImage({ out, buildRoot, runtimeArchive: preservedStockArchive,
        review: record.productionRelease?.review })));
    }
  } else {
    if (args.length !== 6 || args[0] !== '--out' || args[2] !== '--build-root' || args[4] !== '--runtime-archive')
      throw new Error('Usage: package.mjs --out <fresh-directory> --build-root <allocated-Build> --runtime-archive <pinned.zip>');
    console.log(JSON.stringify(await prepareReleasePayload({ out: args[1], buildRoot: args[3], runtimeArchive: args[5] })));
  }
}
