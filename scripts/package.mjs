import { createHash } from 'node:crypto';
import { mkdir, realpath, rm, unlink } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventory, inventoryDigest, root } from './package-base.mjs';
import {
  assertHostIsolation, assertPhysicalCap, canonical, exactFile, prepareUnsignedHost, privateDirectory,
  refreshHostRecords, writeExclusive,
} from './package-host.mjs';

const payloadPath = 'Contents/Resources/browser';
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
  const { metadata } = await refreshHostRecords(bundle, staged.record);
  const files = await inventory(bundle);
  const expected = Object.entries(staged.record.files).filter(([name]) => !excluded.has(name));
  if (Object.keys(files).length !== expected.length ||
      expected.some(([name, digest]) => !Object.hasOwn(files, name) || (!rewrittenRecords.has(name) && files[name] !== digest))) {
    throw new Error('Release staging changed a file outside the recorded exclusions.');
  }
  const runtime = join(bundle, payloadPath);
  const physicalEntries = { bundle: await assertPhysicalCap(bundle), payload: await assertPhysicalCap(runtime) };
  await assertHostIsolation(buildRoot, stateRoot, out);
  if (dirname(staged.scratch) !== out || !staged.scratch.startsWith(`${out}${sep}.host-inputs-`)) {
    throw new Error('Release staging produced an unexpected scratch path.');
  }
  await rm(staged.scratch, { recursive: true });
  await unlink(`${bundle}.unsigned.json`);
  const record = { ...staged.record, kind: 'unsigned-release-payload', runtime: metadata.runtime,
    physicalEntries, excluded: [...excluded].sort(), files, payloadDigest: inventoryDigest(files) };
  await writeExclusive(join(out, 'release-payload.json'), `${JSON.stringify(record, null, 2)}\n`);
  return { bundle, productDigest: record.productDigest, payloadDigest: record.payloadDigest };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 6 || args[0] !== '--out' || args[2] !== '--build-root' || args[4] !== '--runtime-archive') {
    throw new Error('Usage: package.mjs --out <fresh-directory> --build-root <isolated-Build> --runtime-archive <pinned.zip>');
  }
  console.log(JSON.stringify(await prepareReleasePayload({ out: args[1], buildRoot: args[3], runtimeArchive: args[5] })));
}
