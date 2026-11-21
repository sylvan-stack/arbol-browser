/** Test-free schema/types/native compilation. Never tests, stages, signs, loads
 * an emitted native addon, invokes product code or executes a host/helper. */
import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, copyFile, rm, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, relative, resolve, sep } from 'node:path';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { root, inventory, inventoryDigest, sourceInventory, productInventory } from './package-base.mjs';
import { compileNative, validateNativeCompilation } from './compile-native.mjs';
import { compilePlatform, validatePlatformCompilation, officialHeaders, captureCompilerInputs } from './compile-platform.mjs';
import { compileWatchdog, validateWatchdogCompilation } from './compile-watchdog.mjs';
import { installedRuntimeProjection, compactRuntimeProjection, canonical } from './package-host.mjs';
if (process.argv.length > 2) throw new Error('compile.mjs accepts no arguments');
const hash = value => createHash('sha256').update(value).digest('hex');
const sources = await sourceInventory(), productSources = await productInventory();
function run(args) {
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit' });
  if (result.error || result.status !== 0) throw new Error('Static compilation failed');
}
function git(args) {
  const result = spawnSync('/usr/bin/git', args, { cwd: root, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (result.error || result.status !== 0) throw new Error('Actual source identity unavailable'); return result.stdout.trim();
}
// Works with a normal detached worktree: .git is intentionally not assumed to
// be a directory. Dirty static compilation may be inspected but cannot stage.
const sourceIdentity = { repositoryDigest: hash(git(['rev-parse', '--show-toplevel'])), branch: git(['rev-parse', '--abbrev-ref', 'HEAD']),
  commit: git(['rev-parse', 'HEAD']), uncommittedChanges: git(['status', '--porcelain']) !== '' };
await mkdir(join(root, 'build'), { recursive: true });
for (const name of ['lib', 'cli', 'host', 'native']) await rm(join(root, 'dist', name), { recursive: true, force: true });
const generator = join(root, 'build/contracts-generator.mjs');
await build({ entryPoints: [join(root, 'src/contracts/schema.ts')], outfile: generator,
  bundle: true, platform: 'node', format: 'esm', packages: 'external' });
// This evaluates only the schema compiler, not the product/renderer/native host.
const contracts = await import(generator);
if (await readFile(join(root, 'src/contracts/generated.ts'), 'utf8') !== contracts.generatedTypes())
  throw new Error('Generated types are stale; regenerate under a contract Intention');
const count = contracts.compileContracts(), ajv = new Ajv2020({ strict: true, strictRequired: false, strictTypes: false });
addFormats(ajv);
for (const tool of contracts.agentToolSchemas) { ajv.compile(tool.inputSchema); ajv.compile(tool.outputSchema); }
console.log(`Compiled ${count} named contract roots and ${contracts.agentToolSchemas.length * 2} public schema roots`);
run(['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json']);
const shell = join(root, 'dist/lib/shell'); await mkdir(shell, { recursive: true });
for (const name of ['index.html', 'style.css']) await copyFile(join(root, 'src/shell', name), join(shell, name));
await build({ entryPoints: [join(root, 'src/shell/control.ts')], outfile: join(shell, 'control.js'),
  bundle: true, platform: 'browser', format: 'iife', target: 'chrome156' });
await build({ entryPoints: [join(root, 'src/shell/preload.ts')], outfile: join(shell, 'preload.cjs'),
  bundle: true, platform: 'node', format: 'cjs', target: 'node24.22.2', external: ['electron'] });
await compileNative(officialHeaders); await compilePlatform(officialHeaders); await compileWatchdog();
const native = await validateNativeCompilation(), platform = await validatePlatformCompilation(), watchdog = await validateWatchdogCompilation();
await mkdir(join(root, 'dist/cli'), { recursive: true }); await mkdir(join(root, 'dist/host'), { recursive: true });
// The entire actual application graph remains the one physical tsc graph.
// No bundler may duplicate WeakMap brands or relocate import.meta.url consumers.
await writeFile(join(root, 'dist/cli/main.mjs'), `const address = new URL('./main.js', import.meta.url).href;
try { const cli = await import(address); process.exitCode = await cli.runCli(process.argv.slice(2)); }
catch {
  const error = { code: 'internal', message: 'Browser operation failed.', retryable: false, remedy: 'Preserve state and inspect the compatible Build.' };
  const frame = process.argv[2] === 'agent' ? { event: 'error', error } : { error };
  process.stdout.write(JSON.stringify(frame) + '\\n');
  process.stderr.write('arbol-browser: internal\\n');
  process.exitCode = 70;
}
`);
await writeFile(join(root, 'dist/host/main.mjs'), `let host;
try { const address = new URL('../runtime/host-entry.js', import.meta.url).href; host = await import(address); }
catch { const { app } = await import('electron'); app.exit(4); }
// A known original belongs to runHostEntry's native disposition. Never convert
// its actual retained unwind into a blanket normal Electron exit.
if (host) await host.runHostEntry();
`);
const graphs = {};
for (const name of ['cli/main.js', 'runtime/process.js', 'runtime/exit.js', 'runtime/lifecycle.js']) {
  const result = await build({ entryPoints: [join(root, 'dist/lib', name)], write: false, bundle: true,
    format: 'esm', platform: 'node', packages: 'external', metafile: true, logLevel: 'silent' });
  for (const input of Object.values(result.metafile.inputs)) for (const edge of input.imports)
    if (edge.external && /^(?:node:)?electron(?:\/|$)|^original-fs$/.test(edge.path)) throw new Error('Electron implementation entered Node CLI graph');
  graphs[name] = Object.keys(result.metafile.inputs).map(path => relative(root, resolve(root, path))).sort();
}
if (!['agent-session.js', 'agent-tools.js'].every(file => graphs['cli/main.js'].includes(`dist/lib/cli/${file}`)))
  throw new Error('The direct Browser session and description must be reachable from the Node CLI');
// Compile each genuine external provider graph without evaluation. Compare
// every actual package input and manifest/side-asset projection under the lock.
const runtimeProjection = await installedRuntimeProjection(), vendorInputs = {};
for (const entry of ['ajv/dist/2020.js', 'ajv-formats']) {
  const result = await build({ stdin: { contents: `import * as provider from ${JSON.stringify(entry)}; export { provider };`, resolveDir: root },
    write: false, bundle: true, format: 'esm', platform: 'node', metafile: true, logLevel: 'silent' });
  for (const input of Object.keys(result.metafile.inputs)) if (input !== '<stdin>') {
    const path = resolve(root, input), name = relative(root, path);
    if (!name.startsWith('node_modules' + sep) || name.includes('..' + sep)) throw new Error('Unexpected vendor provider input');
    vendorInputs[name] = hash(await readFile(path));
  }
}
const nativeSources = ['ownership', 'integrity', 'bindings', 'accessibility', 'text-input', 'responder', 'interaction'].map(name => `native/${name}.mm`);
const details = { native: native.input, nativeSDK: await captureCompilerInputs(nativeSources), platform: platform.input,
  watchdog: watchdog.input, runtimeProjection, vendorInputs: Object.fromEntries(Object.entries(vendorInputs).sort(([a], [b]) => a.localeCompare(b, 'en'))) };
const frontier = input => ({ digest: hash(canonical(input)), files: Object.keys(input.files).length, policy: input.policy, providers: input.providers });
const compilerInputs = { native: native.input, nativeSDK: frontier(details.nativeSDK), platform: frontier(platform.input),
  watchdog: frontier(watchdog.input), runtimeProjection: compactRuntimeProjection(runtimeProjection),
  vendorInputs: { digest: hash(canonical(details.vendorInputs)), files: Object.keys(details.vendorInputs).length } };
await writeFile(join(root, 'dist/compiler-input-details.json'), JSON.stringify(details, null, 2) + '\n');
if (inventoryDigest(await sourceInventory()) !== inventoryDigest(sources) || inventoryDigest(await productInventory()) !== inventoryDigest(productSources) ||
    git(['rev-parse', 'HEAD']) !== sourceIdentity.commit) throw new Error('Source changed during compilation');
const productOutputs = { libraryDigest: inventoryDigest(await inventory(join(root, 'dist/lib'))),
  entryDigest: hash(await readFile(join(root, 'dist/cli/main.mjs'))), hostDigest: hash(await readFile(join(root, 'dist/host/main.mjs'))), native: {} };
for (const name of ['ownership.node', 'platform.node', 'host-bootstrap', 'host-launch', 'watchdog', 'stable-launch']) productOutputs.native[name] = hash(await readFile(join(root, 'dist/native', name)));
const record = { sourceDigest: inventoryDigest(sources), sources, sourceIdentity, productDigest: inventoryDigest(productSources), productSources,
  ...productOutputs, nativeDigest: inventoryDigest(await inventory(join(root, 'dist/native'))), productOutputs, compilerInputs, graphs,
  qualification: 'unexecuted', testsRun: false };
await writeFile(join(root, 'dist/compile-record.json'), JSON.stringify(record, null, 2) + '\n');
console.log(`Compiled exact product ${record.productDigest}; no runtime qualification executed`);
