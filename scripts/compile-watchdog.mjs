/** Test-free native compilation. Never executes the helper or opens a profile. */
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { root, inventory, inventoryDigest } from './package-base.mjs';
import { captureCompilerInputs } from './compile-platform.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const watchdogCompilerPolicy = Object.freeze({ compiler: 'Apple clang version 21.0.0 (clang-2100.4.1.1)', sdk: 'macosx27.0',
  arch: 'arm64', deployment: '27.0', protocol: 1, modes: ['--watchdog', '--custody'], frameworks: ['Foundation', 'Security'], qualification: 'unexecuted' });
async function sources() {
  const files = Object.fromEntries(Object.entries(await inventory(join(root, 'watchdog'))).map(([name,digest]) => [`watchdog/${name}`,digest]));
  for (const name of ['scripts/compile-watchdog.mjs', 'scripts/compile-platform.mjs', 'src/runtime/platform.mm', 'src/runtime/platform.ts', 'src/runtime/host-bootstrap.mm', 'src/runtime/attempt.hpp', 'src/runtime/installation-paths.json', 'native/publisher-requirement.json'])
    files[name] = hash(await readFile(join(root,name)));
  return Object.fromEntries(Object.entries(files).sort(([a],[b]) => a.localeCompare(b,'en')));
}
function run(args) {
  const r = spawnSync('/usr/bin/xcrun',args,{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},timeout:120000,maxBuffer:1048576});
  if(r.error || r.status !== 0) throw new Error(`Static watchdog compilation failed: ${r.stderr}`); return r.stdout.trim();
}
async function inputs() {
  const sdk = await realpath(run(['--show-sdk-path']));
  if(JSON.parse(await readFile(join(sdk,'SDKSettings.json'),'utf8')).CanonicalName !== watchdogCompilerPolicy.sdk ||
    run(['clang++','--version']).split('\n')[0] !== watchdogCompilerPolicy.compiler) throw new Error('Unsupported watchdog compiler/SDK');
  return { sdk, closure: await captureCompilerInputs(['watchdog/main.mm']) };
}
export async function validateWatchdogCompilation() {
  const record = JSON.parse(await readFile(join(root,'dist/native/watchdog-compile.json'),'utf8'));
  const actual = await inputs();
  if(record.format !== 1 || JSON.stringify(record.policy) !== JSON.stringify(watchdogCompilerPolicy) ||
    inventoryDigest(record.sources) !== inventoryDigest(await sources()) || JSON.stringify(record.input) !== JSON.stringify(actual.closure) ||
    record.payload !== hash(await readFile(join(root,'dist/native/watchdog')))) throw new Error('Stale watchdog compilation');
  return record;
}
export async function compileWatchdog() {
  if(process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Only pinned Darwin arm64 is supported');
  const before = await sources(), input = await inputs(), output = join(root,'dist/native/watchdog');
  await mkdir(join(root,'dist/native'),{recursive:true});
  run(['clang++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-fobjc-arc','-fblocks','-arch','arm64','-mmacosx-version-min=27.0','-isysroot',input.sdk,
    ...input.closure.installationPaths.flags,'watchdog/main.mm','-framework','Foundation','-framework','Security','-lbsm','-o',output]);
  if(inventoryDigest(before) !== inventoryDigest(await sources()) || JSON.stringify(input) !== JSON.stringify(await inputs())) throw new Error('Watchdog source/input changed during compilation');
  await writeFile(join(root,'dist/native/watchdog-compile.json'),JSON.stringify({format:1,policy:watchdogCompilerPolicy,input:input.closure,sources:before,payload:hash(await readFile(output))},null,2)+'\n');
  await validateWatchdogCompilation();
  console.log(JSON.stringify({helper:output,modes:watchdogCompilerPolicy.modes,qualification:'unexecuted'}));
}
if(process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if(process.argv.length !== 2) throw new Error('compile-watchdog.mjs accepts no arguments'); await compileWatchdog();
}
