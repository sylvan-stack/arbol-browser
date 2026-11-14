/** Test-free compile and static export inspection; never loads a native module. */
import { spawnSync } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { root } from './package-base.mjs';
const args = process.argv.slice(2);
if (process.platform !== 'darwin' || process.arch !== 'arm64' || args.length !== 2 || args[0] !== '--headers')
  throw new Error('Usage: compile-native.mjs --headers <pinned-Electron-45.3.2-include/node> (Darwin arm64 only)');
const headers = resolve(args[1]);
const headerHashes = {
  'node_api.h': '2d4560831e525b47b060ec8a0864ab73993df9e20215ce9f0fe7b24cd31af32a',
  'js_native_api.h': '239e46a0e9f74ded674fab6cd693e231a04b79732cdc044831f0b8b5307c569f',
  'js_native_api_types.h': '4f19cb90d240765cc0961d92a1ee20f65fdc50db7de1ab0a5cb6bc227224e1a0',
  'node_api_types.h': 'a25356630d3058f0a0c8937d9f297e9471e037fda58c2696d8a505c2bd99cb00',
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
for (const [name, digest] of Object.entries(headerHashes)) if (hash(await readFile(join(headers, name))) !== digest)
  throw new Error('Electron header mismatch');
function run(command, arguments_) {
  const result = spawnSync(command, arguments_, { cwd: root, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8', timeout: 120000, maxBuffer: 1048576 });
  if (result.error || result.status !== 0) throw new Error(`Static native compilation failed: ${result.stderr}`);
  return result.stdout.trim();
}
const sdk = run('/usr/bin/xcrun', ['--show-sdk-path']);
const settings = JSON.parse(await readFile(join(sdk, 'SDKSettings.json'), 'utf8'));
const compiler = run('/usr/bin/xcrun', ['clang++', '--version']).split('\n')[0];
if (settings.CanonicalName !== 'macosx27.0' || compiler !== 'Apple clang version 21.0.0 (clang-2100.4.1.1)') throw new Error('Unsupported native compiler/SDK');
const pkg = JSON.parse(await readFile(join(root, 'node_modules/electron/package.json'), 'utf8'));
if (pkg.version !== '45.3.2' || (await readFile(join(root, 'node_modules/electron/dist/version'), 'utf8')).trim().replace(/^v/, '') !== pkg.version) throw new Error('Pinned prebuilt Electron absent');
const output = join(root, 'dist/native/ownership.node');
await mkdir(join(root, 'dist/native'), { recursive: true });
run('/usr/bin/xcrun', ['clang++', '-std=c++17', '-O2', '-fobjc-arc', '-fblocks', '-fvisibility=hidden', '-Wall', '-Wextra', '-Werror',
  '-DNAPI_VERSION=8', '-arch', 'arm64', '-mmacosx-version-min=27.0', '-isysroot', sdk, '-bundle', '-undefined', 'dynamic_lookup',
  '-I', headers, 'native/ownership.mm', 'native/integrity.mm', '-framework', 'Cocoa', '-o', output]);
const symbols = run('/usr/bin/nm', ['-gU', output]);
if (!symbols.includes('_napi_register_module_v1') || !symbols.includes('_node_api_module_get_api_version_v1') ||
    run('/usr/bin/lipo', ['-archs', output]) !== 'arm64') throw new Error('Native registration/architecture mismatch');
const text = await readFile(join(root, 'native/ownership.mm'), 'utf8');
const exports_ = [...text.matchAll(/\{"([A-Za-z]+)", nullptr, [A-Za-z]+,/g)].map(match => match[1]).sort();
const required = ['getABI', 'install', 'status', 'checkIntegrity', 'seal'];
const allowed = [...required, 'beginBinding', 'finishBinding', 'bindingInfo', 'mark', 'restore', 'retire', 'interactionState'];
if (required.some(name => !exports_.includes(name)) || exports_.some(name => !allowed.includes(name)) || new Set(exports_).size !== exports_.length)
  throw new Error('Unexpected production native export declaration');
const sources = {};
for (const name of ['ownership.mm', 'integrity.mm', 'inventory.hpp']) sources[`native/${name}`] = hash(await readFile(join(root, 'native', name)));
await writeFile(join(root, 'dist/native/ownership-compile.json'), JSON.stringify({ compiledNapi: 8, architecture: 'arm64',
  electron: '45.3.2', headerArchive: '34a9cbe0cb9851b657b676fef9ce3913d0bf9ff8fe29a84f405ad3836e612493', headerHashes,
  compiler, sdk: settings.CanonicalName, sources, exports: exports_, payload: hash(await readFile(output)), qualification: 'unexecuted' }, null, 2) + '\n');
console.log(JSON.stringify({ native: output, compiledNapi: 8, exports: exports_, qualification: 'unexecuted' }));
