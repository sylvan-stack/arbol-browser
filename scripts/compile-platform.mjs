/** Static native compilation/inspection only. Importing never compiles, loads
 * an addon, signs code or executes any emitted host/helper. */
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join, dirname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { root, inventoryDigest } from './package-base.mjs';
import { nativeCompilerPolicy } from './compile-native.mjs';
export const officialHeaders = '/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-46-20261116-6df9y348/headers/node_headers/include/node';
const frozenConsumer = '/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-46-20261116-6df9y348/consumer-manifest.json';
const frozenDigest = '25fe40877f7c3415bc5c5cce034320440bdfbb287170e30c9cb319728ca9490e';
export const platformCompilerPolicy = Object.freeze({ compiler: nativeCompilerPolicy.compiler, sdk: nativeCompilerPolicy.sdk,
  architecture: 'arm64', deployment: '27.0', compiledNapi: 8, protocol: 1, headerArchive: nativeCompilerPolicy.headerArchive,
  frozenConsumer: frozenDigest, outputs: ['platform.node', 'host-launch', 'host-bootstrap', 'stable-launch'], qualification: 'unexecuted' });
const names = ['src/runtime/platform.mm', 'src/runtime/host-launch.mm', 'src/runtime/host-bootstrap.mm', 'src/runtime/stable-launch.mm'];
const installationConsumers = new Set([...names, 'watchdog/main.mm']);
const installationSource = 'src/runtime/installation-paths.json';
const productionPublisherSource = 'native/production-publisher-requirement.json';
const closure = [...names, 'src/runtime/platform.ts', 'src/runtime/attempt.hpp', 'watchdog/boundary.hpp', 'watchdog/exit.hpp',
  'package.json', 'arbol-build.json', installationSource, 'native/publisher-requirement.json', productionPublisherSource, 'scripts/compile-platform.mjs'];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function installationInput() {
  const bytes = await readFile(join(root, installationSource));
  const layout = JSON.parse(bytes);
  const flags = ['root', 'builds', 'payloads', 'browser', 'stableBuilds', 'stableUses'].map(name => {
    const parts = Array.isArray(layout[name]) ? layout[name] : [layout[name]];
    if (!parts.length || parts.some(part => typeof part !== 'string' ||
        (!/^\.?[a-z][a-z0-9-]*$/i.test(part) && !(name === 'stableBuilds' && part === 'Arbol Browser'))))
      throw new Error('Invalid installation directory component');
    const macro = name.replace(/[A-Z]/g, letter => '_' + letter).toUpperCase();
    return `-DARBOL_INSTALLATION_${macro}=${JSON.stringify(parts.join('/'))}`;
  });
  return { sha256: hash(bytes), flags };
}
/** One package-owned management format, also bound into every native record.
 * Manual compiler defaults cannot masquerade as this selected package. */
export async function profileFormatInput() {
  const packageBytes = await readFile(join(root, 'package.json'));
  const buildBytes = await readFile(join(root, 'arbol-build.json'));
  const pkg = JSON.parse(packageBytes), build = JSON.parse(buildBytes);
  if (pkg.arbolBrowser?.profileFormat !== 2 || build.dataFormat !== 2 ||
      pkg.arbolBrowser.contract !== 1 || build.contract !== 1) throw new Error('Browser package and Build formats differ');
  return { value: 2, packageSha256: hash(packageBytes), buildSha256: hash(buildBytes),
    flags: ['-DARBOL_BROWSER_PROFILE_FORMAT=2'] };
}
async function productionPublisherInput() {
  const file = await readFile(join(root, productionPublisherSource));
  const policy = JSON.parse(file);
  const isolated = JSON.parse(await readFile(join(root, 'native/publisher-requirement.json')));
  if (Object.keys(policy).sort().join(',') !== 'bundleIdentifier,requirement,team' ||
      policy.team !== isolated.team || policy.requirement !== isolated.requirement ||
      policy.bundleIdentifier !== 'com.sylvan-stack.arbol-browser' || policy.bundleIdentifier === isolated.bundleIdentifier)
    throw new Error('Invalid production publisher policy');
  const flags = [
    `-DARBOL_PRODUCTION_PUBLISHER_TEAM=${JSON.stringify(policy.team)}`,
    `-DARBOL_PRODUCTION_BUNDLE_ID=${JSON.stringify(policy.bundleIdentifier)}`,
    `-DARBOL_PRODUCTION_PUBLISHER_REQUIREMENT=${JSON.stringify(policy.requirement)}`,
  ];
  return { sha256: hash(file), flags };
}
export function staticCommand(program, args, maximum = 8388608) {
  const result = spawnSync(program, args, { cwd: root, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8',
    timeout: 120000, maxBuffer: maximum });
  if (result.error || result.status !== 0) throw new Error(`Static compiler/input inspection failed: ${result.stderr}`);
  return result.stdout.trim();
}
export async function assertOfficialHeaders(headers = officialHeaders) {
  if (resolve(headers) !== officialHeaders || await realpath(headers) !== officialHeaders ||
      hash(await readFile(frozenConsumer)) !== frozenDigest) throw new Error('Use exact preserved ABR-46 official Electron headers');
  for (const [name, digest] of Object.entries(nativeCompilerPolicy.headerHashes))
    if (hash(await readFile(join(headers, name))) !== digest) throw new Error('Pinned Electron Node-API headers differ');
  return headers;
}
function dependencies(text) {
  const body = text.replace(/\\\r?\n/g, '').replace(/^[^:]*:/, ''), result = [];
  let current = '', escaped = false;
  for (const char of body) {
    if (escaped) { current += char; escaped = false; }
    else if (char === '\\') escaped = true;
    else if (/\s/.test(char)) { if (current) { result.push(current); current = ''; } }
    else current += char;
  }
  if (escaped) throw new Error('Incomplete compiler dependency pathname');
  if (current) result.push(current); return result;
}
/** Capture the actual complete preprocessor closure, including sys/event.h,
 * every exit/sync/shared-state SDK header and the actual libc++/dlfcn inputs.
 * These are file digests, never a runtime watcher/flush qualification claim. */
export async function captureCompilerInputs(sourceNames, headers = officialHeaders) {
  await assertOfficialHeaders(headers);
  const sdkAlias = staticCommand('/usr/bin/xcrun', ['--show-sdk-path']), compilerAlias = staticCommand('/usr/bin/xcrun', ['--find', 'clang++']);
  const sdk = await realpath(sdkAlias), compilerPath = await realpath(compilerAlias);
  const compilerRoot = dirname(dirname(compilerPath));
  const settings = await readFile(join(sdk, 'SDKSettings.json'));
  if (JSON.parse(settings).CanonicalName !== platformCompilerPolicy.sdk ||
      staticCommand('/usr/bin/xcrun', ['clang++', '--version']).split('\n')[0] !== platformCompilerPolicy.compiler)
    throw new Error('Unsupported pinned compiler or SDK');
  const installationPaths = sourceNames.some(name => installationConsumers.has(name)) ? await installationInput() : undefined;
  const profileFormat = installationPaths ? await profileFormatInput() : undefined;
  const usesProductionPublisher = name => name === names[2] || name === names[3];
  const productionPublisher = sourceNames.some(usesProductionPublisher) ? await productionPublisherInput() : undefined;
  const paths = new Map();
  for (const name of sourceNames) {
    const flags = [
      ...(installationConsumers.has(name) ? [...installationPaths.flags, ...profileFormat.flags] : []),
      ...(usesProductionPublisher(name) ? productionPublisher.flags : []),
    ];
    const output = staticCommand('/usr/bin/xcrun', ['clang++', '-std=c++17', '-fobjc-arc', '-fblocks', '-DNAPI_VERSION=8',
      '-arch', 'arm64', '-mmacosx-version-min=27.0', '-isysroot', sdk, '-I', headers, ...flags, '-M', '-MT', 'closure', name]);
    for (const item of dependencies(output)) {
      const full = resolve(root, item), physical = await realpath(full);
      const scopes = [[officialHeaders, 'node'], [sdk, 'sdk'], [compilerRoot, 'clang'], [root, 'source']];
      const scope = scopes.find(([path]) => full === path || full.startsWith(path + sep));
      if (!scope || (physical !== full && !(physical.startsWith(sdk + sep) || physical.startsWith(compilerRoot + sep))))
        throw new Error('Unexpected compiler dependency provider');
      paths.set(`${scope[1]}/${relative(scope[0], full)}`, full);
    }
  }
  const files = {};
  for (const [name, path] of [...paths].sort(([a], [b]) => a.localeCompare(b, 'en'))) files[name] = hash(await readFile(path));
  if (await realpath(sdkAlias) !== sdk || await realpath(compilerAlias) !== compilerPath) throw new Error('Compiler provider alias changed');
  const linkerAlias = staticCommand('/usr/bin/xcrun', ['--find', 'ld']), linkerPath = await realpath(linkerAlias);
  const linkerInputs = {};
  for (const path of ['System/Library/Frameworks/AppKit.framework/AppKit.tbd',
    'System/Library/Frameworks/Foundation.framework/Foundation.tbd', 'System/Library/Frameworks/Security.framework/Security.tbd',
    'usr/lib/libbsm.tbd', 'usr/lib/libc++.tbd', 'usr/lib/libSystem.tbd'])
    linkerInputs[path] = hash(await readFile(join(sdk, path)));
  return { policy: platformCompilerPolicy, providers: { sdkAlias, sdk, compilerAlias, compilerPath, linkerAlias, linkerPath },
    ...(installationPaths ? { installationPaths, profileFormat } : {}),
    ...(productionPublisher ? { productionPublisher } : {}),
    compiler: hash(await readFile(compilerPath)), linker: hash(await readFile(linkerPath)), linkerInputs,
    frameworks: { 'platform.node': ['Foundation', 'Security', 'AppKit'], 'host-launch': ['AppKit'],
      'host-bootstrap': ['Foundation', 'Security'], 'stable-launch': ['Foundation', 'Security'] },
    sdkSettings: hash(settings), files };
}
async function sources() {
  const files = {};
  for (const name of closure) files[name] = hash(await readFile(join(root, name)));
  return Object.fromEntries(Object.entries(files).sort(([a], [b]) => a.localeCompare(b, 'en')));
}
export async function validatePlatformCompilation() {
  const record = JSON.parse(await readFile(join(root, 'dist/native/platform-compile.json'), 'utf8'));
  if (record.format !== 1 || inventoryDigest(record.sources) !== inventoryDigest(await sources()) ||
      JSON.stringify(record.input) !== JSON.stringify(await captureCompilerInputs(names))) throw new Error('Stale platform compiler inputs');
  for (const name of platformCompilerPolicy.outputs)
    if (record.outputs[name] !== hash(await readFile(join(root, 'dist/native', name)))) throw new Error('Stale platform emitted payload');
  return record;
}
export async function compilePlatform(headers = officialHeaders) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Only pinned Darwin arm64 is supported');
  await assertOfficialHeaders(headers);
  const before = await sources(), input = await captureCompilerInputs(names, headers);
  const sdk = await realpath(staticCommand('/usr/bin/xcrun', ['--show-sdk-path']));
  await mkdir(join(root, 'dist/native'), { recursive: true });
  const common = ['clang++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-fobjc-arc', '-fblocks', '-arch', 'arm64',
    '-mmacosx-version-min=27.0', '-isysroot', sdk, ...input.profileFormat.flags];
  staticCommand('/usr/bin/xcrun', [...common, '-DNAPI_VERSION=8', '-DNODE_GYP_MODULE_NAME=arbol_browser_platform',
    '-bundle', '-undefined', 'dynamic_lookup', '-I', headers, ...input.installationPaths.flags, names[0],
    '-lbsm', '-framework', 'Foundation', '-framework', 'Security', '-framework', 'AppKit',
    '-o', join(root, 'dist/native/platform.node')]);
  for (const [source, name, frameworks] of [[names[1], 'host-launch', ['AppKit']], [names[2], 'host-bootstrap', ['Foundation', 'Security']],
    [names[3], 'stable-launch', ['Foundation', 'Security']]]) {
    const flags = [...input.installationPaths.flags, ...(source !== names[1] ? input.productionPublisher.flags : [])];
    staticCommand('/usr/bin/xcrun', [...common, ...flags, source, ...frameworks.flatMap(value => ['-framework', value]), '-o', join(root, 'dist/native', name)]);
  }
  const outputs = {};
  for (const name of platformCompilerPolicy.outputs) {
    const path = join(root, 'dist/native', name);
    if (staticCommand('/usr/bin/lipo', ['-archs', path]) !== 'arm64') throw new Error('Platform architecture mismatch');
    outputs[name] = hash(await readFile(path));
  }
  const symbols = staticCommand('/usr/bin/nm', ['-gU', join(root, 'dist/native/platform.node')]);
  if (!symbols.includes('_napi_register_module_v1') || !symbols.includes('_node_api_module_get_api_version_v1')) throw new Error('Platform registration mismatch');
  if (inventoryDigest(before) !== inventoryDigest(await sources()) || JSON.stringify(input) !== JSON.stringify(await captureCompilerInputs(names, headers)))
    throw new Error('Platform source/compiler input changed');
  await writeFile(join(root, 'dist/native/platform-compile.json'), JSON.stringify({ format: 1, sources: before, input, outputs }, null, 2) + '\n');
  await validatePlatformCompilation();
  console.log('Compiled/inspected platform, fixed bootstrap, LaunchServices helper and installed launcher');
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('compile-platform.mjs accepts only the exact pinned header provider');
  await compilePlatform(process.env.NODE_API_HEADERS ?? officialHeaders);
}
