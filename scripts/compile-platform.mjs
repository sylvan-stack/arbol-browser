import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Only Darwin arm64 process support is implemented');
const headers = process.env.NODE_API_HEADERS ?? ['/opt/homebrew/include/node', '/usr/local/include/node']
  .find(path => existsSync(`${path}/node_api.h`));
if (!headers || !existsSync(`${headers}/node_api.h`)) throw new Error('Set NODE_API_HEADERS to development Node-API headers');
const output = resolve(root, 'dist/native/platform.node');
mkdirSync(dirname(output), { recursive: true });
const result = spawnSync('/usr/bin/xcrun', ['clang++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
  '-fobjc-arc', '-DNAPI_VERSION=8', '-DNODE_GYP_MODULE_NAME=arbol_browser_platform', '-arch', 'arm64',
  '-mmacosx-version-min=27.0', '-bundle', '-undefined', 'dynamic_lookup', '-I', headers,
  resolve(root, 'src/runtime/platform.mm'), '-lbsm', '-framework', 'Foundation', '-framework', 'Security', '-o', output], { stdio: 'inherit' });
if (result.error || result.status !== 0) throw new Error('Process support compilation failed');
console.log('Compiled private Darwin process support (Node-API 8); no behavioral checks run');

for (const [source, name, frameworks] of [
  ['host-launch.mm', 'host-launch', ['AppKit']],
  ['host-bootstrap.mm', 'host-bootstrap', ['Foundation', 'Security']],
]) {
  const executable = spawnSync('/usr/bin/xcrun', ['clang++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
    '-fobjc-arc', '-arch', 'arm64', '-mmacosx-version-min=27.0', resolve(root, 'src/runtime', source),
    ...frameworks.flatMap(name => ['-framework', name]), '-o', resolve(root, 'dist/native', name)], { stdio: 'inherit' });
  if (executable.error || executable.status !== 0) throw new Error('Host support compilation failed');
}
console.log('Compiled one-shot LaunchServices support and isolated native app bootstrap; no engine launched');
