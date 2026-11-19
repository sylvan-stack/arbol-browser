import { spawn, spawnSync } from 'node:child_process';
import { access, mkdtemp, realpath, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import installation from '../src/runtime/installation-paths.json' with { type: 'json' };

const require = createRequire(import.meta.url);
const { privateDirectory } = require('../src/demo/profile-storage.cjs');
const root = fileURLToPath(new URL('../', import.meta.url));
const options = process.argv.slice(2);

if (options.length === 1 && options[0] === '--help') {
  console.log('Usage: npm run demo -- [--fixture | --url <http-or-https-url>] [--visible]');
  process.exit(0);
}

async function run() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64')
    throw new Error('The local preview needs macOS on Apple silicon.');
  if (options.some(option => Buffer.byteLength(option) > 8192))
    throw new Error('Preview option is too long.');
  const distribution = join(dirname(require.resolve('electron/package.json')), 'dist', 'Electron.app');
  const executable = await realpath(join(distribution, 'Contents/MacOS/Electron'));
  const framework = await realpath(join(distribution, 'Contents/Frameworks/Electron Framework.framework/Electron Framework'));
  const headers = process.env.NODE_API_HEADERS ?? '/opt/homebrew/include/node';
  await access(join(headers, 'node_api.h'));

  const scratch = await mkdtemp(join(await realpath(tmpdir()), 'arbol-browser-demo-'));
  try {
    const storage = options.includes('--fixture') ? scratch :
      privateDirectory(join(privateDirectory(join(await realpath(homedir()), installation.root)), 'browser-preview'));
    const userData = privateDirectory(join(storage, 'instance'));
    const sessionData = storage;
    const profiles = privateDirectory(join(storage, 'site-profiles'));
    const addon = join(scratch, 'clipboard.node');
    const env = { PATH: '/usr/bin:/bin', HOME: process.env.HOME, LANG: 'en_US.UTF-8', TMPDIR: scratch };
    const compiled = spawnSync('/usr/bin/xcrun', ['clang++', '-std=c++17', '-fobjc-arc', '-fblocks',
      '-Wno-deprecated-declarations', '-DNAPI_VERSION=8', '-arch', 'arm64', '-bundle',
      '-undefined', 'dynamic_lookup', '-I', headers, join(root, 'src/demo/clipboard.mm'),
      '-framework', 'AppKit', '-framework', 'Security', '-framework', 'Foundation', '-lbsm', '-o', addon],
    { env, stdio: 'inherit', timeout: 30000 });
    if (compiled.status !== 0) throw new Error('Could not compile the local clipboard protection.');
    return await new Promise((resolve, reject) => {
      const child = spawn(executable, [join(root, 'src/demo/browser.cjs'), ...options], {
        cwd: scratch, env: { ...env, ARBOL_DEMO_USER_DATA: userData, ARBOL_DEMO_SESSION_DATA: sessionData,
          ARBOL_DEMO_CLIPBOARD: addon, ARBOL_DEMO_FRAMEWORK: framework, ARBOL_DEMO_PROFILES: profiles },
        stdio: 'inherit',
      });
      child.once('error', reject);
      child.once('exit', (code, signal) => resolve(code ?? (signal === 'SIGINT' ? 130 : 1)));
    });
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

try { process.exitCode = await run(); }
catch (error) {
  console.error('Arbol Browser preview could not start. ' + error.message);
  process.exitCode = 1;
}
