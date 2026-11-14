// Testing only. Never supplies engine trust, native readiness or exit authority.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, readdir, readlink, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

export { assert, delay };
export const opaque = prefix => `${prefix}_${randomBytes(16).toString('base64url')}`;
export const digest = value => createHash('sha256').update(value).digest('hex');
export const load = (context, name) => import(pathToFileURL(join(context.candidate, 'lib', `${name}.js`)));
export async function privateDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
  return realpath(path);
}
export async function fixture(context, name) {
  const root = await privateDirectory(join(context.output, name));
  const home = await privateDirectory(join(root, 'home'));
  await privateDirectory(join(home, 'Library/Application Support/Arbol'));
  return { ...context, root, home, state: join(home, 'Library/Application Support/Arbol/browser') };
}
export function environment(context) {
  // A closed environment excludes owner credentials and launcher/runtime overrides.
  return { HOME: context.home, PATH: '/usr/bin:/bin', TMPDIR: `${context.root}/`,
    ELECTRON_RUN_AS_NODE: '1', LANG: 'en_US.UTF-8' };
}
export function execute(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], ...options });
  let stdout = '', stderr = '';
  const done = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Fixture process exceeded 20 s')); }, 20000);
    child.stdout.on('data', bytes => { stdout += bytes; });
    child.stderr.on('data', bytes => { stderr += bytes; });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (status, signal) => { clearTimeout(timer); resolve({ status, signal, stdout, stderr }); });
  });
  child.stdin.end(options.input ?? '');
  return { child, done };
}
export async function cli(context, args, input = '') {
  const result = await execute(join(context.candidate, 'bin/arbol-browser'), args,
    { cwd: context.root, env: environment(context), input }).done;
  const lines = result.stdout.trim().split('\n').filter(Boolean);
  if (args[0] === 'mcp') assert.equal(result.stdout, '', 'MCP failure must not emit a CLI JSON result');
  else {
    assert.equal(lines.length, 1, `Expected exactly one CLI JSON document: ${result.stderr}`);
    result.value = JSON.parse(lines[0]);
  }
  return result;
}
export async function snapshot(root) {
  const result = {};
  async function visit(path, name) {
    let st;
    try { st = await lstat(path); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
    result[name] = { dev: st.dev, ino: st.ino, mode: st.mode, uid: st.uid, nlink: st.nlink,
      ...(st.isFile() ? { bytes: digest(await readFile(path)) } : {}),
      ...(st.isSymbolicLink() ? { link: await readlink(path) } : {}) };
    if (st.isDirectory()) for (const item of (await readdir(path)).sort()) await visit(join(path, item), `${name}/${item}`);
  }
  await visit(root, '.');
  return result;
}
export async function dataSentinel(path, text = 'fictional qualification data\n') {
  await writeFile(path, text, { mode: 0o600 });
}
export function refused(result, status, code) {
  assert.equal(result.status, status, result.stderr);
  assert.equal(result.value?.error?.code, code);
}
