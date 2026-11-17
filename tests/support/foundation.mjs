// Testing only. Never supplies engine trust, native readiness or exit authority.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createConnection } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, readdir, readlink, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
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
  const result = await execute(process.execPath, [fileURLToPath(import.meta.url), '--fixture-cli',
    JSON.stringify({ candidate: context.candidate, state: context.state, args })],
    { cwd: context.root, env: environment(context), input }).done;
  const lines = result.stdout.trim().split('\n').filter(Boolean);
  if (args[0] === 'mcp') assert.equal(result.stdout, '', 'MCP failure must not emit a CLI JSON result');
  else {
    assert.equal(lines.length, 1, `Expected exactly one CLI JSON document: ${result.stderr}`);
    result.value = JSON.parse(lines[0]);
  }
  return result;
}

// Preserve the Foundation's explicit no-host scope using the same physical
// packaged production modules. The sealed production entry runs separately in
// Control; this worker supplies neither integration nor any admission authority.
if (process.argv[2] === '--fixture-cli') {
  const input = JSON.parse(process.argv[3]);
  const [{ runCli }, { createProfileService }, { loadPlatform }, { createProcessService, createProfileRuntime }] = await Promise.all([
    load(input, 'cli/main'), load(input, 'profiles/manage'), load(input, 'runtime/platform'), load(input, 'runtime/lifecycle')]);
  const metadata = JSON.parse(await readFile(join(input.candidate, 'metadata.json'), 'utf8'));
  const platform = loadPlatform(), selection = { build: metadata.component.build, explicit: false, directory: input.candidate, guard: '' };
  process.exitCode = await runCli(input.args, {
    profiles: createProfileService({ state: input.state, platform: () => platform, runtime: createProfileRuntime(platform, selection) }),
    process: createProcessService({ state: input.state, selection, platform: () => platform }),
  });
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
export async function bounded(promise, milliseconds = 2000) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Observation exceeded ${milliseconds} ms`)), milliseconds);
  })]); } finally { clearTimeout(timer); }
}
export async function rawConnection(path) {
  const socket = createConnection(path), frames = [], readers = [];
  let pending = '';
  const closed = new Promise(resolve => socket.once('close', resolve));
  socket.on('error', () => {});
  socket.on('data', bytes => {
    pending += bytes;
    let newline;
    while ((newline = pending.indexOf('\n')) >= 0) {
      const value = JSON.parse(pending.slice(0, newline)); pending = pending.slice(newline + 1);
      if (readers.length) readers.shift()(value); else frames.push(value);
    }
  });
  await bounded(new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); }));
  return { socket, closed, send(value) { socket.write(`${JSON.stringify(value)}\n`); },
    next() { return bounded(frames.length ? Promise.resolve(frames.shift()) : new Promise(resolve => readers.push(resolve))); } };
}

export async function worker(context, task, input) {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), '--worker', task,
    JSON.stringify({ candidate: context.candidate, ...input })],
  { cwd: context.root, env: environment(context), stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', bytes => { stderr += bytes; });
  const lines = createInterface({ input: child.stdout });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', status => { lines.close(); status === 0 ? resolve() : reject(new Error(`Worker ${task}: ${status}: ${stderr}`)); });
  });
  // Attach immediately, including when readiness fails before the caller can await done.
  done.catch(() => {});
  const ready = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Worker ${task} not ready: ${stderr}`)), 5000);
    lines.once('line', line => { clearTimeout(timer); try { resolve(JSON.parse(line)); } catch (error) { reject(error); } });
    child.once('exit', status => { clearTimeout(timer); reject(new Error(`Worker ${task} exited before readiness (${status}): ${stderr}`)); });
  }).catch(error => { child.kill('SIGKILL'); throw error; });
  let stopped = false;
  return { child, ready, done, async stop() { if (!stopped) { stopped = true; child.stdin.end('release\n'); } await done; } };
}

// Real process fixtures exercise only no-engine interfaces. No permissive
// StartAuthority/PreviousExit/EngineExitEvidence implementation lives here.
if (process.argv[2] === '--worker') {
  const task = process.argv[3], input = JSON.parse(process.argv[4]);
  const { loadPlatform } = await load(input, 'runtime/platform');
  const platform = loadPlatform();
  const { now, acquireInstance, neverOpenedExit } = await load(input, 'runtime/instance');
  const { readProfile } = await load(input, 'profiles/records');
  const { profilePaths } = await load(input, 'profiles/paths');
  const { acquireBuildLease } = await load(input, 'runtime/build-lease');
  const commands = createInterface({ input: process.stdin });
  if (task === 'starter') {
    const { createStarter, unresolvedStartups } = await load(input, 'runtime/start');
    const profile = await readProfile(profilePaths(input.profile, input.state));
    const { unavailable } = await load(input, 'contracts/errors');
    let launches = 0;
    const start = createStarter({ selection: input.selection, platform,
      acquireBuild: () => acquireBuildLease(input.selection, platform),
      authority: {
        async assertTrusted() { throw unavailable('browser'); },
        async assertReady() { throw unavailable('browser'); },
        async assertFailed() { throw unavailable('browser'); },
      }, launch: { async launch() { ++launches; throw new Error('Unexpected launch'); } } });
    const began = now(); let code;
    try { await start(profile, 'management', began + 500, began + 500); }
    catch (error) { code = error.detail?.code; }
    assert.ok(code, 'Starter unexpectedly succeeded');
    assert.equal(unresolvedStartups().length, 0, 'No launch was attempted; no retained guard may remain');
    console.log(JSON.stringify({ code, launches, elapsed: now() - began }));
    commands.close(); process.stdin.destroy();
  } else {
    let held, ready;
    if (task === 'owner') {
      const profile = await readProfile(profilePaths(input.profile, input.state));
      held = await acquireInstance(profile, platform, input.build, neverOpenedExit, now() + 2000);
      assert.ok(held); ready = { pid: process.pid, record: held.record, runtime: held.location.leaf };
    } else if (task === 'lock-probe') {
      held = platform.tryLock(input.path); ready = { pid: process.pid, acquired: Boolean(held) };
    } else if (task === 'lease') {
      held = await acquireBuildLease(input.selection, platform); ready = { pid: process.pid };
    } else throw new Error('Unknown worker');
    const release = new Promise(resolve => commands.once('line', resolve));
    console.log(JSON.stringify(ready));
    await release;
    if (task === 'owner') held.owner.release(); else held?.release();
    commands.close(); process.stdin.destroy();
  }
}
