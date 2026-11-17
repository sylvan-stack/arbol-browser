// Testing only: real allocated signed entry and protected Unix wire. No host,
// engine, exit, readiness or action authority is supplied by this harness.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, readFile, writeFile, lstat, realpath } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
export { assert, delay };
export const hash = value => createHash('sha256').update(value).digest('hex');
export const token = prefix => `${prefix}_${randomBytes(16).toString('base64url')}`;
export const load = (context, name) => import(pathToFileURL(join(context.payload, 'lib', name + '.js')));
export async function save(path, value) {
  await writeFile(path, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
}
export async function until(observe, milliseconds = 8000) {
  const end = performance.now() + milliseconds;
  do { const value = await observe(); if (value) return value; await delay(50); } while (performance.now() < end);
  throw new Error('Required independent observation unavailable before deadline');
}
export async function contextFor(input, id) {
  const output = join(input.output, id); await mkdir(output, { mode: 0o700 });
  const home = join(output, 'home'); await mkdir(home, { mode: 0o700 });
  const buildRoot = await realpath(input.buildRoot), build = buildRoot.split('/').at(-1);
  const recordPath = join(buildRoot, 'build.json'), originalRecord = await readFile(recordPath);
  const record = JSON.parse(originalRecord);
  assert.equal(record.status, 'building', 'Control must run inside the ordinary allocated Building gate');
  assert.equal(record.component, 'arbol-browser'); assert.equal(record.build, build);
  assert.equal(record.source.uncommittedChanges, false);
  assert.equal(record.source.commit, execFileSync('/usr/bin/git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim());
  const guard = join(dirname(buildRoot), '.uses', build), st = await lstat(guard);
  assert.ok(st.isFile() && st.uid === process.getuid() && (st.mode & 0o7777) === 0o600 && st.nlink === 1);
  const policy = JSON.parse(await readFile(join(dirname(input.payload), 'host-policy.json'), 'utf8'));
  const state = policy.stateRoot;
  assert.equal(state, join(dirname(dirname(dirname(buildRoot))), 'browser-state'));
  const selection = { format: 1, build, explicit: true, directory: buildRoot, guard };
  const c = { ...input, id, output, home, buildRoot, build, state, selection, originalRecord,
    recordPath, calls: [], peers: [], profiles: new Set(), guardIdentity: { dev: st.dev, ino: st.ino } };
  await save(join(output, 'allocation.json'), { record, recordSha256: hash(originalRecord), selection,
    guardIdentity: c.guardIdentity, payload: input.payload, state });
  return c;
}
export async function cli(c, args) {
  const sequence = c.calls.length + 1;
  const row = { sequence, args, startedAt: new Date().toISOString() }; c.calls.push(row);
  await save(join(c.output, 'calls.json'), c.calls);
  const result = await new Promise((resolve, reject) => {
    const child = spawn(join(c.buildRoot, 'bin/arbol-browser'), args, { cwd: c.output,
      env: { HOME: c.home, PATH: '/usr/bin:/bin', LANG: 'en_US.UTF-8', TMPDIR: c.output + '/',
        ARBOL_BROWSER_SELECTION: JSON.stringify(c.selection) }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Actual CLI exceeded 45 s')); }, 45000);
    child.stdout.on('data', b => { stdout += b; }); child.stderr.on('data', b => { stderr += b; });
    child.once('error', e => { clearTimeout(timer); reject(e); });
    child.once('close', (status, signal) => { clearTimeout(timer); resolve({ status, signal, stdout, stderr }); });
  });
  Object.assign(row, result, { finishedAt: new Date().toISOString() });
  await save(join(c.output, 'calls.json'), c.calls);
  const lines = result.stdout.trim().split('\n').filter(Boolean);
  assert.equal(lines.length, 1, 'CLI must return exactly one real JSON result: ' + result.stderr);
  return { ...result, value: JSON.parse(lines[0]) };
}
export function success(result) { assert.equal(result.status, 0, JSON.stringify(result)); return result.value; }
export async function create(c, profile) {
  const result = success(await cli(c, ['profiles', 'create', profile])); c.profiles.add(profile); return result;
}
export async function open(c, profile, url) {
  const value = success(await cli(c, ['open', '--profile', profile, ...(url ? ['--url', url] : [])]));
  c.profiles.add(profile); return value;
}
export async function runtime(c, profile) {
  const [{ readProfile }, { profilePaths }, { runtimeLocation, readRuntime }, { loadPlatform }] = await Promise.all([
    load(c, 'profiles/records'), load(c, 'profiles/paths'), load(c, 'runtime/instance'), load(c, 'runtime/platform')]);
  const p = await readProfile(profilePaths(profile, c.state)), location = await runtimeLocation(p);
  assert.ok(location); const record = await readRuntime(location); assert.ok(record);
  const platform = loadPlatform(), identity = platform.processIdentity(record.pid);
  assert.ok(identity); assert.equal(identity.startId, record.processStartId);
  assert.equal(identity.uid, process.getuid());
  return { location, record, platform, identity };
}
export async function agent(c, profile, label) {
  const r = await runtime(c, profile), { connectRuntime } = await load(c, 'runtime/transport');
  const client = await connectRuntime(r.location, r.record, 'agent', c.selection, r.platform, performance.now() + 5000, label);
  c.peers.push(client); return client;
}
export const tool = (client, name, args = {}) => client.call({ wire: 1, id: token('req'), method: 'tool', params: { name, arguments: args } });
export async function closes(c, profile) { return success(await cli(c, ['close', '--profile', profile])); }
export function processSnapshot() {
  return execFileSync('/bin/ps', ['-axo', 'pid=,ppid=,lstart=,comm='], { encoding: 'utf8' });
}
export async function family(c, label) {
  // Inspect the OS census in memory. Persist only this exact package's rows,
  // never unrelated owner process arguments or the Node-mode gate worker.
  const rows = processSnapshot().split('\n').filter(line => line.includes(c.buildRoot + '/ArbolBrowser.app/') &&
    Number(line.trim().split(/\s+/)[0]) !== process.pid);
  await save(join(c.output, label + '-processes.json'), rows); return rows;
}
export async function finish(c) {
  for (const peer of c.peers) peer.close();
  // Always try the real bounded close, including after an assertion fails.
  // Failed close is retained and never converted into qualification success.
  const cleanup = [];
  for (const profile of c.profiles) {
    try { const result = await cli(c, ['close', '--profile', profile]); cleanup.push({ profile, result }); success(result); }
    catch (error) { cleanup.push({ profile, error: String(error.stack ?? error) }); }
  }
  await save(join(c.output, 'cleanup.json'), cleanup);
  assert.ok(cleanup.every(row => !row.error), 'Real profile cleanup failed; inspect cleanup.json');
  assert.deepEqual(await family(c, 'after-cleanup'), [], 'Owned package process survived actual cleanup');
  assert.deepEqual(await readFile(c.recordPath), c.originalRecord, 'Gate changed the original Building record');
  const st = await lstat(c.selection.guard); assert.deepEqual({ dev: st.dev, ino: st.ino }, c.guardIdentity);
}
export async function loopback(c) {
  const observations = [], arms = new Map();
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/arm') { arms.set(url.searchParams.get('name'), res); return; }
    if (url.pathname === '/seen') {
      observations.push({ name: url.searchParams.get('name'), cookie: req.headers.cookie ?? '', stored: url.searchParams.get('stored') });
      res.end('ok'); return;
    }
    const name = url.searchParams.get('name') ?? 'page', seed = url.searchParams.get('seed');
    res.setHeader('Content-Type', 'text/html'); res.setHeader('Cache-Control', 'no-store');
    res.end(`<!doctype html><title>Fictional qualification ${name}</title><input aria-label="Fictional field"><script>
      ${seed ? `document.cookie='fictional=${seed}; Max-Age=3600; SameSite=Lax'; localStorage.setItem('fictional',${JSON.stringify(seed)});` : ''}
      fetch('/seen?name='+${JSON.stringify(name)}+'&stored='+encodeURIComponent(localStorage.getItem('fictional')));
      fetch('/arm?name='+${JSON.stringify(name)}).then(r=>r.text()).then(v=>{if(v==='hang')for(;;){}});
      </script>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { observations, url: (name, seed) => `${base}/?name=${name}${seed ? '&seed=' + seed : ''}`,
    async hang(name) { const response = await until(() => arms.get(name)); response.end('hang'); },
    async close() { for (const res of arms.values()) if (!res.writableEnded) res.end('stop'); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
      await save(join(c.output, 'loopback-observations.json'), observations); } };
}
