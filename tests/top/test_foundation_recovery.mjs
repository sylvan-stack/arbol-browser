import { join } from 'node:path';
import { writeFile, readFile } from 'node:fs/promises';
import { assert, fixture, cli, load, snapshot, dataSentinel, refused, opaque, bounded, rawConnection, delay, privateDirectory } from '../support/foundation.mjs';

export async function preservationBoundary(context) {
  const f = await fixture(context, 'preservation');
  const absent = await snapshot(f.home);
  assert.equal((await cli(f, ['close'])).value.closed, false);
  refused(await cli(f, ['close', '--profile', 'missing']), 3, 'profile_not_found');
  refused(await cli(f, ['open']), 4, 'browser_unavailable');
  assert.equal((await cli(f, ['mcp'])).status, 4);
  assert.deepEqual(await snapshot(f.home), absent, 'Unavailable open/MCP or missing close created/fell back to a profile');
  assert.equal((await cli(f, ['profiles', 'create', 'retained'])).status, 0);
  const profile = join(f.state, 'profiles/retained');
  await dataSentinel(join(profile, 'data/retained'));
  const before = await snapshot(f.state);
  refused(await cli(f, ['profiles', 'remove', 'retained', '--delete-data'], 'retained\n'), 5, 'control_refused');
  refused(await cli(f, ['profiles', 'remove', 'default', '--delete-data'], 'default\n'), 2, 'invalid_input');
  assert.equal((await cli(f, ['close', '--profile', 'retained'])).value.closed, false);
  assert.deepEqual(await snapshot(f.state), before, 'Close or piped destructive confirmation changed data');

  const recordPath = join(profile, 'profile.json'), original = await readFile(recordPath, 'utf8');
  await writeFile(recordPath, JSON.stringify({ ...JSON.parse(original), format: 9001 }) + '\n');
  const unknown = await snapshot(f.state);
  refused(await cli(f, ['profiles', 'list']), 4, 'profile_unavailable');
  refused(await cli(f, ['profiles', 'create', 'retained']), 4, 'profile_unavailable');
  refused(await cli(f, ['close', '--profile', 'retained']), 4, 'profile_unavailable');
  assert.deepEqual(await snapshot(f.state), unknown, 'Unsupported record changed payload or lock identity');
  await writeFile(recordPath, original);
  const markerPath = join(profile, 'engine.json');
  await writeFile(markerPath, JSON.stringify({ format: 9001, preserved: 'fictional future engine marker' }) + '\n', { mode: 0o600 });
  const markerBefore = await snapshot(f.state);
  refused(await cli(f, ['profiles', 'remove', 'retained', '--delete-data']), 4, 'profile_unavailable');
  refused(await cli(f, ['close', '--profile', 'retained']), 4, 'profile_unavailable');
  assert.deepEqual(await snapshot(f.state), markerBefore);
  // Syntactically supported future reader state still cannot be opened with
  // missing production trust/native services. This does NOT qualify the reader
  // allow-list transaction beyond that earlier refusal boundary.
  await writeFile(markerPath, JSON.stringify({ format: 1, profileInstance: JSON.parse(original).instance,
    engine: 'chromium', dataEpoch: 2, requiredReader: 'fictional-future-reader', lastWriterBuild: 'f',
    lastWriterElectron: 'future', lastWriterChromium: 'future', cleanExit: false }) + '\n');
  const readerBefore = await snapshot(f.state);
  refused(await cli(f, ['open', '--profile', 'retained']), 4, 'browser_unavailable');
  refused(await cli(f, ['close', '--profile', 'retained']), 4, 'profile_unavailable');
  refused(await cli(f, ['profiles', 'list']), 4, 'profile_unavailable');
  assert.deepEqual(await snapshot(f.state), readerBefore, 'Uncertain exit was marked clean or data was replaced');
  return { absentDefaultPreserved: true, pipedConfirmationRefused: true, unsupportedBytesPreserved: true,
    readerTransaction: 'unavailable: no production signed EngineAuthority',
    completeClose: 'unavailable: no complete original-helper/flush authority', nativeAdmission: 'refused' };
}

export async function transportBoundary(context) {
  const base = await fixture(context, 'transport');
  const home = await privateDirectory(join(base.home, 'long-data-path-'.repeat(6), 'retained-profile-home-'.repeat(5)));
  await privateDirectory(join(home, 'Library/Application Support/Arbol'));
  const f = { ...base, home, state: join(home, 'Library/Application Support/Arbol/browser') };
  assert.equal((await cli(f, ['profiles', 'create', 'transport'])).status, 0);
  const { loadPlatform } = await load(f, 'runtime/platform'), platform = loadPlatform();
  const { readProfile } = await load(f, 'profiles/records');
  const { profilePaths } = await load(f, 'profiles/paths');
  const { acquireInstance, neverOpenedExit, now } = await load(f, 'runtime/instance');
  const { listenTransport, connectRuntime } = await load(f, 'runtime/transport');
  const p = await readProfile(profilePaths('transport', f.state));
  const instance = await acquireInstance(p, platform, 'a', neverOpenedExit, now() + 2000);
  assert.ok(instance);
  const peers = [], disconnected = [], cancelled = [];
  let executions = 0, commits = 0, finish, dispatched;
  const started = new Promise(resolve => { dispatched = resolve; });
  const server = await listenTransport(instance.location, instance.record, platform, {
    authorize(c) { peers.push(c.peer); },
    execute(c, request, deadline, signal) {
      ++executions; dispatched(signal);
      return new Promise(resolve => { finish = resolve; });
    },
    commit() { ++commits; },
    disconnect(c) { disconnected.push(c); }, cancel(c, id) { cancelled.push(id); },
    fatal() { throw new Error('Transport unexpectedly entered fatal path'); },
  });
  const connections = [], clients = [];
  try {
    server.openAdmission(); await instance.phase('ready');
    const record = instance.record, location = instance.location;
    assert.ok(Buffer.byteLength(p.paths.root, 'utf8') > 103, 'Fixture must exceed Darwin socket path capacity');
    assert.ok([location.agent, location.management].every(path => Buffer.byteLength(path, 'utf8') + 1 <= 104));
    assert.equal(location.hash, (await import('node:crypto')).createHash('sha256').update(p.paths.root, 'utf8').digest('hex'));
    const selection = { build: 'b', explicit: false, directory: context.candidate, guard: '' };
    const positive = await connectRuntime(location, record, 'agent', selection, platform, now() + 2000);
    clients.push(positive);
    const manage = await connectRuntime(location, record, 'management', selection, platform, now() + 2000);
    clients.push(manage);
    assert.ok(positive.hello.attachment); assert.equal(manage.hello.attachment, undefined);
    assert.equal(positive.hello.build, 'a', 'Normal attachment substituted selected Build for actual running Build');
    await assert.rejects(connectRuntime(location, record, 'agent', { ...selection, explicit: true }, platform, now() + 2000));
    const hello = overrides => ({ wire: 1, id: opaque('req'), method: 'hello', params: {
      profile: record.profile, profileInstance: record.profileInstance, instance: record.instance,
      nonce: record.nonce, contract: 1, label: 'Fictional fixture', ...overrides } });
    const wrongNonce = await rawConnection(location.agent); connections.push(wrongNonce);
    wrongNonce.send(hello({ nonce: Buffer.alloc(32, 7).toString('base64url') }));
    await bounded(wrongNonce.closed);
    const mismatch = await rawConnection(location.management); connections.push(mismatch);
    mismatch.send(hello({ expectedBuild: 'b' })); await bounded(mismatch.closed);
    const wrongRole = await rawConnection(location.agent); connections.push(wrongRole);
    wrongRole.send(hello({})); assert.equal((await wrongRole.next()).ok, true);
    wrongRole.send({ wire: 1, id: opaque('req'), method: 'close', params: {} });
    await bounded(wrongRole.closed);
    const malformed = await rawConnection(location.management); connections.push(malformed);
    malformed.socket.write(Buffer.from([0xff, 0x0a])); await bounded(malformed.closed);
    const oversized = await rawConnection(location.agent); connections.push(oversized);
    oversized.socket.write(Buffer.alloc(1024 * 1024 + 1, 97)); await bounded(oversized.closed);
    assert.equal(executions, 0, 'Rejected peer/frame reached a dispatcher');
    assert.equal(positive.signal.aborted, false, 'A rejected connection disconnected an independent client');

    const request = { wire: 1, id: opaque('req'), method: 'tool', params: { name: 'browser_tabs_list', arguments: {} } };
    let settled = false;
    const pending = positive.call(request).then(() => { settled = true; return 'completed'; }, () => 'rejected');
    const signal = await bounded(started);
    const ack = await positive.cancel(request.id);
    assert.equal(ack.found, true); assert.equal(signal.aborted, true);
    assert.deepEqual(cancelled, [request.id]);
    assert.equal(peers[0].uid, process.geteuid()); assert.equal(peers[0].pid, process.pid);
    assert.equal(peers[0].startId, platform.processIdentity(process.pid).startId);
    finish({ tabs: [] }); await delay(50);
    assert.equal(commits, 0); assert.equal(settled, false, 'Cancelled late response escaped');
    positive.close(); assert.equal(await pending, 'rejected');

    const silent = await rawConnection(location.management); connections.push(silent);
    silent.send(hello({})); assert.equal((await silent.next()).ok, true);
    const began = now(); await bounded(silent.closed, 8500);
    const elapsed = now() - began;
    assert.ok(elapsed >= 5000 && elapsed < 8500, `Silent peer expiry ${elapsed} ms`);
    assert.equal(manage.signal.aborted, false, 'Healthy ping/pong connection lost with silent peer');
    assert.ok(disconnected.length >= 3);
    return { nativePeer: peers[0], rejectedBeforeDispatch: ['nonce', 'explicit Build', 'endpoint role', 'UTF-8', 'oversize'],
      lateCancelledResponseSuppressed: true, silentPeerElapsed: elapsed,
      scope: 'Transport only; no engine, page, native-input or complete-close authority' };
  } finally {
    for (const raw of connections) raw.socket.destroy();
    for (const client of clients) client.close();
    await server.close(); instance.owner.release();
  }
}
