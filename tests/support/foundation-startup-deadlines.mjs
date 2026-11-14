// Testing only: actual packaged clients/guards, explicitly synthetic upstream
// admission/readiness predicates. Never a production native or host authority.
import { registerHooks } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { load, bounded } from './foundation.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
async function qualifiedModule(context, name, state, dependencies) {
  const original = name => pathToFileURL(join(context.candidate, 'lib', `${name}.js`)).href;
  const key = `__abr32_${randomBytes(12).toString('hex')}`;
  const target = `${original(name)}?qualification=${key}`;
  globalThis[key] = state;
  const adapters = new Map(Object.entries(dependencies).map(([name, exports]) => [original(name),
    `export * from ${JSON.stringify(original(name))};\n${exports.map(([symbol, method]) =>
      `export const ${symbol} = (...args) => globalThis[${JSON.stringify(key)}].${method}(...args);`).join('\n')}`]));
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    const result = nextResolve(specifier, context);
    if (context.parentURL !== target || !adapters.has(result.url)) return result;
    return { url: `data:text/javascript,${encodeURIComponent(adapters.get(result.url))}`, shortCircuit: true };
  } });
  try { return { module: await import(target), forget: () => { delete globalThis[key]; } }; }
  catch (error) { delete globalThis[key]; throw error; }
  finally { hooks.deregister(); }
}

export async function startupLifecycle(context, mode, acquire) {
  const clock = await load(context, 'runtime/instance');
  const { unavailable } = await load(context, 'contracts/errors');
  const acquired = deferred(), returned = deferred();
  let deadline, returning = false, checks = 0, expired = false;
  const resources = []; // Strong references exclude garbage collection.
  const state = {
    now: () => expired ? deadline + 1 : clock.now(),
    startupDeadline() { deadline = clock.now() + (mode === 'late' ? 1000 : 10000); return deadline; },
    assertTime(limit) {
      if (returning && limit === deadline && ++checks >=
          (mode === 'post-wait' ? 1 : mode === 'transfer' ? 2 : Infinity)) expired = true;
      if (state.now() >= limit) throw unavailable('browser');
    },
  };
  const scoped = await qualifiedModule(context, 'runtime/lifecycle', state, {
    'runtime/instance': [['now', 'now'], ['assertTime', 'assertTime'], ['startupDeadline', 'startupDeadline']],
  });
  return { ...scoped.module, resources,
    acquired: () => bounded(acquired.promise), settle: returned.resolve,
    get clockChecks() { return checks; },
    async start(profile, endpoint, limit, _contention, label) {
      if (mode === 'reject') throw unavailable('browser'); // No acquired value is concealed.
      const result = await acquire(profile, endpoint, limit, label);
      resources.push(result.client); acquired.resolve();
      await returned.promise; returning = true;
      return result;
    },
    async cleanup() {
      returned.resolve(); await new Promise(resolve => setImmediate(resolve));
      for (const client of resources) client.close();
      scoped.forget();
    },
  };
}

export async function startupStarter(context, { branch, mode, profile, selection, platform, publish }) {
  const clock = await load(context, 'runtime/instance');
  const transport = await load(context, 'runtime/transport');
  const { acquireBuildLease } = await load(context, 'runtime/build-lease');
  const { unavailable } = await load(context, 'contracts/errors');
  let deadline, reads = 0, checks = 0, transferring = false, expired = false, releaseFault = false;
  let simulatedLaunches = 0, failedAttemptRefusals = 0;
  const resources = [], leases = [], predicates = [];
  const state = {
    now: () => expired ? deadline + 1 : clock.now(),
    assertTime(limit) {
      if (transferring && limit === deadline && ++checks >= (mode === 'final' ? 2 : Infinity)) expired = true;
      if (state.now() >= limit) throw unavailable('browser');
    },
    async readRuntime(location) {
      const observed = await clock.readRuntime(location);
      if (++reads === 1 && branch === 'arbitrated') {
        if (observed) throw new Error('Arbitrated fixture must begin with an absent runtime');
        // Publish only after the actual first absent read, preserving its value.
        await publish();
      }
      return observed;
    },
    async connectRuntime(...args) {
      const client = await transport.connectRuntime(...args);
      resources.push(client); return client;
    },
  };
  const scoped = await qualifiedModule(context, 'runtime/start', state, {
    'runtime/instance': [['now', 'now'], ['assertTime', 'assertTime'], ['readRuntime', 'readRuntime']],
    'runtime/transport': [['connectRuntime', 'connectRuntime']],
  });
  // These predicates deliberately simulate only the upstream hand-over. They
  // verify no signature/native readiness/engine/helper state and never enter a
  // production payload. The real assertion is acquired-client socket cleanup.
  const authority = {
    async assertTrusted() { predicates.push('synthetic-publisher-boundary'); },
    async assertReady() {
      predicates.push('synthetic-native-readiness-boundary');
      if (mode === 'readiness') throw unavailable('browser');
      transferring = true;
    },
    async assertFailed() {
      ++failedAttemptRefusals;
      // Never grant fake exit evidence to release a retained startup attempt.
      throw unavailable('browser');
    },
  };
  const start = scoped.module.createStarter({ selection, platform, authority,
    async acquireBuild() {
      const lease = await acquireBuildLease(selection, platform); leases.push(lease);
      return { assert: () => lease.assert(), release() {
        if (transferring && mode === 'guard-release' && !releaseFault) {
          releaseFault = true; throw new Error('Testing-only guard transfer failure');
        }
        lease.release();
        if (transferring && mode === 'post-release') expired = true;
      } };
    },
    launch: { async launch() {
      ++simulatedLaunches;
      // No LaunchServices, process, host or engine is started. Publish only the
      // explicitly synthetic transport fixture in this already-running process.
      await publish(); return process.pid;
    } },
  });
  return { resources, leases, predicates,
    get clockChecks() { return checks; },
    get simulatedLaunches() { return simulatedLaunches; },
    get failedAttemptRefusals() { return failedAttemptRefusals; },
    get retainedAttempts() { return scoped.module.unresolvedStartups().length; },
    run(endpoint = 'management') {
      deadline = clock.now() + 10000;
      return start(profile, endpoint, deadline, Math.min(deadline, clock.now() + 10000), 'Synthetic resource transfer');
    },
    async cleanup() {
      for (const client of resources) client.close();
      // Call only after fixture transport shutdown. This is test-owned resource
      // teardown, never StartAuthority.resolve or a production exit assertion.
      for (const lease of leases) lease.release();
      scoped.forget();
    },
  };
}
