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
