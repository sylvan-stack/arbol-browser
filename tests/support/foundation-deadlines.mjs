// Testing-only dependency timing faults. The packaged lifecycle bytes and real
// lock/socket acquisition functions are unchanged. No runtime/exit authority.
// API: https://nodejs.org/api/module.html#moduleregisterhooksoptions
import { registerHooks } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { load, bounded } from './foundation.mjs';

export async function deadlineLifecycle(context, kind, mode) {
  const actualClock = await load(context, 'runtime/instance');
  const { unavailable } = await load(context, 'contracts/errors');
  const key = `__abr28_${randomBytes(12).toString('hex')}`;
  const original = name => pathToFileURL(join(context.candidate, 'lib', `${name}.js`)).href;
  const lifecycle = `${original('runtime/lifecycle')}?qualification=${key}`;
  let acquired, settle, returning = false, checks = 0, expired = false, acquisitionDeadline;
  const acquiredPromise = new Promise(resolve => { acquired = resolve; });
  const barrier = new Promise(resolve => { settle = resolve; });
  const resources = []; // Deliberate strong references exclude GC as the oracle.
  const state = {
    now() { return expired ? acquisitionDeadline + 1 : actualClock.now(); },
    assertTime(deadline) {
      if (returning && deadline === acquisitionDeadline &&
          ++checks >= (mode === 'post-wait' ? 1 : mode === 'transfer' ? 2 : Infinity)) expired = true;
      if (state.now() >= deadline) throw unavailable('browser');
    },
    async acquire(target, operation, args) {
      if (target !== kind) return operation(...args);
      // A rejected acquisition owns no value. Never hide an acquired resource.
      if (mode === 'reject') throw unavailable('browser');
      acquisitionDeadline = kind === 'lock' ? args[3] : args[5];
      const value = await operation(...args);
      if (!value) throw new Error('Expected a real acquired resource');
      resources.push(value); acquired();
      await barrier;
      returning = true;
      return value;
    },
  };
  globalThis[key] = state;
  const adapters = new Map([
    [original('runtime/instance'), `export * from ${JSON.stringify(original('runtime/instance'))};
      export const now = () => globalThis[${JSON.stringify(key)}].now();
      export const assertTime = deadline => globalThis[${JSON.stringify(key)}].assertTime(deadline);`],
    [original('profiles/locking'), `export * from ${JSON.stringify(original('profiles/locking'))};
      import { ownerLock as actual } from ${JSON.stringify(original('profiles/locking'))};
      export const ownerLock = (...args) => globalThis[${JSON.stringify(key)}].acquire('lock', actual, args);`],
    [original('runtime/transport'), `export * from ${JSON.stringify(original('runtime/transport'))};
      import { connectRuntime as actual } from ${JSON.stringify(original('runtime/transport'))};
      export const connectRuntime = (...args) => globalThis[${JSON.stringify(key)}].acquire('connection', actual, args);`],
  ]);
  const hooks = registerHooks({
    resolve(specifier, context, nextResolve) {
      const result = nextResolve(specifier, context);
      if (context.parentURL !== lifecycle || !adapters.has(result.url)) return result;
      return { url: `data:text/javascript,${encodeURIComponent(adapters.get(result.url))}`, shortCircuit: true };
    },
  });
  let module;
  try { module = await import(lifecycle); }
  catch (error) { delete globalThis[key]; throw error; }
  finally { hooks.deregister(); }
  return { ...module, acquired: () => bounded(acquiredPromise), settle,
    resources, get clockChecks() { return checks; },
    async cleanup() {
      settle();
      // Keep the state until all already-returned resource continuations drain.
      await new Promise(resolve => setImmediate(resolve));
      for (const value of resources) { if (kind === 'lock') value.release(); else value.close(); }
      delete globalThis[key];
    },
  };
}
