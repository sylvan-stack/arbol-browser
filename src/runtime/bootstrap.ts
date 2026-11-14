import { unavailable } from '../contracts/errors.js';
import type { CommandPorts } from './ports.js';

/** ABR-1 has no production native adapter, watchdog, qualified manifest or host.
 * There are intentionally no Electron imports or page/shell constructors here.
 * Later startup must replace this refusal with qualified preflight before any
 * view can be created; a JavaScript shield or support.node is never readiness. */
export async function preflightPageAdmission(): Promise<never> {
  throw unavailable('browser');
}

export const foundationPorts: CommandPorts = Object.freeze({
  process: Object.freeze({
    open: async () => preflightPageAdmission(),
    close: async () => { throw unavailable('browser'); },
    mcp: async () => { throw unavailable('browser'); },
  }),
  profiles: Object.freeze({
    list: async () => { throw unavailable('profile'); },
    create: async () => { throw unavailable('profile'); },
    remove: async () => { throw unavailable('profile'); },
  }),
});
