import { app } from 'electron';
import { refuse } from './manifest.js';
import { assertHostCustody, type HostCustody } from '../runtime/custody.js';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
export const featureConfiguration = Object.freeze({ sitePerProcess: true as const,
  disabledFeatures: Object.freeze(['MacAccessibilityTextOperation']), extraChromiumArguments: Object.freeze([] as string[]) });
let attempted = false, configured = false;
let authenticatedHost: HostCustody | undefined;
/** Only canonical armed bootstrap supplies the genuine retained host. A tuple
 * matching process.argv by itself never grants the production argument route. */
export function authorizeHostFeatureArguments(custody: HostCustody): void {
  assertHostCustody(custody);
  if (attempted || authenticatedHost || app.isReady() ||
      resolve(fileURLToPath(new URL('../../', import.meta.url))) !== custody.host.identity.layout.payload) return custody.terminate();
  authenticatedHost = custody;
}
const forbidden = ['enable-features', 'enable-blink-features', 'disable-blink-features', 'disable-site-isolation-trials',
  'disable-web-security', 'disable-features', 'remote-debugging-port', 'remote-debugging-pipe', 'inspect', 'inspect-brk',
  'js-flags', 'no-sandbox', 'disable-gpu-sandbox', 'load-extension'];
/** Call from the trusted host entry before app readiness or session creation. */
export function configureNativeFeatures(): void {
  if (attempted) refuse();
  attempted = true;
  const host = authenticatedHost; authenticatedHost = undefined;
  const args = process.argv.slice(2);
  if (host) {
    assertHostCustody(host); const layout = host.host.identity.layout, argv = process.argv;
    if (argv.length !== 6 || argv[0] !== layout.engine || process.execPath !== layout.engine ||
        argv[1] !== '--site-per-process' || argv[2] !== '--disable-features=MacAccessibilityTextOperation' ||
        argv[3] !== layout.hostEntry || argv[4] !== '--arbol-host-request' || argv[5] !== host.requestPath) return host.terminate();
  } else if (args.length !== 0 && (args.length !== 2 || args[0] !== '--arbol-host-request' || !args[1]?.startsWith('/'))) refuse();
  if (app.isReady() || process.execArgv.length) refuse();
  // The bootstrap supplies exactly these two switches. A standalone trusted
  // qualification entry may supply neither; arbitrary caller switches refuse.
  for (const key of forbidden) {
    if (app.commandLine.hasSwitch(key) && !(key === 'disable-features' &&
        app.commandLine.getSwitchValue(key) === 'MacAccessibilityTextOperation')) refuse();
  }
  app.commandLine.appendSwitch('site-per-process');
  app.commandLine.appendSwitch('disable-features', 'MacAccessibilityTextOperation');
  configured = true;
  assertNativeFeatures();
}
export function assertNativeFeatures(): void {
  if (!configured || !app.commandLine.hasSwitch('site-per-process') ||
      app.commandLine.getSwitchValue('site-per-process') !== '' ||
      app.commandLine.getSwitchValue('disable-features') !== 'MacAccessibilityTextOperation') refuse();
  for (const key of forbidden) if (key !== 'disable-features' && app.commandLine.hasSwitch(key)) refuse();
}
/** Qualification obligations, never an exclusion result from an inconclusive probe. */
export const unqualifiedNativeRoutes = Object.freeze(['complete AX cached/custom/value/selection/text-service routes',
  'direct NSTextInputClient and generated editing selectors', 'responder and frame/widget churn',
  'pointer/capture, wheel and real trackpad momentum', 'native HTML drag source/destination and multilingual IME',
  'MacAccessibilityTextOperation disabled-feature boundary', 'full-key lifetime/revision callbacks and fatal teardown']);
