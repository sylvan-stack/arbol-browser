#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { resolve, dirname, basename } from 'node:path';
import { stateDirectory } from '../profiles/paths.js';
import { fileURLToPath } from 'node:url';
import { parse } from './parse.js';
import { publicFailure, unavailable, type ExitCode } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import type { Contract } from '../contracts/generated.js';
import type { CommandPorts, Stdio, PackageMetadata } from '../runtime/ports.js';
import { buildLocation, consumePackagedSelection, packagedLayout, type BuildSelection } from '../runtime/selection.js';
import type { VerifiedHost } from '../runtime/authorities.js';
import type { HeldLock, PlatformPort } from '../runtime/platform.js';

const coldStages = ['package-metadata', 'selected-build', 'runtime-imports', 'signed-bundle',
  'signed-policy-metadata-compatibility', 'isolated-roots', 'build-guard', 'initial-verified-host',
  'pinned-runtime-tuple', 'repeated-host-trust', 'native-platform', 'production-adapters',
  'command-dispatch', 'result-schema'] as const;
type ColdStage = typeof coldStages[number];
interface ColdObservation {
  stage: ColdStage;
  open?: import('../runtime/authorities.js').OpenCommandObservation;
  verification?: Readonly<{ module: typeof import('../runtime/authorities.js');
    observation: import('../runtime/authorities.js').HostVerificationObservation }>;
}
function noteCold(observation: ColdObservation | undefined, stage: ColdStage): void {
  if (observation) observation.stage = stage;
}
function coldFailureSuffix(observation: ColdObservation | undefined, status: ExitCode): string {
  // Compose only fixed supplemental text for the existing stderr write. No
  // additional stream operation can introduce a new asynchronous failure.
  try {
    if (observation && (status === 4 || status === 70) && coldStages.includes(observation.stage)) {
      let phase: import('../native/manifest.js').SignedVerificationPhase | undefined;
      try {
        const verification = observation.verification;
        phase = verification?.module.readHostVerificationFailurePhase(verification.observation);
      } catch { /* A failed phase read must retain the existing safe suffix. */ }
      return `arbol-browser: cold-stage ${observation.open?.stage ?? observation.stage}\n` +
        (phase ? `arbol-browser: signed-phase ${phase}\n` : '');
    }
  } catch { /* best effort only */ }
  return '';
}

const defaultPorts = Object.freeze({}) as CommandPorts;
interface InstalledLaunch {
  selection: BuildSelection;
  host: VerifiedHost;
  platform: PlatformPort;
  lock: HeldLock;
  deadline: number;
}
async function installedLaunch(cutoff: number): Promise<InstalledLaunch | undefined> {
  const payload = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const parent = dirname(dirname(dirname(dirname(payload))));
  if (basename(parent) !== 'app') return undefined;
  const root = dirname(parent), build = basename(root);
  if (buildLocation(build, root)?.scope !== 'installed') return undefined;
  const layout = packagedLayout(build, payload);
  if (process.type === 'browser' || process.execPath !== layout.engine) throw unavailable('browser');
  const selection = consumePackagedSelection(build, payload);
  const { verifyPackagedOpenHost } = await import('../runtime/authorities.js');
  const host = await verifyPackagedOpenHost(selection, payload, cutoff);
  const { loadPlatform } = await import('../runtime/platform.js');
  const platform = loadPlatform();
  const { lock, deadline } = platform.adoptInstalledLaunch(layout.bundle);
  return { selection, host, platform, lock, deadline: Math.min(cutoff, deadline) };
}
async function productionPorts(selection: BuildSelection, observation?: ColdObservation, openCutoff?: number,
  installed?: InstalledLaunch): Promise<CommandPorts> {
  if (openCutoff !== undefined && performance.now() >= openCutoff) throw unavailable('browser');
  noteCold(observation, 'runtime-imports');
  const [{ createProfileService }, { loadPlatform }, { createProcessService, createProfileRuntime },
    authorities, { createProductionExitAuthority }, { createProductionProcessIntegration }] = await Promise.all([
    import('../profiles/manage.js'), import('../runtime/platform.js'), import('../runtime/lifecycle.js'),
    import('../runtime/authorities.js'), import('../runtime/exit.js'), import('../runtime/process.js'),
  ]);
  const payload = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const deadline = openCutoff ?? installed?.deadline ?? performance.now() + 30000;
  // Verify the real current outer/payload before loading its native support.
  // The fixed packaged entry must be running as the exact stock engine in
  // Node mode; no system Node, older Foundation or ad hoc helper substitution.
  noteCold(observation, 'signed-bundle');
  const verification = observation ? authorities.createHostVerificationObservation() : undefined;
  try { if (observation && verification) observation.verification = Object.freeze({ module: authorities, observation: verification }); }
  catch { /* Optional readback cannot alter production provider construction. */ }
  const selectedHost = installed ? Promise.resolve(installed.host) : openCutoff === undefined
    ? authorities.verifyPackagedHost(selection, payload, deadline, undefined, verification)
    : authorities.verifyPackagedOpenHost(selection, payload, openCutoff, verification);
  const host = await selectedHost.catch(error => {
    // Read only this genuine module's observation; no callback enters trust
    // verification, and diagnostic readback cannot replace its actual error.
    try {
      if (observation && verification) noteCold(observation, authorities.readHostVerificationStage(verification) ?? 'signed-bundle');
    } catch { /* preserve the original failure */ }
    throw error;
  });
  noteCold(observation, 'pinned-runtime-tuple');
  const address = new URL('../native/manifest.js', import.meta.url).href;
  const { pinnedRuntime } = await import(address) as typeof import('../native/manifest.js');
  if (process.type === 'browser' || resolve(process.execPath) !== host.identity.layout.engine ||
      process.versions.electron !== pinnedRuntime.electron || process.versions.node !== pinnedRuntime.node ||
      process.versions.modules !== pinnedRuntime.modules || process.versions.napi !== pinnedRuntime.napi ||
      process.platform !== pinnedRuntime.platform || process.arch !== pinnedRuntime.arch) throw unavailable('browser');
  noteCold(observation, 'repeated-host-trust');
  if (openCutoff === undefined) await host.assertTrusted(deadline);
  else await authorities.assertHostStartupContinuity(host, deadline, openCutoff);
  noteCold(observation, 'native-platform');
  const platform = installed?.platform ?? loadPlatform();
  noteCold(observation, 'production-adapters');
  const exits = createProductionExitAuthority(platform, selection);
  const openObservation = observation ? authorities.createOpenCommandObservation() : undefined;
  if (observation && openObservation) observation.open = openObservation;
  const integration = createProductionProcessIntegration(host, selection, platform, exits, openObservation, openCutoff);
  const state = host.policy.stateRoot;
  return Object.freeze({
    profiles: createProfileService({ state, platform: () => platform, runtime: createProfileRuntime(platform, selection, exits) }),
    process: createProcessService({ state, selection, platform: () => platform, integration, exits, closeHost: host,
      ...(openObservation ? { observation: openObservation } : {}),
      ...(openCutoff === undefined ? {} : { openCutoff }) }),
  });
}

/** Metadata only: no Electron import, native load, profile read, socket or child. */
export async function componentInfo(): Promise<Contract<'wire.ComponentInfo'>> {
  const payload = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const fixedHost = basename(payload) === 'browser' && basename(dirname(payload)) === 'Resources' &&
    basename(dirname(dirname(payload))) === 'Contents' && basename(dirname(dirname(dirname(payload)))) === 'ArbolBrowser.app';
  if (fixedHost) {
    const address = new URL('../runtime/authorities.js', import.meta.url).href;
    const { readPackagedComponentInfo } = await import(address) as typeof import('../runtime/authorities.js');
    return readPackagedComponentInfo(payload);
  }
  const metadata: PackageMetadata = JSON.parse(await readFile(new URL('../../metadata.json', import.meta.url), 'utf8'));
  if (Object.prototype.hasOwnProperty.call(metadata, 'host')) throw unavailable('browser');
  const info = { ...metadata.component, stateDirectory: stateDirectory() };
  if (!validator('wire.ComponentInfo')(info)) throw new Error('Invalid packaged component metadata');
  return info;
}

export async function runCli(args: readonly string[], ports: CommandPorts = defaultPorts,
  io: Stdio = process): Promise<ExitCode> {
  const commandCutoff = performance.now() + 60000;
  // On the MCP path stdout is reserved exclusively for the MCP transport, including failures.
  const mcp = args[0] === 'mcp';
  let observation: ColdObservation | undefined;
  let installed: InstalledLaunch | undefined;
  try {
    const command = parse(args);
    if (ports === defaultPorts) installed = await installedLaunch(commandCutoff);
    const openCutoff = ports === defaultPorts && command.kind === 'open' ? installed?.deadline ?? commandCutoff : undefined;
    if (ports === defaultPorts && (command.kind === 'open' || command.kind === 'profiles-create'))
      observation = { stage: 'package-metadata' };
    if (ports === defaultPorts && command.kind === 'mcp') throw unavailable('browser');
    let activePorts = ports;
    if (ports === defaultPorts && command.kind !== 'info') {
      if (openCutoff !== undefined && performance.now() >= openCutoff) throw unavailable('browser');
      const metadata = installed?.host.identity.component ?? await componentInfo();
      noteCold(observation, 'selected-build');
      const selection = installed?.selection ?? consumePackagedSelection(metadata.build, resolve(fileURLToPath(new URL('../../', import.meta.url))));
      activePorts = await productionPorts(selection, observation, openCutoff, installed);
    }
    if (command.kind === 'mcp') { await activePorts.process.mcp(command.profile, io); return 0; }
    let result: unknown;
    let check: (value: unknown) => boolean;
    noteCold(observation, 'command-dispatch');
    switch (command.kind) {
      case 'info': result = installed?.host.identity.component ?? await componentInfo(); check = validator('wire.ComponentInfo'); break;
      case 'open': result = await activePorts.process.open(command); check = validator('wire.OpenResult'); break;
      case 'close': result = await activePorts.process.close(command.profile); check = validator('wire.CloseResult'); break;
      case 'profiles-list': result = await activePorts.profiles.list(); check = validator('profile.ProfileList'); break;
      case 'profiles-create':
        result = await activePorts.profiles.create(command.profile, command.creationRequest);
        check = validator('profile.ProfileCreated'); break;
      case 'profiles-remove':
        result = await activePorts.profiles.remove(command.profile);
        check = validator('profile.ProfileRemoved'); break;
    }
    if (observation) delete observation.open;
    noteCold(observation, 'result-schema');
    if (!check(result)) throw new Error('Invalid command result');
    if (openCutoff !== undefined && performance.now() >= openCutoff) throw unavailable('browser');
    io.stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    const failure = publicFailure(error);
    if (!validator('browser.BrowserError')(failure.detail)) {
      const internal = publicFailure(undefined);
      if (!mcp) io.stdout.write(`${JSON.stringify({ error: internal.detail })}\n`);
      io.stderr.write(`arbol-browser: internal\n${coldFailureSuffix(observation, 70)}`);
      return 70;
    }
    if (!mcp) io.stdout.write(`${JSON.stringify({ error: failure.detail })}\n`);
    // No thrown messages, arguments, URLs, protocol bodies or stack traces.
    io.stderr.write(`arbol-browser: ${failure.detail.code}\n${coldFailureSuffix(observation, failure.exitCode)}`);
    return failure.exitCode;
  } finally {
    if (installed) {
      try { installed.lock.release(); }
      catch { /* The installed launcher still retains the original guard until this process exits. */ }
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // A legacy bundled launcher must enter the physical tsc graph as well.
  // The thin compiler entry uses this same module; its import cannot trigger
  // this guard again because argv[1] remains main.mjs.
  const address = new URL('./main.js', import.meta.url).href;
  const entry = import.meta.url === address ? { runCli } : await import(address) as { runCli: typeof runCli };
  process.exitCode = await entry.runCli(process.argv.slice(2));
}
