#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from './parse.js';
import { publicFailure, unavailable, type ExitCode } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import type { Contract } from '../contracts/generated.js';
import type { CommandPorts, Stdio, PackageMetadata } from '../runtime/ports.js';
import { consumePackagedSelection, type BuildSelection } from '../runtime/selection.js';

// All native/profile/runtime work is lazy. info remains metadata only.
const defaultPorts = Object.freeze({}) as CommandPorts;
async function productionPorts(selection: BuildSelection): Promise<CommandPorts> {
  const [{ createProfileService }, { loadPlatform }, { createProcessService, createProfileRuntime },
    { verifyPackagedHost }, { createProductionExitAuthority }, { createProductionProcessIntegration }] = await Promise.all([
    import('../profiles/manage.js'), import('../runtime/platform.js'), import('../runtime/lifecycle.js'),
    import('../runtime/authorities.js'), import('../runtime/exit.js'), import('../runtime/process.js'),
  ]);
  const payload = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const deadline = performance.now() + 30000;
  // Verify the real current outer/payload before loading its native support.
  // The fixed packaged entry must be running as the exact stock engine in
  // Node mode; no system Node, older Foundation or ad hoc helper substitution.
  const host = await verifyPackagedHost(selection, payload, deadline);
  const address = new URL('../native/manifest.js', import.meta.url).href;
  const { pinnedRuntime } = await import(address) as typeof import('../native/manifest.js');
  if (process.type === 'browser' || resolve(process.execPath) !== host.identity.layout.engine ||
      process.versions.electron !== pinnedRuntime.electron || process.versions.node !== pinnedRuntime.node ||
      process.versions.modules !== pinnedRuntime.modules || process.versions.napi !== pinnedRuntime.napi ||
      process.platform !== pinnedRuntime.platform || process.arch !== pinnedRuntime.arch) throw unavailable('browser');
  await host.assertTrusted(deadline);
  const platform = loadPlatform(), exits = createProductionExitAuthority(platform, selection);
  const integration = createProductionProcessIntegration(host, selection, platform, exits);
  const state = host.policy.stateRoot;
  return Object.freeze({
    profiles: createProfileService({ state, platform: () => platform, runtime: createProfileRuntime(platform, selection, exits) }),
    process: createProcessService({ state, selection, platform: () => platform, integration, exits }),
  });
}

/** Metadata only: no Electron import, native load, profile read, socket or child. */
export async function componentInfo(): Promise<Contract<'wire.ComponentInfo'>> {
  const metadata: PackageMetadata = JSON.parse(await readFile(new URL('../../metadata.json', import.meta.url), 'utf8'));
  const info = { ...metadata.component, stateDirectory: join(homedir(), 'Library/Application Support/Arbol/browser') };
  if (!validator('wire.ComponentInfo')(info)) throw new Error('Invalid packaged component metadata');
  return info;
}

export async function runCli(args: readonly string[], ports: CommandPorts = defaultPorts,
  io: Stdio = process): Promise<ExitCode> {
  // On the MCP path stdout is reserved exclusively for the MCP transport, including failures.
  const mcp = args[0] === 'mcp';
  try {
    const command = parse(args);
    if (ports === defaultPorts && command.kind === 'mcp') throw unavailable('browser');
    let activePorts = ports;
    if (ports === defaultPorts && command.kind !== 'info') {
      const metadata = await componentInfo();
      const selection = consumePackagedSelection(metadata.build, resolve(fileURLToPath(new URL('../../', import.meta.url))));
      activePorts = await productionPorts(selection);
    }
    if (command.kind === 'mcp') { await activePorts.process.mcp(command.profile, io); return 0; }
    let result: unknown;
    let check: (value: unknown) => boolean;
    switch (command.kind) {
      case 'info': result = await componentInfo(); check = validator('wire.ComponentInfo'); break;
      case 'open': result = await activePorts.process.open(command); check = validator('wire.OpenResult'); break;
      case 'close': result = await activePorts.process.close(command.profile); check = validator('wire.CloseResult'); break;
      case 'profiles-list': result = await activePorts.profiles.list(); check = validator('profile.ProfileList'); break;
      case 'profiles-create':
        result = await activePorts.profiles.create(command.profile, command.creationRequest);
        check = validator('profile.ProfileCreated'); break;
      case 'profiles-remove':
        result = await activePorts.profiles.remove(command.profile, io);
        check = validator('profile.ProfileRemoved'); break;
    }
    if (!check(result)) throw new Error('Invalid command result');
    io.stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    const failure = publicFailure(error);
    if (!validator('browser.BrowserError')(failure.detail)) {
      const internal = publicFailure(undefined);
      if (!mcp) io.stdout.write(`${JSON.stringify({ error: internal.detail })}\n`);
      io.stderr.write('arbol-browser: internal\n');
      return 70;
    }
    if (!mcp) io.stdout.write(`${JSON.stringify({ error: failure.detail })}\n`);
    // No thrown messages, arguments, URLs, protocol bodies or stack traces.
    io.stderr.write(`arbol-browser: ${failure.detail.code}\n`);
    return failure.exitCode;
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
