#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from './parse.js';
import { publicFailure, type ExitCode } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import type { Contract } from '../contracts/generated.js';
import type { CommandPorts, Stdio, PackageMetadata } from '../runtime/ports.js';
import { foundationPorts } from '../runtime/bootstrap.js';

/** Metadata only: no Electron import, native load, profile read, socket or child. */
export async function componentInfo(): Promise<Contract<'wire.ComponentInfo'>> {
  const metadata: PackageMetadata = JSON.parse(await readFile(new URL('../../metadata.json', import.meta.url), 'utf8'));
  const info = { ...metadata.component, stateDirectory: join(homedir(), 'Library/Application Support/Arbol/browser') };
  if (!validator('wire.ComponentInfo')(info)) throw new Error('Invalid packaged component metadata');
  return info;
}

export async function runCli(args: readonly string[], ports: CommandPorts = foundationPorts,
  io: Stdio = process): Promise<ExitCode> {
  // On the MCP path stdout is reserved exclusively for the MCP transport, including failures.
  const mcp = args[0] === 'mcp';
  try {
    const command = parse(args);
    if (command.kind === 'mcp') { await ports.process.mcp(command.profile, io); return 0; }
    let result: unknown;
    let check: (value: unknown) => boolean;
    switch (command.kind) {
      case 'info': result = await componentInfo(); check = validator('wire.ComponentInfo'); break;
      case 'open': result = await ports.process.open(command); check = validator('wire.OpenResult'); break;
      case 'close': result = await ports.process.close(command.profile); check = validator('wire.CloseResult'); break;
      case 'profiles-list': result = await ports.profiles.list(); check = validator('profile.ProfileList'); break;
      case 'profiles-create':
        result = await ports.profiles.create(command.profile, command.creationRequest);
        check = validator('profile.ProfileCreated'); break;
      case 'profiles-remove':
        result = await ports.profiles.remove(command.profile, io);
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
  process.exitCode = await runCli(process.argv.slice(2));
}
