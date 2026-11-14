import type { Readable, Writable } from 'node:stream';
import type { Contract } from '../contracts/generated.js';

export interface Stdio { stdin: Readable; stdout: Writable; stderr: Writable }
export interface OpenOptions { profile: string; url?: string }
/** The process service arbitrates the host; a CLI process never owns its pages. */
export interface ProcessPort {
  open(options: OpenOptions): Promise<Contract<'wire.OpenResult'>>;
  close(profile: string): Promise<Contract<'wire.CloseResult'>>;
  /** Owns only this adapter's stdio lifetime; EOF releases it, never kills the host. */
  mcp(profile: string, io: Stdio): Promise<void>;
}
/** ABR-2 supplies this service. Removal performs its own controlling-TTY check. */
export interface ProfilePort {
  list(): Promise<Contract<'profile.ProfileList'>>;
  create(profile: string, creationRequest?: string): Promise<Contract<'profile.ProfileCreated'>>;
  remove(profile: string, io: Stdio): Promise<Contract<'profile.ProfileRemoved'>>;
}
export interface CommandPorts { readonly process: ProcessPort; readonly profiles: ProfilePort }

/** Candidate inventory only, deliberately distinct from qualified BuildCompatibility.
 * Runtime/component shapes come from the normative schemas. No candidate metadata
 * is evidence of native readiness, signature trust or compatibility with data. */
export interface PackageMetadata {
  format: 1;
  component: Omit<Contract<'wire.ComponentInfo'>, 'stateDirectory'>;
  runtime: Contract<'native.Runtime'>;
  admission: 'blocked';
  nativeInput: false;
  watchdog: false;
  sourceDigest: string;
  files: Record<string, string>;
}
