import type { Readable, Writable } from 'node:stream';
import type { Contract } from '../contracts/generated.js';
import type { RuntimeClient } from './transport.js';
import type { SeqoyaParameters, SeqoyaResult } from './seqoya-wire.js';

export interface Stdio { stdin: Readable; stdout: Writable; stderr: Writable }
export interface OpenOptions { profile: string; url?: string; profileInstance?: string }
export interface AgentAttachment {
  readonly profile: string;
  readonly label: string;
  readonly deadline: number;
  readonly signal: AbortSignal;
}
/** The process service arbitrates the host; a CLI process never owns its pages. */
export interface ProcessPort {
  open(options: OpenOptions): Promise<Contract<'wire.OpenResult'>>;
  close(profile: string): Promise<Contract<'wire.CloseResult'>>;
  captureSeqoya?(input: SeqoyaParameters & { profile: string; profileInstance: string; deadline: number }): Promise<SeqoyaResult>;
  /** Owns one authenticated client. Releasing it leaves the Browser host running. */
  attachAgent(input: AgentAttachment): Promise<RuntimeClient>;
}
export interface ProfilePort {
  list(profile?: string): Promise<Contract<'profile2.ProfileList'>>;
  create(profile: string, creationRequest?: string): Promise<Contract<'profile2.ProfileCreated'>>;
  remove(profile: string): Promise<Contract<'profile2.ProfileRemoved'>>;
}
export interface CommandPorts { readonly process: ProcessPort; readonly profiles: ProfilePort }

/** Candidate inventory only, deliberately distinct from qualified BuildCompatibility.
 * Runtime/component shapes come from the normative schemas. No candidate metadata
 * is evidence of native readiness, signature trust or compatibility with data. */
export interface PackageMetadata {
  format: 1;
  component: Omit<Contract<'profile2.ComponentInfo'>, 'stateDirectory'>;
  runtime: Contract<'native.Runtime'>;
  admission: 'blocked';
  nativeInput: false;
  watchdog: false;
  sourceDigest: string;
  files: Record<string, string>;
}
