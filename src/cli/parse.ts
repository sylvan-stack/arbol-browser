import { invalidInput } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { isSeqoyaProvider, seqoyaProfilePattern, type SeqoyaProvider } from '../runtime/seqoya-wire.js';

export type Command =
  | { kind: 'info' }
  | { kind: 'open'; profile: string; url?: string; profileInstance?: string; creationRequest?: string }
  | { kind: 'close'; profile: string }
  | { kind: 'seqoya-usage'; profile: string; profileInstance: string; provider: SeqoyaProvider }
  | { kind: 'agent'; profile: string; label: string }
  | { kind: 'agent-describe' }
  | { kind: 'profiles-list'; profile?: string }
  | { kind: 'profiles-create'; profile: string; creationRequest?: string }
  | { kind: 'profiles-remove'; profile: string; deleteData: true };
const profileId = validator('browser.ProfileId');
const clientLabel = validator('browser.ClientLabel');
const creationRequest = /^create_[A-Za-z0-9_-]{22}$/;
const profileInstance = /^prf_[A-Za-z0-9_-]{22}$/;

/** Command-supplied navigation uses the agent URL policy, including Unicode bounds. */
function checkedUrl(value: string): string {
  if ([...value].length > 8192 || /[\u0000\uD800-\uDFFF]/u.test(value)) throw invalidInput();
  if (value === 'about:blank') return value;
  let url: URL;
  try { url = new URL(value); } catch { throw invalidInput(); }
  // Reject URL-parser repair of whitespace, backslashes and missing authority.
  if (!/^https?:\/\//i.test(value) || /[\u0000-\u0020\u007F\\]/u.test(value) ||
      !['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) throw invalidInput();
  return value;
}

export function parse(args: readonly string[]): Command {
  // Command comes first; leading Build selection belongs to the common launcher.
  if (!['info', 'open', 'close', 'agent', 'profiles', 'seqoya-usage'].includes(args[0] ?? '')) throw invalidInput();
  const words: string[] = [];
  const options = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const word = args[i]!;
    if (!word.startsWith('-')) { words.push(word); continue; }
    if (!['--profile', '--profile-instance', '--url', '--creation-request', '--delete-data', '--contract', '--label', '--describe', '--provider'].includes(word))
      throw invalidInput();
    let value: string | true = true;
    if (word !== '--delete-data' && word !== '--describe') {
      const next = args[++i];
      if (!next || next.startsWith('-')) throw invalidInput();
      value = next;
    }
    if (options.has(word) && options.get(word) !== value) throw invalidInput();
    options.set(word, value);
  }
  const allowed = (...names: string[]) => {
    if ([...options.keys()].some(key => !names.includes(key))) throw invalidInput();
  };
  const selectedProfile = (id: unknown): string => {
    if (!profileId(id)) throw invalidInput();
    return id;
  };
  const [command, subcommand, id] = words;
  if (command === 'info' && words.length === 1) { allowed(); return { kind: 'info' }; }
  if (command === 'seqoya-usage' && words.length === 1) {
    allowed('--profile', '--profile-instance', '--provider');
    const profile = options.get('--profile'), instance = options.get('--profile-instance'), provider = options.get('--provider');
    if (typeof profile !== 'string' || !seqoyaProfilePattern.test(profile) ||
        typeof instance !== 'string' || !profileInstance.test(instance) || !isSeqoyaProvider(provider)) throw invalidInput();
    return { kind: 'seqoya-usage', profile, profileInstance: instance, provider };
  }
  if ((command === 'open' || command === 'close') && words.length === 1) {
    allowed('--profile', ...(command === 'open' ? ['--url', '--profile-instance', '--creation-request'] : []));
    const profile = selectedProfile(options.get('--profile') ?? 'default');
    if (command === 'open') {
      const url = options.get('--url');
      const instance = options.get('--profile-instance');
      const request = options.get('--creation-request');
      if (instance !== undefined && (!options.has('--profile') || typeof instance !== 'string' ||
          instance.length !== 26 || !profileInstance.test(instance)))
        throw invalidInput();
      if (request !== undefined && (typeof instance !== 'string' || typeof request !== 'string' ||
          !creationRequest.test(request))) throw invalidInput();
      return { kind: 'open', profile, ...(typeof url === 'string' ? { url: checkedUrl(url) } : {}),
        ...(typeof instance === 'string' ? { profileInstance: instance } : {}),
        ...(typeof request === 'string' ? { creationRequest: request } : {}) };
    }
    return { kind: 'close', profile };
  }
  if (command === 'agent' && words.length === 1) {
    if (options.get('--contract') !== '1') throw invalidInput();
    if (options.has('--describe')) {
      allowed('--contract', '--describe');
      return { kind: 'agent-describe' };
    }
    allowed('--contract', '--profile', '--label');
    const profile = selectedProfile(options.get('--profile') ?? 'default');
    const label = options.get('--label') ?? 'Browser client';
    if (!clientLabel(label)) throw invalidInput();
    return { kind: 'agent', profile, label };
  }
  if (command === 'profiles') {
    if (subcommand === 'list' && (words.length === 2 || words.length === 3)) {
      allowed();
      return id === undefined ? { kind: 'profiles-list' } : { kind: 'profiles-list', profile: selectedProfile(id) };
    }
    if (words.length !== 3) throw invalidInput();
    const profile = selectedProfile(id);
    if (profile === 'default') throw invalidInput();
    if (subcommand === 'create') {
      allowed('--creation-request');
      const token = options.get('--creation-request');
      if (token !== undefined && (typeof token !== 'string' || !creationRequest.test(token))) throw invalidInput();
      return { kind: 'profiles-create', profile, ...(typeof token === 'string' ? { creationRequest: token } : {}) };
    }
    if (subcommand === 'remove') {
      allowed('--delete-data');
      if (options.get('--delete-data') !== true) throw invalidInput();
      return { kind: 'profiles-remove', profile, deleteData: true };
    }
  }
  throw invalidInput();
}
