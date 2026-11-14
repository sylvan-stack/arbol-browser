import { invalidInput } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';

export type Command =
  | { kind: 'info' }
  | { kind: 'open'; profile: string; url?: string }
  | { kind: 'close' | 'mcp'; profile: string }
  | { kind: 'profiles-list' }
  | { kind: 'profiles-create'; profile: string; creationRequest?: string }
  | { kind: 'profiles-remove'; profile: string; deleteData: true };
const profileId = validator('browser.ProfileId');
const creationRequest = /^create_[A-Za-z0-9_-]{22}$/;

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
  if (!['info', 'open', 'close', 'mcp', 'profiles'].includes(args[0] ?? '')) throw invalidInput();
  const words: string[] = [];
  const options = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const word = args[i]!;
    if (!word.startsWith('-')) { words.push(word); continue; }
    if (!['--profile', '--url', '--creation-request', '--delete-data'].includes(word)) throw invalidInput();
    let value: string | true = true;
    if (word !== '--delete-data') {
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
  if (['open', 'close', 'mcp'].includes(command ?? '') && words.length === 1) {
    allowed('--profile', ...(command === 'open' ? ['--url'] : []));
    const profile = selectedProfile(options.get('--profile') ?? 'default');
    if (command === 'open') {
      const url = options.get('--url');
      return { kind: 'open', profile, ...(typeof url === 'string' ? { url: checkedUrl(url) } : {}) };
    }
    return { kind: command as 'close' | 'mcp', profile };
  }
  if (command === 'profiles') {
    if (subcommand === 'list' && words.length === 2) { allowed(); return { kind: 'profiles-list' }; }
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
