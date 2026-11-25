import { execFile } from 'node:child_process';
import { userInfo } from 'node:os';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';
import { invalidInput, unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { createProfile, managedProfiles } from '../profiles/create.js';
import { registryLock } from '../profiles/locking.js';
import { profileId, profileUnavailable, statOrAbsent } from '../profiles/paths.js';
import { readJson, readProfile } from '../profiles/records.js';
import { assertHostCustody, type HostCustody } from '../runtime/custody.js';
import installation from '../runtime/installation-paths.json' with { type: 'json' };
import type { PlatformPort } from '../runtime/platform.js';

export type ProfileNavigationRequest = { method: 'list' } |
  { method: 'create'; profile: string } |
  { method: 'open'; profile: string; instance: string };
export interface ProfileNavigationEntry {
  readonly id: string;
  readonly instance: string;
  readonly label?: string;
}
export interface ProfileNavigationState {
  readonly current: string;
  readonly profiles: readonly ProfileNavigationEntry[];
}
export type ProfileNavigation = (raw: unknown, assertCurrent: () => void) => Promise<ProfileNavigationState>;
const execute = promisify(execFile);
const openResult = validator('wire.OpenResult');
const instancePattern = /^prf_[A-Za-z0-9_-]{22}$/;

async function labels(state: string): Promise<Map<string, { instance: string; label: string }>> {
  const path = join(state, 'profile-labels.json');
  const result = new Map<string, { instance: string; label: string }>();
  if (!await statOrAbsent(path)) return result;
  const { value } = await readJson(path, 1024 * 1024);
  const document = value as { format?: unknown; profiles?: unknown } | null;
  if (!document || Object.keys(document).sort().join(',') !== 'format,profiles' ||
      document.format !== 1 || !Array.isArray(document.profiles) || document.profiles.length > 4096)
    throw profileUnavailable();
  for (const entry of document.profiles) {
    if (!entry || Object.keys(entry).sort().join(',') !== 'id,instance,label' ||
        typeof entry.instance !== 'string' || !instancePattern.test(entry.instance) ||
        typeof entry.label !== 'string' || !entry.label.trim() || [...entry.label].length > 120 || /[\p{Cc}\p{Cf}]/u.test(entry.label))
      throw profileUnavailable();
    const id = profileId(entry.id);
    if (result.has(id)) throw profileUnavailable();
    result.set(id, { instance: entry.instance, label: entry.label });
  }
  return result;
}

export function createProfileNavigation(custody: HostCustody, platform: PlatformPort): ProfileNavigation | undefined {
  assertHostCustody(custody);
  if (custody.host.identity.layout.scope !== 'installed') return undefined;
  const selected = custody.instance.owner.profile;
  const state = custody.host.policy.stateRoot;
  if (selected.paths.state !== state) throw profileUnavailable();
  const home = userInfo().homedir;
  const launcher = join(home, dirname(dirname(join(...installation.stableBuilds))), 'bin', 'arbol-browser');
  let changing = false;

  async function list(check: () => void): Promise<ProfileNavigationState> {
    check();
    const registry = await registryLock(state, platform);
    try {
      const records = await managedProfiles(registry);
      const names = await labels(state);
      await registry.assert();
      check();
      if (!records.some(({ record }) => record.id === selected.record.id && record.instance === selected.record.instance))
        throw profileUnavailable();
      return { current: selected.record.id, profiles: records.map(({ record }) => {
        const name = names.get(record.id);
        return { id: record.id, instance: record.instance, ...(name?.instance === record.instance ? { label: name.label } : {}) };
      }) };
    } finally { registry.release(); }
  }

  return async (raw, assertCurrent) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw invalidInput();
    const request = raw as Record<string, unknown>;
    const keys = Object.keys(request).sort().join(',');
    const check = () => { assertCurrent(); assertHostCustody(custody); };
    if (request.method === 'list' && keys === 'method') return list(check);
    if (!((request.method === 'create' && keys === 'method,profile') ||
          (request.method === 'open' && keys === 'instance,method,profile'))) throw invalidInput();
    const id = profileId(request.profile, request.method === 'create');
    if (changing) throw profileUnavailable();
    changing = true;
    try {
      check();
      if (request.method === 'create') {
        if (/^seqoya-[0-9a-f]{32}$/.test(id)) throw invalidInput();
        await createProfile(id, undefined, platform, state);
      } else {
        const { instance } = request;
        if (typeof instance !== 'string' || !instancePattern.test(instance)) throw invalidInput();
        const snapshot = await list(check);
        if (!snapshot.profiles.some(profile => profile.id === id && profile.instance === instance)) throw profileUnavailable();
        if ((await readProfile(selected.paths)).record.instance !== selected.record.instance) throw profileUnavailable();
        check();
        if (id !== selected.record.id) {
          const result = await execute(launcher, ['open', '--profile', id, '--profile-instance', instance], {
            cwd: home, env: { HOME: home, PATH: '/usr/bin:/bin' }, timeout: 65000, maxBuffer: 16 * 1024,
          });
          const reply: unknown = JSON.parse(result.stdout);
          if (!openResult(reply) || reply.profile !== id) throw unavailable('browser');
        }
      }
      return await list(check);
    } finally { changing = false; }
  };
}
