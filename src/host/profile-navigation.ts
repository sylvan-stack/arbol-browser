import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { invalidInput, unavailable } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import { createProfile, managedProfiles } from '../profiles/create.js';
import { registryLock } from '../profiles/locking.js';
import { hasRetainedProfileLock } from '../profiles/manage.js';
import { profileId, profilePaths, profileUnavailable, statOrAbsent } from '../profiles/paths.js';
import { readJson, readProfile, type ProfileSnapshot } from '../profiles/records.js';
import { assertHostCustody, assertSharedProfileRuntime, type HostCustody, type SharedProfileRuntime } from '../runtime/custody.js';
import { assertTime, now, originalAlive, readRuntime, recordProcess, runtimeLocation, startupDeadline, token } from '../runtime/instance.js';
import type { PlatformPort } from '../runtime/platform.js';
import { createLaunchTransactions } from '../runtime/process.js';
import { connectRuntime } from '../runtime/transport.js';

export type ProfileNavigationRequest = { method: 'list' } |
  { method: 'create'; profile: string } |
  { method: 'open'; profile: string; instance: string };
export interface ProfileNavigationEntry {
  readonly id: string;
  readonly instance: string;
  readonly label?: string;
  readonly unavailable?: true;
}
export interface ProfileNavigationState {
  readonly current: string;
  readonly profiles: readonly ProfileNavigationEntry[];
}
export type ProfileNavigation = (raw: unknown, assertCurrent: () => void, isFocused: () => boolean) => Promise<ProfileNavigationState>;
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

export function createProfileNavigation(custody: HostCustody, platform: PlatformPort,
  yieldPresentation: () => () => void, selectLocal: (profile: string, instance: string) => boolean,
  shared?: Readonly<{ runtime?: SharedProfileRuntime; isReady(profile: string, instance: string): boolean;
    openInWindow(profile: ProfileSnapshot, deadline: number): Promise<void> }>): ProfileNavigation | undefined {
  assertHostCustody(custody);
  if (custody.host.identity.layout.scope !== 'installed') return undefined;
  if (shared?.runtime && assertSharedProfileRuntime(shared.runtime) !== custody) throw profileUnavailable();
  const selected = (shared?.runtime?.instance ?? custody.instance).owner.profile;
  const state = custody.host.policy.stateRoot;
  if (selected.paths.state !== state) throw profileUnavailable();
  const selection = { ...custody.build.selection, explicit: true };
  const attempts = createLaunchTransactions(custody.host, platform);
  let changing = false;

  async function list(check: () => void): Promise<ProfileNavigationState> {
    check();
    const registry = await registryLock(state, platform);
    try {
      const records = await managedProfiles(registry);
      const names = await labels(state);
      if (!records.some(({ record }) => record.id === selected.record.id && record.instance === selected.record.instance))
        throw profileUnavailable();
      const profiles: ProfileNavigationEntry[] = [];
      for (const profile of records) {
        const { record } = profile;
        const name = names.get(record.id);
        const blocked = record.id !== selected.record.id && !shared?.isReady(record.id, record.instance) &&
          await hasRetainedProfileLock(profile, platform) && !shared?.isReady(record.id, record.instance);
        profiles.push({ id: record.id, instance: record.instance,
          ...(name?.instance === record.instance ? { label: name.label } : {}),
          ...(blocked ? { unavailable: true } : {}) });
      }
      await registry.assert();
      check();
      return { current: selected.record.id, profiles };
    } finally { registry.release(); }
  }

  async function open(id: string, instance: string, check: () => void, isFocused: () => boolean): Promise<void> {
    const profile = await readProfile(profilePaths(id, state));
    if (profile.record.instance !== instance) throw profileUnavailable();
    check();
    if (selectLocal(id, instance)) return;
    const deadline = startupDeadline();
    if (shared) {
      await shared.openInWindow(profile, deadline);
      check(); assertTime(deadline);
      if (!selectLocal(id, instance)) throw unavailable('profile');
      return;
    }
    let requested = false;
    for (;;) {
      assertTime(deadline);
      const location = await runtimeLocation(profile);
      const runtime = location && await readRuntime(location);
      check();
      if (location && runtime?.phase === 'ready' && originalAlive(runtime, platform)) {
        if (runtime.build !== selection.build) throw unavailable('browser');
        await attempts.admitted(profile, runtime, deadline);
        const client = await connectRuntime(location, runtime, 'management', selection, platform, deadline);
        try {
          await attempts.admitted(profile, runtime, deadline);
          check();
          const activate = isFocused();
          const restore = yieldPresentation();
          try {
            const reply = await client.call({ wire: 1, id: token('req'), method: 'open', params: {} }, Math.min(deadline, now() + 15000));
            if (!openResult(reply) || reply.profile !== id || reply.process !== runtime.pid || reply.instance !== runtime.instance)
              throw unavailable('browser');
            check();
            if (activate) platform.activateProfileWindow?.(recordProcess(runtime));
            return;
          } catch (error) {
            try { restore(); } catch { /* Preserve the original presentation refusal. */ }
            throw error;
          }
        } finally { client.close(); }
      }
      if (!requested) {
        // LaunchServices starts the ordinary signed command outside the Browser's
        // guarded engine family. Direct child processes are reserved for Chromium.
        if (!platform.requestProfileOpen?.(id, instance)) throw unavailable('browser');
        requested = true;
      }
      await setTimeout(Math.min(75, Math.max(1, deadline - now())));
    }
  }

  return async (raw, assertCurrent, isFocused) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw invalidInput();
    const request = raw as Record<string, unknown>;
    const keys = Object.keys(request).sort().join(',');
    const check = () => {
      assertCurrent(); assertHostCustody(custody);
      if (shared?.runtime) assertSharedProfileRuntime(shared.runtime);
    };
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
        if (!snapshot.profiles.some(profile => profile.id === id && profile.instance === instance && !profile.unavailable))
          throw profileUnavailable();
        if ((await readProfile(selected.paths)).record.instance !== selected.record.instance) throw profileUnavailable();
        check();
        if (id !== selected.record.id) await open(id, instance, check, isFocused);
      }
      return await list(check);
    } finally { changing = false; }
  };
}
