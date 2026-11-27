import { randomBytes } from 'node:crypto';
import { rename } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { validator } from '../contracts/schema.js';
import { assertDirectory, directory, profilePaths, profileUnavailable, statOrAbsent } from '../profiles/paths.js';
import { readJson, readProfile, writeNewFile, type ProfileSnapshot } from '../profiles/records.js';
import { assertTime, now, originalAlive, readRuntime, runtimeLocation, type InstanceOwner,
  type RuntimeLocation, type RuntimeRecord } from './instance.js';
import { assertPlatform, type HeldLock, type PlatformPort } from './platform.js';

const instanceFields = ['profile', 'profileInstance', 'instance', 'pid', 'processStartId', 'build'] as const;
type ResidentPointer = Readonly<{ format: 1 } & Pick<RuntimeRecord, typeof instanceFields[number]>>;
const currentPath = (state: string) => join(state, 'browser-resident.json');
const ownerPath = (state: string) => join(state, 'browser-resident.lock');

/** The main process retains the exclusive original until it exits. The
 * pointer is only a discovery hint for peers; it does not grant admission. */
export async function retainInstalledResidence(state: string, platform: PlatformPort, deadline: number): Promise<Readonly<{
  assertCurrent(): Promise<void>;
  publish(instance: InstanceOwner): Promise<void>;
}>> {
  assertPlatform(platform); assertTime(deadline);
  const root = await directory(state);
  const held = platform.tryLock(ownerPath(state));
  if (!held) throw profileUnavailable();
  const assertCurrent = async () => {
    held.assertIdentity(); await assertDirectory(state, root); held.assertIdentity();
  };
  try { await assertCurrent(); assertTime(deadline); }
  catch (error) { held.release(); throw error; }
  return Object.freeze({
    assertCurrent,
    async publish(instance: InstanceOwner) {
      await assertCurrent(); assertTime(deadline);
      const { owner, record } = instance;
      if (owner.profile.paths.state !== state || record.phase !== 'starting' || record.pid !== process.pid ||
          record.profile !== owner.profile.record.id || record.profileInstance !== owner.profile.record.instance ||
          !originalAlive(record, platform)) throw profileUnavailable();
      await owner.assert(); await instance.location.assert();
      const { profile, profileInstance, instance: id, pid, processStartId, build } = record;
      const pointer: ResidentPointer = { format: 1, profile, profileInstance, instance: id, pid, processStartId, build };
      const pending = join(state, `.browser-resident-${randomBytes(16).toString('hex')}`);
      await writeNewFile(pending, JSON.stringify(pointer) + '\n');
      await assertCurrent(); assertTime(deadline);
      if (instance.record !== record) throw profileUnavailable();
      await rename(pending, currentPath(state)); await assertCurrent();
    },
  });
}

export async function electInstalledStartup(state: string, platform: PlatformPort, deadline: number,
  signal?: AbortSignal): Promise<HeldLock> {
  assertPlatform(platform); const root = await directory(state);
  for (;;) {
    assertTime(deadline); if (signal?.aborted) throw profileUnavailable();
    const gate = platform.tryLock(join(state, 'browser-resident-start.lock'));
    if (gate) {
      try { await assertDirectory(state, root); gate.assertIdentity(); assertTime(deadline); return gate; }
      catch (error) { gate.release(); throw error; }
    }
    await setTimeout(Math.min(20, Math.max(1, deadline - now())), undefined, signal ? { signal } : undefined);
  }
}

export interface ResidentRuntime {
  readonly profile: ProfileSnapshot;
  readonly location: RuntimeLocation;
  readonly record: RuntimeRecord;
}
/** Called only by the current startup election winner. A held lifetime
 * lock with an unreachable resident can never authorize a replacement. */
export async function discoverInstalledResident(state: string, platform: PlatformPort, gate: HeldLock,
  deadline: number, signal?: AbortSignal): Promise<ResidentRuntime | undefined> {
  const root = await directory(state);
  for (;;) {
    assertTime(deadline); if (signal?.aborted) throw profileUnavailable();
    gate.assertIdentity(); await assertDirectory(state, root);
    const vacancy = platform.tryLock(ownerPath(state));
    if (vacancy) { vacancy.release(); return undefined; }
    const path = currentPath(state);
    if (await statOrAbsent(path)) {
      const { value } = await readJson(path, 2048);
      if (!validator('browser.ProfileId')((value as ResidentPointer | null)?.profile) ||
          !value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 7)
        throw profileUnavailable();
      const pointer = value as ResidentPointer;
      if (pointer.format !== 1 || typeof pointer.pid !== 'number' || !Number.isSafeInteger(pointer.pid) || pointer.pid < 2 ||
          typeof pointer.processStartId !== 'string' || !/^[1-9][0-9]{0,19}$/.test(pointer.processStartId))
        throw profileUnavailable();
      const live = platform.processIdentity(pointer.pid);
      if (live?.startId === pointer.processStartId && live.uid === process.geteuid?.()) {
        const profile = await readProfile(profilePaths(pointer.profile, state));
        const location = await runtimeLocation(profile);
        const record = location && await readRuntime(location);
        if (!location || !record || instanceFields.some(key => pointer[key] !== record[key]) ||
            !originalAlive(record, platform) || record.phase === 'closing') throw profileUnavailable();
        if (record.phase === 'ready') {
          gate.assertIdentity(); await assertDirectory(state, root); assertTime(deadline);
          return Object.freeze({ profile, location, record });
        }
      }
    }
    await setTimeout(Math.min(20, Math.max(1, deadline - now())), undefined, signal ? { signal } : undefined);
  }
}
