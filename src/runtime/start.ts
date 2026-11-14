import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { statOrAbsent, profileUnavailable } from '../profiles/paths.js';
import { writeNewFile, assertProfile, type ProfileSnapshot } from '../profiles/records.js';
import type { PlatformPort, HeldLock } from './platform.js';
import type { BuildSelection } from './selection.js';
import { now, token, assertTime, runtimeLocation, readRuntime, originalAlive, startupArbitration,
  type RuntimeRecord } from './instance.js';
import { connectRuntime, type RuntimeClient, type Endpoint } from './transport.js';

export interface BuildGuard { assert(): Promise<void>; release(): void }
export interface StartAuthority {
  assertTrusted(selection: BuildSelection): Promise<void>;
  /** Verify signed native/watchdog readiness and host guard acquisition for the
   * exact record, not just successful socket hello or candidate metadata. */
  assertReady(profile: ProfileSnapshot, record: RuntimeRecord): Promise<void>;
  /** Complete main/helper census of this exact attempt. Failure retains guards;
   * callers must resolve retained attempts before ending their process. */
  assertFailed(profile: ProfileSnapshot, request: string, launchedPid: number | undefined, deadline: number): Promise<void>;
}
export interface LaunchPort { launch(selection: BuildSelection, requestPath: string, deadline: number): Promise<number> }
export const launchServices: LaunchPort = Object.freeze({
  launch(selection: BuildSelection, requestPath: string, deadline: number): Promise<number> {
    assertTime(deadline);
    return new Promise((resolve, reject) => {
      execFile(join(selection.directory, 'native/host-launch'),
        [join(selection.directory, 'runtime/ArbolBrowserHost.app'), requestPath],
        { timeout: Math.max(1, deadline - now()), maxBuffer: 128,
          env: { HOME: process.env.HOME, PATH: '/usr/bin:/bin' } }, (error, stdout) => {
          if (error || !/^[1-9][0-9]*\n$/.test(stdout) || !Number.isSafeInteger(Number(stdout.trim()))) {
            reject(profileUnavailable()); return;
          }
          resolve(Number(stdout.trim()));
        });
    });
  },
});
export interface RetainedStartup {
  readonly profile: ProfileSnapshot; readonly request: string;
  /** Re-run full failed-attempt evidence, then release the exact guards. */
  resolve(deadline: number): Promise<void>;
}
const retained = new Set<RetainedStartup>();
export function unresolvedStartups(): readonly RetainedStartup[] { return [...retained]; }
/** On-demand only. Repeated calls may inspect a live starting host, never launch
 * a replacement or kill a slow owner. There is no resident launch broker. */
export function createStarter(options: { selection: BuildSelection; platform: PlatformPort; authority: StartAuthority;
  acquireBuild(): Promise<BuildGuard>; launch?: LaunchPort }) {
  return async (profile: ProfileSnapshot, endpoint: Endpoint, deadline: number, contentionDeadline = Math.min(deadline, now() + 10000),
    label = 'Browser client'): Promise<{ client: RuntimeClient; record: RuntimeRecord; alreadyRunning: boolean }> => {
    assertTime(deadline); await assertProfile(profile);
    const location = await runtimeLocation(profile, true);
    if (!location) throw profileUnavailable();
    const guard = await options.acquireBuild(); let startup: HeldLock | undefined;
    let request = '', launched: number | undefined, attempted = false, resolved = false;
    const release = () => { startup?.release(); guard.release(); resolved = true; };
    try {
      await guard.assert();
      let current = await readRuntime(location);
      if (current && originalAlive(current, options.platform)) {
        while (current.phase === 'starting' && now() < deadline) {
          await setTimeout(Math.min(25, Math.max(1, deadline - now())));
          const observed = await readRuntime(location);
          if (!observed || observed.instance !== current.instance || !originalAlive(observed, options.platform)) throw profileUnavailable();
          current = observed;
        }
        const client = await connectRuntime(location, current, endpoint, options.selection, options.platform, deadline, label);
        try {
          await options.authority.assertReady(profile, current); await guard.assert(); assertTime(deadline);
          assertTime(deadline); release(); assertTime(deadline);
          return { client, record: current, alreadyRunning: true };
        } catch (error) { client.close(); throw error; }
      }
      startup = await startupArbitration(location, options.platform, contentionDeadline);
      await guard.assert(); assertTime(deadline);
      current = await readRuntime(location);
      if (current && originalAlive(current, options.platform)) {
        // Another starter won while we waited: attach within the same budget.
        while (current.phase === 'starting' && now() < deadline) {
          await setTimeout(Math.min(25, Math.max(1, deadline - now())));
          const observed = await readRuntime(location);
          if (!observed || observed.instance !== current.instance || !originalAlive(observed, options.platform)) throw profileUnavailable();
          current = observed;
        }
        const client = await connectRuntime(location, current, endpoint, options.selection, options.platform, deadline, label);
        try {
          await options.authority.assertReady(profile, current); await guard.assert(); assertTime(deadline);
          assertTime(deadline); release(); assertTime(deadline);
          return { client, record: current, alreadyRunning: true };
        } catch (error) { client.close(); throw error; }
      }
      await options.authority.assertTrusted(options.selection); assertTime(deadline);
      request = token('req');
      const path = join(location.leaf, `launch-${request}.json`);
      if (await statOrAbsent(path)) throw profileUnavailable();
      await writeNewFile(path, JSON.stringify({ format: 1, request, profile: profile.paths.root,
        profileInstance: profile.record.instance, selection: options.selection }) + '\n');
      await location.assert(); await guard.assert(); assertTime(deadline);
      // No owner.lock is acquired or transferred by this starter.
      attempted = true;
      launched = await (options.launch ?? launchServices).launch(options.selection, path, deadline);
      do {
        assertTime(deadline); await guard.assert(); startup.assertIdentity();
        const record = await readRuntime(location);
        if (record && record.phase === 'ready' && originalAlive(record, options.platform)) {
          const client = await connectRuntime(location, record, endpoint, options.selection, options.platform, deadline, label);
          try {
            await options.authority.assertReady(profile, record); await guard.assert(); assertTime(deadline);
            assertTime(deadline); release(); assertTime(deadline);
            return { client, record, alreadyRunning: false };
          } catch (error) { client.close(); throw error; }
        }
        await setTimeout(Math.min(25, Math.max(1, deadline - now())));
      } while (now() < deadline);
      throw profileUnavailable();
    } catch (error) {
      if (attempted && !resolved) {
        const attempt: RetainedStartup = Object.freeze({ profile, request,
          async resolve(limit: number) {
            await options.authority.assertFailed(profile, request, launched, limit);
            await guard.assert(); release(); retained.delete(attempt);
          },
        });
        retained.add(attempt);
        try { await attempt.resolve(deadline); } catch { /* preserve exact guards and request */ }
      } else if (!resolved) release();
      throw error;
    }
  };
}
