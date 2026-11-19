import { noteOpenCommand, type OpenCommandObservation } from './authorities.js';
import { execFile } from 'node:child_process';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { userInfo } from 'node:os';
import { setTimeout } from 'node:timers/promises';
import { statOrAbsent, profileUnavailable } from '../profiles/paths.js';
import { writeNewFile, assertProfile, type ProfileSnapshot } from '../profiles/records.js';
import type { PlatformPort, HeldLock } from './platform.js';
import type { BuildSelection } from './selection.js';
import { selectedLayout } from './selection.js';
import { now, token, assertTime, runtimeLocation, readRuntime, originalAlive, startupArbitration,
  type RuntimeRecord } from './instance.js';
import { connectRuntime, type RuntimeClient, type Endpoint } from './transport.js';

export interface BuildGuard { assert(): Promise<void>; release(): void }
export interface StartAuthority {
  assertTrusted(selection: BuildSelection): Promise<void>;
  /** Verify signed native/watchdog readiness and host guard acquisition for the
   * exact record, not just successful socket hello or candidate metadata. */
  assertReady(profile: ProfileSnapshot, record: RuntimeRecord, request?: string, joiningStartup?: boolean): Promise<void>;
  /** Complete main/helper census of this exact attempt. Failure retains guards;
   * callers must resolve retained attempts before ending their process. */
  assertFailed(profile: ProfileSnapshot, request: string, launchedPid: number | undefined, deadline: number): Promise<void>;
}
export interface LaunchPort { launch(selection: BuildSelection, requestPath: string, deadline: number): Promise<number> }
/** Production supplies the real native transaction port. Foundation's generic
 * transport primitive remains usable in its original bounded scope; only the
 * fully verified packaged integration may call it for a production launch. */
export interface LaunchAttemptPort {
  reserve(profile: ProfileSnapshot, request: string, deadline: number, build?: BuildGuard): Promise<void>;
  launched(profile: ProfileSnapshot, request: string, pid: number, deadline: number): Promise<void>;
  publishedReady(profile: ProfileSnapshot, request: string, pid: number, deadline: number): Promise<RuntimeRecord | undefined>;
  cancel(profile: ProfileSnapshot, request: string, deadline: number): Promise<void>;
  admitted(profile: ProfileSnapshot, record: RuntimeRecord, deadline: number, request?: string, joiningStartup?: boolean): Promise<void>;
}
export const launchServices: LaunchPort = Object.freeze({
  launch(selection: BuildSelection, requestPath: string, deadline: number): Promise<number> {
    assertTime(deadline);
    const layout = selectedLayout(selection, resolve(fileURLToPath(new URL('../../', import.meta.url))));
    const account = userInfo(); if (account.uid !== process.geteuid?.()) return Promise.reject(profileUnavailable());
    return new Promise((resolve, reject) => {
      const timeout = Math.floor(deadline - now());
      if (!Number.isFinite(timeout) || timeout < 1) { reject(profileUnavailable()); return; }
      execFile(layout.launcher, [layout.bundle, requestPath],
        { timeout, maxBuffer: 128,
          env: { HOME: account.homedir, USER: account.username, PATH: '/usr/bin:/bin' } }, (error, stdout) => {
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
  acquireBuild(): Promise<BuildGuard>; launch?: LaunchPort; attempts?: LaunchAttemptPort; observation?: OpenCommandObservation }) {
  return async (profile: ProfileSnapshot, endpoint: Endpoint, deadline: number, contentionDeadline = Math.min(deadline, now() + 10000),
    label = 'Browser client'): Promise<{ client: RuntimeClient; record: RuntimeRecord; alreadyRunning: boolean }> => {
    noteOpenCommand(options.observation, 'open-starter-profile-recheck');
    assertTime(deadline); await assertProfile(profile);
    // Production leaves time for permanent native cancellation/attestation
    // inside the original request budget. This never extends that budget.
    const admissionDeadline = options.attempts ? deadline - 1000 : deadline;
    noteOpenCommand(options.observation, 'open-runtime-location');
    const location = await runtimeLocation(profile, true);
    if (!location) throw profileUnavailable();
    noteOpenCommand(options.observation, 'open-initial-build-lease');
    const guard = await options.acquireBuild(); let startup: HeldLock | undefined;
    let request = '', launched: number | undefined, attempted = false, resolved = false;
    const release = () => { startup?.release(); guard.release(); resolved = true; };
    try {
      await guard.assert();
      let current = await readRuntime(location);
      let joiningStartup = false;
      if (!current || !originalAlive(current, options.platform)) {
        noteOpenCommand(options.observation, 'open-startup-arbitration');
        const arbitration = options.attempts
          ? await startupArbitration(location, options.platform, contentionDeadline, deadline)
          : await startupArbitration(location, options.platform, contentionDeadline);
        if ('phase' in arbitration) {
          current = arbitration; joiningStartup = true;
          await guard.assert(); assertTime(deadline);
        } else {
          startup = arbitration;
          await guard.assert(); assertTime(deadline);
          current = await readRuntime(location);
        }
      }
      if (current && originalAlive(current, options.platform)) {
        noteOpenCommand(options.observation, 'open-native-ready-attachment');
        const original = current;
        joiningStartup ||= original.phase === 'starting';
        while (current.phase === 'starting' && now() < deadline) {
          await setTimeout(Math.min(25, Math.max(1, deadline - now())));
          const observed = await readRuntime(location);
          if (!observed || observed.instance !== original.instance || observed.pid !== original.pid ||
              observed.processStartId !== original.processStartId || observed.nonce !== original.nonce ||
              observed.build !== original.build || !originalAlive(observed, options.platform)) throw profileUnavailable();
          current = observed;
        }
        await options.attempts?.admitted(profile, current, deadline, undefined, joiningStartup);
        const client = await connectRuntime(location, current, endpoint, options.selection, options.platform, deadline, label);
        try {
          await options.authority.assertReady(profile, current, undefined, joiningStartup);
          await guard.assert(); assertTime(deadline);
          assertTime(deadline); release(); assertTime(deadline);
          return { client, record: current, alreadyRunning: true };
        } catch (error) { client.close(); throw error; }
      }
      if (!startup) throw profileUnavailable();
      noteOpenCommand(options.observation, 'open-current-signed-start');
      await options.authority.assertTrusted(options.selection); assertTime(deadline);
      request = token('req');
      const path = join(location.leaf, `launch-${request}.json`);
      if (await statOrAbsent(path)) throw profileUnavailable();
      await writeNewFile(path, JSON.stringify({ format: 1, request, profile: profile.paths.root,
        profileInstance: profile.record.instance, selection: options.selection }) + '\n');
      await location.assert(); await guard.assert(); assertTime(deadline);
      // Production temporarily takes Owner only inside verified reservation;
      // it releases that exact description before LaunchServices, never waits
      // for a host while retaining the temporary Owner.
      attempted = true;
      assertTime(admissionDeadline);
      noteOpenCommand(options.observation, 'open-reservation');
      await options.attempts?.reserve(profile, request, admissionDeadline, guard);
      await guard.assert(); assertTime(admissionDeadline);
      noteOpenCommand(options.observation, 'open-launch');
      launched = await (options.launch ?? launchServices).launch(options.selection, path, admissionDeadline);
      await options.attempts?.launched(profile, request, launched, admissionDeadline);
      noteOpenCommand(options.observation, 'open-native-ready-attachment');
      do {
        assertTime(admissionDeadline); await guard.assert(); startup.assertIdentity();
        // The native READY Claim follows the atomic runtime file replacement.
        // A strict descriptor/name read during that replacement can fail.
        const published = await options.attempts?.publishedReady(profile, request, launched, admissionDeadline);
        if (!options.attempts || published) {
          const record = await readRuntime(location);
          if (published && (!record || (Object.keys(published) as (keyof RuntimeRecord)[])
            .some(key => published[key] !== record[key]))) throw profileUnavailable();
          if (record && record.phase === 'ready' && originalAlive(record, options.platform)) {
            await options.attempts?.admitted(profile, record, admissionDeadline, request);
            const client = await connectRuntime(location, record, endpoint, options.selection, options.platform, deadline, label);
            try {
              await options.authority.assertReady(profile, record, options.attempts ? request : undefined);
              await guard.assert(); assertTime(deadline);
              assertTime(deadline); release(); assertTime(deadline);
              return { client, record, alreadyRunning: false };
            } catch (error) { client.close(); throw error; }
          }
        }
        await setTimeout(Math.min(25, Math.max(1, admissionDeadline - now())));
      } while (now() < admissionDeadline);
      throw profileUnavailable();
    } catch (error) {
      if (attempted && !resolved) {
        const attempt: RetainedStartup = Object.freeze({ profile, request,
          async resolve(limit: number) {
            // Withdrawal consumes only the remaining original budget. It never
            // renews admission or means an NSWorkspace submission was undone.
            await options.attempts?.cancel(profile, request, limit);
            await options.authority.assertFailed(profile, request, launched, limit);
            await guard.assert(); release(); retained.delete(attempt);
          },
        });
        retained.add(attempt);
        try { await attempt.resolve(deadline); }
        catch { /* preserve exact guards/request; a JS Set is not native custody */ }
      } else if (!resolved) release();
      throw error;
    }
  };
}
