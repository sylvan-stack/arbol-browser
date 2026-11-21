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
import { unavailable } from '../contracts/errors.js';

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
export interface LaunchPort { launch(selection: BuildSelection, requestPath: string, deadline: number, signal?: AbortSignal): Promise<number> }
export type LaunchWithdrawal = 'absent' | 'withdrawn' | 'committed';
/** Production supplies the real native transaction port. Foundation's generic
 * transport primitive remains usable in its original bounded scope; only the
 * fully verified packaged integration may call it for a production launch. */
export interface LaunchAttemptPort {
  reserve(profile: ProfileSnapshot, request: string, deadline: number, build?: BuildGuard, signal?: AbortSignal): Promise<void>;
  launched(profile: ProfileSnapshot, request: string, pid: number, deadline: number, signal?: AbortSignal): Promise<void>;
  publishedReady(profile: ProfileSnapshot, request: string, pid: number, deadline: number): Promise<RuntimeRecord | undefined>;
  cancel(profile: ProfileSnapshot, request: string, deadline: number): Promise<LaunchWithdrawal>;
  admitted(profile: ProfileSnapshot, record: RuntimeRecord, deadline: number, request?: string, joiningStartup?: boolean): Promise<void>;
}
export const launchServices: LaunchPort = Object.freeze({
  launch(selection: BuildSelection, requestPath: string, deadline: number, signal?: AbortSignal): Promise<number> {
    assertTime(deadline);
    if (signal?.aborted) return Promise.reject(unavailable('browser'));
    const layout = selectedLayout(selection, resolve(fileURLToPath(new URL('../../', import.meta.url))));
    const account = userInfo(); if (account.uid !== process.geteuid?.()) return Promise.reject(profileUnavailable());
    return new Promise((resolve, reject) => {
      const timeout = Math.floor(deadline - now());
      if (!Number.isFinite(timeout) || timeout < 1) { reject(profileUnavailable()); return; }
      execFile(layout.launcher, [layout.bundle, requestPath],
        { timeout, maxBuffer: 128, ...(signal ? { signal } : {}),
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
    label = 'Browser client', signal?: AbortSignal): Promise<{ client: RuntimeClient; record: RuntimeRecord; alreadyRunning: boolean }> => {
    const current = (limit = deadline) => {
      if (signal?.aborted) throw unavailable('browser');
      assertTime(limit);
    };
    const poll = (limit: number) => setTimeout(Math.min(25, Math.max(1, limit - now())), undefined,
      signal ? { signal } : undefined);
    noteOpenCommand(options.observation, 'open-starter-profile-recheck');
    current(); await assertProfile(profile); current();
    // Production leaves time for permanent native cancellation/attestation
    // inside the original request budget. This never extends that budget.
    const admissionDeadline = options.attempts ? deadline - 1000 : deadline;
    noteOpenCommand(options.observation, 'open-runtime-location');
    const location = await runtimeLocation(profile, true);
    if (!location) throw profileUnavailable();
    current();
    noteOpenCommand(options.observation, 'open-initial-build-lease');
    const guard = await options.acquireBuild(); let startup: HeldLock | undefined;
    let request = '', launched: number | undefined, attempted = false, resolved = false;
    const release = () => { startup?.release(); guard.release(); resolved = true; };
    try {
      current(); await guard.assert(); current();
      let observedRecord = await readRuntime(location); current();
      let joiningStartup = false;
      if (!observedRecord || !originalAlive(observedRecord, options.platform)) {
        noteOpenCommand(options.observation, 'open-startup-arbitration');
        const arbitration = options.attempts
          ? await startupArbitration(location, options.platform, contentionDeadline, deadline)
          : await startupArbitration(location, options.platform, contentionDeadline);
        if ('phase' in arbitration) {
          observedRecord = arbitration; joiningStartup = true;
          current(); await guard.assert(); current();
        } else {
          startup = arbitration;
          current(); await guard.assert(); current();
          observedRecord = await readRuntime(location); current();
        }
      }
      if (observedRecord && originalAlive(observedRecord, options.platform)) {
        noteOpenCommand(options.observation, 'open-native-ready-attachment');
        const original = observedRecord;
        joiningStartup ||= original.phase === 'starting';
        while (observedRecord.phase === 'starting' && now() < deadline) {
          await poll(deadline); current();
          const observed = await readRuntime(location); current();
          if (!observed || observed.instance !== original.instance || observed.pid !== original.pid ||
              observed.processStartId !== original.processStartId || observed.nonce !== original.nonce ||
              observed.build !== original.build || !originalAlive(observed, options.platform)) throw profileUnavailable();
          observedRecord = observed;
        }
        await options.attempts?.admitted(profile, observedRecord, deadline, undefined, joiningStartup); current();
        const client = await connectRuntime(location, observedRecord, endpoint, options.selection, options.platform, deadline, label, signal);
        try {
          current(); await options.authority.assertReady(profile, observedRecord, undefined, joiningStartup); current();
          await guard.assert(); current();
          release(); current();
          return { client, record: observedRecord, alreadyRunning: true };
        } catch (error) { client.close(); throw error; }
      }
      if (!startup) throw profileUnavailable();
      noteOpenCommand(options.observation, 'open-current-signed-start');
      await options.authority.assertTrusted(options.selection); current();
      request = token('req');
      const path = join(location.leaf, `launch-${request}.json`);
      if (await statOrAbsent(path)) throw profileUnavailable();
      current(admissionDeadline);
      await writeNewFile(path, JSON.stringify({ format: 1, request, profile: profile.paths.root,
        profileInstance: profile.record.instance, selection: options.selection }) + '\n');
      current(); await location.assert(); await guard.assert(); current(admissionDeadline);
      // Production temporarily takes Owner only inside verified reservation;
      // it releases that exact description before LaunchServices, never waits
      // for a host while retaining the temporary Owner.
      attempted = true;
      noteOpenCommand(options.observation, 'open-reservation');
      await options.attempts?.reserve(profile, request, admissionDeadline, guard, signal);
      current(admissionDeadline); await guard.assert(); current(admissionDeadline);
      noteOpenCommand(options.observation, 'open-launch');
      launched = await (options.launch ?? launchServices).launch(options.selection, path, admissionDeadline, signal);
      current(admissionDeadline);
      await options.attempts?.launched(profile, request, launched, admissionDeadline, signal);
      noteOpenCommand(options.observation, 'open-native-ready-attachment');
      do {
        current(admissionDeadline); await guard.assert(); startup.assertIdentity(); current(admissionDeadline);
        // The native READY Claim follows the atomic runtime file replacement.
        // A strict descriptor/name read during that replacement can fail.
        const published = await options.attempts?.publishedReady(profile, request, launched, admissionDeadline);
        current(admissionDeadline);
        if (!options.attempts || published) {
          const record = await readRuntime(location); current(admissionDeadline);
          const ready = record?.phase === 'ready' && originalAlive(record, options.platform);
          if (published && (!ready || (Object.keys(published) as (keyof RuntimeRecord)[])
            .some(key => published[key] !== record[key]))) throw profileUnavailable();
          if (ready) {
            await options.attempts?.admitted(profile, record, admissionDeadline, request); current();
            const client = await connectRuntime(location, record, endpoint, options.selection, options.platform, deadline, label, signal);
            try {
              current(); await options.authority.assertReady(profile, record, options.attempts ? request : undefined); current();
              await guard.assert(); current();
              release(); current();
              return { client, record, alreadyRunning: false };
            } catch (error) { client.close(); throw error; }
          }
        }
        await poll(admissionDeadline);
      } while (now() < admissionDeadline);
      throw profileUnavailable();
    } catch (error) {
      if (attempted && !resolved) {
        const attempt: RetainedStartup = Object.freeze({ profile, request,
          async resolve(limit: number) {
            // Withdrawal consumes only the remaining original budget. It never
            // renews admission or means an NSWorkspace submission was undone.
            const withdrawal = await options.attempts?.cancel(profile, request, limit);
            if (withdrawal === 'committed') {
              // The exact host owns the admitted lifetime. Settle only this
              // caller's locks and leave the shared Claim and peers intact.
              await guard.assert(); release(); retained.delete(attempt); return;
            }
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
