import type { App, Session } from 'electron';
import { randomBytes } from 'node:crypto';
import { directory, assertDirectory, profileUnavailable } from './paths.js';
import type { EngineTransaction } from './compatibility.js';

export type ProfileApp = Pick<App, 'isReady' | 'setPath' | 'setAppLogsPath'>;
export interface SessionFactory {
  fromPath(path: string, options: { cache: boolean }): Session;
  fromPartition(partition: string, options: { cache: boolean }): Session;
}
export interface ProfileSessions {
  readonly website: Session;
  readonly shell: Session;
  /** Flushes native storage only. This alone is NOT complete engine exit evidence. */
  flushStorage(): Promise<void>;
}
export interface SessionBinding {
  /** Invoke only after app readiness, with the host's actual Electron session API.
   * All website WebContentsViews must explicitly use website; shell uses shell. */
  bind(factory: SessionFactory): Promise<ProfileSessions>;
}
const configuredApps = new WeakSet<ProfileApp>();
/** No Electron runtime import: the host injects its own actual app/session objects.
 * Prepared dirty marker and retained owner are mandatory even before setPath.
 * This service creates no windows/views and grants no native input admission. */
export async function configureProfileSession(app: ProfileApp, transaction: EngineTransaction): Promise<SessionBinding> {
  await transaction.assertReady();
  const paths = transaction.owner.profile.paths;
  const data = await directory(paths.data), userData = await directory(paths.userData);
  await directory(paths.logs);
  if (app.isReady() || configuredApps.has(app)) throw profileUnavailable();
  configuredApps.add(app);
  // Synchronous: never allow readiness or another profile between these operations.
  app.setPath('userData', paths.userData);
  app.setPath('sessionData', paths.userData);
  app.setAppLogsPath(paths.logs);
  let used = false;
  return Object.freeze({
    async bind(factory: SessionFactory): Promise<ProfileSessions> {
      if (used || !app.isReady()) throw profileUnavailable();
      used = true;
      await transaction.assertReady();
      await assertDirectory(paths.data, data); await assertDirectory(paths.userData, userData);
      const website = factory.fromPath(paths.data, { cache: true });
      const shell = factory.fromPartition(`shell-${randomBytes(16).toString('hex')}`, { cache: false });
      if (website === shell || website.getStoragePath() !== paths.data || shell.getStoragePath() !== null)
        throw profileUnavailable();
      await transaction.assertReady();
      return Object.freeze({ website, shell,
        async flushStorage() {
          await transaction.assertReady();
          website.flushStorageData();
          await website.cookies.flushStore();
          await transaction.assertReady();
        },
      });
    },
  });
}
