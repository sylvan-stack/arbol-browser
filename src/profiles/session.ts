import type { App, Session } from 'electron';
import { randomBytes } from 'node:crypto';
import { directory, assertDirectory, profileUnavailable } from './paths.js';
import { assertEngineRootStorage, type EngineTransaction } from './compatibility.js';
import { assertHostCustody, type HostCustody } from '../runtime/custody.js';
import type { WebsiteSessionReceipt } from '../runtime/platform.js';

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
  /** Production accepts only the actual canonical Electron API after ready. */
  bindActual(): Promise<ProfileSessions>;
}
export interface ActualSessionFactory { readonly role: 'actual-electron-session-factory' }
export interface ActualSessionSeal { readonly role: 'actual-session-seal' }
interface ActualFactory {
  readonly app: App; readonly api: SessionFactory;
  readonly fromPath: SessionFactory['fromPath']; readonly fromPartition: SessionFactory['fromPartition'];
  readonly quit: App['quit'];
}
interface ActualSessionOperations {
  readonly websitePath: Session['getStoragePath']; readonly shellPath: Session['getStoragePath'];
  readonly dom: Session['flushStorageData']; readonly cookies: Session['cookies']; readonly cookieFlush: Session['cookies']['flushStore'];
}
function assertOperations(website: Session, shell: Session, operations: ActualSessionOperations): void {
  if (website.getStoragePath !== operations.websitePath || shell.getStoragePath !== operations.shellPath ||
      website.flushStorageData !== operations.dom || website.cookies !== operations.cookies || operations.cookies.flushStore !== operations.cookieFlush)
    throw profileUnavailable();
}
const actualFactories = new WeakMap<ActualSessionFactory, ActualFactory>();
const actualSeals = new WeakMap<ActualSessionSeal, { factory: ActualSessionFactory; website: Session; shell: Session;
  path: string; partition: string; operations: ActualSessionOperations; used: boolean }>();
const actualSessions = new WeakMap<ProfileSessions, { custody: HostCustody; factory: ActualFactory; native: WebsiteSessionReceipt; operations: ActualSessionOperations; quitting: boolean }>();
export function assertActualSessionFactory(factory: ActualSessionFactory): void {
  const value = actualFactories.get(factory);
  if (!value || process.type !== 'browser' || !value.app.isReady() || value.api.fromPath !== value.fromPath ||
      value.api.fromPartition !== value.fromPartition || value.app.quit !== value.quit) throw profileUnavailable();
}
async function actualSessionFactory(app: ProfileApp): Promise<ActualSessionFactory> {
  if (process.type !== 'browser' || !app.isReady()) throw profileUnavailable();
  const address = 'electron'; const actual = await import(address) as typeof import('electron');
  if (actual.app !== app || !actual.app.isReady() || typeof actual.session.fromPath !== 'function' || typeof actual.session.fromPartition !== 'function')
    throw profileUnavailable();
  const factory: ActualSessionFactory = Object.freeze({ role: 'actual-electron-session-factory' });
  actualFactories.set(factory, { app: actual.app, api: actual.session, fromPath: actual.session.fromPath,
    fromPartition: actual.session.fromPartition, quit: actual.app.quit });
  assertActualSessionFactory(factory); return factory;
}
export function consumeActualSessionSeal(factory: ActualSessionFactory, seal: ActualSessionSeal):
  Readonly<{ format: 1; websitePath: string; shellPartition: string; shellStoragePath: null }> {
  assertActualSessionFactory(factory); const value = actualSeals.get(seal);
  if (!value || value.used || value.factory !== factory || value.website === value.shell || !/^shell-[0-9a-f]{32}$/.test(value.partition))
    throw profileUnavailable();
  assertOperations(value.website, value.shell, value.operations);
  if (value.operations.websitePath.call(value.website) !== value.path || value.operations.shellPath.call(value.shell) !== null) throw profileUnavailable();
  value.used = true;
  return Object.freeze({ format: 1, websitePath: value.path, shellPartition: value.partition, shellStoragePath: null });
}
export function assertProductionSessions(sessions: ProfileSessions, custody: HostCustody): void {
  const actual = actualSessions.get(sessions);
  if (!actual || actual.custody !== custody) throw profileUnavailable(); assertHostCustody(custody);
  assertOperations(sessions.website, sessions.shell, actual.operations);
  if (sessions.website === sessions.shell || actual.operations.websitePath.call(sessions.website) !== custody.instance.owner.profile.paths.data ||
      actual.operations.shellPath.call(sessions.shell) !== null) throw profileUnavailable();
}
/** Only the canonical production lifecycle uses these actual event callbacks.
 * DOM/cookie facts have no public assertion method: their only producer is the
 * real same-website flush below. Quit invokes the captured actual app itself. */
export function productionSessionShutdown(sessions: ProfileSessions, custody: HostCustody): Readonly<{
  pagesRetired(): void; quit(): void; isQuitting(): boolean;
}> {
  assertProductionSessions(sessions, custody); const actual = actualSessions.get(sessions)!;
  return Object.freeze({
    pagesRetired() { assertProductionSessions(sessions, custody); actual.native.pagesRetired(); },
    quit() {
      assertProductionSessions(sessions, custody); if (actual.quitting) return;
      if (actual.factory.app.quit !== actual.factory.quit) return custody.terminate();
      actual.native.quitIntended(); actual.quitting = true; actual.factory.quit.call(actual.factory.app);
    },
    isQuitting: () => actual.quitting,
  });
}
const configuredApps = new WeakSet<ProfileApp>();
/** No Electron runtime import: the host injects its own actual app/session objects.
 * Prepared dirty marker and retained owner are mandatory even before setPath.
 * This service creates no windows/views and grants no native input admission. */
export async function configureProfileSession(app: ProfileApp, transaction: EngineTransaction, custody?: HostCustody): Promise<SessionBinding> {
  if (custody) {
    assertHostCustody(custody);
    if (custody.instance.owner !== transaction.owner) throw profileUnavailable();
    custody.assertMarker();
  }
  await transaction.assertReady();
  const paths = transaction.owner.profile.paths;
  const data = await directory(paths.data), userData = await directory(paths.userData);
  await directory(paths.logs);
  if (custody) await assertEngineRootStorage(transaction.owner, await directory(paths.root));
  if (app.isReady() || configuredApps.has(app)) throw profileUnavailable();
  configuredApps.add(app);
  if (custody) { if (custody.instance.owner !== transaction.owner) return custody.terminate(); custody.assertMarker(); }
  // Synchronous: never allow readiness or another profile between these operations.
  app.setPath('userData', paths.userData);
  // Electron allows the network service to persist only within this parent.
  // Keep it separate from the exact website context created at data/.
  app.setPath('sessionData', custody ? paths.root : paths.userData);
  app.setAppLogsPath(paths.logs);
  let used = false;
  const prebind = async () => {
    if (used || !app.isReady()) throw profileUnavailable(); used = true;
    await transaction.assertReady(); await assertDirectory(paths.data, data); await assertDirectory(paths.userData, userData);
  };
  const sessionsFor = (website: Session, shell: Session, native: () => WebsiteSessionReceipt | undefined, operations?: ActualSessionOperations): ProfileSessions => Object.freeze({ website, shell,
    async flushStorage() {
      try {
        await transaction.assertReady();
        if (operations) {
          assertOperations(website, shell, operations);
          operations.dom.call(website); native()!.domRequested();
          await operations.cookieFlush.call(operations.cookies);
          assertOperations(website, shell, operations); native()!.cookieAcknowledged();
        } else {
          website.flushStorageData(); await website.cookies.flushStore();
        }
        await transaction.assertReady();
      } catch (error) { if (custody) return custody.terminate(); throw error; }
    },
  });
  return Object.freeze({
    async bind(factory: SessionFactory): Promise<ProfileSessions> {
      if (custody) throw profileUnavailable(); // Foundation's explicit generic port only
      await prebind();
      const website = factory.fromPath(paths.data, { cache: true });
      const shell = factory.fromPartition(`shell-${randomBytes(16).toString('hex')}`, { cache: false });
      if (website === shell || website.getStoragePath() !== paths.data || shell.getStoragePath() !== null) throw profileUnavailable();
      await transaction.assertReady(); return sessionsFor(website, shell, () => undefined);
    },
    async bindActual(): Promise<ProfileSessions> {
      if (!custody) throw profileUnavailable();
      let permit: ReturnType<HostCustody['beginSessionUse']> | undefined;
      let native: WebsiteSessionReceipt | undefined;
      try {
        await prebind();
        const factory = await actualSessionFactory(app); assertActualSessionFactory(factory);
        const actual = actualFactories.get(factory)!; assertHostCustody(custody);
        permit = custody.beginSessionUse(factory);
        // NO await or injectable callback between native grant and actual seal.
        const website = actual.fromPath.call(actual.api, paths.data, { cache: true });
        const partition = `shell-${randomBytes(16).toString('hex')}`;
        const shell = actual.fromPartition.call(actual.api, partition, { cache: false });
        if (website === shell || website.getStoragePath() !== paths.data || shell.getStoragePath() !== null) return permit.abort();
        const cookies = website.cookies;
        const operations: ActualSessionOperations = Object.freeze({ websitePath: website.getStoragePath, shellPath: shell.getStoragePath,
          dom: website.flushStorageData, cookies, cookieFlush: cookies.flushStore });
        assertOperations(website, shell, operations);
        const sessions = sessionsFor(website, shell, () => native, operations);
        const seal: ActualSessionSeal = Object.freeze({ role: 'actual-session-seal' });
        actualSeals.set(seal, { factory, website, shell, path: paths.data, partition, operations, used: false });
        native = permit.accept(seal);
        actualSessions.set(sessions, { custody, factory: actual, native, operations, quitting: false });
        await transaction.assertReady(); assertProductionSessions(sessions, custody); return sessions;
      } catch { return permit ? permit.abort() : custody.terminate(); }
    },
  });
}
