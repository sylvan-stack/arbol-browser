import type { BaseWindow, WebContents } from 'electron';
import { now } from '../runtime/instance.js';
import { seqoyaDestinations, type SeqoyaProvider } from '../runtime/seqoya-wire.js';
import { assertWindowHost, type WindowHost } from './windows.js';

export type { SeqoyaProvider } from '../runtime/seqoya-wire.js';

export class SeqoyaPageRefusal extends Error {
  constructor(readonly code: 'deferred' | 'dashboard_unavailable' | 'authentication_required') {
    super(code);
  }
}

const active = new WeakSet<BaseWindow>();
const redirect = (provider: SeqoyaProvider, target: URL, address: string): boolean => {
  try {
    const url = new URL(address);
    const chatgptOverview = (provider === 'codex/chatgpt' || provider === 'pi/chatgpt') &&
      url.search === '?tab=overview';
    return url.origin === target.origin && !url.username && !url.password && (!url.search || chatgptOverview) && !url.hash &&
      (url.pathname === target.pathname || url.pathname === target.pathname + '/' ||
       (provider === 'claude/anthropic' && url.pathname === '/new'));
  } catch {
    return false;
  }
};

/** A profile-owned hidden surface that never enters the ordinary tab registry. */
export async function readSeqoyaPage<T>(
  host: WindowHost, provider: SeqoyaProvider, deadline: number, signal: AbortSignal,
  ownerBusy: () => boolean, read: (contents: WebContents, check: () => void) => Promise<T>,
  source: 'usage' | 'minimax-billing' = 'usage',
): Promise<T> {
  assertWindowHost(host);
  const window = host.window;
  const idle = () => !window.isDestroyed() && !window.isFocused() && window.isEnabled() && !ownerBusy() && host.presentationStable();
  if (active.has(window) || !idle()) throw new SeqoyaPageRefusal('deferred');
  if (!Number.isFinite(deadline) || deadline <= now() || signal.aborted) {
    throw new SeqoyaPageRefusal('dashboard_unavailable');
  }
  if (source === 'minimax-billing' && provider !== 'pi/minimax') {
    throw new SeqoyaPageRefusal('dashboard_unavailable');
  }
  const target = new URL(source === 'minimax-billing'
    ? 'https://platform.minimax.io/console/recharge-records'
    : seqoyaDestinations[provider]);
  const page = host.createPage();
  active.add(window);
  const contents = page.view.webContents;
  let navigation = 0;
  let inspectedNavigation: number | undefined;
  let stop: SeqoyaPageRefusal | undefined;
  let cancel!: (reason: SeqoyaPageRefusal) => void;
  const cancelled = new Promise<never>((_, reject) => { cancel = reject; });
  const refuse = (reason: SeqoyaPageRefusal) => {
    if (stop) return;
    stop = reason;
    cancel(reason);
  };
  const unavailable = () => refuse(new SeqoyaPageRefusal('dashboard_unavailable'));
  const deferral = () => refuse(new SeqoyaPageRefusal('deferred'));
  const authorize = () => {
    if (stop) throw stop;
    if (signal.aborted || deadline <= now() || !host.owns(page) || !page.binding().blocked || contents.isDestroyed()) {
      throw new SeqoyaPageRefusal('dashboard_unavailable');
    }
    if (!idle() || host.selected() === page || page.view.getVisible()) throw new SeqoyaPageRefusal('deferred');
  };
  const check = () => {
    authorize();
    if (navigation !== inspectedNavigation) throw new SeqoyaPageRefusal('dashboard_unavailable');
    if (!redirect(provider, target, contents.getURL())) throw new SeqoyaPageRefusal('authentication_required');
  };
  const limitNavigation = (event: Electron.Event, address: string, main: boolean) => {
    try {
      authorize();
      if (main && redirect(provider, target, address)) return;
      event.preventDefault();
      if (main) refuse(new SeqoyaPageRefusal('authentication_required'));
    } catch (error) {
      event.preventDefault();
      refuse(error instanceof SeqoyaPageRefusal ? error : new SeqoyaPageRefusal('dashboard_unavailable'));
    }
  };
  try {
    page.setNativeBlocked(true);
    // Size the hidden surface for the same dashboard layout as visible tabs.
    page.present(false);
    contents.on('will-navigate', event => limitNavigation(event, event.url, true));
    contents.on('will-frame-navigate', event => limitNavigation(event, event.url, event.isMainFrame));
    contents.on('will-redirect', (event, address, _, main) => limitNavigation(event, address, main));
    contents.on('did-start-navigation', event => {
      if (event.isMainFrame && (!event.isSameDocument || !redirect(provider, target, event.url))) navigation++;
    });
    contents.on('did-navigate-in-page', (_, address, main) => {
      if (main && !redirect(provider, target, address)) {
        refuse(new SeqoyaPageRefusal('authentication_required'));
      }
    });
    contents.on('will-prevent-unload', event => event.preventDefault());
    contents.once('render-process-gone', unavailable);
    contents.once('destroyed', unavailable);
    host.window.on('focus', deferral);
    signal.addEventListener('abort', unavailable, { once: true });
    const timeout = setTimeout(unavailable, Math.min(30_000, Math.max(1, deadline - now())));
    try {
      const result = await Promise.race([(async () => {
        authorize();
        await contents.loadURL(target.href);
        inspectedNavigation = navigation;
        check();
        const value = await read(contents, check);
        check();
        return value;
      })(), cancelled]);
      check();
      return result;
    } catch (error) {
      if (stop) throw stop;
      throw error instanceof SeqoyaPageRefusal ? error : new SeqoyaPageRefusal('dashboard_unavailable');
    } finally {
      clearTimeout(timeout);
    }
  } finally {
    signal.removeEventListener('abort', unavailable);
    host.window.removeListener('focus', deferral);
    contents.removeListener('destroyed', unavailable);
    try { await page.retire(); } finally { active.delete(window); }
  }
}
