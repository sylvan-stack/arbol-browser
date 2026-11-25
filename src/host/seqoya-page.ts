import type { WebContents } from 'electron';
import { now } from '../runtime/instance.js';
import { assertWindowHost, type WindowHost } from './windows.js';

const destinations = {
  'codex/chatgpt': 'https://chatgpt.com/settings/usage',
  'pi/chatgpt': 'https://chatgpt.com/settings/usage',
  'claude/anthropic': 'https://claude.ai/settings/usage',
  'pi/kimi-coding': 'https://www.kimi.ai/code/console',
  'pi/deepseek': 'https://platform.deepseek.com/usage',
  'mimo/xiaomi': 'https://platform.xiaomimimo.com/console/plan-manage',
  'pi/zai': 'https://z.ai/manage-apikey/coding-plan/personal/my-plan',
  'pi/minimax': 'https://platform.minimax.io/console/usage',
} as const;

export type SeqoyaProvider = keyof typeof destinations;

export function isSeqoyaProvider(value: unknown): value is SeqoyaProvider {
  return typeof value === 'string' && Object.hasOwn(destinations, value);
}

export class SeqoyaPageRefusal extends Error {
  constructor(readonly code: 'deferred' | 'dashboard_unavailable' | 'authentication_required') {
    super(code);
  }
}

const active = new WeakSet<WindowHost>();
const redirect = (provider: SeqoyaProvider, target: URL, address: string): boolean => {
  try {
    const url = new URL(address);
    return url.origin === target.origin && !url.username && !url.password &&
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
): Promise<T> {
  assertWindowHost(host);
  const idle = () => !host.hasForegroundWork() && !ownerBusy() && host.presentationStable();
  if (active.has(host) || !idle()) throw new SeqoyaPageRefusal('deferred');
  if (!Number.isFinite(deadline) || deadline <= now() || signal.aborted) {
    throw new SeqoyaPageRefusal('dashboard_unavailable');
  }
  const target = new URL(destinations[provider]);
  const page = host.createPage();
  active.add(host);
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
    contents.on('will-navigate', event => limitNavigation(event, event.url, true));
    contents.on('will-frame-navigate', event => limitNavigation(event, event.url, event.isMainFrame));
    contents.on('will-redirect', (event, address, _, main) => limitNavigation(event, address, main));
    contents.on('did-start-navigation', event => { if (event.isMainFrame) navigation++; });
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
    try { await page.retire(); } finally { active.delete(host); }
  }
}
