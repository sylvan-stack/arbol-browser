import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import type { BaseWindow } from 'electron';
import type { HeldLock, PlatformPort } from '../runtime/platform.js';
import { refused } from './tabs.js';

/** One visible window across profile hosts. These leases never own profile data. */
export function bindProfilePresentation(window: BaseWindow, state: string, platform: PlatformPort,
  canYield: (ownerSwitch: boolean) => boolean) {
  const requests = join(state, 'window-presentation-request.lock');
  const visible = join(state, 'window-presentation-visible.lock');
  const busy = () => refused('control_refused', 'Finish the current Browser interaction before switching profiles.');
  let held: HeldLock | null = null;
  let watch: NodeJS.Timeout | undefined;
  let presenting = false;
  const release = () => {
    clearInterval(watch); watch = undefined;
    held?.release(); held = null;
  };
  const hide = () => {
    if (!window.isDestroyed()) window.hide();
    if (window.isDestroyed() || !window.isVisible()) release();
  };
  const enforce = () => {
    // A native restore/show outside our request must not reveal a second profile.
    if (!held) hide();
  };
  window.on('show', enforce);
  window.on('restore', enforce);
  window.on('hide', () => { if (!window.isVisible()) release(); });
  window.once('closed', release);

  const showUnderRequest = (restore: boolean) => {
    if (window.isDestroyed()) throw busy();
    if (!restore && window.isMinimized()) return false;
    if (!held) {
      held = platform.tryLock(visible);
      if (!held) return false;
      watch = setInterval(() => {
        try { held?.assertIdentity(); } catch { hide(); return; }
        if (presenting) return;
        try {
          const request = platform.trySharedLock(requests);
          if (request) request.release();
          else if (canYield(false)) hide();
        } catch { /* An uncertain request cannot displace the visible window. */ }
      }, 100);
      watch.unref();
    }
    try {
      held.assertIdentity();
      if (window.isMinimized()) window.restore();
      else if (!window.isVisible()) window.showInactive();
      return window.isVisible() && !window.isMinimized();
    } catch (error) { hide(); throw error; }
  };
  function offer(): boolean {
    if (held) return window.isVisible() && !window.isMinimized();
    const request = platform.trySharedLock(requests);
    if (!request) return false;
    try {
      request.assertIdentity();
      if (showUnderRequest(false)) return true;
      if (held) hide();
      return false;
    }
    finally { request.release(); }
  }
  return {
    offer,
    async show(deadline: number, signal: AbortSignal, check: () => void, raiseWindow = false): Promise<void> {
      check();
      if (signal.aborted || performance.now() >= deadline) throw busy();
      if (held && window.isVisible() && !window.isMinimized()) {
        held.assertIdentity();
        if (raiseWindow) window.moveTop();
        return;
      }
      const cutoff = Math.min(deadline, performance.now() + 1800);
      let request: HeldLock | null = null;
      let shown = false;
      try {
        while (performance.now() < cutoff && !signal.aborted) {
          check();
          request ??= platform.tryLock(requests);
          if (request) {
            presenting = true;
            request.assertIdentity();
            shown = showUnderRequest(true);
            if (shown) {
              if (raiseWindow) window.moveTop();
              return;
            }
          }
          await delay(25, undefined, { signal });
        }
        throw busy();
      } finally {
        if (request) {
          try { if (!shown && held) hide(); }
          finally { presenting = false; request.release(); }
        }
      }
    },
    yieldForSwitch(): () => void {
      if (!canYield(true)) throw busy();
      hide();
      if (window.isVisible()) throw busy();
      return () => { if (!window.isDestroyed()) offer(); };
    },
  };
}
