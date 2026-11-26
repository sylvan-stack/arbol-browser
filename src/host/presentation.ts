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

  const showUnderRequest = () => {
    if (window.isDestroyed()) throw busy();
    if (!held) {
      held = platform.tryLock(visible);
      if (!held) return false;
      watch = setInterval(() => {
        try { held?.assertIdentity(); } catch { hide(); return; }
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
      if (!window.isVisible()) window.showInactive();
      if (!window.isVisible()) throw busy();
      return true;
    } catch (error) { hide(); throw error; }
  };
  function offer(): boolean {
    if (held) return showUnderRequest();
    const request = platform.tryLock(requests);
    if (!request) return false;
    try { request.assertIdentity(); return showUnderRequest(); }
    finally { request.release(); }
  }
  return {
    offer,
    async show(deadline: number, signal: AbortSignal, check: () => void): Promise<void> {
      check();
      if (signal.aborted) throw busy();
      if (held && showUnderRequest()) return;
      const cutoff = Math.min(deadline, performance.now() + 1800);
      let request: HeldLock | null = null;
      try {
        while (performance.now() < cutoff && !signal.aborted) {
          check();
          request ??= platform.tryLock(requests);
          if (request) {
            request.assertIdentity();
            if (showUnderRequest()) return;
          }
          await delay(25, undefined, { signal });
        }
        throw busy();
      } finally { request?.release(); }
    },
    yieldForSwitch(): () => void {
      if (!canYield(true)) throw busy();
      hide();
      if (window.isVisible()) throw busy();
      return () => { if (!window.isDestroyed()) offer(); };
    },
  };
}
