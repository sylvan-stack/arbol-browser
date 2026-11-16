import type { Contract } from '../contracts/generated.js';
import type { TabAuthority } from './authority.js';
import { refused, type TabState, type TabTarget } from './tabs.js';

export interface SharingTransition {
  readonly state: TabState;
  readonly settledAction?: Contract<'browser.SettledAction'>;
}
export interface SharingTake {
  /** Starts the privacy transition synchronously, before returning its promise. */
  take(target: TabTarget, expected: number): Promise<SharingTransition>;
}
/** Host-only operations. Agent requests have no path to share or grant control. */
export function createSharing(authority: TabAuthority, transitions: SharingTake) {
  return Object.freeze({
    share(target: TabTarget, recipient: string, expected: number): SharingTransition {
      authority.grant(target, recipient, expected); authority.changed();
      return { state: authority.state(target) };
    },
    stopSharing(target: TabTarget, recipient: string, expected: number): Promise<SharingTransition> {
      const state = authority.expected(target, expected); authority.attachment(recipient);
      if (!state.visibleTo.includes(recipient)) throw refused('control_refused');
      // Start the exact guarded Take before any callback can reenter. Removing
      // the grant and all recipient references/deliveries never waits for drain.
      const pending = state.controller.kind === 'agent' && state.controller.client === recipient
        ? transitions.take(target, expected) : undefined;
      authority.revoke(target, recipient); authority.changed();
      return pending ? pending.then(result => ({ state: authority.state(target),
        ...(result.settledAction ? { settledAction: result.settledAction } : {}) }))
        : Promise.resolve({ state: authority.state(target) });
    },
  });
}
