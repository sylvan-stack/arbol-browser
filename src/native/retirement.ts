/** One production retirement path for Take/recovery/release/shutdown. */
import type { View, WebContentsView } from 'electron';
import { performance } from 'node:perf_hooks';
import type { Binding, BindingKey } from './api.js';
import type { NativeCompatibility } from './preflight.js';
export const bindingKey = (value: Binding): BindingKey => Object.freeze({
  id: value.id, nonce: value.nonce, webContentsId: value.webContentsId, revision: value.revision,
});
export async function retireNativeTarget(native: NativeCompatibility, key: BindingKey, parent: View,
  view: WebContentsView, fatal: (reason: string) => never): Promise<Binding> {
  const deadline = performance.now() + 1000, contents = view.webContents;
  let observedDestroyed = false;
  const ensureTime = () => { if (performance.now() >= deadline) fatal('native_retirement_unavailable'); };
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let onDestroyed: () => void = () => {};
  try {
    native.assertIntegrity(); ensureTime();
    if (contents.id !== key.webContentsId || contents.isDestroyed() || !parent.children.includes(view)) return fatal('native_retirement_unavailable');
    const destroyed = new Promise<void>((resolve, reject) => {
      onDestroyed = () => { observedDestroyed = true; resolve(); };
      contents.once('destroyed', onDestroyed);
      timeout = setTimeout(() => reject(new Error('native_retirement_unavailable')), Math.max(1, deadline - performance.now()));
    });
    void destroyed.catch(() => {}); // observe early rejection while synchronous native work is pending
    const blocked = native.ownership.mark(key, true);
    const retired = native.ownership.retire(bindingKey(blocked));
    if (!blocked.blocked || blocked.retired || !retired.blocked || !retired.retired ||
        retired.id !== key.id || retired.nonce !== key.nonce || retired.webContentsId !== contents.id || retired.revision !== blocked.revision + 1) return fatal('native_retirement_unavailable');
    ensureTime();
    parent.removeChildView(view);
    if (parent.children.includes(view)) return fatal('native_retirement_unavailable');
    ensureTime(); contents.close({ waitForBeforeUnload: false });
    await destroyed;
    ensureTime();
    if (!observedDestroyed || !contents.isDestroyed() || parent.children.includes(view)) return fatal('native_retirement_unavailable');
    native.assertIntegrity(); contents.removeListener('destroyed', onDestroyed); ensureTime();
    return retired;
  } catch { return fatal('native_retirement_unavailable'); }
  finally { if (timeout) clearTimeout(timeout); } // local wait only; never touches watchdog or native policy
}
