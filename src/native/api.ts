/** Private main-process ABI 1. Keys and native capabilities never cross a renderer/MCP boundary. */
import type { Contract } from '../contracts/generated.js';
import { validator } from '../contracts/schema.js';
import { nativeLimit, stable } from './manifest.js';
export type BindingKey = Readonly<Contract<'native.BindingKey'>>;
export type Binding = Readonly<Contract<'native.Binding'>>;
export type Interaction = Readonly<Contract<'native.Interaction'>>;
export const ownershipExports = Object.freeze(['beginBinding', 'bindingInfo', 'checkIntegrity', 'finishBinding', 'getABI',
  'install', 'interactionState', 'mark', 'restore', 'retire', 'seal', 'status'] as const);
export interface OwnershipAddon {
  getABI(): string;
  install(expected: string): string;
  status(): string;
  checkIntegrity(): string;
  seal(): string;
  beginBinding(windowHandle: Buffer, webContentsId: number): void;
  finishBinding(): string;
  bindingInfo(key: string): string;
  mark(key: string, blocked: boolean): string;
  restore(key: string): string;
  retire(key: string): string;
  interactionState(key: string): string;
}
export function validateOwnershipAddon(value: unknown): OwnershipAddon {
  if (!value || typeof value !== 'object' || Object.getOwnPropertySymbols(value).length ||
      stable(Object.getOwnPropertyNames(value).sort()) !== stable(ownershipExports)) throw new Error('native_export_shape');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const name of ownershipExports) if (typeof descriptors[name]?.value !== 'function' || descriptors[name]?.get || descriptors[name]?.set)
    throw new Error('native_export_shape');
  return value as OwnershipAddon;
}
export interface NativeOwnership {
  /** attach must perform precisely the one synchronous host addChildView, with no yield. */
  bind(windowHandle: Buffer, webContentsId: number, attach: () => void): Binding;
  bindingInfo(key: BindingKey): Binding;
  mark(key: BindingKey, blocked: boolean): Binding;
  restore(key: BindingKey): Binding;
  retire(key: BindingKey): Binding;
  interactionState(key: BindingKey): Interaction;
}
/** Constructed only around preflight's one verified, installed addon instance.
 * All failures go to its irreversible profile-fatal port; no operation retries. */
export function createNativeOwnership(addon: OwnershipAddon, assertIntegrity: () => unknown, fatal: () => never): NativeOwnership {
  const bindings = new Map<number, Binding>();
  const nonces = new Set<string>(), contents = new Set<number>(), dropCounts = new Map<number, number>();
  let creating = false;
  function checked<T>(operation: () => T): T {
    try {
      if (creating) return fatal();
      assertIntegrity(); const result = operation(); assertIntegrity(); return result;
    } catch { return fatal(); }
  }
  function reply<K extends 'native.Binding' | 'native.Interaction'>(kind: K, raw: unknown): Readonly<Contract<K>> {
    if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > nativeLimit) return fatal();
    const value: unknown = JSON.parse(raw);
    if (!validator(kind)(value)) return fatal();
    return Object.freeze(value);
  }
  function current(key: BindingKey): { value: Binding; encoded: string } {
    if (!validator('native.BindingKey')(key)) return fatal();
    const value = bindings.get(key.id);
    if (!value || value.retired || value.id !== key.id || value.nonce !== key.nonce || value.webContentsId !== key.webContentsId || value.revision !== key.revision) return fatal();
    return { value, encoded: JSON.stringify({ id: value.id, nonce: value.nonce, webContentsId: value.webContentsId, revision: value.revision }) };
  }
  function acknowledge(raw: unknown, expected: Binding): Binding {
    const value = reply('native.Binding', raw);
    if (stable(value) !== stable(expected)) return fatal();
    return value;
  }
  function transition(key: BindingKey, kind: 'mark' | 'restore' | 'retire', blocked?: boolean): Binding {
    return checked(() => {
      const before = current(key);
      if (kind !== 'restore' && before.value.revision === 0xffffffff) return fatal();
      if (kind === 'mark' && typeof blocked !== 'boolean') return fatal();
      const expected = Object.freeze({ ...before.value, revision: before.value.revision + (kind === 'restore' ? 0 : 1),
        blocked: kind === 'mark' ? blocked! : kind === 'retire' ? true : before.value.blocked, retired: kind === 'retire' });
      const raw = kind === 'mark' ? addon.mark(before.encoded, blocked!) : kind === 'restore' ? addon.restore(before.encoded) : addon.retire(before.encoded);
      const value = acknowledge(raw, expected);
      assertIntegrity(); bindings.set(value.id, value); return value;
    });
  }
  return Object.freeze({
    bind(windowHandle: Buffer, webContentsId: number, attach: () => void): Binding {
      return checked(() => {
        if (!Buffer.isBuffer(windowHandle) || windowHandle.length !== 8 || !Number.isInteger(webContentsId) || webContentsId < 1 || webContentsId > 0xffffffff ||
            contents.has(webContentsId) || bindings.size >= 1000000 || typeof attach !== 'function') return fatal();
        creating = true;
        try {
          if (addon.beginBinding(windowHandle, webContentsId) !== undefined) return fatal();
          const result: unknown = attach();
          if (result !== undefined) return fatal(); // Includes Promise/thenable; never await an interleaved creation.
          const value = reply('native.Binding', addon.finishBinding());
          if (!value.blocked || value.retired || value.revision !== 0 || value.webContentsId !== webContentsId || bindings.has(value.id) || nonces.has(value.nonce)) return fatal();
          assertIntegrity();
          bindings.set(value.id, value); nonces.add(value.nonce); contents.add(webContentsId); dropCounts.set(value.id, 0);
          return value;
        } finally { creating = false; }
      });
    },
    bindingInfo(key: BindingKey): Binding {
      return checked(() => { const before = current(key); return acknowledge(addon.bindingInfo(before.encoded), before.value); });
    },
    mark(key: BindingKey, blocked: boolean): Binding { return transition(key, 'mark', blocked); },
    restore(key: BindingKey): Binding { return transition(key, 'restore'); },
    retire(key: BindingKey): Binding { return transition(key, 'retire'); },
    interactionState(key: BindingKey): Interaction {
      return checked(() => {
        const before = current(key), value = reply('native.Interaction', addon.interactionState(before.encoded));
        const active = value.buttons !== 0 || value.pressedButtons !== 0 || value.wheel || value.momentum || value.htmlSource || value.htmlTarget || value.marked;
        if ((!value.busy && active) || value.drops < (dropCounts.get(key.id) ?? 0)) return fatal();
        dropCounts.set(key.id, value.drops); return value;
      });
    },
  });
}
