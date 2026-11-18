import type { ActionTarget } from './admission.js';
import { staleSnapshot } from '../host/authority.js';
import { BrowserFailure, ForegroundWorkRequired } from '../contracts/errors.js';

export type TargetUse = 'click' | 'key' | 'type' | 'scroll' | 'drag';
export interface TargetPoint { readonly x: number; readonly y: number }
const nativePickerTypes = new Set(['file', 'color', 'date', 'datetime-local', 'month', 'time', 'week']);
function unsuitable(): never {
  throw new BrowserFailure({ code: 'control_refused', message: 'The original target cannot accept this operation.', retryable: true,
    remedy: 'Inspect current page state or use Take control.' });
}
/** Classification and the original reference signature precede AX suitability.
 * AX values/names are never returned, retained or used as replacement keys. */
export async function suitable(target: ActionTarget, use: TargetUse): Promise<void> {
  await target.revalidate(); target.guard();
  const { readiness, fields } = target.inspection;
  const classified = await fields.classify(target.frame, target.guard); target.guard();
  const field = classified.nodes.get(target.backend);
  if (field?.sensitive) throw new ForegroundWorkRequired('tab');
  if (!field || field.unavailable || field.signature.length !== 64) unsuitable();
  if (use === 'type' && !field.editable) unsuitable();
  // Native pickers use separate engine surfaces outside the permission callback.
  const described = await readiness.inspect(target.frame, target.guard, 'DOM.describeNode', { backendNodeId: target.backend, depth: 0 }) as {
    node?: { backendNodeId?: number; nodeType?: number; localName?: string; attributes?: string[] } };
  target.guard();
  if (described.node?.backendNodeId !== target.backend || ![1, 9].includes(described.node.nodeType ?? 0)) throw staleSnapshot();
  const attributes = described.node.attributes ?? [];
  if (attributes.length > 4096 || attributes.length % 2) throw staleSnapshot();
  let opensNativePicker = false;
  for (let i = 0; i < attributes.length; i += 2) {
    const name = attributes[i]!.toLowerCase(), value = attributes[i + 1]!.toLowerCase();
    if (name === 'disabled' || name === 'inert' || (name === 'aria-disabled' && value === 'true') ||
        (use === 'type' && name === 'readonly')) unsuitable();
    if (name === 'type' && described.node.localName === 'input' && nativePickerTypes.has(value) &&
        (value === 'file' || use === 'click' || use === 'key')) opensNativePicker = true;
  }
  if (opensNativePicker) throw new ForegroundWorkRequired('tab');
  const ax = await readiness.inspect(target.frame, target.guard, 'Accessibility.getPartialAXTree',
    { backendNodeId: target.backend, fetchRelatives: false }) as { nodes?: { backendDOMNodeId?: number; ignored?: boolean;
      role?: { value?: string }; properties?: { name: string; value: { value?: unknown } }[] }[] };
  target.guard();
  const nodes = ax.nodes?.filter(node => node.backendDOMNodeId === target.backend);
  if (!nodes || nodes.length !== 1 || nodes[0]!.ignored) unsuitable();
  const node = nodes[0]!;
  if (node.properties?.some(property => ['disabled', 'hidden'].includes(property.name) && property.value.value === true)) unsuitable();
  if (use === 'click' && !['button', 'link', 'checkbox', 'radio', 'switch', 'tab', 'menuitem', 'menuitemcheckbox',
    'menuitemradio', 'combobox', 'textbox', 'searchbox', 'spinbutton', 'slider', 'DisclosureTriangle'].includes(node.role?.value ?? '')) unsuitable();
  await target.revalidate(); target.guard();
}
/** Root-frame CSS coordinates only. Unbound child/frame transforms refuse.
 * An ambiguous/covered centre is refused, never searched around or retargeted. */
export async function hitPoint(target: ActionTarget): Promise<TargetPoint> {
  target.guard(); const readiness = target.inspection.readiness;
  const value = await readiness.inspect(target.frame, target.guard, 'DOM.getBoxModel', { backendNodeId: target.backend }) as {
    model?: { content?: number[] } };
  target.guard(); const quad = value.model?.content;
  if (!quad || quad.length !== 8 || !quad.every(Number.isFinite)) throw staleSnapshot();
  const x = (quad[0]! + quad[2]! + quad[4]! + quad[6]!) / 4;
  const y = (quad[1]! + quad[3]! + quad[5]! + quad[7]!) / 4;
  const metrics = await readiness.inspect(target.frame, target.guard, 'Page.getLayoutMetrics') as {
    cssVisualViewport?: { clientWidth: number; clientHeight: number; scale: number; offsetX: number; offsetY: number } };
  target.guard(); const viewport = metrics.cssVisualViewport;
  if (!viewport || viewport.scale !== 1 || viewport.offsetX !== 0 || viewport.offsetY !== 0 ||
      x < 0 || y < 0 || x >= viewport.clientWidth || y >= viewport.clientHeight) throw staleSnapshot();
  const hit = await readiness.inspect(target.frame, target.guard, 'DOM.getNodeForLocation',
    { x: Math.round(x), y: Math.round(y), includeUserAgentShadowDOM: false, ignorePointerEventsNone: false }) as {
      backendNodeId?: number; frameId?: string };
  target.guard();
  if (hit.backendNodeId !== target.backend || hit.frameId !== target.frame.frameId) throw staleSnapshot();
  await target.revalidate(); target.guard(); return Object.freeze({ x: Math.round(x), y: Math.round(y) });
}
