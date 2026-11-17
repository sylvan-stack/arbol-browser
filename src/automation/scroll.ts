import type { Contract } from '../contracts/generated.js';
import { invalidInput } from '../contracts/errors.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import type { ActionExecution } from '../host/actions.js';
import { staleSnapshot } from '../host/authority.js';
import { admitTarget, interceptInput, type ActionTarget } from './admission.js';
import { suitable, type TargetPoint } from './targets.js';
import { TrustedObservation } from './observations.js';

async function scrollPoint(target: ActionTarget, observation: TrustedObservation): Promise<TargetPoint> {
  const { readiness } = target.inspection;
  const described = await readiness.inspect(target.frame, target.guard, 'DOM.describeNode', { backendNodeId: target.backend, depth: 0 }) as {
    node?: { nodeType?: number } };
  target.guard();
  const metrics = await readiness.inspect(target.frame, target.guard, 'Page.getLayoutMetrics') as {
    cssVisualViewport?: { clientWidth: number; clientHeight: number; scale: number; offsetX: number; offsetY: number } };
  target.guard(); const viewport = metrics.cssVisualViewport;
  if (!viewport || viewport.scale !== 1 || viewport.offsetX !== 0 || viewport.offsetY !== 0 ||
      !Number.isFinite(viewport.clientWidth) || !Number.isFinite(viewport.clientHeight) || viewport.clientWidth <= 0 || viewport.clientHeight <= 0) throw staleSnapshot();
  let x = viewport.clientWidth / 2, y = viewport.clientHeight / 2;
  if (described.node?.nodeType !== 9) {
    const box = await readiness.inspect(target.frame, target.guard, 'DOM.getBoxModel', { backendNodeId: target.backend }) as { model?: { content?: number[] } };
    target.guard(); const quad = box.model?.content;
    if (!quad || quad.length !== 8 || !quad.every(Number.isFinite)) throw staleSnapshot();
    x = (quad[0]! + quad[2]! + quad[4]! + quad[6]!) / 4; y = (quad[1]! + quad[3]! + quad[5]! + quad[7]!) / 4;
  }
  x = Math.round(x); y = Math.round(y);
  if (x < 0 || y < 0 || x >= viewport.clientWidth || y >= viewport.clientHeight) throw staleSnapshot();
  const hit = await readiness.inspect(target.frame, target.guard, 'DOM.getNodeForLocation',
    { x, y, includeUserAgentShadowDOM: false, ignorePointerEventsNone: false }) as { backendNodeId?: number; frameId?: string };
  target.guard();
  if (!hit.backendNodeId || hit.frameId !== target.frame.frameId || !await observation.covers(hit.backendNodeId)) throw staleSnapshot();
  await target.revalidate(); observation.guard(); return Object.freeze({ x, y });
}
export async function scrollTrusted(inspection: SnapshotInspection, execution: ActionExecution,
  input: Contract<'browser.ScrollInput'>): Promise<Contract<'browser.ActionResult'>> {
  if (![input.deltaX, input.deltaY].every(value => Number.isInteger(value) && Math.abs(value) <= 2000) || (!input.deltaX && !input.deltaY)) throw invalidInput();
  const target = await admitTarget(inspection, execution, input); await suitable(target, 'scroll');
  const interception = await interceptInput(target);
  const observation = await TrustedObservation.open(target, 'browser_scroll', interception);
  try {
    const point = await scrollPoint(target, observation); observation.guard(); execution.beginSequence('wheel');
    const gesture = await observation.scroll(point, input.deltaX, input.deltaY);
    await observation.settleScroll(gesture); target.guard();
    return { tab: execution.stamp.target.id, action: execution.action!, status: 'completed',
      controlGeneration: execution.stamp.generation, navigation: execution.stamp.document.navigation,
      pageAvailability: target.frame.receipt.availability, inputReady: target.frame.receipt.ready };
  } finally { await observation.close(); }
}
