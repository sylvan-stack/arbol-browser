import type { HostDocument } from '../host/documents.js';
import type { InspectionFrame, PageReadiness } from '../host/readiness.js';
import { staleSnapshot } from '../host/authority.js';
import type { AXNode } from './tree.js';

export interface FrameTreeRead {
  readonly frame: InspectionFrame;
  readonly nodes: readonly AXNode[];
  readonly unavailable: number;
}
/** Host-private raw read. Classification must precede any AX serialization. */
export async function readAccessibility(readiness: PageReadiness, receipt: HostDocument,
  guard: () => void): Promise<FrameTreeRead> {
  const frames = await readiness.inspection(receipt, guard), frame = frames[0];
  if (!frame?.physical) throw staleSnapshot();
  await readiness.inspect(frame, guard, 'Accessibility.enable');
  const value = await readiness.inspect(frame, guard, 'Accessibility.getFullAXTree',
    { frameId: frame.frameId, depth: 33 }) as { nodes?: AXNode[] };
  guard();
  if (!Array.isArray(value.nodes) || value.nodes.length > 100000) throw staleSnapshot();
  return Object.freeze({ frame, nodes: value.nodes, unavailable: frames.length - 1 });
}
