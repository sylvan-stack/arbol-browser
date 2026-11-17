import type { AuthorityStamp } from '../host/authority.js';
import { staleSnapshot } from '../host/authority.js';
import type { InspectionFrame } from '../host/readiness.js';

/** No selector, label, coordinate or value is retained as a replacement key.
 * The signature covers only relevant identity/state/context, never global DOM
 * revision. Consumers must additionally prove actual hit-test/focus suitability. */
export interface OriginalNode {
  readonly frame: InspectionFrame;
  readonly backend: number;
  readonly signature: string;
  readonly editable: boolean;
}
export interface OriginalReference extends OriginalNode {
  readonly snapshot: string;
  readonly ref: string;
  readonly stamp: AuthorityStamp;
}
export type InspectOriginal = (node: OriginalNode, guard: () => void) => Promise<OriginalNode>;
export async function revalidateOriginal(reference: OriginalReference, inspect: InspectOriginal,
  guard: () => void, editing = false): Promise<OriginalNode> {
  guard(); const current = await inspect(reference, guard); guard();
  if (current.frame.receipt !== reference.frame.receipt || current.frame.physical !== reference.frame.physical ||
      current.frame.frameId !== reference.frame.frameId || current.frame.loaderId !== reference.frame.loaderId ||
      current.frame.parent?.physical !== reference.frame.parent?.physical || current.frame.ownerBackend !== reference.frame.ownerBackend || current.frame.session !== reference.frame.session ||
      current.backend !== reference.backend || current.signature !== reference.signature ||
      current.editable !== reference.editable || (editing && !current.editable)) throw staleSnapshot();
  return current;
}
