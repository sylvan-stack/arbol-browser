import type { Contract } from '../contracts/generated.js';
import type { ClassifiedDOM } from './sensitive.js';
import type { InspectionFrame } from '../host/readiness.js';
import { staleSnapshot } from '../host/authority.js';

export interface AXNode {
  nodeId: string;
  parentId?: string;
  childIds?: string[];
  backendDOMNodeId?: number;
  frameId?: string;
  ignored?: boolean;
  role?: { value?: unknown };
  name?: { value?: unknown };
  value?: { value?: unknown };
  properties?: { name: string; value: { value?: unknown } }[];
}
export type SnapshotNode = Contract<'browser.SnapshotNode'>;
export interface BoundedTree { tree: SnapshotNode[]; truncated: boolean }
/** Projection is supplied only after DOM classification; raw AX data never
 * becomes a public tree implicitly. Repeated/cyclic AX nodes are unavailable. */
export function boundedTree(nodes: readonly AXNode[], root: string, project: (node: AXNode) => SnapshotNode | undefined,
  maxBytes = 480 * 1024): BoundedTree {
  if (nodes.length > 100000) throw staleSnapshot();
  const index = new Map<string, AXNode>();
  for (const node of nodes) {
    if (!node || typeof node.nodeId !== 'string' || index.has(node.nodeId)) throw staleSnapshot();
    index.set(node.nodeId, node);
  }
  const seen = new Set<string>(); let count = 0, bytes = 2, truncated = false;
  const visit = (id: string, depth: number): SnapshotNode | undefined => {
    if (depth > 32 || count >= 5000) { truncated = true; return; }
    const node = index.get(id);
    const unavailable = !node || seen.has(id);
    if (!unavailable) seen.add(id);
    const value: SnapshotNode | undefined = unavailable
      ? { role: 'unknown', state: { unavailable: true } } : project(node);
    if (!value) return;
    const size = Buffer.byteLength(JSON.stringify(value), 'utf8') + 32;
    if (bytes + size > maxBytes) { truncated = true; return; }
    bytes += size; count++;
    // Sensitive/unavailable nodes never traverse potentially revealing children.
    if (!value.state?.sensitive && !value.state?.unavailable) {
      const children: SnapshotNode[] = [];
      for (const child of node?.childIds ?? []) {
        const item = visit(child, depth + 1); if (item) children.push(item);
        if (count >= 5000 || bytes >= maxBytes) { truncated = true; break; }
      }
      if (children.length) value.children = children;
    }
    return value;
  };
  const value = visit(root, 1);
  return { tree: value ? [value] : [], truncated };
}


export interface FrameTreePart { readonly frame: InspectionFrame; readonly nodes: readonly AXNode[]; readonly dom: ClassifiedDOM }
/** AX node ids are local to their actual frame read. Grafting replaces only an
 * authenticated parent backend owner; neither raw numeric ids nor ordering
 * connects trees. Detached/orphaned parts never become traversal roots. */
export function linkedTree(parts: readonly FrameTreePart[], selected: InspectionFrame, backend: number | undefined,
  unknown: boolean): { nodes: AXNode[]; root: string; source: ReadonlyMap<AXNode, FrameTreePart>; linked: ReadonlySet<AXNode> } {
  const nodes: AXNode[] = [], source = new Map<AXNode, FrameTreePart>(), linked = new Set<AXNode>();
  const copies = new Map<InspectionFrame, AXNode[]>(), roots = new Map<InspectionFrame, AXNode>();
  let edges = 0;
  for (let index = 0; index < parts.length; index++) {
    const part = parts[index]!, prefix = `frame-${index}:`, ids = new Set<string>(), local: AXNode[] = [];
    for (const raw of part.nodes) {
      if (typeof raw?.nodeId !== 'string' || raw.nodeId.length > 256 || ids.has(raw.nodeId) ||
          (raw.childIds !== undefined && (!Array.isArray(raw.childIds) || (edges += raw.childIds.length) > 200000 ||
            raw.childIds.some(id => typeof id !== 'string' || id.length > 256)))) throw staleSnapshot();
      ids.add(raw.nodeId);
      const node: AXNode = { ...raw, nodeId: prefix + raw.nodeId,
        ...(raw.parentId === undefined ? {} : { parentId: prefix + raw.parentId }),
        ...(raw.childIds === undefined ? {} : { childIds: raw.childIds.map(id => prefix + id) }) };
      local.push(node); nodes.push(node); source.set(node, part);
    }
    const candidates = local.filter(node => node.backendDOMNodeId !== undefined &&
      (part.frame === selected && backend !== undefined ? node.backendDOMNodeId === backend : part.dom.nodes.get(node.backendDOMNodeId)?.tag === '#DOCUMENT'));
    if (candidates.length !== 1) throw staleSnapshot(); copies.set(part.frame, local); roots.set(part.frame, candidates[0]!);
  }
  const root = roots.get(selected); if (!root) throw staleSnapshot();
  for (const part of parts) if (part.frame !== selected) {
    const parent = part.frame.parent, owner = part.frame.ownerBackend;
    const parentPart = parts.find(value => value.frame === parent);
    const candidates = parent && owner !== undefined ? copies.get(parent)?.filter(node => node.backendDOMNodeId === owner) : undefined;
    const field = owner === undefined ? undefined : parentPart?.dom.nodes.get(owner);
    if (!part.dom.accessible || !parentPart?.dom.accessible || !field || field.sensitive || field.unavailable ||
        !['IFRAME', 'FRAME'].includes(field.tag) || candidates?.length !== 1) { unknown = true; continue; }
    const originalOwner = candidates[0]!, child = roots.get(part.frame)!;
    // More than one physical child claiming an owner is ambiguous.
    if (linked.has(originalOwner)) throw staleSnapshot();
    linked.add(originalOwner); originalOwner.childIds = [child.nodeId]; child.parentId = originalOwner.nodeId;
  }
  if (unknown) {
    const marker: AXNode = { nodeId: 'arbol-unknown-frame-remainder' };
    nodes.push(marker); root.childIds = [...(root.childIds ?? []), marker.nodeId];
  }
  return { nodes, root: root.nodeId, source, linked };
}
