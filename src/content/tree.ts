import type { Contract } from '../contracts/generated.js';
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
