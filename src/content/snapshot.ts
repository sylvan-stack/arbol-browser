import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure } from '../contracts/errors.js';
import type { HostDocument, HostDocuments } from '../host/documents.js';
import type { InspectionFrame, PageReadiness } from '../host/readiness.js';
import { TabAuthority, staleSnapshot } from '../host/authority.js';
import { owningQueue, type ActionExecution } from '../host/actions.js';
import { boundedTree, type AXNode, type SnapshotNode } from './tree.js';
import { InspectionCache } from './cache.js';
import { revalidateOriginal, type OriginalNode } from './references.js';
import { classifiedRefusal, type SensitiveFields } from './sensitive.js';
import { publicURL } from './url.js';

export interface FrameTreeRead {
  readonly frame: InspectionFrame;
  readonly nodes: readonly AXNode[];
  readonly unavailable: number;
}
/** Host-private raw read. Classification must precede any AX serialization. */
export async function readAccessibility(readiness: PageReadiness, frame: InspectionFrame,
  guard: () => void, unavailable: number): Promise<FrameTreeRead> {
  readiness.assertInspection(frame, guard);
  await readiness.inspect(frame, guard, 'Accessibility.enable');
  const value = await readiness.inspect(frame, guard, 'Accessibility.getFullAXTree',
    { frameId: frame.frameId, depth: 33 }) as { nodes?: AXNode[] };
  guard();
  if (!Array.isArray(value.nodes) || value.nodes.length > 100000) throw staleSnapshot();
  return Object.freeze({ frame, nodes: value.nodes, unavailable });
}

/** Actual source contribution: the enclosing OwnershipHost supplies both the
 * authentic queue execution and reserveSnapshot identity. This service never
 * mints/delivers its own snapshot authority or opens default page admission. */
export class SnapshotInspection {
  readonly cache: InspectionCache;
  constructor(readonly authority: TabAuthority, readonly documents: HostDocuments,
    readonly readiness: PageReadiness, readonly fields: SensitiveFields) {
    if (authority.documents !== documents || readiness.documents !== documents || readiness.boundary !== authority.boundary ||
        fields.readiness !== readiness) throw staleSnapshot();
    this.cache = new InspectionCache(authority);
  }
  guard(execution: ActionExecution, mutation = false): () => void {
    return () => {
      if (owningQueue(execution).authority !== this.authority) throw staleSnapshot();
      this.authority.check(execution.stamp, mutation);
      if (execution.signal.aborted || performance.now() >= execution.deadline) throw staleSnapshot();
      this.documents.assertCurrent(execution.stamp.target, execution.stamp.document);
    };
  }
  async resolve(snapshot: string, ref: string, execution: ActionExecution, editing = false): Promise<OriginalNode> {
    const mutation = execution.action !== undefined, guard = this.guard(execution, mutation);
    guard(); const original = this.cache.get(snapshot, ref, execution.stamp, mutation);
    // Target preparation is a read. Under a mutation execution it must not
    // allocate an issued-input slot/continuation or change dispatch outcome.
    const current = await revalidateOriginal(original, (node, check) => this.fields.original(node, check), guard, editing);
    guard(); return current;
  }
  async snapshot(input: Contract<'browser.SnapshotInput'>, execution: ActionExecution, identity: string): Promise<Contract<'browser.SnapshotResult'>> {
    const guard = this.guard(execution), stamp = execution.stamp;
    let raw: FrameTreeRead | undefined, inserted = false;
    try {
      guard();
      if (input.tab !== stamp.target.id || input.controlGeneration !== stamp.generation) throw staleSnapshot();
      const scoped = input.root ? await this.resolve(input.root.snapshot, input.root.ref, execution) : undefined;
      guard();
      const frames = await execution.dispatch(() => this.readiness.inspection(stamp.document as HostDocument, guard)), frame = frames[0];
      if (!frame?.physical) throw classifiedRefusal();
      const before = this.readiness.observation(frame.receipt).epoch;
      const dom = await execution.dispatch(() => this.fields.classify(frame, guard));
      raw = await execution.dispatch(() => readAccessibility(this.readiness, frame, guard, frames.length - 1));
      guard();
      const after = await execution.dispatch(() => this.fields.classify(frame, guard));
      if (dom.signature !== after.signature || this.readiness.observation(frame.receipt).epoch !== before) throw staleSnapshot();
      const roots = scoped ? raw.nodes.filter(node => node.backendDOMNodeId === scoped.backend) :
        raw.nodes.filter(node => node.parentId === undefined && node.backendDOMNodeId !== undefined &&
          dom.nodes.get(node.backendDOMNodeId)?.tag === '#DOCUMENT');
      if (roots.length !== 1) throw staleSnapshot();
      const root = roots[0]!, nodes = [...raw.nodes];
      if (!scoped && raw.unavailable) {
        // Synthetic ids stay entirely internal; each unavailable marker goes
        // through the same depth/node/byte allocator and has no original ref.
        const ids = new Set(nodes.map(node => node.nodeId)), children = [...(root.childIds ?? [])];
        for (let index = 0; index < raw.unavailable; index++) {
          const id = `arbol-unavailable-${index}`; if (ids.has(id)) throw staleSnapshot();
          nodes.push({ nodeId: id }); children.push(id);
        }
        const index = nodes.indexOf(root); nodes[index] = { ...root, childIds: children };
      }
      this.cache.insert(identity, stamp); inserted = true;
      let textTruncated = false;
      const bounded = boundedTree(nodes, root.nodeId, node => {
        const field = node.backendDOMNodeId === undefined ? undefined : dom.nodes.get(node.backendDOMNodeId);
        if (field && ['IFRAME', 'FRAME', 'OBJECT', 'EMBED'].includes(field.tag))
          return { role: 'unknown', state: { unavailable: true } };
        const projected = this.fields.project(node, dom);
        const limited = !projected.value.state?.sensitive && !projected.value.state?.unavailable &&
          ((typeof node.name?.value === 'string' && Array.from(node.name.value).length > 4096) ||
          (typeof node.role?.value === 'string' && Array.from(node.role.value).length > 80) || projected.value.state?.valueTruncated);
        if (limited) textTruncated = true;
        if (projected.original && !limited && !projected.value.state?.unavailable && !projected.value.state?.sensitive)
          projected.value.ref = this.cache.add(identity, stamp, projected.original);
        return projected.value;
      });
      const refs = new Set<string>();
      const collect = (node: SnapshotNode) => { if (node.ref) refs.add(node.ref); for (const child of node.children ?? []) collect(child); };
      for (const node of bounded.tree) collect(node); this.cache.retain(identity, refs);
      const truncated = bounded.truncated || textTruncated;
      if (truncated && input.allowTruncation === false) throw new BrowserFailure({ code: 'snapshot_truncated',
        message: 'The complete page exceeds snapshot bounds.', retryable: true, remedy: 'Request a smaller current subtree.' });
      const result: Contract<'browser.SnapshotResult'> = { tab: stamp.target.id, snapshot: identity,
        navigation: stamp.document.navigation, controlGeneration: stamp.generation, domRevision: before,
        url: publicURL(dom.address), title: dom.title, tree: bounded.tree, truncated };
      if (Buffer.byteLength(JSON.stringify(result), 'utf8') > 512 * 1024) throw new BrowserFailure({ code: 'snapshot_truncated',
        message: 'The complete snapshot exceeds browser capacity.', retryable: true, remedy: 'Request a smaller current subtree.' });
      guard(); return result;
    } catch (error) {
      if (inserted) this.cache.drop(identity); throw error;
    } finally {
      // Drop temporary AX names/values after projection, failure or revocation.
      if (raw) for (const node of raw.nodes) { delete node.name; delete node.value; delete node.properties; }
    }
  }
  close(): void { this.cache.close(); }
}
