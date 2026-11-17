import { performance } from 'node:perf_hooks';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure } from '../contracts/errors.js';
import type { HostDocument, HostDocuments } from '../host/documents.js';
import type { InspectionFrame, PageReadiness } from '../host/readiness.js';
import { TabAuthority, staleSnapshot } from '../host/authority.js';
import { owningQueue, type ActionExecution } from '../host/actions.js';
import { boundedTree, linkedTree, type FrameTreePart, type AXNode, type SnapshotNode } from './tree.js';
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
    guard();
    // Child inspection is useful independently of input. The original action
    // producer still proves only root hit/focus routes and its own action world.
    if (mutation && (current.frame.physical !== current.frame.receipt.frame || current.frame.session !== undefined)) throw staleSnapshot();
    this.readiness.assertInspection(current.frame, guard); return current;
  }
  async snapshot(input: Contract<'browser.SnapshotInput'>, execution: ActionExecution, identity: string): Promise<Contract<'browser.SnapshotResult'>> {
    const guard = this.guard(execution), stamp = execution.stamp;
    const raw: FrameTreeRead[] = []; let inserted = false;
    try {
      guard();
      if (input.tab !== stamp.target.id || input.controlGeneration !== stamp.generation) throw staleSnapshot();
      const scoped = input.root ? await this.resolve(input.root.snapshot, input.root.ref, execution) : undefined;
      guard();
      const frames = await execution.dispatch(() => this.readiness.inspection(stamp.document as HostDocument, guard)), frame = frames[0];
      if (!frame?.physical) throw classifiedRefusal();
      const selected = scoped ? frames.find(value => value.physical === scoped.frame.physical && value.frameId === scoped.frame.frameId &&
        value.session === scoped.frame.session && value.loaderId === scoped.frame.loaderId) : frame;
      if (!selected?.physical) throw staleSnapshot();
      const proven = frames.filter(value => value.physical);
      return await this.fields.bracket(proven, guard, async check => {
        const before = this.readiness.observation(frame.receipt).epoch;
        const doms = await execution.dispatch(() => this.fields.classifyFrames(proven, guard));
        await check();
        const selectedDOM = doms.get(selected); if (!selectedDOM?.accessible) throw classifiedRefusal();
        const parts: FrameTreePart[] = []; let count = 0, bytes = 0;
        for (const current of scoped ? [selected] : proven) {
          const dom = doms.get(current)!; if (!dom.accessible) continue;
          const read = await execution.dispatch(() => readAccessibility(this.readiness, current, guard, 0)); raw.push(read);
          if ((count += read.nodes.length) > 100000) throw classifiedRefusal();
          for (const node of read.nodes) if ((bytes += Buffer.byteLength(JSON.stringify(node), 'utf8')) > 16 * 1024 * 1024) throw classifiedRefusal();
          parts.push({ frame: current, nodes: read.nodes, dom });
        }
        await check();
        const after = await execution.dispatch(() => this.fields.classifyFrames(proven, guard));
        await check();
        for (const current of proven) if (doms.get(current)!.signature !== after.get(current)!.signature ||
          doms.get(current)!.lineage !== after.get(current)!.lineage || doms.get(current)!.accessible !== after.get(current)!.accessible) throw staleSnapshot();
        await this.readiness.verifyInspection(proven, guard);
        if (this.readiness.observation(frame.receipt).epoch !== before) throw staleSnapshot();
        const tree = linkedTree(parts, selected, scoped?.backend, !scoped && frames.some(value => !value.physical));
        this.cache.insert(identity, stamp); inserted = true;
        let textTruncated = false;
        const bounded = boundedTree(tree.nodes, tree.root, node => {
          const part = tree.source.get(node);
          if (!part) return { role: 'unknown', state: { unavailable: true } };
          const field = node.backendDOMNodeId === undefined ? undefined : part.dom.nodes.get(node.backendDOMNodeId);
          if (field && ['IFRAME', 'FRAME', 'OBJECT', 'EMBED'].includes(field.tag))
            return tree.linked.has(node) ? { role: 'iframe', state: {} } : { role: 'unknown', state: { unavailable: true } };
          const projected = this.fields.project(node, part.dom);
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
          url: publicURL(selectedDOM.address), title: selectedDOM.title, tree: bounded.tree, truncated };
        if (Buffer.byteLength(JSON.stringify(result), 'utf8') > 512 * 1024) throw new BrowserFailure({ code: 'snapshot_truncated',
          message: 'The complete snapshot exceeds browser capacity.', retryable: true, remedy: 'Request a smaller current subtree.' });
        await check(); await this.readiness.verifyInspection(proven, guard); guard(); return result;
      });
    } catch (error) {
      if (inserted) this.cache.drop(identity); throw error;
    } finally {
      // Drop temporary AX names/values after projection, failure or revocation.
      for (const read of raw) for (const node of read.nodes) { delete node.name; delete node.value; delete node.properties; }
    }
  }
  close(): void { this.cache.close(); }
}
