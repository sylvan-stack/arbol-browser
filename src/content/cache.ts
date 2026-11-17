import { performance } from 'node:perf_hooks';
import { TabAuthority, staleSnapshot, type AuthorityStamp } from '../host/authority.js';
import type { OriginalNode, OriginalReference } from './references.js';

interface Entry {
  readonly identity: string;
  readonly stamp: AuthorityStamp;
  readonly expires: number;
  readonly nodes: Map<string, OriginalReference>;
  readonly timer: ReturnType<typeof setTimeout>;
}
/** A bounded evidence cache, never a grant/delivery authority. It contains no
 * exported tree, image, page title, URL, input value or transcript. */
export class InspectionCache {
  private readonly entries = new Map<string, Entry>();
  private readonly removeInvalidator: () => void;
  constructor(readonly authority: TabAuthority) {
    this.removeInvalidator = authority.onInvalidate(event => {
      for (const [id, value] of this.entries) if (value.stamp.target === event.target &&
          (event.recipient === undefined || value.stamp.attachment.id === event.recipient)) this.drop(id);
    });
  }
  insert(identity: string, stamp: AuthorityStamp): void {
    this.authority.check(stamp); this.sweep();
    if (this.entries.has(identity)) throw staleSnapshot();
    const own = [...this.entries.values()].filter(entry => entry.stamp.attachment === stamp.attachment);
    while (own.length >= 8) this.drop(own.shift()!.identity);
    const timer = setTimeout(() => this.drop(identity), 300000); timer.unref();
    this.entries.set(identity, { identity, stamp, expires: performance.now() + 300000, nodes: new Map(), timer });
  }
  add(identity: string, stamp: AuthorityStamp, node: OriginalNode): string {
    this.authority.check(stamp); const entry = this.entries.get(identity);
    if (!entry || entry.stamp !== stamp || entry.expires <= performance.now() || entry.nodes.size >= 5000 ||
        node.frame.receipt !== stamp.document || !node.frame.physical || !Number.isSafeInteger(node.backend) || node.backend <= 0 ||
        node.signature.length !== 64) throw staleSnapshot();
    const ref = this.authority.opaque('ref');
    entry.nodes.set(ref, Object.freeze({ ...node, snapshot: identity, ref, stamp })); return ref;
  }
  /** Insertion alone cannot authorize even a scoped read. Only the ownership
   * host's final complete-response commitment activates its snapshot marker. */
  get(identity: string, ref: string, stamp: AuthorityStamp, mutation = false): OriginalReference {
    this.authority.requireSnapshot(identity, stamp, mutation); this.sweep();
    const entry = this.entries.get(identity), value = entry?.nodes.get(ref);
    if (!entry || !value || entry.stamp.target !== stamp.target || entry.stamp.attachment !== stamp.attachment ||
        entry.stamp.document !== stamp.document || entry.stamp.generation !== stamp.generation ||
        entry.stamp.epoch !== stamp.epoch || entry.stamp.recipientEpoch !== stamp.recipientEpoch) throw staleSnapshot();
    return value;
  }
  retain(identity: string, refs: ReadonlySet<string>): void {
    const entry = this.entries.get(identity); if (!entry) throw staleSnapshot();
    for (const ref of entry.nodes.keys()) if (!refs.has(ref)) entry.nodes.delete(ref);
  }
  drop(identity: string): void {
    const entry = this.entries.get(identity); if (!entry) return;
    clearTimeout(entry.timer); entry.nodes.clear(); this.entries.delete(identity);
  }
  private sweep(): void {
    for (const [id, entry] of this.entries) if (entry.expires <= performance.now()) this.drop(id);
  }
  close(): void { this.removeInvalidator(); for (const id of this.entries.keys()) this.drop(id); }
}
