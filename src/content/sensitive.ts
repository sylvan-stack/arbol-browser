import { createHash } from 'node:crypto';
import { BrowserFailure } from '../contracts/errors.js';
import type { HostDocument } from '../host/documents.js';
import type { InspectionFrame, PageReadiness } from '../host/readiness.js';
import { staleSnapshot } from '../host/authority.js';
import type { AXNode, SnapshotNode } from './tree.js';
import type { OriginalNode } from './references.js';

/** Recognized by identity in the queue/delivery layers, never by provider text. */
export class ClassifiedGeometryRefusal extends BrowserFailure {
  constructor() { super({ code: 'control_refused', message: 'Safe classified content is unavailable.', retryable: true,
    remedy: 'Use Take control to inspect this page privately.' }); }
}
export function classifiedRefusal(): ClassifiedGeometryRefusal { return new ClassifiedGeometryRefusal(); }
const fingerprint = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
interface RawDocument {
  frameId: number; documentURL: number; title: number;
  nodes: { parentIndex?: number[]; nodeName?: number[]; backendNodeId?: number[]; attributes?: number[][];
    shadowRootType?: { index: number[]; value: number[] } };
  layout: { nodeIndex: number[]; bounds: number[][] };
}
interface RawSnapshot { strings: string[]; documents: RawDocument[] }
export interface DOMField {
  readonly backend: number;
  readonly parent: number;
  readonly tag: string;
  readonly editable: boolean;
  readonly sensitive: boolean;
  readonly unavailable: boolean;
  readonly signature: string;
}
export interface ClassifiedDOM {
  readonly frame: InspectionFrame;
  readonly nodes: ReadonlyMap<number, DOMField>;
  readonly aggregates: ReadonlySet<number>;
  readonly signature: string;
  readonly address: string;
  readonly title: string;
  readonly lineage: string;
  readonly accessible: boolean;
}
/** Host-only explicit classification, keyed to the original logical document.
 * Tool arguments and website accessibility claims cannot populate this set. */
export class HostSecretFields {
  private readonly fields = new WeakMap<HostDocument, Map<object, Map<string | undefined, Set<number>>>>();
  mark(document: HostDocument, backend: number, frame?: InspectionFrame): void {
    const physical = frame?.physical ?? document.frame, session = frame?.session;
    if (!Number.isSafeInteger(backend) || backend <= 0 || (frame && (frame.receipt !== document || !frame.physical)) ||
        !document.frames.includes(physical)) throw staleSnapshot();
    const frames = this.fields.get(document) ?? new Map<object, Map<string | undefined, Set<number>>>();
    const sessions = frames.get(physical) ?? new Map<string | undefined, Set<number>>();
    const fields = sessions.get(session) ?? new Set<number>();
    let count = 0; for (const contexts of frames.values()) for (const values of contexts.values()) count += values.size;
    if (!fields.has(backend) && count >= 5000) throw classifiedRefusal();
    fields.add(backend); sessions.set(session, fields); frames.set(physical, sessions); this.fields.set(document, frames);
  }
  has(frame: InspectionFrame, backend: number): boolean {
    return Boolean(frame.physical && this.fields.get(frame.receipt)?.get(frame.physical)?.get(frame.session)?.has(backend));
  }
}
function text(value: unknown, limit: number): string {
  if (typeof value !== 'string') return '';
  return Array.from(value.replace(/[\u0000\uD800-\uDFFF]/gu, '')).slice(0, limit).join('');
}
/** No ordinary-page text scanning: this guarantee covers classified DOM
 * authentication fields and user-mode privacy, not arbitrary prose secrets. */
export class SensitiveFields {
  constructor(readonly readiness: PageReadiness, readonly known: HostSecretFields) {}
  /** Every phase captures each actual session only once, charging all raw
   * documents in it before any frame projection. An unused local document is
   * still charged; choosing a smaller logical frame cannot evade raw bounds. */
  async classifyFrames(frames: readonly InspectionFrame[], guard: () => void): Promise<ReadonlyMap<InspectionFrame, ClassifiedDOM>> {
    const result = new Map<InspectionFrame, ClassifiedDOM>();
    const sessions = new Map<string | undefined, InspectionFrame[]>();
    const receipt = frames[0]?.receipt;
    if (!receipt || frames.length > 256) throw classifiedRefusal();
    for (const frame of frames) {
      this.readiness.assertInspection(frame, guard); if (frame.receipt !== receipt) throw staleSnapshot();
      const group = sessions.get(frame.session) ?? []; group.push(frame); sessions.set(frame.session, group);
    }
    const budget = { bytes: 0, strings: 0, documents: 0, nodes: 0, expanded: 0, attributes: 0 };
    for (const group of sessions.values()) {
      const representative = group[0]!;
      const raw = await this.readiness.inspect(representative, guard, 'DOMSnapshot.captureSnapshot',
        { computedStyles: [], includePaintOrder: true, includeDOMRects: true }) as RawSnapshot;
      try {
        guard();
        if (!Array.isArray(raw.strings) || !Array.isArray(raw.documents) ||
            (budget.strings += raw.strings.length) > 1000000 || (budget.documents += raw.documents.length) > 256) throw classifiedRefusal();
        const stringBytes: number[] = [];
        for (const value of raw.strings) {
          if (typeof value !== 'string') throw classifiedRefusal();
          const bytes = Buffer.byteLength(value, 'utf8'); stringBytes.push(bytes);
          if ((budget.bytes += bytes) > 32 * 1024 * 1024) throw classifiedRefusal();
        }
        for (const document of raw.documents) {
          const nodes = document.nodes;
          if (!nodes || !Array.isArray(nodes.backendNodeId) || (budget.nodes += nodes.backendNodeId.length) > 100000 ||
              !Array.isArray(nodes.parentIndex) || !Array.isArray(nodes.nodeName) || !Array.isArray(nodes.attributes) ||
              nodes.parentIndex.length !== nodes.backendNodeId.length || nodes.nodeName.length !== nodes.backendNodeId.length ||
              nodes.attributes.length !== nodes.backendNodeId.length || !Array.isArray(document.layout?.nodeIndex) ||
              !Array.isArray(document.layout?.bounds) || document.layout.nodeIndex.length > 100000 ||
              document.layout.nodeIndex.length !== document.layout.bounds.length) throw classifiedRefusal();
          if ((budget.bytes += nodes.backendNodeId.length * 32 + document.layout.nodeIndex.length * 40) > 32 * 1024 * 1024) throw classifiedRefusal();
          for (const pairs of nodes.attributes) {
            if (!Array.isArray(pairs) || pairs.length > 4096 || pairs.length % 2 || (budget.attributes += pairs.length) > 1000000 ||
                (budget.bytes += pairs.length * 8) > 32 * 1024 * 1024) throw classifiedRefusal();
          }
        }
        const string = (index: number, empty = false): string => {
          if (empty && index === -1) return '';
          if (!Number.isSafeInteger(index) || index < 0 || index >= raw.strings.length) throw classifiedRefusal();
          const value = raw.strings[index]!; if (!empty && value.length === 0) throw classifiedRefusal(); return value;
        };
        const ids = new Set<string>();
        for (const document of raw.documents) { const id = string(document.frameId); if (ids.has(id)) throw classifiedRefusal(); ids.add(id); }
        for (const frame of group) {
          const classified = this.decode(frame, raw, string, stringBytes, budget);
          result.set(frame, classified);
        }
      } finally {
        if (Array.isArray(raw?.strings)) raw.strings.fill('');
        if (Array.isArray(raw?.documents)) raw.documents.length = 0;
      }
    }
    // Parent security/owner ancestry is part of every descendant reference.
    // Neither equal numeric backend ids nor a guessed flattened parent is used.
    for (const frame of frames) {
      const dom = result.get(frame)!;
      const parent = frame.parent ? result.get(frame.parent) : undefined;
      const owner = frame.ownerBackend === undefined ? undefined : parent?.nodes.get(frame.ownerBackend);
      const accessible = frame.parent === undefined ? frame.physical === receipt.frame :
        Boolean(parent?.accessible && owner && !owner.sensitive && !owner.unavailable && ['IFRAME', 'FRAME'].includes(owner.tag));
      const lineage = fingerprint([frame.frameId, frame.loaderId, frame.session, parent?.lineage, owner?.signature]);
      result.set(frame, Object.freeze({ ...dom, accessible, lineage }));
    }
    for (const frame of frames) this.readiness.assertInspection(frame, guard);
    return result;
  }
  async classify(frame: InspectionFrame, guard: () => void): Promise<ClassifiedDOM> {
    const frames: InspectionFrame[] = []; let current: InspectionFrame | undefined = frame;
    while (current) { if (frames.length >= 32) throw classifiedRefusal(); frames.unshift(current); current = current.parent; }
    const result = await this.classifyFrames(frames, guard); return result.get(frame)!;
  }
  /** Every content-bearing read keeps these scopes through its final check and
   * joins exact original cleanup even after the recipient/read lease expires. */
  async bracket<T>(frames: readonly InspectionFrame[], guard: () => void, work: (check: () => Promise<void>) => Promise<T>): Promise<T> {
    const brackets: Awaited<ReturnType<PageReadiness['mutationBracket']>>[] = [];
    try {
      for (const frame of frames) brackets.push(await this.readiness.mutationBracket(frame, guard));
      const check = async () => { guard(); for (const bracket of brackets) await bracket.check(); guard(); };
      await check(); const value = await work(check); await check(); return value;
    } finally {
      const cleanup = await Promise.allSettled(brackets.map(bracket => bracket.close()));
      if (cleanup.some(result => result.status === 'rejected')) throw classifiedRefusal();
    }
  }
  private decode(frame: InspectionFrame, raw: RawSnapshot, string: (index: number, empty?: boolean) => string,
    stringBytes: readonly number[], budget: { expanded: number }): ClassifiedDOM {
    const referenced = (index: number, empty = false): string => {
      const value = string(index, empty);
      if ((budget.expanded += index === -1 ? 0 : stringBytes[index]!) > 16 * 1024 * 1024) throw classifiedRefusal();
      return value; // charge every reference before case folding/split/hash
    };
    const documents = raw.documents.filter(document => string(document.frameId) === frame.frameId);
    if (documents.length !== 1) throw classifiedRefusal(); const document = documents[0]!;
    const { backendNodeId: backends, parentIndex: parents, nodeName: names, attributes } = document.nodes;
    if (!backends || !parents || !names || !attributes || backends.length > 100000 ||
        parents.length !== backends.length || names.length !== backends.length || attributes.length !== backends.length) throw classifiedRefusal();
    const closed = new Set<number>(), shadowHosts = new Set<number>();
    const shadows = document.nodes.shadowRootType;
    if (shadows) {
      if (!Array.isArray(shadows.index) || !Array.isArray(shadows.value) || shadows.index.length !== shadows.value.length ||
          shadows.index.length > backends.length) throw classifiedRefusal();
      const seen = new Set<number>();
      for (let index = 0; index < shadows.index.length; index++) {
        const node = shadows.index[index]!;
        if (!Number.isSafeInteger(node) || node < 0 || node >= backends.length || seen.has(node)) throw classifiedRefusal();
        seen.add(node);
        // Every shadow host and its light/composed content is unavailable
        // until slot/scope lifetime has an authentic independent producer.
        const host = parents[node];
        if (!Number.isSafeInteger(host) || host! < 0 || host! >= node) throw classifiedRefusal();
        shadowHosts.add(host!); closed.add(node); string(shadows.value[index]!);
      }
    }
    const nodes = new Map<number, DOMField>(), aggregates = new Set<number>();
    for (let index = 0; index < backends.length; index++) {
      const backend = backends[index]!, parentIndex = parents[index]!;
      if (!Number.isSafeInteger(backend) || backend <= 0 || nodes.has(backend) || !Number.isSafeInteger(parentIndex) ||
          parentIndex < -1 || parentIndex >= index) throw classifiedRefusal();
      const parent = parentIndex < 0 ? undefined : nodes.get(backends[parentIndex]!);
      if (parentIndex >= 0 && !parent) throw classifiedRefusal();
      const pairs = attributes[index]!;
      if (!Array.isArray(pairs) || pairs.length % 2 || pairs.length > 4096) throw classifiedRefusal();
      const tag = referenced(names[index]!).toUpperCase();
      const attrs = new Map<string, string>();
      for (let offset = 0; offset < pairs.length; offset += 2) {
        const name = referenced(pairs[offset]!), value = referenced(pairs[offset + 1]!, true);
        attrs.set(name.toLowerCase(), value);
      }
      const type = (attrs.get('type') ?? '').toLowerCase();
      const autocomplete = (attrs.get('autocomplete') ?? '').toLowerCase().split(/\s+/);
      const sensitive = Boolean(parent?.sensitive || this.known.has(frame, backend) ||
        (tag === 'INPUT' && type === 'password') || autocomplete.some(token => ['current-password', 'new-password', 'one-time-code'].includes(token)));
      const unavailable = Boolean(parent?.unavailable || closed.has(index) || shadowHosts.has(index) || tag === 'SLOT');
      const editable = !sensitive && !unavailable && !attrs.has('disabled') && !attrs.has('readonly') && attrs.get('aria-disabled') !== 'true' &&
        (tag === 'TEXTAREA' || (tag === 'INPUT' && !['button', 'submit', 'reset', 'hidden', 'checkbox', 'radio', 'file', 'image'].includes(type)) ||
          ['true', '', 'plaintext-only'].includes(attrs.get('contenteditable') ?? 'false'));
      const relevant = ['type', 'autocomplete', 'role', 'contenteditable', 'disabled', 'readonly', 'aria-disabled', 'aria-expanded', 'aria-checked', 'aria-selected'];
      nodes.set(backend, Object.freeze({ backend, parent: parent?.backend ?? 0, tag, editable, sensitive, unavailable,
        signature: fingerprint([backend, parent?.signature, tag, relevant.map(name => [name, attrs.get(name)]), sensitive, unavailable]) }));
    }
    // Validated parents precede children. One reverse pass propagates all
    // sensitive descendants to ancestors without repeated depth walks.
    for (let index = backends.length - 1; index >= 0; index--) {
      const field = nodes.get(backends[index]!)!;
      if (field.parent && (field.sensitive || field.unavailable || ['IFRAME', 'FRAME', 'OBJECT', 'EMBED'].includes(field.tag) || aggregates.has(field.backend))) aggregates.add(field.parent);
    }
    const layout = document.layout;
    if (!layout || !Array.isArray(layout.nodeIndex) || !Array.isArray(layout.bounds) ||
        layout.nodeIndex.length !== layout.bounds.length || layout.nodeIndex.length > 100000) throw classifiedRefusal();
    for (let index = 0; index < layout.nodeIndex.length; index++) {
      const node = layout.nodeIndex[index]!, bounds = layout.bounds[index];
      if (!Number.isSafeInteger(node) || node < 0 || node >= backends.length || !bounds || bounds.length !== 4 ||
          !bounds.every(Number.isFinite)) throw classifiedRefusal();
    }
    return Object.freeze({ frame, nodes, aggregates, address: string(document.documentURL), title: text(string(document.title, true), 512),
      accessible: false, lineage: '',
      signature: fingerprint([[...nodes.values()].map(node => [node.backend, node.signature]), layout.nodeIndex, layout.bounds]) });
  }

  project(node: AXNode, dom: ClassifiedDOM): { value: SnapshotNode; original?: OriginalNode } {
    const field = node.backendDOMNodeId === undefined ? undefined : dom.nodes.get(node.backendDOMNodeId);
    if (!dom.accessible || !field || field.unavailable || (node.frameId !== undefined && node.frameId !== dom.frame.frameId))
      return { value: { role: 'unknown', state: { unavailable: true } } };
    if (field.sensitive) return { value: { role: 'textbox', state: { sensitive: true } } };
    const properties = new Map((node.properties ?? []).map(property => [property.name, property.value?.value]));
    const state: NonNullable<SnapshotNode['state']> = {};
    for (const key of ['disabled', 'selected', 'expanded', 'focused'] as const)
      if (typeof properties.get(key) === 'boolean') state[key] = properties.get(key) as boolean;
    const checked = properties.get('checked');
    if (checked === true || checked === false || checked === 'mixed') state.checked = checked;
    state.editable = field.editable;
    const role = text(node.role?.value, 80) || 'unknown';
    const value: SnapshotNode = { role, state };
    // Aggregate ancestors can incorporate descendant values in synthesized AX names.
    const sources = (node.name as { sources?: { relatedNodes?: { backendDOMNodeId?: number }[];
      attributeValue?: { relatedNodes?: { backendDOMNodeId?: number }[] } }[] } | undefined)?.sources;
    const secretName = sources?.some(source => [...(source.relatedNodes ?? []), ...(source.attributeValue?.relatedNodes ?? [])]
      .some(related => related.backendDOMNodeId !== undefined && (!dom.nodes.has(related.backendDOMNodeId) || dom.nodes.get(related.backendDOMNodeId)?.sensitive || dom.nodes.get(related.backendDOMNodeId)?.unavailable)));
    if (!secretName && !dom.aggregates.has(field.backend)) {
      if (typeof node.name?.value === 'string') value.name = text(node.name.value, 4096);
      if (typeof node.value?.value === 'string') {
        value.value = text(node.value.value, 4096);
        if (Array.from(node.value.value).length > 4096) state.valueTruncated = true;
      }
    }
    const signature = fingerprint([dom.lineage, field.signature, role, value.name, state]);
    return { value, original: Object.freeze({ frame: dom.frame, backend: field.backend, signature, editable: field.editable }) };
  }
  async original(node: OriginalNode, guard: () => void): Promise<OriginalNode> {
    const frames: InspectionFrame[] = []; let frame: InspectionFrame | undefined = node.frame;
    while (frame) { if (frames.length >= 32) throw staleSnapshot(); frames.unshift(frame); frame = frame.parent; }
    return this.bracket(frames, guard, async check => {
      const epoch = this.readiness.observation(node.frame.receipt).epoch;
      const phase = await this.classifyFrames(frames, guard), dom = phase.get(node.frame)!;
      const field = dom.nodes.get(node.backend);
      if (!dom.accessible || !field || field.sensitive || field.unavailable) throw staleSnapshot();
      await check();
      const described = await this.readiness.inspect(node.frame, guard, 'DOM.describeNode',
        { backendNodeId: node.backend, depth: 0 }) as { node?: { backendNodeId?: number } };
      if (described.node?.backendNodeId !== node.backend) throw staleSnapshot();
      // Backend identity plus classified AX proof suffices. ResolveNode and its
      // otherwise unowned remote-object allocation are deliberately eliminated.
      const tree = await this.readiness.inspect(node.frame, guard, 'Accessibility.getPartialAXTree',
        { backendNodeId: node.backend, fetchRelatives: false }) as { nodes?: AXNode[] };
      try {
        await check();
        if (!Array.isArray(tree.nodes) || tree.nodes.length > 1000 || Buffer.byteLength(JSON.stringify(tree.nodes), 'utf8') > 16 * 1024 * 1024) throw staleSnapshot();
        const matches = tree.nodes.filter(value => value.backendDOMNodeId === node.backend);
        if (matches.length !== 1) throw staleSnapshot();
        const after = await this.classifyFrames(frames, guard); await check();
        for (const value of frames) if (phase.get(value)!.signature !== after.get(value)!.signature ||
          phase.get(value)!.lineage !== after.get(value)!.lineage || !after.get(value)!.accessible) throw staleSnapshot();
        const current = this.project(matches[0]!, dom).original;
        this.readiness.assertInspection(node.frame, guard);
        if (!current || this.readiness.observation(node.frame.receipt).epoch !== epoch) throw staleSnapshot(); return current;
      } finally { for (const value of tree.nodes ?? []) { delete value.name; delete value.value; delete value.properties; } }
    });
  }
  /** getBoxModel is root-frame viewport geometry only. There is deliberately
   * no guessed iframe transform; unbound frame trees refuse capture. */
  async geometry(dom: ClassifiedDOM, guard: () => void): Promise<readonly number[][]> {
    if (dom.frame.receipt.frames.length !== 1) throw classifiedRefusal();
    const boxes: number[][] = [];
    for (const field of dom.nodes.values()) if (field.sensitive) {
      const result = await this.readiness.inspect(dom.frame, guard, 'DOM.getBoxModel',
        { backendNodeId: field.backend }) as { model?: { border?: number[] } };
      const quad = result.model?.border;
      if (!quad || quad.length !== 8 || !quad.every(Number.isFinite)) throw classifiedRefusal(); boxes.push([...quad]);
    }
    guard(); return Object.freeze(boxes);
  }
}
