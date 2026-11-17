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
}
/** Host-only explicit classification, keyed to the original logical document.
 * Tool arguments and website accessibility claims cannot populate this set. */
export class HostSecretFields {
  private readonly fields = new WeakMap<HostDocument, Set<number>>();
  mark(document: HostDocument, backend: number): void {
    if (!Number.isSafeInteger(backend) || backend <= 0) throw staleSnapshot();
    const fields = this.fields.get(document) ?? new Set<number>();
    if (fields.size >= 5000) throw classifiedRefusal(); fields.add(backend); this.fields.set(document, fields);
  }
  has(document: HostDocument, backend: number): boolean { return this.fields.get(document)?.has(backend) ?? false; }
}
function text(value: unknown, limit: number): string {
  if (typeof value !== 'string') return '';
  return Array.from(value.replace(/[\u0000\uD800-\uDFFF]/gu, '')).slice(0, limit).join('');
}
/** No ordinary-page text scanning: this guarantee covers classified DOM
 * authentication fields and user-mode privacy, not arbitrary prose secrets. */
export class SensitiveFields {
  constructor(readonly readiness: PageReadiness, readonly known: HostSecretFields) {}
  async classify(frame: InspectionFrame, guard: () => void): Promise<ClassifiedDOM> {
    this.readiness.assertInspection(frame, guard);
    const raw = await this.readiness.inspect(frame, guard, 'DOMSnapshot.captureSnapshot',
      { computedStyles: [], includePaintOrder: true, includeDOMRects: true }) as RawSnapshot;
    try {
      guard();
      if (!Array.isArray(raw.strings) || !Array.isArray(raw.documents) || raw.strings.length > 1000000 || raw.documents.length > 256)
        throw classifiedRefusal();
      let bytes = 0;
      const stringBytes: number[] = [];
      for (const value of raw.strings) {
        if (typeof value !== 'string') throw classifiedRefusal();
        const size = Buffer.byteLength(value, 'utf8');
        if ((bytes += size) > 16 * 1024 * 1024) throw classifiedRefusal(); stringBytes.push(size);
      }
      const string = (index: number, empty = false): string => {
        // Pinned Blink AddString emits -1 for empty title/attribute values.
        // Identity-bearing fields must still resolve to nonempty table strings.
        if (empty && index === -1) return '';
        if (!Number.isSafeInteger(index) || index < 0 || index >= raw.strings.length) throw classifiedRefusal();
        const value = raw.strings[index]!; if (!empty && value.length === 0) throw classifiedRefusal(); return value;
      };
      let expandedBytes = 0, attributeIndices = 0;
      const referenced = (index: number, empty = false): string => {
        const value = string(index, empty);
        if ((expandedBytes += index === -1 ? 0 : stringBytes[index]!) > 16 * 1024 * 1024) throw classifiedRefusal();
        return value; // charge every reference before case folding/split/hash
      };
      const documents = raw.documents.filter(document => string(document.frameId) === frame.frameId);
      if (documents.length !== 1) throw classifiedRefusal(); const document = documents[0]!;
      const { backendNodeId: backends, parentIndex: parents, nodeName: names, attributes } = document.nodes;
      if (!backends || !parents || !names || !attributes || backends.length > 100000 ||
          parents.length !== backends.length || names.length !== backends.length || attributes.length !== backends.length) throw classifiedRefusal();
      const closed = new Set<number>();
      const shadows = document.nodes.shadowRootType;
      if (shadows) {
        if (!Array.isArray(shadows.index) || !Array.isArray(shadows.value) || shadows.index.length !== shadows.value.length ||
            shadows.index.length > backends.length) throw classifiedRefusal();
        const seen = new Set<number>();
        for (let index = 0; index < shadows.index.length; index++) {
          const node = shadows.index[index]!;
          if (!Number.isSafeInteger(node) || node < 0 || node >= backends.length || seen.has(node)) throw classifiedRefusal();
          seen.add(node); if (string(shadows.value[index]!) !== 'open') closed.add(node);
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
        if (!Array.isArray(pairs) || pairs.length % 2 || pairs.length > 4096 ||
            (attributeIndices += pairs.length) > 1000000) throw classifiedRefusal();
        const tag = referenced(names[index]!).toUpperCase();
        const attrs = new Map<string, string>();
        for (let offset = 0; offset < pairs.length; offset += 2) {
          const name = referenced(pairs[offset]!), value = referenced(pairs[offset + 1]!, true);
          attrs.set(name.toLowerCase(), value);
        }
        const type = (attrs.get('type') ?? '').toLowerCase();
        const autocomplete = (attrs.get('autocomplete') ?? '').toLowerCase().split(/\s+/);
        const sensitive = Boolean(parent?.sensitive || this.known.has(frame.receipt, backend) ||
          (tag === 'INPUT' && type === 'password') || autocomplete.some(token => ['current-password', 'new-password', 'one-time-code'].includes(token)));
        const unavailable = Boolean(parent?.unavailable || closed.has(index));
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
        if (field.parent && (field.sensitive || aggregates.has(field.backend))) aggregates.add(field.parent);
      }
      const layout = document.layout;
      if (!layout || !Array.isArray(layout.nodeIndex) || !Array.isArray(layout.bounds) ||
          layout.nodeIndex.length !== layout.bounds.length || layout.nodeIndex.length > 100000) throw classifiedRefusal();
      for (let index = 0; index < layout.nodeIndex.length; index++) {
        const node = layout.nodeIndex[index]!, bounds = layout.bounds[index];
        if (!Number.isSafeInteger(node) || node < 0 || node >= backends.length || !bounds || bounds.length !== 4 ||
            !bounds.every(Number.isFinite)) throw classifiedRefusal();
      }
      this.readiness.assertInspection(frame, guard);
      return Object.freeze({ frame, nodes, aggregates, address: string(document.documentURL), title: text(string(document.title, true), 512),
        signature: fingerprint([[...nodes.values()].map(node => [node.backend, node.signature]), layout.nodeIndex, layout.bounds]) });
    } catch (error) {
      guard(); if (error instanceof ClassifiedGeometryRefusal) throw error; throw classifiedRefusal();
    } finally {
      // Engine values remain temporary; they are never serialized, cached or logged.
      if (Array.isArray(raw?.strings)) raw.strings.fill('');
      if (Array.isArray(raw?.documents)) raw.documents.length = 0;
    }
  }
  project(node: AXNode, dom: ClassifiedDOM): { value: SnapshotNode; original?: OriginalNode } {
    const field = node.backendDOMNodeId === undefined ? undefined : dom.nodes.get(node.backendDOMNodeId);
    if (!field || field.unavailable || (node.frameId !== undefined && node.frameId !== dom.frame.frameId))
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
      .some(related => related.backendDOMNodeId !== undefined && dom.nodes.get(related.backendDOMNodeId)?.sensitive));
    if (!secretName && !dom.aggregates.has(field.backend)) {
      if (typeof node.name?.value === 'string') value.name = text(node.name.value, 4096);
      if (typeof node.value?.value === 'string') {
        value.value = text(node.value.value, 4096);
        if (Array.from(node.value.value).length > 4096) state.valueTruncated = true;
      }
    }
    const signature = fingerprint([field.signature, role, value.name, state]);
    return { value, original: Object.freeze({ frame: dom.frame, backend: field.backend, signature, editable: field.editable }) };
  }
  async original(node: OriginalNode, guard: () => void): Promise<OriginalNode> {
    const epoch = this.readiness.observation(node.frame.receipt).epoch;
    const dom = await this.classify(node.frame, guard);
    const field = dom.nodes.get(node.backend); if (!field || field.sensitive || field.unavailable) throw staleSnapshot();
    const described = await this.readiness.inspect(node.frame, guard, 'DOM.describeNode',
      { backendNodeId: node.backend, depth: 0 }) as { node?: { backendNodeId?: number } };
    if (described.node?.backendNodeId !== node.backend) throw staleSnapshot();
    const resolved = await this.readiness.inspect(node.frame, guard, 'DOM.resolveNode',
      { backendNodeId: node.backend, objectGroup: 'arbol-inspection' }) as { object?: { objectId?: string } };
    if (!resolved.object?.objectId) throw staleSnapshot();
    try {
      const tree = await this.readiness.inspect(node.frame, guard, 'Accessibility.getPartialAXTree',
        { backendNodeId: node.backend, fetchRelatives: false }) as { nodes?: AXNode[] };
      guard(); const matches = tree.nodes?.filter(value => value.backendDOMNodeId === node.backend);
      if (matches?.length !== 1) throw staleSnapshot(); const current = this.project(matches[0]!, dom).original;
      if (!current || this.readiness.observation(node.frame.receipt).epoch !== epoch) throw staleSnapshot(); return current;
    } finally {
      await this.readiness.command(node.frame.receipt.page, guard, 'Runtime.releaseObject', { objectId: resolved.object.objectId });
    }
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
