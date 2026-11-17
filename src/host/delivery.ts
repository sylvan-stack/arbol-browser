import { createHash, timingSafeEqual } from 'node:crypto';
import type { Contract, ContractTypes } from '../contracts/generated.js';
import { BrowserFailure, unavailable, type BrowserError } from '../contracts/errors.js';
import { validator, bundles } from '../contracts/schema.js';
import type { ConnectionContext, Request } from '../runtime/transport.js';
import { TabAuthority, type AuthorityStamp, type CompletedTransition, type Invalidation } from './authority.js';
import { assertTabRegistry, type TabRegistry } from './tabs.js';
import { projectAgentTabs } from './projections.js';
import { ClassifiedReadRefusal } from './actions.js';

export type DeliveryProof =
  | { readonly kind: 'snapshot' | 'screenshot'; readonly stamp: AuthorityStamp; readonly identity: string }
  | { readonly kind: 'action'; readonly stamp: AuthorityStamp; readonly action: string }
  | { readonly kind: 'opened'; readonly stamp: AuthorityStamp; readonly receipt: CompletedTransition }
  | { readonly kind: 'tabs'; readonly recipient: string }
  | { readonly kind: 'info' }
  | { readonly kind: 'management'; readonly method: 'open' | 'close' }
  | { readonly kind: 'release' | 'close'; readonly receipt: CompletedTransition };
interface Pending { bytes: Buffer; proof: DeliveryProof; body: unknown }
interface KnownOutcome { action?: string; dispatchOutcome?: Contract<'browser.Outcome'> }
/** Complete framing occurs before any final guard. The transport must write
 * these exact bytes without serialization or callbacks after commit(). */
export function responseBytes(id: string, success: boolean, value: unknown): Buffer {
  const response = success ? { wire: 1, id, ok: true, result: value } : { wire: 1, id, ok: false, error: value };
  const bytes = Buffer.from(JSON.stringify(response) + '\n', 'utf8');
  if (bytes.length - 1 > 8 * 1024 * 1024) throw new BrowserFailure({ code: 'control_refused',
    message: 'The response exceeds browser transport capacity.', retryable: true,
    remedy: 'Request less page content after inspecting current state.' });
  return bytes;
}
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest();
/** Host-owned per-request final delivery, not an adapter-local post-await check. */
export class DeliveryAuthority {
  private readonly pending = new Map<ConnectionContext, Map<string, Pending>>();
  private readonly failures = new Map<ConnectionContext, Map<string, Buffer>>();
  private readonly outcomes = new Map<ConnectionContext, Map<string, KnownOutcome>>();
  private readonly malformed = new Map<ConnectionContext, Set<string>>();
  private readonly classifiedFailures = new Map<ConnectionContext, Map<string, AuthorityStamp>>();
  constructor(readonly authority: TabAuthority, readonly registry: () => TabRegistry) {
    authority.onInvalidate(event => this.invalidate(event));
  }
  assertContext(context: ConnectionContext): void {
    this.authority.assertAdmission();
    if (!this.pending.has(context) || context.signal.aborted || (context.endpoint === 'agent'
      ? !context.attachment || this.authority.attachment(context.attachment.id) !== context.attachment
      : context.attachment !== undefined)) throw unavailable('browser');
  }
  enroll(context: ConnectionContext): void {
    this.authority.assertAdmission();
    if (this.pending.has(context) || context.signal.aborted || this.pending.size >= 64) throw unavailable('browser');
    const reservation = new Map<string, Pending>();
    // Publish before connect/changed subscribers can synchronously close/revoke.
    this.pending.set(context, reservation); this.failures.set(context, new Map());
    this.outcomes.set(context, new Map()); this.malformed.set(context, new Set());
    this.classifiedFailures.set(context, new Map());
    try {
      if (context.endpoint === 'agent') {
        if (!context.attachment) throw unavailable('browser'); this.authority.connect(context.attachment, context.signal);
      } else if (context.attachment) throw unavailable('browser');
      if (this.pending.get(context) !== reservation) throw unavailable('browser'); this.assertContext(context);
    } catch (error) {
      // Local buffers only. Transport's single attempted-enrollment rollback
      // owns connection/grant revocation even if connect partially completed.
      this.disconnect(context); throw error;
    }
  }
  disconnect(context: ConnectionContext): void {
    for (const record of this.pending.get(context)?.values() ?? []) record.bytes.fill(0);
    for (const bytes of this.failures.get(context)?.values() ?? []) bytes.fill(0);
    this.pending.delete(context); this.failures.delete(context); this.outcomes.delete(context); this.malformed.delete(context);
    this.classifiedFailures.delete(context);
  }
  noteOutcome(context: ConnectionContext, request: Request, outcome: KnownOutcome): void {
    this.assertContext(context);
    if (outcome.action && (!this.authority.knowsAction(outcome.action) || !outcome.dispatchOutcome)) throw unavailable('browser');
    const entries = this.outcomes.get(context)!;
    if (entries.size >= 32 && !entries.has(request.id)) throw unavailable('browser'); entries.set(request.id, { ...outcome });
  }
  private shape(request: Request, value: unknown): boolean {
    if (request.method !== 'tool') return validator(request.method === 'open' ? 'wire.OpenResult' : 'wire.CloseResult')(value);
    if (request.params.name === 'browser_screenshot') return validator('browser.ScreenshotPayload')(value);
    const name = bundles.browser['x-tools'][request.params.name].success.$ref.split('/').at(-1)!;
    return validator(`browser.${name}` as keyof ContractTypes)(value);
  }
  private verify(context: ConnectionContext, request: Request, proof: DeliveryProof, value: unknown): void {
    this.assertContext(context);
    if (!this.shape(request, value)) throw unavailable('browser');
    const body = value as Record<string, unknown>;
    if (proof.kind === 'management') {
      if (context.endpoint !== 'management' || request.method !== proof.method) throw unavailable('browser');
      this.assertContext(context); return;
    }
    if (context.endpoint !== 'agent' || !context.attachment || request.method !== 'tool') throw unavailable('browser');
    const recipient = context.attachment.id, args = request.params.arguments;
    const checkStamp = (stamp: AuthorityStamp, mutation = false) => {
      if (context.attachment !== stamp.attachment || !('tab' in args) || args.tab !== stamp.target.id ||
          !('controlGeneration' in args) || args.controlGeneration !== stamp.generation) throw unavailable('browser');
      this.authority.check(stamp, mutation);
    };
    switch (proof.kind) {
      case 'snapshot': case 'screenshot': {
        if (request.params.name !== (proof.kind === 'snapshot' ? 'browser_snapshot' : 'browser_screenshot')) throw unavailable('browser');
        checkStamp(proof.stamp);
        const data = proof.kind === 'screenshot' ? body.metadata as Record<string, unknown> : body;
        if (data.tab !== proof.stamp.target.id || data.controlGeneration !== proof.stamp.generation ||
            data.navigation !== proof.stamp.document.navigation || data.snapshot !== proof.identity) throw unavailable('browser');
        break;
      }
      case 'action':
        if (!['browser_navigate', 'browser_click', 'browser_type', 'browser_press_key', 'browser_scroll', 'browser_drag'].includes(request.params.name))
          throw unavailable('browser');
        checkStamp(proof.stamp, true);
        if (body.tab !== proof.stamp.target.id || body.controlGeneration !== proof.stamp.generation || body.action !== proof.action ||
            !this.authority.knowsAction(proof.action) || body.status !== 'completed' ||
            (body.navigation !== undefined && body.navigation !== proof.stamp.document.navigation)) throw unavailable('browser');
        break;
      case 'opened': {
        if (request.params.name !== 'browser_tab_open' || context.attachment !== proof.stamp.attachment ||
            proof.stamp.target !== proof.receipt.target || proof.stamp.generation !== proof.receipt.generation) throw unavailable('browser');
        this.authority.verifyTransition(proof.receipt, 'open', recipient, request.id); this.authority.check(proof.stamp, true);
        const tab = body.tab as Record<string, unknown>;
        if (body.action !== proof.receipt.action || tab.tab !== proof.stamp.target.id || tab.controlGeneration !== proof.stamp.generation ||
            tab.ownsControl !== true || tab.inputReady !== true || tab.pageAvailability !== 'ready' ||
            (tab.navigation !== undefined && tab.navigation !== proof.stamp.document.navigation))
          throw unavailable('browser');
        break;
      }
      case 'tabs':
        if (request.params.name !== 'browser_tabs_list' || recipient !== proof.recipient)
          throw unavailable('browser'); break;
      case 'release': case 'close': {
        if (request.params.name !== (proof.kind === 'release' ? 'browser_release' : 'browser_tab_close') ||
            !('tab' in args) || !('controlGeneration' in args)) throw unavailable('browser');
        this.authority.verifyTransition(proof.receipt, proof.kind, recipient, request.id, args.tab, args.controlGeneration);
        if (body.action !== proof.receipt.action || body.status !== 'completed') throw unavailable('browser');
        if (proof.kind === 'close') { if (body.tab !== proof.receipt.target.id || body.closed !== true) throw unavailable('browser'); }
        else {
          const tab = body.tab as Record<string, unknown>;
          if (tab.tab !== proof.receipt.target.id || tab.controlGeneration !== proof.receipt.generation || tab.controller !== 'user')
            throw unavailable('browser');
        }
        break;
      }
      case 'info': if (request.params.name !== 'browser_info') throw unavailable('browser'); break;
      default: throw unavailable('browser');
    }
    this.assertContext(context);
  }
  stage(context: ConnectionContext, request: Request, value: unknown, proof: DeliveryProof): void {
    this.assertContext(context);
    if (!this.shape(request, value)) { this.malformed.get(context)!.add(request.id); throw unavailable('browser'); }
    const entries = this.pending.get(context)!;
    if (entries.has(request.id) || entries.size >= 32) throw unavailable('browser');
    const bytes = responseBytes(request.id, true, value);
    const body: unknown = JSON.parse(bytes.toString('utf8')).result;
    if (!this.shape(request, body)) { this.malformed.get(context)!.add(request.id); throw unavailable('browser'); }
    this.verify(context, request, proof, body); entries.set(request.id, { bytes, proof, body });
  }
  /** Called on the exact complete success buffer immediately before socket.write. */
  commit(context: ConnectionContext, request: Request, bytes: Uint8Array): void {
    this.assertContext(context); const entries = this.pending.get(context)!, record = entries.get(request.id);
    if (!record || !timingSafeEqual(digest(bytes), digest(record.bytes))) throw unavailable('browser');
    this.verify(context, request, record.proof, record.body);
    if (record.proof.kind === 'tabs') {
      const registry = this.registry(); assertTabRegistry(registry);
      const fresh = responseBytes(request.id, true, projectAgentTabs(registry, record.proof.recipient, id => this.authority.connected(id)));
      if (!timingSafeEqual(digest(fresh), digest(bytes))) throw unavailable('browser');
    }
    if (record.proof.kind === 'snapshot') this.authority.commitSnapshot(record.proof.identity, record.proof.stamp);
    this.assertContext(context);
    if (this.malformed.get(context)?.has(request.id)) throw unavailable('browser');
    record.bytes.fill(0); entries.delete(request.id); this.outcomes.get(context)!.delete(request.id);
  }
  /** Never forward provider strings or stale content in the fallback envelope.
   * The original admitted action outcome survives a stale-success refusal. */
  redactedFailure(context: ConnectionContext, request: Request, error: unknown): BrowserError {
    this.assertContext(context);
    if (this.malformed.get(context)?.has(request.id)) throw unavailable('browser');
    const known = this.outcomes.get(context)!.get(request.id);
    let current = error, classified: AuthorityStamp | undefined;
    this.classifiedFailures.get(context)!.delete(request.id);
    if (error instanceof ClassifiedReadRefusal) {
      try {
        if (context.attachment !== error.stamp.attachment || request.method !== 'tool' ||
            !['browser_snapshot', 'browser_screenshot'].includes(request.params.name)) throw unavailable('browser');
        this.authority.check(error.stamp); classified = error.stamp;
      } catch (changed) { current = changed; }
    }
    const publicError = current instanceof BrowserFailure ? current.detail : undefined;
    const value: BrowserError = { code: publicError?.code ?? 'internal', message: 'The browser request could not complete.', retryable: true,
      remedy: classified
        ? 'Use Take control to inspect this page privately.' : 'Inspect fresh browser state before deciding on another action.',
      ...(known?.action ? { action: known.action, dispatchOutcome: known.dispatchOutcome! } : {}) };
    if (!validator('browser.BrowserError')(value)) throw unavailable('browser');
    const old = this.pending.get(context)!.get(request.id); old?.bytes.fill(0); this.pending.get(context)!.delete(request.id);
    const failures = this.failures.get(context)!;
    if (failures.size >= 32 && !failures.has(request.id)) throw unavailable('browser');
    failures.get(request.id)?.fill(0); failures.set(request.id, responseBytes(request.id, false, value));
    if (classified) this.classifiedFailures.get(context)!.set(request.id, classified);
    return value;
  }
  commitFailure(context: ConnectionContext, request: Request, bytes: Uint8Array): void {
    this.assertContext(context); const failures = this.failures.get(context)!, expected = failures.get(request.id);
    if (!expected || !timingSafeEqual(digest(bytes), digest(expected))) throw unavailable('browser');
    const classified = this.classifiedFailures.get(context)!.get(request.id);
    if (classified) this.authority.check(classified);
    // No previous content/grant proof is reused to authorize this new redacted frame.
    this.assertContext(context); expected.fill(0); failures.delete(request.id); this.outcomes.get(context)!.delete(request.id);
    this.classifiedFailures.get(context)!.delete(request.id);
  }
  forget(context: ConnectionContext, request: Request): void {
    this.pending.get(context)?.get(request.id)?.bytes.fill(0); this.pending.get(context)?.delete(request.id);
    this.failures.get(context)?.get(request.id)?.fill(0); this.failures.get(context)?.delete(request.id);
    this.outcomes.get(context)?.delete(request.id);
    this.malformed.get(context)?.delete(request.id);
    this.classifiedFailures.get(context)?.delete(request.id);
  }
  private invalidate(event: Invalidation): void {
    for (const [context, entries] of this.pending) for (const [id, record] of entries) {
      const proof = record.proof;
      if ((event.recipient === undefined || context.attachment?.id === event.recipient) &&
          (proof.kind === 'tabs' || ('stamp' in proof && proof.stamp.target === event.target) ||
          (proof.kind === 'release' && proof.receipt.target === event.target) ||
          (proof.kind === 'close' && event.recipient === undefined && proof.receipt.target === event.target))) {
        record.bytes.fill(0); entries.delete(id);
      }
    }
  }
}
