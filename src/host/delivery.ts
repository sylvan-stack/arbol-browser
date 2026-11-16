import { createHash, timingSafeEqual } from 'node:crypto';
import type { Contract } from '../contracts/generated.js';
import { BrowserFailure, unavailable, type BrowserError } from '../contracts/errors.js';
import { validator } from '../contracts/schema.js';
import type { ConnectionContext, Request } from '../runtime/transport.js';
import { TabAuthority, type AuthorityStamp, type Invalidation } from './authority.js';
import type { TabTarget } from './tabs.js';

export type DeliveryProof =
  | { readonly kind: 'content'; readonly stamp: AuthorityStamp; readonly snapshot?: string }
  | { readonly kind: 'tabs'; readonly recipient: string; readonly project: () => Contract<'browser.TabsResult'> }
  | { readonly kind: 'metadata' }
  | { readonly kind: 'transition'; readonly recipient: string; readonly target: TabTarget; readonly verify: () => void };
interface Pending { bytes: Buffer; proof: DeliveryProof }
interface KnownOutcome { action?: string; dispatchOutcome?: Contract<'browser.Outcome'> }
/** Complete framing occurs before any final guard. The transport must write
 * these exact bytes without serialization or callbacks after commit(). */
export function responseBytes(id: string, success: boolean, value: unknown): Buffer {
  const response = success ? { wire: 1, id, ok: true, result: value } : { wire: 1, id, ok: false, error: value };
  const bytes = Buffer.from(JSON.stringify(response) + '\n', 'utf8');
  if (bytes.length - 1 > 8 * 1024 * 1024) throw unavailable('browser'); return bytes;
}
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest();
/** Host-owned per-request final delivery, not an adapter-local post-await check. */
export class DeliveryAuthority {
  private readonly pending = new Map<ConnectionContext, Map<string, Pending>>();
  private readonly failures = new Map<ConnectionContext, Map<string, Buffer>>();
  private readonly outcomes = new Map<ConnectionContext, Map<string, KnownOutcome>>();
  constructor(readonly authority: TabAuthority) { authority.onInvalidate(event => this.invalidate(event)); }
  assertContext(context: ConnectionContext): void {
    this.authority.assertAdmission();
    if (!this.pending.has(context) || context.signal.aborted || (context.endpoint === 'agent'
      ? !context.attachment || this.authority.attachment(context.attachment.id) !== context.attachment
      : context.attachment !== undefined)) throw unavailable('browser');
  }
  enroll(context: ConnectionContext): void {
    this.authority.assertAdmission(); if (this.pending.has(context) || context.signal.aborted) throw unavailable('browser');
    if (context.endpoint === 'agent') {
      if (!context.attachment) throw unavailable('browser'); this.authority.connect(context.attachment, context.signal);
    } else if (context.attachment) throw unavailable('browser');
    this.pending.set(context, new Map()); this.failures.set(context, new Map()); this.outcomes.set(context, new Map());
  }
  disconnect(context: ConnectionContext): void {
    for (const record of this.pending.get(context)?.values() ?? []) record.bytes.fill(0);
    for (const bytes of this.failures.get(context)?.values() ?? []) bytes.fill(0);
    this.pending.delete(context); this.failures.delete(context); this.outcomes.delete(context);
  }
  noteOutcome(context: ConnectionContext, request: Request, outcome: KnownOutcome): void {
    this.assertContext(context);
    if (outcome.action && (!validator('browser.ActionId')(outcome.action) || !outcome.dispatchOutcome)) throw unavailable('browser');
    const entries = this.outcomes.get(context)!;
    if (entries.size >= 32 && !entries.has(request.id)) throw unavailable('browser'); entries.set(request.id, { ...outcome });
  }
  private verify(context: ConnectionContext, request: Request, proof: DeliveryProof): void {
    this.assertContext(context);
    switch (proof.kind) {
      case 'content':
        if (context.attachment !== proof.stamp.attachment) throw unavailable('browser');
        this.authority.check(proof.stamp); break;
      case 'tabs':
        if (request.method !== 'tool' || request.params.name !== 'browser_tabs_list' || context.attachment?.id !== proof.recipient)
          throw unavailable('browser'); break;
      case 'transition': {
        if (context.attachment?.id !== proof.recipient) throw unavailable('browser');
        const returned: unknown = proof.verify(); if (returned !== undefined) return this.authority.exhausted(); break;
      }
      case 'metadata':
        if (request.method === 'tool' && request.params.name !== 'browser_info') throw unavailable('browser'); break;
    }
    this.assertContext(context);
  }
  stage(context: ConnectionContext, request: Request, value: unknown, proof: DeliveryProof): void {
    this.verify(context, request, proof); const entries = this.pending.get(context)!;
    if (entries.has(request.id) || entries.size >= 32) throw unavailable('browser');
    const bytes = responseBytes(request.id, true, value);
    this.verify(context, request, proof); entries.set(request.id, { bytes, proof });
  }
  /** Called on the exact complete success buffer immediately before socket.write. */
  commit(context: ConnectionContext, request: Request, bytes: Uint8Array): void {
    this.assertContext(context); const entries = this.pending.get(context)!, record = entries.get(request.id);
    if (!record || !timingSafeEqual(digest(bytes), digest(record.bytes))) throw unavailable('browser');
    this.verify(context, request, record.proof);
    if (record.proof.kind === 'tabs') {
      const fresh = responseBytes(request.id, true, record.proof.project());
      if (!timingSafeEqual(digest(fresh), digest(bytes))) throw unavailable('browser');
    }
    if (record.proof.kind === 'content' && record.proof.snapshot) this.authority.commitSnapshot(record.proof.snapshot, record.proof.stamp);
    this.assertContext(context);
    record.bytes.fill(0); entries.delete(request.id); this.outcomes.get(context)!.delete(request.id);
  }
  /** Never forward provider strings or stale content in the fallback envelope.
   * The original admitted action outcome survives a stale-success refusal. */
  redactedFailure(context: ConnectionContext, request: Request, error: unknown): BrowserError {
    this.assertContext(context);
    const known = this.outcomes.get(context)!.get(request.id);
    const publicError = error instanceof BrowserFailure ? error.detail : undefined;
    const value: BrowserError = { code: publicError?.code ?? 'internal', message: 'The browser request could not complete.', retryable: true,
      remedy: 'Inspect fresh browser state before deciding on another action.',
      ...(known?.action ? { action: known.action, dispatchOutcome: known.dispatchOutcome! } : {}) };
    if (!validator('browser.BrowserError')(value)) throw unavailable('browser');
    const old = this.pending.get(context)!.get(request.id); old?.bytes.fill(0); this.pending.get(context)!.delete(request.id);
    const failures = this.failures.get(context)!;
    if (failures.size >= 32 && !failures.has(request.id)) throw unavailable('browser');
    failures.get(request.id)?.fill(0); failures.set(request.id, responseBytes(request.id, false, value));
    return value;
  }
  commitFailure(context: ConnectionContext, request: Request, bytes: Uint8Array): void {
    this.assertContext(context); const failures = this.failures.get(context)!, expected = failures.get(request.id);
    if (!expected || !timingSafeEqual(digest(bytes), digest(expected))) throw unavailable('browser');
    // No previous content/grant proof is reused to authorize this new redacted frame.
    this.assertContext(context); expected.fill(0); failures.delete(request.id); this.outcomes.get(context)!.delete(request.id);
  }
  forget(context: ConnectionContext, request: Request): void {
    this.pending.get(context)?.get(request.id)?.bytes.fill(0); this.pending.get(context)?.delete(request.id);
    this.failures.get(context)?.get(request.id)?.fill(0); this.failures.get(context)?.delete(request.id);
    this.outcomes.get(context)?.delete(request.id);
  }
  private invalidate(event: Invalidation): void {
    for (const [context, entries] of this.pending) for (const [id, record] of entries) {
      const proof = record.proof;
      if ((event.recipient === undefined || context.attachment?.id === event.recipient) &&
          (proof.kind === 'tabs' || (proof.kind === 'content' && proof.stamp.target === event.target) ||
          (proof.kind === 'transition' && event.recipient === undefined && proof.target === event.target))) {
        record.bytes.fill(0); entries.delete(id);
      }
    }
  }
}
