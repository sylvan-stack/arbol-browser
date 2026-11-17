import type { OwnershipHost, OwnershipOperations } from './handoff.js';
import type { ProtectedDispatchPort } from '../runtime/transport.js';
import { BrowserFailure, unavailable } from '../contracts/errors.js';
import type { TabAuthority } from './authority.js';
import type { HostDocuments } from './documents.js';
import type { PageReadiness } from './readiness.js';
import { HostSecretFields, SensitiveFields } from '../content/sensitive.js';
import { SnapshotInspection } from '../content/snapshot.js';
import { inspectScreenshot } from '../content/capture.js';
import { navigateTrusted } from '../automation/navigation.js';
import { clickTrusted } from '../automation/click.js';
import { pressTrusted } from '../automation/keyboard.js';
import { typeTrusted } from '../automation/typing.js';
import { scrollTrusted } from '../automation/scroll.js';
import { dragTrusted } from '../automation/drag.js';
import { retireUnsettled, settledResult } from '../automation/outcomes.js';

export type HostToolOperation = OwnershipOperations['agent'];
export interface HostToolProviders {
  readonly inspection?: HostToolOperation;
  readonly mutation?: HostToolOperation;
}
/** ABR-30 composes this callback with createInspectionTools.agent inside the
 * genuine OwnershipOperations.agent. Open/Close/release/cancel keep their
 * existing protected ownership ports; this contribution enables no host. */
export function createTrustedActionTools(inspection: SnapshotInspection): { readonly agent: HostToolOperation; close(): void } {
  let closed = false;
  const agent: HostToolOperation = async (request, execution) => {
    if (closed) throw unavailable('browser');
    const params = request.params;
    try {
      let result;
      switch (params.name) {
        case 'browser_navigate': result = await navigateTrusted(inspection, execution, params.arguments); break;
        case 'browser_click': result = await clickTrusted(inspection, execution, params.arguments); break;
        case 'browser_press_key': result = await pressTrusted(inspection, execution, params.arguments); break;
        case 'browser_type': result = await typeTrusted(inspection, execution, params.arguments); break;
        case 'browser_scroll': result = await scrollTrusted(inspection, execution, params.arguments); break;
        case 'browser_drag': result = await dragTrusted(inspection, execution, params.arguments); break;
        default: throw unavailable('browser');
      }
      if (closed) throw unavailable('browser');
      return settledResult(inspection, execution, result);
    } catch (error) {
      retireUnsettled(inspection, execution, request.id); throw error;
    }
  };
  return Object.freeze({ agent, close() { closed = true; } });
}
/** Install through createHostToolOperations.inspection inside the genuine
 * OwnershipOperations.agent callback. ABR-30 owns packaged host composition;
 * this does not replace the control/health producer or enable page admission. */
export function createInspectionTools(authority: TabAuthority, documents: HostDocuments, readiness: PageReadiness): {
  readonly agent: HostToolOperation;
  readonly inspection: SnapshotInspection;
  readonly secrets: HostSecretFields;
  close(): void;
} {
  const secrets = new HostSecretFields(), fields = new SensitiveFields(readiness, secrets);
  const inspection = new SnapshotInspection(authority, documents, readiness, fields);
  let closed = false;
  const agent: HostToolOperation = async (request, execution, identity) => {
    if (closed || !identity) throw unavailable('browser');
    const params = request.params;
    switch (params.name) {
      case 'browser_snapshot': return inspection.snapshot(params.arguments, execution, identity);
      case 'browser_screenshot':
        if (identity !== params.arguments.snapshot) throw unavailable('browser');
        return inspectScreenshot(inspection, execution, identity);
      default: throw unavailable('browser');
    }
  };
  return Object.freeze({ agent, inspection, secrets, close() { if (!closed) { closed = true; inspection.close(); } } });
}
/** Main-process contribution consumed inside OwnershipHost's actual guarded
 * ActionQueue. Providers receive its original ActionExecution and inspection
 * identity. No provider receives a raw adapter or an alternate authority. */
export function createHostToolOperations(providers: HostToolProviders): HostToolOperation {
  const { inspection, mutation } = providers;
  return async (request, execution, inspectionIdentity) => {
    if (execution.signal.aborted || performance.now() >= execution.deadline) throw unavailable('browser');
    const name = request.params.name;
    switch (name) {
      case 'browser_snapshot': case 'browser_screenshot':
        if (!inspection || !inspectionIdentity) break;
        return inspection(request, execution, inspectionIdentity);
      case 'browser_navigate': case 'browser_click': case 'browser_type': case 'browser_press_key':
      case 'browser_scroll': case 'browser_drag':
        if (!mutation) break;
        return mutation(request, execution, inspectionIdentity);
      // info/list/open/close/release are implemented by OwnershipHost itself,
      // with authentic projection/transition proofs, never provider callbacks.
      default: break;
    }
    throw new BrowserFailure({ code: 'unsupported', message: 'This browser tool provider is unavailable.',
      retryable: false, remedy: 'Use a complete qualified browser Build.' });
  };
}
/** Production listenProtectedTransport must use this exact existing port. Its
 * authorize/execute, recipient proofs, byte commit, cancellation and disconnect
 * remain one service; infrastructure listenTransport is not an alternative. */
export function protectedToolDispatch(host: OwnershipHost): ProtectedDispatchPort {
  const dispatch = host.dispatch;
  for (const method of ['enroll', 'guardControl', 'authorize', 'execute', 'commitResponse', 'redactedFailure',
    'forget', 'cancel', 'disconnect', 'fatal'] as const)
    if (typeof dispatch[method] !== 'function') throw unavailable('browser');
  return dispatch;
}
