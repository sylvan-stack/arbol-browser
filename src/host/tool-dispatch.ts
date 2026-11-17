import type { OwnershipHost, OwnershipOperations } from './handoff.js';
import type { ProtectedDispatchPort } from '../runtime/transport.js';
import { BrowserFailure, unavailable } from '../contracts/errors.js';

export type HostToolOperation = OwnershipOperations['agent'];
export interface HostToolProviders {
  readonly inspection?: HostToolOperation;
  readonly mutation?: HostToolOperation;
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
