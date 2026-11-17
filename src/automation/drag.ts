import type { Contract } from '../contracts/generated.js';
import { BrowserFailure } from '../contracts/errors.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import type { ActionExecution } from '../host/actions.js';
import type { ActionDragData } from '../host/readiness.js';
import { staleSnapshot } from '../host/authority.js';
import { classifiedRefusal } from '../content/sensitive.js';
import { admitTarget, interceptInput } from './admission.js';
import { hitPoint, suitable } from './targets.js';
import { TrustedObservation } from './observations.js';
import { agentURL } from './navigation.js';

function permittedPayload(data: ActionDragData, previous: string): void {
  const refuse = () => { throw new BrowserFailure({ code: 'unsupported', message: 'This drag payload is outside the browser contract.',
    retryable: false, remedy: 'Use Take control for this drag.' }); };
  if (!data.items.length || data.items.length > 16 || !data.dragOperationsMask || (data.dragOperationsMask & ~19)) refuse();
  let bytes = 0;
  for (const item of data.items) {
    if (!['text/plain', 'text/html', 'text/uri-list'].includes(item.mimeType) ||
        (bytes += Buffer.byteLength(item.data, 'utf8') + Buffer.byteLength(item.title ?? '', 'utf8') + Buffer.byteLength(item.baseURL ?? '', 'utf8')) > 65536) refuse();
    if (item.baseURL) agentURL(item.baseURL, previous);
    if (item.mimeType === 'text/uri-list') {
      const addresses = item.data.split(/\r?\n/).filter(value => value && !value.startsWith('#'));
      if (addresses.length > 16) refuse(); for (const address of addresses) agentURL(address, previous);
    }
  }
}
export async function dragTrusted(inspection: SnapshotInspection, execution: ActionExecution,
  input: Contract<'browser.DragInput'>): Promise<Contract<'browser.ActionResult'>> {
  const source = await admitTarget(inspection, execution, { ...input, ref: input.source });
  const destination = await admitTarget(inspection, execution, { ...input, ref: input.destination });
  if (source.frame.receipt !== destination.frame.receipt || source.frame.physical !== destination.frame.physical ||
      source.frame.frameId !== destination.frame.frameId || source.frame.session !== destination.frame.session) throw staleSnapshot();
  await suitable(source, 'drag'); await suitable(destination, 'drag');
  const classified = await inspection.fields.classify(source.frame, source.guard); source.guard(); destination.guard();
  if (classified.aggregates.has(source.backend) || classified.aggregates.has(destination.backend)) throw classifiedRefusal();
  const interception = await interceptInput(source);
  const observation = await TrustedObservation.open(source, 'browser_drag', interception, destination);
  try {
    await source.revalidate(); await destination.revalidate(); observation.guard();
    const kind = await observation.dragKind();
    const from = await hitPoint(source); observation.guard();
    execution.beginSequence('pointer'); execution.beginSequence('drag');
    const press = await observation.mouse('mousePressed', from);
    const to = await observation.dragPoint(); observation.guard();
    const move = await observation.mouse('mouseMoved', to);
    let drop;
    if (kind === 'html') {
      const data = await observation.interceptedDrag(move);
      permittedPayload(data, inspection.documents.lastSafeURL(execution.stamp.target)); observation.guard();
      await observation.drag('dragEnter', await observation.dragPoint(), data);
      await observation.drag('dragOver', await observation.dragPoint(), data);
      drop = await observation.drag('drop', await observation.dragPoint(), data);
    } else await observation.assertPointerDrag(move);
    // The normal requested final release only; no error/Take cleanup input.
    const release = await observation.mouse('mouseReleased', await observation.dragPoint());
    await observation.settleDrag(press, move, release, drop); source.guard(); destination.guard();
    return { tab: execution.stamp.target.id, action: execution.action!, status: 'completed',
      controlGeneration: execution.stamp.generation, navigation: execution.stamp.document.navigation,
      pageAvailability: source.frame.receipt.availability, inputReady: source.frame.receipt.ready };
  } finally { await observation.close(); }
}
