import type { Contract } from '../contracts/generated.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import type { ActionExecution } from '../host/actions.js';
import { admitTarget, interceptInput } from './admission.js';
import { hitPoint, suitable } from './targets.js';
import { TrustedObservation } from './observations.js';

export async function clickTrusted(inspection: SnapshotInspection, execution: ActionExecution,
  input: Contract<'browser.ClickInput'>): Promise<Contract<'browser.ActionResult'>> {
  const target = await admitTarget(inspection, execution, input);
  await suitable(target, 'click');
  const interception = await interceptInput(target);
  const observation = await TrustedObservation.open(target, 'browser_click', interception);
  try {
    await suitable(target, 'click'); const point = await hitPoint(target); observation.guard();
    execution.beginSequence('pointer');
    const press = await observation.mouse('mousePressed', point);
    // This is the requested balanced click, never a catch/finally release.
    const release = await observation.mouse('mouseReleased', point);
    await observation.settleClick(press, release); target.guard();
    return { tab: execution.stamp.target.id, action: execution.action!, status: 'completed',
      controlGeneration: execution.stamp.generation, navigation: execution.stamp.document.navigation,
      pageAvailability: target.frame.receipt.availability, inputReady: target.frame.receipt.ready };
  } finally { await observation.close(); }
}
