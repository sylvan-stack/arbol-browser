import type { Contract } from '../contracts/generated.js';
import { invalidInput } from '../contracts/errors.js';
import { classifiedRefusal } from '../content/sensitive.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import type { ActionExecution } from '../host/actions.js';
import { admitTarget, interceptInput } from './admission.js';
import { suitable } from './targets.js';
import { TrustedObservation, type KeyStroke } from './observations.js';

export async function typeTrusted(inspection: SnapshotInspection, execution: ActionExecution,
  input: Contract<'browser.TypeInput'>): Promise<Contract<'browser.ActionResult'>> {
  if (!['replace', 'append'].includes(input.mode) || Array.from(input.text).length > 10000 ||
      Buffer.byteLength(input.text, 'utf8') > 65536 || /[\u0000\uD800-\uDFFF]/u.test(input.text)) throw invalidInput();
  const target = await admitTarget(inspection, execution, input, true);
  await suitable(target, 'type');
  const classified = await inspection.fields.classify(target.frame, target.guard); target.guard();
  if (classified.aggregates.has(target.backend)) throw classifiedRefusal();
  const interception = await interceptInput(target);
  const observation = await TrustedObservation.open(target, 'browser_type', interception);
  try {
    execution.beginSequence('key'); await observation.focus();
    await observation.prepareText(input.text, input.mode);
    const strokes: KeyStroke[] = [];
    if (input.mode === 'replace') {
      const modifierDown = await observation.key('Meta', 'keyDown', 4);
      const down = await observation.key('A', 'keyDown', 4), up = await observation.key('A', 'keyUp', 4);
      const modifierUp = await observation.key('Meta', 'keyUp', 0);
      strokes.push({ key: 'A', down, up }, { key: 'Meta', down: modifierDown, up: modifierUp });
    } else {
      const down = await observation.appendSelection(), up = await observation.key('End', 'keyUp', 0);
      strokes.push({ key: 'End', down, up });
    }
    // InsertText uses native editor input. There is no value assignment,
    // clipboard route, page callback success flag or synthesized composition.
    execution.beginSequence('composition');
    const insertion = await observation.insertText(input.text);
    await observation.settleText(strokes, insertion); target.guard();
    return { tab: execution.stamp.target.id, action: execution.action!, status: 'completed',
      controlGeneration: execution.stamp.generation, navigation: execution.stamp.document.navigation,
      pageAvailability: target.frame.receipt.availability, inputReady: target.frame.receipt.ready };
  } finally { await observation.close(); }
}
