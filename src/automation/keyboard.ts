import type { Contract } from '../contracts/generated.js';
import { invalidInput } from '../contracts/errors.js';
import type { SnapshotInspection } from '../content/snapshot.js';
import type { ActionExecution } from '../host/actions.js';
import { admitTarget, interceptInput } from './admission.js';
import { suitable } from './targets.js';
import { TrustedObservation, physicalKeys, type PhysicalKey, type KeyStroke } from './observations.js';

function namedKey(value: Contract<'browser.PressKeyInput'>['key']): { key: PhysicalKey; modifier?: 'Shift' | 'Meta' } {
  if (value === 'Meta+A') return { key: 'A', modifier: 'Meta' };
  if (value.startsWith('Shift+')) {
    const key = value.slice(6);
    if (!['Tab', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(key)) throw invalidInput();
    return { key: key as PhysicalKey, modifier: 'Shift' };
  }
  if (!Object.hasOwn(physicalKeys, value) || ['A', 'Shift', 'Meta'].includes(value)) throw invalidInput();
  return { key: value as PhysicalKey };
}
export async function pressTrusted(inspection: SnapshotInspection, execution: ActionExecution,
  input: Contract<'browser.PressKeyInput'>): Promise<Contract<'browser.ActionResult'>> {
  const key = namedKey(input.key), target = await admitTarget(inspection, execution, input);
  await suitable(target, 'key'); const interception = await interceptInput(target);
  const observation = await TrustedObservation.open(target, 'browser_press_key', interception);
  try {
    execution.beginSequence('key'); await observation.focus();
    const modifiers = key.modifier === 'Shift' ? 8 : key.modifier === 'Meta' ? 4 : 0;
    const modifierDown = key.modifier ? await observation.key(key.modifier, 'keyDown', modifiers) : undefined;
    const down = await observation.key(key.key, 'keyDown', modifiers);
    const up = await observation.key(key.key, 'keyUp', modifiers);
    const strokes: KeyStroke[] = [{ key: key.key, down, up }];
    if (key.modifier && modifierDown) {
      const modifierUp = await observation.key(key.modifier, 'keyUp', 0);
      strokes.push({ key: key.modifier, down: modifierDown, up: modifierUp });
    }
    await observation.settleKeys(strokes, key.key === 'Tab'); target.guard();
    return { tab: execution.stamp.target.id, action: execution.action!, status: 'completed',
      controlGeneration: execution.stamp.generation, navigation: execution.stamp.document.navigation,
      pageAvailability: target.frame.receipt.availability, inputReady: target.frame.receipt.ready };
  } finally { await observation.close(); }
}
