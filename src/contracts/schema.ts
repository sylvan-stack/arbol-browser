/** BRW-0.2 / BRW-0.10. Shape checks confer no attachment or page authority. */
import type { ValidateFunction } from 'ajv/dist/2020.js';
import type { ContractTypes } from './generated.js';
import { bundles, type Bundle, type AgentToolName } from './schema-data.js';
import validators from './validators.cjs';

export { agentDescriptionSchemas, agentToolSchemas, bundles, generatedTypes } from './schema-data.js';
export type { AgentToolName, Bundle } from './schema-data.js';

function compiledValidator<T>(reference: string): ValidateFunction<T> {
  if (!Object.hasOwn(validators, reference)) throw new Error('Unknown contract type');
  const validate = validators[reference];
  if (!validate) throw new Error('Unknown contract type');
  return validate as ValidateFunction<T>;
}

/** Select the exact named root from the signed build's compiled contracts. */
export function validator<K extends keyof ContractTypes>(name: K): ValidateFunction<ContractTypes[K]> {
  const [bundle, definition] = name.split('.');
  const schema = bundles[bundle as Bundle];
  if (!schema || !Object.hasOwn(schema.$defs, definition!)) throw new Error('Unknown contract type');
  return compiledValidator(`${schema.$id}#/$defs/${definition}`);
}

/** Build-specific administrative replies; the wire bundle advertises both
 * historical and current formats, while this Build emits only profile2. */
export const managementResults = Object.freeze({ info: 'profile2.ComponentInfo',
  list: 'profile2.ProfileList', create: 'profile2.ProfileCreated', remove: 'profile2.ProfileRemoved' } as const);

/** Select the outstanding method, including private screenshot transport. */
export function agentToolValidator(name: AgentToolName, direction: 'input' | 'success' | 'wireSuccess'): ValidateFunction {
  const { browser } = bundles;
  const ref = direction === 'wireSuccess' && name === 'browser_screenshot'
    ? `${browser.$id}#/$defs/ScreenshotPayload`
    : browser['x-tools'][name][direction === 'input' ? 'input' : 'success'].$ref;
  return compiledValidator(ref);
}
