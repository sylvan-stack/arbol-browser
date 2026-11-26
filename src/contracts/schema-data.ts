import browser from './browser.schema.json' with { type: 'json' };
import wire from './wire.schema.json' with { type: 'json' };
import profile from './profile.schema.json' with { type: 'json' };
import profile2 from './profile-format-2.schema.json' with { type: 'json' };
import migration from './migration.schema.json' with { type: 'json' };
import native from './native.schema.json' with { type: 'json' };
type Schema = Record<string, any>; // JSON Schema is recursive, not application input.
export const bundles = { browser, wire, profile, native, profile2, migration };
export type Bundle = keyof typeof bundles;
const byId = new Map<string, Schema>(Object.values(bundles).map(b => [b.$id, b]));
const prefix = new Map(Object.entries(bundles).map(([name, b]) => [b.$id, name]));

function resolve(ref: string): Schema {
  const [id, path] = ref.split('#');
  const bundle = byId.get(id!);
  if (!bundle || !path?.startsWith('/$defs/')) throw new Error('Unknown contract reference');
  const definition = bundle.$defs[path.slice(7)];
  if (!definition) throw new Error('Unknown contract definition');
  return definition;
}

function publicRoot(refs: string[]): Schema {
  const definitions: Record<string, Schema> = {};
  const names = new Map<string, string>();
  function copy(value: any): any {
    if (Array.isArray(value)) return value.map(copy);
    if (!value || typeof value !== 'object') return value;
    if (typeof value.$ref === 'string') {
      const ref = value.$ref as string;
      if (!ref.startsWith(`${browser.$id}#/$defs/`) || /#\/\$defs\/Shell/.test(ref)) {
        throw new Error('Private definition in public schema');
      }
      if (!names.has(ref)) {
        const local = `d${names.size}`;
        names.set(ref, local);
        definitions[local] = copy(resolve(ref));
      }
      return { $ref: `#/$defs/${names.get(ref)}` };
    }
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, copy(entry)]));
  }
  const roots = refs.map(ref => copy(resolve(ref)));
  return { $schema: browser.$schema, type: 'object', ...(roots.length === 1 ? roots[0] : { anyOf: roots }),
    ...(names.size ? { $defs: definitions } : {}) };
}

/** Only these self-contained schemas cross tools/list; no shell/native bundle. */
export const agentToolSchemas = Object.entries(browser['x-tools']).map(([name, tool]) => ({
  name,
  inputSchema: publicRoot([tool.input.$ref]),
  outputSchema: publicRoot([tool.success.$ref, tool.failure.$ref]),
  annotations: { readOnlyHint: tool.readOnlyHint, idempotentHint: tool.idempotentHint,
    destructiveHint: !tool.readOnlyHint, openWorldHint: true },
}));

/** Select the outstanding method, including private screenshot transport; a
 * generic success union cannot validate a correlated tool reply. */
export type AgentToolName = keyof typeof browser['x-tools'];

/** Project canonical tool input and success separately for the direct CLI. */
export function agentDescriptionSchemas() {
  const names = Object.keys(browser['x-tools']) as AgentToolName[];
  return names.map(name => {
    const tool = browser['x-tools'][name];
    const inputSchema = publicRoot([tool.input.$ref]);
    const resultSchema = publicRoot([tool.success.$ref]);
    if (inputSchema.type !== 'object' || resultSchema.type !== 'object')
      throw new Error('Browser tool discovery requires object root schemas');
    return { name, inputSchema, resultSchema };
  });
}

/** TypeScript shapes are generated from the same assets used by runtime validators.
 * Numeric/string bounds and conditional requirements remain runtime obligations. */
export function generatedTypes(): string {
  function type(schema: Schema | boolean): string {
    if (typeof schema === 'boolean') return schema ? 'unknown' : 'never';
    if (schema.$ref) {
      resolve(schema.$ref);
      const [id, path] = schema.$ref.split('#');
      return `ContractTypes[${JSON.stringify(`${prefix.get(id)}.${path.slice(7)}`)}]`;
    }
    if ('const' in schema) return JSON.stringify(schema.const);
    if (schema.enum) return schema.enum.map((v: unknown) => JSON.stringify(v)).join(' | ');
    if (schema.oneOf || schema.anyOf) return `(${(schema.oneOf ?? schema.anyOf).map(type).join(' | ')})`;
    if (schema.type === 'array') return `Array<${type(schema.items ?? true)}>`;
    if (schema.type === 'object') {
      const fields = Object.entries(schema.properties ?? {}).map(([name, value]) =>
        `${JSON.stringify(name)}${schema.required?.includes(name) ? '' : '?'}: ${type(value as Schema)};`);
      if (schema.additionalProperties && !Object.keys(schema.properties ?? {}).length)
        fields.push(`[key: string]: ${type(schema.additionalProperties)};`);
      return fields.length ? `{ ${fields.join(' ')} }` : 'Record<string, never>';
    }
    if (schema.type === 'integer' || schema.type === 'number') return 'number';
    if (schema.type === 'null') return 'null';
    if (schema.type === 'string' || schema.type === 'boolean') return schema.type;
    throw new Error('Unsupported schema shape in type generation');
  }
  const lines = Object.entries(bundles).flatMap(([bundle, schema]) => Object.entries(schema.$defs).map(
    ([name, definition]) => `  ${JSON.stringify(`${bundle}.${name}`)}: ${type(definition)};`));
  return '// Generated from the checked schema assets by schema.ts. Do not edit.\n' +
    '// Conditional requirements and value constraints are enforced by validator().\n' +
    `export interface ContractTypes {\n${lines.join('\n')}\n}\n` +
    'export type Contract<K extends keyof ContractTypes> = ContractTypes[K];\n';
}
