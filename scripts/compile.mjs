/** Static/schema/TypeScript/native compilation only. Never invokes tests or a gate. */
import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { root, inventory, inventoryDigest, sourceInventory } from './package-base.mjs';
if (process.argv.length > 2) throw new Error('compile.mjs accepts no arguments');
const sources = await sourceInventory();
function run(args) {
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit' });
  if (result.error || result.status !== 0) throw new Error('Static compilation failed');
}
await mkdir(join(root, 'build'), { recursive: true });
const generator = join(root, 'build/contracts-generator.mjs');
await build({ entryPoints: [join(root, 'src/contracts/schema.ts')], outfile: generator,
  bundle: true, platform: 'node', format: 'esm', packages: 'external' });
const contracts = await import(generator);
if (await readFile(join(root, 'src/contracts/generated.ts'), 'utf8') !== contracts.generatedTypes())
  throw new Error('Generated contract types are stale; regenerate under a contract Intention');
const count = contracts.compileContracts();
const ajv = new Ajv2020({ strict: true, strictRequired: false, strictTypes: false });
addFormats(ajv);
for (const tool of contracts.agentToolSchemas) {
  ajv.compile(tool.inputSchema); ajv.compile(tool.outputSchema);
}
console.log(`Compiled ${count} named contract roots and ${contracts.agentToolSchemas.length * 2} public schema roots`);
run(['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json']);
run(['scripts/compile-platform.mjs']);
await build({ entryPoints: [join(root, 'src/cli/main.ts')], outfile: join(root, 'dist/cli/main.mjs'),
  bundle: true, platform: 'node', format: 'esm', target: 'node24.22.2',
  banner: { js: "import { createRequire as bundledCreateRequire } from 'node:module'; const require = bundledCreateRequire(import.meta.url);" } });
await build({ entryPoints: [join(root, 'src/runtime/host-entry.ts')], outfile: join(root, 'dist/host/main.mjs'),
  bundle: true, platform: 'node', format: 'esm', target: 'node24.22.2', external: ['electron'],
  banner: { js: "import { createRequire as bundledCreateRequire } from 'node:module'; const require = bundledCreateRequire(import.meta.url);" } });
if (inventoryDigest(await sourceInventory()) !== inventoryDigest(sources)) throw new Error('Source changed during compilation');
const record = { sourceDigest: inventoryDigest(sources), sources,
  libraryDigest: inventoryDigest(await inventory(join(root, 'dist/lib'))),
  nativeDigest: inventoryDigest(await inventory(join(root, 'dist/native'))),
  hostDigest: createHash('sha256').update(await readFile(join(root, 'dist/host/main.mjs'))).digest('hex'),
  entryDigest: createHash('sha256').update(await readFile(join(root, 'dist/cli/main.mjs'))).digest('hex') };
await writeFile(join(root, 'dist/compile-record.json'), JSON.stringify(record, null, 2) + '\n');
console.log(`Compiled candidate sources ${record.sourceDigest}; qualification remains unexecuted`);
