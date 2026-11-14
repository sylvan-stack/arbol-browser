/** Test-free staging only. Ad hoc bootstrap seal is not production signing. No registry, selection, browser launch or gate. */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { cp, lstat, mkdir, readFile, readdir, readlink, writeFile, chmod, rename } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
export const root = fileURLToPath(new URL('../', import.meta.url));
const hash = value => createHash('sha256').update(value).digest('hex');
export async function inventory(directory, selectedRoots) {
  const files = {};
  async function walk(path) {
    for (const entry of (path === directory && selectedRoots ? selectedRoots : await readdir(path)).sort()) {
      const full = join(path, entry), stat = await lstat(full), key = relative(directory, full);
      if (stat.isSymbolicLink()) {
        const link = await readlink(full), target = resolve(dirname(full), link);
        if (!target.startsWith(`${resolve(directory)}${sep}`)) throw new Error('Escaping payload symlink');
        files[key] = hash(`symlink\0${link}`);
      } else if (stat.isDirectory()) await walk(full);
      else if (stat.isFile()) {
        const digest = createHash('sha256');
        for await (const chunk of createReadStream(full)) digest.update(chunk);
        files[key] = digest.digest('hex');
      } else throw new Error('Unsupported payload file type');
    }
  }
  await walk(directory);
  return files;
}
export async function sourceInventory() {
  const entries = {};
  for (const name of ['package.json', 'package-lock.json', 'arbol-build.json', 'tsconfig.json'])
    entries[name] = hash(await readFile(join(root, name)));
  for (const name of ['src', 'scripts'])
    for (const [path, digest] of Object.entries(await inventory(join(root, name)))) entries[`${name}/${path}`] = digest;
  return Object.fromEntries(Object.entries(entries).sort(([a], [b]) => a.localeCompare(b, 'en')));
}
export const inventoryDigest = files => hash(JSON.stringify(files));

async function stage(args) {
  if (args.length !== 4 || args[0] !== '--out' || args[2] !== '--build' ||
      !/^[1-9a-f][0-9a-f]{0,15}$/.test(args[3])) throw new Error('Usage: package-base.mjs --out <new-directory> --build <hex>');
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Only Darwin arm64 candidates are implemented');
  const out = resolve(args[1]);
  if (out === root || out.startsWith(`${root}${sep}`)) throw new Error('Candidates must be outside the checkout');
  // Never overwrite an existing candidate or a registry allocation's other files.
  const reserved = ['bin', 'lib', 'native', 'runtime', 'node_modules', 'metadata.json', 'package.json'];
  await mkdir(out, { recursive: true });
  const existing = await readdir(out);
  if (reserved.some(name => existing.includes(name))) throw new Error('Candidate payload destination already exists');
  const record = JSON.parse(await readFile(join(root, 'dist/compile-record.json'), 'utf8'));
  const sources = await sourceInventory();
  if (inventoryDigest(sources) !== record.sourceDigest ||
      inventoryDigest(await inventory(join(root, 'dist/lib'))) !== record.libraryDigest ||
      inventoryDigest(await inventory(join(root, 'dist/native'))) !== record.nativeDigest ||
      hash(await readFile(join(root, 'dist/cli/main.mjs'))) !== record.entryDigest ||
      hash(await readFile(join(root, 'dist/host/main.mjs'))) !== record.hostDigest)
    throw new Error('Sources or compiled payload changed; recompile before packaging');
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  const electron = JSON.parse(await readFile(join(root, 'node_modules/electron/package.json'), 'utf8'));
  const version = (await readFile(join(root, 'node_modules/electron/dist/version'), 'utf8')).trim().replace(/^v/, '');
  if (electron.version !== pkg.arbolBrowser.runtime.electron || version !== electron.version)
    throw new Error('Pinned prebuilt Electron is absent');
  const copy = { recursive: true, force: false, errorOnExist: true, verbatimSymlinks: true };
  await cp(join(root, 'dist/lib'), join(out, 'lib'), copy);
  await cp(join(root, 'dist/cli/main.mjs'), join(out, 'lib/cli/main.mjs'), copy);
  await cp(join(root, 'dist/host'), join(out, 'lib/host'), copy);
  await cp(join(root, 'dist/native'), join(out, 'native'), copy);
  await mkdir(join(out, 'runtime'));
  await cp(join(root, 'node_modules/electron/dist/Electron.app'), join(out, 'runtime/Electron.app'), copy);
  const host = join(out, 'runtime/ArbolBrowserHost.app');
  await mkdir(join(host, 'Contents/MacOS'), { recursive: true });
  await cp(join(root, 'dist/native/host-bootstrap'), join(host, 'Contents/MacOS/arbol-browser-host'), copy);
  await writeFile(join(host, 'Contents/Info.plist'), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.sylvan-stack.arbol-browser.host</string>
<key>CFBundleName</key><string>Arbol Browser</string>
<key>CFBundleExecutable</key><string>arbol-browser-host</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMultipleInstancesProhibited</key><false/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
`);
  const seal = spawnSync('/usr/bin/codesign', ['--force', '--sign', '-', '--options', 'runtime', host], { stdio: 'inherit' });
  if (seal.error || seal.status !== 0) throw new Error('Candidate bootstrap seal failed');
  for (const name of ['LICENSE', 'LICENSES.chromium.html'])
    await cp(join(root, 'node_modules/electron/dist', name), join(out, 'runtime', name), copy);
  const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'));
  for (const [path, entry] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b, 'en'))) {
    if (!path || entry.dev) continue;
    if (!path.startsWith('node_modules/') || path.includes('..')) throw new Error('Unsafe dependency path');
    await cp(join(root, path), join(out, path), copy);
  }
  await writeFile(join(out, 'package.json'), JSON.stringify({ name: pkg.name, version: pkg.version, bin: pkg.bin, type: 'module', private: true }) + '\n');
  await mkdir(join(out, 'bin'));
  await writeFile(join(out, 'bin/arbol-browser'), `#!/bin/sh
set -eu
candidate_root=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/.." && pwd)
exec /usr/bin/env -u NODE_OPTIONS -u NODE_PATH -u ELECTRON_EXTRA_LAUNCH_ARGS -u ELECTRON_OVERRIDE_DIST_PATH ELECTRON_RUN_AS_NODE=1 "$candidate_root/runtime/Electron.app/Contents/MacOS/Electron" "$candidate_root/lib/cli/main.mjs" "$@"
`);
  await chmod(join(out, 'bin/arbol-browser'), 0o755);
  // No time, absolute source path or random identity: deterministic content inventory.
  const metadata = {
    format: 1,
    component: { name: 'arbol-browser', version: pkg.version, build: args[3],
      contract: pkg.arbolBrowser.contract, profileFormat: pkg.arbolBrowser.profileFormat },
    runtime: pkg.arbolBrowser.runtime, admission: 'blocked', nativeInput: false, watchdog: false,
    sourceDigest: record.sourceDigest, files: await inventory(out, reserved.filter(name => name !== 'metadata.json')),
  };
  await writeFile(join(out, 'metadata.json.tmp'), JSON.stringify(metadata, null, 2) + '\n');
  await rename(join(out, 'metadata.json.tmp'), join(out, 'metadata.json'));
  console.log(JSON.stringify({ candidate: out, sourceDigest: record.sourceDigest,
    payloadDigest: inventoryDigest(metadata.files), admission: 'blocked', qualification: 'unexecuted' }));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await stage(process.argv.slice(2));
