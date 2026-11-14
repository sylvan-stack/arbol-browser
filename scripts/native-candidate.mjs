/** Isolated static candidate staging only. No runtime execution or Build gate. */
import { cp, mkdir, readFile, writeFile, lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { root, inventory, inventoryDigest, sourceInventory } from './package-base.mjs';
import { validateNativeCompilation } from './compile-native.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const candidateQualification = 'unqualified:ABR-6-static-only';
export const policy = JSON.parse(await readFile(join(root, 'native/publisher-requirement.json'), 'utf8'));
const runtime = { electron: '45.3.2', chromium: '156.0.8078.100', node: '24.22.2', napi: '10', modules: '150', platform: 'darwin', arch: 'arm64', macOS: '27.0.1' };
const foundation = '/Users/msix/Builds/sylvan-stack/arbol-browser/ABR-32-20261114/registry/arbol-browser/1';
const canonical = value => JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b, 'en'))));
function infoPlist() { return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${policy.bundleIdentifier}</string><key>CFBundleName</key><string>Arbol Browser Native Candidate</string><key>CFBundleExecutable</key><string>arbol-browser-native</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>6</string><key>LSMinimumSystemVersion</key><string>27.0.1</string></dict></plist>\n`; }
async function currentCompilation() {
  const compiled = JSON.parse(await readFile(join(root, 'dist/compile-record.json'), 'utf8'));
  if (inventoryDigest(await sourceInventory()) !== compiled.sourceDigest ||
      inventoryDigest(await inventory(join(root, 'dist/lib'))) !== compiled.libraryDigest ||
      inventoryDigest(await inventory(join(root, 'dist/native'))) !== compiled.nativeDigest) throw new Error('Native staging requires fresh test-free compilation');
  await validateNativeCompilation();
  return compiled;
}
async function expectedUnsignedFiles() {
  const raw = await readFile(join(foundation, 'metadata.json'));
  if (hash(raw) !== '75e592cd773a7b3cdb300af827b4d5971331fe489941cadeddb58e09aaef9bec') throw new Error('Foundation metadata changed');
  const metadata = JSON.parse(raw), files = {};
  for (const [name, digest] of Object.entries(metadata.files)) files[`Contents/Resources/browser/${name}`] = digest;
  files['Contents/Resources/browser/metadata.json'] = hash(raw);
  const bootstrap = hash(await readFile(join(root, 'dist/native/host-bootstrap')));
  for (const name of ['native/host-bootstrap', 'runtime/ArbolBrowserHost.app/Contents/MacOS/arbol-browser-host']) files[`Contents/Resources/browser/${name}`] = bootstrap;
  for (const [name, digest] of Object.entries(await inventory(join(root, 'dist/lib/native')))) files[`Contents/Resources/browser/lib/native/${name}`] = digest;
  for (const name of ['ownership.node', 'ownership-compile.json']) files[`Contents/Resources/browser/native/${name}`] = hash(await readFile(join(root, 'dist/native', name)));
  files['Contents/MacOS/arbol-browser-native'] = bootstrap;
  files['Contents/Info.plist'] = hash(infoPlist());
  files['Contents/Resources/publisher-requirement.json'] = hash(JSON.stringify(policy, null, 2) + '\n');
  return files;
}
/** The unsigned record is checked against independent immutable predecessor and
 * current compiled inputs; editing the record cannot authorize different bytes. */
export async function assertStagedSource(bundle, unsigned = false) {
  const staged = JSON.parse(await readFile(join(bundle, 'Contents/Resources/native-staging.json'), 'utf8'));
  const compiled = await currentCompilation();
  if (Object.keys(staged).sort().join(',') !== 'compileRecordDigest,files,format,nativeCompilationDigest,sourceDigest' || staged.format !== 1 ||
      staged.sourceDigest !== compiled.sourceDigest || staged.compileRecordDigest !== hash(await readFile(join(root, 'dist/compile-record.json'))) ||
      staged.nativeCompilationDigest !== hash(await readFile(join(root, 'dist/native/ownership-compile.json'))) ||
      canonical(staged.files) !== canonical(await expectedUnsignedFiles())) throw new Error('Staged source identity differs; retain candidate and stage a new one');
  if (unsigned) {
    const actual = await inventory(bundle);
    delete actual['Contents/Resources/native-staging.json'];
    delete actual['Contents/Resources/native-compatibility.json'];
    if (canonical(actual) !== canonical(staged.files)) throw new Error('Unsigned staged bytes changed');
  }
  return staged;
}
export async function writeCompatibility(bundle) {
  const staged = await assertStagedSource(bundle);
  const files = Object.fromEntries(Object.entries(await inventory(join(bundle, 'Contents/Resources/browser'))).map(([path, digest]) => [`Contents/Resources/browser/${path}`, digest]));
  const manifest = { abi: 1, runtime, nativeABI: JSON.parse(await readFile(join(root, 'native/expected-inventory.json'), 'utf8')),
    publisherTeam: policy.team, bundleIdentifier: policy.bundleIdentifier,
    featureConfiguration: { sitePerProcess: true, disabledFeatures: ['MacAccessibilityTextOperation'], extraChromiumArguments: [] },
    files, dataEpoch: 1, compatibleReaderKeys: ['candidate-unqualified'], writerKey: 'candidate-unqualified', readableDataEpochs: [1],
    qualification: `${candidateQualification};source=${staged.sourceDigest}` };
  const raw = JSON.stringify(manifest, null, 2) + '\n';
  if (Buffer.byteLength(raw) > 1048576 || Object.keys(files).length > 4096) throw new Error('Native manifest bound exceeded');
  await writeFile(join(bundle, 'Contents/Resources/native-compatibility.json'), raw);
  return manifest;
}
export async function stageNativeCandidate(out) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('Only Darwin arm64 is supported');
  const bundle = resolve(out);
  if (!bundle.endsWith('.app') || bundle.startsWith(root + sep) || bundle.startsWith('/Users/msix/Artifacts/')) throw new Error('Use a new isolated .app outside checkout/corpus');
  const prior = await lstat(bundle).catch(error => { if (error.code !== 'ENOENT') throw error; });
  if (prior) throw new Error('Never overwrite an existing candidate');
  const metadataRaw = await readFile(join(foundation, 'metadata.json'));
  if (hash(metadataRaw) !== '75e592cd773a7b3cdb300af827b4d5971331fe489941cadeddb58e09aaef9bec') throw new Error('Foundation metadata changed');
  const metadata = JSON.parse(metadataRaw);
  const roots = [...new Set(Object.keys(metadata.files).map(path => path.split('/')[0]))].sort();
  if (inventoryDigest(await inventory(foundation, roots)) !== 'd16ce228df322d957b1065008509a4ea26f9321650bd391ce3ca174927351929') throw new Error('Immutable Foundation payload changed');
  const compiled = await currentCompilation();
  const payload = join(bundle, 'Contents/Resources/browser');
  await mkdir(payload, { recursive: true });
  const copy = { recursive: true, force: false, errorOnExist: true, verbatimSymlinks: true };
  for (const name of [...roots, 'metadata.json']) await cp(join(foundation, name), join(payload, name), copy);
  await cp(join(root, 'dist/lib/native'), join(payload, 'lib/native'), copy);
  for (const name of ['ownership.node', 'ownership-compile.json']) await cp(join(root, 'dist/native', name), join(payload, 'native', name), copy);
  // Replace only these explicitly new bootstrap bytes. No Foundation evidence is
  // promoted to evidence for this newly signed candidate.
  for (const destination of ['native/host-bootstrap', 'runtime/ArbolBrowserHost.app/Contents/MacOS/arbol-browser-host'])
    await cp(join(root, 'dist/native/host-bootstrap'), join(payload, destination), { force: true });
  await mkdir(join(bundle, 'Contents/MacOS'));
  await cp(join(root, 'dist/native/host-bootstrap'), join(bundle, 'Contents/MacOS/arbol-browser-native'));
  await writeFile(join(bundle, 'Contents/Resources/publisher-requirement.json'), JSON.stringify(policy, null, 2) + '\n');
  await writeFile(join(bundle, 'Contents/Info.plist'), infoPlist());
  const staged = { format: 1, sourceDigest: compiled.sourceDigest,
    compileRecordDigest: hash(await readFile(join(root, 'dist/compile-record.json'))),
    nativeCompilationDigest: hash(await readFile(join(root, 'dist/native/ownership-compile.json'))), files: await expectedUnsignedFiles() };
  await writeFile(join(bundle, 'Contents/Resources/native-staging.json'), JSON.stringify(staged, null, 2) + '\n', { flag: 'wx' });
  await assertStagedSource(bundle, true);
  const manifest = await writeCompatibility(bundle);
  console.log(JSON.stringify({ candidate: bundle, foundation, sourceDigest: compiled.sourceDigest,
    manifestDigest: hash(await readFile(join(bundle, 'Contents/Resources/native-compatibility.json'))), files: Object.keys(manifest.files).length,
    admission: 'blocked', watchdog: 'not-yet-implemented; ABR-7 stages its real signed helper', qualification: 'unexecuted' }));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4 || process.argv[2] !== '--out') throw new Error('Usage: native-candidate.mjs --out <new-isolated.app>');
  await stageNativeCandidate(process.argv[3]);
}
