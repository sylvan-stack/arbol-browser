/** Timestamped Developer ID signing only in a newly staged isolated candidate.
 * No runtime launch, notarization, installation, registry selection or key export. */
import { spawnSync } from 'node:child_process';
import { lstat, readFile, readdir, writeFile, realpath } from 'node:fs/promises';
import { resolve, join, relative, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { root, inventoryDigest } from './package-base.mjs';
import { policy, candidateQualification, writeCompatibility, assertStagedSource } from './native-candidate.mjs';
const identity = 'F1B6782A3BACC18E73FE08CA424C0A81450A982C';
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--candidate') throw new Error('Usage: sign-candidate.mjs --candidate <new-isolated.app>');
const bundle = resolve(args[1]);
if (!bundle.endsWith('.app') || bundle.startsWith(root + sep) || bundle.startsWith('/Users/msix/Artifacts/') ||
    await realpath(bundle) !== bundle) throw new Error('Signing requires the isolated real candidate');
const staged = await assertStagedSource(bundle, true);
const original = JSON.parse(await readFile(join(bundle, 'Contents/Resources/native-compatibility.json'), 'utf8'));
if (original.qualification !== `${candidateQualification};source=${staged.sourceDigest}` || original.publisherTeam !== policy.team || original.bundleIdentifier !== policy.bundleIdentifier)
  throw new Error('Not an unqualified native candidate');
if (await lstat(join(bundle, 'Contents/_CodeSignature')).catch(error => { if (error.code !== 'ENOENT') throw error; })) throw new Error('Outer candidate already signed; retain it and stage a fresh attempt');
await writeFile(bundle + '.signing-attempt.json', JSON.stringify({ candidate: bundle, qualification: 'unexecuted' }) + '\n', { flag: 'wx', mode: 0o600 });
function command(executable, argv, input) {
  const result = spawnSync(executable, argv, { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' }, timeout: 120000, maxBuffer: 1048576, ...(input === undefined ? {} : { input }) });
  if (result.error || result.status !== 0) throw new Error(`Candidate signature operation failed: ${result.stderr}`);
  return result;
}
const leaves = [], bundles = [];
async function walk(directory) {
  for (const name of (await readdir(directory)).sort()) {
    const path = join(directory, name), stat = await lstat(path);
    if (stat.isSymbolicLink()) {
      if (!(await realpath(path)).startsWith(bundle + sep)) throw new Error('Escaping signed symlink');
    } else if (stat.isDirectory()) {
      await walk(path);
      if (/\.(app|framework|xpc)$/.test(path)) bundles.push(path);
    } else if (stat.isFile()) {
      const magic = (await readFile(path)).subarray(0, 4).toString('hex');
      if (['cffaedfe', 'cefaedfe', 'feedfacf', 'cafebabe', 'bebafeca'].includes(magic) && path !== join(bundle, 'Contents/MacOS/arbol-browser-native')) leaves.push(path);
    } else throw new Error('Unsupported signed object');
  }
}
await walk(bundle);
const electron = join(bundle, 'Contents/Resources/browser/runtime/Electron.app');
function jitAllowed(path) {
  return path === electron || (path.startsWith(electron + sep) && (path.includes('/Contents/MacOS/') || path.endsWith('.app')));
}
function sign(path) {
  command('/usr/bin/codesign', ['--force', '--sign', identity, '--options', 'runtime', '--timestamp',
    ...(jitAllowed(path) ? ['--entitlements', join(root, 'entitlements.plist')] : []), path]);
  console.log(`Signed ${relative(bundle, path) || '.'}`);
}
for (const path of leaves.sort((a, b) => b.split(sep).length - a.split(sep).length)) sign(path);
for (const path of bundles.sort((a, b) => b.split(sep).length - a.split(sep).length)) sign(path);
// Nested signatures are now final; bind their exact bytes/resources before the
// outer seal. This avoids self-referential hashes of the outer signature.
const manifest = await writeCompatibility(bundle);
sign(bundle);
const audit = [];
for (const path of [...leaves, ...bundles, join(bundle, 'Contents/MacOS/arbol-browser-native'), bundle]) {
  const requirement = policy.requirement + (path === bundle ? ` and identifier "${policy.bundleIdentifier}"` : '');
  command('/usr/bin/codesign', ['--verify', '--strict', ...(path === bundle ? ['--deep'] : []), '-R', `=${requirement}`, path]);
  const details = command('/usr/bin/codesign', ['-dvvv', path]).stderr;
  if (!details.includes(`TeamIdentifier=${policy.team}`) || !details.includes('runtime)') || !details.includes('Timestamp=')) throw new Error('Publisher/hardened runtime/timestamp mismatch');
  const xml = command('/usr/bin/codesign', ['-d', '--entitlements', '-', '--xml', path]).stdout;
  const entitlements = xml.trim() ? JSON.parse(command('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '-'], xml).stdout) : {};
  for (const [key, value] of Object.entries(entitlements)) if (key !== 'com.apple.security.cs.allow-jit' || value !== true || !jitAllowed(path)) throw new Error('Forbidden native entitlement');
  if (jitAllowed(path) && entitlements['com.apple.security.cs.allow-jit'] !== true) throw new Error('Electron JIT entitlement absent');
  audit.push({ path: relative(bundle, path) || '.', team: policy.team, hardenedRuntime: true, timestamped: true, entitlements });
}
await assertStagedSource(bundle);
const manifestRaw = await readFile(join(bundle, 'Contents/Resources/native-compatibility.json'));
await writeFile(bundle + '.signature-audit.json', JSON.stringify({ candidate: bundle, publisher: policy,
  objects: audit, files: Object.keys(manifest.files).length, payloadDigest: inventoryDigest(manifest.files),
  manifestDigest: createHash('sha256').update(manifestRaw).digest('hex'), qualification: 'unexecuted',
  unavailable: ['watchdog until ABR-7', 'native runtime/route/full-key/rollback/watchdog qualification until ABR-8', 'complete production host until ABR-29', 'notarization/Gatekeeper/distribution until ABR-25'] }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
console.log(JSON.stringify({ candidate: bundle, signedObjects: audit.length, libraryValidationDisabled: false, qualification: 'unexecuted' }));
