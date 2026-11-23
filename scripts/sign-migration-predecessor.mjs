/** Reviewed historical packaging adapter. No compilation, fixture runner or
 * synthetic custody. Importing never stages, signs or executes a product. */
import { cp, lstat, writeFile, readdir, chmod } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventory, inventoryDigest } from './package-base.mjs';
import { profileMigrationPredecessor, assertHostIsolation, maintenanceFixtureLayout, privateDirectory,
  currentHostCompilation, acceptedHostProduct, exactFile, hash, canonical, writeExclusive, command, hostLauncher,
  assertPhysicalCap } from './package-host.mjs';
import { withVerifiedMigrationPredecessor } from './install-release.mjs';
import { signBundle } from './sign.mjs';
import publisher from '../native/publisher-requirement.json' with { type: 'json' };
const identity = 'F1B6782A3BACC18E73FE08CA424C0A81450A982C';
const refuse = () => { throw new Error('Exact historical predecessor staging refused; preserve this attempt'); };
const equal = (a, b) => canonical(a) === canonical(b);
/** The AFM-9 isolated grant authenticates this current adapter separately from
 * the frozen original product authenticated by its signed image and pins. */
export async function signMigrationPredecessor({ out, buildRoot, stateRoot, image, signedReceiptPath, review }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || resolve(out) !== out || !out.endsWith('/ArbolBrowser.app')) refuse();
  await assertHostIsolation(buildRoot, stateRoot, out); await privateDirectory(dirname(out), true);
  const fixture = await maintenanceFixtureLayout(buildRoot, stateRoot), pinned = profileMigrationPredecessor;
  if (!fixture || fixture.build !== pinned.build) refuse();
  try { await lstat(out); refuse(); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const compiled = await currentHostCompilation(), accepted = await acceptedHostProduct(review, compiled);
  const original = await withVerifiedMigrationPredecessor({ image, signedReceiptPath }, async source => {
    await cp(source.app, out, { recursive: true, force: false, errorOnExist: true, verbatimSymlinks: true });
    if (!equal(await inventory(out), source.files)) refuse();
    return source;
  });
  await chmod(out, 0o700);
  const resources = join(out, 'Contents/Resources'), payload = join(resources, 'browser');
  const mutable = new Set(['Contents/Info.plist', 'Contents/Resources/publisher-requirement.json',
    'Contents/Resources/browser/metadata.json', 'Contents/Resources/native-compatibility.json',
    'Contents/Resources/host-policy.json', 'Contents/Resources/browser/bin/arbol-browser']);
  command('/usr/bin/plutil', ['-replace', 'CFBundleIdentifier', '-string', publisher.bundleIdentifier, join(out, 'Contents/Info.plist')]);
  await writeFile(join(resources, 'publisher-requirement.json'), JSON.stringify(publisher, null, 2) + '\n', { mode: 0o600 });
  await writeFile(join(payload, 'bin/arbol-browser'), hostLauncher('..'), { mode: 0o755 });
  await writeExclusive(out + '.historical-signing-attempt.json', JSON.stringify({ format: 1, kind: 'historical-isolated-adapter',
    original: pinned, receiptSha256: original.receiptSha256, adapterSource: compiled.sourceIdentity,
    adapterProductDigest: compiled.record.productDigest, reviewHandover: review, reviewDigest: accepted.digest,
    fixture, qualification: 'unexecuted' }, null, 2) + '\n');
  const readerKey = `host-isolated:1:${pinned.productDigest}`;
  async function refresh() {
    if (!equal(await maintenanceFixtureLayout(buildRoot, stateRoot), fixture)) refuse();
    const metadata = { ...original.metadata,
      files: await inventory(payload, (await readdir(payload)).filter(name => name !== 'metadata.json')) };
    await writeFile(join(payload, 'metadata.json'), JSON.stringify(metadata, null, 2) + '\n', { mode: 0o600 });
    const compatibility = { ...original.compatibility, publisherTeam: publisher.team, bundleIdentifier: publisher.bundleIdentifier,
      files: Object.fromEntries(Object.entries(await inventory(payload)).map(([p, d]) => [`Contents/Resources/browser/${p}`, d])),
      compatibleReaderKeys: [readerKey], writerKey: readerKey, qualification: readerKey };
    const bytes = JSON.stringify(compatibility, null, 2) + '\n';
    if (Buffer.byteLength(bytes) > 1048576 || Object.keys(compatibility.files).length > 4096) refuse();
    await writeFile(join(resources, 'native-compatibility.json'), bytes, { mode: 0o600 });
    const policy = { ...original.policy, purpose: 'isolated-qualification', buildRoot, stateRoot,
      metadataDigest: (await exactFile(join(payload, 'metadata.json'))).sha256,
      compatibilityDigest: hash(bytes), reviewDigest: accepted.digest,
      qualificationDigest: hash(canonical({ kind: 'historical-isolated-adapter', fixture, original: pinned,
        adapter: accepted.digest, adapterSource: compiled.sourceIdentity, originalReceiptSha256: original.receiptSha256 })),
      readerKey, readableReaderKeys: [readerKey] };
    await writeFile(join(resources, 'host-policy.json'), JSON.stringify(policy, null, 2) + '\n', { mode: 0o600 });
    return { metadata, compatibility, policy };
  }
  await refresh();
  const signatureResource = name => /(?:^|\/)_CodeSignature\/CodeResources$/.test(name);
  async function unchanged() {
    const files = await inventory(out);
    for (const [name, digest] of Object.entries(original.files))
      if (!mutable.has(name) && !signatureResource(name) && files[name] !== digest) refuse();
    for (const name of Object.keys(files)) if (!(name in original.files) && !signatureResource(name)) refuse();
    return files;
  }
  await unchanged(); await assertPhysicalCap(out);
  const { records, audit } = await signBundle({ bundle: out, identity, publisher, async sealResources(signedCode) {
    for (const name of signedCode) mutable.add(name);
    const records = await refresh(); await unchanged(); await assertPhysicalCap(out); return records;
  } });
  const files = await unchanged();
  if ((await currentHostCompilation()).digest !== compiled.digest || !equal(await maintenanceFixtureLayout(buildRoot, stateRoot), fixture) ||
      records.metadata.component.profileFormat !== 1 || records.policy.productDigest !== pinned.productDigest) refuse();
  const result = { format: 1, kind: 'signed-historical-isolated-predecessor', bundle: out,
    original: pinned, originalReceiptSha256: original.receiptSha256, fixture,
    adapterSource: compiled.sourceIdentity, adapterProductDigest: compiled.record.productDigest,
    reviewHandover: review, reviewDigest: accepted.digest, publisher, files, payloadDigest: inventoryDigest(files),
    objects: audit, qualification: 'unexecuted' };
  await writeExclusive(out + '.signature-audit.json', JSON.stringify(result, null, 2) + '\n');
  return result;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), names = ['--out', '--build-root', '--state-root', '--image', '--signed-receipt', '--review-handover'];
  if (args.length !== 12 || names.some((name, i) => args[i * 2] !== name)) refuse();
  const result = await signMigrationPredecessor({ out: resolve(args[1]), buildRoot: resolve(args[3]), stateRoot: resolve(args[5]),
    image: resolve(args[7]), signedReceiptPath: resolve(args[9]), review: args[11] });
  console.log(JSON.stringify({ bundle: result.bundle, productDigest: result.original.productDigest, qualification: result.qualification }));
}
