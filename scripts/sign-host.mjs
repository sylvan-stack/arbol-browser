/** Source-only recipe in ABR-29. Actual new candidate signing belongs to the
 * separately authorized isolated ABR-12 Build. Importing never signs/stages. */
import { lstat, realpath, mkdtemp, chmod } from 'node:fs/promises';
import { resolve, join, dirname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { root, inventory, inventoryDigest } from './package-base.mjs';
import { hash, canonical, exactFile, json, privateDirectory, writeExclusive, assertHostIsolation,
  currentHostCompilation, acceptedHostProduct, prepareUnsignedHost, refreshHostRecords, assertPhysicalCap } from './package-host.mjs';
import { signBundle } from './sign.mjs';
const identity = 'F1B6782A3BACC18E73FE08CA424C0A81450A982C';
const publisher = Object.freeze({ team: '7V372XL59S', bundleIdentifier: 'com.sylvan-stack.arbol-browser.native-candidate',
  requirement: 'anchor apple generic and certificate leaf[subject.OU] = "7V372XL59S" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' });
const fail = () => { throw new Error('Exact reviewed host signing unavailable; preserve this attempt'); };
async function absent(path) {
  try { await lstat(path); return false; } catch (error) { if (error.code !== 'ENOENT') throw error; return true; }
}
/** Reproduce every unsigned byte independently from current compiler outputs,
 * source-pinned stock archive and lockfile integrity. An editable unsigned JSON
 * record alone cannot authorize substitutions in Electron, dependencies or JS. */
export async function signHost({ bundle, runtimeArchive, review }) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || resolve(bundle) !== bundle ||
      !(bundle.endsWith('/ArbolBrowser.app') || /^\.host-preparation-[A-Za-z0-9_-]{22}\.app$/.test(bundle.split('/').at(-1))) || await realpath(bundle) !== bundle || bundle.startsWith(root + sep)) fail();
  await privateDirectory(bundle); await privateDirectory(dirname(bundle));
  const unsigned = await json(bundle + '.unsigned.json'), staged = unsigned.value;
  const compiled = await currentHostCompilation(), accepted = await acceptedHostProduct(review, compiled);
  if (staged.format !== 1 || staged.kind !== 'unsigned-current-host' || staged.reviewHandover !== review ||
      staged.reviewDigest !== accepted.digest || staged.purpose !== 'isolated-qualification' ||
      staged.compileDigest !== compiled.digest || staged.sourceDigest !== compiled.record.sourceDigest ||
      canonical(staged.sourceIdentity) !== canonical(compiled.sourceIdentity) ||
      canonical(staged.compilerInputs) !== canonical(compiled.record.compilerInputs)) fail();
  await assertHostIsolation(staged.buildRoot, staged.stateRoot);
  if (!bundle.endsWith('/ArbolBrowser.app') && dirname(bundle) !== staged.buildRoot) fail();
  if (!await absent(join(bundle, 'Contents/_CodeSignature')) || !await absent(bundle + '.signing-attempt.json')) fail();
  const comparison = await mkdtemp(join(dirname(bundle), '.host-sign-inputs-')); await chmod(comparison, 0o700);
  const expected = await prepareUnsignedHost({ out: join(comparison, 'ArbolBrowser.app'), buildRoot: staged.buildRoot,
    stateRoot: staged.stateRoot, runtimeArchive, review, purpose: staged.purpose });
  if (canonical(expected.record) !== canonical(staged) || canonical(await inventory(bundle)) !== canonical(expected.record.files)) fail();
  await writeExclusive(bundle + '.signing-attempt.json', JSON.stringify({ format: 1, bundle, comparison,
    unsignedDigest: unsigned.sha256, reviewHandover: review, reviewDigest: accepted.digest, qualification: 'unexecuted' }) + '\n');
  const mutable = new Set(['Contents/Resources/browser/metadata.json', 'Contents/Resources/native-compatibility.json',
    'Contents/Resources/host-policy.json', 'Contents/Resources/maintenance-fixture.json']);
  const signatureResource = name => /(?:^|\/)_CodeSignature\/CodeResources$/.test(name);
  async function assertUnchangedResources() {
    const actual = await inventory(bundle);
    for (const [name, digest] of Object.entries(expected.record.files))
      if (!mutable.has(name) && !signatureResource(name) && actual[name] !== digest) fail();
    for (const name of Object.keys(actual)) if (!(name in expected.record.files) && !signatureResource(name)) fail();
    return actual;
  }
  const { records, audit } = await signBundle({ bundle, identity, publisher, isolatedMaintenance: Boolean(staged.maintenanceFixture), async sealResources(signedCode) {
    for (const name of signedCode) mutable.add(name);
    const records = await refreshHostRecords(bundle, staged);
    await assertUnchangedResources();
    await assertPhysicalCap(bundle);
    await assertPhysicalCap(join(bundle, 'Contents/Resources/browser'));
    return records;
  } });
  const finalFiles = await assertUnchangedResources();
  if ((await currentHostCompilation()).digest !== compiled.digest ||
      (await json(bundle + '.unsigned.json')).sha256 !== unsigned.sha256 ||
      records.policy.reviewDigest !== accepted.digest || records.policy.productDigest !== compiled.record.productDigest ||
      records.metadata.sourceDigest !== compiled.record.sourceDigest) fail();
  await assertHostIsolation(staged.buildRoot, staged.stateRoot);
  const result = { format: 1, kind: 'signed-current-host', bundle, publisher, sourceDigest: staged.sourceDigest,
    sourceIdentity: staged.sourceIdentity, productDigest: staged.productDigest, productSources: staged.productSources,
    productOutputs: staged.productOutputs, compilerInputs: staged.compilerInputs, reviewHandover: review, reviewDigest: accepted.digest,
    unsignedDigest: unsigned.sha256, compileDigest: compiled.digest, metadataDigest: records.policy.metadataDigest,
    compatibilityDigest: records.policy.compatibilityDigest, policyDigest: (await exactFile(join(bundle, 'Contents/Resources/host-policy.json'))).sha256,
    physicalEntries: { bundle: await assertPhysicalCap(bundle), payload: await assertPhysicalCap(join(bundle, 'Contents/Resources/browser')) },
    maintenanceFixture: records.maintenanceFixture,
    files: finalFiles, payloadDigest: inventoryDigest(finalFiles), objects: audit, libraryValidationDisabled: false,
    qualification: 'unexecuted', unavailable: ['ABR-12 actual product/readiness/failure/race/persistence/close qualification', 'ABR-30 inspection and agent effects', 'ABR-25 distribution/notarization/release qualification'] };
  await writeExclusive(bundle + '.signature-audit.json', JSON.stringify(result, null, 2) + '\n');
  return Object.freeze(result);
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 6 || args[0] !== '--candidate' || args[2] !== '--runtime-archive' || args[4] !== '--review-handover') fail();
  const result = await signHost({ bundle: resolve(args[1]), runtimeArchive: resolve(args[3]), review: args[5] });
  console.log(JSON.stringify({ candidate: result.bundle, qualification: 'unexecuted', productDigest: result.productDigest }));
}
