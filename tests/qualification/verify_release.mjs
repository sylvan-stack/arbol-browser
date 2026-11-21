import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { exactFile, json, writeExclusive } from '../../scripts/package-host.mjs';
import { readSignedRelease, verifyReleaseImage } from '../support/release.mjs';

// Deliberately explicit and standalone. The normal Build gate never calls this
// verifier, submits a release or activates a canonical installation.
const flags = ['--original', '--delivered', '--signed-receipt', '--submission-receipt', '--notary-result', '--notary-log', '--out'];
const args = process.argv.slice(2);
if (args.length !== flags.length * 2 || flags.some((flag, index) => args[index * 2] !== flag || !args[index * 2 + 1])) {
  throw new Error('Usage: verify_release.mjs --original <signed.dmg> --delivered <stapled.dmg> --signed-receipt <release.json> --submission-receipt <submitted.json> --notary-result <result.json> --notary-log <log.json> --out <delivery.json>');
}
const [original, delivered, signedReceiptPath, submissionPath, resultPath, logPath, out] =
  flags.map((_, index) => resolve(args[index * 2 + 1]));
assert.equal(process.platform, 'darwin');
assert.equal(process.arch, 'arm64');
assert.notEqual(original, delivered);

const [signed, submitted, result, log] = await Promise.all([
  readSignedRelease(signedReceiptPath), json(submissionPath), json(resultPath), json(logPath),
]);
const expected = signed.value;
const submission = submitted.value.submission;
assert.match(submission, /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i);
assert.equal(submitted.value.format, 1);
assert.equal(submitted.value.signedReceiptSha256, signed.sha256);
assert.equal(submitted.value.imageSha256, expected.imageSha256);
assert.equal(result.value.status, 'Accepted');
assert.equal(result.value.id.toLowerCase(), submission.toLowerCase());
assert.equal(log.value.status, 'Accepted');
assert.equal(log.value.jobId.toLowerCase(), submission.toLowerCase());
assert.ok(log.value.issues === null || (Array.isArray(log.value.issues) && !log.value.issues.length), 'Apple recorded notarization issues');
if (log.value.sha256 !== undefined) assert.equal(log.value.sha256, expected.imageSha256);

const before = await verifyReleaseImage({ image: original, expected, imageSha256: expected.imageSha256, stapled: false });
const { sha256: imageSha256 } = await exactFile(delivered, 1024 ** 3);
const after = await verifyReleaseImage({ image: delivered, expected, imageSha256, stapled: true });
const { imageSha256: priorArchive, ...priorApp } = before;
const { imageSha256: deliveredArchive, ...deliveredApp } = after;
assert.deepEqual(deliveredApp, priorApp);
for (const [path, input] of [[signedReceiptPath, signed], [submissionPath, submitted], [resultPath, result], [logPath, log]]) {
  assert.equal((await json(path)).sha256, input.sha256, 'Release evidence changed during verification');
}

const delivery = { format: 1, kind: 'notarized-production-release', status: 'Accepted', submission,
  signedReceiptSha256: signed.sha256, signedImageSha256: priorArchive, imageSha256: deliveredArchive,
  build: expected.build, source: expected.source, productDigest: expected.productDigest, payloadDigest: expected.payloadDigest,
  submissionReceiptSha256: submitted.sha256, notaryResultSha256: result.sha256, notaryLogSha256: log.sha256,
  publisher: expected.publisher, runtime: expected.runtime, signedFileCount: after.signedFileCount,
  verification: { preSubmissionInventory: 'matched', postStapleInventory: 'matched', stapledTicket: 'valid', gatekeeperImage: 'accepted', gatekeeperApp: 'accepted' } };
await writeExclusive(out, JSON.stringify(delivery, null, 2) + '\n');
console.log(JSON.stringify({ verified: out, build: delivery.build, imageSha256: deliveredArchive, payloadDigest: delivery.payloadDigest }));
