import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { json } from '../../scripts/package-host.mjs';
import { readSignedRelease, verifyReleaseImage } from '../support/release.mjs';

export async function releaseArtifactIdentity({ buildRoot, repository }) {
  const build = basename(buildRoot);
  const allocationPath = join(buildRoot, 'build.json');
  const allocation = await json(allocationPath);
  const { productionRelease, source } = allocation.value;
  assert.equal(allocation.value.status, 'building');
  assert.equal(allocation.value.component, 'arbol-browser');
  assert.equal(allocation.value.build, build);
  assert.equal(source.commit, execFileSync('/usr/bin/git', ['-C', repository, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim());
  assert.equal(source.uncommittedChanges, false);
  assert.ok(productionRelease, 'The normal production Build must publish its signed image before qualification');

  const releaseRoot = join(dirname(dirname(dirname(buildRoot))), `release-${build}`);
  assert.equal(await realpath(releaseRoot), releaseRoot);
  const image = join(releaseRoot, 'ArbolBrowser.dmg'), receiptPath = join(releaseRoot, 'signed-release.json');
  assert.equal(productionRelease.image, image);
  assert.equal(productionRelease.receipt, receiptPath);
  const receipt = await readSignedRelease(receiptPath), expected = receipt.value;
  assert.equal(receipt.sha256, productionRelease.receiptSha256);
  assert.equal(expected.review, productionRelease.review);
  assert.equal(expected.build, build);
  assert.equal(expected.source, source.commit);
  assert.equal(expected.qualification, 'unexecuted');
  assert.equal(expected.imageSha256, productionRelease.imageSha256);
  assert.equal(expected.payloadDigest, productionRelease.payloadDigest);
  const provenance = await verifyReleaseImage({ image, expected, imageSha256: expected.imageSha256, stapled: false });
  assert.equal((await json(allocationPath)).sha256, allocation.sha256, 'Verification changed the original Building allocation');
  assert.equal((await readSignedRelease(receiptPath)).sha256, receipt.sha256, 'Verification changed the signed release receipt');
  return { allocationSha256: allocation.sha256, signedReceiptSha256: receipt.sha256, ...provenance };
}
