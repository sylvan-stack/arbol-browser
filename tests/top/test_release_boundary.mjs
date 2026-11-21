import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeExclusive } from '../../scripts/package-host.mjs';
import { checkBuildsReadRestriction, snapshotFirstInstall } from '../support/release.mjs';

// Explicit, read-only first-install preflight. Never run from the automatic gate.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [check, outFlag, out, controlFlag, control, ...extra] = process.argv.slice(2);
  if (check !== '--first-install-preflight' || outFlag !== '--out' || !out || controlFlag !== '--builds-control' || !control || extra.length)
    throw new Error('Usage: test_release_boundary.mjs --first-install-preflight --out <new-receipt.json> --builds-control <private-token-file>');
  const before = await snapshotFirstInstall();
  const restriction = await checkBuildsReadRestriction(resolve(control));
  assert.deepEqual(await snapshotFirstInstall(), before);
  await writeExclusive(resolve(out), JSON.stringify({ format: 1, kind: 'browser-first-install-preflight',
    observedAt: new Date().toISOString(), before, restriction, processTreeObservation: 'unavailable',
    independentFilesystemObservation: 'unavailable' }, null, 2) + '\n');
}
