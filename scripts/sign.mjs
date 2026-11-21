import { spawnSync } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { root } from './package-base.mjs';
import { exactFile } from './package-host.mjs';

const jitEntitlement = 'com.apple.security.cs.allow-jit';
const machOMagic = new Set(['cffaedfe', 'cefaedfe', 'feedfacf', 'cafebabe', 'bebafeca']);

function command(program, args, input) {
  const result = spawnSync(program, args, {
    cwd: root, encoding: 'utf8', env: { PATH: '/usr/bin:/bin' },
    timeout: 120000, maxBuffer: 1048576, ...(input === undefined ? {} : { input }),
  });
  if (result.error || result.status !== 0) throw new Error('Bundle signing command failed');
  return result;
}

/** The caller must independently verify the unsigned bundle before signing.
 * Only the caller may regenerate the sealed metadata after nested signing. */
export async function signBundle({ bundle, identity, publisher, sealResources }) {
  const bootstrap = join(bundle, 'Contents/MacOS/arbol-browser-native');
  const electron = join(bundle, 'Contents/Resources/browser/runtime/Electron.app');
  const frameworks = join(electron, 'Contents/Frameworks');
  const jitTargets = new Set([electron, join(electron, 'Contents/MacOS/Electron')]);
  for (const name of ['Electron Helper', 'Electron Helper (GPU)', 'Electron Helper (Plugin)', 'Electron Helper (Renderer)']) {
    const helper = join(frameworks, `${name}.app`);
    jitTargets.add(helper);
    jitTargets.add(join(helper, 'Contents/MacOS', name));
  }

  const leaves = [], containers = [], mutable = new Set();
  async function walk(directory) {
    for (const name of (await readdir(directory)).sort()) {
      const file = join(directory, name), info = await lstat(file);
      if (info.isSymbolicLink()) {
        if (!(await realpath(file)).startsWith(bundle + sep)) throw new Error('Escaping bundle link');
      } else if (info.isDirectory()) {
        await walk(file);
        if (/\.(app|framework|xpc)$/.test(file)) containers.push(file);
      } else if (info.isFile()) {
        const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        try {
          const bytes = Buffer.alloc(4);
          const header = await fd.read(bytes, 0, bytes.length, 0);
          if (header.bytesRead === bytes.length && machOMagic.has(bytes.toString('hex'))) {
            mutable.add(relative(bundle, file));
            if (file !== bootstrap) leaves.push(file);
          }
        } finally { await fd.close(); }
      } else throw new Error('Unsupported bundle entry');
    }
  }
  await walk(bundle);
  if (!mutable.has(relative(bundle, bootstrap)) ||
      [...jitTargets].some(file => !leaves.includes(file) && !containers.includes(file))) {
    throw new Error('Pinned Electron or Browser launcher layout is incomplete');
  }
  const entitlementPath = join(root, 'entitlements.plist');
  const entitlements = await exactFile(entitlementPath);
  function sign(file) {
    command('/usr/bin/codesign', ['--force', '--sign', identity, '--options', 'runtime', '--timestamp',
      ...(jitTargets.has(file) ? ['--entitlements', entitlementPath] : []), file]);
  }
  const deepestFirst = (left, right) => right.split(sep).length - left.split(sep).length;
  for (const file of leaves.sort(deepestFirst)) sign(file);
  for (const file of containers.sort(deepestFirst)) sign(file);
  if ((await exactFile(entitlementPath)).sha256 !== entitlements.sha256) throw new Error('Signing entitlements changed');
  const records = await sealResources(mutable);
  sign(bundle);

  const audit = [];
  for (const file of [...leaves, ...containers, bootstrap, bundle]) {
    const requirement = publisher.requirement + (file === bundle ? ` and identifier "${publisher.bundleIdentifier}"` : '');
    command('/usr/bin/codesign', ['--verify', '--strict', ...(file === bundle ? ['--deep'] : []), '-R', `=${requirement}`, file]);
    const details = command('/usr/bin/codesign', ['-dvvv', file]).stderr;
    if (!details.includes(`TeamIdentifier=${publisher.team}`) || !details.includes('runtime)') || !details.includes('Timestamp=')) {
      throw new Error('Signed bundle identity differs from the signing policy');
    }
    const xml = command('/usr/bin/codesign', ['-d', '--entitlements', '-', '--xml', file]).stdout;
    const values = xml.trim() ? JSON.parse(command('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '-'], xml).stdout) : {};
    if (Object.keys(values).some(key => key !== jitEntitlement) ||
        (jitTargets.has(file) ? values[jitEntitlement] !== true : Object.hasOwn(values, jitEntitlement))) {
      throw new Error('Signed bundle entitlements differ from the signing policy');
    }
    audit.push({ path: relative(bundle, file) || '.', team: publisher.team, hardenedRuntime: true, timestamped: true, entitlements: values });
  }
  return { records, audit };
}
