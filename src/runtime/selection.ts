import { isAbsolute, resolve, dirname, basename, join, sep } from 'node:path';
import { userInfo } from 'node:os';
import { validator } from '../contracts/schema.js';
import { unavailable } from '../contracts/errors.js';
import installation from './installation-paths.json' with { type: 'json' };

export interface BuildSelection {
  readonly build: string; readonly explicit: boolean;
  readonly directory: string; readonly guard: string;
}
/** Paths describe the package and its guard. Signature and image proof remain separate. */
export interface PackagedLayout {
  readonly build: string; readonly buildRoot: string; readonly bundle: string;
  readonly guard: string; readonly scope: 'isolated' | 'installed';
  readonly payload: string; readonly launcher: string; readonly engine: string;
  readonly bootstrap: string;
  readonly cliEntry: string; readonly hostEntry: string;
}
export function buildLocation(build: string, buildRoot: string): Pick<PackagedLayout, 'guard' | 'scope'> | undefined {
  if (!validator('browser.Build')(build) || !isAbsolute(buildRoot) || resolve(buildRoot) !== buildRoot ||
      basename(buildRoot) !== build || basename(dirname(buildRoot)) !== 'arbol-browser') return undefined;
  const component = dirname(buildRoot);
  if (component.endsWith(sep + join(...installation.stableBuilds))) {
    const home = userInfo().homedir;
    if (component !== join(home, ...installation.stableBuilds)) return undefined;
    return { scope: 'installed', guard: join(home, ...installation.stableUses, build) };
  }
  return { scope: 'isolated', guard: join(component, '.uses', build) };
}
export function packagedLayout(build: string, payload: string): PackagedLayout {
  if (!validator('browser.Build')(build) || !isAbsolute(payload) || resolve(payload) !== payload ||
      basename(payload) !== 'browser' || basename(dirname(payload)) !== 'Resources' ||
      basename(dirname(dirname(payload))) !== 'Contents') throw unavailable('browser');
  const bundle = dirname(dirname(dirname(payload))), parent = dirname(bundle);
  const buildRoot = basename(parent) === 'app' ? dirname(parent) : parent;
  const location = buildLocation(build, buildRoot);
  if (basename(bundle) !== 'ArbolBrowser.app' || !location ||
      (location.scope === 'installed' && basename(parent) !== 'app')) throw unavailable('browser');
  return Object.freeze({ build, buildRoot, bundle, payload, ...location,
    launcher: join(payload, 'native/host-launch'),
    bootstrap: join(bundle, 'Contents/MacOS/arbol-browser-native'),
    engine: join(payload, 'runtime/Electron.app/Contents/MacOS/Electron'),
    cliEntry: join(payload, 'lib/cli/main.mjs'), hostEntry: join(payload, 'lib/host/main.mjs') });
}
/** The immutable starter exists even before a bootstrap has claimed a launch.
 * Later actor paths must agree; none may select a different package layout. */
export function claimedLayout(attempt: {
  readonly build: string; readonly buildRoot: string; readonly buildGuard: string;
  readonly starter: { readonly executable: string };
  readonly bootstrap: { readonly executable: string } | null;
  readonly engine: { readonly executable: string } | null;
}): PackagedLayout {
  const suffix = '/runtime/Electron.app/Contents/MacOS/Electron';
  if (!attempt.starter.executable.endsWith(suffix)) throw unavailable('browser');
  const layout = selectedLayout({ build: attempt.build, directory: attempt.buildRoot,
    guard: attempt.buildGuard, explicit: true }, attempt.starter.executable.slice(0, -suffix.length));
  if (attempt.starter.executable !== layout.engine ||
      (attempt.bootstrap !== null && attempt.bootstrap.executable !== layout.bootstrap) ||
      (attempt.engine !== null && attempt.engine.executable !== layout.engine)) throw unavailable('browser');
  return layout;
}
export function selectedLayout(selection: BuildSelection, payload: string): PackagedLayout {
  const layout = packagedLayout(selection.build, payload);
  if (selection.directory !== layout.buildRoot ||
      selection.guard !== layout.guard) throw unavailable('browser');
  return layout;
}
/** The physical CLI lives below Contents/Resources/browser, not at Build root.
 * A launcher hint can neither relocate that payload nor select its older base. */
export function consumePackagedSelection(build: string, payload: string,
  environment: NodeJS.ProcessEnv = process.env): BuildSelection {
  const layout = packagedLayout(build, payload);
  const selection = consumeSelection(build, layout.buildRoot, environment);
  selectedLayout(selection, payload); return selection;
}
/** Private launcher input is a selection hint, never signature/native authority.
 * Consume once and erase before spawning anything. Direct isolated candidates
 * have no launcher context and cannot acquire a production Build-use lease. */
export function consumeSelection(packagedBuild: string, directory: string,
  environment: NodeJS.ProcessEnv = process.env): BuildSelection {
  const raw = environment.ARBOL_BROWSER_SELECTION;
  delete environment.ARBOL_BROWSER_SELECTION;
  if (!validator('browser.Build')(packagedBuild)) throw unavailable('browser');
  if (raw === undefined) return Object.freeze({ build: packagedBuild, explicit: false, directory, guard: '' });
  try {
    if (Buffer.byteLength(raw) > 16384) throw new Error();
    const value = JSON.parse(raw);
    if (!value || Object.keys(value).sort().join(',') !== 'build,directory,explicit,format,guard' ||
        value.format !== 1 || value.build !== packagedBuild || typeof value.explicit !== 'boolean' ||
        typeof value.directory !== 'string' || !isAbsolute(value.directory) || resolve(value.directory) !== directory ||
        typeof value.guard !== 'string' || !isAbsolute(value.guard) || resolve(value.guard) !== value.guard ||
        value.guard !== buildLocation(packagedBuild, directory)?.guard) throw new Error();
    return Object.freeze({ build: packagedBuild, explicit: value.explicit, directory, guard: value.guard });
  } catch { throw unavailable('browser'); }
}
export function expectedBuild(selection: BuildSelection): { expectedBuild?: string } {
  return selection.explicit ? { expectedBuild: selection.build } : {};
}
