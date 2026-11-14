import { isAbsolute, resolve, dirname, basename, join } from 'node:path';
import { validator } from '../contracts/schema.js';
import { unavailable } from '../contracts/errors.js';

export interface BuildSelection {
  readonly build: string; readonly explicit: boolean;
  readonly directory: string; readonly guard: string;
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
        basename(directory) !== packagedBuild || basename(dirname(directory)) !== 'arbol-browser' ||
        value.guard !== join(dirname(directory), '.uses', packagedBuild)) throw new Error();
    return Object.freeze({ build: packagedBuild, explicit: value.explicit, directory, guard: value.guard });
  } catch { throw unavailable('browser'); }
}
export function expectedBuild(selection: BuildSelection): { expectedBuild?: string } {
  return selection.explicit ? { expectedBuild: selection.build } : {};
}
