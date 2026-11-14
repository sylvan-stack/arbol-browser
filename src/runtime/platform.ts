import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { isAbsolute } from 'node:path';
import { unavailable } from '../contracts/errors.js';

export interface FileIdentity { readonly device: string; readonly inode: string; readonly uid: number }
export interface ProcessIdentity { readonly pid: number; readonly uid: number; readonly startId: string }
export interface HeldLock {
  /** Check the retained descriptor against the published pathname after waits/transactions. */
  assertIdentity(): FileIdentity;
  /** Caller retains this object through flush and complete helper shutdown. Never unlinks. */
  release(): void;
}
export interface PlatformPort {
  /** Nonblocking: null means contention. The caller enforces its monotonic deadline. */
  tryLock(absolutePath: string): HeldLock | null;
  /** null means kernel ESRCH only; denied/uncertain observation throws unavailability. */
  processIdentity(pid: number): ProcessIdentity | null;
  /** Connected AF_UNIX stream FD owned by the caller; verifies UID, PID and kernel PID version. */
  peerIdentity(socketFd: number): ProcessIdentity;
}
interface NativeSupport {
  tryLock(path: string): object | null;
  assertLock(handle: object): FileIdentity;
  releaseLock(handle: object): void;
  processIdentity(pid: number): ProcessIdentity | null;
  peerIdentity(fd: number): ProcessIdentity;
}

/** Explicit lazy loading: CLI info and schema parsing never load this private module.
 * ABR-2 injects this port into its locking code. It is not the BRW-4 input adapter.
 * Callers first validate canonical/private ancestors and recheck profile instance.
 * No JavaScript lockfile or PID-only implementation is an allowed fallback. */
export function loadPlatform(): PlatformPort {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw unavailable('profile');
  let native: NativeSupport;
  try {
    native = createRequire(import.meta.url)(fileURLToPath(new URL('../../native/platform.node', import.meta.url)));
    for (const name of ['tryLock', 'assertLock', 'releaseLock', 'processIdentity', 'peerIdentity'] as const)
      if (typeof native[name] !== 'function') throw new Error('Missing process support');
  } catch { throw unavailable('profile'); }
  const call = <T>(operation: () => T): T => {
    try { return operation(); } catch { throw unavailable('profile'); }
  };
  return Object.freeze({
    tryLock(path: string): HeldLock | null {
      if (!isAbsolute(path) || path.includes('\0')) throw unavailable('profile');
      const handle = call(() => native.tryLock(path));
      if (handle === null) return null;
      let released = false;
      return Object.freeze({
        assertIdentity: () => { if (released) throw unavailable('profile'); return call(() => native.assertLock(handle)); },
        release: () => { if (!released) { released = true; call(() => native.releaseLock(handle)); } },
      });
    },
    processIdentity: (pid: number) => call(() => native.processIdentity(pid)),
    peerIdentity: (fd: number) => call(() => native.peerIdentity(fd)),
  });
}
