import { contextBridge, ipcRenderer } from 'electron';
import type { Contract } from '../contracts/generated.js';

/** Bundled CJS for the sandbox. Never expose ipcRenderer, native objects or arbitrary channels. */
contextBridge.exposeInMainWorld('browserShell', Object.freeze({
  request: (request: Contract<'browser.ShellRequest'>) => ipcRenderer.invoke('browser-shell:request', request),
  subscribe: (receive: (event: Contract<'browser.ShellEvent'>) => void) => {
    const listener = (_event: unknown, value: Contract<'browser.ShellEvent'>) => receive(value);
    ipcRenderer.on('browser-shell:state', listener);
    return () => ipcRenderer.removeListener('browser-shell:state', listener);
  },
  resync: () => ipcRenderer.invoke('browser-shell:state'),
}));
