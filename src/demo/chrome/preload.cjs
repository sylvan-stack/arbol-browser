const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('arbolPreview', {
  state: () => ipcRenderer.invoke('arbol-preview:state'),
  action: request => ipcRenderer.invoke('arbol-preview:action', request),
  onState: listener => { ipcRenderer.on('arbol-preview:changed', (_event, state) => listener(state)); },
});
