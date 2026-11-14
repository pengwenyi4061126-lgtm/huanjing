'use strict'

const { contextBridge, ipcRenderer } = require('electron')

const manager = {
  getState: () => ipcRenderer.invoke('manager:get-state'),
  saveAccount: (input) => ipcRenderer.invoke('manager:save-account', input),
  deleteAccount: (id) => ipcRenderer.invoke('manager:delete-account', id),
  activateAccount: (id) => ipcRenderer.invoke('manager:activate-account', id),
  stopAccount: (id) => ipcRenderer.invoke('manager:stop-account', id),
  openLogin: (id) => ipcRenderer.invoke('manager:open-login', id),
  restoreSession: (id) => ipcRenderer.invoke('manager:restore-session', id),
  clearSession: (id) => ipcRenderer.invoke('manager:clear-session', id),
  exportAccounts: (options) => ipcRenderer.invoke('manager:export', options),
  importAccounts: () => ipcRenderer.invoke('manager:import'),
  listProxies: () => ipcRenderer.invoke('manager:list-proxies'),
  addProxy: (url) => ipcRenderer.invoke('manager:add-proxy', url),
  removeProxy: (id) => ipcRenderer.invoke('manager:remove-proxy', id),
  bindProxy: (accountId, proxyId) => ipcRenderer.invoke('manager:bind-proxy', accountId, proxyId),
  unbindProxy: (accountId) => ipcRenderer.invoke('manager:unbind-proxy', accountId),
  testProxy: (id) => ipcRenderer.invoke('manager:test-proxy', id),
  saveSettings: (settings) => ipcRenderer.invoke('manager:save-settings', settings),
  openPath: (target) => ipcRenderer.invoke('manager:open-path', target),
  onEvent: (callback) => {
    const handler = (_event, event) => callback(event)
    ipcRenderer.on('manager:event', handler)
    return () => ipcRenderer.removeListener('manager:event', handler)
  }
}

contextBridge.exposeInMainWorld('manager', manager)
