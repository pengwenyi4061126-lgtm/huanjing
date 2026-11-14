'use strict'

const { app, BrowserWindow, session } = require('electron')

app.commandLine.appendSwitch('no-sandbox')
app.commandLine.appendSwitch('disable-gpu-sandbox')
app.commandLine.appendSwitch('disable-quic')

app.whenReady()
  .then(async () => {
    const win = new BrowserWindow({
      show: false,
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true
      }
    })
    await win.loadURL('data:text/html;charset=utf-8,<title>native-electron-smoke</title>')
    await session.defaultSession.resolveProxy('https://example.com/')
    await new Promise((resolve) => setTimeout(resolve, 1500))
    win.destroy()
  })
  .then(() => app.exit(0))
  .catch((error) => {
    console.error(`[FAIL] ${error.stack || error.message || error}`)
    app.exit(1)
  })
