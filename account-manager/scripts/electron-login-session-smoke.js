'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const http = require('node:http')
const os = require('node:os')
const path = require('node:path')
const { spawn } = require('node:child_process')

async function runWorker() {
  const { app, BrowserWindow, session } = require('electron')
  const [phase, sessionPath, origin] = process.argv.slice(2)
  try {
    await app.whenReady()
    const sess = session.fromPath(sessionPath, { cache: false })
    const win = new BrowserWindow({ show: false, webPreferences: { session: sess, sandbox: true } })
    await win.loadURL(origin)
    if (phase === 'write') {
      await win.webContents.executeJavaScript("localStorage.setItem('cac-fixture', 'saved'); document.cookie = 'cac-fixture=saved; Max-Age=3600; SameSite=Lax'")
    } else {
      const values = await win.webContents.executeJavaScript("({ local: localStorage.getItem('cac-fixture'), cookie: document.cookie })")
      assert.equal(values.local, phase === 'verify' ? 'saved' : null)
      assert.equal(values.cookie.includes('cac-fixture=saved'), phase === 'verify')
    }
    await sess.cookies.flushStore()
    if (phase === 'verify') {
      await sess.clearAuthCache()
      await sess.clearData()
    }
    sess.flushStorageData()
    win.destroy()
    if (phase === 'cleared') {
      await sess.closeAllConnections()
      fs.rmSync(path.join(path.dirname(path.dirname(sessionPath)), 'profile-a'), { recursive: true, force: true })
    }
    console.log(`[PASS] Electron persistent session ${phase}`)
    app.exit(0)
  } catch (error) {
    console.error(error)
    app.exit(1)
  }
}

function runPhase(executable, phase, sessionPath, origin) {
  return new Promise((resolve, reject) => {
    const childEnv = { ...process.env }
    delete childEnv.ELECTRON_RUN_AS_NODE
    const child = spawn(executable, [__filename, phase, sessionPath, origin], {
      windowsHide: true,
      env: childEnv,
      timeout: 30000
    })
    let output = ''
    child.stdout.on('data', (chunk) => { output += chunk })
    child.stderr.on('data', (chunk) => { output += chunk })
    child.once('error', reject)
    child.once('close', (code) => {
      if (code === 0 && output.includes(`[PASS] Electron persistent session ${phase}`)) resolve()
      else reject(new Error(`Electron ${phase} exited ${code}: ${output.trim()}`))
    })
  })
}

async function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cac-login-session-smoke-'))
  const sessionPath = path.join(tempRoot, 'web-login-sessions', 'account-a')
  fs.mkdirSync(path.join(tempRoot, 'profile-a'))
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    response.end('<!doctype html><title>Session smoke</title>')
  })
  try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    const origin = `http://127.0.0.1:${server.address().port}/`
    const electron = require('electron')
    for (const phase of ['write', 'verify', 'cleared']) {
      await runPhase(electron, phase, sessionPath, origin)
    }
    assert.equal(fs.existsSync(path.join(tempRoot, 'profile-a')), false)
    fs.rmSync(sessionPath, { recursive: true, force: true })
    assert.equal(fs.existsSync(sessionPath), false)
    console.log('[PASS] Electron session survives restart, clears, and permits Profile deletion')
  } finally {
    await new Promise((resolve) => server.close(resolve))
    if (path.dirname(tempRoot) === os.tmpdir() && path.basename(tempRoot).startsWith('cac-login-session-smoke-')) {
      fs.rmSync(tempRoot, { recursive: true, force: true })
    }
  }
}

if (process.versions.electron) {
  void runWorker()
} else {
  main().catch((error) => { console.error(error); process.exitCode = 1 })
}
