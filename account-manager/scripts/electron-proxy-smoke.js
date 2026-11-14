'use strict'

const { app, BrowserWindow, net, session } = require('electron')
const fs = require('node:fs')
const http = require('node:http')
const netModule = require('node:net')
const os = require('node:os')
const path = require('node:path')
const { spawn } = require('node:child_process')
const {
  applyLoginSessionPersona,
  installLoginWebContentsPersona
} = require('../src/login-fingerprint')

app.commandLine.appendSwitch('host-resolver-rules', 'MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1, EXCLUDE ::1')
app.commandLine.appendSwitch('disable-quic')
app.commandLine.appendSwitch('force-webrtc-ip-handling-policy', 'disable_non_proxied_udp')

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cac-electron-proxy-'))
const relayPath = path.resolve(__dirname, '..', '..', 'src', 'relay.js')
let relayProcess = null
let relayPidFile = ''

function fail(error) {
  console.error(`[FAIL] ${error.message || error}`)
  app.exit(1)
}

function getFreeTcpPort() {
  return new Promise((resolve, reject) => {
    const listener = netModule.createServer()
    listener.once('error', reject)
    listener.listen(0, '127.0.0.1', () => {
      const address = listener.address()
      const port = typeof address === 'object' && address ? Number(address.port) : 0
      listener.close((error) => error ? reject(error) : resolve(port))
    })
  })
}

function waitForRelayHealth(port) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 8000
    const poll = () => {
      if (relayProcess && relayProcess.exitCode !== null) {
        reject(new Error(`relay exited with ${relayProcess.exitCode}`))
        return
      }
      const request = http.request({
        host: '127.0.0.1',
        port,
        method: 'GET',
        path: 'http://cac-relay.local/__cac_relay_health__',
        headers: { Host: 'cac-relay.local', Connection: 'close' },
        timeout: 750,
        agent: false
      }, (response) => {
        response.resume()
        response.once('end', () => {
          if (Number(response.statusCode || 0) === 200 && String(response.headers['x-cac-relay'] || '').toLowerCase() === 'ready') {
            resolve()
          } else if (Date.now() >= deadline) {
            reject(new Error('relay health check failed'))
          } else {
            setTimeout(poll, 100)
          }
        })
      })
      request.once('timeout', () => request.destroy())
      request.once('error', () => {
        if (Date.now() >= deadline) reject(new Error('relay startup timeout'))
        else setTimeout(poll, 100)
      })
      request.end()
    }
    poll()
  })
}

function stopRelay() {
  const pid = Number(relayProcess?.pid || 0)
  if (pid > 0 && relayProcess.exitCode === null) {
    try {
      if (process.platform === 'win32') {
        const killer = spawn('taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
          windowsHide: true,
          stdio: 'ignore'
        })
        killer.unref()
      } else {
        relayProcess.kill('SIGTERM')
      }
    } catch { }
  }
  try { if (relayPidFile) fs.rmSync(relayPidFile, { force: true }) } catch { }
}

function requestThroughSession(sess, url) {
  return new Promise((resolve, reject) => {
    const request = net.request({ method: 'GET', session: sess, url })
    let body = ''
    const timer = setTimeout(() => {
      try { request.abort() } catch { }
      reject(new Error('request timeout'))
    }, 15000)
    request.once('error', (error) => { clearTimeout(timer); reject(error) })
    request.once('response', (response) => {
      response.setEncoding('utf8')
      response.on('data', (chunk) => { body += chunk })
      response.once('error', (error) => { clearTimeout(timer); reject(error) })
      response.once('end', () => { clearTimeout(timer); resolve({ statusCode: response.statusCode, body }) })
    })
    request.end()
  })
}

async function main() {
  const poolPath = path.join(os.homedir(), '.cac', 'proxy-pool.json')
  const pool = JSON.parse(fs.readFileSync(poolPath, 'utf8'))
  const item = (pool.proxies || []).find((entry) => entry.enabled !== false)
  if (!item) throw new Error('no enabled proxy in pool')
  if (!fs.existsSync(relayPath)) throw new Error(`relay not found: ${relayPath}`)

  const port = await getFreeTcpPort()
  relayPidFile = path.join(tempRoot, 'relay.pid')
  const logFile = path.join(tempRoot, 'relay.log')
  const logFd = fs.openSync(logFile, 'a')
  try {
    relayProcess = spawn(process.env.CAC_NODE_EXECUTABLE || 'node.exe', [relayPath, String(port), relayPidFile], {
      cwd: path.resolve(__dirname, '..', '..'),
      windowsHide: true,
      env: {
        ...process.env,
        CAC_RELAY_UPSTREAM_URL: String(item.url),
        CAC_RELAY_PID_FILE: relayPidFile
      },
      stdio: ['ignore', logFd, logFd]
    })
  } finally {
    try { fs.closeSync(logFd) } catch { }
  }
  await waitForRelayHealth(port)

  const sess = session.fromPartition('persist:cac-electron-proxy-smoke')
  const persona = {
    seed: 'electron-smoke',
    timezone: 'America/New_York',
    locale: 'en-US',
    languages: ['en-US', 'en'],
    ua: 'CAC-Electron-Profile-Smoke/1.0',
    platform: 'Win32',
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    webrtc: 'filter-private'
  }
  applyLoginSessionPersona(sess, persona)
  await sess.setProxy({
    mode: 'fixed_servers',
    proxyRules: `http=127.0.0.1:${port};https=127.0.0.1:${port}`,
    proxyBypassRules: '<-loopback>'
  })
  const resolution = String(await sess.resolveProxy('https://claude.ai/login') || '').trim()
  if (!new RegExp(`127\\.0\\.0\\.1:${port}`).test(resolution) || /\bDIRECT\b/i.test(resolution)) {
    throw new Error(`proxy resolution is ${resolution || 'DIRECT'}`)
  }
  const response = await requestThroughSession(sess, 'https://api.ipify.org/?format=json')
  if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`HTTP ${response.statusCode}`)
  const externalIp = JSON.parse(response.body).ip
  const shim = fs.readFileSync(path.resolve(__dirname, '..', '..', 'scripts', 'fingerprint-shim.js'), 'utf8')
  const source = `window.__CAC_PERSONA__=${JSON.stringify(persona)};\n${shim}`
  const win = new BrowserWindow({
    show: false,
    webPreferences: { session: sess, contextIsolation: true, nodeIntegration: false, sandbox: true }
  })
  await win.loadURL('about:blank')
  const runtime = await installLoginWebContentsPersona(win.webContents, { persona, script: source })
  await win.loadURL('data:text/html;charset=utf-8,<title>fingerprint-smoke</title>')
  const observed = await win.webContents.executeJavaScript(`({
    ua: navigator.userAgent,
    language: navigator.language,
    languages: Array.from(navigator.languages || []),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    platform: navigator.platform
  })`)
  if (observed.ua !== persona.ua) throw new Error(`userAgent mismatch: ${observed.ua}`)
  if (observed.language !== persona.languages[0]) throw new Error(`language mismatch: ${observed.language}`)
  if (observed.languages.join(',') !== persona.languages.join(',')) throw new Error(`languages mismatch: ${observed.languages.join(',')}`)
  if (observed.timezone !== persona.timezone) throw new Error(`timezone mismatch: ${observed.timezone}`)
  if (observed.platform !== persona.platform) throw new Error(`platform mismatch: ${observed.platform}`)
  const candidates = await win.webContents.executeJavaScript(`new Promise(async (resolve) => {
    const values = [];
    const pc = new RTCPeerConnection({ iceServers: [] });
    pc.createDataChannel('cac');
    pc.onicecandidate = (event) => {
      if (event.candidate && event.candidate.candidate) values.push(event.candidate.candidate);
      if (!event.candidate) { pc.close(); resolve(values); }
    };
    try {
      await pc.setLocalDescription(await pc.createOffer());
      setTimeout(() => { try { pc.close(); } catch {} resolve(values); }, 3000);
    } catch (_) {
      try { pc.close(); } catch {}
      resolve(values);
    }
  })`)
  const privateCandidate = candidates.find((value) => /(^|[\s:])(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|::1)/i.test(String(value)))
  if (privateCandidate) throw new Error(`WebRTC private candidate leaked: ${privateCandidate}`)
  win.destroy()
  console.log(`[PASS] Electron session ${resolution} externalIp=${externalIp} dns=relay->SOCKS5-domain fingerprint=${runtime.mode} webrtcPrivateLeak=0`)
}

app.setPath('userData', tempRoot)
app.whenReady()
  .then(main)
  .then(() => {
    stopRelay()
    app.exit(0)
  })
  .catch((error) => {
    stopRelay()
    fail(error)
  })
