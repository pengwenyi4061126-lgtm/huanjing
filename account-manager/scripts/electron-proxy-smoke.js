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
const {
  FIXED_US_LANGUAGES,
  FIXED_US_LOCALE,
  FIXED_US_TIMEZONE
} = require('../src/proxy-profile')
const { probeSocks5Profile } = require('../src/socks-client')

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
    try { relayProcess.kill('SIGTERM') } catch { }
  }
  try { if (relayPidFile) fs.rmSync(relayPidFile, { force: true }) } catch { }
  relayProcess = null
  relayPidFile = ''
}

async function startRelay(item, port) {
  stopRelay()
  relayPidFile = path.join(tempRoot, `relay-${item.id}.pid`)
  const logFile = path.join(tempRoot, `relay-${item.id}.log`)
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
  const items = (pool.proxies || []).filter((entry) => entry.enabled !== false)
  if (!items.length) throw new Error('no enabled proxy in pool')
  if (!fs.existsSync(relayPath)) throw new Error(`relay not found: ${relayPath}`)

  let selectedProxy = null
  let sess = null
  let port = 0
  let resolution = ''
  let externalIp = ''
  const failures = []
  for (const item of items) {
    try {
      port = await getFreeTcpPort()
      await startRelay(item, port)
      sess = session.fromPartition(`persist:cac-electron-proxy-smoke-${item.id}`)
      await sess.setProxy({
        mode: 'fixed_servers',
        proxyRules: `http=127.0.0.1:${port};https=127.0.0.1:${port}`,
        proxyBypassRules: '<-loopback>'
      })
      resolution = String(await sess.resolveProxy('https://claude.ai/login') || '').trim()
      if (!new RegExp(`127\.0\.0\.1:${port}`).test(resolution) || /\bDIRECT\b/i.test(resolution)) {
        throw new Error(`proxy resolution is ${resolution || 'DIRECT'}`)
      }
      const response = await requestThroughSession(sess, 'https://api.ipify.org/?format=json')
      if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`HTTP ${response.statusCode}`)
      externalIp = String(JSON.parse(response.body).ip || '').trim()
      if (!netModule.isIP(externalIp)) throw new Error('invalid external IP')
      selectedProxy = item
      break
    } catch (error) {
      failures.push(`${item.id}: ${error.message || error}`)
      stopRelay()
    }
  }
  if (!selectedProxy || !sess) throw new Error(`all enabled proxies failed: ${failures.join('; ')}`)

  const proxyProfile = await probeSocks5Profile(selectedProxy.url, selectedProxy.id, {
    timezone: FIXED_US_TIMEZONE,
    locale: FIXED_US_LOCALE,
    languages: FIXED_US_LANGUAGES
  })
  const persona = {
    seed: 'electron-smoke',
    timezone: proxyProfile.timezone,
    locale: proxyProfile.locale,
    languages: proxyProfile.languages,
    ua: 'CAC-Electron-Profile-Smoke/1.0',
    platform: 'Win32',
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    screen: {
      width: 1920,
      height: 1080,
      availWidth: 1920,
      availHeight: 1040,
      colorDepth: 24,
      pixelDepth: 24,
      dpr: 1
    },
    audioNoise: 0.0000001,
    webrtc: 'filter-private'
  }
  applyLoginSessionPersona(sess, persona)
  resolution = String(await sess.resolveProxy('https://claude.ai/login') || '').trim()
  if (!new RegExp(`127\\.0\\.0\\.1:${port}`).test(resolution) || /\bDIRECT\b/i.test(resolution)) {
    throw new Error(`proxy resolution is ${resolution || 'DIRECT'}`)
  }
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
    timezoneOffsetIsInteger: Number.isInteger(new Date('2026-11-15T12:34:56.789Z').getTimezoneOffset()),
    platform: navigator.platform,
    viewportIndependent: window.innerWidth !== screen.width,
    audioStable: (() => {
      const buffer = new AudioBuffer({ length: 4096, sampleRate: 44100, numberOfChannels: 1 });
      const first = buffer.getChannelData(0);
      const sample = first[0];
      buffer.getChannelData(0);
      return first[0] === sample;
    })()
  })`)
  if (observed.ua !== persona.ua) throw new Error(`userAgent mismatch: ${observed.ua}`)
  if (observed.language !== persona.languages[0]) throw new Error(`language mismatch: ${observed.language}`)
  if (observed.languages.join(',') !== persona.languages.join(',')) throw new Error(`languages mismatch: ${observed.languages.join(',')}`)
  if (observed.timezone !== persona.timezone) throw new Error(`timezone mismatch: ${observed.timezone}`)
  if (!observed.timezoneOffsetIsInteger) throw new Error('timezone offset is fractional')
  if (observed.platform !== persona.platform) throw new Error(`platform mismatch: ${observed.platform}`)
  if (!observed.viewportIndependent) throw new Error('viewport dimensions were overwritten with screen dimensions')
  if (!observed.audioStable) throw new Error('audio noise accumulated across repeated reads')
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
  console.log(`[PASS] Electron session ${resolution} proxy=${selectedProxy.id} loginExit=${externalIp} genesisExit=${proxyProfile.externalIp} timezone=${proxyProfile.timezone} locale=${proxyProfile.locale} dns=relay->SOCKS5-domain fingerprint=${runtime.mode} webrtcPrivateLeak=0`)
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
