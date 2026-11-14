'use strict'

const {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  safeStorage,
  session,
  shell
} = require('electron')
const path = require('node:path')
const fs = require('node:fs/promises')
const fsSync = require('node:fs')
const os = require('node:os')
const crypto = require('node:crypto')
const net = require('node:net')
const tls = require('node:tls')
const { spawn } = require('node:child_process')

const PROJECT_ROOT = path.resolve(__dirname, '..', '..')
const DEFAULT_DESKTOP_EXE = 'C:\\Program Files\\WindowsApps\\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\\app\\claude.exe'
const PROFILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const LOGIN_URL_RE = /^https?:\/\//i
const SCHEMA_VERSION = 1

let mainWindow = null
let loginWindow = null
let loginAccountId = null
let statePath = ''
let state = null
let runtimeRoot = PROJECT_ROOT
let scriptRoot = path.join(PROJECT_ROOT, 'scripts')

function nowIso() {
  return new Date().toISOString()
}

function newId(prefix) {
  return `${prefix}-${crypto.randomUUID()}`
}

function defaultState() {
  return {
    schemaVersion: SCHEMA_VERSION,
    selectedAccountId: null,
    settings: {
      desktopExe: DEFAULT_DESKTOP_EXE,
      launchInject: true,
      launchFingerprint: false,
      loginUrl: 'https://claude.ai/login',
      accountsPerProxy: 2,
      warningMultiplier: 2,
      autoBind: true
    },
    accounts: [],
    events: []
  }
}

function normalizeProfileName(value) {
  const candidate = String(value || '').trim()
  if (!PROFILE_RE.test(candidate)) {
    throw new Error('Profile 名称只能包含字母、数字、点、下划线和短横线，长度 1-64')
  }
  return candidate
}

function normalizeLoginUrl(value) {
  const candidate = String(value || '').trim()
  if (!candidate) return 'https://claude.ai/login'
  if (!LOGIN_URL_RE.test(candidate)) throw new Error('登录地址必须是 http:// 或 https:// 地址')
  return candidate
}

function normalizeAccount(input, existing) {
  const base = existing || {}
  const profileName = normalizeProfileName(input.profileName || base.profileName || 'default')
  const label = String(input.label ?? base.label ?? input.email ?? base.email ?? profileName).trim().slice(0, 80)
  const email = String(input.email ?? base.email ?? '').trim().slice(0, 320)
  const loginUrl = normalizeLoginUrl(input.loginUrl || base.loginUrl || state?.settings?.loginUrl)
  const sourceSession = input.session || base.session
  const account = {
    id: String(input.id || base.id || newId('acct')),
    label,
    email,
    provider: 'Claude Desktop',
    profileName,
    proxyId: input.proxyId ?? base.proxyId ?? null,
    loginUrl,
    notes: String(input.notes ?? base.notes ?? '').trim().slice(0, 2000),
    enabled: Object.prototype.hasOwnProperty.call(input, 'enabled') ? input.enabled !== false : base.enabled !== false,
    status: base.status || 'ready',
    lastUsedAt: base.lastUsedAt || null,
    lastLoginAt: base.lastLoginAt || null,
    runtimePid: base.runtimePid || null,
    createdAt: base.createdAt || nowIso(),
    updatedAt: nowIso(),
    session: sourceSession ? { ...sourceSession } : {
      partition: `persist:cac-account-${String(input.id || base.id || '').replace(/[^A-Za-z0-9_-]/g, '')}`,
      savedAt: null,
      cookieCount: 0,
      domains: [],
      encryptedCookies: null
    }
  }
  if (!account.session.partition || account.session.partition === 'persist:cac-account-') {
    account.session.partition = `persist:cac-account-${account.id.replace(/[^A-Za-z0-9_-]/g, '')}`
  }
  return account
}

function normalizeState(raw) {
  const fresh = defaultState()
  if (!raw || typeof raw !== 'object') return fresh
  if (raw.schemaVersion && Number(raw.schemaVersion) > SCHEMA_VERSION) {
    throw new Error(`不支持的账号管理器数据版本: ${raw.schemaVersion}`)
  }
  const settings = raw.settings && typeof raw.settings === 'object' ? raw.settings : {}
  fresh.settings = {
    ...fresh.settings,
    desktopExe: String(settings.desktopExe || fresh.settings.desktopExe),
    launchInject: settings.launchInject !== false,
    launchFingerprint: settings.launchFingerprint === true,
    loginUrl: normalizeLoginUrl(settings.loginUrl || fresh.settings.loginUrl),
    accountsPerProxy: Math.max(1, Math.min(100, Number(settings.accountsPerProxy) || 2)),
    warningMultiplier: Math.max(1, Math.min(20, Number(settings.warningMultiplier) || 2)),
    autoBind: settings.autoBind !== false
  }
  const seen = new Set()
  fresh.accounts = Array.isArray(raw.accounts)
    ? raw.accounts.map((item) => {
        const id = String(item?.id || newId('acct'))
        if (seen.has(id)) return null
        seen.add(id)
        return normalizeAccount({ ...item, id }, item)
      }).filter(Boolean)
    : []
  fresh.selectedAccountId = fresh.accounts.some((item) => item.id === raw.selectedAccountId)
    ? raw.selectedAccountId
    : (fresh.accounts[0]?.id || null)
  fresh.events = Array.isArray(raw.events) ? raw.events.slice(-200).map((event) => ({
    time: String(event?.time || nowIso()),
    level: String(event?.level || 'info'),
    message: String(event?.message || '').slice(0, 500)
  })) : []
  return fresh
}

async function atomicWriteJson(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true })
  const tempPath = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`
  await fs.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  await fs.rename(tempPath, filePath)
}

async function loadState() {
  try {
    const raw = JSON.parse(await fs.readFile(statePath, 'utf8'))
    state = normalizeState(raw)
  } catch (error) {
    if (error.code !== 'ENOENT') console.warn(`[manager] state read failed: ${error.message}`)
    state = defaultState()
  }
  await saveState()
}

async function saveState() {
  if (!statePath || !state) return
  await atomicWriteJson(statePath, state)
}

async function recordEvent(level, message, persist = true) {
  if (!state) return
  state.events = [...(state.events || []), { time: nowIso(), level, message: String(message).slice(0, 500) }].slice(-200)
  if (persist) await saveState()
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('manager:event', state.events[state.events.length - 1])
}

function safeStorageAvailable() {
  try { return safeStorage.isEncryptionAvailable() } catch { return false }
}

function encryptJson(value) {
  if (!safeStorageAvailable()) return null
  return safeStorage.encryptString(JSON.stringify(value)).toString('base64')
}

function decryptJson(value) {
  if (!value || !safeStorageAvailable()) return null
  try { return JSON.parse(safeStorage.decryptString(Buffer.from(value, 'base64'))) } catch { return null }
}

function safeAccountForRenderer(account) {
  return {
    ...account,
    session: {
      partition: account.session?.partition || '',
      savedAt: account.session?.savedAt || null,
      cookieCount: account.session?.cookieCount || 0,
      domains: Array.isArray(account.session?.domains) ? account.session.domains : [],
      hasEncryptedBackup: Boolean(account.session?.encryptedCookies)
    }
  }
}

function stateForRenderer() {
  return {
    schemaVersion: state.schemaVersion,
    selectedAccountId: state.selectedAccountId,
    settings: { ...state.settings },
    accounts: state.accounts.map(safeAccountForRenderer),
    events: state.events.slice(-100),
    encryptionAvailable: safeStorageAvailable(),
    projectRoot: runtimeRoot,
    dataPath: statePath
  }
}

function resolveRuntimeRoot() {
  const localScript = path.join(PROJECT_ROOT, 'scripts', 'desktop-profile.ps1')
  if (fsSync.existsSync(localScript)) return PROJECT_ROOT
  const packagedRoot = path.join(process.resourcesPath, 'cac-runtime')
  if (fsSync.existsSync(path.join(packagedRoot, 'scripts', 'desktop-profile.ps1'))) return packagedRoot
  return PROJECT_ROOT
}

function runPowerShell(argumentsList, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', [
      '-NoLogo',
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      ...argumentsList
    ], {
      cwd: runtimeRoot,
      windowsHide: true,
      env: { ...process.env, ...extraEnv }
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', (code) => resolve({ code: Number(code ?? 1), stdout, stderr }))
  })
}

async function runDesktopScript(args, extraEnv = {}) {
  const script = path.join(scriptRoot, 'desktop-profile.ps1')
  if (!fsSync.existsSync(script)) throw new Error(`Desktop 脚本不存在: ${script}`)
  return runPowerShell(['-File', script, ...args], extraEnv)
}

async function runProxyScript(args, extraEnv = {}) {
  const script = path.join(scriptRoot, 'proxy-pool.ps1')
  if (!fsSync.existsSync(script)) throw new Error(`代理池脚本不存在: ${script}`)
  return runPowerShell(['-File', script, ...args], extraEnv)
}

function parsePid(output) {
  const match = String(output || '').match(/\bPID:\s*(\d+)/i)
  return match ? Number(match[1]) : null
}

function proxyPoolPath() {
  return path.resolve(process.env.CAC_PROXY_POOL_PATH || path.join(os.homedir(), '.cac', 'proxy-pool.json'))
}

function maskProxyUrl(raw) {
  try {
    const url = new URL(raw)
    const auth = url.username || url.password ? '***:***@' : ''
    const port = url.port ? `:${url.port}` : ''
    return `${url.protocol}//${auth}${url.hostname}${port}`
  } catch {
    return '<invalid-proxy>'
  }
}

async function readProxyState() {
  const file = proxyPoolPath()
  let raw
  try { raw = JSON.parse(await fs.readFile(file, 'utf8')) } catch (error) {
    if (error.code !== 'ENOENT') throw new Error(`代理池 JSON 读取失败: ${error.message}`)
    raw = { version: 1, settings: {}, proxies: [], bindings: [] }
  }
  const proxies = Array.isArray(raw.proxies) ? raw.proxies : []
  const bindings = Array.isArray(raw.bindings) ? raw.bindings : []
  const counts = new Map()
  for (const item of proxies) counts.set(String(item.id), 0)
  for (const binding of bindings) counts.set(String(binding.proxyId), (counts.get(String(binding.proxyId)) || 0) + 1)
  return {
    version: Number(raw.version || 1),
    settings: {
      autoBindOnNewAccount: raw.settings?.autoBindOnNewAccount !== false,
      accountsPerProxy: Math.max(1, Number(raw.settings?.accountsPerProxy) || state.settings.accountsPerProxy),
      warningMultiplier: Math.max(1, Number(raw.settings?.warningMultiplier) || state.settings.warningMultiplier)
    },
    proxies: proxies.map((item) => ({
      id: String(item.id),
      displayUrl: maskProxyUrl(String(item.url || '')),
      enabled: item.enabled !== false,
      createdUtc: String(item.createdUtc || ''),
      lastError: String(item.lastError || ''),
      lastChecked: String(item.lastChecked || ''),
      accountCount: counts.get(String(item.id)) || 0
    })),
    bindings: bindings.map((item) => ({ accountKey: String(item.accountKey), proxyId: String(item.proxyId), updatedUtc: String(item.updatedUtc || '') }))
  }
}

async function readRawProxy(proxyId) {
  try {
    const raw = JSON.parse(await fs.readFile(proxyPoolPath(), 'utf8'))
    return (Array.isArray(raw.proxies) ? raw.proxies : []).find((item) => String(item.id).toLowerCase() === String(proxyId).toLowerCase()) || null
  } catch (error) {
    if (error.code === 'ENOENT') return null
    throw error
  }
}

function buildElectronProxyRules(rawUrl) {
  const url = new URL(rawUrl)
  const hostPort = `${url.hostname}${url.port ? `:${url.port}` : ''}`
  const auth = url.username || url.password
    ? `${decodeURIComponent(url.username)}${url.password ? `:${decodeURIComponent(url.password)}` : ''}@`
    : ''
  const scheme = url.protocol.replace(':', '').toLowerCase()
  if (scheme === 'socks5' || scheme === 'socks5h') return `socks5=${auth}${hostPort}`
  if (scheme === 'http' || scheme === 'https') return `http=${auth}${hostPort};https=${auth}${hostPort}`
  throw new Error(`不支持的代理协议: ${scheme}`)
}

function closeLoginWindow() {
  if (loginWindow && !loginWindow.isDestroyed()) loginWindow.destroy()
  loginWindow = null
  loginAccountId = null
}

async function captureLoginSession(account) {
  const sess = session.fromPartition(account.session.partition)
  try { await sess.cookies.flushStore() } catch { }
  const cookies = await sess.cookies.get({})
  const domains = [...new Set(cookies.map((cookie) => cookie.domain).filter(Boolean))].sort()
  const encryptedCookies = encryptJson(cookies)
  account.session = {
    ...account.session,
    savedAt: nowIso(),
    cookieCount: cookies.length,
    domains,
    encryptedCookies
  }
  account.lastLoginAt = nowIso()
  account.status = cookies.length > 0 ? 'logged-in' : 'ready'
  account.updatedAt = nowIso()
  await saveState()
  await recordEvent('info', `${account.label || account.email || account.profileName} 登录窗口已保存 ${cookies.length} 个 Cookie`)
}

async function openLogin(accountId) {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  closeLoginWindow()
  const rawProxy = account.proxyId ? await readRawProxy(account.proxyId) : null
  if (account.proxyId && !rawProxy) throw new Error(`绑定代理不存在: ${account.proxyId}`)
  const partition = account.session.partition
  const sess = session.fromPartition(partition)
  if (rawProxy) {
    await sess.setProxy({ proxyRules: buildElectronProxyRules(String(rawProxy.url)), proxyBypassRules: '<-loopback>' })
  } else {
    await sess.setProxy({ proxyRules: '', proxyBypassRules: '<-loopback>' })
  }
  loginAccountId = account.id
  loginWindow = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 860,
    minHeight: 620,
    title: `网页登录 - ${account.label || account.email || account.profileName}`,
    autoHideMenuBar: true,
    webPreferences: {
      partition,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  })
  let closing = false
  loginWindow.on('close', (event) => {
    if (closing) return
    event.preventDefault()
    captureLoginSession(account)
      .catch((error) => recordEvent('warn', `登录 Cookie 保存失败: ${error.message}`))
      .finally(() => {
        closing = true
        if (loginWindow && !loginWindow.isDestroyed()) loginWindow.close()
      })
  })
  loginWindow.on('closed', () => {
    loginWindow = null
    loginAccountId = null
  })
  await loginWindow.loadURL(account.loginUrl)
  await recordEvent('info', `${account.label || account.profileName} 已打开网页登录${rawProxy ? `（${maskProxyUrl(rawProxy.url)}）` : '（直连）'}`)
  return { opened: true, proxy: rawProxy ? maskProxyUrl(rawProxy.url) : 'direct' }
}

async function restoreSession(accountId) {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  const cookies = decryptJson(account.session?.encryptedCookies)
  if (!Array.isArray(cookies)) throw new Error('当前机器无法解密该会话备份')
  const sess = session.fromPartition(account.session.partition)
  let restored = 0
  for (const cookie of cookies) {
    try {
      const url = `${cookie.secure ? 'https' : 'http'}://${String(cookie.domain || '').replace(/^\./, '')}${cookie.path || '/'}`
      await sess.cookies.set({
        url,
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path || '/',
        secure: Boolean(cookie.secure),
        httpOnly: Boolean(cookie.httpOnly),
        expirationDate: cookie.expirationDate
      })
      restored++
    } catch { }
  }
  await recordEvent('info', `${account.label || account.profileName} 已恢复 ${restored} 个 Cookie`)
  return { restored }
}

async function clearSession(accountId) {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  if (loginAccountId === account.id) closeLoginWindow()
  const sess = session.fromPartition(account.session.partition)
  await sess.clearStorageData()
  account.session = { ...account.session, savedAt: null, cookieCount: 0, domains: [], encryptedCookies: null }
  account.status = 'ready'
  account.updatedAt = nowIso()
  await saveState()
  await recordEvent('info', `${account.label || account.profileName} 的网页登录会话已清除`)
  return true
}

async function ensureProfile(profileName) {
  const result = await runDesktopScript(['-Action', 'create', '-Profile', profileName, '-SuppressProxyWarning'])
  if (result.code !== 0) throw new Error((result.stderr || result.stdout || 'Profile 创建失败').trim())
  return result
}

async function bindProxy(account, proxyId) {
  const result = await runProxyScript([
    '-Action', 'bind',
    '-AccountKey', `desktop:${account.profileName}`,
    '-Id', String(proxyId)
  ])
  if (result.code !== 0) throw new Error((result.stderr || result.stdout || '代理绑定失败').trim())
  account.proxyId = String(proxyId)
  account.updatedAt = nowIso()
}

async function autoBindProxy(account) {
  const result = await runProxyScript([
    '-Action', 'auto-bind',
    '-AccountKey', `desktop:${account.profileName}`
  ])
  if (result.code !== 0) throw new Error((result.stderr || result.stdout || '代理自动绑定失败').trim())
  const pool = await readProxyState()
  const binding = pool.bindings.find((item) => item.accountKey.toLowerCase() === `desktop:${account.profileName}`.toLowerCase())
  if (binding) account.proxyId = binding.proxyId
}

async function stopAccount(account) {
  const result = await runDesktopScript(['-Action', 'stop', '-Profile', account.profileName])
  if (result.code !== 0) throw new Error((result.stderr || result.stdout || 'Profile 停止失败').trim())
  account.runtimePid = null
  if (account.status === 'running') account.status = 'ready'
  account.updatedAt = nowIso()
}

async function activateAccount(accountId) {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  if (!account.enabled) throw new Error('账号已禁用')
  await ensureProfile(account.profileName)
  const pool = await readProxyState()
  const existingBinding = pool.bindings.find((item) => item.accountKey.toLowerCase() === `desktop:${account.profileName}`.toLowerCase())
  if (account.proxyId) {
    await bindProxy(account, account.proxyId)
  } else if (state.settings.autoBind && pool.settings.autoBindOnNewAccount && pool.proxies.some((item) => item.enabled !== false)) {
    await autoBindProxy(account)
  } else if (existingBinding) {
    account.proxyId = existingBinding.proxyId
  }
  for (const other of state.accounts) {
    if (other.id !== account.id) {
      try { await stopAccount(other) } catch (error) { await recordEvent('warn', `${other.label || other.profileName} 停止失败: ${error.message}`) }
    }
  }
  const args = [
    '-Action', 'launch',
    '-Profile', account.profileName,
    '-Exe', state.settings.desktopExe
  ]
  if (state.settings.launchInject) args.push('-Inject')
  if (state.settings.launchFingerprint) args.push('-Fingerprint')
  const result = await runDesktopScript(args)
  const output = `${result.stdout}\n${result.stderr}`.trim()
  if (result.code !== 0) throw new Error(output || 'Desktop 启动失败')
  account.runtimePid = parsePid(output)
  account.status = 'running'
  account.lastUsedAt = nowIso()
  account.updatedAt = nowIso()
  state.selectedAccountId = account.id
  await saveState()
  await recordEvent('info', `${account.label || account.profileName} 已启动${account.runtimePid ? `（PID ${account.runtimePid}）` : ''}`)
  return { output, pid: account.runtimePid, account: safeAccountForRenderer(account) }
}

function createSocketConnection(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('代理连接超时'))
    }, timeoutMs)
    socket.once('connect', () => { clearTimeout(timer); resolve(socket) })
    socket.once('error', (error) => { clearTimeout(timer); reject(error) })
  })
}

function readExact(socket, length, timeoutMs) {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0)
    const timer = setTimeout(() => { cleanup(); reject(new Error('SOCKS5 握手超时')) }, timeoutMs)
    const onData = (chunk) => {
      data = Buffer.concat([data, chunk])
      if (data.length >= length) {
        cleanup()
        const head = data.subarray(0, length)
        const rest = data.subarray(length)
        if (rest.length) socket.unshift(rest)
        resolve(head)
      }
    }
    const onError = (error) => { cleanup(); reject(error) }
    const cleanup = () => { clearTimeout(timer); socket.off('data', onData); socket.off('error', onError) }
    socket.on('data', onData)
    socket.once('error', onError)
  })
}

async function socks5Connect(rawUrl, targetHost, targetPort, timeoutMs = 8000) {
  const proxy = new URL(rawUrl)
  const socket = await createSocketConnection(proxy.hostname, Number(proxy.port || 1080), timeoutMs)
  const username = decodeURIComponent(proxy.username || '')
  const password = decodeURIComponent(proxy.password || '')
  const methods = username || password ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00])
  socket.write(methods)
  const selected = await readExact(socket, 2, timeoutMs)
  if (selected[0] !== 0x05 || selected[1] === 0xff) throw new Error('SOCKS5 不接受认证方式')
  if (selected[1] === 0x02) {
    const userBuf = Buffer.from(username)
    const passBuf = Buffer.from(password)
    socket.write(Buffer.concat([Buffer.from([0x01, userBuf.length]), userBuf, Buffer.from([passBuf.length]), passBuf]))
    const auth = await readExact(socket, 2, timeoutMs)
    if (auth[1] !== 0x00) throw new Error('SOCKS5 用户名或密码错误')
  }
  const hostBuf = Buffer.from(targetHost, 'utf8')
  socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]), hostBuf, Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff])]))
  const head = await readExact(socket, 4, timeoutMs)
  if (head[1] !== 0x00) throw new Error(`SOCKS5 CONNECT 失败: 0x${head[1].toString(16)}`)
  let addressLength = 0
  if (head[3] === 0x01) addressLength = 4
  else if (head[3] === 0x04) addressLength = 16
  else if (head[3] === 0x03) addressLength = (await readExact(socket, 1, timeoutMs))[0]
  await readExact(socket, addressLength + 2, timeoutMs)
  return socket
}

async function testSocks5(rawUrl) {
  const url = new URL(rawUrl)
  const scheme = url.protocol.replace(':', '').toLowerCase()
  if (scheme !== 'socks5' && scheme !== 'socks5h') throw new Error('当前验活只支持 socks5/socks5h')
  const started = Date.now()
  const socket = await socks5Connect(rawUrl, 'api.ipify.org', 443, 8000)
  const secure = tls.connect({ socket, servername: 'api.ipify.org', rejectUnauthorized: true })
  const response = await new Promise((resolve, reject) => {
    let data = ''
    const timer = setTimeout(() => { secure.destroy(); reject(new Error('出口 IP 请求超时')) }, 10000)
    secure.setEncoding('utf8')
    secure.on('data', (chunk) => { data += chunk })
    secure.once('error', (error) => { clearTimeout(timer); reject(error) })
    secure.once('end', () => { clearTimeout(timer); resolve(data) })
    secure.once('secureConnect', () => {
      secure.write('GET /?format=json HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\nUser-Agent: cac-account-manager\r\n\r\n')
    })
  })
  secure.destroy()
  const body = String(response).split(/\r?\n\r?\n/).slice(1).join('\n').trim()
  let externalIp = body
  try { externalIp = JSON.parse(body).ip || body } catch { }
  return { success: true, latencyMs: Date.now() - started, externalIp: String(externalIp).slice(0, 100), dnsMode: 'remote-hostname-atyp-3' }
}

async function saveAccount(input) {
  const existing = input?.id ? state.accounts.find((item) => item.id === input.id) : null
  const account = normalizeAccount(input || {}, existing)
  const duplicate = state.accounts.find((item) => item.id !== account.id && account.email && item.email.toLowerCase() === account.email.toLowerCase())
  if (duplicate) throw new Error(`邮箱已存在于账号 ${duplicate.label || duplicate.profileName}`)
  await ensureProfile(account.profileName)
  if (existing && existing.profileName !== account.profileName) {
    try {
      await runProxyScript(['-Action', 'unbind', '-AccountKey', `desktop:${existing.profileName}`])
    } catch (error) {
      await recordEvent('warn', `${existing.label || existing.profileName} 旧代理绑定清理失败: ${error.message}`)
    }
  }
  if (account.proxyId) await bindProxy(account, account.proxyId)
  else if (existing?.proxyId) {
    try { await runProxyScript(['-Action', 'unbind', '-AccountKey', `desktop:${account.profileName}`]) } catch { }
  }
  const index = state.accounts.findIndex((item) => item.id === account.id)
  if (index >= 0) state.accounts[index] = account
  else state.accounts.push(account)
  if (!state.selectedAccountId) state.selectedAccountId = account.id
  await saveState()
  await recordEvent('info', `${account.label || account.profileName} 已保存`)
  return safeAccountForRenderer(account)
}

async function deleteAccount(accountId) {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  if (account.status === 'running') await stopAccount(account)
  try { await runProxyScript(['-Action', 'unbind', '-AccountKey', `desktop:${account.profileName}`]) } catch { }
  state.accounts = state.accounts.filter((item) => item.id !== accountId)
  if (state.selectedAccountId === accountId) state.selectedAccountId = state.accounts[0]?.id || null
  await saveState()
  await recordEvent('info', `${account.label || account.profileName} 已从管理器移除（Profile 数据保留）`)
  return true
}

async function exportAccounts(options = {}) {
  const includeSecrets = options.includeSecrets === true
  const selectedIds = Array.isArray(options.accountIds) && options.accountIds.length ? new Set(options.accountIds) : null
  const accounts = state.accounts.filter((account) => !selectedIds || selectedIds.has(account.id)).map((account) => {
    const output = { ...account, session: { ...account.session } }
    if (!includeSecrets) output.session.encryptedCookies = null
    return output
  })
  const payload = {
    format: 'cac-account-manager',
    schemaVersion: SCHEMA_VERSION,
    exportedAt: nowIso(),
    encryption: includeSecrets ? (safeStorageAvailable() ? 'electron-safeStorage-dpapi' : 'unavailable') : 'metadata-only',
    accounts
  }
  const result = await dialog.showSaveDialog(mainWindow, {
    title: '导出账号 JSON',
    defaultPath: path.join(os.homedir(), `cac-accounts-${new Date().toISOString().slice(0, 10)}.json`),
    filters: [{ name: 'JSON', extensions: ['json'] }]
  })
  if (result.canceled || !result.filePath) return { canceled: true }
  await atomicWriteJson(result.filePath, payload)
  await recordEvent('info', `已导出 ${accounts.length} 个账号到 ${path.basename(result.filePath)}`)
  return { canceled: false, path: result.filePath, count: accounts.length, includeSecrets }
}

async function importAccounts() {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: '导入账号 JSON',
    properties: ['openFile'],
    filters: [{ name: 'JSON', extensions: ['json'] }]
  })
  if (result.canceled || !result.filePaths[0]) return { canceled: true }
  const imported = JSON.parse(await fs.readFile(result.filePaths[0], 'utf8'))
  const items = Array.isArray(imported) ? imported : imported.accounts
  if (!Array.isArray(items)) throw new Error('JSON 必须包含 accounts 数组')
  let added = 0
  let updated = 0
  for (const item of items) {
    const existing = item?.id ? state.accounts.find((account) => account.id === item.id) : null
    const account = normalizeAccount(item || {}, existing)
    await ensureProfile(account.profileName)
    if (account.proxyId) {
      try { await bindProxy(account, account.proxyId) } catch (error) { await recordEvent('warn', `${account.label} 代理绑定失败: ${error.message}`) }
    }
    const index = state.accounts.findIndex((candidate) => candidate.id === account.id)
    if (index >= 0) { state.accounts[index] = account; updated++ } else { state.accounts.push(account); added++ }
  }
  if (!state.selectedAccountId) state.selectedAccountId = state.accounts[0]?.id || null
  await saveState()
  await recordEvent('info', `已导入账号 ${added + updated} 个，新增 ${added}，更新 ${updated}`)
  return { canceled: false, added, updated }
}

function registerIpc() {
  ipcMain.handle('manager:get-state', () => stateForRenderer())
  ipcMain.handle('manager:save-account', (_event, input) => saveAccount(input))
  ipcMain.handle('manager:delete-account', (_event, accountId) => deleteAccount(String(accountId)))
  ipcMain.handle('manager:activate-account', (_event, accountId) => activateAccount(String(accountId)))
  ipcMain.handle('manager:stop-account', async (_event, accountId) => {
    const account = state.accounts.find((item) => item.id === String(accountId))
    if (!account) throw new Error('账号不存在')
    await stopAccount(account)
    await saveState()
    await recordEvent('info', `${account.label || account.profileName} 已停止`)
    return safeAccountForRenderer(account)
  })
  ipcMain.handle('manager:open-login', (_event, accountId) => openLogin(String(accountId)))
  ipcMain.handle('manager:restore-session', (_event, accountId) => restoreSession(String(accountId)))
  ipcMain.handle('manager:clear-session', (_event, accountId) => clearSession(String(accountId)))
  ipcMain.handle('manager:export', (_event, options) => exportAccounts(options))
  ipcMain.handle('manager:import', () => importAccounts())
  ipcMain.handle('manager:list-proxies', () => readProxyState())
  ipcMain.handle('manager:add-proxy', async (_event, rawUrl) => {
    const inputValue = String(rawUrl || '').trim()
    if (!inputValue) throw new Error('代理地址不能为空')
    const value = /^[a-z][a-z0-9+.-]*:\/\//i.test(inputValue) ? inputValue : `socks5h://${inputValue}`
    const parsed = new URL(value)
    const protocol = parsed.protocol.toLowerCase()
    if (protocol !== 'socks5:' && protocol !== 'socks5h:') throw new Error('账号管理器只接收 socks5:// 或 socks5h:// 代理')
    const result = await runProxyScript(['-Action', 'add'], { CAC_PROXY_POOL_INPUT: value })
    if (result.code !== 0) throw new Error((result.stderr || result.stdout || '代理添加失败').trim())
    await recordEvent('info', `已添加代理 ${maskProxyUrl(value)}`)
    return readProxyState()
  })
  ipcMain.handle('manager:remove-proxy', async (_event, proxyId) => {
    const result = await runProxyScript(['-Action', 'remove', '-Id', String(proxyId)])
    if (result.code !== 0) throw new Error((result.stderr || result.stdout || '代理删除失败').trim())
    for (const account of state.accounts) if (account.proxyId === String(proxyId)) account.proxyId = null
    await saveState()
    await recordEvent('info', `已删除代理 ${proxyId}`)
    return readProxyState()
  })
  ipcMain.handle('manager:bind-proxy', async (_event, accountId, proxyId) => {
    const account = state.accounts.find((item) => item.id === String(accountId))
    if (!account) throw new Error('账号不存在')
    await bindProxy(account, String(proxyId))
    await saveState()
    await recordEvent('info', `${account.label || account.profileName} 已绑定代理 ${proxyId}`)
    return { account: safeAccountForRenderer(account), pool: await readProxyState() }
  })
  ipcMain.handle('manager:unbind-proxy', async (_event, accountId) => {
    const account = state.accounts.find((item) => item.id === String(accountId))
    if (!account) throw new Error('账号不存在')
    const result = await runProxyScript(['-Action', 'unbind', '-AccountKey', `desktop:${account.profileName}`])
    if (result.code !== 0) throw new Error((result.stderr || result.stdout || '代理解绑失败').trim())
    account.proxyId = null
    await saveState()
    await recordEvent('info', `${account.label || account.profileName} 已解绑代理`)
    return { account: safeAccountForRenderer(account), pool: await readProxyState() }
  })
  ipcMain.handle('manager:test-proxy', async (_event, proxyId) => {
    const proxy = await readRawProxy(String(proxyId))
    if (!proxy) throw new Error('代理不存在')
    const result = await testSocks5(String(proxy.url))
    await recordEvent('info', `${proxyId} 验活成功，出口 ${result.externalIp}，${result.latencyMs}ms`)
    return result
  })
  ipcMain.handle('manager:save-settings', async (_event, input) => {
    const desktopExe = String(input?.desktopExe || '').trim()
    if (!desktopExe) throw new Error('Desktop 可执行文件路径不能为空')
    state.settings.desktopExe = desktopExe
    state.settings.launchInject = input?.launchInject !== false
    state.settings.launchFingerprint = input?.launchFingerprint === true
    state.settings.loginUrl = normalizeLoginUrl(input?.loginUrl || state.settings.loginUrl)
    state.settings.accountsPerProxy = Math.max(1, Math.min(100, Number(input?.accountsPerProxy) || 2))
    state.settings.warningMultiplier = Math.max(1, Math.min(20, Number(input?.warningMultiplier) || 2))
    state.settings.autoBind = input?.autoBind !== false
    await saveState()
    const poolResult = await runProxyScript([
      '-Action', 'settings',
      '-AccountsPerProxy', String(state.settings.accountsPerProxy),
      '-WarningMultiplier', String(state.settings.warningMultiplier),
      ...(state.settings.autoBind ? [] : ['-DisableAuto'])
    ])
    if (poolResult.code !== 0) throw new Error((poolResult.stderr || poolResult.stdout || '代理池设置失败').trim())
    await recordEvent('info', '设置已保存')
    return stateForRenderer()
  })
  ipcMain.handle('manager:open-path', async (_event, target) => {
    const selected = target === 'data' ? path.dirname(statePath) : runtimeRoot
    await shell.openPath(selected)
    return selected
  })
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1080,
    minHeight: 680,
    backgroundColor: '#101317',
    title: 'CAC Account Manager',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  })
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'))
  mainWindow.on('closed', () => { mainWindow = null })
}

app.whenReady().then(async () => {
  app.setAppUserModelId('com.cac.windows.accountmanager')
  runtimeRoot = resolveRuntimeRoot()
  scriptRoot = path.join(runtimeRoot, 'scripts')
  statePath = path.join(app.getPath('userData'), 'accounts.json')
  await loadState()
  registerIpc()
  createMainWindow()
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createMainWindow() })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  if (loginWindow && !loginWindow.isDestroyed()) loginWindow.destroy()
})
