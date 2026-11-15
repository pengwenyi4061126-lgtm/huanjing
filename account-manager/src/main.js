'use strict'

const {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  net: electronNet,
  safeStorage,
  session,
  shell
} = require('electron')
const path = require('node:path')
const fs = require('node:fs/promises')
const fsSync = require('node:fs')
const os = require('node:os')
const crypto = require('node:crypto')
const nodeHttp = require('node:http')
const nodeNet = require('node:net')
const tls = require('node:tls')
const { spawn, spawnSync } = require('node:child_process')
const { maskProxyUrl, normalizeProxyUrl, parseProxyInput } = require('./proxy-input')
const {
  isClaudeDeepLink,
  isClaudeMagicLink,
  maskLoginTarget,
  normalizeLoginUrl,
  normalizeWebLoginTarget,
  webUrlFromClaudeDeepLink
} = require('./login-input')
const { analyzeClaudeSession, isClaudeCookie } = require('./session-status')
const {
  applyLoginSessionPersona,
  installLoginWebContentsPersona
} = require('./login-fingerprint')
const {
  assertRuntimeMatchesPersona,
  evidenceMatches,
  publicEvidence,
  verifyDeviceImage
} = require('./device-image')
const {
  chromiumCookieExpiresUtc,
  chromiumCookieTimeNow,
  chromiumSameSite,
  chromiumSourceType,
  getDesktopSessionSyncKey,
  normalizeCookieForDesktop
} = require('./desktop-cookie')

const PROJECT_ROOT = path.resolve(__dirname, '..', '..')
const DEFAULT_DESKTOP_EXE = 'C:\\Program Files\\WindowsApps\\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\\app\\claude.exe'
const PROFILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const SCHEMA_VERSION = 1
const DESKTOP_START_TIMEOUT_MS = 90000
const HOST_USERPROFILE = process.env.USERPROFILE || os.homedir()
const NATIVE_MANAGER_CHILD_SWITCH = '--cac-native-manager-child'
const LOGIN_ENV_KEYS = [
  'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'HOME', 'TEMP', 'TMP',
  'TZ',
  'CLAUDE_CONFIG_DIR', 'CAC_PROFILE_DIR', 'CAC_PROFILE_IDENTITY',
  'CAC_HOSTNAME', 'CAC_MACHINE_ID', 'CAC_MAC', 'CAC_USERNAME',
  'CAC_NATIVE_READ_POLICY', 'CAC_NATIVE_CPUID_MODE', 'CAC_NATIVE_AUDIT',
  'CAC_NATIVE_DISABLE_NETWORK_HOOKS', 'CAC_NETWORK_ENFORCE', 'CAC_WFP_REQUIRED',
  'CAC_KERNEL_POLICY_REQUIRED', 'CAC_NATIVE_DLL'
]

function nativeManagerRuntime() {
  const root = app.isPackaged
    ? path.join(process.resourcesPath, 'cac-runtime', 'native', 'dist')
    : path.join(PROJECT_ROOT, 'native', 'dist')
  return {
    root,
    launcher: path.join(root, 'cac-native-launch.exe'),
    bridge: path.join(root, 'NativeBridge.dll')
  }
}

function bootstrapNativeManager() {
  if (process.platform !== 'win32' || process.env.CAC_NATIVE_MANAGER_CHILD === '1' ||
      process.argv.includes(NATIVE_MANAGER_CHILD_SWITCH)) return false
  const native = nativeManagerRuntime()
  if (!fsSync.existsSync(native.launcher) || !fsSync.existsSync(native.bridge)) return false

  const auditPath = path.join(
    process.env.LOCALAPPDATA || os.tmpdir(),
    'CAC Account Manager',
    'audit',
    'native-manager.jsonl'
  )
  fsSync.mkdirSync(path.dirname(auditPath), { recursive: true })
  const launcherLogPath = path.join(path.dirname(auditPath), 'native-launch.log')
  const launcherLogFd = fsSync.openSync(launcherLogPath, 'a')
  const env = {
    ...process.env,
    CAC_NATIVE_MANAGER_CHILD: '1',
    CAC_NATIVE_DLL: native.bridge,
    CAC_NATIVE_AUDIT: auditPath,
    CAC_NATIVE_READ_POLICY: 'profile',
    CAC_NATIVE_CPUID_MODE: 'neutral',
    CAC_NATIVE_DISABLE_NETWORK_HOOKS: '1',
    CAC_NETWORK_ENFORCE: '0',
    CAC_WFP_REQUIRED: '0',
    CAC_KERNEL_POLICY_REQUIRED: '0'
  }
  let result
  try {
    const forwardedArgs = process.argv.slice(1).filter((arg) => arg !== NATIVE_MANAGER_CHILD_SWITCH)
    result = spawnSync(native.launcher, [process.execPath, ...forwardedArgs, NATIVE_MANAGER_CHILD_SWITCH], {
      cwd: process.cwd(),
      env,
      windowsHide: true,
      stdio: ['ignore', launcherLogFd, launcherLogFd]
    })
  } finally {
    try { fsSync.closeSync(launcherLogFd) } catch { }
  }
  if (result?.error) {
    try { fsSync.appendFileSync(launcherLogPath, `[bootstrap] ${result.error.stack || result.error.message || result.error}\n`) } catch { }
  }
  process.exit(Number.isInteger(result?.status) ? result.status : 1)
  return true
}

// The login window is part of the identity boundary. Start the manager through
// the verified launcher so future Electron renderer/utility children inherit
// NativeBridge before navigation begins.
bootstrapNativeManager()

// Keep the login Chromium instance fail-closed for resolver, QUIC and non-proxied
// WebRTC traffic. The login session itself still receives a per-profile proxy
// through session.setProxy().
app.commandLine.appendSwitch('host-resolver-rules', 'MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1, EXCLUDE ::1')
app.commandLine.appendSwitch('disable-quic')
app.commandLine.appendSwitch('force-webrtc-ip-handling-policy', 'disable_non_proxied_udp')
if (process.env.CAC_NATIVE_MANAGER_CHILD === '1') {
  // NativeBridge must load before Chromium renderer/GPU code initializes. The
  // unsigned local bridge cannot be loaded inside ACG/CIG-protected sandboxes.
  app.commandLine.appendSwitch('no-sandbox')
  app.commandLine.appendSwitch('disable-gpu-sandbox')
}

let mainWindow = null
let loginWindow = null
let loginAccountId = null
let loginRelay = null
let loginCaptureTimer = null
let loginCaptureRunning = false
let loginCapturePending = false
let loginCookieListener = null
let loginNativeEnvPrevious = null
let loginOpenInProgress = false
const activationLocks = new Map()
let statePath = ''
let state = null
let runtimeRoot = PROJECT_ROOT
let scriptRoot = path.join(PROJECT_ROOT, 'scripts')
let runtimeWatchTimer = null
let runtimeReconcileInFlight = false
const hasSingleInstanceLock = app.requestSingleInstanceLock()
if (!hasSingleInstanceLock) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (!mainWindow || mainWindow.isDestroyed()) return
    if (mainWindow.isMinimized()) mainWindow.restore()
    mainWindow.show()
    mainWindow.focus()
  })
}

function nowIso() {
  return new Date().toISOString()
}

function isPidAlive(pid) {
  const numericPid = Number(pid)
  if (!Number.isInteger(numericPid) || numericPid <= 0) return false
  try {
    process.kill(numericPid, 0)
    return true
  } catch (error) {
    return error?.code === 'EPERM'
  }
}

function reconcileRuntimeState() {
  const recovered = []
  for (const account of state?.accounts || []) {
    const tracked = account.status === 'running' || account.status === 'starting' || Boolean(account.runtimePid)
    if (!tracked || isPidAlive(account.runtimePid)) continue
    account.runtimePid = null
    account.status = account.session?.authenticated === true && Number(account.session?.cookieCount || 0) > 0
      ? 'logged-in'
      : 'ready'
    account.updatedAt = nowIso()
    recovered.push(account.label || account.profileName)
  }
  return recovered
}

async function reconcileRuntimeStateAndPersist() {
  if (runtimeReconcileInFlight || !state) return
  const recovered = reconcileRuntimeState()
  if (!recovered.length) return
  runtimeReconcileInFlight = true
  try {
    await saveState()
    await recordEvent('warn', `检测到 Desktop 进程已退出，已恢复账号状态: ${recovered.join('、')}`)
  } finally {
    runtimeReconcileInFlight = false
  }
}

function startRuntimeStateWatch() {
  if (runtimeWatchTimer) clearInterval(runtimeWatchTimer)
  runtimeWatchTimer = setInterval(() => {
    void reconcileRuntimeStateAndPersist()
  }, 5000)
  runtimeWatchTimer.unref?.()
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
      launchFingerprint: true,
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

function findProfileOwner(profileName, accountId = '') {
  const normalized = String(profileName || '').toLowerCase()
  return state?.accounts?.find((item) => item.id !== accountId && String(item.profileName || '').toLowerCase() === normalized) || null
}

function normalizeAccount(input, existing) {
  const base = existing || {}
  const profileName = normalizeProfileName(input.profileName || base.profileName || 'default')
  const label = String(input.label ?? base.label ?? input.email ?? base.email ?? profileName).trim().slice(0, 80)
  const email = String(input.email ?? base.email ?? '').trim().slice(0, 320)
  const loginUrl = normalizeLoginUrl(input.loginUrl || base.loginUrl || state?.settings?.loginUrl)
  const sourceSession = input.session || base.session
  const hasSavedSession = Number(sourceSession?.cookieCount || 0) > 0 || Boolean(sourceSession?.encryptedCookies)
  const persistedStatus = String(base.status || 'ready')
  const hasAuthFlag = Boolean(sourceSession && Object.prototype.hasOwnProperty.call(sourceSession, 'authenticated'))
  let status = persistedStatus === 'starting' ? (sourceSession?.authenticated === true ? 'logged-in' : 'ready') : persistedStatus
  if (hasAuthFlag && persistedStatus === 'logged-in' && sourceSession.authenticated !== true) {
    status = hasSavedSession ? 'auth-pending' : 'ready'
  }
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
    status,
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
      authenticated: false,
      authVerifiedAt: null,
      encryptedCookies: null,
      deviceImage: null
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
    launchInject: true,
    launchFingerprint: true,
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

function desktopUserDataDir(account) {
  return path.join(
    HOST_USERPROFILE,
    '.cac',
    'desktop',
    account.profileName,
    'home',
    'AppData',
    'Roaming',
    'Claude'
  )
}

function desktopProfileRoot(account) {
  return path.join(
    HOST_USERPROFILE,
    '.cac',
    'desktop',
    account.profileName
  )
}

function loginSessionPath(account) {
  return path.join(desktopProfileRoot(account), 'login-session')
}

function accountLoginSession(account) {
  const root = loginSessionPath(account)
  fsSync.mkdirSync(root, { recursive: true })
  return session.fromPath(root)
}

function configureLoginNativeEnvironment(account) {
  if (process.platform === 'win32' && process.env.CAC_NATIVE_MANAGER_CHILD !== '1') {
    throw new Error('账号管理器未通过 NativeBridge 启动，已阻止未覆盖硬件画像的网页登录')
  }
  if (process.platform === 'win32') {
    const managerAudit = readNativeAuditEvents(process.env.CAC_NATIVE_AUDIT || '')
    const managerReady = managerAudit.some((event) =>
      Number(event.pid) === process.pid && event.surface === 'native.bridge' && event.action === 'ready'
    )
    if (!managerReady) throw new Error('账号管理器 NativeBridge 没有 ready 证据，已阻止未审计的网页登录')
  }
  const profileRoot = desktopProfileRoot(account)
  const identityPath = path.join(profileRoot, 'identity.json')
  const auditDir = path.join(profileRoot, 'audit')
  const auditPath = path.join(auditDir, 'login-native.jsonl')
  if (!fsSync.existsSync(identityPath)) throw new Error(`Profile identity.json 不存在: ${identityPath}`)
  fsSync.mkdirSync(auditDir, { recursive: true })
  try { fsSync.rmSync(auditPath, { force: true }) } catch { }
  let identity
  try {
    identity = JSON.parse(fsSync.readFileSync(identityPath, 'utf8'))
  } catch (error) {
    throw new Error(`Profile identity.json 无法读取: ${error.message}`)
  }
  const native = nativeManagerRuntime()
  if (process.platform === 'win32' && !fsSync.existsSync(native.bridge)) {
    throw new Error(`NativeBridge.dll 不存在: ${native.bridge}`)
  }
  const readProfileFileValue = (name, fallback) => {
    try {
      const value = fsSync.readFileSync(path.join(profileRoot, name), 'utf8').trim()
      return value || fallback
    } catch {
      return fallback
    }
  }
  // Match the desktop launch exactly: these must mirror
  // scripts/desktop-profile.ps1, or login and session fingerprints diverge.
  const nativeReadPolicy = readProfileFileValue('native_read_policy', 'profile') === 'empty'
    ? 'empty' : 'profile'
  let cpuidMode = readProfileFileValue('cpuid_mode', 'neutral')
  if (!['neutral', 'empty', 'passthrough'].includes(cpuidMode)) {
    cpuidMode = nativeReadPolicy === 'empty' ? 'empty' : 'neutral'
  }
  const tzValue = readProfileFileValue('tz', '')
  const env = {
    APPDATA: path.join(profileRoot, 'home', 'AppData', 'Roaming'),
    LOCALAPPDATA: path.join(profileRoot, 'home', 'AppData', 'Local'),
    USERPROFILE: path.join(profileRoot, 'home'),
    HOME: path.join(profileRoot, 'home'),
    CLAUDE_CONFIG_DIR: path.join(profileRoot, 'config'),
    CAC_PROFILE_DIR: profileRoot,
    CAC_PROFILE_IDENTITY: identityPath,
    CAC_HOSTNAME: String(identity.hostname || ''),
    CAC_MACHINE_ID: String(identity.machine_id || ''),
    CAC_MAC: String(identity.mac_address || ''),
    CAC_USERNAME: String(identity.username || ''),
    CAC_NATIVE_READ_POLICY: nativeReadPolicy,
    CAC_NATIVE_CPUID_MODE: cpuidMode,
    CAC_NATIVE_AUDIT: auditPath,
    CAC_NATIVE_DISABLE_NETWORK_HOOKS: '1',
    CAC_NETWORK_ENFORCE: '1',
    CAC_WFP_REQUIRED: '1',
    CAC_KERNEL_POLICY_REQUIRED: '0',
    CAC_NATIVE_DLL: native.bridge,
    TEMP: path.join(profileRoot, 'temp'),
    TMP: path.join(profileRoot, 'temp')
  }
  loginNativeEnvPrevious = Object.fromEntries(LOGIN_ENV_KEYS.map((key) => [key, process.env[key]]))
  for (const [key, value] of Object.entries(env)) {
    if (value) process.env[key] = value
  }
  if (tzValue) process.env.TZ = tzValue
  for (const directory of [env.APPDATA, env.LOCALAPPDATA, env.USERPROFILE, env.CLAUDE_CONFIG_DIR]) {
    fsSync.mkdirSync(directory, { recursive: true })
  }
  fsSync.mkdirSync(env.TEMP, { recursive: true })
  return { profileRoot, identityPath, auditPath, native }
}

function restoreLoginNativeEnvironment() {
  if (!loginNativeEnvPrevious) return
  for (const key of LOGIN_ENV_KEYS) {
    const value = loginNativeEnvPrevious[key]
    if (typeof value === 'undefined') delete process.env[key]
    else process.env[key] = value
  }
  loginNativeEnvPrevious = null
}

function readNativeAuditEvents(auditPath) {
  try {
    return fsSync.readFileSync(auditPath, 'utf8').split(/\r?\n/).map((line) => {
      try { return JSON.parse(line) } catch { return null }
    }).filter(Boolean)
  } catch {
    return []
  }
}

async function waitForNativeBridgeReady(auditPath, pid, timeoutMs = 20000) {
  const targetPid = Number(pid)
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const events = readNativeAuditEvents(auditPath).filter((event) => Number(event.pid) === targetPid)
    const failed = events.find((event) => event.surface === 'native.bridge' && event.action === 'failed')
    if (failed) throw new Error(`网页登录 NativeBridge 初始化失败（PID ${targetPid}）`)
    const attached = events.some((event) => event.surface === 'native.bridge' && event.action === 'attach')
    const ready = events.some((event) => event.surface === 'native.bridge' && event.action === 'ready')
    if (attached && ready) return { pid: targetPid, events }
    await sleep(100)
  }
  throw new Error(`网页登录 renderer/utility NativeBridge 未就绪（PID ${targetPid}）`)
}

async function loadLockedDeviceImage(account, options = {}) {
  const profileRoot = desktopProfileRoot(account)
  const identityPath = path.join(profileRoot, 'identity.json')
  const personaPath = path.join(profileRoot, 'fingerprint.json')
  const lockPath = path.join(profileRoot, 'device-image.lock.json')
  let identityBuffer
  let personaBuffer
  let lock
  try {
    const [identityBytes, personaBytes, lockText] = await Promise.all([
      fs.readFile(identityPath),
      fs.readFile(personaPath),
      fs.readFile(lockPath, 'utf8')
    ])
    identityBuffer = identityBytes
    personaBuffer = personaBytes
    lock = JSON.parse(lockText.replace(/^\uFEFF/, ''))
  } catch (error) {
    throw new Error(`Profile device image cannot be read: ${error.message}`)
  }
  const evidence = verifyDeviceImage({
    profileName: account.profileName,
    identityBuffer,
    personaBuffer,
    lock
  })
  if (options.requireRuntime === true) assertRuntimeMatchesPersona(evidence.persona)
  return evidence
}

async function loadDesktopFingerprint(account) {
  const shimPath = path.join(runtimeRoot, 'scripts', 'fingerprint-shim.js')
  const [evidence, shim] = await Promise.all([
    loadLockedDeviceImage(account, { requireRuntime: true }),
    fs.readFile(shimPath, 'utf8')
  ])
  const serialized = JSON.stringify(evidence.persona).replace(/</g, '\\u003c')
  return {
    evidence: publicEvidence(evidence),
    persona: evidence.persona,
    script: `window.__CAC_PERSONA__=${serialized};\n${shim}`
  }
}

function desktopCookieDbCandidates(account) {
  const userDataDir = desktopUserDataDir(account)
  return [
    path.join(userDataDir, 'Network', 'Cookies'),
    path.join(userDataDir, 'Cookies'),
    path.join(userDataDir, 'Default', 'Network', 'Cookies'),
    path.join(userDataDir, 'Default', 'Cookies')
  ]
}

function desktopCookieDbPath(account) {
  const candidates = desktopCookieDbCandidates(account)
  return candidates.find((candidate) => fsSync.existsSync(candidate)) || candidates[0]
}

function openDesktopCookieDatabase(cookieDbPath) {
  let DatabaseSync
  try {
    ({ DatabaseSync } = require('node:sqlite'))
  } catch (error) {
    throw new Error(`当前 Electron 运行时不支持 SQLite Cookie 同步: ${error.message}`)
  }
  fsSync.mkdirSync(path.dirname(cookieDbPath), { recursive: true })
  return new DatabaseSync(cookieDbPath)
}

function ensureDesktopCookieSchema(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS cookies(
      creation_utc INTEGER NOT NULL,
      host_key TEXT NOT NULL,
      top_frame_site_key TEXT NOT NULL,
      name TEXT NOT NULL,
      value TEXT NOT NULL,
      encrypted_value BLOB NOT NULL,
      path TEXT NOT NULL,
      expires_utc INTEGER NOT NULL,
      is_secure INTEGER NOT NULL,
      is_httponly INTEGER NOT NULL,
      last_access_utc INTEGER NOT NULL,
      has_expires INTEGER NOT NULL,
      is_persistent INTEGER NOT NULL,
      priority INTEGER NOT NULL,
      samesite INTEGER NOT NULL,
      source_scheme INTEGER NOT NULL,
      source_port INTEGER NOT NULL,
      last_update_utc INTEGER NOT NULL,
      source_type INTEGER NOT NULL,
      has_cross_site_ancestor INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS cookies_unique_index
      ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port);
  `)
  const columns = new Set(database.prepare('PRAGMA table_info(cookies)').all().map((row) => String(row.name)))
  const required = [
    'creation_utc', 'host_key', 'top_frame_site_key', 'name', 'value',
    'encrypted_value', 'path', 'expires_utc', 'is_secure', 'is_httponly',
    'last_access_utc', 'has_expires', 'is_persistent', 'priority', 'samesite',
    'source_scheme', 'source_port', 'last_update_utc', 'source_type',
    'has_cross_site_ancestor'
  ]
  const missing = required.filter((column) => !columns.has(column))
  if (missing.length) throw new Error(`Claude Cookies 数据库结构不完整，缺少: ${missing.join(', ')}`)
}

function syncDesktopCookieDatabase(account, cookies, options = {}) {
  const normalizedCookies = (Array.isArray(cookies) ? cookies : [])
    .map(normalizeCookieForDesktop)
    .filter(Boolean)
  const cookieDbPath = desktopCookieDbPath(account)
  const database = openDesktopCookieDatabase(cookieDbPath)
  const nowChromium = chromiumCookieTimeNow()
  let imported = 0
  let removed = 0
  try {
    database.exec('PRAGMA busy_timeout = 5000')
    ensureDesktopCookieSchema(database)
    database.exec('BEGIN IMMEDIATE')
    const removeClaudeCookies = database.prepare(`
      DELETE FROM cookies
      WHERE lower(host_key) = 'claude.ai'
         OR lower(host_key) LIKE '%.claude.ai'
         OR lower(host_key) = 'claude.com'
         OR lower(host_key) LIKE '%.claude.com'
    `)
    const removeResult = removeClaudeCookies.run()
    removed = Number(removeResult.changes || 0)

    const insertCookie = database.prepare(`
      INSERT INTO cookies(
        creation_utc, host_key, top_frame_site_key, name, value, encrypted_value,
        path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires,
        is_persistent, priority, samesite, source_scheme, source_port,
        last_update_utc, source_type, has_cross_site_ancestor
      ) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 2, 443, ?, ?, 1)
      ON CONFLICT(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port)
      DO UPDATE SET
        value = excluded.value,
        encrypted_value = excluded.encrypted_value,
        expires_utc = excluded.expires_utc,
        is_secure = excluded.is_secure,
        is_httponly = excluded.is_httponly,
        last_access_utc = excluded.last_access_utc,
        has_expires = excluded.has_expires,
        is_persistent = excluded.is_persistent,
        samesite = excluded.samesite,
        last_update_utc = excluded.last_update_utc,
        source_type = excluded.source_type
    `)
    for (const cookie of normalizedCookies) {
      const expiresUtc = chromiumCookieExpiresUtc(cookie)
      const persistent = expiresUtc > 0 ? 1 : 0
      insertCookie.run(
        nowChromium,
        String(cookie.domain || 'claude.ai').trim() || 'claude.ai',
        cookie.name,
        cookie.value,
        Buffer.alloc(0),
        cookie.path || '/',
        expiresUtc,
        cookie.secure ? 1 : 0,
        cookie.httpOnly ? 1 : 0,
        nowChromium,
        persistent,
        persistent,
        chromiumSameSite(cookie),
        nowChromium,
        chromiumSourceType(cookie)
      )
      imported++
    }
    database.exec('COMMIT')

    const requiredRows = database.prepare(`
      SELECT host_key AS domain, name, value
      FROM cookies
      WHERE name IN ('sessionKey', 'sessionKeyV2', 'sessionKeyV3', 'lastActiveOrg')
        AND length(value) > 0
        AND (
          lower(host_key) = 'claude.ai' OR lower(host_key) LIKE '%.claude.ai'
          OR lower(host_key) = 'claude.com' OR lower(host_key) LIKE '%.claude.com'
        )
    `).all()
    const auth = analyzeClaudeSession(requiredRows)
    if (options.requireAuth !== false && !auth.authenticated) {
      throw new Error(`Claude Desktop Cookie 写入后未检测到完整登录态（${cookieDbPath}）`)
    }
    return { ...auth, cookieDbPath, imported, removed }
  } catch (error) {
    try { database.exec('ROLLBACK') } catch { }
    throw error
  } finally {
    try { database.close() } catch { }
  }
}

async function importCookiesIntoDesktopProfile(account, cookies) {
  const claudeCookies = (Array.isArray(cookies) ? cookies : []).filter(isClaudeCookie)
  const auth = analyzeClaudeSession(claudeCookies)
  if (!auth.authenticated) throw new Error('网页登录会话不完整，缺少 sessionKey 和有效 lastActiveOrg')
  if (account.status === 'running' || account.runtimePid) await stopAccount(account)
  const result = syncDesktopCookieDatabase(account, claudeCookies)
  account.session = {
    ...account.session,
    desktopSessionSyncKey: getDesktopSessionSyncKey(claudeCookies),
    desktopSessionSyncedAt: nowIso(),
    desktopSessionSyncError: null
  }
  account.updatedAt = nowIso()
  return result
}

async function clearDesktopCookies(account) {
  if (account.status === 'running' || account.runtimePid) await stopAccount(account)
  return syncDesktopCookieDatabase(account, [], { requireAuth: false })
}

async function backupUnreadableState() {
  if (!statePath || !fsSync.existsSync(statePath)) return null
  const backupPath = `${statePath}.corrupt.${Date.now()}.json`
  try {
    await fs.rename(statePath, backupPath)
    return backupPath
  } catch {
    try {
      await fs.copyFile(statePath, backupPath)
      return backupPath
    } catch {
      return null
    }
  }
}

async function loadState() {
  try {
    const raw = JSON.parse(await fs.readFile(statePath, 'utf8'))
    state = normalizeState(raw)
  } catch (error) {
    if (error.code !== 'ENOENT') {
      const backupPath = await backupUnreadableState()
      console.warn(`[manager] state read failed: ${error.message}${backupPath ? `; backup=${backupPath}` : ''}`)
    }
    state = defaultState()
  }
  const recovered = reconcileRuntimeState()
  await saveState()
  if (recovered.length) {
    await recordEvent('warn', `检测到 Desktop 进程已退出，已恢复账号状态: ${recovered.join('、')}`)
  }
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
      authenticated: account.session?.authenticated === true,
      authVerifiedAt: account.session?.authVerifiedAt || null,
      desktopSessionSyncedAt: account.session?.desktopSessionSyncedAt || null,
      desktopSessionSyncError: account.session?.desktopSessionSyncError || null,
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

function runPowerShell(argumentsList, extraEnv = {}, options = {}) {
  return new Promise((resolve, reject) => {
    const fileCapture = options.fileCapture === true
    const timeoutMs = Math.max(0, Number(options.timeoutMs || 0))
    let captureDir = null
    let stdoutPath = null
    let stderrPath = null
    let timer = null
    let settled = false
    const cleanupCapture = () => {
      if (!captureDir) return
      try { fsSync.rmSync(captureDir, { recursive: true, force: true }) } catch { }
      captureDir = null
    }
    const finish = (error, value) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      cleanupCapture()
      if (error) reject(error)
      else resolve(value)
    }

    let child
    let stdout = ''
    let stderr = ''
    try {
      let stdio = ['ignore', 'pipe', 'pipe']
      if (fileCapture) {
        captureDir = fsSync.mkdtempSync(path.join(os.tmpdir(), 'cac-powershell-'))
        stdoutPath = path.join(captureDir, 'stdout.log')
        stderrPath = path.join(captureDir, 'stderr.log')
        const stdoutFd = fsSync.openSync(stdoutPath, 'a')
        const stderrFd = fsSync.openSync(stderrPath, 'a')
        stdio = ['ignore', stdoutFd, stderrFd]
        child = spawn('powershell.exe', [
          '-NoLogo',
          '-NoProfile',
          '-ExecutionPolicy',
          'Bypass',
          ...argumentsList
        ], {
          cwd: runtimeRoot,
          windowsHide: true,
          env: { ...process.env, ...extraEnv },
          stdio
        })
        try { fsSync.closeSync(stdoutFd) } catch { }
        try { fsSync.closeSync(stderrFd) } catch { }
      } else {
        child = spawn('powershell.exe', [
          '-NoLogo',
          '-NoProfile',
          '-ExecutionPolicy',
          'Bypass',
          ...argumentsList
        ], {
          cwd: runtimeRoot,
          windowsHide: true,
          env: { ...process.env, ...extraEnv },
          stdio
        })
        child.stdout.setEncoding('utf8')
        child.stderr.setEncoding('utf8')
        child.stdout.on('data', (chunk) => { stdout += chunk })
        child.stderr.on('data', (chunk) => { stderr += chunk })
      }
    } catch (error) {
      finish(error)
      return
    }

    const readCaptured = (filePath) => {
      try { return fsSync.readFileSync(filePath, 'utf8') } catch { return '' }
    }
    const complete = (code) => {
      if (fileCapture) {
        stdout = readCaptured(stdoutPath)
        stderr = readCaptured(stderrPath)
      }
      finish(null, { code: Number(code ?? 1), stdout, stderr })
    }
    child.once('error', finish)
    if (fileCapture) child.once('exit', (code) => complete(code))
    else child.once('close', (code) => complete(code))
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        try { child.kill() } catch { }
        finish(new Error(`PowerShell 操作超时（${Math.ceil(timeoutMs / 1000)} 秒）`))
      }, timeoutMs)
    }
  })
}

async function runDesktopScript(args, extraEnv = {}, options = {}) {
  const script = path.join(scriptRoot, 'desktop-profile.ps1')
  if (!fsSync.existsSync(script)) throw new Error(`Desktop 脚本不存在: ${script}`)
  return runPowerShell(['-File', script, ...args], extraEnv, options)
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
  const url = new URL(normalizeProxyUrl(rawUrl))
  const hostPort = `${url.hostname}${url.port ? `:${url.port}` : ''}`
  const auth = url.username || url.password
    ? `${decodeURIComponent(url.username)}${url.password ? `:${decodeURIComponent(url.password)}` : ''}@`
    : ''
  const scheme = url.protocol.replace(':', '').toLowerCase()
  if (scheme === 'socks5' || scheme === 'socks5h') return `socks5://${hostPort}`
  if (scheme === 'http' || scheme === 'https') return `http=${auth}${hostPort};https=${auth}${hostPort}`
  throw new Error(`不支持的代理协议: ${scheme}`)
}

function buildLocalRelayRules(port) {
  const hostPort = `127.0.0.1:${Number(port)}`
  return `http=${hostPort};https=${hostPort}`
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

function getFreeTcpPort() {
  return new Promise((resolve, reject) => {
    const listener = nodeNet.createServer()
    listener.once('error', reject)
    listener.listen(0, '127.0.0.1', () => {
      const address = listener.address()
      const port = typeof address === 'object' && address ? Number(address.port) : 0
      listener.close((error) => error ? reject(error) : resolve(port))
    })
  })
}

async function resolveNodeExecutable() {
  const configured = String(process.env.CAC_NODE_EXECUTABLE || '').trim()
  if (configured && fsSync.existsSync(configured)) return configured
  return new Promise((resolve, reject) => {
    const lookup = spawn(process.platform === 'win32' ? 'where.exe' : 'which', [process.platform === 'win32' ? 'node.exe' : 'node'], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore']
    })
    let output = ''
    lookup.stdout.setEncoding('utf8')
    lookup.stdout.on('data', (chunk) => { output += chunk })
    lookup.once('error', reject)
    lookup.once('close', (code) => {
      const executable = output.split(/\r?\n/).map((item) => item.trim()).find(Boolean)
      if (Number(code) === 0 && executable) resolve(executable)
      else reject(new Error('找不到 node.exe，无法启动网页登录代理中继'))
    })
  })
}

function requestRelayHealth(port) {
  return new Promise((resolve, reject) => {
    const request = nodeHttp.request({
      host: '127.0.0.1',
      port,
      method: 'GET',
      path: 'http://cac-relay.local/__cac_relay_health__',
      headers: { Host: 'cac-relay.local', Connection: 'close' },
      timeout: 750,
      agent: false
    }, (response) => {
      response.resume()
      response.once('end', () => resolve({
        statusCode: Number(response.statusCode || 0),
        ready: Number(response.statusCode || 0) === 200 && String(response.headers['x-cac-relay'] || '').toLowerCase() === 'ready'
      }))
    })
    request.once('timeout', () => request.destroy(new Error('relay health timeout')))
    request.once('error', reject)
    request.end()
  })
}

async function waitForLoginRelay(relay) {
  const deadline = Date.now() + 8000
  while (Date.now() < deadline) {
    if (relay.process.exitCode !== null) throw new Error(`代理中继进程已退出（${relay.process.exitCode}）`)
    try {
      const health = await requestRelayHealth(relay.port)
      if (health.ready) return
    } catch { }
    await sleep(100)
  }
  throw new Error('代理中继启动握手超时')
}

function stopLoginRelay() {
  const relay = loginRelay
  loginRelay = null
  if (!relay) return
  const pid = Number(relay.process?.pid || 0)
  try {
    if (pid > 0 && relay.process.exitCode === null) {
      if (process.platform === 'win32') {
        const killer = spawn('taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
          windowsHide: true,
          stdio: 'ignore'
        })
        killer.unref()
      } else {
        relay.process.kill('SIGTERM')
      }
    }
  } catch { }
  try { if (relay.pidFile) fsSync.rmSync(relay.pidFile, { force: true }) } catch { }
}

async function startLoginRelay(account, proxyUrl) {
  const relayScript = path.join(runtimeRoot, 'src', 'relay.js')
  if (!fsSync.existsSync(relayScript)) throw new Error(`代理中继脚本不存在: ${relayScript}`)
  const relayDir = path.join(app.getPath('userData'), 'login-relay', String(account.id).replace(/[^A-Za-z0-9_-]/g, '_'))
  await fs.mkdir(relayDir, { recursive: true })
  const pidFile = path.join(relayDir, 'proxy-relay.pid')
  const logFile = path.join(relayDir, 'proxy-relay.log')
  try { fsSync.rmSync(pidFile, { force: true }) } catch { }

  const nodeExecutable = await resolveNodeExecutable()
  const port = await getFreeTcpPort()
  const logFd = fsSync.openSync(logFile, 'a')
  let child
  try {
    child = spawn(nodeExecutable, [relayScript, String(port), pidFile], {
      cwd: runtimeRoot,
      windowsHide: true,
      env: {
        ...process.env,
        CAC_RELAY_UPSTREAM_URL: proxyUrl,
        CAC_RELAY_PID_FILE: pidFile
      },
      stdio: ['ignore', logFd, logFd]
    })
  } finally {
    try { fsSync.closeSync(logFd) } catch { }
  }
  const relay = { accountId: account.id, proxyUrl, process: child, port, pidFile, logFile }
  loginRelay = relay
  try {
    await waitForLoginRelay(relay)
    return relay
  } catch (error) {
    stopLoginRelay()
    throw new Error(`网页登录代理中继启动失败: ${error.message}`)
  }
}

async function ensureLoginRelay(account, proxyUrl) {
  if (loginRelay && loginRelay.accountId === account.id && loginRelay.proxyUrl === proxyUrl && loginRelay.process.exitCode === null) {
    return loginRelay
  }
  stopLoginRelay()
  return startLoginRelay(account, proxyUrl)
}

async function configureLoginSession(account) {
  if (!account.proxyId) throw new Error('网页登录已禁止直连，请先为账号绑定可用的 SOCKS5 代理')
  const rawProxy = await readRawProxy(account.proxyId)
  if (!rawProxy) throw new Error(`绑定代理不存在: ${account.proxyId}`)
  if (rawProxy.enabled === false) throw new Error(`绑定代理已停用: ${account.proxyId}`)

  const proxyUrl = normalizeProxyUrl(String(rawProxy.url || ''))
  const proxy = new URL(proxyUrl)
  if (proxy.protocol !== 'socks5:' && proxy.protocol !== 'socks5h:') {
    throw new Error('网页登录必须使用 socks5:// 或 socks5h:// 代理')
  }

  const sess = accountLoginSession(account)
  const relay = await ensureLoginRelay(account, proxyUrl)
  await sess.setProxy({
    mode: 'fixed_servers',
    proxyRules: buildLocalRelayRules(relay.port),
    proxyBypassRules: '<-loopback>'
  })
  const proxyResolution = String(await sess.resolveProxy('https://claude.ai/login') || '').trim()
  if (!new RegExp(`127\\.0\\.0\\.1:${relay.port}`).test(proxyResolution) || /\bDIRECT\b/i.test(proxyResolution)) {
    throw new Error(`网页登录代理未生效（解析结果: ${proxyResolution || 'DIRECT'}）`)
  }
  return { sess, rawProxy, proxyUrl, proxyResolution, relay }
}

function requestElectronSession(sess, targetUrl, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    let request
    let settled = false
    let timer
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(value)
    }
    try {
      request = electronNet.request({ method: 'GET', session: sess, url: targetUrl })
      request.setHeader('Accept', 'application/json,text/plain;q=0.9,*/*;q=0.8')
      request.on('response', (response) => {
        let body = ''
        response.setEncoding('utf8')
        response.on('data', (chunk) => { body += chunk })
        response.once('aborted', () => finish(new Error('网页登录代理检查响应被中止')))
        response.once('error', finish)
        response.once('end', () => finish(null, { statusCode: Number(response.statusCode || 0), body }))
      })
      request.once('error', finish)
      timer = setTimeout(() => {
        try { request.abort() } catch { }
        finish(new Error('网页登录代理检查超时'))
      }, timeoutMs)
      request.end()
    } catch (error) {
      finish(error)
    }
  })
}

async function probeConfiguredLoginProxy(account, configured, announce = true) {
  const started = Date.now()
  const response = await requestElectronSession(configured.sess, 'https://api.ipify.org/?format=json')
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`网页登录代理检查 HTTP ${response.statusCode}`)
  }
  let externalIp = String(response.body || '').trim()
  try { externalIp = JSON.parse(externalIp).ip || externalIp } catch { }
  externalIp = String(externalIp).trim()
  if (!externalIp || externalIp.length > 100) throw new Error('网页登录代理检查未返回有效出口 IP')
  const result = {
    success: true,
    externalIp,
    latencyMs: Date.now() - started,
    proxy: maskProxyUrl(configured.proxyUrl),
    proxyResolution: configured.proxyResolution,
    dnsMode: '本机 HTTP 中继 -> SOCKS5/SOCKS5H 域名解析（ATYP=3）'
  }
  if (announce) {
    await recordEvent('info', `${account.label || account.profileName} 登录代理检查成功，出口 ${externalIp}，${result.latencyMs}ms`)
  }
  return result
}

async function checkLoginProxy(account) {
  const configured = await configureLoginSession(account)
  return probeConfiguredLoginProxy(account, configured, true)
}

function clearLoginCaptureTimer() {
  if (loginCaptureTimer) clearTimeout(loginCaptureTimer)
  loginCaptureTimer = null
}

function detachLoginObservers() {
  clearLoginCaptureTimer()
  loginCapturePending = false
  if (loginCookieListener) {
    try { loginCookieListener.cookies.removeListener('changed', loginCookieListener.handler) } catch { }
  }
  loginCookieListener = null
}

function queueLoginCapture(reason = 'event') {
  if (!loginAccountId) return
  clearLoginCaptureTimer()
  loginCaptureTimer = setTimeout(() => {
    loginCaptureTimer = null
    void runQueuedLoginCapture(reason)
  }, 250)
}

async function runQueuedLoginCapture(reason) {
  if (loginCaptureRunning) {
    loginCapturePending = true
    return
  }
  const account = state?.accounts.find((item) => item.id === loginAccountId)
  if (!account) return
  loginCaptureRunning = true
  try {
    await captureLoginSession(account, { reason, announce: true })
  } catch (error) {
    await recordEvent('warn', `登录会话自动保存失败: ${error.message}`)
  } finally {
    loginCaptureRunning = false
    if (loginCapturePending && loginAccountId) {
      loginCapturePending = false
      queueLoginCapture('coalesced-event')
    }
  }
}

function closeLoginWindow() {
  detachLoginObservers()
  if (loginWindow && !loginWindow.isDestroyed()) loginWindow.destroy()
  loginWindow = null
  loginAccountId = null
  stopLoginRelay()
  restoreLoginNativeEnvironment()
}

async function captureLoginSession(account, options = {}) {
  const sess = accountLoginSession(account)
  try { await sess.cookies.flushStore() } catch { }
  const cookies = (await sess.cookies.get({})).filter(isClaudeCookie)
  const auth = analyzeClaudeSession(cookies)
  const wasAuthenticated = account.session?.authenticated === true
  let deviceImage = account.session?.deviceImage || null
  if (auth.authenticated) {
    const currentDeviceImage = publicEvidence(await loadLockedDeviceImage(account))
    if (deviceImage && !evidenceMatches(deviceImage, currentDeviceImage)) {
      throw new Error('The authenticated login session does not match the locked Profile device image')
    }
    deviceImage = currentDeviceImage
  }
  const verifiedAt = auth.authenticated
    ? (account.session?.authVerifiedAt || nowIso())
    : null
  const encryptedCookies = encryptJson(cookies)
  const desktopSyncKey = auth.authenticated ? getDesktopSessionSyncKey(cookies) : ''
  let desktopSyncError = null
  let desktopSynced = false
  if (auth.authenticated && desktopSyncKey && account.session?.desktopSessionSyncKey !== desktopSyncKey) {
    try {
      await importCookiesIntoDesktopProfile(account, cookies)
      desktopSynced = true
    } catch (error) {
      desktopSyncError = error.message
      account.session = {
        ...account.session,
        desktopSessionSyncError: desktopSyncError
      }
    }
  }
  account.session = {
    ...account.session,
    savedAt: nowIso(),
    cookieCount: auth.cookieCount,
    domains: auth.domains,
    authenticated: auth.authenticated,
    authVerifiedAt: verifiedAt,
    sessionKeyName: auth.sessionKeyName,
    organizationId: auth.organizationId,
    encryptedCookies,
    deviceImage,
    desktopSessionSyncKey: desktopSynced ? desktopSyncKey : (account.session?.desktopSessionSyncKey || null),
    desktopSessionSyncedAt: desktopSynced ? nowIso() : (account.session?.desktopSessionSyncedAt || null),
    desktopSessionSyncError: desktopSyncError
  }
  if (auth.authenticated && !wasAuthenticated) account.lastLoginAt = nowIso()
  account.status = auth.authenticated ? 'logged-in' : (auth.cookieCount ? 'auth-pending' : 'ready')
  account.updatedAt = nowIso()
  await saveState()
  const reason = String(options.reason || 'manual')
  if (options.announce !== false && (auth.authenticated !== wasAuthenticated || reason === 'window-closed')) {
    const label = account.label || account.email || account.profileName
    const message = auth.authenticated
      ? (desktopSyncError
          ? `${label} 登录会话已验证并保存 ${auth.cookieCount} 个 Claude Cookie，但 Desktop 同步失败: ${desktopSyncError}`
          : `${label} 登录会话已验证、保存 ${auth.cookieCount} 个 Claude Cookie，并已同步 Desktop Profile`)
      : `${label} 已保存 ${auth.cookieCount} 个 Claude Cookie，但尚未检测到完整登录会话`
    await recordEvent(desktopSyncError ? 'warn' : (auth.authenticated ? 'info' : 'warn'), message)
  }
  return auth
}

async function openLogin(accountId, requestedUrl = '') {
  if (loginOpenInProgress) throw new Error('网页登录窗口正在初始化，请等待当前操作完成')
  loginOpenInProgress = true
  try {
    return await openLoginImpl(accountId, requestedUrl)
  } finally {
    loginOpenInProgress = false
  }
}

async function openLoginImpl(accountId, requestedUrl = '') {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  const targetUrl = normalizeWebLoginTarget(requestedUrl || account.loginUrl, account.loginUrl)
  if (loginWindow && !loginWindow.isDestroyed() && loginAccountId) {
    const previous = state.accounts.find((item) => item.id === loginAccountId)
    if (previous) {
      try {
        await captureLoginSession(previous, { reason: 'window-switch', announce: false })
      } catch (error) {
        await recordEvent('warn', `切换网页登录前保存 Cookie 失败: ${error.message}`)
      }
    }
  }
  closeLoginWindow()
  await ensureProfile(account.profileName)
  let loginNative
  let configured
  let proxyCheck
  let loginFingerprint
  try {
    loginNative = configureLoginNativeEnvironment(account)
    loginFingerprint = await loadDesktopFingerprint(account)
    if (!loginFingerprint) throw new Error('Profile 指纹配置缺失，已阻止未一致化的网页登录')
    if (account.session?.deviceImage && !evidenceMatches(account.session.deviceImage, loginFingerprint.evidence)) {
      throw new Error('Web login device image does not match the image recorded by the first login')
    }
    configured = await configureLoginSession(account)
    applyLoginSessionPersona(configured.sess, loginFingerprint.persona)
    proxyCheck = await probeConfiguredLoginProxy(account, configured, true)
  } catch (error) {
    stopLoginRelay()
    restoreLoginNativeEnvironment()
    throw error
  }
  loginAccountId = account.id
  loginWindow = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 860,
    minHeight: 620,
    title: `网页登录 - ${account.label || account.email || account.profileName}`,
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      session: configured.sess,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  })
  const currentLoginWindow = loginWindow
  const rendererPid = typeof currentLoginWindow.webContents.getOSProcessId === 'function'
    ? Number(currentLoginWindow.webContents.getOSProcessId())
    : 0
  if (!rendererPid) {
    closeLoginWindow()
    throw new Error('网页登录 renderer PID 获取失败，已阻止未审计登录')
  }
  try {
    await waitForNativeBridgeReady(loginNative.auditPath, rendererPid)
  } catch (error) {
    closeLoginWindow()
    throw error
  }
  try {
    await currentLoginWindow.loadURL('about:blank')
  } catch (error) {
    closeLoginWindow()
    throw new Error(`网页登录 renderer 初始化失败: ${error.message}`)
  }
  let fingerprintRuntime
  try {
    fingerprintRuntime = await installLoginWebContentsPersona(currentLoginWindow.webContents, loginFingerprint)
  } catch (error) {
    closeLoginWindow()
    throw new Error(`网页登录指纹运行时安装失败: ${error.message}`)
  }
  let closing = false
  const cookies = configured.sess.cookies
  const onCookieChanged = (_event, cookie) => {
    if (isClaudeCookie(cookie)) queueLoginCapture('cookie-change')
  }
  loginCookieListener = { cookies, handler: onCookieChanged }
  cookies.on('changed', onCookieChanged)
  const handleClaudeDeepLink = (event, url) => {
    if (!isClaudeDeepLink(url)) return
    event.preventDefault()
    const webUrl = webUrlFromClaudeDeepLink(url)
    if (!webUrl) return
    void currentLoginWindow.loadURL(webUrl).catch((error) => {
      void recordEvent('warn', `Magic Link 网页化跳转失败: ${error.message}`)
    })
  }
  currentLoginWindow.webContents.on('will-navigate', handleClaudeDeepLink)
  currentLoginWindow.webContents.on('will-redirect', handleClaudeDeepLink)
  currentLoginWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (!isClaudeDeepLink(url)) return { action: 'allow' }
    const webUrl = webUrlFromClaudeDeepLink(url)
    if (webUrl) {
      void currentLoginWindow.loadURL(webUrl).catch((error) => {
        void recordEvent('warn', `Magic Link 网页化打开失败: ${error.message}`)
      })
    }
    return { action: 'deny' }
  })
  currentLoginWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription, url, isMainFrame) => {
    if (!isMainFrame || Number(errorCode) === -3) return
    void recordEvent('warn', `网页登录加载失败: ${errorDescription || errorCode}（${maskLoginTarget(url)}）`)
  })
  currentLoginWindow.on('close', (event) => {
    if (closing) return
    event.preventDefault()
    captureLoginSession(account, { reason: 'window-closed', announce: true })
      .catch((error) => recordEvent('warn', `登录 Cookie 保存失败: ${error.message}`))
      .finally(() => {
        closing = true
        if (!currentLoginWindow.isDestroyed()) currentLoginWindow.close()
      })
  })
  currentLoginWindow.on('closed', () => {
    if (loginWindow !== currentLoginWindow) return
    detachLoginObservers()
    loginWindow = null
    loginAccountId = null
    stopLoginRelay()
    restoreLoginNativeEnvironment()
  })
  currentLoginWindow.webContents.on('did-navigate', () => queueLoginCapture('navigation'))
  currentLoginWindow.webContents.on('did-navigate-in-page', (_event, _url, isMainFrame) => {
    if (isMainFrame) queueLoginCapture('navigation-in-page')
  })
  currentLoginWindow.webContents.on('did-finish-load', () => queueLoginCapture('page-loaded'))
  try {
    await currentLoginWindow.loadURL(targetUrl)
  } catch (error) {
    const aborted = Number(error?.errno) === -3 || Number(error?.code) === -3 || /ERR_ABORTED/i.test(String(error?.message || error))
    const currentUrl = currentLoginWindow.isDestroyed() ? '' : currentLoginWindow.webContents.getURL()
    if (!aborted || !currentUrl || currentUrl === 'about:blank') {
      closeLoginWindow()
      throw error
    }
    await recordEvent('info', `${account.label || account.profileName} Magic Link 已转入独立网页登录会话`)
  }
  if (!currentLoginWindow.isDestroyed()) currentLoginWindow.show()
  await sleep(500)
  const childFailures = readNativeAuditEvents(loginNative.auditPath).filter((event) =>
    event.surface === 'native.child' && event.action === 'failed'
  )
  if (childFailures.length > 0) {
    closeLoginWindow()
    throw new Error(`网页登录子进程 NativeBridge 注入失败（${childFailures.length} 个）`)
  }
  queueLoginCapture('initial-load')
  const kind = isClaudeMagicLink(targetUrl) ? 'Magic Link' : '登录页'
  await recordEvent('info', `${account.label || account.profileName} 已打开网页${kind}（${maskProxyUrl(configured.proxyUrl)}，出口 ${proxyCheck.externalIp}，Native PID ${rendererPid}，指纹 ${fingerprintRuntime.mode}）`)
  return {
    opened: true,
    target: kind,
    targetUrl: maskLoginTarget(targetUrl),
    proxy: maskProxyUrl(configured.proxyUrl),
    proxyResolution: configured.proxyResolution,
    externalIp: proxyCheck.externalIp,
    nativePid: rendererPid,
    nativeAudit: loginNative.auditPath,
    fingerprintMode: fingerprintRuntime.mode,
    dnsMode: '本机 HTTP 中继 -> SOCKS5/SOCKS5H 域名解析（ATYP=3）'
  }
}

async function restoreSession(accountId) {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  const currentDeviceImage = publicEvidence(await loadLockedDeviceImage(account))
  if (account.session?.deviceImage && !evidenceMatches(account.session.deviceImage, currentDeviceImage)) {
    throw new Error('The saved login session does not match the locked Profile device image')
  }
  const cookies = decryptJson(account.session?.encryptedCookies)
  if (!Array.isArray(cookies)) throw new Error('当前机器无法解密该会话备份')
  const sess = accountLoginSession(account)
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
  let desktopSynced = false
  if (analyzeClaudeSession(cookies).authenticated) {
    const sync = await importCookiesIntoDesktopProfile(account, cookies)
    account.session = {
      ...account.session,
      deviceImage: currentDeviceImage,
      desktopSessionSyncKey: getDesktopSessionSyncKey(cookies),
      desktopSessionSyncedAt: nowIso(),
      desktopSessionSyncError: null
    }
    account.updatedAt = nowIso()
    await saveState()
    desktopSynced = sync.authenticated
  }
  await recordEvent('info', `${account.label || account.profileName} 已恢复 ${restored} 个网页登录 Cookie${desktopSynced ? '并同步 Desktop Profile' : ''}`)
  return { restored, desktopSynced }
}

async function clearSession(accountId) {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  if (loginAccountId === account.id) closeLoginWindow()
  await clearDesktopCookies(account)
  const sess = accountLoginSession(account)
  await sess.clearStorageData()
  account.session = {
    ...account.session,
    savedAt: null,
    cookieCount: 0,
    domains: [],
    authenticated: false,
    authVerifiedAt: null,
    sessionKeyName: null,
    organizationId: null,
    encryptedCookies: null,
    desktopSessionSyncKey: null,
    desktopSessionSyncedAt: null,
    desktopSessionSyncError: null
  }
  account.status = 'ready'
  account.updatedAt = nowIso()
  await saveState()
  await recordEvent('info', `${account.label || account.profileName} 的网页登录会话已清除`)
  return true
}

async function ensureProfile(profileName) {
  const result = await runDesktopScript([
    '-Action', 'create',
    '-Profile', profileName,
    '-Exe', state.settings.desktopExe,
    '-Fingerprint',
    '-SuppressProxyWarning'
  ])
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
  const result = await runDesktopScript(
    ['-Action', 'stop', '-Profile', account.profileName],
    {},
    { fileCapture: true, timeoutMs: 30000 }
  )
  if (result.code !== 0) throw new Error((result.stderr || result.stdout || 'Profile 停止失败').trim())
  account.runtimePid = null
  if (account.status === 'running') account.status = 'ready'
  account.updatedAt = nowIso()
}

async function activateAccount(accountId) {
  const key = String(accountId)
  if (activationLocks.has(key)) throw new Error('该 Profile 正在启动，请等待当前操作结束')
  const operation = activateAccountImpl(key)
  activationLocks.set(key, operation)
  try {
    return await operation
  } finally {
    if (activationLocks.get(key) === operation) activationLocks.delete(key)
  }
}

async function activateAccountImpl(accountId) {
  const account = state.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error('账号不存在')
  if (!account.enabled) throw new Error('账号已禁用')
  if (account.status === 'running' || account.runtimePid) await stopAccount(account)
  const restoreStatus = () => account.session?.authenticated === true && Number(account.session?.cookieCount || 0) > 0 ? 'logged-in' : 'ready'
  account.status = 'starting'
  account.runtimePid = null
  account.updatedAt = nowIso()
  await saveState()
  await recordEvent('info', `${account.label || account.profileName} 启动中`)

  try {
    await ensureProfile(account.profileName)
    const currentDeviceImage = publicEvidence(await loadLockedDeviceImage(account))
    if (account.session?.deviceImage && !evidenceMatches(account.session.deviceImage, currentDeviceImage)) {
      throw new Error('Desktop launch device image does not match the image recorded by the first login')
    }
    if (account.session?.authenticated !== true || Number(account.session?.cookieCount || 0) < 1) {
      throw new Error('The account has no verified first-login session; Desktop launch is blocked')
    }
    if (!account.session.deviceImage) {
      account.session = { ...account.session, deviceImage: currentDeviceImage }
      await recordEvent('info', `${account.label || account.profileName} 已迁移并锁定现有首次登录画像 ${currentDeviceImage.imageSha256.slice(0, 12)}`)
    }
    const storedCookies = decryptJson(account.session.encryptedCookies)
    if (!Array.isArray(storedCookies)) throw new Error('网页登录会话备份无法解密，禁止启动未同步登录态的 Desktop')
    const sync = await importCookiesIntoDesktopProfile(account, storedCookies)
    account.session = {
      ...account.session,
      deviceImage: currentDeviceImage,
      desktopSessionSyncKey: getDesktopSessionSyncKey(storedCookies),
      desktopSessionSyncedAt: nowIso(),
      desktopSessionSyncError: null
    }
    account.updatedAt = nowIso()
    await saveState()
    await recordEvent('info', `${account.label || account.profileName} Desktop 会话已同步（${sync.imported} 个 Cookie，${path.basename(sync.cookieDbPath)}）`)
    const pool = await readProxyState()
    const existingBinding = pool.bindings.find((item) => item.accountKey.toLowerCase() === `desktop:${account.profileName}`.toLowerCase())
    if (account.proxyId) {
      await bindProxy(account, account.proxyId)
    } else if (state.settings.autoBind && pool.settings.autoBindOnNewAccount && pool.proxies.some((item) => item.enabled !== false)) {
      await autoBindProxy(account)
    } else if (existingBinding) {
      account.proxyId = existingBinding.proxyId
    }

    if (account.proxyId) {
      const boundProxy = await readRawProxy(account.proxyId)
      if (!boundProxy || boundProxy.enabled === false) throw new Error(`绑定代理不可用: ${account.proxyId}`)
      try {
        const check = await testSocks5(String(boundProxy.url))
        await recordEvent('info', `${account.label || account.profileName} 启动前代理检查成功，出口 ${check.externalIp}`)
      } catch (error) {
        throw new Error(`启动前代理验活失败: ${error.message}`)
      }
    }

    for (const other of state.accounts) {
      if (other.id !== account.id) {
        try { await stopAccount(other) } catch (error) { await recordEvent('warn', `${other.label || other.profileName} 停止失败: ${error.message}`) }
      }
    }
    const args = [
      '-Action', 'launch',
      '-Profile', account.profileName,
      '-Exe', state.settings.desktopExe,
      '-Inject',
      '-Fingerprint'
    ]
    const result = await runDesktopScript(args, {}, { fileCapture: true, timeoutMs: DESKTOP_START_TIMEOUT_MS })
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
  } catch (error) {
    try { await stopAccount(account) } catch { }
    account.runtimePid = null
    account.status = restoreStatus()
    account.updatedAt = nowIso()
    await saveState()
    await recordEvent('error', `${account.label || account.profileName} 启动失败: ${error.message}`)
    throw error
  }
}

function createSocketConnection(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = nodeNet.createConnection({ host, port })
    let settled = false
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      socket.destroy()
      finish(new Error('代理连接超时'))
    }, timeoutMs)
    socket.once('connect', () => finish(null, socket))
    socket.once('error', (error) => finish(error))
  })
}

function createBufferedSocketReader(socket) {
  let buffer = Buffer.alloc(0)
  let failure = null
  let detached = false
  const waiters = []

  const drain = () => {
    while (waiters.length) {
      const waiter = waiters[0]
      if (failure) {
        waiters.shift()
        clearTimeout(waiter.timer)
        waiter.reject(failure)
        continue
      }
      if (buffer.length < waiter.length) return
      waiters.shift()
      clearTimeout(waiter.timer)
      const chunk = buffer.subarray(0, waiter.length)
      buffer = buffer.subarray(waiter.length)
      waiter.resolve(chunk)
    }
  }
  const fail = (error) => {
    if (!failure) failure = error instanceof Error ? error : new Error(String(error || 'SOCKS5 socket closed'))
    drain()
  }
  const onData = (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    drain()
  }
  const onError = (error) => fail(error)
  const onEnd = () => fail(new Error('SOCKS5 连接在握手完成前关闭'))
  const onClose = () => fail(new Error('SOCKS5 连接在握手完成前关闭'))

  socket.on('data', onData)
  socket.once('error', onError)
  socket.once('end', onEnd)
  socket.once('close', onClose)

  return {
    read(length, timeoutMs, label) {
      return new Promise((resolve, reject) => {
        const waiter = {
          length,
          resolve,
          reject,
          timer: setTimeout(() => {
            const index = waiters.indexOf(waiter)
            if (index >= 0) waiters.splice(index, 1)
            reject(new Error(`${label}超时`))
          }, timeoutMs)
        }
        waiters.push(waiter)
        drain()
      })
    },
    detach() {
      if (detached) return
      detached = true
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('end', onEnd)
      socket.off('close', onClose)
      if (buffer.length) socket.unshift(buffer)
      buffer = Buffer.alloc(0)
    },
    dispose() {
      if (detached) return
      detached = true
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('end', onEnd)
      socket.off('close', onClose)
      for (const waiter of waiters.splice(0)) {
        clearTimeout(waiter.timer)
        waiter.reject(failure || new Error('SOCKS5 reader closed'))
      }
      buffer = Buffer.alloc(0)
    }
  }
}

async function socks5Connect(rawUrl, targetHost, targetPort, timeoutMs = 15000) {
  const proxy = new URL(normalizeProxyUrl(rawUrl))
  const socket = await createSocketConnection(proxy.hostname, Number(proxy.port || 1080), timeoutMs)
  const reader = createBufferedSocketReader(socket)
  const username = decodeURIComponent(proxy.username || '')
  const password = decodeURIComponent(proxy.password || '')
  if (Buffer.byteLength(username) > 255 || Buffer.byteLength(password) > 255) throw new Error('SOCKS5 用户名或密码超过 255 字节')
  try {
    // Some upstream SOCKS5 gateways reject a greeting that advertises NOAUTH
    // alongside USERPASS. Credentials therefore select USERPASS alone.
    const methods = username || password ? Buffer.from([0x05, 0x01, 0x02]) : Buffer.from([0x05, 0x01, 0x00])
    socket.write(methods)
    const selected = await reader.read(2, timeoutMs, 'SOCKS5 方法协商')
    if (selected[0] !== 0x05 || selected[1] === 0xff) throw new Error('SOCKS5 不接受认证方式')
    if (selected[1] === 0x02) {
      const userBuf = Buffer.from(username)
      const passBuf = Buffer.from(password)
      socket.write(Buffer.concat([Buffer.from([0x01, userBuf.length]), userBuf, Buffer.from([passBuf.length]), passBuf]))
      const auth = await reader.read(2, timeoutMs, 'SOCKS5 用户名密码认证')
      if (auth[1] !== 0x00) throw new Error('SOCKS5 用户名或密码错误')
    } else if (selected[1] !== 0x00) {
      throw new Error(`SOCKS5 返回了不支持的认证方式: 0x${selected[1].toString(16)}`)
    }
    const hostBuf = Buffer.from(String(targetHost), 'utf8')
    if (!hostBuf.length || hostBuf.length > 255) throw new Error('SOCKS5 目标域名长度无效')
    if (!Number.isInteger(Number(targetPort)) || Number(targetPort) < 1 || Number(targetPort) > 65535) throw new Error('SOCKS5 目标端口无效')
    const port = Number(targetPort)
    socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]), hostBuf, Buffer.from([(port >> 8) & 0xff, port & 0xff])]))
    const head = await reader.read(4, timeoutMs, 'SOCKS5 CONNECT 响应')
    if (head[1] !== 0x00) throw new Error(`SOCKS5 CONNECT 失败: 0x${head[1].toString(16)}`)
    let addressLength = 0
    if (head[3] === 0x01) addressLength = 4
    else if (head[3] === 0x04) addressLength = 16
    else if (head[3] === 0x03) addressLength = (await reader.read(1, timeoutMs, 'SOCKS5 绑定域名长度'))[0]
    else throw new Error(`SOCKS5 返回了未知地址类型: 0x${head[3].toString(16)}`)
    await reader.read(addressLength + 2, timeoutMs, 'SOCKS5 绑定地址')
    reader.detach()
    return socket
  } catch (error) {
    reader.dispose()
    socket.destroy()
    throw error
  }
}

async function testSocks5(rawUrl) {
  const normalizedUrl = normalizeProxyUrl(rawUrl)
  const url = new URL(normalizedUrl)
  const scheme = url.protocol.replace(':', '').toLowerCase()
  if (scheme !== 'socks5' && scheme !== 'socks5h') throw new Error('当前验活只支持 socks5/socks5h')
  const started = Date.now()
  const socket = await socks5Connect(normalizedUrl, 'api.ipify.org', 443, 15000)
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
  const rawResponse = String(response)
  const separator = rawResponse.indexOf('\r\n\r\n')
  const headerText = separator >= 0 ? rawResponse.slice(0, separator) : ''
  let body = separator >= 0 ? rawResponse.slice(separator + 4) : rawResponse
  const headers = new Map()
  for (const line of headerText.split(/\r?\n/).slice(1)) {
    const index = line.indexOf(':')
    if (index > 0) headers.set(line.slice(0, index).trim().toLowerCase(), line.slice(index + 1).trim())
  }
  if (/\bchunked\b/i.test(headers.get('transfer-encoding') || '')) {
    let offset = 0
    let decoded = ''
    while (offset < body.length) {
      const lineEnd = body.indexOf('\r\n', offset)
      if (lineEnd < 0) break
      const size = Number.parseInt(body.slice(offset, lineEnd).split(';', 1)[0].trim(), 16)
      if (!Number.isFinite(size) || size < 0) break
      offset = lineEnd + 2
      if (size === 0) break
      decoded += body.slice(offset, offset + size)
      offset += size + 2
    }
    body = decoded
  } else if (headers.has('content-length')) {
    const length = Number.parseInt(headers.get('content-length'), 10)
    if (Number.isFinite(length) && length >= 0) body = body.slice(0, length)
  }
  body = body.trim()
  let externalIp = body
  try { externalIp = JSON.parse(body).ip || body } catch { }
  if (!String(externalIp).trim()) throw new Error('代理返回了空的出口 IP 响应')
  return { success: true, latencyMs: Date.now() - started, externalIp: String(externalIp).slice(0, 100), dnsMode: 'remote-hostname-atyp-3' }
}

async function saveAccount(input) {
  const existing = input?.id ? state.accounts.find((item) => item.id === input.id) : null
  const account = normalizeAccount(input || {}, existing)
  if (existing && existing.profileName !== account.profileName &&
      (existing.session?.deviceImage || Number(existing.session?.cookieCount || 0) > 0)) {
    throw new Error('Profile 名称在首次登录画像锁定后不可修改')
  }
  const duplicate = state.accounts.find((item) => item.id !== account.id && account.email && item.email.toLowerCase() === account.email.toLowerCase())
  if (duplicate) throw new Error(`邮箱已存在于账号 ${duplicate.label || duplicate.profileName}`)
  const profileOwner = findProfileOwner(account.profileName, account.id)
  if (profileOwner) throw new Error(`Profile 名称已被账号 ${profileOwner.label || profileOwner.profileName} 使用，请使用新的 Profile 名称`)
  await ensureProfile(account.profileName)
  if (!existing && !account.proxyId && state.settings.autoBind) {
    const pool = await readProxyState()
    if (pool.settings.autoBindOnNewAccount && pool.proxies.some((item) => item.enabled !== false)) await autoBindProxy(account)
  }
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
    const profileOwner = findProfileOwner(account.profileName, account.id)
    if (profileOwner) throw new Error(`导入失败：Profile 名称 ${account.profileName} 已被账号 ${profileOwner.label || profileOwner.profileName} 使用`)
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
  ipcMain.handle('manager:open-login', (_event, accountId, targetUrl) => openLogin(String(accountId), String(targetUrl || '')))
  ipcMain.handle('manager:close-login', () => {
    closeLoginWindow()
    return true
  })
  ipcMain.handle('manager:check-login-proxy', async (_event, accountId) => {
    const account = state.accounts.find((item) => item.id === String(accountId))
    if (!account) throw new Error('账号不存在')
    return checkLoginProxy(account)
  })
  ipcMain.handle('manager:restore-session', (_event, accountId) => restoreSession(String(accountId)))
  ipcMain.handle('manager:clear-session', (_event, accountId) => clearSession(String(accountId)))
  ipcMain.handle('manager:export', (_event, options) => exportAccounts(options))
  ipcMain.handle('manager:import', () => importAccounts())
  ipcMain.handle('manager:list-proxies', () => readProxyState())
  ipcMain.handle('manager:add-proxy', async (_event, rawInput) => {
    const parsed = parseProxyInput(rawInput)
    if (!parsed.entries.length) {
      const detail = parsed.errors.map((item) => `第 ${item.line} 行：${item.message}`).join('\n')
      throw new Error(detail || '没有识别到有效代理')
    }

    const added = []
    const failed = []
    for (const entry of parsed.entries) {
      const result = await runProxyScript(['-Action', 'add'], { CAC_PROXY_POOL_INPUT: entry.url })
      if (result.code !== 0) {
        failed.push({ line: entry.line, displayUrl: entry.displayUrl, message: (result.stderr || result.stdout || '代理添加失败').trim() })
      } else {
        added.push({ line: entry.line, displayUrl: entry.displayUrl })
      }
    }

    if (!added.length) {
      const detail = failed.map((item) => `第 ${item.line} 行 ${item.displayUrl}：${item.message}`).join('\n')
      throw new Error(detail || '代理添加失败')
    }

    const skipped = parsed.errors.length + parsed.duplicates.length + failed.length
    await recordEvent('info', `已识别 ${parsed.total} 条代理，写入 ${added.length} 条${skipped ? `，跳过 ${skipped} 条` : ''}`)
    return {
      total: parsed.total,
      added,
      failed,
      errors: parsed.errors,
      duplicates: parsed.duplicates,
      pool: await readProxyState()
    }
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
    state.settings.launchInject = true
    state.settings.launchFingerprint = true
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
  if (!hasSingleInstanceLock) return
  app.setAppUserModelId('com.cac.windows.accountmanager')
  runtimeRoot = resolveRuntimeRoot()
  scriptRoot = path.join(runtimeRoot, 'scripts')
  statePath = path.join(app.getPath('userData'), 'accounts.json')
  await loadState()
  registerIpc()
  createMainWindow()
  startRuntimeStateWatch()
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createMainWindow() })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  if (runtimeWatchTimer) clearInterval(runtimeWatchTimer)
  if (loginWindow && !loginWindow.isDestroyed()) loginWindow.destroy()
  stopLoginRelay()
})
