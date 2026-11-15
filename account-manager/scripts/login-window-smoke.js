'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const { createRequire } = require('node:module')

const root = path.resolve(__dirname, '..')

async function testMainWindowReuse() {
  const sourcePath = path.join(root, 'src', 'main.js')
  const electron = {
    app: {
      isPackaged: false,
      commandLine: { appendSwitch() {} },
      requestSingleInstanceLock: () => true,
      on() {},
      whenReady: () => new Promise(() => {})
    },
    session: { fromPath(p, options) { sandbox.sessionPath = p; sandbox.sessionOptions = options; return {} } }
  }
  let freshBrowser
  electron.BrowserWindow = function BrowserWindow() {
    freshBrowser = {
      url: 'about:blank', loads: [], destroyed: false,
      webContents: {
        events: {},
        debugger: { on(event, listener) { this[event] = listener } },
        on(event, listener) { this.events[event] = listener },
        setWindowOpenHandler(listener) { this.popupHandler = listener },
        getURL() { return freshBrowser.url }
      },
      on() {},
      isDestroyed() { return this.destroyed },
      async loadURL(url) { this.loads.push(url); this.url = url },
      show() {}, focus() {}, destroy() { this.destroyed = true }
    }
    return freshBrowser
  }
  const localRequire = createRequire(sourcePath)
  const relay = { accountId: 'account-a', proxyUrl: 'socks5h://user:pass@example.test:1080', port: 34567,
    process: { exitCode: null, signalCode: null, killed: false } }
  const browser = {
    url: 'https://claude.ai/login', loads: 0, shows: 0, focuses: 0, destroyed: false,
    isDestroyed() { return this.destroyed },
    webContents: { getURL() { return browser.url } },
    async loadURL(url) { this.loads++; this.url = url },
    show() { this.shows++ },
    focus() { this.focuses++ },
    destroy() { this.destroyed = true }
  }
  const account = { id: 'account-a', profileName: 'a', proxyId: 'proxy-a', loginUrl: 'https://claude.ai/login',
    session: { magicLinkDigests: [] } }
  const sandbox = {
    __account: account, __relay: relay, __browser: browser,
    require: (id) => id === 'electron' ? electron : id === './login-fingerprint'
      ? { applyLoginSessionPersona() {}, installLoginWebContentsPersona: async () => ({ mode: 'cdp-main-world' }) }
      : localRequire(id),
    __dirname: path.dirname(sourcePath),
    process: { ...process, platform: 'linux', env: { ...process.env, CAC_NATIVE_MANAGER_CHILD: '0' } },
    console, Buffer, setTimeout, clearTimeout, URL
  }
  vm.createContext(sandbox)
  vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath })
  vm.runInContext('accountLoginSession(__account)', sandbox)
  const idDigest = require('node:crypto').createHash('sha256').update(account.id).digest('hex')
  assert.equal(sandbox.sessionPath, path.join(process.env.USERPROFILE || require('node:os').homedir(), '.cac', 'web-login-sessions', idDigest))
  assert.equal(sandbox.sessionOptions.cache, false)
  const editedAccount = vm.runInContext(`normalizeAccount({ id: 'account-a', session: { authenticated: false } }, {
    ...__account, session: { encryptedCookies: 'encrypted-backup', magicLinkDigests: ['${'a'.repeat(64)}'] }
  })`, sandbox)
  assert.equal(editedAccount.session.encryptedCookies, 'encrypted-backup')
  assert.equal(editedAccount.session.magicLinkDigests.length, 1)
  vm.runInContext(`
    state = { accounts: [__account] }
    globalThis.savedStates = []
    saveState = async () => { savedStates.push(JSON.parse(JSON.stringify(state))) }
    loginAccountId = __account.id
    loginRelay = __relay
    loginWindow = __browser
    loginWindowState = {
      proxyId: __account.proxyId, proxyUrl: __relay.proxyUrl, relay: __relay,
      externalIp: '203.0.113.10', nativePid: 123, nativeAudit: 'fixture',
      fingerprintMode: 'cdp-main-world', lastMagicLinkDigest: null
    }
    readRawProxy = async () => ({ enabled: true, url: __relay.proxyUrl })
    accountLoginSession = () => ({ resolveProxy: async () => 'PROXY 127.0.0.1:34567' })
    globalThis.probes = 0
    globalThis.exitedIp = '203.0.113.10'
    probeConfiguredLoginProxy = async () => ({ externalIp: (probes++, exitedIp) })
    globalThis.loginEvents = []
    recordEvent = async (level, message) => { loginEvents.push({ level, message }) }
    queueLoginCapture = () => {}
    globalThis.stops = 0
    stopLoginRelay = () => { loginRelay = null; stops++ }
    captureLoginSession = async () => {}
  `, sandbox)
  const focus = await vm.runInContext("openLogin('account-a', 'https://claude.ai/login')", sandbox)
  assert.equal(focus.reused, true)
  assert.equal(focus.navigated, false)
  assert.equal(browser.loads, 0)
  assert.equal(sandbox.probes, 0)
  assert.equal(sandbox.stops, 0)
  assert.equal(browser.focuses, 1)

  const magic = 'https://claude.ai/magic-link#fixture'
  const firstMagic = await vm.runInContext(`openLogin('account-a', ${JSON.stringify(magic)})`, sandbox)
  assert.equal(firstMagic.reused, true)
  assert.equal(firstMagic.navigated, true)
  assert.equal(browser.loads, 1)
  assert.equal(sandbox.probes, 1)
  assert.equal(sandbox.stops, 0)
  assert.equal(browser.url, magic)
  assert.equal(sandbox.savedStates.length, 1)
  assert.equal(sandbox.savedStates[0].accounts[0].session.magicLinkDigests.length, 1)
  assert.equal(JSON.stringify(sandbox.savedStates).includes(magic), false)
  await assert.rejects(vm.runInContext(`openLogin('account-a', ${JSON.stringify(magic)})`, sandbox), /已在网页登录窗口/)
  assert.equal(browser.loads, 1)
  assert.equal(sandbox.probes, 1)

  sandbox.exitedIp = '203.0.113.11'
  await assert.rejects(vm.runInContext("openLogin('account-a', 'https://claude.ai/magic-link#other')", sandbox), /出口从/)
  assert.equal(browser.loads, 1)
  assert.equal(sandbox.stops, 0)
  assert.equal(sandbox.savedStates.length, 1)
  sandbox.exitedIp = '203.0.113.10'
  await vm.runInContext("checkLoginProxy(state.accounts[0])", sandbox)
  assert.equal(sandbox.stops, 0)

  vm.runInContext('loginOpenInProgress = true', sandbox)
  await assert.rejects(vm.runInContext('closeLoginWithCapture()', sandbox), /尚未完成/)
  assert.equal(browser.destroyed, false)
  vm.runInContext('loginOpenInProgress = false', sandbox)
  await vm.runInContext('closeLoginWithCapture()', sandbox)
  assert.equal(browser.destroyed, true)
  assert.equal(sandbox.stops, 1)
  vm.runInContext('state = JSON.parse(JSON.stringify(savedStates.at(-1)))', sandbox)
  await assert.rejects(vm.runInContext(`openLogin('account-a', ${JSON.stringify(magic)})`, sandbox), /已在网页登录窗口/)
  vm.runInContext("state.accounts.push({ id: 'account-b', profileName: 'b', session: { magicLinkDigests: [] } })", sandbox)
  await assert.rejects(vm.runInContext(`openLogin('account-b', ${JSON.stringify(magic)})`, sandbox), /已在网页登录窗口/)
  vm.runInContext('state.accounts.pop()', sandbox)
  assert.equal(sandbox.stops, 1)

  vm.runInContext(`
    loginRelay = __relay
    globalThis.setProxyCalls = 0
    globalThis.sessionFixture = {
      setProxy: async () => { setProxyCalls++ },
      resolveProxy: async () => 'PROXY 127.0.0.1:34567',
      cookies: { on() {}, removeListener() {}, get: async () => [] }
    }
    accountLoginSession = () => sessionFixture
    ensureLoginRelay = async () => {
      if (loginRelay !== __relay) throw new Error('prechecked relay was replaced')
      return loginRelay
    }
    ensureProfile = async () => {}
    configureLoginNativeEnvironment = () => ({ auditPath: 'fixture' })
    loadDesktopFingerprint = async () => ({
      evidence: { imageSha256: 'fixture' },
      persona: { ua: 'fixture', timezone: 'America/New_York', locale: 'en-US', languages: ['en-US', 'en'] }
    })
    waitForRendererProcessId = async () => 123
    waitForNativeBridgeReady = async () => {}
    readNativeAuditEvents = () => []
    sleep = async () => {}
  `, sandbox)
  const firstOpen = await vm.runInContext("openLogin('account-a', 'https://claude.ai/login')", sandbox)
  assert.equal(firstOpen.reused, false)
  assert.equal(sandbox.stops, 1)
  assert.equal(sandbox.setProxyCalls, 1)
  assert.deepEqual(freshBrowser.loads, ['about:blank', 'https://claude.ai/login'])
  const newMagic = 'https://claude.ai/magic-link#new-fixture'
  const magicAfterOpen = await vm.runInContext(`openLogin('account-a', ${JSON.stringify(newMagic)})`, sandbox)
  assert.equal(magicAfterOpen.reused, true)
  assert.equal(sandbox.setProxyCalls, 1)
  assert.equal(sandbox.stops, 1)
  assert.equal(freshBrowser.loads.length, 3)
  assert.equal(sandbox.savedStates.at(-1).accounts[0].session.magicLinkDigests.length, 2)
  const redirects = freshBrowser.webContents.events
  redirects['did-navigate']({}, newMagic)
  redirects['did-navigate']({}, 'https://claude.ai/login?email=private')
  assert.match(sandbox.loginEvents.at(-1).message, /Magic Link 跳回邮箱登录页/)
  assert.equal(sandbox.loginEvents.at(-1).message.includes('private'), false)
  const loadsBeforeCallback = freshBrowser.loads.length
  let blockedCallback = false
  redirects['will-navigate']({ preventDefault() { blockedCallback = true } }, 'claude://claude.ai/magic-link#fixture')
  assert.equal(blockedCallback, true)
  assert.equal(freshBrowser.loads.length, loadsBeforeCallback)
  assert.equal(freshBrowser.webContents.popupHandler({ url: 'claude://claude.ai/magic-link#fixture' }).action, 'deny')
  assert.equal(freshBrowser.loads.length, loadsBeforeCallback)
  assert.equal(freshBrowser.webContents.popupHandler({ url: newMagic }).action, 'deny')
  await new Promise(setImmediate)
  assert.match(sandbox.loginEvents.at(-1).message, /已在网页登录窗口/)
  assert.equal(freshBrowser.loads.length, loadsBeforeCallback)
  let blockedPageNavigation = false
  redirects['will-navigate']({ preventDefault() { blockedPageNavigation = true } }, newMagic)
  await new Promise(setImmediate)
  assert.equal(blockedPageNavigation, true)
  assert.match(sandbox.loginEvents.at(-1).message, /已在网页登录窗口/)
  assert.equal(freshBrowser.loads.length, loadsBeforeCallback)
  let blockedTokenlessNavigation = false
  redirects['will-navigate']({ preventDefault() { blockedTokenlessNavigation = true } }, 'https://claude.ai/magic-link')
  assert.equal(blockedTokenlessNavigation, false)
  assert.equal(freshBrowser.loads.length, loadsBeforeCallback)
  assert.match(sandbox.loginEvents.at(-1).message, /无令牌的 Magic Link 页面/)
  freshBrowser.webContents.debugger.message({}, 'Network.responseReceived', {
    response: { status: 403, url: 'https://claude.ai/api/auth/verify?token=secret' }
  })
  assert.match(sandbox.loginEvents.at(-1).message, /认证接口 HTTP 403/)
  assert.equal(sandbox.loginEvents.at(-1).message.includes('secret'), false)
  freshBrowser.webContents.debugger.message({}, 'Network.responseReceived', {
    type: 'Document', response: { status: 403, url: 'https://claude.ai/magic-link#secret', headers: { 'cf-mitigated': 'challenge' } }
  })
  assert.match(sandbox.loginEvents.at(-1).message, /网页主文档 magic-link HTTP 403（Cloudflare 验证）/)
  assert.equal(sandbox.loginEvents.at(-1).message.includes('secret'), false)
  relay.process.exitCode = 1
  await assert.rejects(vm.runInContext("openLogin('account-a', 'https://claude.ai/magic-link#new')", sandbox), /中继已断开/)
  assert.equal(freshBrowser.destroyed, true)
  assert.equal(freshBrowser.loads.length, 3)
  relay.process.exitCode = null
  vm.runInContext(`loginRelay = __relay; ensureProfile = async () => { throw new Error('fixture profile failure') }`, sandbox)
  await assert.rejects(vm.runInContext("openLogin('account-a', 'https://claude.ai/login')", sandbox), /fixture profile failure/)
  assert.equal(sandbox.stops, 3)
}

async function testRendererDialogPersistence() {
  const sourcePath = path.join(root, 'src', 'renderer', 'app.js')
  const nodes = new Map()
  const node = (selector) => {
    if (!nodes.has(selector)) {
      nodes.set(selector, {
        innerHTML: '', textContent: '', disabled: false, dataset: {}, events: {},
        addEventListener(event, listener) { this.events[event] = listener },
        appendChild() {}, remove() {}
      })
    }
    return nodes.get(selector)
  }
  const form = node('#login-form')
  form.elements = { loginUrl: { value: 'https://claude.ai/login' }, magicLink: { value: '' } }
  let opens = 0
  let closes = 0
  let releaseOpen
  let holdOpen = true
  const manager = {
    async openLogin(_id, url) {
      opens++
      if (holdOpen) await new Promise((resolve) => { releaseOpen = resolve })
      return { target: url.includes('magic-link') ? 'Magic Link' : '登录页',
        navigated: true, externalIp: '203.0.113.10', nativePid: 123,
        dnsMode: 'SOCKS5', proxy: 'socks5h://example.test:1080' }
    },
    async closeLogin() { closes++ },
    async checkLoginProxy() { return { externalIp: '203.0.113.10', latencyMs: 3, dnsMode: 'SOCKS5' } }
  }
  const document = {
    querySelector: node,
    querySelectorAll: () => [],
    createElement: () => ({ remove() {} }),
    addEventListener() {}
  }
  const sandbox = { window: { manager }, document, setTimeout: () => 0, console }
  vm.createContext(sandbox)
  vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath })
  vm.runInContext(`model.proxies = [{ id: 'proxy-a', displayUrl: 'socks5h://example.test:1080' }];
    openLoginModal({ id: 'account-a', profileName: 'a', proxyId: 'proxy-a', loginUrl: 'https://claude.ai/login' })`, sandbox)
  const modal = node('#modal-root')
  assert.match(modal.innerHTML, /网页登录 · a/)
  assert.equal(node('.modal-backdrop').events.click, undefined)
  assert.equal(opens, 0)
  assert.equal(closes, 0)

  const click = (selector) => {
    const button = node(selector)
    return button.events.click({ currentTarget: button })
  }
  const opening = click('#open-login-page')
  await click('#cancel-login')
  assert.equal(closes, 0)
  assert.match(modal.innerHTML, /网页登录 · a/)
  holdOpen = false
  releaseOpen()
  await opening
  assert.equal(opens, 1)
  assert.match(modal.innerHTML, /网页登录 · a/)
  assert.equal(closes, 0)
  form.elements.magicLink.value = 'https://claude.ai/magic-link#fixture'
  await click('#open-magic-link')
  assert.equal(opens, 2)
  assert.equal(form.elements.magicLink.value, '')
  assert.match(node('#login-proxy-audit').textContent, /登录状态待确认/)
  assert.match(modal.innerHTML, /网页登录 · a/)
  assert.equal(closes, 0)
  await click('#cancel-login')
  assert.equal(closes, 1)
  assert.equal(modal.innerHTML, '')
}

async function testAuditAndCookieRestoration() {
  const os = require('node:os')
  const sourcePath = path.join(root, 'src', 'main.js')
  const profileRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cac-login-audit-smoke-'))
  const auditDir = path.join(profileRoot, 'audit')
  const localRequire = createRequire(sourcePath)
  const existingCookie = { domain: '.claude.ai', path: '/', name: 'sessionKey', value: 'fresh' }
  const backup = [
    { ...existingCookie, value: 'stale' },
    { domain: '.claude.ai', path: '/', name: 'lastActiveOrg', value: 'fixture-org' }
  ]
  const writes = []
  const electron = {
    app: {
      isPackaged: false,
      commandLine: { appendSwitch() {} },
      requestSingleInstanceLock: () => true,
      on() {},
      whenReady: () => new Promise(() => {})
    },
    safeStorage: {
      isEncryptionAvailable: () => true,
      decryptString: () => JSON.stringify(backup)
    }
  }
  const sandbox = {
    __profileRoot: profileRoot,
    __account: { id: 'fixture-account', profileName: 'fixture' },
    __cookieAccount: { session: { encryptedCookies: 'YQ==' } },
    __cookieSession: { cookies: { get: async () => [existingCookie], set: async (cookie) => { writes.push(cookie) } } },
    require: (id) => id === 'electron' ? electron : localRequire(id),
    __dirname: path.dirname(sourcePath),
    process: { ...process, platform: 'linux', env: { ...process.env } },
    console, Buffer, setTimeout, clearTimeout, URL
  }
  try {
    fs.writeFileSync(path.join(profileRoot, 'identity.json'), '{}')
    fs.writeFileSync(path.join(profileRoot, 'fingerprint.json'), JSON.stringify({
      timezone: 'America/New_York', locale: 'en-US', languages: ['en-US', 'en']
    }))
    fs.mkdirSync(auditDir)
    const legacyPath = path.join(auditDir, 'login-native.jsonl')
    fs.writeFileSync(legacyPath, 'old-audit')
    vm.createContext(sandbox)
    vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath })
    vm.runInContext('desktopProfileRoot = () => __profileRoot', sandbox)
    const first = vm.runInContext('configureLoginNativeEnvironment(__account)', sandbox)
    fs.writeFileSync(first.auditPath, 'first-audit')
    vm.runInContext('restoreLoginNativeEnvironment()', sandbox)
    const second = vm.runInContext('configureLoginNativeEnvironment(__account)', sandbox)
    vm.runInContext('restoreLoginNativeEnvironment()', sandbox)
    assert.notEqual(first.auditPath, second.auditPath)
    assert.equal(fs.readFileSync(first.auditPath, 'utf8'), 'first-audit')
    assert.equal(fs.readFileSync(legacyPath, 'utf8'), 'old-audit')
    const result = await vm.runInContext('restoreLoginCookies(__cookieAccount, __cookieSession)', sandbox)
    assert.equal(result.restored, 1)
    assert.equal(writes[0].name, 'lastActiveOrg')
    assert.equal(result.cookies.find((cookie) => cookie.name === 'sessionKey').value, 'fresh')
    const forced = await vm.runInContext('restoreLoginCookies(__cookieAccount, __cookieSession, true)', sandbox)
    assert.equal(forced.restored, 2)
  } finally {
    if (path.dirname(profileRoot) === os.tmpdir() && path.basename(profileRoot).startsWith('cac-login-audit-smoke-')) {
      fs.rmSync(profileRoot, { recursive: true, force: true })
    }
  }
}

Promise.resolve().then(testMainWindowReuse).then(testRendererDialogPersistence).then(testAuditAndCookieRestoration)
  .then(() => console.log('[PASS] login reuse, cross-window link dedup, cookie restoration and audit preservation'))
  .catch((error) => { console.error(error); process.exitCode = 1 })
