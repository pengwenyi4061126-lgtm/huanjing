'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const { normalizeProxyUrl, parseProxyInput } = require(path.join(root, 'src', 'proxy-input.js'))
const { inspectClaudeResponse } = require(path.join(root, 'src', 'socks-client.js'))
const {
  isClaudeDeepLink,
  isClaudeMagicLink,
  loginPageStage,
  maskLoginTarget,
  normalizeLoginTarget,
  normalizeWebLoginTarget,
  webUrlFromClaudePopup
} = require(path.join(root, 'src', 'login-input.js'))
const { analyzeClaudeSession, isClaudeCookie } = require(path.join(root, 'src', 'session-status.js'))
assert.equal(webUrlFromClaudePopup('https://claude.ai/magic-link?client=desktop_app#fixture'), null)
assert.equal(webUrlFromClaudePopup('claude://claude.ai/magic-link#fixture'), null)
assert.equal(webUrlFromClaudePopup('https://accounts.google.com/'), null)
assert.equal(webUrlFromClaudePopup('http://claude.ai/login'), null)
assert.match(fs.readFileSync(path.join(root, 'src', 'main.js'), 'utf8'), /webUrlFromClaudePopup\(url\)/)
assert.match(fs.readFileSync(path.join(root, 'src', 'main.js'), 'utf8'), /manager:close-login', \(\) => closeLoginWithCapture\(\)/)
const {
  chromiumCookieExpiresUtc,
  chromiumSameSite,
  getDesktopSessionSyncKey,
  normalizeCookieForDesktop
} = require(path.join(root, 'src', 'desktop-cookie.js'))
const {
  applyLoginSessionPersona,
  normalizeLanguages,
  validatePersona
} = require(path.join(root, 'src', 'login-fingerprint.js'))
const {
  assertRuntimeMatchesPersona,
  buildImageSha256,
  evidenceMatches,
  publicEvidence,
  sha256,
  verifyDeviceImage
} = require(path.join(root, 'src', 'device-image.js'))
const {
  FIXED_US_LANGUAGES,
  FIXED_US_LOCALE,
  FIXED_US_TIMEZONE,
  normalizeProxyGeo,
  profileGenesisEnvironment
} = require(path.join(root, 'src', 'proxy-profile.js'))
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
assert.equal(packageJson.name, 'cac-account-manager')
assert.ok(packageJson.build.extraResources.length >= 3)
const mainSource = fs.readFileSync(path.join(root, 'src', 'main.js'), 'utf8')
const socksClientSource = fs.readFileSync(path.join(root, 'src', 'socks-client.js'), 'utf8')
assert.match(mainSource, /bootstrapNativeManager\(\)/)
assert.match(mainSource, /spawnSync\(native\.launcher/)
assert.match(mainSource, /requestSingleInstanceLock\(\)/)
assert.match(mainSource, /second-instance/)
assert.match(mainSource, /waitForNativeBridgeReady/)
assert.match(mainSource, /waitForRendererProcessId/)
assert.match(mainSource, /probeConfiguredLoginProxy/)
assert.match(mainSource, /installLoginWebContentsPersona/)
assert.doesNotMatch(mainSource, /addScriptToExecuteOnNewDocument/)
assert.match(mainSource, /loginOpenInProgress/)
assert.match(mainSource, /login-native-\$\{Date\.now\(\)\}-\$\{process\.pid\}-\$\{crypto\.randomUUID\(\)\}\.jsonl/)
assert.doesNotMatch(mainSource, /rmSync\(auditPath, \{ force: true \}\)/)
assert.match(mainSource, /window-switch/)
assert.match(mainSource, /host-resolver-rules/)
assert.match(mainSource, /disable_non_proxied_udp/)
assert.match(mainSource, /initializeNewAccountProfile/)
assert.match(mainSource, /probeSocks5Profile/)
assert.match(mainSource, /path\.join\(HOST_USERPROFILE, '\.cac', 'proxy-pool\.json'\)/)
assert.match(mainSource, /Profile .*存在未归属的旧设备画像/)
assert.match(mainSource, /'-Action', 'cleanup', '-Profile', account\.profileName/)
assert.match(mainSource, /已删除账号、代理绑定和 Desktop Profile；网页登录数据已清空/)
assert.match(mainSource, /session\.fromPath\(accountLoginSessionPath\(account\), \{ cache: false \}\)/)
assert.match(mainSource, /removedOrphanWebSessions/)
assert.match(mainSource, /restoreLoginCookies\(account, configured\.sess\)/)
assert.match(mainSource, /await sess\.clearData\(\)/)
assert.match(mainSource, /cleanupLegacyLoginArtifacts\(\)/)
assert.match(mainSource, /entry\.name\.startsWith\('cac-account-'\)/)
assert.match(socksClientSource, /socks5-domain-atyp-3/)
assert.match(socksClientSource, /0x03, hostBuf\.length/)
for (const file of ['src/main.js', 'src/preload.js', 'src/login-input.js', 'src/login-fingerprint.js', 'src/device-image.js', 'src/proxy-profile.js', 'src/socks-client.js', 'src/desktop-cookie.js', 'src/renderer/app.js', 'src/renderer/index.html', 'src/renderer/styles.css', 'scripts/electron-proxy-smoke.js', 'scripts/electron-native-smoke.js', 'scripts/electron-native-smoke.ps1', 'scripts/manager-bootstrap-smoke.ps1']) {
  assert.ok(fs.existsSync(path.join(root, file)), `missing ${file}`)
}
const profileName = 'profile-a'
assert.match(profileName, /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/)
assert.doesNotMatch('../profile-a', /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/)
assert.equal(normalizeProxyUrl('host.example:1080:user:pass'), 'socks5h://user:pass@host.example:1080')
assert.equal(normalizeProxyUrl('socks5://host.example:1080:user:pass'), 'socks5h://user:pass@host.example:1080')
assert.equal(normalizeProxyUrl('host.example|1080|user|pass'), 'socks5h://user:pass@host.example:1080')
assert.equal(normalizeProxyUrl('user:pass@host.example:1080'), 'socks5h://user:pass@host.example:1080')
const encodedCity = normalizeProxyUrl('host.example:1080:miya_g-US_c-Kansas%20City_sid-1:pass')
assert.equal(decodeURIComponent(new URL(encodedCity).username), 'miya_g-US_c-Kansas%20City_sid-1')
assert.equal(normalizeProxyUrl(encodedCity), encodedCity)
assert.deepEqual(inspectClaudeResponse({ statusCode: 403, headers: new Map([['cf-mitigated', 'challenge']]) }), {
  statusCode: 403, httpOk: false, challenge: true
})
assert.equal(inspectClaudeResponse({ statusCode: 200, headers: new Map() }).httpOk, true)
const proxyBatch = parseProxyInput('host.example:1080:user:pass\nhost2.example,1081,user2,pass2\nhost.example:1080:user:pass')
assert.equal(proxyBatch.entries.length, 2)
assert.equal(proxyBatch.duplicates.length, 1)
assert.equal(proxyBatch.errors.length, 0)
const magicLink = 'https://claude.ai/magic-link#opaque-token:ZW1haWxAZXhhbXBsZS5jb20='
assert.equal(isClaudeMagicLink(magicLink), true)
assert.equal(normalizeLoginTarget(magicLink), magicLink)
assert.throws(() => normalizeWebLoginTarget('https://claude.ai/magic-link?client=desktop_app#opaque-token'), /Desktop 专用/)
assert.equal(isClaudeDeepLink('claude://claude.ai/magic-link?client=desktop_app#opaque-token'), true)
assert.equal(loginPageStage(magicLink), 'magic-link')
assert.equal(loginPageStage('https://claude.ai/login?email=private'), 'email-login')
assert.equal(loginPageStage('https://claude.ai/chats'), 'chat')
assert.equal(loginPageStage('https://accounts.google.com/'), 'external')
assert.equal(maskLoginTarget(magicLink), 'https://claude.ai/magic-link#…')
assert.throws(() => normalizeLoginTarget('https://claude.ai/magic-link'), /缺少登录令牌/)
assert.throws(() => normalizeLoginTarget('http://claude.ai/magic-link#opaque-token'), /必须使用 HTTPS/)
assert.equal(isClaudeCookie({ domain: '.claude.ai', name: 'sessionKey', value: 'session' }), true)
assert.equal(isClaudeCookie({ domain: '.google.com', name: 'SID', value: 'unrelated' }), false)
const authenticatedSession = analyzeClaudeSession([
  { domain: '.claude.ai', name: 'sessionKey', value: 'session' },
  { domain: '.claude.ai', name: 'lastActiveOrg', value: '123e4567-e89b-12d3-a456-426614174000' },
  { domain: '.google.com', name: 'SID', value: 'unrelated' }
])
assert.equal(authenticatedSession.authenticated, true)
assert.equal(authenticatedSession.cookieCount, 2)
assert.equal(authenticatedSession.organizationId, '123e4567-e89b-12d3-a456-426614174000')
assert.equal(analyzeClaudeSession([{ domain: '.claude.ai', name: 'sessionKey', value: 'session' }]).authenticated, false)
const desktopCookie = normalizeCookieForDesktop({
  domain: '.claude.ai',
  name: 'sessionKey',
  value: 'session',
  path: '/',
  secure: true,
  httpOnly: true,
  sameSite: 'lax',
  expirationDate: 2000000000
})
assert.equal(desktopCookie.domain, '.claude.ai')
assert.equal(desktopCookie.sameSite, 'lax')
assert.equal(chromiumSameSite(desktopCookie), 1)
assert.ok(chromiumCookieExpiresUtc(desktopCookie) > 0)
assert.match(getDesktopSessionSyncKey([
  desktopCookie,
  { domain: '.claude.ai', name: 'lastActiveOrg', value: '123e4567-e89b-12d3-a456-426614174000' }
]), /^[0-9a-f]{64}$/)
const persona = {
  ua: 'CAC-Smoke/1.0',
  timezone: 'America/New_York',
  locale: 'en-US',
  languages: ['en-US', 'en', 'en-US'],
  seed: 'profile-a|machine-a',
  uaElectronVersion: '45.2.1',
  uaChromiumVersion: '156.0.8078.75'
}
assert.deepEqual(normalizeLanguages(persona), ['en-US', 'en'])
assert.equal(validatePersona(persona).timezone, 'America/New_York')
let appliedPersona = null
applyLoginSessionPersona({ setUserAgent: (...args) => { appliedPersona = args } }, persona)
assert.deepEqual(appliedPersona, ['CAC-Smoke/1.0', 'en-US,en'])
assert.throws(() => validatePersona({}), /userAgent/)
const identityBuffer = Buffer.from(`${JSON.stringify({ machine_id: 'machine-a' }, null, 2)}\n`)
const personaBuffer = Buffer.from(`${JSON.stringify(persona, null, 2)}\n`)
const identitySha256 = sha256(identityBuffer)
const personaSha256 = sha256(personaBuffer)
const lock = {
  schema: 1,
  profile: 'profile-a',
  lockedUtc: '2026-11-15T00:00:00.000Z',
  identitySha256,
  personaSha256,
  imageSha256: buildImageSha256(identitySha256, personaSha256),
  machineId: 'machine-a',
  seed: persona.seed,
  electronVersion: persona.uaElectronVersion,
  chromiumVersion: persona.uaChromiumVersion
}
const deviceImage = verifyDeviceImage({ profileName: 'profile-a', identityBuffer, personaBuffer, lock })
assert.equal(deviceImage.imageSha256, lock.imageSha256)
assert.equal(evidenceMatches(publicEvidence(deviceImage), publicEvidence(deviceImage)), true)
assert.deepEqual(assertRuntimeMatchesPersona(persona, { electron: '45.2.1', chrome: '156.0.8078.75' }), {
  electron: '45.2.1',
  chromium: '156.0.8078.75'
})
assert.throws(() => assertRuntimeMatchesPersona(persona, { electron: '45.2.2', chrome: '156.0.8078.80' }), /does not match/)
assert.throws(() => verifyDeviceImage({
  profileName: 'profile-a',
  identityBuffer,
  personaBuffer: Buffer.from(`${JSON.stringify({ ...persona, locale: 'fr-FR' }, null, 2)}\n`),
  lock
}), /fingerprint\.json changed/)
const proxyProfile = normalizeProxyGeo({
  ip: '203.0.113.10',
  country_code: 'US',
  country_name: 'United States',
  region: 'Florida',
  city: 'Miami',
  timezone: 'America/New_York',
  languages: 'en-US,es-US'
}, {
  proxyId: 'proxy-first',
  locale: 'zh-CN',
  languages: ['zh-CN', 'zh'],
  capturedUtc: '2026-11-15T00:00:00.000Z'
})
assert.equal(proxyProfile.timezone, 'America/New_York')
assert.equal(proxyProfile.locale, FIXED_US_LOCALE)
assert.deepEqual(proxyProfile.languages, FIXED_US_LANGUAGES)
const fixedProfile = normalizeProxyGeo({
  ip: '203.0.113.11', country_code: 'US', timezone: 'America/Los_Angeles'
}, { proxyId: 'proxy-language', timezone: 'Asia/Shanghai', locale: 'zh-CN', languages: ['zh-CN', 'zh'] })
assert.equal(fixedProfile.timezone, FIXED_US_TIMEZONE)
assert.equal(fixedProfile.locale, FIXED_US_LOCALE)
assert.deepEqual(fixedProfile.languages, FIXED_US_LANGUAGES)
const genesisEnv = profileGenesisEnvironment(fixedProfile)
assert.equal(genesisEnv.CAC_PROFILE_TIMEZONE, FIXED_US_TIMEZONE)
assert.equal(genesisEnv.CAC_PROFILE_LOCALE, FIXED_US_LOCALE)
assert.equal(genesisEnv.CAC_PROFILE_LANGUAGES, FIXED_US_LANGUAGES.join(','))
for (const override of [
  { timezone: 'Asia/Shanghai' },
  { locale: 'zh-CN' },
  { languages: ['zh-CN', 'zh'] }
]) {
  assert.throws(() => profileGenesisEnvironment({ ...fixedProfile, ...override }), /must match fixed/)
}
assert.equal(profileGenesisEnvironment(proxyProfile).CAC_PROFILE_ORIGIN_PROXY_ID, 'proxy-first')
assert.equal(profileGenesisEnvironment(proxyProfile).CAC_PROFILE_ORIGIN_PROVIDER, 'ipapi.co')
const firstProxyPersona = {
  ...persona,
  schema: 2,
  locale: proxyProfile.locale,
  languages: proxyProfile.languages,
  timezone: proxyProfile.timezone,
  origin: proxyProfile
}
const firstProxyPersonaBuffer = Buffer.from(`${JSON.stringify(firstProxyPersona, null, 2)}\n`)
const firstProxyPersonaSha = sha256(firstProxyPersonaBuffer)
const firstProxyLock = {
  ...lock,
  schema: 2,
  personaSha256: firstProxyPersonaSha,
  imageSha256: buildImageSha256(identitySha256, firstProxyPersonaSha),
  seed: firstProxyPersona.seed,
  electronVersion: firstProxyPersona.uaElectronVersion,
  chromiumVersion: firstProxyPersona.uaChromiumVersion,
  timezone: firstProxyPersona.timezone,
  locale: firstProxyPersona.locale,
  languages: firstProxyPersona.languages,
  origin: firstProxyPersona.origin
}
const firstProxyImage = verifyDeviceImage({
  profileName: 'profile-a',
  identityBuffer,
  personaBuffer: firstProxyPersonaBuffer,
  lock: firstProxyLock
})
assert.equal(firstProxyImage.schema, 2)
assert.equal(firstProxyImage.origin.proxyId, 'proxy-first')
assert.throws(() => verifyDeviceImage({
  profileName: 'profile-a',
  identityBuffer,
  personaBuffer: firstProxyPersonaBuffer,
  lock: { ...firstProxyLock, origin: { ...firstProxyLock.origin, proxyId: 'proxy-other' } }
}), /origin proxyId/)
assert.throws(() => normalizeProxyGeo({
  ip: 'not-an-ip', country_code: 'US', timezone: 'Invalid/Zone', languages: 'en-US'
}, { proxyId: 'proxy-first' }), /无效出口 IP/)
console.log('[PASS] account-manager source and packaging smoke')
