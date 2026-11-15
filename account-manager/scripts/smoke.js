'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const { normalizeProxyUrl, parseProxyInput } = require(path.join(root, 'src', 'proxy-input.js'))
const {
  isClaudeDeepLink,
  isClaudeMagicLink,
  maskLoginTarget,
  normalizeLoginTarget,
  normalizeWebLoginTarget,
  webUrlFromClaudeDeepLink
} = require(path.join(root, 'src', 'login-input.js'))
const { analyzeClaudeSession, isClaudeCookie } = require(path.join(root, 'src', 'session-status.js'))
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
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
assert.equal(packageJson.name, 'cac-account-manager')
assert.ok(packageJson.build.extraResources.length >= 3)
const mainSource = fs.readFileSync(path.join(root, 'src', 'main.js'), 'utf8')
assert.match(mainSource, /bootstrapNativeManager\(\)/)
assert.match(mainSource, /spawnSync\(native\.launcher/)
assert.match(mainSource, /requestSingleInstanceLock\(\)/)
assert.match(mainSource, /second-instance/)
assert.match(mainSource, /waitForNativeBridgeReady/)
assert.match(mainSource, /probeConfiguredLoginProxy/)
assert.match(mainSource, /session\.fromPath/)
assert.match(mainSource, /installLoginWebContentsPersona/)
assert.doesNotMatch(mainSource, /addScriptToExecuteOnNewDocument/)
assert.match(mainSource, /loginOpenInProgress/)
assert.match(mainSource, /rmSync\(auditPath, \{ force: true \}\)/)
assert.match(mainSource, /window-switch/)
assert.match(mainSource, /host-resolver-rules/)
assert.match(mainSource, /disable_non_proxied_udp/)
for (const file of ['src/main.js', 'src/preload.js', 'src/login-input.js', 'src/login-fingerprint.js', 'src/device-image.js', 'src/desktop-cookie.js', 'src/renderer/app.js', 'src/renderer/index.html', 'src/renderer/styles.css', 'scripts/electron-native-smoke.js', 'scripts/electron-native-smoke.ps1', 'scripts/manager-bootstrap-smoke.ps1']) {
  assert.ok(fs.existsSync(path.join(root, file)), `missing ${file}`)
}
const profileName = 'profile-a'
assert.match(profileName, /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/)
assert.doesNotMatch('../profile-a', /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/)
assert.equal(normalizeProxyUrl('host.example:1080:user:pass'), 'socks5h://user:pass@host.example:1080')
assert.equal(normalizeProxyUrl('socks5://host.example:1080:user:pass'), 'socks5h://user:pass@host.example:1080')
assert.equal(normalizeProxyUrl('host.example|1080|user|pass'), 'socks5h://user:pass@host.example:1080')
assert.equal(normalizeProxyUrl('user:pass@host.example:1080'), 'socks5h://user:pass@host.example:1080')
const proxyBatch = parseProxyInput('host.example:1080:user:pass\nhost2.example,1081,user2,pass2\nhost.example:1080:user:pass')
assert.equal(proxyBatch.entries.length, 2)
assert.equal(proxyBatch.duplicates.length, 1)
assert.equal(proxyBatch.errors.length, 0)
const magicLink = 'https://claude.ai/magic-link#opaque-token:ZW1haWxAZXhhbXBsZS5jb20='
assert.equal(isClaudeMagicLink(magicLink), true)
assert.equal(normalizeLoginTarget(magicLink), magicLink)
assert.equal(normalizeWebLoginTarget('https://claude.ai/magic-link?client=desktop_app#opaque-token'), 'https://claude.ai/magic-link#opaque-token')
assert.equal(isClaudeDeepLink('claude://claude.ai/magic-link?client=desktop_app#opaque-token'), true)
assert.equal(webUrlFromClaudeDeepLink('claude://claude.ai/magic-link?client=desktop_app#opaque-token'), 'https://claude.ai/magic-link#opaque-token')
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
console.log('[PASS] account-manager source and packaging smoke')
