'use strict'

const crypto = require('node:crypto')

const SESSION_COOKIE_NAMES = ['sessionKey', 'sessionKeyV2', 'sessionKeyV3']
const VALID_SAME_SITE = new Set(['unspecified', 'no_restriction', 'lax', 'strict'])

function cookieDomain(cookie) {
  return String(cookie?.domain || '').trim().replace(/^\.+/, '').toLowerCase()
}

function isClaudeCookieDomain(domain) {
  const normalized = cookieDomain({ domain })
  return normalized === 'claude.ai' || normalized.endsWith('.claude.ai') ||
    normalized === 'claude.com' || normalized.endsWith('.claude.com')
}

function normalizeCookieForDesktop(cookie) {
  if (!cookie || typeof cookie !== 'object' || !isClaudeCookieDomain(cookie.domain)) return null
  const name = String(cookie.name || '').trim()
  const value = typeof cookie.value === 'string' ? cookie.value : ''
  if (!name || !value) return null
  const domain = String(cookie.domain || '').trim() || 'claude.ai'
  const path = String(cookie.path || '/').trim() || '/'
  const expirationDate = Number(cookie.expirationDate)
  return {
    name,
    value,
    domain,
    path: path.startsWith('/') ? path : `/${path}`,
    secure: cookie.secure !== false,
    httpOnly: Boolean(cookie.httpOnly),
    expirationDate: Number.isFinite(expirationDate) && expirationDate > 0 ? expirationDate : null,
    sameSite: VALID_SAME_SITE.has(String(cookie.sameSite || '').toLowerCase())
      ? String(cookie.sameSite).toLowerCase()
      : 'unspecified'
  }
}

function getDesktopSessionSyncKey(cookies) {
  const list = Array.isArray(cookies) ? cookies : []
  const sessionCookie = list.find((cookie) => SESSION_COOKIE_NAMES.includes(cookie?.name) && cookie?.value && isClaudeCookieDomain(cookie.domain))
  const organizationCookie = list.find((cookie) => cookie?.name === 'lastActiveOrg' && cookie?.value && isClaudeCookieDomain(cookie.domain))
  if (!sessionCookie || !organizationCookie) return ''
  return crypto.createHash('sha256')
    .update(`${sessionCookie.name}\u0000${sessionCookie.value}\u0000${organizationCookie.value}`)
    .digest('hex')
}

function chromiumCookieTimeNow() {
  return (Date.now() + 11644473600000) * 1000
}

function chromiumCookieExpiresUtc(cookie) {
  const expirationDate = Number(cookie?.expirationDate)
  if (!Number.isFinite(expirationDate) || expirationDate <= 0) return 0
  return (Math.round(expirationDate * 1000) + 11644473600000) * 1000
}

function chromiumSameSite(cookie) {
  switch (String(cookie?.sameSite || '').toLowerCase()) {
    case 'strict': return 2
    case 'lax': return 1
    case 'no_restriction':
    case 'none': return 0
    default: return -1
  }
}

function chromiumSourceType(cookie) {
  return cookie?.httpOnly ? 1 : 2
}

module.exports = {
  SESSION_COOKIE_NAMES,
  chromiumCookieExpiresUtc,
  chromiumCookieTimeNow,
  chromiumSameSite,
  chromiumSourceType,
  getDesktopSessionSyncKey,
  isClaudeCookieDomain,
  normalizeCookieForDesktop
}
