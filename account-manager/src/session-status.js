'use strict'

const SESSION_COOKIE_NAMES = ['sessionKey', 'sessionKeyV3', 'sessionKeyV2']

function isClaudeCookie(cookie) {
  const domain = String(cookie?.domain || '').trim().replace(/^\./, '').toLowerCase()
  return domain === 'claude.ai' || domain.endsWith('.claude.ai') || domain === 'claude.com' || domain.endsWith('.claude.com')
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value || ''))
}

function findCookie(cookies, names) {
  const accepted = new Set(Array.isArray(names) ? names : [names])
  return cookies.find((cookie) => accepted.has(cookie?.name) && cookie?.value) || null
}

function analyzeClaudeSession(cookies) {
  const claudeCookies = (Array.isArray(cookies) ? cookies : []).filter(isClaudeCookie)
  const sessionCookie = findCookie(claudeCookies, SESSION_COOKIE_NAMES)
  const organizationCookie = findCookie(claudeCookies, 'lastActiveOrg')
  const organizationId = organizationCookie?.value ? String(organizationCookie.value) : null
  const authenticated = Boolean(sessionCookie && organizationId && isUuid(organizationId))

  return {
    authenticated,
    sessionKeyName: sessionCookie?.name || null,
    organizationId: authenticated ? organizationId : null,
    cookieCount: claudeCookies.length,
    domains: [...new Set(claudeCookies.map((cookie) => String(cookie.domain || '').trim()).filter(Boolean))].sort()
  }
}

module.exports = {
  analyzeClaudeSession,
  isClaudeCookie,
  isUuid
}
