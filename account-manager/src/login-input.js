'use strict'

const LOGIN_URL_RE = /^https?:\/\//i
const CLAUDE_HOSTS = new Set(['claude.ai', 'www.claude.ai'])

function normalizeLoginUrl(value) {
  const candidate = String(value || '').trim()
  if (!candidate) return 'https://claude.ai/login'
  if (!LOGIN_URL_RE.test(candidate)) throw new Error('登录地址必须是 http:// 或 https:// 地址')
  try {
    return new URL(candidate).toString()
  } catch {
    throw new Error('登录地址不是有效 URL')
  }
}

function isClaudeMagicLink(value) {
  try {
    const url = new URL(String(value || '').trim())
    return CLAUDE_HOSTS.has(url.hostname.toLowerCase())
      && url.pathname.replace(/\/$/, '').toLowerCase() === '/magic-link'
  } catch {
    return false
  }
}

function normalizeMagicLink(value) {
  const candidate = String(value || '').trim()
  if (!candidate) throw new Error('Magic Link 不能为空')
  if (!isClaudeMagicLink(candidate)) throw new Error('Magic Link 必须是 claude.ai/magic-link 的 HTTPS 链接')
  const url = new URL(candidate)
  if (url.protocol !== 'https:') throw new Error('Magic Link 必须使用 HTTPS')
  if (!url.hash && !url.search) throw new Error('Magic Link 缺少登录令牌')
  return url.toString()
}

function normalizeLoginTarget(value, fallback = 'https://claude.ai/login') {
  const candidate = String(value || fallback || '').trim()
  return isClaudeMagicLink(candidate) ? normalizeMagicLink(candidate) : normalizeLoginUrl(candidate)
}

function normalizeWebLoginTarget(value, fallback = 'https://claude.ai/login') {
  const target = normalizeLoginTarget(value, fallback)
  const url = new URL(target)
  if (isClaudeMagicLink(target) && url.searchParams.get('client') === 'desktop_app') {
    url.searchParams.delete('client')
  }
  return url.toString()
}

function isClaudeDeepLink(value) {
  try {
    const url = new URL(String(value || '').trim())
    const host = url.hostname.toLowerCase()
    return url.protocol === 'claude:' && (host === 'claude.ai' || host.endsWith('.claude.ai'))
  } catch {
    return false
  }
}

function webUrlFromClaudeDeepLink(value) {
  if (!isClaudeDeepLink(value)) return null
  const url = new URL(String(value || '').trim().replace(/^claude:/i, 'https:'))
  if (url.searchParams.get('client') === 'desktop_app') url.searchParams.delete('client')
  return url.toString()
}

function maskLoginTarget(value) {
  try {
    const url = new URL(String(value || '').trim())
    return `${url.origin}${url.pathname}${url.search ? '?…' : ''}${url.hash ? '#…' : ''}`
  } catch {
    return '<invalid-login-url>'
  }
}

module.exports = {
  isClaudeMagicLink,
  isClaudeDeepLink,
  maskLoginTarget,
  normalizeLoginTarget,
  normalizeLoginUrl,
  normalizeMagicLink,
  normalizeWebLoginTarget,
  webUrlFromClaudeDeepLink
}
