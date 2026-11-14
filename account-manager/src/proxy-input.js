'use strict'

const SUPPORTED_SCHEMES = new Set(['socks5:', 'socks5h:'])
const DEFAULT_PORT = 1080

function stripOuterQuotes(value) {
  return String(value || '').trim().replace(/^(?:"|'|`)(.*)(?:"|'|`)$/s, '$1').trim()
}

function assertPort(rawPort) {
  const port = Number(rawPort)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('端口必须是 1-65535 的整数')
  return port
}

function encodeCredential(value) {
  return encodeURIComponent(String(value ?? ''))
}

function formatProxyUrl({ host, port = DEFAULT_PORT, username, password, scheme = 'socks5h' }) {
  const normalizedHost = String(host || '').trim().replace(/^\[|\]$/g, '')
  if (!normalizedHost) throw new Error('主机地址不能为空')
  const normalizedPort = assertPort(port)
  const normalizedScheme = String(scheme || 'socks5h').toLowerCase()
  if (!SUPPORTED_SCHEMES.has(`${normalizedScheme}:`)) throw new Error('只支持 socks5:// 或 socks5h://')
  const hostPart = normalizedHost.includes(':') ? `[${normalizedHost}]` : normalizedHost
  const hasCredentials = username !== undefined || password !== undefined
  const auth = hasCredentials ? `${encodeCredential(username)}:${encodeCredential(password)}@` : ''
  return `socks5h://${auth}${hostPart}:${normalizedPort}`
}

function normalizeExplicitUrl(value) {
  const parsed = new URL(value)
  const scheme = parsed.protocol.toLowerCase().replace(/:$/, '')
  if (!SUPPORTED_SCHEMES.has(scheme + ':')) throw new Error('只支持 socks5:// 或 socks5h://')
  if (!parsed.hostname) throw new Error('主机地址不能为空')
  const username = parsed.username || parsed.password ? decodeURIComponent(parsed.username || '') : undefined
  const password = parsed.username || parsed.password ? decodeURIComponent(parsed.password || '') : undefined
  return formatProxyUrl({
    host: parsed.hostname,
    port: parsed.port || DEFAULT_PORT,
    username,
    password,
    scheme
  })
}

function normalizeBareProxy(value) {
  let match = value.match(/^\[([^\]]+)\]:(\d+):([^:]+):(.*)$/)
  if (!match) match = value.match(/^([^:/\s]+):(\d+):([^:]+):(.*)$/)
  if (match) {
    return formatProxyUrl({ host: match[1], port: match[2], username: match[3], password: match[4] })
  }

  match = value.match(/^([^,|;\t]+)[,|;\t](\d+)[,|;\t]([^,|;\t]+)[,|;\t](.*)$/)
  if (match) {
    return formatProxyUrl({ host: match[1], port: match[2], username: match[3], password: match[4] })
  }

  match = value.match(/^(\[[^\]]+\]|[^\s:]+):(\d+)@([^:]+):(.*)$/)
  if (match) {
    return formatProxyUrl({ host: match[1], port: match[2], username: match[3], password: match[4] })
  }

  if (value.includes('@')) return normalizeExplicitUrl(`socks5h://${value}`)

  match = value.match(/^\[([^\]]+)\]:(\d+)$/)
  if (!match) match = value.match(/^([^:/\s]+):(\d+)$/)
  if (match) return formatProxyUrl({ host: match[1], port: match[2] })

  throw new Error('无法识别代理格式')
}

function normalizeProxyUrl(raw) {
  const value = stripOuterQuotes(raw)
  if (!value) throw new Error('代理地址不能为空')
  const hasScheme = new RegExp('^[a-z][a-z0-9+.-]*://', 'i').test(value)
  if (hasScheme) {
    try { return normalizeExplicitUrl(value) } catch (error) {
      const match = value.match(new RegExp('^socks5h?://(.+)$', 'i'))
      if (match) return normalizeBareProxy(match[1])
      throw error
    }
  }
  return normalizeBareProxy(value)
}

function maskProxyUrl(raw) {
  try {
    const url = new URL(normalizeProxyUrl(raw))
    const auth = url.username || url.password ? '***:***@' : ''
    const host = url.hostname.includes(':') ? `[${url.hostname.replace(/^\[|\]$/g, '')}]` : url.hostname
    const port = url.port ? `:${url.port}` : ''
    return `${url.protocol}//${auth}${host}${port}`
  } catch {
    return '<invalid-proxy>'
  }
}

function proxyCandidateFromJson(item) {
  if (typeof item === 'string') return item
  if (!item || typeof item !== 'object') throw new Error('JSON 项不是代理字符串或对象')
  for (const key of ['url', 'proxy', 'address', 'endpoint']) {
    if (typeof item[key] === 'string' && item[key].trim()) return item[key]
  }
  const host = item.host ?? item.hostname ?? item.server ?? item.ip
  const port = item.port
  if (host && port) return formatProxyUrl({ host, port, username: item.username ?? item.user, password: item.password ?? item.pass })
  throw new Error('JSON 项缺少 url 或 host/port')
}

function extractCandidates(input) {
  const value = String(input || '').trim()
  if (!value) return []
  if (value.startsWith('[') || value.startsWith('{')) {
    try {
      const parsed = JSON.parse(value)
      const items = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed.proxies) ? parsed.proxies
          : Array.isArray(parsed.items) ? parsed.items
            : [parsed]
      return items.map(proxyCandidateFromJson)
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error('JSON 代理列表格式错误')
      throw error
    }
  }
  return value.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'))
}

function parseProxyInput(input) {
  const candidates = extractCandidates(input)
  const entries = []
  const errors = []
  const duplicates = []
  const seen = new Set()

  candidates.forEach((candidate, index) => {
    const line = index + 1
    try {
      const url = normalizeProxyUrl(candidate)
      if (seen.has(url.toLowerCase())) {
        duplicates.push({ line, displayUrl: maskProxyUrl(url) })
        return
      }
      seen.add(url.toLowerCase())
      entries.push({ url, displayUrl: maskProxyUrl(url), line })
    } catch (error) {
      errors.push({ line, message: error.message || '无法识别代理格式' })
    }
  })

  return { entries, errors, duplicates, total: candidates.length }
}

module.exports = {
  maskProxyUrl,
  normalizeProxyUrl,
  parseProxyInput
}
