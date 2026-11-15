'use strict'

const net = require('node:net')
const FIXED_US_TIMEZONE = 'America/New_York'
const FIXED_US_LOCALE = 'en-US'
const FIXED_US_LANGUAGES = Object.freeze(['en-US', 'en'])

function requireText(value, label) {
  const text = String(value || '').trim()
  if (!text) throw new Error(`SOCKS5 地理信息缺少 ${label}`)
  return text
}

function canonicalTimeZone(value) {
  const requested = requireText(value, 'timezone')
  try {
    return new Intl.DateTimeFormat('en-US', { timeZone: requested }).resolvedOptions().timeZone
  } catch {
    throw new Error(`SOCKS5 地理信息返回了无效时区: ${requested}`)
  }
}

function canonicalLocale(value, countryCode) {
  let requested = String(value || '').trim().replace(/_/g, '-')
  if (!requested) throw new Error('Profile 语言为空')
  if (/^[A-Za-z]{2,3}$/.test(requested) && /^[A-Z]{2}$/.test(countryCode)) {
    requested = `${requested.toLowerCase()}-${countryCode}`
  }
  try {
    return Intl.getCanonicalLocales(requested)[0]
  } catch {
    throw new Error(`Profile 语言无效: ${requested}`)
  }
}

function normalizeSystemLanguages(locale, values) {
  const primary = canonicalLocale(locale || FIXED_US_LOCALE, '')
  const candidates = [primary, ...(Array.isArray(values) ? values : [])]
  const normalized = []
  for (const value of candidates) {
    try {
      const item = Intl.getCanonicalLocales(String(value || '').trim().replace(/_/g, '-'))[0]
      if (item && !normalized.includes(item)) normalized.push(item)
    } catch { }
  }
  const base = primary.split('-')[0]
  if (base && !normalized.includes(base)) normalized.push(base)
  return normalized.length ? normalized : [...FIXED_US_LANGUAGES]
}

function normalizeProxyGeo(payload, options = {}) {
  if (!payload || typeof payload !== 'object') throw new Error('SOCKS5 地理信息响应不是 JSON 对象')
  if (payload.error === true) throw new Error(`SOCKS5 地理信息查询失败: ${payload.reason || payload.message || 'unknown error'}`)

  const externalIp = requireText(payload.ip, '出口 IP')
  if (!net.isIP(externalIp)) throw new Error(`SOCKS5 地理信息返回了无效出口 IP: ${externalIp}`)
  const countryCode = requireText(payload.country_code || payload.countryCode, '国家代码').toUpperCase()
  if (!/^[A-Z]{2}$/.test(countryCode)) throw new Error(`SOCKS5 地理信息返回了无效国家代码: ${countryCode}`)
  const timezone = canonicalTimeZone(FIXED_US_TIMEZONE)
  const locale = canonicalLocale(FIXED_US_LOCALE, '')
  const languages = [...FIXED_US_LANGUAGES]

  return {
    source: 'first-socks5',
    provider: String(options.provider || 'ipapi.co'),
    proxyId: requireText(options.proxyId, 'proxyId'),
    externalIp,
    countryCode,
    country: String(payload.country_name || payload.country || '').trim().slice(0, 120),
    region: String(payload.region || payload.region_name || '').trim().slice(0, 120),
    city: String(payload.city || '').trim().slice(0, 120),
    timezone,
    locale,
    languages,
    dnsMode: 'socks5-domain-atyp-3',
    capturedUtc: String(options.capturedUtc || new Date().toISOString())
  }
}

function profileGenesisEnvironment(profile) {
  if (!profile || profile.source !== 'first-socks5') throw new Error('Profile 初始化缺少首个 SOCKS5 画像')
  if (profile.timezone !== FIXED_US_TIMEZONE || profile.locale !== FIXED_US_LOCALE ||
      !Array.isArray(profile.languages) || profile.languages.length !== FIXED_US_LANGUAGES.length ||
      profile.languages.some((language, index) => language !== FIXED_US_LANGUAGES[index])) {
    throw new Error('Profile timezone/language must match fixed America/New_York and en-US,en')
  }
  return {
    CAC_PROFILE_TIMEZONE: profile.timezone,
    CAC_PROFILE_LOCALE: profile.locale,
    CAC_PROFILE_LANGUAGES: profile.languages.join(','),
    CAC_PROFILE_ORIGIN_PROVIDER: profile.provider,
    CAC_PROFILE_ORIGIN_PROXY_ID: profile.proxyId,
    CAC_PROFILE_ORIGIN_IP: profile.externalIp,
    CAC_PROFILE_ORIGIN_COUNTRY: profile.countryCode,
    CAC_PROFILE_ORIGIN_REGION: profile.region,
    CAC_PROFILE_ORIGIN_CITY: profile.city,
    CAC_PROFILE_ORIGIN_DNS_MODE: profile.dnsMode,
    CAC_PROFILE_ORIGIN_CAPTURED_UTC: profile.capturedUtc
  }
}

module.exports = {
  FIXED_US_LANGUAGES,
  FIXED_US_LOCALE,
  FIXED_US_TIMEZONE,
  canonicalLocale,
  canonicalTimeZone,
  normalizeProxyGeo,
  normalizeSystemLanguages,
  profileGenesisEnvironment
}
