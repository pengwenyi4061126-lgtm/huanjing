'use strict'

function normalizeLanguages(persona) {
  const values = Array.isArray(persona?.languages) ? persona.languages : []
  const languages = values.map((value) => String(value || '').trim()).filter(Boolean)
  if (!languages.length && persona?.locale) languages.push(String(persona.locale).trim())
  return [...new Set(languages)]
}

function validatePersona(persona) {
  if (!persona || typeof persona !== 'object') throw new Error('Profile 指纹配置无效')
  const ua = String(persona.ua || '').trim()
  const timezone = String(persona.timezone || '').trim()
  const locale = String(persona.locale || '').trim()
  const languages = normalizeLanguages(persona)
  if (!ua) throw new Error('Profile 指纹缺少 userAgent')
  if (!timezone) throw new Error('Profile 指纹缺少 timezone')
  if (!locale || !languages.length) throw new Error('Profile 指纹缺少 locale/languages')
  return { ua, timezone, locale, languages }
}

function applyLoginSessionPersona(sess, persona) {
  const normalized = validatePersona(persona)
  if (!sess || typeof sess.setUserAgent !== 'function') {
    throw new Error('Electron Session 不支持 userAgent/Accept-Language 绑定')
  }
  sess.setUserAgent(normalized.ua, normalized.languages.join(','))
  return normalized
}

function withTimeout(promise, label, timeoutMs = 10000) {
  let timer
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} 超时`)), timeoutMs)
    })
  ]).finally(() => clearTimeout(timer))
}

async function installLoginWebContentsPersona(webContents, fingerprint) {
  const persona = fingerprint?.persona
  const source = String(fingerprint?.script || '')
  const normalized = validatePersona(persona)
  if (!source) throw new Error('Profile 指纹注入脚本为空')
  if (!webContents?.debugger) throw new Error('Electron WebContents 调试协议不可用')

  const debuggerApi = webContents.debugger
  if (!debuggerApi.isAttached()) debuggerApi.attach('1.3')
  await withTimeout(debuggerApi.sendCommand('Page.enable'), 'Page.enable')
  await withTimeout(debuggerApi.sendCommand('Network.enable'), 'Network.enable')
  const installed = await withTimeout(
    debuggerApi.sendCommand('Page.addScriptToEvaluateOnNewDocument', { source }),
    'Page.addScriptToEvaluateOnNewDocument'
  )
  if (!installed?.identifier) throw new Error('页面指纹启动脚本未返回 identifier')
  await withTimeout(debuggerApi.sendCommand('Network.setUserAgentOverride', {
    userAgent: normalized.ua,
    acceptLanguage: normalized.languages.join(','),
    platform: String(persona.platform || 'Win32')
  }), 'Network.setUserAgentOverride')
  await withTimeout(
    debuggerApi.sendCommand('Emulation.setTimezoneOverride', { timezoneId: normalized.timezone }),
    'Emulation.setTimezoneOverride'
  )
  await withTimeout(
    debuggerApi.sendCommand('Emulation.setLocaleOverride', { locale: normalized.locale }),
    'Emulation.setLocaleOverride'
  )
  return {
    mode: 'cdp-main-world',
    scriptIdentifier: installed.identifier,
    userAgent: normalized.ua,
    languages: normalized.languages,
    timezone: normalized.timezone,
    locale: normalized.locale
  }
}

module.exports = {
  applyLoginSessionPersona,
  installLoginWebContentsPersona,
  normalizeLanguages,
  validatePersona
}
