'use strict'

const { analyzeClaudeSession } = require('./session-status')

function prepareImportedSession(imported, existing, decrypt, metadataOnly = false) {
  const incoming = imported && typeof imported === 'object' ? imported : {}
  const current = existing && typeof existing === 'object' ? existing : null
  if (metadataOnly || !incoming.encryptedCookies) {
    if (current) return { ...current }
    return {
      deviceImage: incoming.deviceImage || null,
      deviceImageProvenance: incoming.deviceImageProvenance || null,
      deviceImageCreatedAt: incoming.deviceImageCreatedAt || null,
      savedAt: null,
      cookieCount: 0,
      domains: [],
      authenticated: false,
      authVerifiedAt: null,
      encryptedCookies: null,
      desktopSessionSyncKey: null,
      desktopSessionSyncedAt: null,
      desktopSessionSyncError: null
    }
  }
  const cookies = decrypt(incoming.encryptedCookies)
  if (!Array.isArray(cookies)) throw new Error('导入会话无法在当前 Windows 用户下解密，原账号保持不变')
  const auth = analyzeClaudeSession(cookies)
  return {
    ...(current || {}),
    ...incoming,
    deviceImage: current?.deviceImage || incoming.deviceImage || null,
    cookieCount: auth.cookieCount,
    domains: auth.domains,
    authenticated: auth.authenticated,
    authVerifiedAt: null,
    sessionKeyName: auth.sessionKeyName,
    organizationId: auth.organizationId,
    desktopSessionSyncKey: null,
    desktopSessionSyncedAt: null,
    desktopSessionSyncError: null
  }
}

class SessionCaptureGate {
  constructor() {
    this.inFlight = new Map()
    this.blocked = new Set()
  }

  isBlocked(id) {
    return this.blocked.has(id)
  }

  capture(id, operation) {
    if (this.isBlocked(id)) return Promise.resolve(null)
    const previous = this.inFlight.get(id)
    const pending = Promise.resolve(previous).catch(() => {}).then(() => {
      if (this.isBlocked(id)) return null
      return operation()
    })
    this.inFlight.set(id, pending)
    void pending.finally(() => {
      if (this.inFlight.get(id) === pending) this.inFlight.delete(id)
    }).catch(() => {})
    return pending
  }

  async reset(id, operation) {
    if (this.isBlocked(id)) throw new Error('该账号的会话正在清理')
    this.blocked.add(id)
    try {
      await this.inFlight.get(id)?.catch(() => {})
      return await operation()
    } finally {
      this.blocked.delete(id)
    }
  }
}

module.exports = { prepareImportedSession, SessionCaptureGate }
