'use strict'

const https = require('node:https')
const net = require('node:net')
const tls = require('node:tls')
const { normalizeProxyUrl } = require('./proxy-input')
const { normalizeProxyGeo } = require('./proxy-profile')

function createSocketConnection(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port })
    let settled = false
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      socket.destroy()
      finish(new Error('代理连接超时'))
    }, timeoutMs)
    socket.once('connect', () => finish(null, socket))
    socket.once('error', (error) => finish(error))
  })
}

function createBufferedSocketReader(socket) {
  let buffer = Buffer.alloc(0)
  let failure = null
  let detached = false
  const waiters = []

  const drain = () => {
    while (waiters.length) {
      const waiter = waiters[0]
      if (failure) {
        waiters.shift()
        clearTimeout(waiter.timer)
        waiter.reject(failure)
        continue
      }
      if (buffer.length < waiter.length) return
      waiters.shift()
      clearTimeout(waiter.timer)
      const chunk = buffer.subarray(0, waiter.length)
      buffer = buffer.subarray(waiter.length)
      waiter.resolve(chunk)
    }
  }
  const fail = (error) => {
    if (!failure) failure = error instanceof Error ? error : new Error(String(error || 'SOCKS5 socket closed'))
    drain()
  }
  const onData = (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    drain()
  }
  const onError = (error) => fail(error)
  const onEnd = () => fail(new Error('SOCKS5 连接在握手完成前关闭'))
  const onClose = () => fail(new Error('SOCKS5 连接在握手完成前关闭'))

  socket.on('data', onData)
  socket.once('error', onError)
  socket.once('end', onEnd)
  socket.once('close', onClose)

  return {
    read(length, timeoutMs, label) {
      return new Promise((resolve, reject) => {
        const waiter = {
          length,
          resolve,
          reject,
          timer: setTimeout(() => {
            const index = waiters.indexOf(waiter)
            if (index >= 0) waiters.splice(index, 1)
            reject(new Error(`${label}超时`))
          }, timeoutMs)
        }
        waiters.push(waiter)
        drain()
      })
    },
    detach() {
      if (detached) return
      detached = true
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('end', onEnd)
      socket.off('close', onClose)
      if (buffer.length) socket.unshift(buffer)
      buffer = Buffer.alloc(0)
    },
    dispose() {
      if (detached) return
      detached = true
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('end', onEnd)
      socket.off('close', onClose)
      for (const waiter of waiters.splice(0)) {
        clearTimeout(waiter.timer)
        waiter.reject(failure || new Error('SOCKS5 reader closed'))
      }
      buffer = Buffer.alloc(0)
    }
  }
}

async function socks5Connect(rawUrl, targetHost, targetPort, timeoutMs = 15000) {
  const proxy = new URL(normalizeProxyUrl(rawUrl))
  const socket = await createSocketConnection(proxy.hostname, Number(proxy.port || 1080), timeoutMs)
  const reader = createBufferedSocketReader(socket)
  const username = decodeURIComponent(proxy.username || '')
  const password = decodeURIComponent(proxy.password || '')
  if (Buffer.byteLength(username) > 255 || Buffer.byteLength(password) > 255) {
    socket.destroy()
    throw new Error('SOCKS5 用户名或密码超过 255 字节')
  }
  try {
    const methods = username || password ? Buffer.from([0x05, 0x01, 0x02]) : Buffer.from([0x05, 0x01, 0x00])
    socket.write(methods)
    const selected = await reader.read(2, timeoutMs, 'SOCKS5 方法协商')
    if (selected[0] !== 0x05 || selected[1] === 0xff) throw new Error('SOCKS5 不接受认证方式')
    if (selected[1] === 0x02) {
      const userBuf = Buffer.from(username)
      const passBuf = Buffer.from(password)
      socket.write(Buffer.concat([Buffer.from([0x01, userBuf.length]), userBuf, Buffer.from([passBuf.length]), passBuf]))
      const auth = await reader.read(2, timeoutMs, 'SOCKS5 用户名密码认证')
      if (auth[1] !== 0x00) throw new Error('SOCKS5 用户名或密码错误')
    } else if (selected[1] !== 0x00) {
      throw new Error(`SOCKS5 返回了不支持的认证方式: 0x${selected[1].toString(16)}`)
    }

    const hostBuf = Buffer.from(String(targetHost), 'utf8')
    if (!hostBuf.length || hostBuf.length > 255) throw new Error('SOCKS5 目标域名长度无效')
    const port = Number(targetPort)
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SOCKS5 目标端口无效')
    socket.write(Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
      hostBuf,
      Buffer.from([(port >> 8) & 0xff, port & 0xff])
    ]))
    const head = await reader.read(4, timeoutMs, 'SOCKS5 CONNECT 响应')
    if (head[1] !== 0x00) throw new Error(`SOCKS5 CONNECT 失败: 0x${head[1].toString(16)}`)
    let addressLength
    if (head[3] === 0x01) addressLength = 4
    else if (head[3] === 0x04) addressLength = 16
    else if (head[3] === 0x03) addressLength = (await reader.read(1, timeoutMs, 'SOCKS5 绑定域名长度'))[0]
    else throw new Error(`SOCKS5 返回了未知地址类型: 0x${head[3].toString(16)}`)
    await reader.read(addressLength + 2, timeoutMs, 'SOCKS5 绑定地址')
    reader.detach()
    return socket
  } catch (error) {
    reader.dispose()
    socket.destroy()
    throw error
  }
}

async function waitForTls(secure, timeoutMs) {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      secure.destroy()
      reject(new Error('SOCKS5 TLS 握手超时'))
    }, timeoutMs)
    const cleanup = () => {
      clearTimeout(timer)
      secure.off('secureConnect', onConnect)
      secure.off('error', onError)
    }
    const onConnect = () => { cleanup(); resolve() }
    const onError = (error) => { cleanup(); reject(error) }
    secure.once('secureConnect', onConnect)
    secure.once('error', onError)
  })
}

async function requestHttpsOverSocks(rawUrl, host, requestPath, timeoutMs = 15000) {
  const normalizedUrl = normalizeProxyUrl(rawUrl)
  const url = new URL(normalizedUrl)
  const scheme = url.protocol.replace(':', '').toLowerCase()
  if (scheme !== 'socks5' && scheme !== 'socks5h') throw new Error('当前请求只支持 socks5/socks5h')
  const socket = await socks5Connect(normalizedUrl, host, 443, timeoutMs)
  const secure = tls.connect({
    socket,
    servername: host,
    rejectUnauthorized: true,
    ALPNProtocols: ['http/1.1']
  })
  try {
    await waitForTls(secure, timeoutMs)
    const agent = new https.Agent({ keepAlive: false })
    agent.createConnection = () => secure
    return await new Promise((resolve, reject) => {
      let settled = false
      const finish = (error, value) => {
        if (settled) return
        settled = true
        if (error) reject(error)
        else resolve(value)
      }
      const request = https.request({
        method: 'GET',
        host,
        port: 443,
        path: requestPath,
        agent,
        headers: {
          Accept: 'application/json,text/plain;q=0.9',
          'Accept-Encoding': 'identity',
          Connection: 'close',
          'User-Agent': 'cac-account-manager'
        }
      }, (response) => {
        const chunks = []
        let total = 0
        response.on('data', (chunk) => {
          const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          total += value.length
          if (total > 1024 * 1024) {
            response.destroy(new Error('SOCKS5 HTTPS 响应超过 1 MiB'))
            return
          }
          chunks.push(value)
        })
        response.once('aborted', () => finish(new Error('SOCKS5 HTTPS 响应被中止')))
        response.once('error', (error) => finish(error))
        response.once('end', () => {
          const headers = new Map(Object.entries(response.headers).map(([name, value]) => [
            name,
            Array.isArray(value) ? value.join(', ') : String(value || '')
          ]))
          finish(null, {
            statusCode: Number(response.statusCode || 0),
            headers,
            body: Buffer.concat(chunks).toString('utf8').trim()
          })
        })
      })
      request.setTimeout(timeoutMs, () => request.destroy(new Error('SOCKS5 HTTPS 请求超时')))
      request.once('socket', (assigned) => {
        if (assigned !== secure) request.destroy(new Error('SOCKS5 HTTPS request bypassed the proxy socket'))
      })
      request.once('error', (error) => finish(error))
      request.end()
    })
  } finally {
    secure.destroy()
  }
}

function inspectClaudeResponse(response) {
  const statusCode = Number(response.statusCode || 0)
  return {
    statusCode,
    httpOk: statusCode >= 200 && statusCode < 400,
    challenge: statusCode === 403 && String(response.headers.get('cf-mitigated') || '').toLowerCase() === 'challenge'
  }
}

function parseIp2LocationExit(body) {
  const title = String(body || '').match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1] || ''
  const candidate = title.replace(/&nbsp;/gi, ' ').trim().split(/\s+/, 1)[0].replace(/^\[|\]$/g, '')
  return net.isIP(candidate) ? candidate : ""
}

async function probeIp2Location(rawUrl, timeoutMs = 15000) {
  const response = await requestHttpsOverSocks(rawUrl, 'www.ip2location.com', '/demo', timeoutMs)
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`IP2Location HTTP ${response.statusCode}`)
  }
  const externalIp = parseIp2LocationExit(response.body)
  if (!externalIp) throw new Error('IP2Location 未返回可识别的出口 IP')
  return { externalIp, statusCode: response.statusCode }
}

async function testSocks5(rawUrl, timeoutMs = 15000, options = {}) {
  const started = Date.now()
  const response = await requestHttpsOverSocks(rawUrl, 'api.ipify.org', '/?format=json', timeoutMs)
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`出口 IP 请求 HTTP ${response.statusCode}`)
  }
  let externalIp = response.body
  try { externalIp = JSON.parse(response.body).ip || response.body } catch { }
  externalIp = String(externalIp || '').trim()
  if (!net.isIP(externalIp)) throw new Error('代理返回了无效的出口 IP 响应')
  const result = {
    success: true,
    latencyMs: Date.now() - started,
    externalIp,
    dnsMode: 'socks5-domain-atyp-3'
  }
  try {
    const ip2Location = await probeIp2Location(rawUrl, timeoutMs)
    result.ip2Location = {
      ...ip2Location,
      sameAsIpify: ip2Location.externalIp === externalIp
    }
  } catch (error) {
    result.ip2Location = { error: error.message || String(error) }
  }
  if (options.probeClaude) {
    try {
      const claudeResponse = await requestHttpsOverSocks(rawUrl, 'claude.ai', '/login', timeoutMs)
      result.claude = inspectClaudeResponse(claudeResponse)
    } catch (error) {
      result.claude = { httpOk: false, challenge: false, error: error.message }
    }
  }
  return result
}

async function probeSocks5Profile(rawUrl, proxyId, options = {}) {
  const providers = [
    { name: 'ipapi.co', host: 'ipapi.co', path: '/json/' },
    { name: 'ipwho.is', host: 'ipwho.is', path: '/' }
  ]
  const failures = []
  for (const provider of providers) {
    try {
      const response = await requestHttpsOverSocks(rawUrl, provider.host, provider.path, options.timeoutMs)
      if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`HTTP ${response.statusCode}`)
      let payload
      try { payload = JSON.parse(response.body) } catch (error) {
        throw new Error(`JSON 无法解析: ${error.message}`)
      }
      return normalizeProxyGeo(payload, {
        proxyId,
        timezone: options.timezone,
        locale: options.locale,
        languages: options.languages,
        capturedUtc: options.capturedUtc,
        provider: provider.name
      })
    } catch (error) {
      failures.push(`${provider.name}: ${error.message}`)
    }
  }
  throw new Error(`SOCKS5 地理信息查询失败（${failures.join('；')}）`)
}

module.exports = {
  inspectClaudeResponse,
  parseIp2LocationExit,
  probeIp2Location,
  probeSocks5Profile,
  requestHttpsOverSocks,
  socks5Connect,
  testSocks5
}
