'use strict'

const assert = require('node:assert/strict')
const net = require('node:net')
const { normalizeProxyUrl } = require('../src/proxy-input')
const { socks5Connect } = require('../src/socks-client')

const username = 'miya_g-US_c-Kansas%20City_sid-123_l-60'
const targetHost = 'claude.ai'
const observed = []

const server = net.createServer((socket) => {
  let buffer = Buffer.alloc(0)
  let stage = 'method'
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    while (true) {
      if (stage === 'method') {
        if (buffer.length < 3) return
        assert.deepEqual(buffer.subarray(0, 3), Buffer.from([5, 1, 2]))
        buffer = buffer.subarray(3)
        stage = 'auth'
        socket.write(Buffer.from([5, 2]))
      } else if (stage === 'auth') {
        if (buffer.length < 2) return
        const userLength = buffer[1]
        if (buffer.length < 3 + userLength) return
        const passLength = buffer[2 + userLength]
        if (buffer.length < 3 + userLength + passLength) return
        assert.equal(buffer.subarray(2, 2 + userLength).toString('utf8'), username)
        assert.equal(buffer.subarray(3 + userLength, 3 + userLength + passLength).toString('utf8'), 'pass')
        buffer = buffer.subarray(3 + userLength + passLength)
        stage = 'connect'
        socket.write(Buffer.from([1, 0]))
      } else if (stage === 'connect') {
        if (buffer.length < 5) return
        assert.deepEqual(buffer.subarray(0, 4), Buffer.from([5, 1, 0, 3]))
        const hostLength = buffer[4]
        if (buffer.length < 7 + hostLength) return
        assert.equal(buffer.subarray(5, 5 + hostLength).toString('utf8'), targetHost)
        assert.equal(buffer.readUInt16BE(5 + hostLength), 443)
        observed.push(true)
        stage = 'done'
        socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]))
        return
      } else {
        return
      }
    }
  })
})

async function main() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const raw = `127.0.0.1:${server.address().port}:${username}:pass`
  const normalized = normalizeProxyUrl(raw)
  try {
    assert.equal(decodeURIComponent(new URL(normalized).username), username)
    assert.equal(normalizeProxyUrl(normalized), normalized)
    for (const proxy of [raw, normalized]) {
      const socket = await socks5Connect(proxy, targetHost, 443, 5000)
      socket.destroy()
    }
    assert.equal(observed.length, 2)
    console.log('[PASS] encoded SOCKS username and remote domain handshake')
  } finally {
    server.close()
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; server.close() })
