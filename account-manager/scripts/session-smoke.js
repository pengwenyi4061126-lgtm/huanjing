'use strict'

const assert = require('node:assert/strict')
const { prepareImportedSession, SessionCaptureGate } = require('../src/account-session')

const cookie = { domain: '.claude.ai', name: 'sessionKey', value: 'fixture-session' }
const org = { domain: '.claude.ai', name: 'lastActiveOrg', value: '123e4567-e89b-12d3-a456-426614174000' }
const current = {
  encryptedCookies: 'encrypted-existing',
  authenticated: true,
  cookieCount: 2,
  deviceImage: { imageSha256: 'locked-image' },
  desktopSessionSyncKey: 'existing-key'
}

assert.deepEqual(prepareImportedSession({
  encryptedCookies: null,
  authenticated: true,
  cookieCount: 2
}, current, () => { throw new Error('metadata must not decrypt') }, true), current)
assert.deepEqual(prepareImportedSession({}, current, () => null), current)
const newMetadata = prepareImportedSession({
  authenticated: true,
  cookieCount: 2,
  deviceImage: current.deviceImage
}, null, () => null, true)
assert.equal(newMetadata.authenticated, false)
assert.equal(newMetadata.encryptedCookies, null)
assert.equal(newMetadata.cookieCount, 0)
assert.deepEqual(newMetadata.deviceImage, current.deviceImage)

const imported = prepareImportedSession({
  encryptedCookies: 'encrypted-new',
  authenticated: true,
  cookieCount: 99,
  deviceImage: current.deviceImage
}, current, () => [cookie, org])
assert.equal(imported.encryptedCookies, 'encrypted-new')
assert.equal(imported.cookieCount, 2)
assert.equal(imported.authenticated, true)
assert.equal(imported.desktopSessionSyncKey, null)
assert.throws(() => prepareImportedSession({ encryptedCookies: 'wrong-user' }, current, () => null), /无法.*解密/)
assert.equal(prepareImportedSession({ encryptedCookies: 'expired' }, null, () => [
  { ...cookie, expirationDate: 1 }, org
]).authenticated, false)

async function main() {
  const gate = new SessionCaptureGate()
  const order = []
  let release
  let started
  const captureStarted = new Promise((resolve) => { started = resolve })
  const inFlight = gate.capture('profile-a', async () => {
    started()
    await new Promise((resolve) => { release = resolve })
    order.push('capture-finished')
  })
  await captureStarted
  const queued = gate.capture('profile-a', async () => { order.push('stale-capture') })
  const reset = gate.reset('profile-a', async () => { order.push('cleared') })
  assert.equal(gate.isBlocked('profile-a'), true)
  assert.equal(await gate.capture('profile-a', async () => { order.push('late-capture') }), null)
  await gate.capture('profile-b', async () => { order.push('other-profile') })
  release()
  await Promise.all([inFlight, queued, reset])
  assert.deepEqual(order, ['other-profile', 'capture-finished', 'cleared'])
  assert.equal(gate.isBlocked('profile-a'), false)
  await gate.capture('profile-a', async () => { order.push('new-capture') })
  assert.equal(order.at(-1), 'new-capture')
  await assert.rejects(gate.reset('profile-a', async () => { throw new Error('failed clear') }), /failed clear/)
  assert.equal(gate.isBlocked('profile-a'), false)
  console.log('[PASS] import preserves working session and clear/delete waits for capture')
}

main().catch((error) => { console.error(error); process.exitCode = 1 })
