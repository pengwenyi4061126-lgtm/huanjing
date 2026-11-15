'use strict'

const crypto = require('node:crypto')

function sha256(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8')
  return crypto.createHash('sha256').update(buffer).digest('hex').toUpperCase()
}

function requireText(value, label) {
  const text = String(value || '').trim()
  if (!text) throw new Error(`Device image is missing ${label}`)
  return text
}

function parseJsonBuffer(buffer, label) {
  try {
    return JSON.parse(buffer.toString('utf8').replace(/^\uFEFF/, ''))
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`)
  }
}

function buildImageSha256(identitySha256, personaSha256) {
  return sha256(`${identitySha256}:${personaSha256}`)
}

function verifyDeviceImage(options) {
  const profileName = requireText(options?.profileName, 'profile name')
  const identityBuffer = options?.identityBuffer
  const personaBuffer = options?.personaBuffer
  const lock = options?.lock
  if (!Buffer.isBuffer(identityBuffer)) throw new Error('Device image identity bytes are missing')
  if (!Buffer.isBuffer(personaBuffer)) throw new Error('Device image persona bytes are missing')
  if (!lock || typeof lock !== 'object') throw new Error('Device image lock is missing')

  const identity = parseJsonBuffer(identityBuffer, 'identity.json')
  const persona = parseJsonBuffer(personaBuffer, 'fingerprint.json')
  const identitySha256 = sha256(identityBuffer)
  const personaSha256 = sha256(personaBuffer)
  const imageSha256 = buildImageSha256(identitySha256, personaSha256)

  if (Number(lock.schema) !== 1) throw new Error(`Unsupported device image lock schema: ${lock.schema}`)
  if (String(lock.profile || '').toLowerCase() !== profileName.toLowerCase()) {
    throw new Error(`Device image lock belongs to another profile: ${lock.profile || '(empty)'}`)
  }
  if (String(lock.identitySha256 || '').toUpperCase() !== identitySha256) {
    throw new Error('identity.json changed after the device image was locked')
  }
  if (String(lock.personaSha256 || '').toUpperCase() !== personaSha256) {
    throw new Error('fingerprint.json changed after the device image was locked')
  }
  if (String(lock.imageSha256 || '').toUpperCase() !== imageSha256) {
    throw new Error('Device image composite digest does not match the locked files')
  }

  const machineId = requireText(identity.machine_id, 'machine_id')
  const seed = requireText(persona.seed, 'seed')
  const electronVersion = requireText(persona.uaElectronVersion, 'Electron version')
  const chromiumVersion = requireText(persona.uaChromiumVersion, 'Chromium version')
  if (String(lock.machineId || '') !== machineId) throw new Error('Device image machine_id does not match its lock')
  if (String(lock.seed || '') !== seed) throw new Error('Device image seed does not match its lock')
  if (String(lock.electronVersion || '') !== electronVersion) throw new Error('Device image Electron version does not match its lock')
  if (String(lock.chromiumVersion || '') !== chromiumVersion) throw new Error('Device image Chromium version does not match its lock')

  return {
    schema: 1,
    profile: profileName,
    lockedUtc: requireText(lock.lockedUtc, 'lock timestamp'),
    identitySha256,
    personaSha256,
    imageSha256,
    machineId,
    seed,
    electronVersion,
    chromiumVersion,
    identity,
    persona
  }
}

function assertRuntimeMatchesPersona(persona, versions = process.versions) {
  const expectedElectron = requireText(persona?.uaElectronVersion, 'Electron version')
  const expectedChromium = requireText(persona?.uaChromiumVersion, 'Chromium version')
  const actualElectron = requireText(versions?.electron, 'runtime Electron version')
  const actualChromium = requireText(versions?.chrome, 'runtime Chromium version')
  if (actualElectron !== expectedElectron || actualChromium !== expectedChromium) {
    throw new Error(
      `Login runtime ${actualElectron}/${actualChromium} does not match locked device image ${expectedElectron}/${expectedChromium}`
    )
  }
  return { electron: actualElectron, chromium: actualChromium }
}

function evidenceMatches(expected, actual) {
  return Boolean(expected?.imageSha256 && actual?.imageSha256 &&
    String(expected.imageSha256).toUpperCase() === String(actual.imageSha256).toUpperCase())
}

function publicEvidence(evidence) {
  return {
    schema: 1,
    profile: evidence.profile,
    lockedUtc: evidence.lockedUtc,
    identitySha256: evidence.identitySha256,
    personaSha256: evidence.personaSha256,
    imageSha256: evidence.imageSha256,
    machineId: evidence.machineId,
    seed: evidence.seed,
    electronVersion: evidence.electronVersion,
    chromiumVersion: evidence.chromiumVersion
  }
}

module.exports = {
  assertRuntimeMatchesPersona,
  buildImageSha256,
  evidenceMatches,
  publicEvidence,
  sha256,
  verifyDeviceImage
}
