'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
assert.equal(packageJson.name, 'cac-account-manager')
assert.ok(packageJson.build.extraResources.length >= 3)
for (const file of ['src/main.js', 'src/preload.js', 'src/renderer/app.js', 'src/renderer/index.html', 'src/renderer/styles.css']) {
  assert.ok(fs.existsSync(path.join(root, file)), `missing ${file}`)
}
const profileName = 'profile-a'
assert.match(profileName, /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/)
assert.doesNotMatch('../profile-a', /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/)
console.log('[PASS] account-manager source and packaging smoke')
