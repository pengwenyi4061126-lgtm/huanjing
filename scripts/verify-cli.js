#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ccDir = process.argv[2];
const expectedVersion = process.argv[3] || '';

function fail(message) {
  process.stdout.write(JSON.stringify({ ok: false, error: message }) + '\n');
  process.exit(2);
}

if (!ccDir) fail('Claude Code install directory is required');

const pkgPath = path.join(ccDir, 'package.json');
const exePath = path.join(ccDir, 'bin', 'claude.exe');
if (!fs.existsSync(pkgPath)) fail('Claude Code package.json not found');
if (!fs.existsSync(exePath)) fail('Claude Code claude.exe not found');

let pkg;
try {
  pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
} catch (error) {
  fail(`Cannot parse package.json: ${error.message}`);
}

const bytes = fs.readFileSync(exePath);
const text = bytes.toString('latin1');
const markers = {
  tzDate: text.includes('function Ano(){return new Intl.DateTimeFormat("sv",{timeZone:process.env.TZ||"UTC"}'),
  tzCache: text.includes('function y_o(){if(!g)g=process.env.TZ||"UTC"'),
  language: text.includes('function hSs(){if(l===null)l="en"'),
  tzVariable: text.includes('let A=process.env.TZ||"UTC"'),
  locale: text.includes('.toLocaleDateString( "en" ,'),
  utcOffset: text.includes('Fe="+00:00"'),
};

const markersOk = Object.values(markers).every(Boolean);
const sha256 = crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();
const versionOk = pkg.version === expectedVersion;

const result = {
  ok: versionOk && markersOk,
  version: pkg.version || null,
  expectedVersion,
  exe: path.resolve(exePath),
  sha256,
  markers,
  markersOk,
  versionOk,
};
process.stdout.write(JSON.stringify(result) + '\n');
process.exit(result.ok ? 0 : 2);
