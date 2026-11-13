'use strict';
const assert = require('assert');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

function readUntil(sock, predicate, timeout = 5000) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { cleanup(); reject(new Error('timeout')); }, timeout);
    function cleanup() { clearTimeout(timer); sock.removeListener('data', onData); sock.removeListener('error', onError); }
    function onError(err) { cleanup(); reject(err); }
    function onData(chunk) { buf = Buffer.concat([buf, chunk]); const value = predicate(buf); if (value) { cleanup(); resolve(value); } }
    sock.on('data', onData); sock.on('error', onError);
  });
}

(async () => {
  const upstreamPort = await freePort();
  const relayPort = await freePort();
  let requestedHost = null;
  const upstream = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    let greetingDone = false;
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!greetingDone && buf.length >= 3 && buf[0] === 0x05 && buf[1] === 0x01) {
        sock.write(Buffer.from([0x05, 0x00]));
        greetingDone = true;
        buf = buf.slice(3);
      }
      if (greetingDone && buf.length >= 5 && buf[0] === 0x05 && buf[1] === 0x01 && buf[3] === 0x03) {
        const length = buf[4];
        if (buf.length < 7 + length) return;
        requestedHost = buf.slice(5, 5 + length).toString();
        sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 1]));
      }
    });
  });
  const relayPath = path.join(__dirname, '..', 'src', 'relay.js');
  let child;
  try {
    await new Promise((resolve, reject) => upstream.listen(upstreamPort, '127.0.0.1', resolve).once('error', reject));
    child = spawn(process.execPath, [relayPath, String(relayPort), `socks5h://127.0.0.1:${upstreamPort}`], { stdio: 'ignore', windowsHide: true });
    await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('relay did not start')), 5000); const probe = () => { const s = net.connect(relayPort, '127.0.0.1', () => { clearTimeout(timer); s.destroy(); resolve(); }); s.once('error', () => setTimeout(probe, 100)); }; probe(); });
    const client = net.connect(relayPort, '127.0.0.1');
    await new Promise((resolve, reject) => { client.once('connect', resolve); client.once('error', reject); });
    client.write('CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n');
    const response = await readUntil(client, (buf) => buf.includes(Buffer.from('200 Connection Established')) ? buf : null);
    assert(response.includes(Buffer.from('200 Connection Established')));
    assert.strictEqual(requestedHost, 'example.invalid');
    client.destroy();
    console.log('[PASS] relay sends destination hostname as SOCKS5 domain (no local DNS lookup)');
  } finally {
    if (child) child.kill();
    await new Promise((resolve) => upstream.close(() => resolve()));
  }
})().catch((err) => { console.error('[FAIL] proxy relay smoke:', err.message); process.exitCode = 1; });
