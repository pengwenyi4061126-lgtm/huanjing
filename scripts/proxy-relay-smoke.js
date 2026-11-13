'use strict';

const assert = require('assert');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function readUntil(socket, predicate, timeout = 5000) {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    const timer = setTimeout(() => { cleanup(); reject(new Error('timeout')); }, timeout);
    function cleanup() { clearTimeout(timer); socket.removeListener('data', onData); socket.removeListener('error', onError); }
    function onError(error) { cleanup(); reject(error); }
    function onData(chunk) {
      data = Buffer.concat([data, Buffer.from(chunk)]);
      const value = predicate(data);
      if (value) { cleanup(); resolve(value); }
    }
    socket.on('data', onData);
    socket.on('error', onError);
  });
}

function waitForHealth(port, child, stderr) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 5000;
    const probe = () => {
      if (child.exitCode !== null) { reject(new Error('relay exited: ' + stderr())); return; }
      const socket = net.connect(port, '127.0.0.1');
      socket.once('connect', () => {
        socket.write('GET http://cac-relay.local/__cac_relay_health__ HTTP/1.1\r\nHost: cac-relay.local\r\nConnection: close\r\n\r\n');
        readUntil(socket, (data) => data.includes(Buffer.from('X-Cac-Relay: ready')) ? data : null, 500)
          .then(() => { socket.destroy(); resolve(); })
          .catch(() => { socket.destroy(); retry(); });
      });
      socket.once('error', () => { socket.destroy(); retry(); });
    };
    const retry = () => {
      if (Date.now() >= deadline) { reject(new Error('relay did not pass health handshake: ' + stderr())); return; }
      setTimeout(probe, 50);
    };
    probe();
  });
}

function startRelay(upstreamUrl) {
  return freePort().then((port) => {
    const relayPath = path.join(__dirname, '..', 'src', 'relay.js');
    const pidFile = path.join(os.tmpdir(), 'cac-relay-smoke-' + process.pid + '-' + port + '.pid');
    const child = spawn(process.execPath, [relayPath, String(port), pidFile], {
      env: Object.assign({}, process.env, { CAC_RELAY_UPSTREAM_URL: upstreamUrl, CAC_RELAY_PID_FILE: pidFile }),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    let errorText = '';
    child.stderr.on('data', (chunk) => { errorText += chunk.toString(); });
    return waitForHealth(port, child, () => errorText).then(() => ({ child, port, pidFile, stderr: () => errorText }));
  });
}

function stopRelay(relay) {
  if (!relay) return Promise.resolve();
  if (relay.child.exitCode === null) relay.child.kill();
  return new Promise((resolve) => {
    if (relay.child.exitCode !== null) return resolve();
    relay.child.once('exit', resolve);
    setTimeout(resolve, 1000);
  });
}

function ipv6Bytes() {
  return Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
}

function startSocksServer(options = {}) {
  const auth = options.auth || null;
  const requests = [];
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    const state = { buffer: Buffer.alloc(0), greetingDone: false, authDone: !auth, target: null, payload: Buffer.alloc(0), replied: false };
    function processBuffer() {
      if (!state.greetingDone) {
        if (state.buffer.length < 2) return;
        const methodCount = state.buffer[1];
        if (state.buffer[0] !== 0x05 || state.buffer.length < 2 + methodCount) return;
        if (auth) {
          if (state.buffer.slice(2, 2 + methodCount).indexOf(0x02) === -1) {
            socket.write(Buffer.from([0x05, 0xff]));
            socket.destroy();
            return;
          }
          socket.write(Buffer.from([0x05, 0x02]));
        } else {
          socket.write(Buffer.from([0x05, 0x00]));
        }
        state.buffer = state.buffer.slice(2 + methodCount);
        state.greetingDone = true;
      }
      if (auth && !state.authDone) {
        if (state.buffer.length < 2) return;
        const userLength = state.buffer[1];
        if (state.buffer.length < 3 + userLength) return;
        const passLength = state.buffer[2 + userLength];
        const authLength = 3 + userLength + passLength;
        if (state.buffer.length < authLength) return;
        const username = state.buffer.slice(2, 2 + userLength).toString();
        const password = state.buffer.slice(3 + userLength, authLength).toString();
        if (state.buffer[0] !== 0x01 || username !== auth.username || password !== auth.password) {
          socket.write(Buffer.from([0x01, 0x01]));
          socket.destroy();
          return;
        }
        socket.write(Buffer.from([0x01, 0x00]));
        state.buffer = state.buffer.slice(authLength);
        state.authDone = true;
      }
      if (!state.target) {
        if (state.buffer.length < 4) return;
        if (state.buffer[0] !== 0x05 || state.buffer[1] !== 0x01) throw new Error('invalid SOCKS request');
        const atyp = state.buffer[3];
        let total;
        let address;
        let host;
        if (atyp === 0x01) {
          total = 10;
          if (state.buffer.length < total) return;
          address = state.buffer.slice(4, 8);
          host = Array.from(address).join('.');
        } else if (atyp === 0x04) {
          total = 22;
          if (state.buffer.length < total) return;
          address = state.buffer.slice(4, 20);
          host = address.toString('hex');
        } else if (atyp === 0x03) {
          if (state.buffer.length < 5) return;
          total = 7 + state.buffer[4];
          if (state.buffer.length < total) return;
          address = state.buffer.slice(5, 5 + state.buffer[4]);
          host = address.toString();
        } else {
          throw new Error('invalid SOCKS ATYP');
        }
        state.target = { atyp, address, host, port: state.buffer.readUInt16BE(total - 2) };
        requests.push(state.target);
        socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 1]));
        state.buffer = state.buffer.slice(total);
      }
      if (state.buffer.length) {
        state.payload = Buffer.concat([state.payload, state.buffer]);
        state.buffer = Buffer.alloc(0);
        if (!state.replied) {
          state.replied = true;
          if (state.payload.includes(Buffer.from('GET /plain HTTP/1.1'))) {
            socket.write('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
          } else {
            socket.write(Buffer.from([0xde, 0xad, 0xbe, 0xef]));
          }
        }
      }
      if (state.target) state.target.payload = state.payload;
    }
    socket.on('data', (chunk) => {
      state.buffer = Buffer.concat([state.buffer, Buffer.from(chunk)]);
      try { processBuffer(); } catch (error) { socket.destroy(error); }
    });
    socket.on('error', () => {});
    socket.state = state;
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      requests,
      close: () => new Promise((done) => { for (const socket of sockets) socket.destroy(); server.close(() => done()); })
    }));
  });
}

async function connectAndRead(port, request, predicate, timeout = 5000, label = 'request') {
  const socket = net.connect(port, '127.0.0.1');
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  socket.write(request);
  try { return await readUntil(socket, predicate, timeout); }
  catch (error) { throw new Error(label + ': ' + error.message); }
  finally { socket.destroy(); }
}

async function runSocksRegression(scheme, server, credentials = null) {
  const authPrefix = credentials ? `${encodeURIComponent(credentials.username)}:${encodeURIComponent(credentials.password)}@` : '';
  const relay = await startRelay(`${scheme}://${authPrefix}127.0.0.1:${server.port}`);
  try {
    const binaryTail = Buffer.from([0x00, 0xff, 0x80, 0x2a]);
    try {
      await connectAndRead(relay.port, Buffer.concat([Buffer.from('CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n'), binaryTail]),
        (data) => data.includes(Buffer.from('200 Connection Established')) && data.includes(Buffer.from([0xde, 0xad, 0xbe, 0xef])) ? data : null,
        5000, 'domain CONNECT');
    } catch (error) {
      throw new Error(error.message + '; upstream requests=' + JSON.stringify(server.requests) + '; relay=' + relay.stderr());
    }
    const domain = server.requests[server.requests.length - 1];
    assert.strictEqual(domain.atyp, 0x03);
    assert.strictEqual(domain.host, 'example.invalid');

    await connectAndRead(relay.port, Buffer.from('CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n'),
      (data) => data.includes(Buffer.from('200 Connection Established')) ? data : null,
      5000, 'IPv4 CONNECT');
    const ipv4 = server.requests[server.requests.length - 1];
    assert.strictEqual(ipv4.atyp, 0x01);
    assert.deepStrictEqual(Array.from(ipv4.address), [127, 0, 0, 1]);

    await connectAndRead(relay.port, Buffer.from('CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n'),
      (data) => data.includes(Buffer.from('200 Connection Established')) ? data : null,
      5000, 'IPv6 CONNECT');
    const ipv6 = server.requests[server.requests.length - 1];
    assert.strictEqual(ipv6.atyp, 0x04);
    assert.deepStrictEqual(Array.from(ipv6.address), Array.from(ipv6Bytes()));

    if (scheme === 'socks5') {
      const response = await connectAndRead(relay.port, Buffer.from('GET http://example.invalid/plain HTTP/1.1\r\nHost: example.invalid\r\nProxy-Authorization: Basic bGVhazpsZWFr\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n'),
        (data) => data.includes(Buffer.from('204 No Content')) ? data : null,
        5000, 'plain HTTP');
      assert(response.includes(Buffer.from('204 No Content')));
      const plain = server.requests[server.requests.length - 1];
      assert.strictEqual(plain.atyp, 0x03);
      assert.strictEqual(plain.host, 'example.invalid');
      assert(!plain.payload.toString('latin1').toLowerCase().includes('proxy-authorization'));
      assert(!plain.payload.toString('latin1').toLowerCase().includes('proxy-connection'));
    }
  } finally {
    await stopRelay(relay);
  }
}

async function runTimeoutRegression() {
  const sockets = new Set();
  const silent = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => silent.listen(0, '127.0.0.1', resolve).once('error', reject));
  const relay = await startRelay(`http://127.0.0.1:${silent.address().port}`);
  try {
    await connectAndRead(relay.port, Buffer.from('CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n'),
      (data) => data.includes(Buffer.from('502 Bad Gateway')) ? data : null, 10000, 'timeout CONNECT');
  } finally {
    await stopRelay(relay);
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => silent.close(resolve));
  }
}

(async () => {
  const server = await startSocksServer();
  try {
    await runSocksRegression('socks5h', server);
    await runSocksRegression('socks5', server);
    console.log('[PASS] SOCKS5/SOCKS5H routing, domain/IP ATYP, binary trailing and plain HTTP conversion');
  } finally {
    await server.close();
  }
  await runTimeoutRegression();
  console.log('[PASS] upstream handshake timeout and one-shot failure path');

  const authServer = await startSocksServer({ auth: { username: 'user', password: 'pass' } });
  try {
    await runSocksRegression('socks5h', authServer, { username: 'user', password: 'pass' });
    console.log('[PASS] SOCKS5 username/password authentication and proxy-header filtering');
  } finally {
    await authServer.close();
  }
})().catch((error) => { console.error('[FAIL] proxy relay smoke:', error.message); process.exitCode = 1; });
