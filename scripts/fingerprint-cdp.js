#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

function arg(name, fallback) {
  const index = process.argv.indexOf('--' + name);
  if (index < 0 || index + 1 >= process.argv.length) return fallback;
  return process.argv[index + 1];
}

const port = Number(arg('port', '9222'));
const personaPath = arg('persona', '');
const shimPath = arg('shim', path.join(__dirname, 'fingerprint-shim.js'));
const logPath = arg('log', '');
const waitSeconds = Number(arg('wait', '60'));
const ownerPid = Number(arg('pid', '0'));

function log(message) {
  const line = `[${new Date().toISOString()}] ${message}\n`;
  try {
    if (logPath) fs.appendFileSync(logPath, line);
  } catch (_) {}
  if (process.env.CAC_FINGERPRINT_VERBOSE === '1') process.stdout.write(line);
}

function fail(message) {
  log('ERROR ' + message);
  process.stderr.write('[cac-fingerprint] ' + message + '\n');
  process.exit(1);
}

function listen(target, event, handler) {
  if (target && typeof target.addEventListener === 'function') {
    target.addEventListener(event, handler);
    return;
  }
  if (target && typeof target.on === 'function') {
    target.on(event, (...args) => {
      if (event === 'message') handler({ data: args[0] });
      else handler(args[0]);
    });
  }
}

function requestJson(url) {
  if (typeof globalThis.fetch === 'function') {
    return globalThis.fetch(url).then((response) => {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.json();
    });
  }
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const transport = target.protocol === 'https:' ? https : http;
    const request = transport.get(target, { headers: { accept: 'application/json' } }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error('HTTP ' + response.statusCode));
          return;
        }
        try { resolve(JSON.parse(body)); }
        catch (error) { reject(new Error('invalid JSON: ' + error.message)); }
      });
    });
    request.setTimeout(5000, () => request.destroy(new Error('HTTP request timeout')));
    request.on('error', reject);
  });
}

class TinyWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.events = new Map();
    this.buffer = Buffer.alloc(0);
    this.fragments = [];
    this.fragmentOpcode = 0;
    this.handshakeComplete = false;
    this.closeEmitted = false;
    this.key = crypto.randomBytes(16).toString('base64');
    const target = new URL(url);
    const secure = target.protocol === 'wss:';
    const options = { host: target.hostname, port: Number(target.port || (secure ? 443 : 80)) };
    this.socket = secure ? tls.connect(options, () => this.sendHandshake(target))
      : net.connect(options, () => this.sendHandshake(target));
    this.socket.setNoDelay(true);
    this.socket.on('data', (chunk) => {
      try { this.onData(chunk); }
      catch (error) {
        this.emit('error', error);
        this.socket.destroy();
      }
    });
    this.socket.on('error', (error) => this.emit('error', error));
    this.socket.on('close', () => this.emitClose());
  }

  addEventListener(event, handler) {
    const handlers = this.events.get(event) || [];
    handlers.push(handler);
    this.events.set(event, handlers);
  }

  emit(event, value) {
    for (const handler of this.events.get(event) || []) {
      try { handler(value); } catch (_) {}
    }
  }

  emitClose() {
    if (this.closeEmitted) return;
    this.closeEmitted = true;
    this.readyState = 3;
    this.emit('close', {});
  }

  sendHandshake(target) {
    const pathName = (target.pathname || '/') + (target.search || '');
    this.socket.write([
      'GET ' + pathName + ' HTTP/1.1',
      'Host: ' + target.host,
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Key: ' + this.key,
      'Sec-WebSocket-Version: 13',
      '\r\n',
    ].join('\r\n'));
  }

  onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (!this.handshakeComplete) {
      const marker = this.buffer.indexOf(Buffer.from('\r\n\r\n'));
      if (marker < 0) return;
      const header = this.buffer.subarray(0, marker).toString('latin1');
      this.buffer = this.buffer.subarray(marker + 4);
      const lines = header.split('\r\n');
      if (!/^HTTP\/1\.1 101\b/.test(lines[0] || '')) {
        this.emit('error', new Error('CDP WebSocket upgrade failed: ' + (lines[0] || '')));
        this.socket.destroy();
        return;
      }
      const headers = {};
      for (const line of lines.slice(1)) {
        const separator = line.indexOf(':');
        if (separator > 0) headers[line.slice(0, separator).trim().toLowerCase()] =
          line.slice(separator + 1).trim();
      }
      const expected = crypto.createHash('sha1')
        .update(this.key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        .digest('base64');
      if (headers['sec-websocket-accept'] !== expected) {
        this.emit('error', new Error('CDP WebSocket accept mismatch'));
        this.socket.destroy();
        return;
      }
      this.handshakeComplete = true;
      this.readyState = 1;
      this.emit('open', {});
    }
    this.readFrames();
  }

  readFrames() {
    while (this.buffer.length >= 2) {
      const first = this.buffer[0];
      const second = this.buffer[1];
      const fin = (first & 0x80) !== 0;
      const opcode = first & 0x0f;
      const masked = (second & 0x80) !== 0;
      let length = second & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.length < offset + 2) return;
        length = this.buffer.readUInt16BE(offset);
        offset += 2;
      } else if (length === 127) {
        if (this.buffer.length < offset + 8) return;
        const high = this.buffer.readUInt32BE(offset);
        const low = this.buffer.readUInt32BE(offset + 4);
        if (high > 0x1fffff) throw new Error('WebSocket frame too large');
        length = high * 0x100000000 + low;
        offset += 8;
      }
      const maskLength = masked ? 4 : 0;
      if (this.buffer.length < offset + maskLength + length) return;
      const mask = masked ? this.buffer.subarray(offset, offset + 4) : null;
      offset += maskLength;
      let payload = Buffer.from(this.buffer.subarray(offset, offset + length));
      this.buffer = this.buffer.subarray(offset + length);
      if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];

      if (opcode === 0x8) {
        this.sendFrame(0x8, payload);
        this.socket.end();
        this.emitClose();
      } else if (opcode === 0x9) {
        this.sendFrame(0xA, payload);
      } else if (opcode === 0xA) {
        continue;
      } else if (opcode === 0x0) {
        this.fragments.push(payload);
        if (fin) {
          this.emitMessage(this.fragmentOpcode, Buffer.concat(this.fragments));
          this.fragments = [];
          this.fragmentOpcode = 0;
        }
      } else if (fin) {
        this.emitMessage(opcode, payload);
      } else {
        this.fragmentOpcode = opcode;
        this.fragments = [payload];
      }
    }
  }

  emitMessage(opcode, payload) {
    this.emit('message', { data: opcode === 0x1 ? payload.toString('utf8') : payload });
  }

  sendFrame(opcode, payload) {
    if (this.readyState !== 1 && opcode !== 0x8) return;
    const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload || '');
    const mask = crypto.randomBytes(4);
    let header;
    if (body.length < 126) {
      header = Buffer.from([0x80 | opcode, 0x80 | body.length]);
    } else if (body.length <= 0xffff) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(body.length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 127;
      header.writeUInt32BE(Math.floor(body.length / 0x100000000), 2);
      header.writeUInt32BE(body.length >>> 0, 6);
    }
    const masked = Buffer.from(body);
    for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i % 4];
    this.socket.write(Buffer.concat([header, mask, masked]));
  }

  send(data) { this.sendFrame(0x1, data); }

  close() {
    if (this.readyState === 3) return;
    if (this.readyState === 1) this.sendFrame(0x8, Buffer.alloc(0));
    this.readyState = 2;
    this.socket.end();
    this.emitClose();
  }
}

function createWebSocket(url) {
  if (typeof globalThis.WebSocket === 'function') return new globalThis.WebSocket(url);
  try {
    const moduleValue = require('ws');
    const WebSocketCtor = moduleValue.WebSocket || moduleValue;
    if (typeof WebSocketCtor === 'function') return new WebSocketCtor(url);
  } catch (_) {}
  return new TinyWebSocket(url);
}

let persona = {};
try {
  persona = JSON.parse(fs.readFileSync(personaPath, 'utf8').replace(/^\uFEFF/, ''));
} catch (error) {
  fail('cannot read persona: ' + error.message);
}

let shim = '';
try {
  shim = fs.readFileSync(shimPath, 'utf8');
} catch (error) {
  fail('cannot read shim: ' + error.message);
}

const source = `window.__CAC_PERSONA__ = ${JSON.stringify(persona)};\n${shim}`;

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function waitVersion(seconds) {
  const deadline = Date.now() + seconds * 1000;
  let last = '';
  while (Date.now() < deadline) {
    try {
      return await requestJson(`http://127.0.0.1:${port}/json/version`);
    } catch (error) {
      last = error.message;
    }
    await sleep(300);
  }
  throw new Error('CDP endpoint not ready: ' + last);
}

class Client {
  constructor(url) {
    this.ws = createWebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = [];
    this.closed = false;
  }

  open() {
    return new Promise((resolve, reject) => {
      listen(this.ws, 'open', () => resolve());
      listen(this.ws, 'error', (event) => reject(new Error(
        event && event.message ? 'WebSocket error: ' + event.message : 'WebSocket error')));
    });
  }

  attach() {
    listen(this.ws, 'message', (event) => {
      let message;
      try {
        const data = event && event.data;
        message = JSON.parse(typeof data === 'string' ? data : data.toString('utf8'));
      } catch (_) { return; }
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message || 'CDP error'));
        else pending.resolve(message.result || {});
        return;
      }
      for (const listener of this.listeners) {
        try { listener(message); } catch (_) {}
      }
    });
    listen(this.ws, 'close', () => {
      this.closed = true;
      for (const pending of this.pending.values()) {
        pending.reject(new Error('CDP connection closed'));
      }
      this.pending.clear();
    });
  }

  onEvent(listener) { this.listeners.push(listener); }

  send(method, params = {}, sessionId) {
    if (this.closed) return Promise.reject(new Error('CDP connection closed'));
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(message));
    });
  }
}

async function inject(sessionId, targetInfo) {
  const type = targetInfo && targetInfo.type;
  if (type !== 'page' && type !== 'iframe') return;
  try {
    await client.send('Page.enable', {}, sessionId);
  } catch (_) {}
  try {
    await client.send('Page.addScriptToEvaluateOnNewDocument',
      { source, runImmediately: true }, sessionId);
  } catch (_) {
    try {
      await client.send('Page.addScriptToEvaluateOnNewDocument', { source }, sessionId);
    } catch (error) {
      log(`addScript failed ${type} ${targetInfo && targetInfo.targetId}: ${error.message}`);
    }
  }
  try {
    await client.send('Runtime.evaluate', { expression: source, awaitPromise: false }, sessionId);
  } catch (_) {}
  try {
    await client.send('Runtime.runIfWaitingForDebugger', {}, sessionId);
  } catch (_) {}
  log(`injected ${type} ${targetInfo && targetInfo.targetId} session=${sessionId}`);
}

let client;
const injectedTargets = new Set();

async function run() {
  const version = await waitVersion(waitSeconds);
  const url = version.webSocketDebuggerUrl;
  if (!url) throw new Error('webSocketDebuggerUrl missing');
  log('browser ' + version.Browser + ' ws=' + url);

  client = new Client(url);
  client.attach();
  await client.open();
  await client.send('Target.setDiscoverTargets', { discover: true });
  await client.send('Target.setAutoAttach', {
    autoAttach: true,
    waitForDebuggerOnStart: true,
    flatten: true,
  }).catch((error) => log('setAutoAttach: ' + error.message));

  client.onEvent(async (message) => {
    if (message.method !== 'Target.attachedToTarget') return;
    const { sessionId, targetInfo } = message.params || {};
    if (!sessionId || !targetInfo) return;
    if (injectedTargets.has(targetInfo.targetId)) return;
    injectedTargets.add(targetInfo.targetId);
    await inject(sessionId, targetInfo);
  });

  // Attach to pages that existed before auto-attach.
  try {
    const { targetInfos } = await client.send('Target.getTargets');
    for (const info of targetInfos || []) {
      if (info.type !== 'page' && info.type !== 'iframe') continue;
      if (injectedTargets.has(info.targetId)) continue;
      injectedTargets.add(info.targetId);
      try {
        const { sessionId } = await client.send('Target.attachToTarget',
          { targetId: info.targetId, flatten: true });
        await inject(sessionId, info);
      } catch (error) {
        log('attach existing failed ' + info.targetId + ': ' + error.message);
      }
    }
  } catch (error) {
    log('getTargets: ' + error.message);
  }

  if (ownerPid > 0) {
    const timer = setInterval(() => {
      try { process.kill(ownerPid, 0); }
      catch (_) { log('owner exited'); process.exit(0); }
    }, 2000);
    timer.unref();
  }

  listen(client.ws, 'close', () => {
    log('browser connection closed');
    process.exit(0);
  });
}

run().catch((error) => fail(error.message));
