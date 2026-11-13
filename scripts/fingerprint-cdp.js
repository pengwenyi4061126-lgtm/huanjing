#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

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

if (typeof WebSocket !== 'function') {
  fail('Node 22+ is required (global WebSocket missing)');
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
      const response = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (response.ok) return await response.json();
      last = 'HTTP ' + response.status;
    } catch (error) {
      last = error.message;
    }
    await sleep(300);
  }
  throw new Error('CDP endpoint not ready: ' + last);
}

class Client {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = [];
    this.closed = false;
  }

  open() {
    return new Promise((resolve, reject) => {
      this.ws.addEventListener('open', () => resolve());
      this.ws.addEventListener('error', (event) => reject(new Error('WebSocket error')));
    });
  }

  attach() {
    this.ws.addEventListener('message', (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch (_) { return; }
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
    this.ws.addEventListener('close', () => {
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

  client.ws.addEventListener('close', () => {
    log('browser connection closed');
    process.exit(0);
  });
}

run().catch((error) => fail(error.message));
