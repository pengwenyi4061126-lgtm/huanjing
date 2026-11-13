#!/usr/bin/env node
'use strict';

function arg(name, fallback) {
  const index = process.argv.indexOf('--' + name);
  if (index < 0 || index + 1 >= process.argv.length) return fallback;
  return process.argv[index + 1];
}

const port = Number(arg('port', '9222'));
const expression = `(() => {
  const result = { persona: !!window.__CAC_PERSONA__ };
  try { result.hardwareConcurrency = navigator.hardwareConcurrency; } catch (_) {}
  try { result.deviceMemory = navigator.deviceMemory; } catch (_) {}
  try { result.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (_) {}
  try { result.offset = new Date().getTimezoneOffset(); } catch (_) {}
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 120; canvas.height = 40;
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = '16px Arial'; ctx.fillText('cac-fingerprint', 2, 2);
    result.canvasLength = canvas.toDataURL().length;
  } catch (_) {}
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      result.webglVendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      result.webglRenderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
    }
  } catch (_) {}
  return result;
})()`;

async function main() {
  const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  let id = 1;
  const pending = new Map();
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve);
    ws.addEventListener('error', reject);
  });
  ws.addEventListener('message', (event) => {
    const message = JSON.parse(event.data);
    if (!message.id) return;
    const item = pending.get(message.id);
    if (!item) return;
    pending.delete(message.id);
    if (message.error) item.reject(new Error(message.error.message));
    else item.resolve(message.result);
  });
  const send = (method, params, sessionId) => new Promise((resolve, reject) => {
    const current = id++;
    pending.set(current, { resolve, reject });
    ws.send(JSON.stringify({ id: current, method, params, sessionId }));
  });
  const targets = await send('Target.getTargets', {});
  const page = (targets.targetInfos || []).find((item) => item.type === 'page');
  if (!page) throw new Error('no page target');
  const attached = await send('Target.attachToTarget', { targetId: page.targetId, flatten: true });
  const result = await send('Runtime.evaluate', { expression, returnByValue: true }, attached.sessionId);
  console.log(JSON.stringify(result.result.value, null, 2));
  ws.close();
}

main().catch((error) => { console.error(error.message); process.exit(1); });
