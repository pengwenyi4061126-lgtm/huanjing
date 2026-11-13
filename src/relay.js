#!/usr/bin/env node
// cac-relay - local HTTP proxy relay for HTTP and SOCKS5/SOCKS5H upstreams.
'use strict';

var net = require('net');
var fs = require('fs');

var HANDSHAKE_TIMEOUT = 8000;
var IDLE_TIMEOUT = 1800000;
var MAX_CONNECTIONS = 128;
var MAX_HEADER_BYTES = 64 * 1024;
var CRLF = Buffer.from('\r\n');
var HEADER_END = Buffer.from('\r\n\r\n');

var listenPort = parseInt(process.argv[2], 10);
var pidFile = process.env.CAC_RELAY_PID_FILE || '';
var upstreamUrl = process.env.CAC_RELAY_UPSTREAM_URL || process.env.CAC_RELAY_PROXY || '';
var configFile = process.env.CAC_RELAY_CONFIG_FILE || '';
var proxyFile = process.env.CAC_RELAY_PROXY_FILE || '';

function log(message) {
  process.stderr.write('[cac-relay] ' + String(message) + '\n');
}

function safeError(err) {
  var value = String(err && err.message || err || 'error');
  if (upstreamUrl) value = value.split(upstreamUrl).join('<redacted-proxy>');
  return value;
}

function readRelayConfig() {
  if (process.argv.slice(2).some(function(arg) { return typeof arg === 'string' && /:\/\//.test(arg); })) {
    throw new Error('proxy URL must be supplied through CAC_RELAY_UPSTREAM_URL, CAC_RELAY_CONFIG_FILE, or CAC_RELAY_PROXY_FILE');
  }
  if (configFile) {
    var raw = fs.readFileSync(configFile, 'utf8').trim();
    if (raw) {
      try {
        var parsed = JSON.parse(raw);
        if (parsed && parsed.upstreamUrl) upstreamUrl = String(parsed.upstreamUrl);
        if (!pidFile && parsed && parsed.pidFile) pidFile = String(parsed.pidFile);
      } catch (_) {
        upstreamUrl = raw;
      }
    }
  }
  if (!upstreamUrl && proxyFile) upstreamUrl = fs.readFileSync(proxyFile, 'utf8').trim();
  if (!pidFile) {
    if (process.argv[4]) pidFile = process.argv[4];
    else if (process.argv[3] && !/:\/\//.test(process.argv[3])) pidFile = process.argv[3];
  }
}

try {
  readRelayConfig();
} catch (_) {
  process.stderr.write('[cac-relay] startup failed: cannot read relay configuration\n');
  process.exit(1);
}

if (!listenPort || !upstreamUrl) {
  process.stderr.write('Usage: node relay.js <port> [pid_file]\n');
  process.exit(1);
}

var upstream;
var upstreamProtocol;
var upstreamHost;
var upstreamPort;
var upstreamUser;
var upstreamPass;

function stripBrackets(host) {
  var value = String(host || '');
  if (value.length >= 2 && value[0] === '[' && value[value.length - 1] === ']') return value.slice(1, -1);
  return value;
}

function defaultPort(protocol) {
  if (protocol === 'http:') return 80;
  if (protocol === 'https:') return 443;
  if (protocol === 'socks5:' || protocol === 'socks5h:') return 1080;
  return 0;
}

try {
  upstream = new URL(upstreamUrl);
  upstreamProtocol = upstream.protocol.toLowerCase();
  if (upstreamProtocol !== 'http:' && upstreamProtocol !== 'socks5:' && upstreamProtocol !== 'socks5h:') {
    throw new Error('unsupported upstream protocol');
  }
  upstreamHost = stripBrackets(upstream.hostname);
  upstreamPort = parseInt(upstream.port, 10) || defaultPort(upstreamProtocol);
  if (!upstreamHost || !upstreamPort || upstreamPort < 1 || upstreamPort > 65535) throw new Error('invalid upstream endpoint');
  upstreamUser = decodeURIComponent(upstream.username || '');
  upstreamPass = decodeURIComponent(upstream.password || '');
} catch (_) {
  process.stderr.write('[cac-relay] startup failed: invalid upstream proxy configuration\n');
  process.exit(1);
}

var isSocks5 = upstreamProtocol === 'socks5:' || upstreamProtocol === 'socks5h:';
var upstreamLabel = (net.isIP(upstreamHost) === 6 ? '[' + upstreamHost + ']' : upstreamHost) + ':' + upstreamPort;

function fatalShutdown(reason) {
  log('fatal error: ' + safeError(reason));
  shuttingDown = true;
  try { if (server) server.close(); } catch (_) {}
  setTimeout(function() { process.exit(1); }, 25).unref();
}
process.on('uncaughtException', fatalShutdown);
process.on('unhandledRejection', fatalShutdown);

var upstreamHealthy = true;
var heartbeatTimer;
function heartbeat() {
  var sock;
  try { sock = net.connect({ port: upstreamPort, host: upstreamHost, timeout: 5000 }); } catch (_) { return; }
  sock.once('connect', function() {
    if (!upstreamHealthy) log('upstream recovered: ' + upstreamLabel);
    upstreamHealthy = true;
    sock.destroy();
  });
  sock.once('error', function() {
    if (upstreamHealthy) log('upstream unreachable: ' + upstreamLabel);
    upstreamHealthy = false;
    sock.destroy();
  });
  sock.once('timeout', function() {
    if (upstreamHealthy) log('upstream timeout: ' + upstreamLabel);
    upstreamHealthy = false;
    sock.destroy();
  });
}
heartbeatTimer = setInterval(heartbeat, 30000);

function startHandshake(onConnect, callback) {
  var sock;
  var timer;
  var done = false;
  var cleanupHandshake = function() {};

  function finish(err, extra) {
    if (done) return;
    done = true;
    clearTimeout(timer);
    cleanupHandshake();
    if (sock) {
      sock.removeListener('error', onError);
      sock.removeListener('timeout', onTimeout);
      sock.setTimeout(0);
    }
    if (err) {
      if (sock) sock.destroy();
      callback(err);
      return;
    }
    callback(null, sock, extra instanceof Buffer ? extra : Buffer.alloc(0));
  }
  function onError(err) { finish(err); }
  function onTimeout() { finish(new Error('upstream handshake timeout')); }

  try {
    sock = net.connect({ port: upstreamPort, host: upstreamHost, timeout: HANDSHAKE_TIMEOUT });
  } catch (err) {
    callback(err);
    return;
  }
  timer = setTimeout(onTimeout, HANDSHAKE_TIMEOUT);
  sock.once('error', onError);
  sock.once('timeout', onTimeout);
  sock.once('connect', function() {
    try {
      onConnect(sock, finish, function(cleanup) { cleanupHandshake = cleanup || function() {}; });
    } catch (err) {
      finish(err);
    }
  });
}

function ipv4Buffer(host) {
  var parts = String(host).split('.');
  if (parts.length !== 4) return null;
  var out = Buffer.alloc(4);
  for (var i = 0; i < 4; i++) {
    var value = parseInt(parts[i], 10);
    if (!/^\d+$/.test(parts[i]) || value < 0 || value > 255) return null;
    out[i] = value;
  }
  return out;
}

function ipv6Groups(part) {
  if (!part) return [];
  var pieces = part.split(':');
  var groups = [];
  for (var i = 0; i < pieces.length; i++) {
    var piece = pieces[i];
    if (!piece) return null;
    if (piece.indexOf('.') !== -1) {
      var v4 = ipv4Buffer(piece);
      if (!v4) return null;
      groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
    } else {
      if (!/^[0-9a-f]{1,4}$/i.test(piece)) return null;
      groups.push(parseInt(piece, 16));
    }
  }
  return groups;
}

function ipv6Buffer(host) {
  var value = String(host);
  if (value.indexOf('%') !== -1) return null;
  var halves = value.split('::');
  if (halves.length > 2) return null;
  var left = ipv6Groups(halves[0]);
  var right = halves.length === 2 ? ipv6Groups(halves[1]) : [];
  if (!left || !right) return null;
  var groups;
  if (halves.length === 2) {
    var zeros = 8 - left.length - right.length;
    if (zeros < 1) return null;
    groups = left.concat(new Array(zeros).fill(0), right);
  } else {
    groups = left;
  }
  if (groups.length !== 8) return null;
  var out = Buffer.alloc(16);
  for (var i = 0; i < groups.length; i++) out.writeUInt16BE(groups[i], i * 2);
  return out;
}

function socksAddress(host) {
  var value = stripBrackets(host);
  var ipKind = net.isIP(value);
  if (ipKind === 4) {
    var v4 = ipv4Buffer(value);
    return v4 ? Buffer.concat([Buffer.from([0x01]), v4]) : null;
  }
  if (ipKind === 6) {
    var v6 = ipv6Buffer(value);
    return v6 ? Buffer.concat([Buffer.from([0x04]), v6]) : null;
  }
  var domain = Buffer.from(value, 'utf8');
  if (!domain.length || domain.length > 255) return null;
  return Buffer.concat([Buffer.from([0x03, domain.length]), domain]);
}

function socks5Connect(targetHost, targetPort, callback) {
  startHandshake(function(sock, finish, registerCleanup) {
    var hasAuth = !!(upstreamUser || upstreamPass);
    var methods = hasAuth ? [0x02, 0x00] : [0x00];
    var state = 'greeting';
    var buf = Buffer.alloc(0);
    var onData;

    function fail(message) { finish(new Error(message)); }
    function sendConnectRequest() {
      var address = socksAddress(targetHost);
      if (!address) { fail('invalid SOCKS5 target address'); return; }
      var request = Buffer.alloc(3 + address.length + 2);
      request[0] = 0x05;
      request[1] = 0x01;
      request[2] = 0x00;
      address.copy(request, 3);
      request.writeUInt16BE(targetPort, 3 + address.length);
      state = 'connect';
      sock.write(request);
    }
    function processBuffer() {
      while (true) {
        if (state === 'greeting') {
          if (buf.length < 2) return;
          if (buf[0] !== 0x05) { fail('SOCKS5 invalid greeting'); return; }
          var method = buf[1];
          buf = buf.slice(2);
          if (method === 0x02 && hasAuth) {
            var uBuf = Buffer.from(upstreamUser);
            var pBuf = Buffer.from(upstreamPass);
            if (uBuf.length > 255 || pBuf.length > 255) { fail('SOCKS5 credentials are too long'); return; }
            var auth = Buffer.alloc(3 + uBuf.length + pBuf.length);
            auth[0] = 0x01;
            auth[1] = uBuf.length;
            uBuf.copy(auth, 2);
            auth[2 + uBuf.length] = pBuf.length;
            pBuf.copy(auth, 3 + uBuf.length);
            state = 'auth';
            sock.write(auth);
          } else if (method === 0x00) {
            sendConnectRequest();
          } else {
            fail('SOCKS5 unsupported auth method');
          }
          continue;
        }
        if (state === 'auth') {
          if (buf.length < 2) return;
          if (buf[0] !== 0x01 || buf[1] !== 0x00) { fail('SOCKS5 auth failed'); return; }
          buf = buf.slice(2);
          sendConnectRequest();
          continue;
        }
        if (state === 'connect') {
          if (buf.length < 4) return;
          if (buf[0] !== 0x05 || buf[1] !== 0x00) { fail('SOCKS5 connect failed'); return; }
          var atyp = buf[3];
          var addressBytes;
          if (atyp === 0x01) addressBytes = 4;
          else if (atyp === 0x04) addressBytes = 16;
          else if (atyp === 0x03) {
            if (buf.length < 5) return;
            addressBytes = 1 + buf[4];
          } else { fail('SOCKS5 invalid reply address'); return; }
          var total = 4 + addressBytes + 2;
          if (buf.length < total) return;
          finish(null, buf.slice(total));
          return;
        }
        return;
      }
    }
    onData = function(chunk) {
      buf = Buffer.concat([buf, Buffer.from(chunk)]);
      processBuffer();
    };
    registerCleanup(function() { sock.removeListener('data', onData); });
    sock.on('data', onData);
    sock.write(Buffer.from([0x05, methods.length].concat(methods)));
  }, callback);
}

function httpConnect(targetHost, targetPort, callback) {
  startHandshake(function(sock, finish, registerCleanup) {
    var host = stripBrackets(targetHost);
    var authority = net.isIP(host) === 6 ? '[' + host + ']' : host;
    var request = 'CONNECT ' + authority + ':' + targetPort + ' HTTP/1.1\r\n' + 'Host: ' + authority + ':' + targetPort + '\r\n';
    if (upstreamUser) request += 'Proxy-Authorization: Basic ' + Buffer.from(upstreamUser + ':' + upstreamPass).toString('base64') + '\r\n';
    request += '\r\n';
    var buf = Buffer.alloc(0);
    var onData = function(chunk) {
      buf = Buffer.concat([buf, Buffer.from(chunk)]);
      if (buf.length > MAX_HEADER_BYTES) { finish(new Error('upstream HTTP response too large')); return; }
      var end = buf.indexOf(HEADER_END);
      if (end === -1) return;
      var lineEnd = buf.indexOf(CRLF);
      var statusLine = lineEnd === -1 ? '' : buf.slice(0, lineEnd).toString('latin1');
      var statusCode = parseInt((statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/) || [])[1], 10);
      if (statusCode === 200) finish(null, buf.slice(end + HEADER_END.length));
      else finish(new Error('upstream HTTP CONNECT rejected'));
    };
    registerCleanup(function() { sock.removeListener('data', onData); });
    sock.on('data', onData);
    sock.write(request);
  }, callback);
}

function connectUpstream(targetHost, targetPort, callback) {
  if (isSocks5) socks5Connect(targetHost, targetPort, callback);
  else httpConnect(targetHost, targetPort, callback);
}

function openPlainUpstream(callback) {
  startHandshake(function(sock, finish) { finish(null, Buffer.alloc(0)); }, callback);
}

function parseConnectAuthority(value) {
  var match = String(value).match(/^\[([^\]]+)\]:(\d+)$/);
  if (!match) match = String(value).match(/^([^:\s]+):(\d+)$/);
  if (!match) return null;
  var port = parseInt(match[2], 10);
  if (!port || port < 1 || port > 65535) return null;
  return { host: stripBrackets(match[1]), port: port };
}

function replyAndClose(sock, code, reason) {
  if (!sock || sock.destroyed) return;
  var body = code + ' ' + reason + '\r\n';
  var response = 'HTTP/1.1 ' + code + ' ' + reason + '\r\nConnection: close\r\nContent-Length: ' + Buffer.byteLength(body) + '\r\n\r\n' + body;
  try { sock.end(response); } catch (_) { try { sock.destroy(); } catch (__) {} }
}

function sanitizeForwardHeaders(headerBlock) {
  var lines = Buffer.from(headerBlock || Buffer.alloc(0)).toString('latin1').split('\r\n');
  var connectionTokens = {};
  for (var i = 0; i < lines.length; i++) {
    if (!lines[i]) break;
    var separator = lines[i].indexOf(':');
    if (separator <= 0) continue;
    var name = lines[i].slice(0, separator).trim().toLowerCase();
    if (name === 'connection') {
      lines[i].slice(separator + 1).split(',').forEach(function(token) {
        token = token.trim().toLowerCase();
        if (token) connectionTokens[token] = true;
      });
    }
  }
  var hopByHop = {
    'connection': true, 'keep-alive': true, 'proxy-authenticate': true,
    'proxy-authorization': true, 'proxy-connection': true, 'te': true,
    'trailer': true, 'transfer-encoding': true, 'upgrade': true
  };
  var kept = [];
  for (var j = 0; j < lines.length; j++) {
    var line = lines[j];
    if (!line) break;
    var split = line.indexOf(':');
    if (split <= 0) { kept.push(line); continue; }
    var headerName = line.slice(0, split).trim().toLowerCase();
    if (hopByHop[headerName] || connectionTokens[headerName]) continue;
    kept.push(line);
  }
  return Buffer.from(kept.join('\r\n') + '\r\n\r\n', 'latin1');
}

function isHealthRequest(firstLine) {
  var match = String(firstLine).match(/^(GET|HEAD)\s+(https?:\/\/[^\s]+)\s+HTTP\/\d(?:\.\d)?$/i);
  if (!match) return false;
  try {
    var url = new URL(match[2]);
    return url.hostname.toLowerCase() === 'cac-relay.local' && url.pathname === '/__cac_relay_health__';
  } catch (_) { return false; }
}

function handleHealth(clientSock, firstLine) {
  var body = /^HEAD\s/i.test(firstLine) ? '' : 'ready\n';
  clientSock.end('HTTP/1.1 200 OK\r\nX-Cac-Relay: ready\r\nConnection: close\r\nContent-Length: ' + Buffer.byteLength(body) + '\r\n\r\n' + body);
}

function pipeTunnel(clientSock, upstreamSock, upstreamExtra, trailingData) {
  clientSock.pipe(upstreamSock);
  upstreamSock.pipe(clientSock);
  if (upstreamExtra && upstreamExtra.length) clientSock.write(upstreamExtra);
  if (trailingData && trailingData.length) upstreamSock.write(trailingData);
  clientSock.on('error', function() { upstreamSock.destroy(); });
  upstreamSock.on('error', function() { clientSock.destroy(); });
  upstreamSock.setTimeout(IDLE_TIMEOUT, function() { upstreamSock.destroy(); });
  clientSock.setTimeout(IDLE_TIMEOUT, function() { clientSock.destroy(); });
}

function handleConnect(clientSock, targetHost, targetPort, trailingData) {
  connectUpstream(targetHost, targetPort, function(err, upstreamSock, upstreamExtra) {
    if (err) { replyAndClose(clientSock, 502, 'Bad Gateway'); return; }
    try { clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); } catch (_) { upstreamSock.destroy(); return; }
    pipeTunnel(clientSock, upstreamSock, upstreamExtra, trailingData);
  });
}

function handlePlainHttp(clientSock, firstLine, headerBlock, trailingData) {
  var match = String(firstLine).match(/^([A-Z]+)\s+(https?:\/\/[^\s]+)\s+(HTTP\/\d(?:\.\d)?)$/i);
  if (isSocks5) {
    if (!match) { replyAndClose(clientSock, 400, 'Bad Request'); return; }
    var targetUrl;
    try { targetUrl = new URL(match[2]); } catch (_) { targetUrl = null; }
    if (!targetUrl || !targetUrl.hostname) { replyAndClose(clientSock, 400, 'Bad Request'); return; }
    var targetHost = stripBrackets(targetUrl.hostname);
    var targetPort = parseInt(targetUrl.port, 10) || (targetUrl.protocol === 'https:' ? 443 : 80);
    var targetPath = (targetUrl.pathname || '/') + (targetUrl.search || '');
    var originLine = Buffer.from(match[1] + ' ' + targetPath + ' ' + match[3] + '\r\n', 'latin1');
    var safeHeaderBlock = sanitizeForwardHeaders(headerBlock);
    connectUpstream(targetHost, targetPort, function(err, upstreamSock, upstreamExtra) {
      if (err) { replyAndClose(clientSock, 502, 'Bad Gateway'); return; }
      upstreamSock.pipe(clientSock);
      clientSock.pipe(upstreamSock);
      if (upstreamExtra && upstreamExtra.length) clientSock.write(upstreamExtra);
      upstreamSock.write(Buffer.concat([originLine, safeHeaderBlock, trailingData]));
      clientSock.on('error', function() { upstreamSock.destroy(); });
      upstreamSock.on('error', function() { clientSock.destroy(); });
      upstreamSock.setTimeout(IDLE_TIMEOUT, function() { upstreamSock.destroy(); });
    });
    return;
  }
  openPlainUpstream(function(err, upstreamSock) {
    if (err) { replyAndClose(clientSock, 502, 'Bad Gateway'); return; }
    var authHeader = upstreamUser ? Buffer.from('Proxy-Authorization: Basic ' + Buffer.from(upstreamUser + ':' + upstreamPass).toString('base64') + '\r\n', 'latin1') : Buffer.alloc(0);
    var safeHeaderBlock = sanitizeForwardHeaders(headerBlock);
    upstreamSock.pipe(clientSock);
    clientSock.pipe(upstreamSock);
    upstreamSock.write(Buffer.concat([Buffer.from(firstLine + '\r\n', 'latin1'), authHeader, safeHeaderBlock, trailingData]));
    clientSock.on('error', function() { upstreamSock.destroy(); });
    upstreamSock.on('error', function() { clientSock.destroy(); });
    upstreamSock.setTimeout(IDLE_TIMEOUT, function() { upstreamSock.destroy(); });
  });
}

var activeConnections = 0;
var server = net.createServer({ pauseOnConnect: true }, function(clientSock) {
  if (activeConnections >= MAX_CONNECTIONS) { clientSock.destroy(); return; }
  activeConnections++;
  clientSock.on('close', function() { activeConnections--; });
  clientSock.on('error', function() {});
  clientSock.setTimeout(IDLE_TIMEOUT, function() { clientSock.destroy(); });
  clientSock.pause();

  var requestBuffer = Buffer.alloc(0);
  function onInitialData(chunk) {
    requestBuffer = Buffer.concat([requestBuffer, Buffer.from(chunk)]);
    var headerEnd = requestBuffer.indexOf(HEADER_END);
    if (headerEnd === -1) {
      if (requestBuffer.length > MAX_HEADER_BYTES) {
        clientSock.removeListener('data', onInitialData);
        replyAndClose(clientSock, 431, 'Request Header Fields Too Large');
      }
      return;
    }
    if (headerEnd + HEADER_END.length > MAX_HEADER_BYTES) {
      clientSock.removeListener('data', onInitialData);
      replyAndClose(clientSock, 431, 'Request Header Fields Too Large');
      return;
    }
    clientSock.removeListener('data', onInitialData);
    clientSock.pause();
    var lineEnd = requestBuffer.indexOf(CRLF);
    if (lineEnd === -1 || lineEnd > headerEnd) { replyAndClose(clientSock, 400, 'Bad Request'); return; }
    var firstLine = requestBuffer.slice(0, lineEnd).toString('latin1');
    var headerBlock = requestBuffer.slice(lineEnd + CRLF.length, headerEnd + HEADER_END.length);
    var trailingData = requestBuffer.slice(headerEnd + HEADER_END.length);
    if (isHealthRequest(firstLine)) { handleHealth(clientSock, firstLine); return; }
    var connectMatch = firstLine.match(/^CONNECT\s+([^\s]+)\s+HTTP\/\d(?:\.\d)?$/i);
    if (connectMatch) {
      var target = parseConnectAuthority(connectMatch[1]);
      if (!target) { replyAndClose(clientSock, 400, 'Bad Request'); return; }
      handleConnect(clientSock, target.host, target.port, trailingData);
      return;
    }
    handlePlainHttp(clientSock, firstLine, headerBlock, trailingData);
  }
  clientSock.on('data', onInitialData);
  clientSock.resume();
});

function writePid() {
  if (!pidFile) return;
  try { fs.writeFileSync(pidFile, String(process.pid)); } catch (_) {}
}

var shuttingDown = false;
function cleanup() {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(heartbeatTimer);
  if (pidFile) { try { fs.unlinkSync(pidFile); } catch (_) {} }
  try { server.close(function() { process.exit(0); }); } catch (_) { process.exit(0); }
  setTimeout(function() { process.exit(0); }, 1000).unref();
}
process.on('SIGTERM', cleanup);
process.on('SIGINT', cleanup);

var startAttempts = 0;
function startServer() {
  if (shuttingDown) return;
  startAttempts++;
  try { server.listen(listenPort, '127.0.0.1', function() { writePid(); log('listening on 127.0.0.1:' + listenPort + ' -> ' + upstreamLabel + (isSocks5 ? ' (socks5)' : ' (http)')); }); } catch (err) { log('server start failed: ' + safeError(err)); }
}
server.on('error', function(err) {
  if (shuttingDown) return;
  log('server error: ' + safeError(err));
  if (startAttempts < 12 && (err.code === 'EADDRINUSE' || err.code === 'EADDRNOTAVAIL')) {
    try { server.close(); } catch (_) {}
    setTimeout(startServer, err.code === 'EADDRINUSE' ? 250 : 1000);
    return;
  }
  process.exit(1);
});

startServer();
