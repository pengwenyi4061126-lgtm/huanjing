(() => {
  'use strict';
  const persona = window.__CAC_PERSONA__;
  if (!persona) return;
  if (window.__CAC_FINGERPRINT_SHIM_APPLIED__) return;
  try { window.__CAC_FINGERPRINT_SHIM_APPLIED__ = true; } catch (_) {}

  const nativeToString = Function.prototype.toString;
  const patched = new WeakSet();
  function mask(fn, name) {
    try {
      patched.add(fn);
      if (name) Object.defineProperty(fn, 'name', { value: name, configurable: true });
    } catch (_) {}
    return fn;
  }
  try {
    Function.prototype.toString = mask(function toString() {
      if (patched.has(this)) return `function ${this.name || ''}() { [native code] }`;
      return nativeToString.call(this);
    }, 'toString');
  } catch (_) {}

  function getter(target, prop, value) {
    try {
      const fn = mask(function () { return value; }, 'get ' + prop);
      Object.defineProperty(target, prop, { get: fn, configurable: true, enumerable: true });
    } catch (_) {}
  }
  function value(target, prop, val) {
    try { Object.defineProperty(target, prop, { value: val, configurable: true, writable: true }); } catch (_) {}
  }
  function hash(text) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 16777619);
    return h >>> 0;
  }
  function rng(seed) {
    let a = hash(String(seed)) >>> 0;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function clamp(v) { return v < 0 ? 0 : v > 255 ? 255 : v; }

  const seed = String(persona.seed || 'default');

  // Canvas: deterministic per-profile noise, stable across reloads.
  try {
    const proto = HTMLCanvasElement.prototype;
    const ctxProto = CanvasRenderingContext2D.prototype;
    const origGetImageData = ctxProto.getImageData;
    const origToDataURL = proto.toDataURL;
    const origToBlob = proto.toBlob;
    function noisy(image, tag) {
      if (!persona.canvasNoise) return image;
      const data = image.data;
      const random = rng(seed + '|canvas|' + image.width + 'x' + image.height + '|' + tag);
      const step = Math.max(1, Math.floor(data.length / 4096));
      for (let i = 0; i < data.length; i += 4 * step) {
        const n = Math.floor(random() * 3) - 1;
        data[i] = clamp(data[i] + n);
        data[i + 1] = clamp(data[i + 1] + n);
        data[i + 2] = clamp(data[i + 2] + n);
      }
      return image;
    }
    ctxProto.getImageData = mask(function getImageData() {
      const image = origGetImageData.apply(this, arguments);
      try { noisy(image, 'get'); } catch (_) {}
      return image;
    }, 'getImageData');
    proto.toDataURL = mask(function toDataURL() {
      try {
        const copy = document.createElement('canvas');
        copy.width = this.width; copy.height = this.height;
        const ctx = copy.getContext('2d');
        ctx.drawImage(this, 0, 0);
        const image = origGetImageData.call(ctx, 0, 0, copy.width, copy.height);
        ctx.putImageData(noisy(image, 'url'), 0, 0);
        return origToDataURL.apply(copy, arguments);
      } catch (_) {
        return origToDataURL.apply(this, arguments);
      }
    }, 'toDataURL');
    if (origToBlob) {
      proto.toBlob = mask(function toBlob() {
        try {
          const copy = document.createElement('canvas');
          copy.width = this.width; copy.height = this.height;
          const ctx = copy.getContext('2d');
          ctx.drawImage(this, 0, 0);
          const image = origGetImageData.call(ctx, 0, 0, copy.width, copy.height);
          ctx.putImageData(noisy(image, 'blob'), 0, 0);
          return origToBlob.apply(copy, arguments);
        } catch (_) {
          return origToBlob.apply(this, arguments);
        }
      }, 'toBlob');
    }
  } catch (_) {}

  // WebGL vendor/renderer.
  try {
    const gl = window.WebGLRenderingContext && WebGLRenderingContext.prototype;
    const gl2 = window.WebGL2RenderingContext && WebGL2RenderingContext.prototype;
    function patchGL(proto) {
      if (!proto || !proto.getParameter) return;
      const orig = proto.getParameter;
      proto.getParameter = mask(function getParameter(p) {
        try {
          if (p === 37445 || p === 7936) return persona.webgl && persona.webgl.vendor || 'Google Inc.';
          if (p === 37446 || p === 7937) return persona.webgl && persona.webgl.renderer || 'ANGLE';
          if (p === 7938 && persona.webgl && persona.webgl.version) return persona.webgl.version;
        } catch (_) {}
        return orig.call(this, p);
      }, 'getParameter');
    }
    patchGL(gl); patchGL(gl2);
  } catch (_) {}

  // Audio: tiny deterministic noise in AudioBuffer reads.
  try {
    if (window.AudioBuffer && AudioBuffer.prototype.getChannelData && persona.audioNoise) {
      const orig = AudioBuffer.prototype.getChannelData;
      AudioBuffer.prototype.getChannelData = mask(function getChannelData(channel) {
        const data = orig.call(this, channel);
        try {
          const random = rng(seed + '|audio|' + this.length + '|' + channel);
          const step = Math.max(1, Math.floor(data.length / 2048));
          const amp = Number(persona.audioNoise) || 0;
          for (let i = 0; i < data.length; i += step) data[i] += (random() * 2 - 1) * amp;
        } catch (_) {}
        return data;
      }, 'getChannelData');
    }
  } catch (_) {}

  // Navigator.
  try {
    const nav = Navigator.prototype;
    if (persona.hardwareConcurrency) getter(nav, 'hardwareConcurrency', Number(persona.hardwareConcurrency));
    if (persona.deviceMemory) getter(nav, 'deviceMemory', Number(persona.deviceMemory));
    if (persona.platform) getter(nav, 'platform', String(persona.platform));
    if (persona.maxTouchPoints != null) getter(nav, 'maxTouchPoints', Number(persona.maxTouchPoints));
    getter(nav, 'webdriver', false);
    if (persona.languages && persona.languages.length) {
      getter(nav, 'language', String(persona.languages[0]));
      getter(nav, 'languages', Object.freeze(persona.languages.map(String)));
    }
    if (persona.connection) {
      const connection = Object.assign({
        effectiveType: '4g',
        rtt: 50,
        downlink: 10,
        saveData: false,
        onchange: null,
      }, persona.connection);
      getter(nav, 'connection', connection);
    }
    const hasValue = (object, key) => Object.prototype.hasOwnProperty.call(object, key) &&
      object[key] !== undefined;
    const configuredBrands = Array.isArray(persona.uaBrands) && persona.uaBrands.length > 0
      ? persona.uaBrands.map((b) => ({ brand: String(b.brand), version: String(b.version) }))
      : null;
    if (hasValue(persona, 'ua')) getter(nav, 'userAgent', String(persona.ua));

    const nativeUaData = nav.userAgentData;
    const highEntropy = persona.uaHighEntropy && typeof persona.uaHighEntropy === 'object'
      ? persona.uaHighEntropy
      : null;
    const hasUaDataOverride = !!configuredBrands || hasValue(persona, 'uaMobile') ||
      hasValue(persona, 'uaPlatform') || (highEntropy && Object.keys(highEntropy).length > 0);
    if (hasUaDataOverride) {
      let data;
      try { data = nativeUaData ? Object.create(Object.getPrototypeOf(nativeUaData)) : {}; }
      catch (_) { data = {}; }
      const nativeBrands = nativeUaData && nativeUaData.brands;
      const nativeMobile = nativeUaData && nativeUaData.mobile;
      const nativePlatform = nativeUaData && nativeUaData.platform;
      if (configuredBrands) getter(data, 'brands', configuredBrands.map((b) => ({ ...b })));
      else if (nativeBrands) getter(data, 'brands', nativeBrands);
      if (hasValue(persona, 'uaMobile')) getter(data, 'mobile', !!persona.uaMobile);
      else if (nativeUaData && nativeMobile !== undefined) getter(data, 'mobile', !!nativeMobile);
      if (hasValue(persona, 'uaPlatform')) getter(data, 'platform', String(persona.uaPlatform));
      else if (nativeUaData && nativePlatform !== undefined) getter(data, 'platform', String(nativePlatform));

      const nativeHighEntropy = nativeUaData && typeof nativeUaData.getHighEntropyValues === 'function'
        ? nativeUaData.getHighEntropyValues.bind(nativeUaData)
        : null;
      value(data, 'getHighEntropyValues', mask(async function getHighEntropyValues(hints) {
        let result = {};
        if (nativeHighEntropy) {
          try { result = await nativeHighEntropy(hints); } catch (_) {}
        }
        if (configuredBrands) result.brands = configuredBrands.map((b) => ({ ...b }));
        if (hasValue(persona, 'uaMobile')) result.mobile = !!persona.uaMobile;
        if (hasValue(persona, 'uaPlatform')) result.platform = String(persona.uaPlatform);
        if (highEntropy) {
          const requested = Array.isArray(hints) ? new Set(hints.map(String)) : null;
          for (const key of Object.keys(highEntropy)) {
            if (!requested || requested.has(key)) result[key] = highEntropy[key];
          }
        }
        return result;
      }, 'getHighEntropyValues'));
      const nativeToJson = nativeUaData && typeof nativeUaData.toJSON === 'function'
        ? nativeUaData.toJSON.bind(nativeUaData)
        : null;
      value(data, 'toJSON', mask(function toJSON() {
        let result = {};
        try { result = nativeToJson ? nativeToJson() : {}; } catch (_) {}
        if (configuredBrands) result.brands = configuredBrands.map((b) => ({ ...b }));
        if (hasValue(persona, 'uaMobile')) result.mobile = !!persona.uaMobile;
        if (hasValue(persona, 'uaPlatform')) result.platform = String(persona.uaPlatform);
        return result;
      }, 'toJSON'));
      getter(nav, 'userAgentData', data);
    }
  } catch (_) {}

  // Screen / DPR.
  try {
    if (persona.screen) {
      const screenProto = Screen.prototype;
      for (const key of ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth']) {
        if (persona.screen[key] != null) getter(screenProto, key, Number(persona.screen[key]));
      }
      if (persona.screen.dpr != null) getter(Window.prototype, 'devicePixelRatio', Number(persona.screen.dpr));
      if (persona.screen.width != null) getter(Window.prototype, 'innerWidth', Number(persona.screen.width));
      if (persona.screen.height != null) getter(Window.prototype, 'innerHeight', Number(persona.screen.height));
      if (persona.screen.width != null) getter(Window.prototype, 'outerWidth', Number(persona.screen.width));
      if (persona.screen.height != null) getter(Window.prototype, 'outerHeight', Number(persona.screen.height));
    }
  } catch (_) {}

  // Timezone: Intl default + resolvedOptions + getTimezoneOffset.
  try {
    if (persona.timezone) {
      const Orig = Intl.DateTimeFormat;
      const profileFormatters = new WeakSet();
      function DTF(locales, options) {
        const opts = Object.assign({}, options || {});
        const hasExplicitTimeZone = options != null &&
          Object.prototype.hasOwnProperty.call(Object(options), 'timeZone') &&
          options.timeZone !== undefined;
        if (!hasExplicitTimeZone) opts.timeZone = persona.timezone;
        const formatter = new Orig(locales, opts);
        if (!hasExplicitTimeZone) profileFormatters.add(formatter);
        return formatter;
      }
      DTF.prototype = Orig.prototype;
      try { DTF.supportedLocalesOf = Orig.supportedLocalesOf.bind(Orig); } catch (_) {}
      try { Object.setPrototypeOf(DTF, Orig); } catch (_) {}
      Intl.DateTimeFormat = mask(DTF, 'DateTimeFormat');
      const origResolved = Orig.prototype.resolvedOptions;
      Orig.prototype.resolvedOptions = mask(function resolvedOptions() {
        const options = origResolved.call(this);
        if (profileFormatters.has(this)) options.timeZone = persona.timezone;
        return options;
      }, 'resolvedOptions');
      function offsetMinutes(date) {
        try {
          const parts = new Orig('en-US', {
            timeZone: persona.timezone, hour12: false, year: 'numeric', month: '2-digit',
            day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
          }).formatToParts(date).reduce((acc, p) => { acc[p.type] = p.value; return acc; }, {});
          const utc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
          return (date.getTime() - utc) / 60000;
        } catch (_) { return date.getTimezoneOffset(); }
      }
      Date.prototype.getTimezoneOffset = mask(function getTimezoneOffset() {
        return offsetMinutes(this);
      }, 'getTimezoneOffset');
    }
  } catch (_) {}

  // WebRTC: filter private candidates only when explicitly configured.
  try {
    if (persona.webrtc === 'filter-private' && window.RTCPeerConnection) {
      const Orig = window.RTCPeerConnection;
      const privateAddress = /(^|[\s:])(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|::1)/i;
      const descriptor = (target, key) => {
        for (let cursor = target; cursor; cursor = Object.getPrototypeOf(cursor)) {
          const item = Object.getOwnPropertyDescriptor(cursor, key);
          if (item) return item;
        }
        return null;
      };
      const candidateText = (candidate) => {
        if (!candidate) return '';
        return [candidate.candidate, candidate.address, candidate.ip].filter(Boolean).join(' ');
      };
      const isPrivateCandidate = (candidate) => {
        try { return privateAddress.test(candidateText(candidate)); } catch (_) { return false; }
      };
      const invokeListener = (listener, event, receiver) => {
        if (typeof listener === 'function') return listener.call(receiver, event);
        if (listener && typeof listener.handleEvent === 'function') {
          return listener.handleEvent.call(listener, event);
        }
        return undefined;
      };
      const wrapListener = (listener) => function filteredIceCandidate(event) {
        try {
          if (event && event.candidate && isPrivateCandidate(event.candidate)) return undefined;
        } catch (_) {}
        return invokeListener(listener, event, this);
      };
      const reportEntries = (report) => {
        const entries = [];
        try {
          if (report && typeof report.forEach === 'function') {
            report.forEach((value, key) => entries.push([key, value]));
          } else if (report && typeof report[Symbol.iterator] === 'function') {
            for (const entry of report) entries.push(entry);
          }
        } catch (_) {}
        return entries;
      };
      const statText = (stat) => {
        if (!stat) return '';
        return [stat.address, stat.ip, stat.candidate, stat.url].filter(Boolean).join(' ');
      };
      const filterStats = (report) => {
        const entries = reportEntries(report);
        if (!entries.length) return report;
        const hidden = new Set();
        for (const [id, stat] of entries) {
          if (stat && (stat.type === 'local-candidate' || stat.type === 'remote-candidate') &&
              isPrivateCandidate(stat)) hidden.add(id);
        }
        const filtered = new Map();
        for (const [id, stat] of entries) {
          if (hidden.has(id)) continue;
          if (stat && stat.type === 'candidate-pair' &&
              (hidden.has(stat.localCandidateId) || hidden.has(stat.remoteCandidateId))) continue;
          if (stat && (stat.type === 'local-candidate' || stat.type === 'remote-candidate') &&
              privateAddress.test(statText(stat))) continue;
          filtered.set(id, stat);
        }
        return filtered;
      };
      function PC() {
        const pc = new Orig(...arguments);
        try {
          const add = pc.addEventListener;
          const remove = pc.removeEventListener;
          const listenerWrappers = new WeakMap();
          const getWrapped = (listener) => {
            if (!listener || (typeof listener !== 'function' && typeof listener !== 'object')) return listener;
            let wrapped = listenerWrappers.get(listener);
            if (!wrapped) {
              wrapped = wrapListener(listener);
              listenerWrappers.set(listener, wrapped);
            }
            return wrapped;
          };
          pc.addEventListener = function (type, listener, options) {
            return add.call(this, type, type === 'icecandidate' ? getWrapped(listener) : listener, options);
          };
          pc.removeEventListener = function (type, listener, options) {
            return remove.call(this, type, type === 'icecandidate' ? getWrapped(listener) : listener, options);
          };
          const onIce = descriptor(Orig.prototype, 'onicecandidate');
          if (onIce && onIce.set) {
            let assigned = null;
            Object.defineProperty(pc, 'onicecandidate', {
              configurable: true,
              enumerable: true,
              get() { return assigned; },
              set(listener) {
                assigned = listener;
                onIce.set.call(this, listener ? getWrapped(listener) : listener);
              },
            });
          }
          const originalGetStats = pc.getStats;
          if (typeof originalGetStats === 'function') {
            pc.getStats = mask(function getStats() {
              const args = Array.prototype.slice.call(arguments);
              const callbackIndex = args.findIndex((item) => typeof item === 'function');
              if (callbackIndex >= 0) {
                const callback = args[callbackIndex];
                args[callbackIndex] = function filteredStatsCallback(report) {
                  return callback.call(this, filterStats(report));
                };
                return originalGetStats.apply(this, args);
              }
              const result = originalGetStats.apply(this, args);
              if (result && typeof result.then === 'function') return result.then(filterStats);
              return filterStats(result);
            }, 'getStats');
          }
        } catch (_) {}
        return pc;
      }
      PC.prototype = Orig.prototype;
      try { Object.setPrototypeOf(PC, Orig); } catch (_) {}
      window.RTCPeerConnection = mask(PC, 'RTCPeerConnection');
    }
  } catch (_) {}
})();
