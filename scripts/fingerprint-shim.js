(() => {
  'use strict';
  const persona = window.__CAC_PERSONA__;
  if (!persona) return;

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
    if (persona.languages && persona.languages.length) {
      getter(nav, 'language', String(persona.languages[0]));
      getter(nav, 'languages', Object.freeze(persona.languages.map(String)));
    }
    if (persona.ua) getter(nav, 'userAgent', String(persona.ua));
    if (persona.uaBrands && persona.uaBrands.length) {
      const data = {
        brands: persona.uaBrands.map((b) => ({ brand: String(b.brand), version: String(b.version) })),
        mobile: !!persona.uaMobile,
        platform: String(persona.uaPlatform || 'Windows'),
        getHighEntropyValues: async (hints) => Object.assign({
          brands: persona.uaBrands.map((b) => ({ brand: String(b.brand), version: String(b.version) })),
          mobile: !!persona.uaMobile,
          platform: String(persona.uaPlatform || 'Windows'),
        }, persona.uaHighEntropy || {}),
        toJSON() { return { brands: this.brands, mobile: this.mobile, platform: this.platform }; },
      };
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
    }
  } catch (_) {}

  // Timezone: Intl default + resolvedOptions + getTimezoneOffset.
  try {
    if (persona.timezone) {
      const Orig = Intl.DateTimeFormat;
      function DTF(locales, options) {
        const opts = Object.assign({}, options || {});
        if (!opts.timeZone) opts.timeZone = persona.timezone;
        return new Orig(locales, opts);
      }
      DTF.prototype = Orig.prototype;
      try { DTF.supportedLocalesOf = Orig.supportedLocalesOf.bind(Orig); } catch (_) {}
      try { Object.setPrototypeOf(DTF, Orig); } catch (_) {}
      Intl.DateTimeFormat = mask(DTF, 'DateTimeFormat');
      const origResolved = Orig.prototype.resolvedOptions;
      Orig.prototype.resolvedOptions = mask(function resolvedOptions() {
        const options = origResolved.call(this);
        options.timeZone = persona.timezone;
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
        return -offsetMinutes(this);
      }, 'getTimezoneOffset');
    }
  } catch (_) {}

  // WebRTC: drop private host candidates when configured.
  try {
    if (persona.webrtc === 'filter-private' && window.RTCPeerConnection) {
      const Orig = window.RTCPeerConnection;
      const privateAddress = /(^|[\s:])(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|::1)/i;
      function PC() {
        const pc = new Orig(...arguments);
        try {
          const add = pc.addEventListener;
          pc.addEventListener = function (type, listener, options) {
            if (type === 'icecandidate' && typeof listener === 'function') {
              const wrapped = function (event) {
                try { if (event.candidate && privateAddress.test(event.candidate.candidate)) return; } catch (_) {}
                return listener.call(this, event);
              };
              return add.call(this, type, wrapped, options);
            }
            return add.call(this, type, listener, options);
          };
        } catch (_) {}
        return pc;
      }
      PC.prototype = Orig.prototype;
      try { Object.setPrototypeOf(PC, Orig); } catch (_) {}
      window.RTCPeerConnection = mask(PC, 'RTCPeerConnection');
    }
  } catch (_) {}
})();
