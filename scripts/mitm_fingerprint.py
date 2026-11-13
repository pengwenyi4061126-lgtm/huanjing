import json
import os
import threading
import time
import ctypes

from mitmproxy import http


def log(message):
    path = os.environ.get("CAC_MITM_LOG", "")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {message}\n")
    except OSError:
        pass


def load_text(path):
    with open(path, "r", encoding="utf-8-sig") as handle:
        return handle.read()


PERSONA = json.loads(load_text(os.environ["CAC_PERSONA"]))
SHIM = load_text(os.environ["CAC_SHIM"])
ALLOWED = (
    "claude.ai",
    "claude.com",
    "platform.claude.com",
    "hcaptcha.com",
    "challenges.cloudflare.com",
    "accounts.google.com",
    "login.microsoftonline.com",
)

PROBE = """
<script>
setTimeout(function () {
  try {
    var c = document.createElement('canvas');
    var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    var value = {
      hc: navigator.hardwareConcurrency,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      offset: new Date().getTimezoneOffset(),
      gl: gl ? gl.getParameter(gl.RENDERER) : null,
      persona: !!window.__CAC_PERSONA__
    };
    fetch('/__cac_probe?d=' + encodeURIComponent(JSON.stringify(value)), {cache: 'no-store'});
  } catch (e) {}
}, 1500);
</script>
"""


def allowed(host):
    host = (host or "").lower()
    return any(host == item or host.endswith("." + item) for item in ALLOWED)


def process_alive(pid):
    if os.name == "nt":
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def inject(html):
    script = (
        "<script>window.__CAC_PERSONA__=" + json.dumps(PERSONA, ensure_ascii=False) + ";\n"
        + SHIM + "\n</script>" + PROBE
    )
    lower = html.lower()
    index = lower.find("<head")
    if index >= 0:
        end = html.find(">", index)
        if end >= 0:
            return html[: end + 1] + script + html[end + 1 :]
    index = lower.find("<html")
    if index >= 0:
        end = html.find(">", index)
        if end >= 0:
            return html[: end + 1] + script + html[end + 1 :]
    return script + html


class Addon:
    def __init__(self):
        self.pid = int(os.environ.get("CAC_MITM_PID", "0") or "0")
        self.pid_file = os.environ.get("CAC_MITM_PIDFILE", "")
        self.started_at = time.monotonic()
        self.startup_grace = max(
            5.0, float(os.environ.get("CAC_MITM_PID_STARTUP_GRACE", "20"))
        )
        self.missing_grace = max(
            2.0, float(os.environ.get("CAC_MITM_PID_MISSING_GRACE", "6"))
        )
        self.missing_since = None
        self.missing_logged = False
        if self.pid or self.pid_file:
            threading.Thread(target=self.monitor, daemon=True).start()

    def monitor(self):
        while True:
            pid = self.pid
            if self.pid_file:
                try:
                    with open(self.pid_file, "r", encoding="ascii") as handle:
                        pid = int(handle.read().strip() or "0")
                    if pid <= 0:
                        raise ValueError("empty Desktop PID")
                    self.missing_since = None
                    self.missing_logged = False
                except (OSError, ValueError):
                    now = time.monotonic()
                    if now - self.started_at < self.startup_grace:
                        time.sleep(1)
                        continue
                    if self.missing_since is None:
                        self.missing_since = now
                    if not self.missing_logged:
                        log(
                            "Desktop PID file missing after startup grace; "
                            f"waiting {self.missing_grace:.0f}s before exit"
                        )
                        self.missing_logged = True
                    if now - self.missing_since >= self.missing_grace:
                        log("Desktop PID file remained missing; exiting MITM")
                        os._exit(0)
                    time.sleep(1)
                    continue
            elif not pid:
                log("no Desktop PID or PID file configured; exiting MITM")
                os._exit(0)
            if pid:
                if not process_alive(pid):
                    log(f"Desktop PID {pid} is no longer alive; exiting MITM")
                    os._exit(0)
            time.sleep(2)

    def request(self, flow: http.HTTPFlow):
        if flow.request.path.startswith("/__cac_probe"):
            value = flow.request.query.get("d", "")
            log("probe " + value)
            flow.response = http.Response.make(204, b"")

    def response(self, flow: http.HTTPFlow):
        if not allowed(flow.request.pretty_host):
            return
        content_type = flow.response.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            return
        try:
            html = flow.response.get_text(strict=False)
        except Exception:
            return
        if not html:
            return
        flow.response.headers.pop("content-security-policy", None)
        flow.response.headers.pop("content-security-policy-report-only", None)
        flow.response.set_text(inject(html))
        log("inject " + flow.request.pretty_host + flow.request.path)


addons = [Addon()]
