"""Parse proxy URIs (share links and compact formats) into a unified ProxyConfig."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse


@dataclass
class ProxyConfig:
    type: str  # socks5 / vmess / vless / trojan / shadowsocks
    server: str
    port: int
    username: str = ""
    password: str = ""
    uuid: str = ""
    alter_id: int = 0
    security: str = ""
    method: str = ""
    tls: bool = False
    sni: str = ""
    extra: dict = field(default_factory=dict)


def parse(uri: str) -> ProxyConfig:
    """Auto-detect format and parse into ProxyConfig."""
    uri = uri.strip()
    if "://" in uri:
        scheme = uri.split("://", 1)[0].lower()
        parsers = {
            "ss": _parse_ss,
            "vmess": _parse_vmess,
            "vless": _parse_vless,
            "trojan": _parse_trojan,
        }
        parser = parsers.get(scheme)
        if not parser:
            raise ValueError(f"Unsupported protocol: {scheme}")
        return parser(uri)
    return _parse_compact(uri)


# ---------------------------------------------------------------------------
# Compact format: ip:port or ip:port:user:pass
# ---------------------------------------------------------------------------

def _parse_compact(uri: str) -> ProxyConfig:
    parts = uri.split(":")
    if len(parts) == 2:
        return ProxyConfig(type="socks5", server=parts[0], port=int(parts[1]))
    if len(parts) == 4:
        return ProxyConfig(
            type="socks5",
            server=parts[0],
            port=int(parts[1]),
            username=parts[2],
            password=parts[3],
        )
    raise ValueError(
        f"Invalid compact format (expect ip:port or ip:port:user:pass): {uri}"
    )


# ---------------------------------------------------------------------------
# ss://  (Shadowsocks)
# Formats:
#   ss://BASE64(method:password)@host:port#tag
#   ss://BASE64(method:password@host:port)#tag
# ---------------------------------------------------------------------------

def _b64decode(s: str) -> str:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode()


def _parse_ss(uri: str) -> ProxyConfig:
    uri = uri.split("#", 1)[0]  # strip fragment/tag
    body = uri[len("ss://"):]

    # Try format: BASE64(method:password)@host:port
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            decoded = _b64decode(userinfo)
        except Exception:
            decoded = unquote(userinfo)
        method, password = decoded.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    else:
        # Entire body is base64: method:password@host:port
        decoded = _b64decode(body)
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)

    return ProxyConfig(
        type="shadowsocks",
        server=host,
        port=int(port),
        password=password,
        method=method,
    )


# ---------------------------------------------------------------------------
# vmess://  (V2Ray)
# Format: vmess://BASE64(json)
# ---------------------------------------------------------------------------

def _parse_vmess(uri: str) -> ProxyConfig:
    body = uri[len("vmess://"):]
    data = json.loads(_b64decode(body))
    return ProxyConfig(
        type="vmess",
        server=str(data.get("add", "")),
        port=int(data.get("port", 0)),
        uuid=str(data.get("id", "")),
        alter_id=int(data.get("aid", 0)),
        security=str(data.get("scy", "auto")),
        tls=str(data.get("tls", "")) == "tls",
        sni=str(data.get("sni", data.get("host", ""))),
    )


# ---------------------------------------------------------------------------
# vless://  uuid@host:port?params#tag
# ---------------------------------------------------------------------------

def _parse_vless(uri: str) -> ProxyConfig:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    return ProxyConfig(
        type="vless",
        server=parsed.hostname or "",
        port=parsed.port or 443,
        uuid=parsed.username or "",
        tls=params.get("security", ["none"])[0] in ("tls", "reality"),
        sni=params.get("sni", [""])[0],
        extra={
            "flow": params.get("flow", [""])[0],
            "transport": params.get("type", ["tcp"])[0],
        },
    )


# ---------------------------------------------------------------------------
# trojan://  password@host:port?params#tag
# ---------------------------------------------------------------------------

def _parse_trojan(uri: str) -> ProxyConfig:
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    return ProxyConfig(
        type="trojan",
        server=parsed.hostname or "",
        port=parsed.port or 443,
        password=unquote(parsed.username or ""),
        tls=params.get("security", ["tls"])[0] != "none",
        sni=params.get("sni", [parsed.hostname or ""])[0],
    )
