"""Generate sing-box JSON configuration from ProxyConfig + environment parameters."""

from __future__ import annotations

import json
from typing import Any

from .protocols import ProxyConfig


def render(
    proxy: ProxyConfig,
    *,
    dns_server: str,
    tun_address: str,
    tun_mtu: int,
) -> dict[str, Any]:
    """Build a complete sing-box config dict."""
    return {
        "log": {"level": "warn"},
        "dns": _dns_section(dns_server),
        "inbounds": [_tun_inbound(tun_address, tun_mtu)],
        "outbounds": [_outbound(proxy), {"type": "direct", "tag": "direct"}],
        "route": _route_section(),
    }


def render_json(proxy: ProxyConfig, **kwargs: Any) -> str:
    return json.dumps(render(proxy, **kwargs), indent=2)


def _dns_section(server: str) -> dict:
    return {
        "servers": [{"tag": "remote-dns", "address": server, "detour": "proxy"}],
        "final": "remote-dns",
        "strategy": "ipv4_only",
    }


def _tun_inbound(address: str, mtu: int) -> dict:
    return {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": "tun0",
        "address": [address],
        "mtu": mtu,
        "auto_route": True,
        "strict_route": True,
        "stack": "system",
        "auto_redirect": True,
    }


def _route_section() -> dict:
    return {
        "rules": [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"ip_is_private": True, "outbound": "direct"},
        ],
        "final": "proxy",
        "auto_detect_interface": True,
    }


def _apply_tls(out: dict, p: ProxyConfig) -> None:
    if p.tls:
        tls: dict[str, Any] = {"enabled": True}
        if p.sni:
            tls["server_name"] = p.sni
        out["tls"] = tls


_OUTBOUND_BUILDERS: dict[str, Any] = {}


def _outbound(proxy: ProxyConfig) -> dict:
    builder = _OUTBOUND_BUILDERS.get(proxy.type)
    if not builder:
        raise ValueError(f"Unsupported proxy type for sing-box: {proxy.type}")
    return builder(proxy)


def _outbound_socks5(p: ProxyConfig) -> dict:
    out: dict[str, Any] = {
        "type": "socks",
        "tag": "proxy",
        "server": p.server,
        "server_port": p.port,
        "version": "5",
    }
    if p.username:
        out["username"] = p.username
    if p.password:
        out["password"] = p.password
    return out


def _outbound_shadowsocks(p: ProxyConfig) -> dict:
    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": p.server,
        "server_port": p.port,
        "method": p.method,
        "password": p.password,
    }


def _outbound_vmess(p: ProxyConfig) -> dict:
    out: dict[str, Any] = {
        "type": "vmess",
        "tag": "proxy",
        "server": p.server,
        "server_port": p.port,
        "uuid": p.uuid,
        "alter_id": p.alter_id,
        "security": p.security or "auto",
    }
    _apply_tls(out, p)
    return out


def _outbound_vless(p: ProxyConfig) -> dict:
    out: dict[str, Any] = {
        "type": "vless",
        "tag": "proxy",
        "server": p.server,
        "server_port": p.port,
        "uuid": p.uuid,
    }
    flow = p.extra.get("flow", "")
    if flow:
        out["flow"] = flow
    _apply_tls(out, p)
    transport = p.extra.get("transport", "tcp")
    if transport and transport != "tcp":
        out["transport"] = {"type": transport}
    return out


def _outbound_trojan(p: ProxyConfig) -> dict:
    out: dict[str, Any] = {
        "type": "trojan",
        "tag": "proxy",
        "server": p.server,
        "server_port": p.port,
        "password": p.password,
    }
    _apply_tls(out, p)
    return out


_OUTBOUND_BUILDERS.update({
    "socks5": _outbound_socks5,
    "shadowsocks": _outbound_shadowsocks,
    "vmess": _outbound_vmess,
    "vless": _outbound_vless,
    "trojan": _outbound_trojan,
})
