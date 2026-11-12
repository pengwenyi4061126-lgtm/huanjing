"""Auto-detect timezone and locale from proxy exit IP."""

from __future__ import annotations

import json
import urllib.request

# Country code → (locale, accept-language)
COUNTRY_LOCALE = {
    "US": ("en_US", "en-US,en;q=0.9"),
    "GB": ("en_GB", "en-GB,en;q=0.9"),
    "CA": ("en_US", "en-US,en;q=0.9"),
    "AU": ("en_AU", "en-AU,en;q=0.9"),
    "JP": ("ja_JP", "ja,en-US;q=0.9,en;q=0.8"),
    "KR": ("ko_KR", "ko,en-US;q=0.9,en;q=0.8"),
    "CN": ("zh_CN", "zh-CN,zh;q=0.9,en;q=0.8"),
    "TW": ("zh_TW", "zh-TW,zh;q=0.9,en;q=0.8"),
    "HK": ("zh_TW", "zh-HK,zh;q=0.9,en;q=0.8"),
    "DE": ("de_DE", "de,en-US;q=0.9,en;q=0.8"),
    "FR": ("fr_FR", "fr,en-US;q=0.9,en;q=0.8"),
    "SG": ("en_US", "en-SG,en;q=0.9"),
}

DEFAULT_LOCALE = "en_US"
DEFAULT_ACCEPT = "en-US,en;q=0.9"


def detect() -> dict[str, str]:
    """Query exit IP geolocation, return timezone/locale/language info.

    Returns dict with keys: timezone, locale, language, accept_language, country, ip
    """
    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/?fields=status,country,countryCode,timezone,query",
            headers={"User-Agent": "ccimage"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception:
        return {}

    if data.get("status") != "success":
        return {}

    cc = data.get("countryCode", "")
    locale, accept = COUNTRY_LOCALE.get(cc, (DEFAULT_LOCALE, DEFAULT_ACCEPT))

    return {
        "ip": data.get("query", ""),
        "country": data.get("country", ""),
        "country_code": cc,
        "timezone": data.get("timezone", ""),
        "locale": locale,
        "language": locale.split("_")[0],
        "accept_language": accept,
    }


if __name__ == "__main__":
    import sys

    info = detect()
    if not info:
        print("Failed to detect geolocation", file=sys.stderr)
        sys.exit(1)

    # Output as shell-compatible export lines
    print(f'export TZ="{info["timezone"]}"')
    print(f'export LANG="{info["locale"]}.UTF-8"')
    print(f'export LANGUAGE="{info["language"]}"')
    print(f'export LC_ALL="{info["locale"]}.UTF-8"')
    print(f'export ACCEPT_LANGUAGE="{info["accept_language"]}"')
    print(f'# Detected: {info["ip"]} → {info["country"]} ({info["timezone"]})', file=sys.stderr)
