#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

export CAC_DIR="${TMPDIR:-/tmp}/cac-test"

# shellcheck source=/dev/null
source "$ROOT_DIR/src/utils.sh"

assert_eq() {
    local actual="$1"
    local expected="$2"
    local label="$3"

    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: $label" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
}

assert_eq \
    "$(_curl_proxy_url 'socks5://proxy:pass@1.2.3.4:1080')" \
    "socks5h://proxy:pass@1.2.3.4:1080" \
    "standard socks5 URL should use remote DNS"

assert_eq \
    "$(_curl_proxy_url 'socks5://1.2.3.4:1080:proxy:pass')" \
    "socks5h://proxy:pass@1.2.3.4:1080" \
    "legacy socks5 URL should normalize and use remote DNS"

assert_eq \
    "$(_curl_proxy_url 'http://proxy:pass@1.2.3.4:8080')" \
    "http://proxy:pass@1.2.3.4:8080" \
    "http proxies should stay unchanged"

assert_eq \
    "$(_curl_proxy_url 'https://proxy:pass@1.2.3.4:8443')" \
    "https://proxy:pass@1.2.3.4:8443" \
    "https proxies should stay unchanged"

echo "✓ SOCKS5 curl probes use remote DNS"
