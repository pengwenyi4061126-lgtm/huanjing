ARG NODE_TAG=22-bookworm
FROM node:${NODE_TAG}

ENV DEBIAN_FRONTEND=noninteractive

ARG SINGBOX_VERSION=1.11.4
ARG BUILD_PROXY

# System packages + uv + sing-box
# BUILD_PROXY: only used for curl (uv, sing-box, claude install).
# apt-get uses direct connection (Debian mirrors don't need proxy in CI).
# For local builds behind a SOCKS5 proxy, apt can reach mirrors via the
# host's network; only external downloads (GitHub, astral.sh) need the proxy.
RUN set -eux; \
    CURL="curl ${BUILD_PROXY:+-x $BUILD_PROXY}"; \
    export ALL_PROXY="${BUILD_PROXY:-}" all_proxy="${BUILD_PROXY:-}"; \
    apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl git iproute2 \
      locales nftables procps python3 python3-venv \
      openssl uuid-runtime tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i 's/^# *\(en_US\|en_GB\|ja_JP\|ko_KR\|zh_CN\|zh_TW\|de_DE\|fr_FR\)\.UTF-8/\1.UTF-8/' /etc/locale.gen \
    && locale-gen \
    && corepack enable \
    && $CURL -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local sh \
    && ln -sf /usr/local/uv /usr/local/bin/uv \
    && ln -sf /usr/local/uvx /usr/local/bin/uvx \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in amd64) SB_ARCH=amd64;; arm64) SB_ARCH=arm64;; *) echo "unsupported: $ARCH" >&2; exit 1;; esac \
    && $CURL -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}.tar.gz" \
       | tar xzO "sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}/sing-box" > /usr/local/bin/sing-box \
    && chmod +x /usr/local/bin/sing-box

# Claude Code CLI
# install.sh internally uses curl — needs ALL_PROXY so inner downloads also go through proxy
RUN set -eux; \
    export ALL_PROXY="${BUILD_PROXY:-}" all_proxy="${BUILD_PROXY:-}"; \
    curl ${BUILD_PROXY:+-x "$BUILD_PROXY"} -fsSL https://claude.ai/install.sh | bash; \
    test -x /root/.local/bin/claude

# cac (Claude Anti-fingerprint Cloak) — build from source
COPY src/ /tmp/cac-build/src/
COPY build.sh /tmp/cac-build/
RUN cd /tmp/cac-build && bash build.sh \
    && cp cac /usr/local/bin/cac \
    && cp fingerprint-hook.js /usr/local/bin/fingerprint-hook.js \
    && cp relay.js /usr/local/bin/relay.js \
    && chmod +x /usr/local/bin/cac \
    && rm -rf /tmp/cac-build

ENV LANG=en_US.UTF-8 \
    PATH="/root/.local/bin:${PATH}"

RUN echo 'export PATH="/root/.local/bin:$PATH"' >> /root/.bashrc

# sing-box config engine
COPY docker/lib/ /opt/ccimage/ccimage/
ENV PYTHONPATH="/opt/ccimage"

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/cac-check /usr/local/bin/cac-check
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/cac-check

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
