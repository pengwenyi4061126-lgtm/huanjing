# ── cmd: relay (local relay, bypass TUN) ──────────────────────────────

_relay_valid_pid() {
    local pid="${1:-}"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && [[ "$pid" != "1" ]]
}

_relay_stop_pid() {
    local pid="${1:-}" _i
    _relay_valid_pid "$pid" || return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        for _i in {1..20}; do
            kill -0 "$pid" 2>/dev/null || return 0
            sleep 0.1
        done
        kill -KILL "$pid" 2>/dev/null || true
    fi
}

_relay_spawn() {
    local relay_js="$1" port="$2" proxy_file="$3" pid_file="$4"
    local relay_loader='
const fs = require("fs");
const relayJs = process.env.CAC_RELAY_JS;
const proxy = fs.readFileSync(process.env.CAC_RELAY_PROXY_FILE, "utf8").trim();
process.argv = [process.execPath, relayJs, process.env.CAC_RELAY_PORT, proxy, process.env.CAC_RELAY_PID_FILE];
require(relayJs);
'
    CAC_RELAY_JS="$relay_js" \
    CAC_RELAY_PORT="$port" \
    CAC_RELAY_PROXY_FILE="$proxy_file" \
    CAC_RELAY_PID_FILE="$pid_file" \
    exec node -e "$relay_loader"
}

_relay_start() {
    local name="${1:-$(_current_env)}"
    local env_dir="$ENVS_DIR/$name"
    local proxy; proxy=$(_parse_proxy "$(_read "$env_dir/proxy")")
    [[ -z "$proxy" ]] && return 1

    case "$proxy" in
        http://*|socks5://*|socks5h://*) ;;
        https://*)
            echo "error: local relay does not support TLS upstream proxies" >&2
            return 1
            ;;
        *)
            echo "error: unsupported proxy protocol" >&2
            return 1
            ;;
    esac

    local relay_js="$CAC_DIR/relay.js"
    [[ -f "$relay_js" ]] || { echo "error: relay.js not found, reinstall with 'npm i -g claude-cac'" >&2; return 1; }

    # find available port (17890-17999)
    local port=17890
    while (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null; do
        (( port++ ))
        if [[ $port -gt 17999 ]]; then
            echo "error: all ports 17890-17999 occupied" >&2
            return 1
        fi
    done

    local pid_file="$CAC_DIR/relay.pid"
    local proxy_file="$CAC_DIR/relay.proxy"
    local log_file="$CAC_DIR/relay.log"

    if [[ -f "$pid_file" ]] && ! _relay_is_running; then
        rm -f "$pid_file" "$CAC_DIR/relay.port" "$proxy_file"
    fi

    (umask 077; printf '%s\n' "$proxy" > "$proxy_file")
    (umask 077; : > "$log_file")
    chmod 600 "$proxy_file" "$log_file"

    _relay_spawn "$relay_js" "$port" "$proxy_file" "$pid_file" </dev/null >>"$log_file" 2>&1 &
    local relay_job=$!

    # wait for relay ready
    local _i
    for _i in {1..30}; do
        (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null && break
        sleep 0.1
    done

    if ! (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null; then
        _relay_stop_pid "$relay_job"
        wait "$relay_job" 2>/dev/null || true
        rm -f "$pid_file" "$CAC_DIR/relay.port" "$proxy_file"
        echo "error: relay startup timeout" >&2
        return 1
    fi

    local relay_pid; relay_pid=$(_read "$pid_file")
    if ! _relay_valid_pid "$relay_pid" || ! kill -0 "$relay_pid" 2>/dev/null; then
        _relay_stop_pid "$relay_job"
        wait "$relay_job" 2>/dev/null || true
        rm -f "$pid_file" "$CAC_DIR/relay.port" "$proxy_file"
        echo "error: relay did not create a valid PID" >&2
        return 1
    fi

    disown "$relay_job" 2>/dev/null || true
    printf '%s\n' "$port" > "$CAC_DIR/relay.port"
    return 0
}

_relay_stop() {
    local pid_file="$CAC_DIR/relay.pid"
    if [[ -f "$pid_file" ]]; then
        local pid; pid=$(tr -d '[:space:]' < "$pid_file")
        _relay_stop_pid "$pid"
        rm -f "$pid_file"
    fi
    rm -f "$CAC_DIR/relay.port" "$CAC_DIR/relay.proxy"

    # stop watchdog (relay.proxy already removed above, watchdog will self-exit within 5s;
    # kill it immediately for clean teardown)
    local wd_file="$CAC_DIR/relay.watchdog.pid"
    if [[ -f "$wd_file" ]]; then
        local wd_pid; wd_pid=$(tr -d '[:space:]' < "$wd_file")
        _relay_stop_pid "$wd_pid"
        rm -f "$wd_file"
    fi

    # cleanup route
    _relay_remove_route 2>/dev/null || true
}

_relay_is_running() {
    local pid_file="$CAC_DIR/relay.pid"
    [[ -f "$pid_file" ]] || return 1
    local pid; pid=$(tr -d '[:space:]' < "$pid_file")
    _relay_valid_pid "$pid" && kill -0 "$pid" 2>/dev/null
}

# ── route management (direct route to bypass TUN) ──────────────────────────────

_relay_add_route() {
    local proxy="$1"
    local proxy_host; proxy_host=$(_proxy_host_port "$proxy")
    proxy_host="${proxy_host%%:*}"

    # skip loopback addresses
    [[ "$proxy_host" == "127."* || "$proxy_host" == "localhost" ]] && return 0

    # resolve to IP
    local proxy_ip
    proxy_ip=$(python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "$proxy_host" 2>/dev/null || echo "$proxy_host")

    local os; os=$(_detect_os)
    if [[ "$os" == "macos" ]]; then
        local gateway
        gateway=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
        [[ -z "$gateway" ]] && return 1

        # check if direct route exists
        local current_gw
        current_gw=$(route -n get "$proxy_ip" 2>/dev/null | awk '/gateway:/{print $2}')
        [[ "$current_gw" == "$gateway" ]] && return 0

        echo "  adding direct route: $proxy_ip -> $gateway (needs sudo)"
        sudo route add -host "$proxy_ip" "$gateway" >/dev/null 2>&1 || return 1
        echo "$proxy_ip" > "$CAC_DIR/relay_route_ip"

    elif [[ "$os" == "linux" ]]; then
        local gateway iface
        gateway=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
        iface=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
        [[ -z "$gateway" ]] && return 1

        echo "  adding direct route: $proxy_ip -> $gateway dev $iface (needs sudo)"
        sudo ip route add "$proxy_ip/32" via "$gateway" dev "$iface" 2>/dev/null || return 1
        echo "$proxy_ip" > "$CAC_DIR/relay_route_ip"
    fi
}

_relay_remove_route() {
    local route_file="$CAC_DIR/relay_route_ip"
    [[ -f "$route_file" ]] || return 0

    local proxy_ip; proxy_ip=$(tr -d '[:space:]' < "$route_file")
    [[ -z "$proxy_ip" ]] && return 0

    local os; os=$(_detect_os)
    if [[ "$os" == "macos" ]]; then
        sudo route delete -host "$proxy_ip" >/dev/null 2>&1 || true
    elif [[ "$os" == "linux" ]]; then
        sudo ip route del "$proxy_ip/32" 2>/dev/null || true
    fi
    rm -f "$route_file"
}

# detect if TUN interface is active
_detect_tun_active() {
    local os; os=$(_detect_os)
    if [[ "$os" == "macos" ]]; then
        local tun_count
        tun_count=$(ifconfig 2>/dev/null | grep -cE '^utun[0-9]+' || echo 0)
        [[ "$tun_count" -gt 3 ]]
    elif [[ "$os" == "linux" ]]; then
        ip link show tun0 >/dev/null 2>&1
    else
        return 1
    fi
}

# ── user commands ─────────────────────────────────────────────────────

cmd_relay() {
    _require_setup
    local current; current=$(_current_env)
    [[ -z "$current" ]] && { echo "error: no active environment, run 'cac <name>' first" >&2; exit 1; }

    local env_dir="$ENVS_DIR/$current"
    local action="${1:-status}"
    local flag="${2:-}"

    case "$action" in
        on)
            echo "on" > "$env_dir/relay"
            echo "$(_green "✓") Relay enabled (env: $(_bold "$current"))"

            # --route flag: add direct route
            if [[ "$flag" == "--route" ]]; then
                local proxy; proxy=$(_parse_proxy "$(_read "$env_dir/proxy")")
                _relay_add_route "$proxy"
            fi

            # start relay if not running
            if ! _relay_is_running; then
                printf "  starting relay ... "
                if _relay_start "$current"; then
                    local port; port=$(_read "$CAC_DIR/relay.port")
                    echo "$(_green "✓") 127.0.0.1:$port"
                else
                    echo "$(_red "✗ failed to start")"
                fi
            fi
            echo "  next claude launch will automatically connect via local relay"
            ;;
        off)
            rm -f "$env_dir/relay"
            _relay_stop
            echo "$(_green "✓") Relay disabled (env: $(_bold "$current"))"
            ;;
        status)
            if [[ -f "$env_dir/relay" ]] && [[ "$(_read "$env_dir/relay")" == "on" ]]; then
                echo "Relay mode: $(_green "enabled")"
            else
                echo "Relay mode: disabled"
                if _detect_tun_active; then
                    echo "  $(_yellow "⚠") TUN mode detected, consider running 'cac relay on'"
                fi
                return
            fi

            if _relay_is_running; then
                local pid; pid=$(_read "$CAC_DIR/relay.pid")
                local port; port=$(_read "$CAC_DIR/relay.port" "unknown")
                echo "Relay process: $(_green "running") (PID=$pid, port=$port)"
            else
                echo "Relay process: $(_yellow "not started") (will auto-start with claude)"
            fi

            if [[ -f "$CAC_DIR/relay_route_ip" ]]; then
                local route_ip; route_ip=$(_read "$CAC_DIR/relay_route_ip")
                echo "Direct route: $route_ip"
            fi
            ;;
        *)
            echo "usage: cac relay [on|off|status]" >&2
            echo "  on [--route]  enable local relay (--route adds direct route to bypass TUN)" >&2
            echo "  off           disable local relay" >&2
            echo "  status        show status" >&2
            ;;
    esac
}
