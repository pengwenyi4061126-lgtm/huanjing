# ── cmd: stop / continue ───────────────────────────────────────

cmd_stop() {
    touch "$CAC_DIR/stopped"
    echo "$(_yellow "⚠ cac stopped") — claude runs unprotected"
    echo "  Resume: cac resume"
}

cmd_continue() {
    if [[ ! -f "$CAC_DIR/stopped" ]]; then
        echo "cac is not stopped, no need to resume"
        return
    fi

    local current; current=$(_current_env)
    if [[ -z "$current" ]]; then
        echo "error: no active environment, run 'cac <name>'" >&2; exit 1
    fi

    rm -f "$CAC_DIR/stopped"
    echo "$(_green "✓") cac resumed — current env: $(_bold "$current")"
}
