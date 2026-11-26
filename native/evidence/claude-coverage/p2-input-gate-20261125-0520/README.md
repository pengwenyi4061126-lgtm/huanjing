# P2 input gate

All non-account gates are closed: G1b (v2.31), G5c (v2.32), G6 (v2.30), G7 (v2.32), G8 (v2.31).

The remaining work is P2 only and is blocked on user-supplied external input:

- S-02, M-03, M-04, A-01, A-02, A-03: a real authenticated Claude session (Cowork / computer-use / MCP).
- L-03: a test account for login, logout, relogin and account switch.
- R-05: a post-login feature-flag snapshot.
- R-06: a telemetry credential or a real TelemetryEvent body.

Not acceptable: pushState/route tricks, CDP or shim direct calls, fabricated pass, or a shared token used without consent.

See requirements.json for the per-item unblock action and the next batch plan.