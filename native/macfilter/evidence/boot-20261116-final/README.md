# boot-20261116-final

Five consecutive reboots with `CacMacLwf` set to `SYSTEM_START`.

| # | LastBootUpTime (guest) | service | attached | oidQueriesSeen |
|---|---|---|---|---|
| 1 | 2026-11-16 20:15:36 | RUNNING | 1 | 184 |
| 2 | 2026-11-16 20:17:22 | RUNNING | 1 | 172 |
| 3 | 2026-11-16 20:18:55 | RUNNING | 1 | 170 |
| 4 | 2026-11-16 20:20:30 | RUNNING | 1 | 180 |
| 5 | 2026-11-16 20:22:05 | RUNNING | 1 | 170 |

Every boot: `registerStatus=0`, `running=1`, `oidRewrites=2`.
No new minidumps and no new System event 1001.

`soak.jsonl` contains 6 `baseline`/`boot` pairs: five recorded boots plus
one retry on the first boot (same `LastBootUpTime`).

Why SYSTEM_START: the INF declares `FilterRunType=2` (optional), so a
demand-start service stays STOPPED after reboot and `cac-macctl state`
fails with `win32=2`. `install-macfilter.ps1 -Enable` now writes
`start= system`.
