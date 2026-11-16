# Full soak aborted run (2026-11-16)

This run completed the heavy cycle portion but did not finish the 2h traffic
window because the test VM was suspended/powered off before the timer expired.
It is kept as evidence for the cycle results, not as a 2h pass.

```text
30x disable/enable:  PASS
10x restart:         PASS
OID storm:           PASS (oidDelta=569)
traffic:             STARTED 15:15:21, did not reach stop/summary
new dumps:           none
new bugchecks:       none
```

Final counters at the last recorded event:

```text
oidQueriesSeen = 11023
oidRewrites    = 114
attached       = 59
detached       = 55
MAC            = 02:11:22:33:44:55
```

A fresh traffic-only run was started after adding:

- `SetThreadExecutionState` keep-awake
- deadline-based traffic loop
- 5-minute heartbeat records
- explicit `traffic complete` record
