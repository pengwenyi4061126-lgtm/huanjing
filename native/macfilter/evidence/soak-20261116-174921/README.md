# soak-20261116-174921

2h traffic-only soak on the isolated Windows 11 test VM (`Ethernet0`).

```text
pass            true
startedUtc      2026-11-16T09:49:21Z
finishedUtc     2026-11-16T11:49:48Z
elapsed         7201 s
newDumps        []
newBugChecks    0
failures        []
```

State deltas:

```text
oidQueriesSeen   12665 -> 15524
oidRewrites        118 -> 118
sendForwarded     8744 -> 16125
receiveForwarded  1736 -> 4062
attached            61 -> 61
```

Files:

```text
soak.jsonl    sha256 B91635C911F35A063CDFDB365CE1C090233527E53321E5E25E38C9983B1BF0C6
summary.json  sha256 973E1AD892AD182295EF239A461CA7DDA36F0C6CB4A10AD23C17722FC6D7552E
```

Driver under test: `bin/CacMacLwf.sys`
SHA-256 `DA5AC0634A92F36EB7FCFE303D5835A4647CA2E2D8C16DCEE6157DB96C22E670`.
