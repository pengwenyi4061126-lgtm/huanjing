# CPU cache topology — 2026-11-17

Profile: `C:\Users\Administrator\.cac\desktop\audit-clean`
Binary: `native\dist\NativeBridge.dll` (`2758F1C3DD5B97D7FE69EE9F13BAECD2A09FB67B369DB7373234BA6E4E058A4F`)

## Commands

```powershell
native\dist\cac-cache-probe.exe
native\dist\cac-native-launch.exe native\dist\cac-cache-probe.exe
```

## Result

| Level | Outside (Xeon E5-2678 v3) | Inside (Ryzen 3 3100 profile) |
| --- | --- | --- |
| L1 entries | 24 | 8 |
| L2 entries / total | 12 / 3072 KB | 4 / 2048 KB |
| L3 entries / total | 1 / 30720 KB | 1 / 16384 KB |
| L2 per entry | 256 KB | 512 KB |

`GetLogicalProcessorInformationEx(RelationCache)` now drops host cache
entries down to the profile core count, rewrites per-core L2 to
`l2_cache_kb / cores`, shared L3 to `l3_cache_kb`, and re-maps every
GroupMask onto the compacted 8-logical-processor package.
