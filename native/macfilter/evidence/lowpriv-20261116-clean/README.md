# lowpriv-20261116-clean

Standard user `cactest` (member of `Users`) runs
`cac-macctl.exe state` against `\\.\CacMacLwf`.

```text
harness pass   true
failures       []
exitCode       1
stdout         {"ok":false,"error":"open device","win32":5}
```

`win32=5` is `ERROR_ACCESS_DENIED`, matching the `SYSTEM + Administrators`
DACL set by `IoCreateDeviceSecure`.

The same run also repeated clone/lower fault modes and the four invalid
IOCTL probes; all stayed within the expected error paths.

Files:

```text
fault.jsonl    sha256 E68457F79E0A4AA636D0BCF961F62FF87E6A940BC9D4E45CA646336AD59A33A7
summary.json   sha256 071F80D530210AE1C0629E999886808DD6BF9F7AC2EF95FFBA1D967A0B153A5D
```
