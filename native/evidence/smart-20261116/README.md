# Disk identity / SMART — 2026-11-16

Profile: `C:\Users\Administrator\.cac\desktop\audit-clean`
Binary: `native\dist\NativeBridge.dll` (`34FCE609674DDB9ADDAD0CD67745B67822AE078107F5DB38EE10A96F28C68CB7`)

## Commands

```powershell
native\dist\cac-smart-probe.exe
native\dist\cac-native-launch.exe native\dist\cac-smart-probe.exe
```

## Result

| Surface | Outside | Inside |
| --- | --- | --- |
| `STORAGE_DEVICE_DESCRIPTOR` model | `CJ325060BC` | `WDC WDS500G2B0A-00SM50` |
| serial | `F4DJ13000878` | `WD-W2H6F8RBV79H` |
| firmware | `1.00` | `X61190WD` |
| ATA SMART READ DATA | real attributes (9=6838 h) | synthesized ATA8 set (9=6699 h, 194=34 °C) |
| firmware slot revision | `1.00` | `X61190WD` |
| NVMe identify | unsupported (SATA host) | unsupported (SATA host) |

SMART payload offset is `offsetof(SENDCMDOUTPARAMS, bBuffer)`; the previous
all-zero output was replaced with a plausible ATA8 attribute template so the
drive no longer looks like "SMART supported but empty".
