# WmiMonitorID — 2026-11-16

Profile: `C:\Users\Administrator\.cac\desktop\audit-clean`
Binary: `native\dist\NativeBridge.dll` (`B5374A5B3DAD02052A948B1FD1774D1590CC40496A8040AF663F997D64E5E4FA`)

## Commands

```powershell
native\dist\cac-monitor-wmi-probe.exe
native\dist\cac-native-launch.exe native\dist\cac-monitor-wmi-probe.exe
```

## Result

| Field | Outside | Inside |
| --- | --- | --- |
| InstanceName | `DISPLAY\PHLC031\...` | `DISPLAY\DEL41A9\5&PROFILE&0&UID4352` |
| ManufacturerName | `PHL` | `DEL` |
| ProductCodeID | `C031` | `41A9` |
| SerialNumberID | `UK11125009671` | `MON-bed5c608a7` |
| UserFriendlyName | `Philips 190E` | `Dell U2419H` |

`outside-ps.txt` is the real WmiMonitorID row captured through `Get-CimInstance`
(the C++ probe's array decoder only handles the injected VT_UI2 layout).
Audit: `wmi.monitorid=patched` per array/length/instance property.
