# USB descriptors — 2026-11-16

Profile: `C:\Users\Administrator\.cac\desktop\audit-clean`
Binary: `native\dist\NativeBridge.dll` (`CB77EA294E095511052D218246825BE85DD2EEDA362EB040168A32C5BE4701A7`)

## Commands

```powershell
native\dist\cac-usb-probe.exe
native\dist\cac-native-launch.exe native\dist\cac-usb-probe.exe
```

## Result

| Row | Outside | Inside |
| --- | --- | --- |
| HID keyboard | `USB\VID_1C4F&PID_0034` | `USB\VID_046D&PID_C52B\5&08EBA5A3&0&1` |
| composite | `USB\VID_1A2C&PID_0B2A` | `USB\VID_046D&PID_C52B\5&3DA63024&0&1` |
| interfaces | `&MI_00` / `&MI_01` | `&MI_00` / `&MI_01` preserved |
| manufacturer | `(中文厂商)` | `Logitech` |
| hardware IDs | real VID/PID | `USB\VID_046D&PID_C52B&REV_0111...` |
| root/generic hubs | `ROOT_HUB30`, `VID_8087` | unchanged |

Each rewritten row gets a stable FNV-1a suffix so instance IDs stay unique.
USBSTOR is empty on this host; the storage path is already covered by
`STORAGE_DEVICE_DESCRIPTOR` and SMART.
