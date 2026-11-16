# PnP WMI projection — 2026-11-16

Profile: `C:\Users\Administrator\.cac\desktop\audit-clean`
Binary: `native\dist\NativeBridge.dll` (`A3463907A4FEB6469EFAC949F8B87C14BEAB2C0481B60828AB54E93A33AB41B9`)

## Commands

```powershell
# outside
native\dist\cac-pnp-wmi-probe.exe

# inside
$p = "$env:USERPROFILE\.cac\desktop\audit-clean"
$env:CAC_PROFILE_DIR = $p
$env:CAC_PROFILE_IDENTITY = "$p\identity.json"
$env:CAC_NATIVE_DLL = "E:\环境\huanjing\native\dist\NativeBridge.dll"
native\dist\cac-native-launch.exe native\dist\cac-pnp-wmi-probe.exe
```

## Result

| Surface | Outside | Inside |
| --- | --- | --- |
| `Win32_PnPEntity` rows | 199 | 185 |
| GameViewer rows | 1 | 0 |
| Display rows | 2 | 1 |
| `Win32_BIOS` SerialNumber | `Default string` | `YU38R4PMAVNA` |
| `Win32_ComputerSystem` Name | `DESKTOP-PBOG23U` | `DESKTOP-3E2092A` |
| `Win32_Processor` ProcessorId | `BFEBFBFF000306F2` | `8CD39B0BD8785A72` |

`inside-full.txt` contains the projected rows: Display → `VEN_10DE&DEV_1F82`,
Monitor → `MONITOR\DEL41A9` + `Dell U2419H`, Net → `Realtek PCIe GbE Family
Controller`. Audit events: `wmi.pnp=virtual-hidden` for GameViewer,
`wmi.pnp=projected` per rewritten row.

## CIM availability

`Get-CimInstance Win32_BIOS` previously failed with `WBEM_E_TYPE_MISMATCH`
(`0x80041005`) under injection. After preserving provider CIM types and
formatting `ReleaseDate` as a CIM datetime, the call succeeds (`cim-inside2.txt`).
CIM/MI still bypasses the COM wrapper and returns real values; that remains an
explicit boundary, not a hook failure.

## Verifier

`scripts\device-profile-verify.ps1` adds `probe.pnp_wmi`,
`hardware.wmi_pnp_gameviewer`, `hardware.wmi_pnp_rows`,
`hardware.wmi_pnp_identity`, `hardware.wmi_pnp_cross` and the
`identity.*_realism` checks. Closing run: `pass=77 fail=1 warn=0`
(`artifacts\device-profile-20261116d\result.json`); the only failure is
Clash process visibility, deferred to TUN+clean.
