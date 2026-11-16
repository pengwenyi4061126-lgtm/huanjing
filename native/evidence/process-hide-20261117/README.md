# VPN process visibility — 2026-11-17

Profile: `C:\Users\Administrator\.cac\desktop\audit-clean`
Binary: `native\dist\NativeBridge.dll` (`051274E6F86227039EB64DE5416B66039627DC42793AC67475E40AD9C3845439`)

## Commands

```powershell
powershell -NoProfile -Command "Get-Process -Name clash-verge,clash-verge-service,verge-mihomo | Select -Expand ProcessName"
native\dist\cac-native-launch.exe powershell.exe -NoProfile -Command "Get-Process -Name clash-verge,clash-verge-service,verge-mihomo | Select -Expand ProcessName"
```

## Result

Outside: `clash-verge`, `clash-verge-service`, `verge-mihomo`.

Inside: no rows; audit `api.process=hidden` value `3`.

`NtQuerySystemInformation(SystemProcessInformation)` compacts the linked list
and drops the six known VPN image names. Full verifier (profile and clean
mode): `pass=107 fail=0 warn=0`.
