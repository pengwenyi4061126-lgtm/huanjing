# Vulkan probe — 2026-11-16

Profile: `C:\Users\Administrator\.cac\desktop\audit-clean`
Binary: `native\dist\NativeBridge.dll` (`34FCE609674DDB9ADDAD0CD67745B67822AE078107F5DB38EE10A96F28C68CB7`)

## Commands

```powershell
native\dist\cac-vulkan-probe.exe
native\dist\cac-native-launch.exe native\dist\cac-vulkan-probe.exe
```

## Result

The probe imports `vulkan-1.dll` statically, so the bridge patches its IAT
slots. Outside reports the real adapter; inside reports the profile:

| Field | Outside | Inside |
| --- | --- | --- |
| name | `NVIDIA GeForce GTX 1050 Ti` | `NVIDIA GeForce GTX 1650` |
| vendor/device | `0x10de/0x1c82` | `0x10de/0x1f82` |
| heap0 | 4017 MB | 4096 MB |

Audit: `optional-iat` for both functions, then `api.vulkan.properties=patched`
and `api.vulkan.memory=patched`. The loader's 5-byte `jmp rel32` export thunks
are left untouched: patching them re-enters loader dispatch and fail-fasts
with `0xC0000409`. Dynamic `vkGetInstanceProcAddr` resolution is still open.
