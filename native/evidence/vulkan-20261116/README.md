# Vulkan probe — 2026-11-16

Profile: `C:\Users\Administrator\.cac\desktop\audit-clean`
Binary: `native\dist\NativeBridge.dll` (`A3463907A4FEB6469EFAC949F8B87C14BEAB2C0481B60828AB54E93A33AB41B9`)

## Commands

```powershell
native\dist\cac-vulkan-probe.exe
native\dist\cac-native-launch.exe native\dist\cac-vulkan-probe.exe
```

## Result

Both runs report the real host adapter:

```text
vulkan_state=ok
vulkan0_name=NVIDIA GeForce GTX 1050 Ti
vulkan0_vendor=0x10de
vulkan0_device=0x1c82
vulkan0_heap0_mb=4017
```

Vulkan identity is **not spoofed yet**. `vulkan-1.dll` exports are 5-byte
`jmp rel32` terminator thunks (`E9 ....`). The generic inline engine records
`optional-refused: unsupported prologue instruction`. A direct thunk patch
re-enters the loader dispatch and fail-fasts with `0xC0000409`; that attempt
was reverted. The probe stays as the regression harness; the safe path is a
`vkGetInstanceProcAddr` wrapper that returns profile-backed property
functions without patching the loader terminator.
