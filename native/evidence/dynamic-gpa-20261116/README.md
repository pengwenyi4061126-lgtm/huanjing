# Dynamic GetProcAddress — negative evidence (2026-11-16)

Goal: cover dynamic `GetProcAddress` resolution for Vulkan/NVML/OpenCL.

Attempt: patch only the main module IAT slot for `kernel32!GetProcAddress`
(no inline detour, to avoid the earlier code-patch race). The bridge reaches
`native.bridge=ready` and the audit records:

```json
{"surface":"api.install","action":"iat","detail":"kernel32.dll!GetProcAddress","value":"1"}
{"surface":"native.bridge","action":"ready"}
```

The next `GetProcAddress` call from the probe fail-fasts with `0xC0000409`
(`-1073740791`). The same probe works immediately after reverting the patch.

Conclusion: IAT-only interception of `GetProcAddress` is still unsafe in this
bridge (likely CFG/fail-fast on the re-entrant resolution path). Dynamic
resolution remains an explicit boundary; static IAT coverage is used instead
for Vulkan/NVML/OpenCL.
