#pragma once

// Hooks CreateProcessW inside the injected process. Children that carry the
// same image name (claude.exe renderer/utility processes) are created suspended,
// receive NativeBridge.dll, then resume with the same flags the caller asked for.
void InstallChildInjection();
