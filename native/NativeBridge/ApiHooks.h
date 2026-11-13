#pragma once

bool InstallApiHooks();

// Shared IAT/delay/inline hook installer used by the optional child-injection
// and WMI layers. Returns the same audit trail as InstallApiHooks().
void InstallHookShared(const char* dllName, const char* functionName, void* detour,
                       void** original, bool allowInline = true);

// Installs an inline detour on the real export and then patches import tables.
// Used for APIs that callers also resolve dynamically with GetProcAddress.
void InstallHookInlinePrimary(const char* dllName, const char* functionName, void* detour,
                              void** original);

// True when the current Profile uses the strict empty-read policy.
bool NativeEmptyReadsEnabled();
void InstallCpuHooksFromManifest();
void ScanCpuCandidates();
