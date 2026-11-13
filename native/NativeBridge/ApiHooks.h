#pragma once

bool InstallApiHooks();

// Number of required userland hook installs that failed in this process.
// The bridge does not signal ready while this is non-zero.
unsigned int NativeHookInstallFailures();

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

// True when virtual adapters and proxy configuration must be hidden.
bool NativeCleanNetworkEnabled();

// Case-insensitive match against known virtual/tunnel adapter names.
bool NativeIsVirtualAdapterName(const wchar_t* name);
void InstallCpuHooksFromManifest();
void ScanCpuCandidates();
