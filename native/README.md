# NativeBridge (x64, userland only)

The kernel boundary is documented separately in [kernel/README.md](kernel/README.md). WDK availability does not mean that a driver is installed. The project accepts only a signed KMDF/WDM driver through an SCM/INF path; manual mappers and vulnerable-driver loaders are not product dependencies.

Claude Desktop also runs a LocalSystem user-mode service, `cowork-svc.exe`.
`cac-service-injector.exe` injects NativeBridge into that service and any
replacement process by name. Profile handoff uses
`C:\ProgramData\CAC\active-profile.ini`; see
[SERVICE-COVERAGE-20261116.md](SERVICE-COVERAGE-20261116.md).

`NativeBridge.dll` is injected into the Claude process before its main thread resumes. It applies profile-scoped return-value hooks and an optional, hash-bound CPU hook set.

## What it covers

| Surface | Mechanism | Default |
|---|---|---|
| `GetAdaptersAddresses` / `GetAdaptersInfo` | inline-primary + IAT/delay patch | on |
| `GetVolumeInformationW` | inline-primary + IAT/delay patch | on |
| `GlobalMemoryStatusEx` / `GetPhysicallyInstalledSystemMemory` | inline-primary + IAT/delay patch; profile memory size | on |
| `GetDiskFreeSpaceExW` / `GetDiskFreeSpaceExA` | inline-primary + IAT/delay patch; profile disk size/free | on |
| `GetSystemInfo` / `GetNativeSystemInfo` | inline-primary + IAT/delay patch; profile logical CPU count and mask | on |
| `GetActiveProcessorCount` / `GetMaximumProcessorCount` | inline + IAT/delay; profile logical CPU count | on |
| `GetPerformanceInfo` | inline + IAT/delay; profile physical/available memory in pages | on |
| `GetLogicalProcessorInformation` | inline + IAT/delay; core entries compacted to profile cores/masks | on |
| `GetLogicalProcessorInformationEx` | inline + IAT/delay; core/package masks rewritten (probe parse still being stabilized) | on |
| `GetSystemFirmwareTable('RSMB')` | inline-primary + IAT/delay patch + in-place SMBIOS rewrite | on |
| `GetSystemFirmwareTable('ACPI'/'FIRM')` / `EnumSystemFirmwareTables` | inline-primary + IAT/delay patch; ACPI/FIRM hidden by `firmware_mode=hide-acpi` | service |
| `NtQuerySystemInformation` class 76 | inline-primary + IAT/delay patch + SMBIOS rewrite | on |
| `NtQuerySystemInformation` class 11 | profile-mode virtualization module filtering | on |
| `DeviceIoControl` `IOCTL_STORAGE_QUERY_PROPERTY` | IAT/inline; immediate serial rewrite; pending requests tracked for completion | on |
| `DeviceIoControl` `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` | MBR signature/partition GUID and GPT DiskId/PartitionId/name rewrite | on |
| `NtDeviceIoControlFile` | inline + IAT; storage serial rewrite, SMART/firmware cleared; `STATUS_PENDING` is audited as unhandled | on |
| `GetVolumeInformationByHandleW` / `GetFileInformationByHandle` / `NtQueryVolumeInformationFile` | inline-primary + IAT/delay patch + volume serial rewrite | on |
| `GetComputerNameW` / `GetComputerNameExW` | inline-primary + IAT/delay patch | on |
| `GetUserNameW` | inline-primary + IAT/delay patch | on |
| `RegGetValueW` / `RegQueryValueExW` (MachineGuid/BIOS/CPU values) | inline-primary + IAT/delay patch | on |
| `HidD_GetSerialNumberString` | inline-primary + IAT/delay patch | on |
| `HidD_GetAttributes` / `GetManufacturerString` / `GetProductString` | profile VID/PID/version and strings | on |
| `SetupDiGetDevicePropertyW` / `SetupDiGetDeviceRegistryPropertyW` / `SetupDiGetDeviceInstanceIdW` | inline-primary with IAT/delay fallback; profile mode hides virtual device IDs/properties, empty policy clears output | profile |
| `GetIfTable2` / `GetIfEntry2` / `GetIfTable` | inline-primary + IAT/delay patch + MAC rewrite | on |
| `RegEnumValueW` | inline-primary + IAT/delay patch + value rewrite | on |
| `EnumDeviceDrivers` / `K32EnumDeviceDrivers` | inline-primary + IAT/delay patch; empty policy hides the list; profile mode filters virtualization drivers | on |
| `SetupDiGetClassDevsW` | inline-primary + IAT/delay patch; empty policy hides disk/display/net/system classes | on |
| `CreateFileW` / `CreateFileA` / `CreateFile2` raw device paths | inline-primary + IAT/delay patch; empty policy denies `\\.\PhysicalDrive*` and related native paths | on |
| `NtCreateFile` raw native paths | inline + IAT; empty policy denies physical-disk, volume and firmware device paths | on |
| `GetOverlappedResult*` / `GetQueuedCompletionStatus*` | completion evidence and tracked storage-buffer sanitization | on |
| `CreateProcessW` / `CreateProcessInternalW` / `CreateProcessAsUserW` / `CreateProcessWithTokenW` / `NtCreateUserProcess` | inline + IAT; inject same-image, tool, Claude helper and MCP-host children at creation | on |
| `claude-ssh-broker.exe` / `claude-ssh-proxy.exe` / `claude-ssh-askpass.exe` | Claude-owned Go helper allowlist; API hooks + per-image CPU manifest (helper flag RVA still pending) | on |
| `github-mcp-server.exe` | Claude-owned Go helper allowlist; 6 CPU hooks + per-image manifest (helper flag RVA still pending) | on |
| `cmd/powershell/wmic/systeminfo/reg/sc/...` tools | injected when clean network or hardware profile is enabled | on |
| `cac-service-injector` descendant watcher | `cowork-svc` descendant allowlist polling + ready-gated injection | on |
| WMI COM (`CLSID_WbemLocator`) | in-process `IWbemLocator`/`IWbemServices`/`IWbemClassObject` wrappers; async sink and callback evidence | on |
| WMI hardware fields (memory/disk/CPU/GPU/display/TPM/hypervisor/network) | numeric/boolean/string VARIANT rewrite | on |
| `EnumDisplayDevicesW` / `EnumDisplaySettingsW` / `GetMonitorInfoW` | optional inline/IAT; profile GPU/monitor/resolution | on |
| `DisplayConfigGetDeviceInfo` | optional inline/IAT; monitor friendly name, EDID IDs and PnP paths | on |
| `IDXGIAdapter::GetDesc` / `GetDesc1` | per-process DXGI vtable patch; profile GPU name/PCI/VRAM | on |
| `RegQueryValueExW` / `RegGetValueW` (`EDID`) | profile-generated 128-byte EDID | on |
| SMBIOS Type 1/2/3/4/9/10/11/12/13/16/17/39/41/42/43 | in-place string/field rewrite | on |
| TBS `Tbsi_Context_Create` / `Tbsip_Submit_Command` / `Tbsi_Get_TCG_Log` | optional inline/IAT; hidden when `tpm_present=false` | optional |
| `GetAdaptersAddresses` / `GetAdaptersInfo` / `GetIfTable2` / `GetIfEntry2` / `GetIfTable` / `GetInterfaceInfo` | virtual-adapter filtering in clean mode | clean |
| `ConvertInterfaceLuidToNameW/ToAlias` / `ConvertInterfaceNameToLuidW` | virtual-adapter name lookup refused in clean mode | clean |
| `WinHttpGetIEProxyConfigForCurrentUser` / `WinHttpGetProxyForUrl` / `WinHttpGetDefaultProxyConfiguration` / `WinHttpOpen` | forced DIRECT in clean mode | clean |
| `InternetQueryOptionW(INTERNET_OPTION_PROXY)` | forced DIRECT in clean mode | clean |
| Proxy registry values (`ProxyEnable` / `ProxyServer` / `ProxyOverride` / `AutoConfigURL` / `AutoDetect`) | registry read rewrite in clean mode | clean |
| WMI `Win32_NetworkAdapter` / `Win32_NetworkAdapterConfiguration` rows | virtual rows filtered in clean mode | clean |
| `CPUID` / `XGETBV` | inline hook at verified function entry | manifest required |
| CacKernel per-process policy and exit cleanup | signed WDM control plane + narrow IOCTL + audit ring | optional, required by `-RequireKernel` |
| Dynamic outbound boundary | user-mode WFP dynamic session; app-image match, loopback allow, non-loopback block | `CAC_NETWORK_ENFORCE=1` |
| NDIS, WFP callout driver, driver objects, physical hardware | not implemented by this DLL/control plane | — |

Delay imports are resolved by loading the target DLL, resolving the real export, and replacing the delay IAT slot with the hook. Critical network, storage, registry, identity, SetupDi and completion APIs use inline-first installation so direct `GetProcAddress` callers are covered when the prologue is recognized; IAT and delay-IAT slots are then patched for imported callers. `LoadLibraryA`/`GetProcAddress` are called from the bridge init thread, not from DllMain. Export forwarders such as the x64 `kernel32!CreateFile2` form are followed to the real implementation before an inline hook is attempted. If a prologue cannot be decoded safely, the audit records `inline-refused` or `not-imported`; that event is partial evidence, never a successful install, and the bridge does not signal ready. SMBIOS string replacement keeps the original byte length and pads with spaces, so structure offsets and the string-set layout stay valid. UUID and processor ID are fixed-size fields.

## Read policy

The wrapper passes `CAC_NATIVE_READ_POLICY=profile` by default. Set the current Profile's `native_read_policy` file to `empty` to make covered identity reads return empty strings, zero serials, no SMBIOS table, no storage serial, empty SetupDi properties, and zeroed CPUID/XGETBV output. `CAC_NATIVE_CPUID_MODE` accepts `neutral`, `empty`, or `passthrough`; `empty` is selected automatically when the read policy is `empty` unless a Profile-specific `cpuid_mode` file overrides it.

The `profile` mode is the compatibility default. The `empty` mode is intentionally strict and may make applications disable hardware-dependent features. WMI/COM wrappers and same-image child-process injection are implemented in userland, but each process and each WMI path must be confirmed by audit evidence. NativeBridge registers each process with CacKernel and records `kernel.policy=verified`; this is lifecycle/control-plane evidence, not hardware virtualization.

`CAC_NETWORK_MODE=clean` (or `network_mode` file set to `clean`) hides virtual adapters from enumeration, refuses virtual LUID/name resolution, forces WinHTTP/IE/registry proxy queries to DIRECT, and filters virtual WMI network rows. `empty` read policy implies `clean`. This is a process-local view: actual routing and the server-visible exit IP are unchanged, and `GetBestRoute2` can still expose a tunnel interface index.

WMI COM hooks are skipped for tool images (`powershell.exe`, `pwsh.exe`,
`wmic.exe`, `cscript.exe`, `wscript.exe`, `mshta.exe`, `mmc.exe`) so
`Get-CimInstance` and `wmic` stay usable. Set `CAC_WMI_SPOOF_TOOLS=1` to
force filtering in those images, and `CAC_NATIVE_DISABLE_WMI=1` to disable
WMI hooks for every process. `Get-WmiObject` still crashes under injection
and is a known separate gap; use `Get-CimInstance` or `wmic`.

The `IWbemServices` wrapper forwards `IClientSecurity`, so CIM/MI queries
no longer fail with `WBEM_E_ACCESS_DENIED` when WMI hooks are enabled.
That restores availability, not filtering: MI/CIM results bypass the COM
wrapper and still show real hardware values. The C++ `IWbemLocator` path
is the covered one; `Win32_BIOS` over CIM under hooks remains a known
type-mismatch gap.

`CAC_NETWORK_MODE=enforce` additionally sets `CAC_NETWORK_ENFORCE=1`. NativeBridge opens a dynamic WFP session and installs rules for the current executable image: `127.0.0.1` and `::1` are permitted for a local proxy, while other ALE Connect traffic is blocked. Set `CAC_WFP_REQUIRED=1` to refuse readiness when the WFP session cannot be installed. This is not an NDIS lightweight filter or a kernel WFP callout.

Enable it for a Code Profile with:

```powershell
Set-Content "$env:USERPROFILE\.cac\envs\profile-a\native_read_policy" "empty" -Encoding ASCII
Set-Content "$env:USERPROFILE\.cac\envs\profile-a\cpuid_mode" "empty" -Encoding ASCII
```

## Build

The build script auto-detects the local MSVC and Windows SDK:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File E:\环境\huanjing\native\build.ps1 -Clean
```

On this machine it uses:

```text
MSVC: D:\huanjing\BuildTools\VC\Tools\MSVC\14.44.35207
SDK : D:\huanjing\WindowsKits  10.0.26100.0
```

Outputs:

```text
native/dist/NativeBridge.dll
native/dist/cac-native-launch.exe
```

The project can also be built with CMake 3.20+ and the same toolchain.

## Run and inject

The wrapper does this automatically after `Sync-NativeLayer` copies the two binaries to `%USERPROFILE%\.cac\native\`. Manual form:

```powershell
$env:CAC_PROFILE_DIR = "$env:USERPROFILE\.cac\envs\profile-a"
$env:CAC_PROFILE_IDENTITY = "$env:CAC_PROFILE_DIR\identity.json"
$env:CAC_NATIVE_AUDIT = "$env:CAC_PROFILE_DIR\audit\native-hook.jsonl"
$env:CAC_NATIVE_DLL = "$env:USERPROFILE\.cac\native\NativeBridge.dll"
& "$env:USERPROFILE\.cac\native\cac-native-launch.exe" "TARGET.exe" @args
```

The launcher creates the target suspended, injects the DLL with `LoadLibraryW`, waits for the bridge ready event, then resumes the main thread.

## CPUID / XGETBV manifest

API hooks install without a manifest. CPU hooks are refused unless the exact module hash, RVA, entry bytes and kind match `%USERPROFILE%\.cac\native\native-hook-manifest.txt`:

```text
module|sha256|rva|kind|prologue_hex
C:\path\claude.exe|ABCD...|0x1A2B30|cpuid|48895C2408...
```

Generate candidates:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File E:\环境\huanjing\native\scan-native-target.ps1 `
  -Target "C:\path\claude.exe" `
  -Output "$env:USERPROFILE\.cac\native\native-hook-candidates.txt"
```

The scanner is heuristic. Only promote an entry after confirming it is the real `__cpuid` / `__cpuidex` / `_xgetbv` entry with the exact signature. Hooking an arbitrary function that merely contains a `cpuid` instruction will replace that function's behavior.

`kind` values:

```text
cpuid    void(int out[4], int leaf)
cpuidex  void(int out[4], int leaf, int subleaf)
xgetbv   unsigned __int64(unsigned int index)
```

## Evidence

`audit\native-hook.jsonl` records:

```text
native.bridge         attach / ready
  api.install           iat / inline / inline-refused / not-imported / refused
api.getadapters*      patched
api.getvolumeinfo*    patched
smbios.patch          patched, field count
  api.deviceiocontrol   observed IOCTL code and serial patch
  api.deviceiocontrol.pending  tracked / sanitized / failed
  api.ntdeviceiocontrol.pending  unhandled for `STATUS_PENDING`
api.getcomputername*  patched
api.getusername       patched
api.reggetvalue       patched
api.regqueryvalue     patched
api.hid.serial        patched
  api.setupdi.*         observed / cleared / refused
  api.createfile*       observed / denied for raw device paths
  wmi.async             async method invocation evidence
  wmi.sink              sink wrapping / indication evidence
cpu.install           installed / refused
cpu.cpuid             filtered leaf
cpu.xgetbv            observed index
```

## Device profile verifier

`scripts\device-profile-verify.ps1` runs `cac-hardware-probe.exe` and
`wmi_probe.exe` through `cac-native-launch.exe` for one Profile, then
compares `identity.json` with the observed BIOS/UUID/disk/MAC/volume/
processor/memory/disk/CPU/SMBIOS surfaces. It also checks CIM availability
and VPN process visibility:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\device-profile-verify.ps1 `
  -ProfilePath "$env:USERPROFILE\.cac\desktop\1" -NetworkMode clean
```

The 2026-11-16 baseline is `pass=43 fail=1 warn=0`; the only failure is
Clash process visibility, which belongs to the deferred TUN+clean work.
SMBIOS Type 17 now rewrites only populated slots, so the sum of module
sizes matches the profile memory total instead of filling empty slots.

`cac-gpu-probe.exe` prints `gpuN_name/vendor/device/subsys/revision/vram_mb`
for each DXGI adapter. Run it outside and inside `cac-native-launch.exe` to
see the real GPU vs the profile GPU:

```powershell
native\dist\cac-gpu-probe.exe
```

`cac-disk-probe.exe` prints the MBR signature/partition GUIDs or GPT
DiskId/PartitionId/name for `\\.\PhysicalDrive0`; run it outside and inside
the launcher to compare.

`cac-display-probe.exe` prints the DisplayConfig friendly name, EDID
manufacturer/product IDs, monitor path and adapter path.

`cac-hid-probe.exe` enumerates HID interfaces and prints
`hidN_vendor/product/version/manufacturer/product_string/serial`.

## Boundaries

- NativeBridge remains a userland return-value layer. CacKernel is a separate SCM-loaded storage filter and control plane for per-process registration/lifecycle evidence; `network_mode=enforce` adds a dynamic user-mode WFP session for the Claude image.
- Physical disk, firmware and NIC state are unchanged on the host.
- `DeviceIoControl` rewrite only handles the supported storage serial queries; other IOCTLs are observed and passed through.
- An overlapped `DeviceIoControl` request is sanitized only when the bridge tracks the request and later observes completion through `GetOverlappedResult*` or IOCP. A `NtDeviceIoControlFile` request that returns `STATUS_PENDING` has no safe completion context in this bridge and is recorded as `unhandled`/PARTIAL.
- `GetSystemFirmwareTable` patches the returned buffer, not the firmware.
- A process that resolves APIs dynamically and bypasses the IAT is covered by inline-primary only for the listed critical APIs; unsupported ANSI variants, unknown exports and unrecognized prologues remain outside the userland coverage matrix.
- CPU hooks are opt-in and hash-bound; no unsigned heuristic patch is applied by default.
- SetupDi calls use the inline path first and the IAT/delay path as fallback. The empty policy clears the supported output buffers, but it does not create a coherent synthetic PnP device graph or change kernel PnP state. Any refused or missing install is recorded as FAIL/PARTIAL by the audit scripts.
- Child injection covers same-image, hardware/network tools, Claude-owned Go helpers and common MCP hosts. Each intercepted child must report `native.bridge=ready`; failed or timed-out child injection is terminated. System/PPL helpers (`vmcompute`, `vmwp`, `vmms`, `wslservice`), COM/WMI brokers (`dllhost`, `wmiprvse`, `RuntimeBroker`) and short-lived processes remain explicit boundaries; missing child evidence stays NOT_OBSERVED/PARTIAL.
- CacKernel rewrites supported storage identity queries for registered PIDs; its SMBIOS physical module is opt-in and disabled by default. The bridge and driver do not virtualize host CPUID, physical NIC/NDIS, DPAPI or arbitrary driver-object/hardware reads that bypass the covered paths. The audit never treats a Node/Native hook or dynamic WFP rule as full hardware isolation.

## Claude Desktop 5.1231.2

The Desktop app stores its primary install ID as `userData\ant-did` (base64 UUID, mode 0600). On this machine the live path is `%APPDATA%\Claude\ant-did`; the `%LOCALAPPDATA%\Claude-3p` path is a conditional 3p-mode branch.

Use the Desktop profile launcher instead of `CLAUDE_USER_DATA_DIR` (the app deletes that variable):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File E:\环境\huanjing\scripts\desktop-profile.ps1 -Action create -Profile work
pwsh -NoProfile -ExecutionPolicy Bypass -File E:\环境\huanjing\scripts\desktop-profile.ps1 -Action launch -Profile work -Inject
pwsh -NoProfile -ExecutionPolicy Bypass -File E:\环境\huanjing\scripts\desktop-profile.ps1 -Action ab -Inject -WaitSeconds 45
```

The launcher aligns `APPDATA` under `USERPROFILE\AppData\Roaming`, sets `HOME`, `TEMP`, `TMP`, `CAC_PROFILE_DIR`, `CAC_PROFILE_IDENTITY`, and `--user-data-dir=<profile>\home\AppData\Roaming\Claude`. This alignment is required: Electron fails with `Failed to get 'appData' path` if `APPDATA` is outside the `USERPROFILE` tree.

Native mode also appends `--no-sandbox --disable-gpu-sandbox`. Chromium's ACG/CIG blocks unsigned DLL loads in GPU/renderer processes; without these flags those processes cannot be intercepted by a user-mode DLL.
