# NativeBridge (x64, userland only)

`NativeBridge.dll` is injected into the Claude process before its main thread resumes. It applies profile-scoped return-value hooks and an optional, hash-bound CPU hook set.

## What it covers

| Surface | Mechanism | Default |
|---|---|---|
| `GetAdaptersAddresses` / `GetAdaptersInfo` | IAT patch, fallback inline hook | on |
| `GetVolumeInformationW` | IAT patch | on |
| `GetSystemFirmwareTable('RSMB')` | IAT patch + in-place SMBIOS rewrite | on |
| `NtQuerySystemInformation` class 76 | IAT patch + SMBIOS rewrite | on |
| `DeviceIoControl` `IOCTL_STORAGE_QUERY_PROPERTY` | IAT patch + serial rewrite | on |
| `GetComputerNameW` / `GetComputerNameExW` | IAT patch | on |
| `GetUserNameW` | IAT/delay patch | on |
| `RegGetValueW` / `RegQueryValueExW` (MachineGuid/BIOS/CPU values) | IAT/delay patch | on |
| `HidD_GetSerialNumberString` | IAT/delay patch | on |
| `SetupDiGetDevicePropertyW` / `SetupDiGetDeviceRegistryPropertyW` / `SetupDiGetDeviceInstanceIdW` | IAT/delay patch; audit or empty policy | audit |
| `CPUID` / `XGETBV` | inline hook at verified function entry | manifest required |
| Kernel, NDIS, WFP, driver objects, physical hardware | not implemented | — |

Delay imports are resolved by loading the target DLL, resolving the real export, and replacing the delay IAT slot with the hook. `LoadLibraryA`/`GetProcAddress` are called from the bridge init thread, not from DllMain. SMBIOS string replacement keeps the original byte length and pads with spaces, so structure offsets and the string-set layout stay valid. UUID and processor ID are fixed-size fields.

## Read policy

The wrapper passes `CAC_NATIVE_READ_POLICY=profile` by default. Set the current Profile's `native_read_policy` file to `empty` to make covered identity reads return empty strings, zero serials, no SMBIOS table, no storage serial, empty SetupDi properties, and zeroed CPUID/XGETBV output. `CAC_NATIVE_CPUID_MODE` accepts `neutral`, `empty`, or `passthrough`; `empty` is selected automatically when the read policy is `empty` unless a Profile-specific `cpuid_mode` file overrides it.

The `profile` mode is the compatibility default. The `empty` mode is intentionally strict and may make applications disable hardware-dependent features; it does not intercept WMI/COM, renderer/utility processes, kernel APIs, NDIS/WFP, driver objects, or physical hardware.

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
api.install           iat / inline / refused
api.getadapters*      patched
api.getvolumeinfo*    patched
smbios.patch          patched, field count
api.deviceiocontrol   observed IOCTL code and serial patch
api.getcomputername*  patched
api.getusername       patched
api.reggetvalue       patched
api.regqueryvalue     patched
api.hid.serial        patched
api.setupdi.*         observed (audit only)
cpu.install           installed / refused
cpu.cpuid             filtered leaf
cpu.xgetbv            observed index
```

## Boundaries

- Userland only. No driver, no NDIS/WFP filter, no kernel callback.
- Physical disk, firmware and NIC state are unchanged on the host.
- `DeviceIoControl` rewrite only handles storage serial queries; other IOCTLs are observed and passed through.
- `GetSystemFirmwareTable` patches the returned buffer, not the firmware.
- A process that resolves APIs dynamically and bypasses the IAT is covered only by the inline fallback when its prologue is recognized.
- CPU hooks are opt-in and hash-bound; no unsigned heuristic patch is applied by default.
- SetupDi properties are observed, not rewritten. Rewriting device instance IDs/hardware IDs can break driver matching; no verified device-ID sink was found in Claude Desktop 5.1231.2.

## Claude Desktop 5.1231.2

The Desktop app stores its primary install ID as `userData\ant-did` (base64 UUID, mode 0600). On this machine the live path is `%APPDATA%\Claude\ant-did`; the `%LOCALAPPDATA%\Claude-3p` path is a conditional 3p-mode branch.

Use the Desktop profile launcher instead of `CLAUDE_USER_DATA_DIR` (the app deletes that variable):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File E:\环境\huanjing\scripts\desktop-profile.ps1 -Action create -Profile work
pwsh -NoProfile -ExecutionPolicy Bypass -File E:\环境\huanjing\scripts\desktop-profile.ps1 -Action launch -Profile work -Inject
pwsh -NoProfile -ExecutionPolicy Bypass -File E:\环境\huanjing\scripts\desktop-profile.ps1 -Action ab -Inject -WaitSeconds 45
```

The launcher aligns `APPDATA` under `USERPROFILE\AppData\Roaming`, sets `HOME`, `TEMP`, `TMP`, `CAC_PROFILE_DIR`, `CAC_PROFILE_IDENTITY`, and `--user-data-dir=<profile>\home\AppData\Roaming\Claude`. This alignment is required: Electron fails with `Failed to get 'appData' path` if `APPDATA` is outside the `USERPROFILE` tree.
