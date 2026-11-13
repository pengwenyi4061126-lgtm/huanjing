[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$tests = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $tests
$bin = Join-Path $tests "bin"
$dist = Join-Path $root "dist"

$failures = New-Object System.Collections.Generic.List[string]
function Assert-True([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host "  [PASS] $Message" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $Message" -ForegroundColor Red; $failures.Add($Message) }
}

function Parse-ProbeOutput([string[]]$Lines) {
    $values = @{}
    foreach ($line in $Lines) {
        if ($line -match '^([a-z_][a-z0-9_]*)=(.*)$') { $values[$matches[1]] = $matches[2] }
    }
    return $values
}

function Get-PeImageBase([string]$Path) {
    $headers = & dumpbin.exe /headers $Path
    foreach ($line in $headers) {
        if ($line -match '^\s+([0-9A-Fa-f]+)\s+image base') { return [Convert]::ToUInt64($matches[1], 16) }
    }
    throw "image base not found"
}

function Get-SymbolRva([string]$Path, [string]$Name) {
    $lines = @(& dumpbin.exe /disasm:nobytes $Path)
    $base = Get-PeImageBase $Path
    for ($i = 0; $i -lt $lines.Count - 1; $i++) {
        if ($lines[$i] -match ('^\s*>?\s*' + [regex]::Escape($Name) + ':')) {
            if ($lines[$i + 1] -match '^\s+([0-9A-Fa-f]+):') {
                return [Convert]::ToUInt64($matches[1], 16) - $base
            }
        }
    }
    throw "symbol not found: $Name"
}

function Get-BytesAtRva([string]$Path, [uint32]$Rva, [int]$Count) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    $sections = [BitConverter]::ToUInt16($bytes, $pe + 6)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
    $table = $pe + 24 + $optionalSize
    for ($i = 0; $i -lt $sections; $i++) {
        $entry = $table + $i * 40
        $va = [BitConverter]::ToUInt32($bytes, $entry + 12)
        $rawSize = [BitConverter]::ToUInt32($bytes, $entry + 16)
        $rawPointer = [BitConverter]::ToUInt32($bytes, $entry + 20)
        if ($Rva -ge $va -and $Rva -lt ($va + $rawSize)) {
            $offset = [int]($rawPointer + ($Rva - $va))
            return $bytes[$offset..($offset + $Count - 1)]
        }
    }
    throw "rva not mapped: 0x$($Rva.ToString('X'))"
}

New-Item -ItemType Directory -Path $bin -Force | Out-Null

Write-Host "Building NativeBridge ..." -ForegroundColor Cyan
& (Join-Path $root "build.ps1") -Clean | Out-Null
if ($LASTEXITCODE -ne 0) { throw "native build failed" }

. (Join-Path $root "toolchain.ps1")
Set-CacToolchain | Out-Null

Write-Host "Building probes ..." -ForegroundColor Cyan
Push-Location $bin
try {
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /O2 /MT (Join-Path $tests "hook_probe.cpp") /Fe:hook_probe.exe /link iphlpapi.lib advapi32.lib hid.lib | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "hook_probe build failed" }
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /O2 /MT (Join-Path $tests "delay_probe.cpp") /Fe:delay_probe.exe /link /DELAYLOAD:iphlpapi.dll iphlpapi.lib delayimp.lib | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "delay_probe build failed" }
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /Od /Zi /MT (Join-Path $tests "cpu_probe.cpp") /Fe:cpu_probe.exe /link /DEBUG | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cpu_probe build failed" }
} finally {
    Pop-Location
}

$profile = Join-Path $tests "smoke-profile"
Remove-Item -LiteralPath $profile -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path (Join-Path $profile "audit") -Force | Out-Null
$identity = [ordered]@{
    schema = 1; name = "smoke"; uuid = "11111111-2222-3333-4444-555555555555"
    stable_id = "smoke-stable"; user_id = "smoke-user"; machine_id = "0123456789abcdef0123456789abcdef"
    hostname = "host-smoke"; mac_address = "02:aa:bb:cc:dd:ee"
    system_uuid = "11111111222233334444555555555555"; disk_serial = "WD-SMOKETEST01"
    bios_serial = "PFSMOKE01"; board_serial = "MBSMOKE01"; system_serial = "SYSSMOKE01"
    processor_id = "AABBCCDDEEFF0011"; volume_serial = "DEADBEEF"
    hid_serial = "HIDSMOKE01"
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $profile "identity.json"), ($identity | ConvertTo-Json -Depth 5), $utf8)

$env:CAC_PROFILE_DIR = $profile
$env:CAC_PROFILE_IDENTITY = Join-Path $profile "identity.json"
$env:CAC_NATIVE_AUDIT = Join-Path $profile "audit\native-hook.jsonl"
$env:CAC_MAC = $identity.mac_address
$env:CAC_MACHINE_ID = $identity.machine_id
$env:CAC_HOSTNAME = $identity.hostname
$env:CAC_USERNAME = "user-audit"
$env:CAC_NATIVE_CPUID_TEST = "1"

Write-Host "Hook probe: baseline vs injected" -ForegroundColor Cyan
$baseline = Parse-ProbeOutput @(& (Join-Path $bin "hook_probe.exe") 2>&1)
$injected = Parse-ProbeOutput @(& (Join-Path $dist "cac-native-launch.exe") (Join-Path $bin "hook_probe.exe") 2>&1)

Assert-True ($baseline.mac -ne $identity.mac_address) "baseline MAC differs from profile MAC"
Assert-True ($injected.mac -eq $identity.mac_address) "injected GetAdaptersAddresses MAC matches profile"
Assert-True ($injected.mac_info -eq $identity.mac_address) "injected GetAdaptersInfo MAC matches profile"
Assert-True ($injected.volume -eq $identity.volume_serial) "injected volume serial matches profile"
Assert-True ($injected.smbios_serial.Trim() -eq $identity.system_serial) "injected SMBIOS system serial matches profile"
Assert-True ($baseline.smbios_hash -ne $injected.smbios_hash) "SMBIOS table changed after injection"
Assert-True ($injected.native_computer_name -eq $identity.hostname) "native GetComputerNameW matches profile"
Assert-True ($injected.native_computer_name_ex -eq $identity.hostname) "native GetComputerNameExW matches profile"
Assert-True ($injected.native_user_name -eq "user-audit") "native GetUserNameW matches profile"
Assert-True ($injected.native_machine_guid -eq $identity.machine_id) "native RegGetValueW MachineGuid matches profile"
Assert-True ($injected.native_machine_guid_query -eq $identity.machine_id) "native RegQueryValueExW MachineGuid matches profile"
Assert-True ($injected.native_hid_serial -eq $identity.hid_serial) "native HidD_GetSerialNumberString matches profile"

$delayBaseline = Parse-ProbeOutput @(& (Join-Path $bin "delay_probe.exe") 2>&1)
$delayInjected = Parse-ProbeOutput @(& (Join-Path $dist "cac-native-launch.exe") (Join-Path $bin "delay_probe.exe") 2>&1)
Assert-True ($delayBaseline.delay_mac -ne $identity.mac_address) "delay-import baseline MAC differs from profile"
Assert-True ($delayInjected.delay_mac -eq $identity.mac_address) "delay-import GetAdaptersAddresses MAC matches profile"

$auditLines = @(Get-Content -LiteralPath $env:CAC_NATIVE_AUDIT -ErrorAction SilentlyContinue)
Assert-True (@($auditLines | Where-Object { $_ -match '"detail":"iphlpapi.dll!GetAdaptersAddresses iat=0 delay=1"' }).Count -gt 0) "delay import descriptor patched (iat=0 delay=1)"

Assert-True (@($auditLines | Where-Object { $_ -match '"surface":"api.install","action":"complete"' }).Count -gt 0) "API hooks installed"
Assert-True (@($auditLines | Where-Object { $_ -match '"surface":"api.getvolumeinformation"' }).Count -gt 0) "volume hook recorded"
Assert-True (@($auditLines | Where-Object { $_ -match '"surface":"smbios.patch"' }).Count -gt 0) "SMBIOS patch recorded"
Assert-True (@($auditLines | Where-Object { $_ -match '"surface":"api.reggetvalue"' }).Count -gt 0) "RegGetValueW hook recorded"
Assert-True (@($auditLines | Where-Object { $_ -match '"surface":"api.hid.serial"' }).Count -gt 0) "HID serial hook recorded"

Write-Host "CPUID/XGETBV manifest hook" -ForegroundColor Cyan
$cpuProbe = Join-Path $bin "cpu_probe.exe"
$cpuIdRva = Get-SymbolRva $cpuProbe "TestCpuId"
$xgetbvRva = Get-SymbolRva $cpuProbe "TestXgetbv"
$cpuIdBytes = Get-BytesAtRva $cpuProbe ([uint32]$cpuIdRva) 16
$xgetbvBytes = Get-BytesAtRva $cpuProbe ([uint32]$xgetbvRva) 16
$cpuHash = (Get-FileHash -LiteralPath $cpuProbe -Algorithm SHA256).Hash
$cpuPrologue = -join ($cpuIdBytes | ForEach-Object { $_.ToString("x2") })
$xgetbvPrologue = -join ($xgetbvBytes | ForEach-Object { $_.ToString("x2") })
$manifest = @(
    "# cac native CPU hook manifest",
    "# module|sha256|rva|kind|prologue_hex",
    ("{0}|{1}|0x{2:X}|cpuid|{3}" -f $cpuProbe, $cpuHash, $cpuIdRva, $cpuPrologue),
    ("{0}|{1}|0x{2:X}|xgetbv|{3}" -f $cpuProbe, $cpuHash, $xgetbvRva, $xgetbvPrologue)
)
[IO.File]::WriteAllText((Join-Path $profile "cpu-manifest.txt"), ($manifest -join "`r`n") + "`r`n", $utf8)
$env:CAC_NATIVE_MANIFEST = Join-Path $profile "cpu-manifest.txt"

$cpuBaseline = Parse-ProbeOutput @(& $cpuProbe 2>&1)
$cpuInjected = Parse-ProbeOutput @(& (Join-Path $dist "cac-native-launch.exe") $cpuProbe 2>&1)
Assert-True ($cpuInjected.test_leaf -eq "0000CAFE") "CPUID detour executed and filtered"
Assert-True ($cpuInjected.hypervisor -eq "0") "hypervisor-present bit is clear"
Assert-True ($cpuInjected.xcr0 -eq $cpuBaseline.xcr0) "XGETBV value remains readable"

$auditLines = @(Get-Content -LiteralPath $env:CAC_NATIVE_AUDIT -ErrorAction SilentlyContinue)
Assert-True (@($auditLines | Where-Object { $_ -match '"surface":"cpu.install","action":"installed","detail":"cpuid"' }).Count -gt 0) "CPUID hook installed from manifest"
Assert-True (@($auditLines | Where-Object { $_ -match '"surface":"cpu.install","action":"installed","detail":"xgetbv"' }).Count -gt 0) "XGETBV hook installed from manifest"
Assert-True (@($auditLines | Where-Object { $_ -match '"surface":"cpu.cpuid"' }).Count -gt 0) "CPUID call recorded"

Write-Host "Strict empty-read policy" -ForegroundColor Cyan
Remove-Item Env:CAC_NATIVE_CPUID_TEST -ErrorAction SilentlyContinue
$env:CAC_NATIVE_READ_POLICY = "empty"
$env:CAC_NATIVE_CPUID_MODE = "empty"
$emptyInjected = Parse-ProbeOutput @(& (Join-Path $dist "cac-native-launch.exe") (Join-Path $bin "hook_probe.exe") 2>&1)
Assert-True ($emptyInjected.mac -eq "none") "empty policy clears GetAdaptersAddresses MAC"
Assert-True ($emptyInjected.mac_info -eq "none") "empty policy clears GetAdaptersInfo MAC"
Assert-True ($emptyInjected.volume -eq "00000000") "empty policy clears volume serial"
Assert-True ($emptyInjected.smbios_serial -eq "unavailable") "empty policy suppresses SMBIOS"
Assert-True ($emptyInjected.disk_serial -eq "") "empty policy clears storage serial"
Assert-True ($emptyInjected.native_computer_name -eq "") "empty policy clears computer name"
Assert-True ($emptyInjected.native_computer_name_ex -eq "") "empty policy clears extended computer name"
Assert-True ($emptyInjected.native_user_name -eq "") "empty policy clears username"
Assert-True ($emptyInjected.native_machine_guid -eq "") "empty policy clears RegGetValueW MachineGuid"
Assert-True ($emptyInjected.native_machine_guid_query -eq "") "empty policy clears RegQueryValueExW MachineGuid"
Assert-True ($emptyInjected.native_hid_serial -eq "") "empty policy clears HID serial"

$emptyCpu = Parse-ProbeOutput @(& (Join-Path $dist "cac-native-launch.exe") (Join-Path $bin "cpu_probe.exe") 2>&1)
Assert-True ($emptyCpu.test_leaf -eq "00000000") "empty policy clears arbitrary CPUID leaf"
Assert-True ($emptyCpu.hypervisor -eq "0") "empty policy clears CPUID hypervisor bit"
Assert-True ($emptyCpu.hypervisor_max -eq "00000000") "empty policy clears hypervisor leaves"
Assert-True ($emptyCpu.xcr0 -eq "0000000000000000") "empty policy clears XGETBV"

Remove-Item -LiteralPath $env:CAC_NATIVE_MANIFEST -Force -ErrorAction SilentlyContinue

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "$($failures.Count) failure(s)" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "All native smoke checks passed" -ForegroundColor Green
