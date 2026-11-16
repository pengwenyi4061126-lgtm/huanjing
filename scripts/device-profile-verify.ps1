#requires -Version 5.1
<#
  Device profile consistency verifier.

  Runs the native hardware probe and the WMI probe through
  cac-native-launch.exe with one Profile, then compares the observed
  identity/hardware surfaces against identity.json.

  Output: <OutputDir>\result.json + raw probe logs.

  Exit code: 0 when no check fails; 1 when at least one check fails.
  Warnings are recorded but do not fail the run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProfilePath,
    [string]$OutputDir,
    [string]$NetworkMode,
    [string]$Launcher,
    [string]$DllPath,
    [string]$HardwareProbe,
    [string]$GpuProbe,
    [string]$WmiProbe,
    [switch]$SkipCim
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Launcher) { $Launcher = Join-Path $repoRoot 'native\dist\cac-native-launch.exe' }
if (-not $DllPath) { $DllPath = Join-Path $repoRoot 'native\dist\NativeBridge.dll' }
if (-not $HardwareProbe) { $HardwareProbe = Join-Path $repoRoot 'native\dist\cac-hardware-probe.exe' }
if (-not $GpuProbe) { $GpuProbe = Join-Path $repoRoot 'native\dist\cac-gpu-probe.exe' }
if (-not $WmiProbe) { $WmiProbe = Join-Path $repoRoot 'artifacts\wmi_probe.exe' }
$ProfilePath = (Resolve-Path -LiteralPath $ProfilePath).Path
$Launcher = (Resolve-Path -LiteralPath $Launcher).Path
$DllPath = (Resolve-Path -LiteralPath $DllPath).Path
$HardwareProbe = (Resolve-Path -LiteralPath $HardwareProbe).Path
if (-not (Test-Path -LiteralPath $GpuProbe -PathType Leaf)) {
    throw "GPU probe not found: $GpuProbe"
}
$GpuProbe = (Resolve-Path -LiteralPath $GpuProbe).Path
if (-not (Test-Path -LiteralPath $WmiProbe -PathType Leaf)) {
    throw "WMI probe not found: $WmiProbe"
}
$WmiProbe = (Resolve-Path -LiteralPath $WmiProbe).Path
if (-not $OutputDir) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputDir = Join-Path $repoRoot "artifacts\device-profile-$stamp"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$identityPath = Join-Path $ProfilePath 'identity.json'
if (-not (Test-Path -LiteralPath $identityPath -PathType Leaf)) {
    throw "identity.json not found: $identityPath"
}
$identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json

function Read-ProfileValue {
    param([string]$Name)
    $path = Join-Path $ProfilePath $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    return (Get-Content -LiteralPath $path -Raw).Trim()
}

function Set-ProfileEnvironment {
    $env:CAC_PROFILE_DIR = $ProfilePath
    $env:CAC_PROFILE_IDENTITY = $identityPath
    $env:CAC_NATIVE_DLL = $DllPath
    $env:CAC_NATIVE_AUDIT = Join-Path $OutputDir 'native-audit.jsonl'
    $mode = $NetworkMode
    if (-not $mode) { $mode = Read-ProfileValue 'network_mode' }
    if ($mode) { $env:CAC_NETWORK_MODE = $mode } else { Remove-Item Env:\CAC_NETWORK_MODE -ErrorAction SilentlyContinue }
    $policy = Read-ProfileValue 'native_read_policy'
    if ($policy) { $env:CAC_NATIVE_READ_POLICY = $policy }
    $cpuid = Read-ProfileValue 'cpuid_mode'
    if ($cpuid) { $env:CAC_NATIVE_CPUID_MODE = $cpuid }
    $firmware = Read-ProfileValue 'firmware_mode'
    if ($firmware) { $env:CAC_NATIVE_FIRMWARE_MODE = $firmware } else { Remove-Item Env:\CAC_NATIVE_FIRMWARE_MODE -ErrorAction SilentlyContinue }
    $redirect = Read-ProfileValue 'redirect_ant_did'
    if ($redirect) { $env:CAC_REDIRECT_ANT_DID = $redirect }
}

function Invoke-Injected {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$LogPath
    )
    $lines = & $Launcher $Executable @Arguments 2>&1
    $code = $LASTEXITCODE
    $lines | Out-File -LiteralPath $LogPath -Encoding UTF8
    return $code
}

function Read-KeyValues {
    param([string]$Path)
    $map = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $map }
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^([A-Za-z0-9_]+)=(.*)$') {
            $map[$Matches[1]] = $Matches[2].Trim()
        }
    }
    return $map
}

function Get-ProbeLine {
    param([string]$Path, [string]$Key)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match "^$([regex]::Escape($Key))=(.*)$") {
            return $Matches[1].Trim()
        }
    }
    return ''
}

function Get-ProbeScalar {
    param([string]$Path, [string]$Key)
    $value = Get-ProbeLine -Path $Path -Key $Key
    if ($value -match '^(\S+)') { return $Matches[1] }
    return ''
}

$checks = New-Object System.Collections.Generic.List[object]
function Add-Check {
    param(
        [string]$Id,
        [string]$Severity,
        [bool]$Ok,
        [string]$Expected,
        [string]$Actual,
        [string]$Note
    )
    $checks.Add([pscustomobject]@{
        id = $Id
        severity = $Severity
        ok = $Ok
        expected = $Expected
        actual = $Actual
        note = $Note
    })
}

function Normalize-Guid {
    param([string]$Value)
    if (-not $Value) { return '' }
    return ($Value -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}

function Convert-ToInt64 {
    param([object]$Value)
    if ($null -eq $Value) { return 0 }
    $parsed = [int64]0
    if ([int64]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return 0
}

Set-ProfileEnvironment

$hardwareLog = Join-Path $OutputDir 'hardware-probe.txt'
$hardwareCode = Invoke-Injected -Executable $HardwareProbe -Arguments @() -LogPath $hardwareLog
$hardware = Read-KeyValues -Path $hardwareLog

$wmiLog = Join-Path $OutputDir 'wmi-probe.txt'
$wmiCode = Invoke-Injected -Executable $WmiProbe -Arguments @() -LogPath $wmiLog
$wmi = Read-KeyValues -Path $wmiLog

$gpuLog = Join-Path $OutputDir 'gpu-probe.txt'
$gpuCode = Invoke-Injected -Executable $GpuProbe -Arguments @() -LogPath $gpuLog
$gpu = Read-KeyValues -Path $gpuLog

$cimCode = $null
$cimLog = Join-Path $OutputDir 'cim-probe.txt'
if (-not $SkipCim) {
    $cimCode = Invoke-Injected -Executable 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version | Format-List") `
        -LogPath $cimLog
}

$processLog = Join-Path $OutputDir 'process-probe.txt'
$processCode = Invoke-Injected -Executable 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
    -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
        "Get-Process -Name clash-verge,clash-verge-service,verge-mihomo -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName") `
    -LogPath $processLog

$networkModeActual = $env:CAC_NETWORK_MODE
Add-Check 'probe.hardware' 'fail' ($hardwareCode -eq 0 -and $hardware.Count -gt 0) 'exit 0 + key=value' "exit=$hardwareCode lines=$($hardware.Count)" 'native hardware probe'
Add-Check 'probe.wmi' 'fail' ($wmiCode -eq 0 -and $wmi['wmi_state'] -eq 'ok') 'wmi_state=ok' "exit=$wmiCode state=$($wmi['wmi_state'])" 'IWbemLocator probe'
Add-Check 'probe.gpu' 'fail' ($gpuCode -eq 0 -and $gpu['gpu_state'] -eq 'ok') 'gpu_state=ok' "exit=$gpuCode state=$($gpu['gpu_state'])" 'DXGI probe'
if (-not $SkipCim) {
    Add-Check 'cim.available' 'fail' ($cimCode -eq 0 -and (Test-Path -LiteralPath $cimLog)) 'Get-CimInstance succeeds' "exit=$cimCode" 'tool-image WMI gate; Get-WmiObject is still a known gap'
}

$bios = [string]$wmi['wmi_bios_serial']
$biosMatches = ($bios.Trim() -eq ([string]$identity.bios_serial).Trim()) -or
               ($bios.Trim() -eq ([string]$identity.system_serial).Trim())
Add-Check 'identity.bios_serial' 'warn' $biosMatches ([string]$identity.bios_serial) $bios 'WMI Win32_BIOS currently reports system_serial; bios_serial may be unused'
$uuid = Normalize-Guid ([string]$wmi['wmi_uuid'])
Add-Check 'identity.system_uuid' 'fail' ($uuid -eq (Normalize-Guid ([string]$identity.system_uuid))) ([string]$identity.system_uuid) ([string]$wmi['wmi_uuid']) 'WMI UUID vs identity.json'
$diskSerial = [string]$wmi['wmi_disk_serial']
Add-Check 'identity.disk_serial' 'fail' ($diskSerial -eq ([string]$identity.disk_serial)) ([string]$identity.disk_serial) $diskSerial 'WMI disk serial vs identity.json'
$mac = [string]$wmi['wmi_mac']
Add-Check 'identity.mac' 'fail' ($mac -eq ([string]$identity.mac_address)) ([string]$identity.mac_address) $mac 'WMI MAC vs identity.json'
$volume = [string]$wmi['wmi_volume_serial']
Add-Check 'identity.volume_serial' 'fail' ($volume -eq ([string]$identity.volume_serial)) ([string]$identity.volume_serial) $volume 'WMI volume serial vs identity.json'
$processorId = [string]$wmi['wmi_processor_id']
Add-Check 'identity.processor_id' 'fail' ($processorId -eq ([string]$identity.processor_id)) ([string]$identity.processor_id) $processorId 'WMI ProcessorId vs identity.json'

$memoryMb = Convert-ToInt64 (Get-ProbeScalar -Path $hardwareLog -Key 'memory_total_mb')
$wmiTotal = Convert-ToInt64 $wmi['wmi_total_physical']
$wmiTotalMb = if ($wmiTotal -gt 0) { [int64]($wmiTotal / 1MB) } else { 0 }
Add-Check 'consistency.memory' 'fail' ($memoryMb -gt 0 -and $memoryMb -eq $wmiTotalMb) "$memoryMb MB" "$wmiTotalMb MB" 'GlobalMemoryStatusEx vs Win32_ComputerSystem.TotalPhysicalMemory'

$diskGb = Convert-ToInt64 (Get-ProbeScalar -Path $hardwareLog -Key 'disk_total_gb')
$wmiDisk = Convert-ToInt64 $wmi['wmi_disk_size']
$wmiDiskGb = if ($wmiDisk -gt 0) { [int64]($wmiDisk / 1GB) } else { 0 }
Add-Check 'consistency.disk_size' 'fail' ($diskGb -gt 0 -and $diskGb -eq $wmiDiskGb) "$diskGb GB" "$wmiDiskGb GB" 'GetDiskFreeSpaceEx vs Win32_DiskDrive.Size'

$cpuCount = Convert-ToInt64 (Get-ProbeScalar -Path $hardwareLog -Key 'processors')
$wmiLogical = Convert-ToInt64 $wmi['wmi_cpu_logical']
Add-Check 'consistency.cpu_count' 'fail' ($cpuCount -gt 0 -and $cpuCount -eq $wmiLogical) "$cpuCount" "$wmiLogical" 'GetSystemInfo vs Win32_Processor.NumberOfLogicalProcessors'

$label = Get-ProbeScalar -Path $hardwareLog -Key 'volume_label'
Add-Check 'consistency.volume_label' 'fail' ($label -eq ([string]$wmi['wmi_disk_label'])) $label ([string]$wmi['wmi_disk_label']) 'GetVolumeInformation vs Win32_LogicalDisk.VolumeName'

$smbiosSystem = (Get-ProbeLine -Path $hardwareLog -Key 'smbios_type1_serial').Trim()
Add-Check 'consistency.smbios_system_serial' 'fail' ($smbiosSystem -eq ([string]$identity.system_serial).Trim()) ([string]$identity.system_serial) $smbiosSystem 'GetSystemFirmwareTable RSMB vs identity.json'

$smbiosTotalMb = [int64]0
foreach ($line in Get-Content -LiteralPath $hardwareLog) {
    if ($line -match '^smbios_type17_serial=.*size=(\d+)') {
        $smbiosTotalMb += [int64]$Matches[1]
    }
}
Add-Check 'consistency.smbios_memory_sum' 'fail' ($smbiosTotalMb -gt 0 -and $smbiosTotalMb -eq $memoryMb) "$memoryMb MB" "$smbiosTotalMb MB" 'sum of SMBIOS Type 17 sizes vs GlobalMemoryStatusEx'

$adapterName = [string]$wmi['wmi_adapter_name']
$virtualAdapterMatch = $adapterName -match 'VMware|Meta|Wintun|TAP|WireGuard|Tailscale|Virtual|Tunnel|Clash|Mihomo'
Add-Check 'network.virtual_adapter' 'fail' (-not $virtualAdapterMatch) 'no virtual adapter' $adapterName 'WMI adapter row after clean/profile filtering'

$gpuName = [string]$wmi['wmi_gpu_name']
Add-Check 'hardware.gpu_realism' 'warn' (-not ($gpuName -match 'Generic|Microsoft Basic|Display Adapter')) 'plausible physical GPU model' $gpuName 'Generic GPU is an obvious synthetic value'
$expectedGpuName = [string]$identity.gpu_name
if (-not $expectedGpuName) { $expectedGpuName = 'NVIDIA GeForce GTX 1650' }
$dxgiName = [string]$gpu['gpu0_name']
Add-Check 'hardware.dxgi_name' 'fail' ($dxgiName -eq $expectedGpuName) $expectedGpuName $dxgiName 'IDXGIAdapter::GetDesc1'
$dxgiVendor = [string]$gpu['gpu0_vendor']
$dxgiDevice = [string]$gpu['gpu0_device']
$expectedVendor = '0x10de'
$expectedDevice = '0x1f82'
Add-Check 'hardware.dxgi_pci' 'fail' ($dxgiVendor -eq $expectedVendor -and $dxgiDevice -eq $expectedDevice) "$expectedVendor/$expectedDevice" "$dxgiVendor/$dxgiDevice" 'DXGI vendor/device'
$dxgiVram = Convert-ToInt64 $gpu['gpu0_vram_mb']
Add-Check 'hardware.dxgi_vram' 'fail' ($dxgiVram -eq 4096) '4096 MB' "$dxgiVram MB" 'DXGI DedicatedVideoMemory'
$displayId = Get-ProbeLine -Path $hardwareLog -Key 'display0_name'
Add-Check 'hardware.pci_realism' 'warn' (-not ((Get-Content -LiteralPath $hardwareLog -Raw) -match 'VEN_8086&DEV_0000')) 'plausible PCI id' $displayId 'fake VEN_8086&DEV_0000 is an obvious synthetic value'
$smbiosCpu = (Get-ProbeLine -Path $hardwareLog -Key 'smbios_type4_version').Trim()
Add-Check 'hardware.cpu_realism' 'warn' (-not ($smbiosCpu -match 'Generic')) 'plausible CPU model' $smbiosCpu 'Generic x64 Processor is an obvious synthetic value'
$smbiosMemPart = if ((Get-Content -LiteralPath $hardwareLog -Raw) -match 'part=Generic') { 'Generic DDR' } else { '' }
Add-Check 'hardware.memory_realism' 'warn' ([string]::IsNullOrEmpty($smbiosMemPart)) 'plausible memory part number' $smbiosMemPart 'Generic DDR is an obvious synthetic value'

$acpiSize = Convert-ToInt64 (Get-ProbeScalar -Path $hardwareLog -Key 'acpi_size')
Add-Check 'firmware.acpi_hidden' 'warn' ($acpiSize -eq 0) '0' "$acpiSize" 'set firmware_mode=hide-acpi in the Profile'

$processNames = @()
if (Test-Path -LiteralPath $processLog) {
    $processNames = @(Get-Content -LiteralPath $processLog | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
}
Add-Check 'network.vpn_processes' 'fail' ($processNames.Count -eq 0) 'no Clash/VPN process' ($processNames -join ',') 'process enumeration is still global'

$failCount = @($checks | Where-Object { -not $_.ok -and $_.severity -eq 'fail' }).Count
$warnCount = @($checks | Where-Object { -not $_.ok -and $_.severity -eq 'warn' }).Count
$passCount = @($checks | Where-Object { $_.ok }).Count

$result = [ordered]@{
    schema = 1
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    profile = $ProfilePath
    networkMode = $networkModeActual
    launcher = $Launcher
    dll = $DllPath
    summary = [ordered]@{
        pass = $passCount
        fail = $failCount
        warn = $warnCount
    }
    checks = $checks
    raw = [ordered]@{
        hardware = $hardware
        gpu = $gpu
        wmi = $wmi
        hardwareExit = $hardwareCode
        gpuExit = $gpuCode
        wmiExit = $wmiCode
        cimExit = $cimCode
        processExit = $processCode
    }
}
$resultPath = Join-Path $OutputDir 'result.json'
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8

$checks | Select-Object id, severity, ok, expected, actual, note | Format-Table -AutoSize
Write-Output ("result: {0}" -f $resultPath)
Write-Output ("summary: pass={0} fail={1} warn={2}" -f $passCount, $failCount, $warnCount)
if ($failCount -gt 0) { exit 1 }
