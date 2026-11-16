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
    [string]$CpuDeepProbe,
    [string]$DiskProbe,
    [string]$DisplayProbe,
    [string]$HidProbe,
    [string]$NvmlProbe,
    [string]$PnpProbe,
    [string]$AudioProbe,
    [string]$OpenClProbe,
    [string]$WmiProbe,
    [switch]$SkipCim
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Launcher) { $Launcher = Join-Path $repoRoot 'native\dist\cac-native-launch.exe' }
if (-not $DllPath) { $DllPath = Join-Path $repoRoot 'native\dist\NativeBridge.dll' }
if (-not $HardwareProbe) { $HardwareProbe = Join-Path $repoRoot 'native\dist\cac-hardware-probe.exe' }
if (-not $GpuProbe) { $GpuProbe = Join-Path $repoRoot 'native\dist\cac-gpu-probe.exe' }
if (-not $CpuDeepProbe) { $CpuDeepProbe = Join-Path $repoRoot 'native\dist\cac-cpu-deep-probe.exe' }
if (-not $DiskProbe) { $DiskProbe = Join-Path $repoRoot 'native\dist\cac-disk-probe.exe' }
if (-not $DisplayProbe) { $DisplayProbe = Join-Path $repoRoot 'native\dist\cac-display-probe.exe' }
if (-not $HidProbe) { $HidProbe = Join-Path $repoRoot 'native\dist\cac-hid-probe.exe' }
if (-not $NvmlProbe) { $NvmlProbe = Join-Path $repoRoot 'native\dist\cac-nvml-probe.exe' }
if (-not $PnpProbe) { $PnpProbe = Join-Path $repoRoot 'native\dist\cac-pnp-probe.exe' }
if (-not $AudioProbe) { $AudioProbe = Join-Path $repoRoot 'native\dist\cac-audio-probe.exe' }
if (-not $OpenClProbe) { $OpenClProbe = Join-Path $repoRoot 'native\dist\cac-opencl-probe.exe' }
if (-not $WmiProbe) { $WmiProbe = Join-Path $repoRoot 'artifacts\wmi_probe.exe' }
$ProfilePath = (Resolve-Path -LiteralPath $ProfilePath).Path
$Launcher = (Resolve-Path -LiteralPath $Launcher).Path
$DllPath = (Resolve-Path -LiteralPath $DllPath).Path
$HardwareProbe = (Resolve-Path -LiteralPath $HardwareProbe).Path
if (-not (Test-Path -LiteralPath $GpuProbe -PathType Leaf)) {
    throw "GPU probe not found: $GpuProbe"
}
$GpuProbe = (Resolve-Path -LiteralPath $GpuProbe).Path
if (-not (Test-Path -LiteralPath $CpuDeepProbe -PathType Leaf)) {
    throw "CPU deep probe not found: $CpuDeepProbe"
}
$CpuDeepProbe = (Resolve-Path -LiteralPath $CpuDeepProbe).Path
if (-not (Test-Path -LiteralPath $DiskProbe -PathType Leaf)) {
    throw "Disk probe not found: $DiskProbe"
}
$DiskProbe = (Resolve-Path -LiteralPath $DiskProbe).Path
if (-not (Test-Path -LiteralPath $DisplayProbe -PathType Leaf)) {
    throw "Display probe not found: $DisplayProbe"
}
$DisplayProbe = (Resolve-Path -LiteralPath $DisplayProbe).Path
if (-not (Test-Path -LiteralPath $HidProbe -PathType Leaf)) {
    throw "HID probe not found: $HidProbe"
}
$HidProbe = (Resolve-Path -LiteralPath $HidProbe).Path
if (-not (Test-Path -LiteralPath $NvmlProbe -PathType Leaf)) {
    throw "NVML probe not found: $NvmlProbe"
}
$NvmlProbe = (Resolve-Path -LiteralPath $NvmlProbe).Path
if (-not (Test-Path -LiteralPath $PnpProbe -PathType Leaf)) {
    throw "PNP probe not found: $PnpProbe"
}
$PnpProbe = (Resolve-Path -LiteralPath $PnpProbe).Path
if (-not (Test-Path -LiteralPath $AudioProbe -PathType Leaf)) {
    throw "Audio probe not found: $AudioProbe"
}
$AudioProbe = (Resolve-Path -LiteralPath $AudioProbe).Path
if (-not (Test-Path -LiteralPath $OpenClProbe -PathType Leaf)) {
    throw "OpenCL probe not found: $OpenClProbe"
}
$OpenClProbe = (Resolve-Path -LiteralPath $OpenClProbe).Path
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

$cpuLog = Join-Path $OutputDir 'cpu-deep-probe.txt'
$cpuCode = Invoke-Injected -Executable $CpuDeepProbe -Arguments @() -LogPath $cpuLog
$cpu = Read-KeyValues -Path $cpuLog

$diskLog = Join-Path $OutputDir 'disk-probe.txt'
$diskCode = Invoke-Injected -Executable $DiskProbe -Arguments @() -LogPath $diskLog
$disk = Read-KeyValues -Path $diskLog

$displayLog = Join-Path $OutputDir 'display-probe.txt'
$displayCode = Invoke-Injected -Executable $DisplayProbe -Arguments @() -LogPath $displayLog
$display = Read-KeyValues -Path $displayLog

$hidLog = Join-Path $OutputDir 'hid-probe.txt'
$hidCode = Invoke-Injected -Executable $HidProbe -Arguments @() -LogPath $hidLog
$hid = Read-KeyValues -Path $hidLog

$nvmlLog = Join-Path $OutputDir 'nvml-probe.txt'
$nvmlCode = Invoke-Injected -Executable $NvmlProbe -Arguments @() -LogPath $nvmlLog
$nvml = Read-KeyValues -Path $nvmlLog

$pnpLog = Join-Path $OutputDir 'pnp-probe.txt'
$pnpCode = Invoke-Injected -Executable $PnpProbe -Arguments @() -LogPath $pnpLog
$pnp = Read-KeyValues -Path $pnpLog

$audioLog = Join-Path $OutputDir 'audio-probe.txt'
$audioCode = Invoke-Injected -Executable $AudioProbe -Arguments @() -LogPath $audioLog
$audio = Read-KeyValues -Path $audioLog

$openclLog = Join-Path $OutputDir 'opencl-probe.txt'
$openclCode = Invoke-Injected -Executable $OpenClProbe -Arguments @() -LogPath $openclLog
$opencl = Read-KeyValues -Path $openclLog

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
Add-Check 'probe.cpudeep' 'fail' ($cpuCode -eq 0 -and $cpu.Count -gt 0) 'exit 0 + key=value' "exit=$cpuCode lines=$($cpu.Count)" 'CPU/memory deep probe'
Add-Check 'probe.disk' 'fail' ($diskCode -eq 0 -and $disk['disk_state'] -eq 'ok') 'disk_state=ok' "exit=$diskCode state=$($disk['disk_state'])" 'Disk layout probe'
Add-Check 'probe.display' 'fail' ($displayCode -eq 0 -and $display['display_state'] -eq 'ok') 'display_state=ok' "exit=$displayCode state=$($display['display_state'])" 'DisplayConfig probe'
Add-Check 'probe.hid' 'fail' ($hidCode -eq 0 -and $hid['hid_state'] -eq 'ok') 'hid_state=ok' "exit=$hidCode state=$($hid['hid_state'])" 'HID probe'
Add-Check 'probe.nvml' 'fail' ($nvmlCode -eq 0 -and $nvml['nvml_state'] -eq 'ok') 'nvml_state=ok' "exit=$nvmlCode state=$($nvml['nvml_state'])" 'NVML static-import probe'
Add-Check 'probe.pnp' 'fail' ($pnpCode -eq 0 -and $pnp['pnp_state'] -eq 'ok') 'pnp_state=ok' "exit=$pnpCode state=$($pnp['pnp_state'])" 'SetupDi PnP probe'
Add-Check 'probe.audio' 'fail' ($audioCode -eq 0 -and $audio['audio_state'] -eq 'ok') 'audio_state=ok' "exit=$audioCode state=$($audio['audio_state'])" 'IMMDevice audio probe'
Add-Check 'probe.opencl' 'fail' ($openclCode -eq 0 -and $opencl['opencl_state'] -eq 'ok') 'opencl_state=ok' "exit=$openclCode state=$($opencl['opencl_state'])" 'OpenCL probe'
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

$expectedLogical = Convert-ToInt64 $identity.cpu_logical
if ($expectedLogical -le 0) { $expectedLogical = 8 }
$activeProcessors = Convert-ToInt64 $cpu['active_processors']
$maximumProcessors = Convert-ToInt64 $cpu['maximum_processors']
Add-Check 'consistency.active_processors' 'fail' ($activeProcessors -eq $expectedLogical) "$expectedLogical" "$activeProcessors" 'GetActiveProcessorCount'
Add-Check 'consistency.maximum_processors' 'fail' ($maximumProcessors -eq $expectedLogical) "$expectedLogical" "$maximumProcessors" 'GetMaximumProcessorCount'
$expectedCores = Convert-ToInt64 $identity.cpu_cores
if ($expectedCores -le 0) { $expectedCores = 4 }
$legacyCores = Convert-ToInt64 $cpu['legacy_core_entries']
Add-Check 'consistency.legacy_core_entries' 'fail' ($legacyCores -eq $expectedCores) "$expectedCores" "$legacyCores" 'GetLogicalProcessorInformation core entries'
$exCores = Convert-ToInt64 $cpu['core_entries']
Add-Check 'consistency.ex_core_entries' 'fail' ($exCores -eq $expectedCores) "$expectedCores" "$exCores" 'GetLogicalProcessorInformationEx core entries'
$exPackage = [string]$cpu['package_mask']
$expectedPackageMask = '0x' + (([int64]1 -shl [int]($expectedLogical)) - 1).ToString('x')
Add-Check 'consistency.ex_package_mask' 'fail' ($exPackage -eq $expectedPackageMask) $expectedPackageMask $exPackage 'GetLogicalProcessorInformationEx package mask'
$exCore0 = [string]$cpu['core0_mask']
$perCore = [int]($expectedLogical / $expectedCores)
$expectedCoreMask = '0x' + (([int64]1 -shl $perCore) - 1).ToString('x')
Add-Check 'consistency.ex_core0_mask' 'fail' ($exCore0 -eq $expectedCoreMask) $expectedCoreMask $exCore0 'GetLogicalProcessorInformationEx first core mask'

$expectedMemoryMb = Convert-ToInt64 $identity.memory_total_mb
if ($expectedMemoryMb -le 0) { $expectedMemoryMb = $memoryMb }
$expectedAvailableMb = Convert-ToInt64 $identity.memory_available_mb
if ($expectedAvailableMb -le 0) { $expectedAvailableMb = 12288 }
$perfPhysical = Convert-ToInt64 $cpu['perf_physical_mb']
$perfAvailable = Convert-ToInt64 $cpu['perf_available_mb']
Add-Check 'consistency.perf_physical' 'fail' ($perfPhysical -eq $expectedMemoryMb) "$expectedMemoryMb MB" "$perfPhysical MB" 'GetPerformanceInfo.PhysicalTotal'
Add-Check 'consistency.perf_available' 'fail' ($perfAvailable -eq $expectedAvailableMb) "$expectedAvailableMb MB" "$perfAvailable MB" 'GetPerformanceInfo.PhysicalAvailable'

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

$diskStyle = [string]$disk['disk_style']
Add-Check 'hardware.disk_layout' 'fail' ($diskStyle -eq 'GPT' -or $diskStyle -eq 'MBR') 'GPT or MBR' $diskStyle 'IOCTL_DISK_GET_DRIVE_LAYOUT_EX'
$diskId = if ($diskStyle -eq 'GPT') { [string]$disk['disk_id'] } else { [string]$disk['disk_signature'] }
Add-Check 'hardware.disk_id' 'fail' (-not [string]::IsNullOrWhiteSpace($diskId) -and $diskId -ne '0x90248822') 'profile disk signature/GUID' $diskId 'real MBR signature 0x90248822 must not leak'

$expectedMonitor = [string]$identity.monitor_name
if (-not $expectedMonitor) { $expectedMonitor = 'Dell U2419H' }
$displayName = [string]$display['display0_friendly']
Add-Check 'hardware.display_name' 'fail' ($displayName -eq $expectedMonitor) $expectedMonitor $displayName 'DisplayConfig target friendly name'
$displayVendor = [string]$display['display0_edid_manufacturer']
$displayProduct = [string]$display['display0_edid_product']
Add-Check 'hardware.display_edid' 'fail' ($displayVendor -eq '0x10ac' -and $displayProduct -eq '0x41a9') '0x10ac/0x41a9' "$displayVendor/$displayProduct" 'DisplayConfig EDID IDs'
$displayPath = [string]$display['display0_path']
Add-Check 'hardware.display_path' 'fail' ($displayPath -notmatch 'PHLC031|PHL') 'profile monitor path' $displayPath 'real monitor PnP id must not leak'
$displayAdapterPath = [string]$display['adapter0_path']
Add-Check 'hardware.display_adapter_path' 'fail' ($displayAdapterPath -notmatch 'DEV_1C82|DEV_1c82') 'profile GPU PCI id' $displayAdapterPath 'real GPU PCI id must not leak'

$hidVendor = [string]$hid['hid0_vendor']
$hidProduct = [string]$hid['hid0_product']
Add-Check 'hardware.hid_vendor' 'fail' ($hidVendor -eq '0x046d' -and $hidProduct -eq '0xc52b') '0x046d/0xc52b' "$hidVendor/$hidProduct" 'HidD_GetAttributes'
$hidManufacturer = [string]$hid['hid0_manufacturer']
Add-Check 'hardware.hid_manufacturer' 'fail' ($hidManufacturer -eq 'Logitech') 'Logitech' $hidManufacturer 'HidD_GetManufacturerString'
$hidProductString = [string]$hid['hid0_product_string']
Add-Check 'hardware.hid_product' 'fail' ($hidProductString -eq 'USB Receiver') 'USB Receiver' $hidProductString 'HidD_GetProductString'

$expectedNvmlName = [string]$identity.gpu_name
if (-not $expectedNvmlName) { $expectedNvmlName = 'NVIDIA GeForce GTX 1650' }
$expectedNvmlSerial = [string]$identity.gpu_serial
if (-not $expectedNvmlSerial) { $expectedNvmlSerial = '1321919076543' }
$expectedNvmlUuid = [string]$identity.gpu_uuid
if (-not $expectedNvmlUuid) { $expectedNvmlUuid = 'GPU-8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f' }
$nvmlName = [string]$nvml['nvml0_name']
$nvmlSerial = [string]$nvml['nvml0_serial']
$nvmlUuid = [string]$nvml['nvml0_uuid']
$nvmlMemory = Convert-ToInt64 $nvml['nvml0_mem_total_mb']
Add-Check 'hardware.nvml_name' 'fail' ($nvmlName -eq $expectedNvmlName) $expectedNvmlName $nvmlName 'nvmlDeviceGetName'
Add-Check 'hardware.nvml_serial' 'fail' ($nvmlSerial -eq $expectedNvmlSerial) $expectedNvmlSerial $nvmlSerial 'nvmlDeviceGetSerial'
Add-Check 'hardware.nvml_uuid' 'fail' ($nvmlUuid -eq $expectedNvmlUuid) $expectedNvmlUuid $nvmlUuid 'nvmlDeviceGetUUID'
Add-Check 'hardware.nvml_memory' 'fail' ($nvmlMemory -eq 4096) '4096 MB' "$nvmlMemory MB" 'nvmlDeviceGetMemoryInfo'

$pnpInstances = @($pnp.Keys | Where-Object { $_ -match '^pnp\d+_instance$' } | ForEach-Object { [string]$pnp[$_] })
$pnpText = $pnpInstances -join '|'
Add-Check 'hardware.pnp_instance_ids' 'fail' (
    $pnpText -notmatch 'VEN_10DE&DEV_1C82' -and
    $pnpText -notmatch 'PHLC031' -and
    $pnpText -match 'VEN_10DE&DEV_1F82' -and
    $pnpText -match 'DEL41A9'
) 'profile GPU/monitor PnP ids' $pnpText 'SetupDiGetDeviceInstanceIdW'
$pnpAll = (@($pnp.Values | ForEach-Object { [string]$_ }) -join '|')
Add-Check 'hardware.pnp_strings' 'fail' (
    $pnpAll -notmatch 'GTX 1050 Ti' -and
    $pnpAll -notmatch 'Philips 190E' -and
    $pnpAll -notmatch 'VEN_10DE&DEV_1C82' -and
    $pnpAll -notmatch 'PHLC031' -and
    $pnpAll -match 'GTX 1650' -and
    $pnpAll -match 'Dell U2419H'
) 'profile GPU/monitor strings' $pnpAll 'SPDRP_HARDWAREID/DEVICEDESC/FRIENDLYNAME'
Add-Check 'hardware.pnp_virtual_hidden' 'fail' (
    $pnpAll -notmatch 'GameViewer' -and
    $pnpAll -notmatch 'ROOT\\DISPLAY'
) 'no GameViewer virtual display' $pnpAll 'SetupDiGetDeviceInstanceIdW virtual-hidden'
Add-Check 'hardware.pnp_devprops' 'fail' (
    $pnpAll -match 'NVIDIA' -and
    $pnpAll -match 'Dell' -and
    $pnpAll -notmatch 'GTX 1050' -and
    $pnpAll -notmatch 'Philips'
) 'profile DEVPKEY strings' $pnpAll 'SetupDiGetDevicePropertyW'
Add-Check 'hardware.pnp_graph' 'fail' (
    $pnpAll -match 'VEN_10DE&DEV_1F82' -and
    $pnpAll -match 'Display' -and
    $pnpAll -match 'Monitor' -and
    $pnpAll -match '4d36e968' -and
    $pnpAll -match '4d36e96e'
) 'parent/class/classguid/driver' $pnpAll 'PnP graph fields'

$expectedAudioId = [string]$identity.audio_endpoint_id
if (-not $expectedAudioId) {
    $expectedAudioId = '{0.0.0.00000000}.{8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f}'
}
$audioIds = @($audio.Keys | Where-Object { $_ -match '^audio\d+_id$' } | ForEach-Object { [string]$audio[$_] })
$audioAllMatch = ($audioIds.Count -gt 0) -and (@($audioIds | Where-Object { $_ -ne $expectedAudioId }).Count -eq 0)
Add-Check 'hardware.audio_endpoint_ids' 'fail' $audioAllMatch $expectedAudioId ($audioIds -join '|') 'IMMDevice::GetId wrapper'
$expectedAudioFriendly = [string]$identity.audio_friendly_name
if (-not $expectedAudioFriendly) { $expectedAudioFriendly = 'Speakers (Realtek(R) Audio)' }
$expectedAudioInterface = [string]$identity.audio_interface_name
if (-not $expectedAudioInterface) { $expectedAudioInterface = 'Realtek High Definition Audio' }
$expectedAudioGuid = [string]$identity.audio_endpoint_guid
if (-not $expectedAudioGuid) { $expectedAudioGuid = '{8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f}' }
$audioFriendly = @($audio.Keys | Where-Object { $_ -match '^audio\d+_friendly$' } | ForEach-Object { [string]$audio[$_] })
$audioInterface = @($audio.Keys | Where-Object { $_ -match '^audio\d+_interface$' } | ForEach-Object { [string]$audio[$_] })
$audioGuid = @($audio.Keys | Where-Object { $_ -match '^audio\d+_guid$' } | ForEach-Object { [string]$audio[$_] })
$audioFormFactor = @($audio.Keys | Where-Object { $_ -match '^audio\d+_formfactor$' } | ForEach-Object { [string]$audio[$_] })
Add-Check 'hardware.audio_friendly' 'fail' (
    $audioFriendly.Count -gt 0 -and @($audioFriendly | Where-Object { $_ -ne $expectedAudioFriendly }).Count -eq 0
) $expectedAudioFriendly ($audioFriendly -join '|') 'PKEY_Device_FriendlyName'
Add-Check 'hardware.audio_interface' 'fail' (
    $audioInterface.Count -gt 0 -and @($audioInterface | Where-Object { $_ -ne $expectedAudioInterface }).Count -eq 0
) $expectedAudioInterface ($audioInterface -join '|') 'PKEY_DeviceInterface_FriendlyName'
Add-Check 'hardware.audio_guid' 'fail' (
    $audioGuid.Count -gt 0 -and @($audioGuid | Where-Object { $_ -ne $expectedAudioGuid }).Count -eq 0
) $expectedAudioGuid ($audioGuid -join '|') 'PKEY_AudioEndpoint_GUID'
Add-Check 'hardware.audio_formfactor' 'fail' (
    $audioFormFactor.Count -gt 0 -and @($audioFormFactor | Where-Object { $_ -ne '1' }).Count -eq 0
) '1' ($audioFormFactor -join '|') 'PKEY_AudioEndpoint_FormFactor'

$expectedOpenClName = [string]$identity.opencl_name
if (-not $expectedOpenClName) { $expectedOpenClName = 'NVIDIA GeForce GTX 1650' }
$expectedOpenClVendor = [string]$identity.opencl_vendor
if (-not $expectedOpenClVendor) { $expectedOpenClVendor = 'NVIDIA' }
$expectedOpenClUnits = Convert-ToInt64 $identity.opencl_compute_units
if ($expectedOpenClUnits -le 0) { $expectedOpenClUnits = 14 }
Add-Check 'hardware.opencl_name' 'fail' ([string]$opencl['opencl_name'] -eq $expectedOpenClName) $expectedOpenClName ([string]$opencl['opencl_name']) 'clGetDeviceInfo CL_DEVICE_NAME'
Add-Check 'hardware.opencl_vendor' 'fail' ([string]$opencl['opencl_vendor'] -eq $expectedOpenClVendor) $expectedOpenClVendor ([string]$opencl['opencl_vendor']) 'clGetDeviceInfo CL_DEVICE_VENDOR'
$openclMemory = Convert-ToInt64 $opencl['opencl_mem_mb']
Add-Check 'hardware.opencl_memory' 'fail' ($openclMemory -eq 4096) '4096 MB' "$openclMemory MB" 'CL_DEVICE_GLOBAL_MEM_SIZE'
$openclUnits = Convert-ToInt64 $opencl['opencl_cus']
Add-Check 'hardware.opencl_compute_units' 'fail' ($openclUnits -eq $expectedOpenClUnits) "$expectedOpenClUnits" "$openclUnits" 'CL_DEVICE_MAX_COMPUTE_UNITS'

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
        cpu = $cpu
        disk = $disk
        display = $display
        hid = $hid
        nvml = $nvml
        pnp = $pnp
        audio = $audio
        opencl = $opencl
        wmi = $wmi
        hardwareExit = $hardwareCode
        gpuExit = $gpuCode
        cpuExit = $cpuCode
        diskExit = $diskCode
        displayExit = $displayCode
        hidExit = $hidCode
        nvmlExit = $nvmlCode
        pnpExit = $pnpCode
        audioExit = $audioCode
        openclExit = $openclCode
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
