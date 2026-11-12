# Collect host-level evidence separately from Profile and Node isolation.
[CmdletBinding()]
param(
    [string]$EnvName
)

$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "lib.ps1")

function Protect-Value {
    param([object]$Value)
    if ($null -eq $Value) {
        return [ordered]@{ present = $false }
    }
    $text = [string]$Value
    $hash = [System.BitConverter]::ToString(
        (New-Object System.Security.Cryptography.SHA256Managed).ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($text)
        )
    ).Replace("-", "").ToUpperInvariant()
    return [ordered]@{ present = $true; length = $text.Length; sha256 = $hash }
}

function Get-PropertyValue {
    param([object]$Object, [string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-CimSurface {
    param(
        [string]$ClassName,
        [string[]]$PlainProperties,
        [string[]]$HashedProperties,
        [string]$Filter
    )
    try {
        if ($Filter) {
            $rows = @(Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction Stop)
        } else {
            $rows = @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop)
        }
        $result = @()
        foreach ($row in ($rows | Select-Object -First 32)) {
            $item = [ordered]@{}
            foreach ($name in $PlainProperties) {
                $item[$name] = Get-PropertyValue $row $name
            }
            foreach ($name in $HashedProperties) {
                $item[$name] = Protect-Value (Get-PropertyValue $row $name)
            }
            $result += $item
        }
        return $result
    } catch {
        return [ordered]@{ error = $_.Exception.Message }
    }
}

$profileEvidence = [ordered]@{
    requested = $EnvName
    status = "NOT_REQUESTED"
}
if ($EnvName -and (Test-ProfileName $EnvName)) {
    try {
        $paths = Ensure-ProfileLayout $EnvName
        $profileEvidence = [ordered]@{
            requested = $EnvName
            status = "PROFILE_PATHS_ONLY"
            root = $paths.Root
            config = $paths.ConfigDir
            temp = $paths.TempDir
        }
    } catch {
        $profileEvidence = [ordered]@{
            requested = $EnvName
            status = "INVALID_PROFILE"
            error = $_.Exception.Message
        }
    }
}

$machineGuid = $null
try {
    $machineGuid = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -ErrorAction Stop).MachineGuid
} catch { }

$researchRoot = "E:\claude"
$evidence = [ordered]@{
    schema = 1
    checkedUtc = [DateTime]::UtcNow.ToString("o")
    scope = "host-shared-native-hardware"
    profile = $profileEvidence
    boundary = [ordered]@{
        profileIsolation = "PROCESS_PROFILE_ONLY"
        hardwareIsolation = "NOT_PROVIDED"
        nodeHookIsHardwareProof = $false
        cpuid = "NOT_COLLECTED"
        deviceIoControl = "NOT_COLLECTED"
        kernelDrivers = "NOT_COLLECTED"
        physicalMemory = "NOT_COLLECTED"
    }
    host = [ordered]@{
        computerName = $env:COMPUTERNAME
        osVersion = [Environment]::OSVersion.Version.ToString()
        machineGuid = Protect-Value $machineGuid
    }
    surfaces = [ordered]@{
        computerSystemProduct = Get-CimSurface "Win32_ComputerSystemProduct" @("Vendor", "Name", "Version") @("UUID", "IdentifyingNumber") ""
        bios = Get-CimSurface "Win32_BIOS" @("Manufacturer", "SMBIOSBIOSVersion", "Version") @("SerialNumber") ""
        processor = Get-CimSurface "Win32_Processor" @("Name", "AddressWidth", "NumberOfLogicalProcessors") @("ProcessorId") ""
        disk = Get-CimSurface "Win32_DiskDrive" @("Model", "InterfaceType", "MediaType") @("SerialNumber") ""
        network = Get-CimSurface "Win32_NetworkAdapter" @("Name", "PhysicalAdapter", "NetConnectionStatus") @("MACAddress") "PhysicalAdapter = TRUE"
        volume = Get-CimSurface "Win32_LogicalDisk" @("DeviceID", "FileSystem", "VolumeName") @("VolumeSerialNumber") ""
    }
    research = [ordered]@{
        root = $researchRoot
        rootPresent = Test-Path -LiteralPath $researchRoot
        hardwareExePresent = Test-Path -LiteralPath (Join-Path $researchRoot "hardware.exe")
        hardwareTracePresent = Test-Path -LiteralPath (Join-Path $researchRoot "hardware.trace.jsonl")
        note = "E:\claude Native/硬件报告与本项目 Profile/Node 结果分开保存。"
    }
    conclusion = "当前程序没有修改 Windows 内核、物理网卡、磁盘序列号、BIOS/SMBIOS、CPUID 或 Native DeviceIoControl；上述主机面仍由同一台 Windows 设备共享。"
}

$auditDir = Join-Path $CAC_DIR "audit"
New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
$outPath = Join-Path $auditDir "native-hardware-check.json"
Set-Content -LiteralPath $outPath -Value ($evidence | ConvertTo-Json -Depth 10) -Encoding UTF8
Write-Host ""
Write-Host "Native / hardware boundary evidence" -ForegroundColor Cyan
Write-Host "  Profile boundary: PROCESS_PROFILE_ONLY" -ForegroundColor Yellow
Write-Host "  Hardware boundary: NOT_PROVIDED" -ForegroundColor Yellow
Write-Host "  Node Hook is hardware proof: False" -ForegroundColor Yellow
Write-Host "  Evidence: $outPath" -ForegroundColor DarkGray
Write-Host ""
