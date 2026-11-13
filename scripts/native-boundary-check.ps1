# Collect host-level evidence separately from Profile and Node isolation.
[CmdletBinding()]
param(
    [string]$EnvName,
    [switch]$Strict
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

$hookEvidence = [ordered]@{
    mode = "NODE_USERLAND_ONLY"
    path = $null
    present = $false
    events = 0
    surfaces = @()
}
$nativeEvidence = [ordered]@{
    path = $null
    present = $false
    events = 0
    surfaces = @()
    apiInstalled = $false
    apiInstallComplete = $false
    apiInstallFailures = 0
    apiInstallNotImported = 0
    apiInstallFailureDetails = @()
    apiInstallNotImportedDetails = @()
    apiInstallHealthy = $false
    cpuidHooked = $false
    xgetbvHooked = $false
    delayImports = $false
    hostnameHook = $false
    userHook = $false
    registryHook = $false
    hidHook = $false
    setupDiHook = $false
    childInjections = 0
    childInjectionFailures = 0
    processes = @()
    wmiWrapped = $false
    wmiObserved = $false
    wmiAsyncObserved = $false
    wmiSinkObserved = $false
    deviceIoPendingObserved = $false
    deviceIoPendingSanitized = 0
    deviceIoPendingUnverified = 0
    readPolicy = "unknown"
    cpuidMode = "unknown"
    networkMode = "unknown"
    networkCleanEvents = 0
}
if ($EnvName -and (Test-ProfileName $EnvName)) {
    $profilePaths = Ensure-ProfileLayout $EnvName
    $nativeEvidence.readPolicy = Read-FileValue (Join-Path $profilePaths.Root "native_read_policy") "profile"
    $nativeEvidence.cpuidMode = Read-FileValue (Join-Path $profilePaths.Root "cpuid_mode") "neutral"
    $nativeEvidence.networkMode = Read-FileValue (Join-Path $profilePaths.Root "network_mode") "profile"
    $hookEvidence.path = $profilePaths.HookAuditPath
    $hookEvidence.present = Test-Path -LiteralPath $profilePaths.HookAuditPath
    if ($hookEvidence.present) {
        $events = @(Get-Content -LiteralPath $profilePaths.HookAuditPath -ErrorAction SilentlyContinue |
            ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
            Where-Object { $null -ne $_ })
        $hookEvidence.events = $events.Count
        $hookEvidence.surfaces = @($events | Select-Object -ExpandProperty surface -Unique)
    }
    $nativeEvidence.path = Join-Path $profilePaths.AuditDir "native-hook.jsonl"
    $nativeEvidence.present = Test-Path -LiteralPath $nativeEvidence.path
    if ($nativeEvidence.present) {
        $nativeEvents = @(Get-Content -LiteralPath $nativeEvidence.path -ErrorAction SilentlyContinue |
            ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
            Where-Object { $null -ne $_ })
        $attachIndexes = @()
        for ($index = 0; $index -lt $nativeEvents.Count; $index++) {
            if ($nativeEvents[$index].surface -eq 'native.bridge' -and
                $nativeEvents[$index].action -eq 'attach') {
                $attachIndexes += $index
            }
        }
        $sessionStart = if ($attachIndexes.Count -gt 0) {
            [int]$attachIndexes[$attachIndexes.Count - 1]
        } else { 0 }
        $childEvents = @($nativeEvents | Where-Object {
            $_.surface -eq 'native.child' -and $_.action -in @('injected', 'launcher-injected')
        })
        if ($childEvents.Count -gt 0) {
            $lastChild = $childEvents[$childEvents.Count - 1]
            $rootPid = [uint32]$lastChild.pid
            $rootAttachIndexes = @($attachIndexes | Where-Object {
                [uint32]$nativeEvents[[int]$_].pid -eq $rootPid
            })
            if ($rootAttachIndexes.Count -gt 0) {
                $sessionStart = [int]$rootAttachIndexes[$rootAttachIndexes.Count - 1]
            }
        }
        $nativeEvents = @($nativeEvents | Select-Object -Skip $sessionStart)
        $nativeEvidence.events = $nativeEvents.Count
        $nativeEvidence.surfaces = @($nativeEvents | Select-Object -ExpandProperty surface -Unique)
        $nativeEvidence.apiInstallComplete = @($nativeEvents | Where-Object { $_.surface -eq "api.install" -and $_.action -eq "complete" }).Count -gt 0
        $failureEvents = @($nativeEvents | Where-Object {
                $_.surface -eq "api.install" -and $_.action -in @("refused", "missing", "inline-refused", "inline-missing")
            })
        $nativeEvidence.apiInstallFailures = $failureEvents.Count
        $nativeEvidence.apiInstallFailureDetails = @($failureEvents | ForEach-Object {
                [ordered]@{ action = $_.action; detail = $_.detail }
            })
        $notImportedEvents = @($nativeEvents | Where-Object {
                $_.surface -eq "api.install" -and $_.action -eq "not-imported"
            })
        $nativeEvidence.apiInstallNotImported = $notImportedEvents.Count
        $nativeEvidence.apiInstallNotImportedDetails = @($notImportedEvents | ForEach-Object {
                [ordered]@{ detail = $_.detail }
            })
        $nativeEvidence.apiInstallHealthy = $nativeEvidence.apiInstallComplete -and
            $nativeEvidence.apiInstallFailures -eq 0 -and
            $nativeEvidence.apiInstallNotImported -eq 0
        $nativeEvidence.apiInstalled = $nativeEvidence.apiInstallHealthy
        $nativeEvidence.cpuidHooked = @($nativeEvents | Where-Object { $_.surface -eq "cpu.install" -and $_.action -eq "installed" -and $_.detail -eq "cpuid" }).Count -gt 0
        $nativeEvidence.xgetbvHooked = @($nativeEvents | Where-Object { $_.surface -eq "cpu.install" -and $_.action -eq "installed" -and $_.detail -eq "xgetbv" }).Count -gt 0
        $nativeEvidence.delayImports = @($nativeEvents | Where-Object { $_.surface -eq "api.install" -and $_.detail -match 'delay=[1-9]' }).Count -gt 0
        $nativeEvidence.hostnameHook = @($nativeEvents | Where-Object { $_.surface -eq "api.getcomputernameex" }).Count -gt 0
        $nativeEvidence.userHook = @($nativeEvents | Where-Object { $_.surface -eq "api.getusername" }).Count -gt 0
        $nativeEvidence.registryHook = @($nativeEvents | Where-Object { $_.surface -in @("api.reggetvalue", "api.regqueryvalue") }).Count -gt 0
        $nativeEvidence.hidHook = @($nativeEvents | Where-Object { $_.surface -eq "api.hid.serial" }).Count -gt 0
        $nativeEvidence.setupDiHook = @($nativeEvents | Where-Object { $_.surface -like "api.setupdi*" }).Count -gt 0
        $nativeEvidence.processes = @($nativeEvents | Where-Object { $_.surface -eq "native.bridge" -and $_.action -eq "attach" } |
            Select-Object -ExpandProperty pid -Unique)
        $nativeEvidence.childInjections = @($nativeEvents | Where-Object { $_.surface -eq "native.child" -and $_.action -in @("injected", "launcher-injected") }).Count
        $nativeEvidence.childInjectionFailures = @($nativeEvents | Where-Object { $_.surface -eq "native.child" -and $_.action -in @("failed", "launcher-failed") }).Count
        $nativeEvidence.wmiWrapped = @($nativeEvents | Where-Object { $_.surface -eq "wmi.install" }).Count -gt 0
        $nativeEvidence.wmiObserved = @($nativeEvents | Where-Object {
            $_.surface -in @("wmi.get", "wmi.enum", "wmi.services", "wmi.async", "wmi.sink")
        }).Count -gt 0
        $nativeEvidence.wmiAsyncObserved = @($nativeEvents | Where-Object { $_.surface -eq "wmi.async" }).Count -gt 0
        $nativeEvidence.wmiSinkObserved = @($nativeEvents | Where-Object { $_.surface -eq "wmi.sink" }).Count -gt 0
        $pendingEvents = @($nativeEvents | Where-Object {
            $_.surface -in @("api.deviceiocontrol.pending", "api.ntdeviceiocontrol.pending")
        })
        $nativeEvidence.deviceIoPendingObserved = $pendingEvents.Count -gt 0
        $nativeEvidence.deviceIoPendingSanitized = @($pendingEvents | Where-Object {
            $_.action -in @("sanitized", "replaced")
        }).Count
        $nativeEvidence.deviceIoPendingUnverified = @($pendingEvents | Where-Object {
            $_.action -in @("unhandled", "unverified", "failed")
        }).Count
        $nativeEvidence.networkCleanEvents = @($nativeEvents | Where-Object { $_.action -eq "cleaned" -or $_.action -eq "clean-none" }).Count
    }
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
$nativeUserlandState = "NOT_INSTALLED"
if ($nativeEvidence.apiInstallComplete -and $nativeEvidence.apiInstallFailures -gt 0) {
    $nativeUserlandState = "PARTIAL_FAILURE"
} elseif ($nativeEvidence.apiInstallComplete -and $nativeEvidence.apiInstallNotImported -gt 0) {
    $nativeUserlandState = "PARTIAL_NOT_IMPORTED"
} elseif ($nativeEvidence.apiInstallHealthy) {
    $nativeUserlandState = "INSTALLED_WITHOUT_FAILURES"
}
$cpuidState = "NOT_COLLECTED"
if ($nativeEvidence.cpuidHooked) { $cpuidState = "HOOKED_MANIFEST_BOUND" }
$xgetbvState = "NOT_COLLECTED"
if ($nativeEvidence.xgetbvHooked) { $xgetbvState = "HOOKED_MANIFEST_BOUND" }
$deviceIoState = "NOT_COLLECTED"
if ($nativeEvidence.apiInstalled) { $deviceIoState = "USERLAND_HOOKED" }
$delayState = "NONE_OBSERVED"
if ($nativeEvidence.delayImports) { $delayState = "PATCHED" }
$hostnameState = "NONE_OBSERVED"
if ($nativeEvidence.hostnameHook) { $hostnameState = "PATCHED" }
$userState = "NONE_OBSERVED"
if ($nativeEvidence.userHook) { $userState = "PATCHED" }
$registryState = "NONE_OBSERVED"
if ($nativeEvidence.registryHook) { $registryState = "PATCHED" }
$hidState = "NONE_OBSERVED"
if ($nativeEvidence.hidHook) { $hidState = "PATCHED" }
$setupDiState = "NONE_OBSERVED"
if ($nativeEvidence.setupDiHook -and $nativeEvidence.apiInstallNotImported -eq 0) { $setupDiState = "HOOKED_OR_OBSERVED" }
elseif ($nativeEvidence.setupDiHook) { $setupDiState = "PARTIAL" }
$hardwareExePresent = Test-Path -LiteralPath (Join-Path $researchRoot "hardware.exe")
$hardwareTracePresent = Test-Path -LiteralPath (Join-Path $researchRoot "hardware.trace.jsonl")
$hardwareEvidenceState = if ($hardwareExePresent -and $hardwareTracePresent) { "PRESENT" } else { "NOT_PROVIDED" }
$boundaryFailures = New-Object System.Collections.Generic.List[string]
$boundaryPartial = New-Object System.Collections.Generic.List[string]
if (-not $EnvName) { $boundaryFailures.Add('profile-not-provided') }
elseif (-not (Test-ProfileName $EnvName)) { $boundaryFailures.Add('profile-invalid') }
if (-not $nativeEvidence.present) { $boundaryFailures.Add('native-audit-not-observed') }
if ($nativeEvidence.apiInstallFailures -gt 0) { $boundaryFailures.Add("api-install-failures:$($nativeEvidence.apiInstallFailures)") }
if ($nativeEvidence.childInjectionFailures -gt 0) { $boundaryFailures.Add("child-injection-failures:$($nativeEvidence.childInjectionFailures)") }
if ($nativeEvidence.apiInstallNotImported -gt 0) { $boundaryPartial.Add("api-not-imported:$($nativeEvidence.apiInstallNotImported)") }
if (-not $nativeEvidence.wmiWrapped) { $boundaryPartial.Add('wmi-wrapper-not-observed') }
if (-not $nativeEvidence.wmiObserved) { $boundaryPartial.Add('wmi-call-not-observed') }
if (-not $nativeEvidence.wmiAsyncObserved) { $boundaryPartial.Add('wmi-async-not-observed') }
if (-not $nativeEvidence.deviceIoPendingObserved) { $boundaryPartial.Add('deviceio-pending-not-observed') }
if ($nativeEvidence.deviceIoPendingUnverified -gt 0) {
    $boundaryPartial.Add("deviceio-pending-unverified:$($nativeEvidence.deviceIoPendingUnverified)")
}
if ($hardwareEvidenceState -ne 'PRESENT') { $boundaryPartial.Add('hardware-evidence-not-provided') }
$boundaryStatus = if ($boundaryFailures.Count -gt 0) { 'FAIL' } elseif ($boundaryPartial.Count -gt 0) { 'PARTIAL' } else { 'PASS' }
if ($Strict -and $boundaryPartial.Count -gt 0) {
    foreach ($reason in $boundaryPartial) { $boundaryFailures.Add("strict:$reason") }
    $boundaryStatus = 'FAIL'
}
$evidence = [ordered]@{
    schema = 1
    checkedUtc = [DateTime]::UtcNow.ToString("o")
    scope = "host-shared-native-hardware"
    status = $boundaryStatus
    strict = [bool]$Strict
    failures = @($boundaryFailures)
    partialReasons = @($boundaryPartial)
    profile = $profileEvidence
    boundary = [ordered]@{
        profileIsolation = "PROCESS_PROFILE_ONLY"
        hardwareIsolation = "NOT_PROVIDED"
        nodeHook = $hookEvidence.mode
        nodeHookPresent = $hookEvidence.present
        nodeHookIsHardwareProof = $false
        nativeUserland = $nativeUserlandState
        apiInstallComplete = $nativeEvidence.apiInstallComplete
        apiInstallHealthy = $nativeEvidence.apiInstallHealthy
        apiInstallFailures = $nativeEvidence.apiInstallFailures
        apiInstallNotImported = $nativeEvidence.apiInstallNotImported
        apiInstallFailureDetails = $nativeEvidence.apiInstallFailureDetails
        apiInstallNotImportedDetails = $nativeEvidence.apiInstallNotImportedDetails
        cpuid = $cpuidState
        xgetbv = $xgetbvState
        deviceIoControl = $deviceIoState
        delayImports = $delayState
        hostnameHook = $hostnameState
        userHook = $userState
        registryHook = $registryState
        hidHook = $hidState
        setupDiHook = $setupDiState
        rendererInjection = if ($nativeEvidence.childInjections -gt 0) { "PARENT_HOOK+MONITOR" } else { "NONE_OBSERVED" }
        rendererProcesses = @($nativeEvidence.processes).Count
        childInjections = $nativeEvidence.childInjections
        childInjectionFailures = $nativeEvidence.childInjectionFailures
        wmiCom = if ($nativeEvidence.wmiWrapped) { "WRAPPED" } else { "NOT_OBSERVED" }
        wmiObserved = $nativeEvidence.wmiObserved
        wmiAsyncObserved = $nativeEvidence.wmiAsyncObserved
        wmiSinkObserved = $nativeEvidence.wmiSinkObserved
        deviceIoPendingObserved = $nativeEvidence.deviceIoPendingObserved
        deviceIoPendingSanitized = $nativeEvidence.deviceIoPendingSanitized
        deviceIoPendingUnverified = $nativeEvidence.deviceIoPendingUnverified
        networkMode = $nativeEvidence.networkMode
        networkCleanEvents = $nativeEvidence.networkCleanEvents
        readPolicy = $nativeEvidence.readPolicy
        cpuidMode = $nativeEvidence.cpuidMode
        kernelDrivers = "NOT_COLLECTED"
        physicalMemory = "NOT_COLLECTED"
        hardwareEvidence = $hardwareEvidenceState
        hardwareExePresent = $hardwareExePresent
        hardwareTracePresent = $hardwareTracePresent
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
        diskPartition = Get-CimSurface "Win32_DiskPartition" @("DeviceID", "DiskIndex", "Size", "Type") @("PNPDeviceID") ""
        network = Get-CimSurface "Win32_NetworkAdapter" @("Name", "PhysicalAdapter", "NetConnectionStatus") @("MACAddress") "PhysicalAdapter = TRUE"
        networkConfiguration = Get-CimSurface "Win32_NetworkAdapterConfiguration" @("Description", "DHCPEnabled") @("SettingID", "MACAddress", "IPAddress", "DefaultIPGateway") "IPEnabled = TRUE"
        volume = Get-CimSurface "Win32_LogicalDisk" @("DeviceID", "FileSystem", "VolumeName") @("VolumeSerialNumber") ""
        baseBoard = Get-CimSurface "Win32_BaseBoard" @("Manufacturer", "Product", "Version") @("SerialNumber") ""
        operatingSystem = Get-CimSurface "Win32_OperatingSystem" @("Caption", "BuildNumber", "Version") @("SerialNumber", "InstallDate") ""
        video = Get-CimSurface "Win32_VideoController" @("Name", "AdapterCompatibility", "DriverVersion") @("PNPDeviceID") ""
    }
    hook = $hookEvidence
    native = $nativeEvidence
    research = [ordered]@{
        root = $researchRoot
        rootPresent = Test-Path -LiteralPath $researchRoot
        hardwareExePresent = $hardwareExePresent
        hardwareTracePresent = $hardwareTracePresent
        note = "E:\claude Native/硬件报告与本项目 Profile/Node 结果分开保存。"
    }
    conclusion = "Node 层与可选 NativeBridge 用户态层按 Profile 返回一致的 MAC、卷序列号、SMBIOS 和 CPUID 结果；Windows 内核、NDIS/WFP、驱动设备对象和物理硬件仍由同一台设备共享。"
}

$auditDir = if ($EnvName -and (Test-ProfileName $EnvName)) {
    (Get-ProfilePaths $EnvName).AuditDir
} else {
    Join-Path $CAC_DIR "audit"
}
New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
$outPath = Join-Path $auditDir "native-hardware-check.json"
Set-Content -LiteralPath $outPath -Value ($evidence | ConvertTo-Json -Depth 10) -Encoding UTF8
Write-Host ""
Write-Host "Native / hardware boundary evidence" -ForegroundColor Cyan
Write-Host "  Profile boundary: PROCESS_PROFILE_ONLY" -ForegroundColor Yellow
Write-Host "  Hardware boundary: NOT_PROVIDED" -ForegroundColor Yellow
Write-Host "  Node Hook is hardware proof: False" -ForegroundColor Yellow
Write-Host ("  Renderer injection: {0} ({1} processes, {2} injections, {3} failures)" -f
    $(if ($nativeEvidence.childInjections -gt 0) { "PARENT_HOOK+MONITOR" } else { "NONE_OBSERVED" }),
    @($nativeEvidence.processes).Count, $nativeEvidence.childInjections, $nativeEvidence.childInjectionFailures) -ForegroundColor Yellow
Write-Host ("  WMI/COM: {0} (calls={1}, async={2}, sink={3})" -f
    $(if ($nativeEvidence.wmiWrapped) { "WRAPPED" } else { "NOT_OBSERVED" }),
    $nativeEvidence.wmiObserved, $nativeEvidence.wmiAsyncObserved, $nativeEvidence.wmiSinkObserved) -ForegroundColor Yellow
Write-Host ("  DeviceIoControl pending: observed={0}, sanitized={1}, unverified={2}" -f
    $nativeEvidence.deviceIoPendingObserved,
    $nativeEvidence.deviceIoPendingSanitized,
    $nativeEvidence.deviceIoPendingUnverified) -ForegroundColor Yellow
Write-Host ("  Network mode: {0} (clean events: {1})" -f $nativeEvidence.networkMode, $nativeEvidence.networkCleanEvents) -ForegroundColor Yellow
Write-Host "  Evidence: $outPath" -ForegroundColor DarkGray
Write-Host ""
if ($boundaryStatus -eq 'FAIL') {
    Write-Host ("[FAIL] Native boundary evidence failed: {0}" -f (($boundaryFailures | Select-Object -Unique) -join ', ')) -ForegroundColor Red
    exit 1
}
if ($boundaryStatus -eq 'PARTIAL') {
    Write-Host ("[PARTIAL] Native boundary evidence is incomplete: {0}" -f (($boundaryPartial | Select-Object -Unique) -join ', ')) -ForegroundColor Yellow
    exit 1
}
Write-Host "[PASS] Native boundary evidence is complete." -ForegroundColor Green
