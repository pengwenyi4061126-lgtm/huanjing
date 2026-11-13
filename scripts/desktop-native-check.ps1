# Verify the latest NativeBridge session recorded for one Claude Desktop Profile.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$Profile,
    [switch]$RequireChild,
    [switch]$RequireCpuManifest,
    [switch]$RequireRendererUtility,
    [switch]$Strict,
    [switch]$AllowPartial
)

$ErrorActionPreference = 'Stop'
$root = Join-Path (Join-Path $env:USERPROFILE '.cac\desktop') $Profile
$auditPath = Join-Path $root 'audit\native-hook.jsonl'
$outputPath = Join-Path $root 'audit\desktop-native-check.json'

if (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
    throw "Native audit log is missing: $auditPath"
}

$events = @(Get-Content -LiteralPath $auditPath -ErrorAction Stop |
    ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
    Where-Object { $null -ne $_ })
$attachIndexes = @()
for ($index = 0; $index -lt $events.Count; $index++) {
    if ($events[$index].surface -eq 'native.bridge' -and $events[$index].action -eq 'attach') {
        $attachIndexes += $index
    }
}
if ($attachIndexes.Count -eq 0) { throw "No NativeBridge attach event found: $auditPath" }
$sessionStartIndex = [int]$attachIndexes[$attachIndexes.Count - 1]
$rootPid = $null
$childEvents = @($events | Where-Object {
    $_.surface -eq 'native.child' -and $_.action -in @('injected', 'launcher-injected')
})
if ($childEvents.Count -gt 0) {
    $lastChild = $childEvents[$childEvents.Count - 1]
    $rootPid = [uint32]$lastChild.pid
    $rootAttachIndexes = @($attachIndexes | Where-Object {
        [uint32]$events[[int]$_].pid -eq $rootPid
    })
    if ($rootAttachIndexes.Count -gt 0) {
        $sessionStartIndex = [int]$rootAttachIndexes[$rootAttachIndexes.Count - 1]
    }
}
$session = @($events | Select-Object -Skip $sessionStartIndex)

$failureActions = @('refused', 'missing', 'inline-refused', 'inline-missing')
$failures = @($session | Where-Object {
    $_.surface -eq 'api.install' -and $_.action -in $failureActions
})
$notImported = @($session | Where-Object {
    $_.surface -eq 'api.install' -and $_.action -eq 'not-imported'
})
$children = @($session | Where-Object { $_.surface -eq 'native.child' })
$childInjected = @($children | Where-Object { $_.action -in @('injected', 'launcher-injected') })
$childFailed = @($children | Where-Object { $_.action -in @('failed', 'launcher-failed') })
$attachEvents = @($session | Where-Object {
    $_.surface -eq 'native.bridge' -and $_.action -eq 'attach'
})
$processTypes = [ordered]@{}
foreach ($event in $attachEvents) {
    $type = 'unknown'
    if ([string]$event.detail -match 'process=([^, ]+)') { $type = $matches[1] }
    if (-not $processTypes.Contains($type)) { $processTypes[$type] = 0 }
    $processTypes[$type]++
}
$unwrappedWmi = @($session | Where-Object {
    $_.surface -in @('wmi.enum', 'wmi.services') -and $_.action -match 'unwrapped'
})
$filteredWmi = @($session | Where-Object { $_.surface -eq 'wmi.sink' -and $_.action -eq 'async-filtered' })
$wmiInstall = @($session | Where-Object { $_.surface -eq 'wmi.install' })
$wmiAsync = @($session | Where-Object { $_.surface -eq 'wmi.async' })
$wmiSink = @($session | Where-Object { $_.surface -eq 'wmi.sink' })
$wmiObserved = @($session | Where-Object {
    $_.surface -in @('wmi.get', 'wmi.enum', 'wmi.services', 'wmi.async', 'wmi.sink')
})
$pendingEvents = @($session | Where-Object {
    $_.surface -in @('api.deviceiocontrol.pending', 'api.ntdeviceiocontrol.pending')
})
$pendingSanitized = @($pendingEvents | Where-Object { $_.action -in @('sanitized', 'replaced') })
$pendingUnverified = @($pendingEvents | Where-Object {
    $_.action -in @('unhandled', 'unverified', 'failed')
})
$cpuManifest = @($session | Where-Object { $_.surface -eq 'cpu.manifest' } | Select-Object -Last 1)
$cpuInstalled = @($session | Where-Object {
    $_.surface -eq 'cpu.install' -and $_.action -eq 'installed'
})
$ready = @($session | Where-Object { $_.surface -eq 'native.bridge' -and $_.action -eq 'ready' }).Count -gt 0

$result = [ordered]@{
    schema = 1
    checkedUtc = [DateTime]::UtcNow.ToString('o')
    profile = $Profile
    auditPath = $auditPath
    sessionStart = $session[0].utc
    rootPid = $rootPid
    session = [ordered]@{
        ready = $ready
        processes = @($attachEvents |
            Select-Object -ExpandProperty pid -Unique)
        processTypes = $processTypes
        mainAttached = [bool]($processTypes.Contains('main'))
        rendererAttached = [bool]($processTypes.Contains('renderer'))
        utilityAttached = [bool]($processTypes.Contains('utility'))
        gpuAttached = [bool]($processTypes.Contains('gpu-process'))
        crashpadAttached = [bool]($processTypes.Contains('crashpad-handler'))
        apiInstallComplete = @($session | Where-Object { $_.surface -eq 'api.install' -and $_.action -eq 'complete' }).Count -gt 0
        apiInstallFailures = $failures.Count
        apiInstallFailureDetails = @($failures | ForEach-Object {
            [ordered]@{ action = $_.action; detail = $_.detail; pid = $_.pid }
        })
        apiInstallNotImported = $notImported.Count
        apiInstallNotImportedDetails = @($notImported | ForEach-Object {
            [ordered]@{ detail = $_.detail; pid = $_.pid }
        })
        childInjected = $childInjected.Count
        childInjectionFailures = $childFailed.Count
        childDetails = @($children | ForEach-Object {
            [ordered]@{ action = $_.action; detail = $_.detail; pid = $_.pid; value = $_.value }
        })
        wmiAsyncUnwrapped = $unwrappedWmi.Count
        wmiAsyncFiltered = $filteredWmi.Count
        wmiWrapped = $wmiInstall.Count -gt 0
        wmiObserved = $wmiObserved.Count -gt 0
        wmiAsyncObserved = $wmiAsync.Count -gt 0
        wmiSinkObserved = $wmiSink.Count -gt 0
        deviceIoPendingObserved = $pendingEvents.Count -gt 0
        deviceIoPendingSanitized = $pendingSanitized.Count
        deviceIoPendingUnverified = $pendingUnverified.Count
        cpuManifest = if ($cpuManifest.Count -gt 0) { [string]$cpuManifest[0].action } else { 'NOT_OBSERVED' }
        cpuHooksInstalled = $cpuInstalled.Count
        networkCleanEvents = @($session | Where-Object {
            $_.action -in @('cleaned', 'clean-none')
        }).Count
    }
}

$partialReasons = New-Object System.Collections.Generic.List[string]
if ($notImported.Count -gt 0) { $partialReasons.Add("api-not-imported:$($notImported.Count)") }
if ($wmiInstall.Count -eq 0) { $partialReasons.Add('wmi-wrapper-not-observed') }
if ($wmiObserved.Count -eq 0) { $partialReasons.Add('wmi-call-not-observed') }
if ($wmiAsync.Count -eq 0) { $partialReasons.Add('wmi-async-not-observed') }
if ($pendingEvents.Count -eq 0) { $partialReasons.Add('deviceio-pending-not-observed') }
if ($pendingUnverified.Count -gt 0) {
    $partialReasons.Add("deviceio-pending-unverified:$($pendingUnverified.Count)")
}
if ($cpuManifest.Count -eq 0 -or [string]$cpuManifest[0].action -eq 'not-configured') {
    $partialReasons.Add('cpu-manifest-not-configured')
}

$failureReasons = New-Object System.Collections.Generic.List[string]
if (-not $ready) { $failureReasons.Add('native-bridge-not-ready') }
if ($failures.Count -gt 0) { $failureReasons.Add("api-install-failures:$($failures.Count)") }
if ($childFailed.Count -gt 0) { $failureReasons.Add("child-injection-failures:$($childFailed.Count)") }
if ($unwrappedWmi.Count -gt 0) { $failureReasons.Add("wmi-unwrapped:$($unwrappedWmi.Count)") }
$pass = $failureReasons.Count -eq 0
if ($RequireChild -and $childInjected.Count -eq 0) { $pass = $false }
if ($RequireCpuManifest -and $cpuInstalled.Count -eq 0) { $pass = $false }
if ($RequireRendererUtility -and
    (-not $processTypes.Contains('renderer') -or -not $processTypes.Contains('utility'))) { $pass = $false }
if (-not $pass -and $failureReasons.Count -eq 0) { $failureReasons.Add('required-evidence-missing') }
if ($Strict) {
    foreach ($reason in $partialReasons) { $failureReasons.Add("strict:$reason") }
}
$result.status = if ($failureReasons.Count -gt 0) { 'FAIL' } elseif ($partialReasons.Count -gt 0) { 'PARTIAL' } else { 'PASS' }
$result.result = $result.status
$result.strict = [bool]$Strict
$result.partialReasons = @($partialReasons)
$result.failureReasons = @($failureReasons)
$result.note = 'This is current-session userland evidence. It does not prove kernel, NDIS/WFP, DPAPI, or physical hardware isolation.'

New-Item -ItemType Directory -Path (Split-Path -Parent $outputPath) -Force | Out-Null
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $outputPath -Encoding UTF8
$result | ConvertTo-Json -Depth 10
Write-Host "Evidence: $outputPath" -ForegroundColor DarkGray
if ($result.status -eq 'FAIL') {
    Write-Host ("[FAIL] Desktop NativeBridge session failed: {0}" -f ($failureReasons -join ', ')) -ForegroundColor Red
    exit 1
}
if ($result.status -eq 'PARTIAL' -and -not $AllowPartial) {
    Write-Host ("[PARTIAL] Desktop NativeBridge evidence is incomplete: {0}" -f ($partialReasons -join ', ')) -ForegroundColor Yellow
    exit 1
}
if ($result.status -eq 'PARTIAL') {
    Write-Host ("[PARTIAL] Desktop NativeBridge evidence is incomplete (allowed): {0}" -f ($partialReasons -join ', ')) -ForegroundColor Yellow
    exit 0
}
Write-Host "[PASS] Desktop NativeBridge session is complete for $Profile" -ForegroundColor Green
