# Verify the latest NativeBridge session recorded for one Claude Desktop Profile.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$Profile,
    [switch]$RequireChild,
    [switch]$RequireCpuManifest,
    [switch]$RequireRendererUtility,
    [switch]$RequireKernel,
    [switch]$RequireWfp,
    [switch]$Strict,
    [switch]$AllowPartial
)

$ErrorActionPreference = 'Stop'
$root = Join-Path (Join-Path $env:USERPROFILE '.cac\desktop') $Profile
$auditPath = Join-Path $root 'audit\native-hook.jsonl'
$outputPath = Join-Path $root 'audit\desktop-native-check.json'

function Get-ProcessMetadata {
    param([int[]]$ProcessIds)

    $uniquePids = New-Object 'System.Collections.Generic.List[int]'
    foreach ($value in @($ProcessIds)) {
        $processIdValue = 0
        if ([int]::TryParse([string]$value, [ref]$processIdValue) -and $processIdValue -gt 0 -and
            -not $uniquePids.Contains($processIdValue)) {
            [void]$uniquePids.Add($processIdValue)
        }
    }

    $snapshot = @()
    try {
        $snapshot = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    } catch {
        try {
            $snapshot = @(Get-WmiObject -Class Win32_Process -ErrorAction Stop)
        } catch {
            $snapshot = @()
        }
    }

    $byPid = @{}
    foreach ($row in $snapshot) {
        $processIdValue = 0
        if (-not [int]::TryParse([string]$row.ProcessId, [ref]$processIdValue) -or
            $processIdValue -le 0 -or -not $uniquePids.Contains($processIdValue)) {
            continue
        }

        $executablePath = [string]$row.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($executablePath)) {
            try {
                $executablePath = [string](Get-Process -Id $processIdValue -ErrorAction Stop).Path
            } catch {
                $executablePath = $null
            }
        }

        $parentPid = $null
        $parsedParentPid = 0
        if ([int]::TryParse([string]$row.ParentProcessId, [ref]$parsedParentPid)) {
            $parentPid = $parsedParentPid
        }
        $byPid[$processIdValue] = [pscustomobject][ordered]@{
            pid             = $processIdValue
            observed        = $true
            parentProcessId = $parentPid
            executablePath  = $executablePath
            commandLine     = [string]$row.CommandLine
            processType     = $null
        }
    }

    $result = New-Object 'System.Collections.Generic.List[object]'
    foreach ($processIdValue in $uniquePids) {
        if ($byPid.ContainsKey($processIdValue)) {
            [void]$result.Add($byPid[$processIdValue])
        } else {
            [void]$result.Add([pscustomobject][ordered]@{
                pid             = [int]$processIdValue
                observed        = $false
                parentProcessId = $null
                executablePath  = $null
                commandLine     = $null
                processType     = $null
            })
        }
    }
    return $result.ToArray()
}

function Get-ConfiguredDesktopProxy {
    param(
        [string]$ProfileRoot,
        [string]$ProfileName
    )

    $profileProxyPath = Join-Path $ProfileRoot 'proxy'
    if (Test-Path -LiteralPath $profileProxyPath -PathType Leaf) {
        $profileProxy = (Get-Content -LiteralPath $profileProxyPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($profileProxy)) {
            return [pscustomobject][ordered]@{
                configured = $true
                source     = 'profile'
                proxyId    = $null
            }
        }
    }

    $poolPath = [Environment]::GetEnvironmentVariable('CAC_PROXY_POOL_PATH', 'Process')
    if ([string]::IsNullOrWhiteSpace($poolPath)) {
        $poolPath = Join-Path $env:USERPROFILE '.cac\proxy-pool.json'
    }
    if (Test-Path -LiteralPath $poolPath -PathType Leaf) {
        try {
            $pool = Get-Content -LiteralPath $poolPath -Raw | ConvertFrom-Json
            $accountKey = 'desktop:' + $ProfileName
            $binding = @($pool.bindings | Where-Object {
                [string]$_.accountKey -ieq $accountKey
            } | Select-Object -First 1)[0]
            if ($null -ne $binding) {
                $proxy = @($pool.proxies | Where-Object {
                    [string]$_.id -eq [string]$binding.proxyId
                } | Select-Object -First 1)[0]
                if ($null -ne $proxy -and [bool]$proxy.enabled) {
                    return [pscustomobject][ordered]@{
                        configured = $true
                        source     = 'pool'
                        proxyId    = [string]$proxy.id
                    }
                }
            }
        } catch {
            # A malformed optional pool is reported as not configured here;
            # the launcher remains responsible for rejecting it at startup.
        }
    }

    return [pscustomobject][ordered]@{
        configured = $false
        source     = 'none'
        proxyId    = $null
    }
}

function Test-CommandLineValue {
    param(
        [string]$CommandLine,
        [string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    $normalized = $CommandLine.Replace('"', '')
    return $normalized.IndexOf($Value, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-CommandLineSwitchValue {
    param(
        [string]$CommandLine,
        [string]$SwitchName
    )
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $normalized = $CommandLine.Replace('"', '')
    $pattern = '(?i)(?:^|\s)' + [regex]::Escape($SwitchName) + '=(\S+)'
    $match = [regex]::Match($normalized, $pattern)
    if (-not $match.Success) { return $null }
    return $match.Groups[1].Value
}

function Test-LocalProxyValue {
    param([string]$ProxyValue)
    if ([string]::IsNullOrWhiteSpace($ProxyValue)) { return $false }
    return $ProxyValue -match '(?i)^(?:(?:https?|socks5h?)://)?(?:127\.0\.0\.1|localhost|\[::1\]):\d+$'
}

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
$kernelVerified = @($session | Where-Object {
    $_.surface -eq 'kernel.policy' -and $_.action -eq 'verified'
}).Count -gt 0
$kernelFailures = @($session | Where-Object {
    $_.surface -eq 'kernel.policy' -and $_.action -match 'failed|unavailable'
})
$wfpInstalled = @($session | Where-Object {
    $_.surface -eq 'wfp.policy' -and $_.action -eq 'installed'
})
$wfpFailures = @($session | Where-Object {
    $_.surface -eq 'wfp.policy' -and $_.action -eq 'failed'
})
$networkMode = 'profile'
$networkModePath = Join-Path $root 'network_mode'
if (Test-Path -LiteralPath $networkModePath -PathType Leaf) {
    $configuredMode = (Get-Content -LiteralPath $networkModePath -Raw).Trim().ToLowerInvariant()
    if ($configuredMode) { $networkMode = $configuredMode }
}
$ready = @($session | Where-Object { $_.surface -eq 'native.bridge' -and $_.action -eq 'ready' }).Count -gt 0

$processTypeByPid = @{}
foreach ($event in $attachEvents) {
    $eventPid = 0
    if (-not [int]::TryParse([string]$event.pid, [ref]$eventPid) -or $eventPid -le 0) {
        continue
    }
    $processType = 'unknown'
    if ([string]$event.detail -match 'process=([^, ]+)') { $processType = $matches[1] }
    $processTypeByPid[$eventPid] = $processType
}
if ($null -eq $rootPid) {
    $mainAttach = @($attachEvents | Where-Object {
        [string]$processTypeByPid[[int]$_.pid] -eq 'main'
    } | Select-Object -Last 1)[0]
    if ($null -ne $mainAttach) { $rootPid = [uint32]$mainAttach.pid }
}

$knownPids = New-Object 'System.Collections.Generic.List[int]'
foreach ($event in $attachEvents) {
    $eventPid = 0
    if ([int]::TryParse([string]$event.pid, [ref]$eventPid) -and $eventPid -gt 0 -and
        -not $knownPids.Contains($eventPid)) {
        [void]$knownPids.Add($eventPid)
    }
}
foreach ($event in $children) {
    foreach ($value in @($event.pid, $event.value)) {
        $eventPid = 0
        if ([int]::TryParse([string]$value, [ref]$eventPid) -and $eventPid -gt 0 -and
            -not $knownPids.Contains($eventPid)) {
            [void]$knownPids.Add($eventPid)
        }
    }
}

$processMetadata = @(Get-ProcessMetadata -ProcessIds @($knownPids))
foreach ($row in $processMetadata) {
    $row.processType = if ($processTypeByPid.ContainsKey([int]$row.pid)) {
        [string]$processTypeByPid[[int]$row.pid]
    } else {
        'child'
    }
}

$expectedUserDataDir = Join-Path (Join-Path $root 'home\AppData\Roaming') 'Claude'
$proxyConfiguration = Get-ConfiguredDesktopProxy -ProfileRoot $root -ProfileName $Profile
$processPartialReasons = New-Object 'System.Collections.Generic.List[string]'
$processFailureReasons = New-Object 'System.Collections.Generic.List[string]'
$metadataObserved = @($processMetadata | Where-Object { [bool]$_.observed })
$metadataMissing = @($processMetadata | Where-Object { -not [bool]$_.observed })
$profileArgumentObserved = 0
$profileArgumentMismatches = New-Object 'System.Collections.Generic.List[object]'
$proxyArgumentObserved = 0
$proxyArgumentMissing = New-Object 'System.Collections.Generic.List[int]'
$proxyArgumentInvalid = New-Object 'System.Collections.Generic.List[object]'
$proxySwitchesMissing = New-Object 'System.Collections.Generic.List[object]'
$chromiumArgumentMissing = New-Object 'System.Collections.Generic.List[object]'
$parentProcessIdObserved = 0
$executablePathObserved = 0
$commandLineObserved = 0

foreach ($row in $metadataMissing) {
    [void]$processPartialReasons.Add("process-not-observed:$($row.pid)")
}
foreach ($row in $metadataObserved) {
    if ($null -ne $row.parentProcessId) { $parentProcessIdObserved++ }
    else { [void]$processPartialReasons.Add("parent-process-id-not-observed:$($row.pid)") }
    if (-not [string]::IsNullOrWhiteSpace([string]$row.executablePath)) { $executablePathObserved++ }
    else { [void]$processPartialReasons.Add("executable-path-not-observed:$($row.pid)") }

    $commandLine = [string]$row.commandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) {
        [void]$processPartialReasons.Add("command-line-not-observed:$($row.pid)")
        continue
    }
    $commandLineObserved++

    $profileArgument = '--user-data-dir=' + $expectedUserDataDir
    if (Test-CommandLineValue -CommandLine $commandLine -Value $profileArgument) {
        $profileArgumentObserved++
    } else {
        [void]$profileArgumentMismatches.Add([ordered]@{
            pid = [int]$row.pid
            expected = $profileArgument
        })
        [void]$processFailureReasons.Add("profile-argument-mismatch:$($row.pid)")
    }

    $proxyValue = Get-CommandLineSwitchValue -CommandLine $commandLine -SwitchName '--proxy-server'
    if ($null -ne $proxyValue) {
        $proxyArgumentObserved++
        if (-not (Test-LocalProxyValue -ProxyValue $proxyValue)) {
            [void]$proxyArgumentInvalid.Add([ordered]@{
                pid = [int]$row.pid
                value = $proxyValue
            })
            [void]$processFailureReasons.Add("proxy-argument-not-local:$($row.pid)")
        }
    } elseif ($proxyConfiguration.configured) {
        [void]$proxyArgumentMissing.Add([int]$row.pid)
        [void]$processFailureReasons.Add("proxy-argument-missing:$($row.pid)")
    }

    if ($proxyConfiguration.configured) {
        foreach ($requiredProxySwitch in @(
            '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1, EXCLUDE ::1',
            '--disable-quic',
            '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--proxy-bypass-list=localhost;127.0.0.1;[::1]'
        )) {
            if (-not (Test-CommandLineValue -CommandLine $commandLine -Value $requiredProxySwitch)) {
                [void]$proxySwitchesMissing.Add([ordered]@{
                    pid = [int]$row.pid
                    expected = $requiredProxySwitch
                })
                [void]$processFailureReasons.Add("proxy-switch-missing:$($row.pid)")
            }
        }
    }

    $isMain = ([int]$row.pid -eq [int]$rootPid) -or ([string]$row.processType -eq 'main')
    if ($isMain -and $attachEvents.Count -gt 0) {
        foreach ($requiredChromiumSwitch in @('--no-sandbox', '--disable-gpu-sandbox')) {
            if (-not (Test-CommandLineValue -CommandLine $commandLine -Value $requiredChromiumSwitch)) {
                [void]$chromiumArgumentMissing.Add([ordered]@{
                    pid = [int]$row.pid
                    expected = $requiredChromiumSwitch
                })
                [void]$processFailureReasons.Add("chromium-switch-missing:$($row.pid)")
            }
        }
    }

    $expectedType = [string]$row.processType
    if ($expectedType -in @('renderer', 'utility', 'gpu-process', 'crashpad-handler') -and
        -not (Test-CommandLineValue -CommandLine $commandLine -Value ('--type=' + $expectedType))) {
        [void]$chromiumArgumentMissing.Add([ordered]@{
            pid = [int]$row.pid
            expected = '--type=' + $expectedType
        })
        [void]$processFailureReasons.Add("chromium-type-mismatch:$($row.pid)")
    }
}

$processAssertionStatus = if ($processFailureReasons.Count -gt 0) {
    'FAIL'
} elseif ($processPartialReasons.Count -gt 0) {
    'PARTIAL'
} else {
    'PASS'
}
$processAssertions = [ordered]@{
    status = $processAssertionStatus
    knownPidCount = $processMetadata.Count
    observedPidCount = $metadataObserved.Count
    missingPidCount = $metadataMissing.Count
    parentProcessIdObserved = $parentProcessIdObserved
    executablePathObserved = $executablePathObserved
    commandLineObserved = $commandLineObserved
    profile = [ordered]@{
        expectedUserDataDir = $expectedUserDataDir
        argumentObserved = $profileArgumentObserved
        mismatches = $profileArgumentMismatches.ToArray()
    }
    proxy = [ordered]@{
        configured = [bool]$proxyConfiguration.configured
        source = [string]$proxyConfiguration.source
        argumentObserved = $proxyArgumentObserved
        missing = $proxyArgumentMissing.ToArray()
        invalid = $proxyArgumentInvalid.ToArray()
        missingRelaySwitches = $proxySwitchesMissing.ToArray()
    }
    chromium = [ordered]@{
        nativeFlagsRequired = [bool]($attachEvents.Count -gt 0)
        missing = $chromiumArgumentMissing.ToArray()
    }
}

$result = [ordered]@{
    schema = 2
    checkedUtc = [DateTime]::UtcNow.ToString('o')
    profile = $Profile
    auditPath = $auditPath
    sessionStart = $session[0].utc
    rootPid = $rootPid
    processMetadata = @($processMetadata | ForEach-Object {
        [ordered]@{
            pid = [int]$_.pid
            processType = [string]$_.processType
            observed = [bool]$_.observed
            parentProcessId = $_.parentProcessId
            executablePath = $_.executablePath
            commandLine = $_.commandLine
        }
    })
    processAssertions = $processAssertions
    session = [ordered]@{
        ready = $ready
        processes = @($attachEvents |
            Select-Object -ExpandProperty pid -Unique)
        processMetadataObserved = $metadataObserved.Count
        processMetadataMissing = $metadataMissing.Count
        profileArgumentObserved = $profileArgumentObserved
        proxyArgumentObserved = $proxyArgumentObserved
        chromiumArgumentFailures = $chromiumArgumentMissing.Count
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
        kernelPolicyVerified = $kernelVerified
        kernelPolicyFailures = $kernelFailures.Count
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
        networkMode = $networkMode
        wfpInstalled = $wfpInstalled.Count
        wfpFailures = $wfpFailures.Count
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
foreach ($reason in @($processPartialReasons | ForEach-Object { [string]$_ })) {
    [void]$partialReasons.Add($reason)
}

$failureReasons = New-Object System.Collections.Generic.List[string]
if (-not $ready) { $failureReasons.Add('native-bridge-not-ready') }
if ($failures.Count -gt 0) { $failureReasons.Add("api-install-failures:$($failures.Count)") }
if ($childFailed.Count -gt 0) { $failureReasons.Add("child-injection-failures:$($childFailed.Count)") }
if ($unwrappedWmi.Count -gt 0) { $failureReasons.Add("wmi-unwrapped:$($unwrappedWmi.Count)") }
foreach ($reason in @($processFailureReasons | ForEach-Object { [string]$_ })) {
    [void]$failureReasons.Add($reason)
}
$pass = $failureReasons.Count -eq 0
if ($RequireChild -and $childInjected.Count -eq 0) { $pass = $false }
if ($RequireCpuManifest -and $cpuInstalled.Count -eq 0) { $pass = $false }
if ($RequireRendererUtility -and
    (-not $processTypes.Contains('renderer') -or -not $processTypes.Contains('utility'))) { $pass = $false }
if ($RequireKernel -and -not $kernelVerified) {
    $pass = $false
    $failureReasons.Add('kernel-policy-not-verified')
}
if ($RequireWfp -and $wfpInstalled.Count -eq 0) {
    $pass = $false
    $failureReasons.Add('wfp-policy-not-installed')
}
if ($networkMode -eq 'enforce' -and $wfpInstalled.Count -eq 0) {
    $pass = $false
    $failureReasons.Add('wfp-enforce-not-installed')
}
if ($wfpFailures.Count -gt 0) { $pass = $false; $failureReasons.Add("wfp-install-failures:$($wfpFailures.Count)") }
if (-not $pass -and $failureReasons.Count -eq 0) { $failureReasons.Add('required-evidence-missing') }
if ($Strict) {
    foreach ($reason in $partialReasons) { $failureReasons.Add("strict:$reason") }
}
$result.status = if ($failureReasons.Count -gt 0) { 'FAIL' } elseif ($partialReasons.Count -gt 0) { 'PARTIAL' } else { 'PASS' }
$result.result = $result.status
$result.strict = [bool]$Strict
$result.partialReasons = @($partialReasons)
$result.failureReasons = @($failureReasons)
$result.note = 'This is current-session evidence. kernel.policy is the signed control-plane registration; wfp.policy is a dynamic app-image outbound boundary. Neither proves NDIS, DPAPI, or physical hardware virtualization.'

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
