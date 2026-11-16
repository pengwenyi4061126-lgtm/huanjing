#requires -Version 5.1
<#
  CacMacLwf soak harness.

  Run on an isolated test machine with test signing enabled and the filter
  installed/bound. The host service is DISABLED by default; this script
  refuses to run until the operator explicitly enables it.

  Output: evidence/soak-<timestamp>/soak.jsonl + summary.json
#>
[CmdletBinding()]
param(
    [string]$AdapterName,
    [string]$Mac = '02:11:22:33:44:55',
    [int]$DisableEnableCycles = 30,
    [int]$RestartCycles = 10,
    [int]$SleepCycles = 0,
    [int]$TrafficSeconds = 7200,
    [int]$ConcurrentTcp = 100,
    [string]$TrafficTarget,
    [switch]$SkipTraffic,
    [switch]$RecordBoot,
    [switch]$AllowDisabled,
    [switch]$DryRun,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$ctl = Join-Path $root 'bin\cac-macctl.exe'
$component = 'CacMacLwf'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutputDir) {
    $OutputDir = Join-Path $root "evidence\soak-$stamp"
}
$logPath = Join-Path $OutputDir 'soak.jsonl'
$summaryPath = Join-Path $OutputDir 'summary.json'
$startUtc = (Get-Date).ToUniversalTime()
$failures = New-Object System.Collections.Generic.List[string]

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges are required for the soak harness.'
    }
}

function Write-Record {
    param([hashtable]$Record)
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    $Record['utc'] = (Get-Date).ToUniversalTime().ToString('o')
    $line = ($Record | ConvertTo-Json -Compress -Depth 6)
    [System.IO.File]::AppendAllText(
        $logPath, $line + [Environment]::NewLine,
        (New-Object System.Text.UTF8Encoding($false)))
}

function Get-MacState {
    $raw = & $ctl state 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "cac-macctl state failed: $($raw -join ' ')"
    }
    return ($raw | Out-String | ConvertFrom-Json)
}

function Get-DumpSet {
    return @(Get-ChildItem -LiteralPath "$env:SystemRoot\Minidump" -Filter '*.dmp' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name)
}

function Get-BugCheckEvents {
    param([datetime]$SinceUtc)
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001 } -MaxEvents 20 -ErrorAction Stop |
            Where-Object { $_.TimeCreated.ToUniversalTime() -ge $SinceUtc })
    } catch {
        return @()
    }
}

function Invoke-OidStorm {
    param([int]$Iterations = 20)
    for ($i = 0; $i -lt $Iterations; $i++) {
        [void][System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        [void](Get-CimInstance Win32_NetworkAdapter -Property Name, MacAddress -ErrorAction SilentlyContinue)
        [void](& getmac.exe /fo csv 2>$null)
        [void](& ipconfig.exe /all 2>$null)
    }
}

function Invoke-Traffic {
    param([int]$Seconds, [string]$Target)
    if ($Seconds -le 0) { return }
    $gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1).NextHop
    if (-not $gateway) { $gateway = '127.0.0.1' }
    $ping = Start-Process -FilePath 'ping.exe' -ArgumentList @('-t', $gateway) -PassThru -WindowStyle Hidden
    $clients = @()
    try {
        if ($Target -and $ConcurrentTcp -gt 0) {
            $parts = $Target.Split(':')
            $hostName = $parts[0]
            $port = if ($parts.Count -gt 1) { [int]$parts[1] } else { 443 }
            for ($i = 0; $i -lt $ConcurrentTcp; $i++) {
                try {
                    $client = New-Object System.Net.Sockets.TcpClient
                    $async = $client.BeginConnect($hostName, $port, $null, $null)
                    $clients += [pscustomobject]@{ Client = $client; Async = $async }
                } catch { }
            }
        }
        Write-Record @{
            phase = 'traffic'; action = 'start'; seconds = $Seconds;
            gateway = $gateway; target = $Target; tcpClients = $clients.Count
        }
        Start-Sleep -Seconds $Seconds
        Invoke-OidStorm -Iterations 10
    } finally {
        foreach ($item in $clients) {
            try { $item.Client.Close() } catch { }
        }
        if ($ping -and -not $ping.HasExited) {
            Stop-Process -Id $ping.Id -Force -ErrorAction SilentlyContinue
        }
        Write-Record @{ phase = 'traffic'; action = 'stop' }
    }
}

function Restore-Adapter {
    param([string]$Name)
    if (-not $Name) { return }
    $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
    if ($adapter -and $adapter.Status -ne 'Up') {
        Enable-NetAdapter -Name $Name -Confirm:$false -ErrorAction SilentlyContinue
    }
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $ctl -PathType Leaf)) {
    throw "cac-macctl.exe not found: $ctl"
}

$service = Get-Service -Name $component -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Service $component not installed."
}
if ($service.StartType -eq 'Disabled' -and -not $AllowDisabled -and -not $DryRun) {
    throw "Service $component is DISABLED. Enable it on the isolated test machine first, or pass -AllowDisabled."
}
if ($service.Status -ne 'Running' -and -not $DryRun) {
    Start-Service -Name $component
    Start-Sleep -Seconds 3
    Write-Record @{ phase = 'setup'; action = 'service-start'; state = (Get-MacState) }
}

$binding = @(Get-NetAdapterBinding -ComponentID $component -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled })
if (-not $AdapterName) {
    $AdapterName = ($binding | Select-Object -First 1 -ExpandProperty Name)
}
if (-not $AdapterName) {
    if ($DryRun) {
        $AdapterName = '(unbound)'
    } else {
        throw "No adapter is bound to $component."
    }
}
if (-not $DryRun) {
    $adapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop
}

if ($DryRun) {
    $plan = [ordered]@{
        adapter = $AdapterName
        mac = $Mac
        serviceState = $service.Status.ToString()
        serviceStartMode = $service.StartType.ToString()
        disableEnableCycles = $DisableEnableCycles
        restartCycles = $RestartCycles
        sleepCycles = $SleepCycles
        trafficSeconds = $TrafficSeconds
        concurrentTcp = $ConcurrentTcp
        outputDir = $OutputDir
    }
    Write-Output ($plan | ConvertTo-Json -Depth 4)
    return
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$baselineDumps = Get-DumpSet
$baselineBugChecks = Get-BugCheckEvents -SinceUtc $startUtc
$baseline = Get-MacState

Write-Record @{
    phase = 'baseline'; adapter = $AdapterName; mac = $Mac;
    state = $baseline; dumpCount = $baselineDumps.Count;
    bugCheckCount = $baselineBugChecks.Count;
    serviceState = $service.Status.ToString(); serviceStartMode = $service.StartType.ToString()
}

if ($RecordBoot) {
    Write-Record @{ phase = 'boot'; action = 'recorded'; adapter = $AdapterName; state = (Get-MacState) }
    Write-Output "Boot event recorded: $logPath"
    return
}

try {
    & $ctl set --mac $Mac | Out-Null
    Write-Record @{ phase = 'setup'; action = 'mac-set'; mac = $Mac; state = (Get-MacState) }

    for ($i = 1; $i -le $DisableEnableCycles; $i++) {
        try {
            Disable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 2
            Enable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 4
            $state = Get-MacState
            Write-Record @{ phase = 'disable-enable'; cycle = $i; ok = $true; state = $state }
        } catch {
            $failures.Add("disable-enable ${i}: $($_.Exception.Message)")
            Write-Record @{ phase = 'disable-enable'; cycle = $i; ok = $false; error = $_.Exception.Message }
            Restore-Adapter -Name $AdapterName
        }
    }

    for ($i = 1; $i -le $RestartCycles; $i++) {
        try {
            Restart-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 5
            $state = Get-MacState
            Write-Record @{ phase = 'restart'; cycle = $i; ok = $true; state = $state }
        } catch {
            $failures.Add("restart ${i}: $($_.Exception.Message)")
            Write-Record @{ phase = 'restart'; cycle = $i; ok = $false; error = $_.Exception.Message }
            Restore-Adapter -Name $AdapterName
        }
    }

    for ($i = 1; $i -le $SleepCycles; $i++) {
        try {
            Write-Record @{ phase = 'sleep'; cycle = $i; action = 'suspend' }
            & rundll32.exe powrprof.dll,SetSuspendState 0,1,0
            Start-Sleep -Seconds 10
            $state = Get-MacState
            Write-Record @{ phase = 'sleep'; cycle = $i; action = 'resumed'; state = $state }
        } catch {
            $failures.Add("sleep ${i}: $($_.Exception.Message)")
            Write-Record @{ phase = 'sleep'; cycle = $i; ok = $false; error = $_.Exception.Message }
        }
    }

    $beforeOid = Get-MacState
    Invoke-OidStorm -Iterations 50
    $afterOid = Get-MacState
    Write-Record @{
        phase = 'oid-storm'; before = $beforeOid; after = $afterOid;
        oidDelta = ([int64]$afterOid.oidQueriesSeen - [int64]$beforeOid.oidQueriesSeen)
    }

    if (-not $SkipTraffic) {
        Invoke-Traffic -Seconds $TrafficSeconds -Target $TrafficTarget
    }

    $finalDumps = Get-DumpSet
    $newDumps = @($finalDumps | Where-Object { $_ -notin $baselineDumps })
    $newBugChecks = @(Get-BugCheckEvents -SinceUtc $startUtc)
    $finalState = Get-MacState
    $pass = ($newDumps.Count -eq 0) -and ($newBugChecks.Count -eq 0) -and ($failures.Count -eq 0)

    $summary = [ordered]@{
        schema = 1
        pass = $pass
        adapter = $AdapterName
        mac = $Mac
        startedUtc = $startUtc.ToString('o')
        finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
        cycles = [ordered]@{
            disableEnable = $DisableEnableCycles
            restart = $RestartCycles
            sleep = $SleepCycles
            trafficSeconds = $TrafficSeconds
        }
        baseline = $baseline
        final = $finalState
        newDumps = $newDumps
        newBugChecks = $newBugChecks.Count
        failures = $failures
        log = $logPath
    }
    $summary | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-Record @{ phase = 'summary'; pass = $pass; newDumps = $newDumps.Count;
        newBugChecks = $newBugChecks.Count; failures = $failures.Count }
    Write-Output ($summary | ConvertTo-Json -Depth 8)
    if (-not $pass) { exit 1 }
} finally {
    Restore-Adapter -Name $AdapterName
}
