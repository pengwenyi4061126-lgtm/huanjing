[CmdletBinding()]
param(
    [ValidateSet('development', 'unpacked', 'portable')]
    [string]$Mode = 'development'
)

$ErrorActionPreference = 'Stop'
$managerRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $managerRoot '..'))
$auditPath = Join-Path $env:LOCALAPPDATA 'CAC Account Manager\audit\native-manager.jsonl'
$package = Get-Content -LiteralPath (Join-Path $managerRoot 'package.json') -Raw | ConvertFrom-Json

switch ($Mode) {
    'development' {
        $target = Join-Path $managerRoot 'node_modules\electron\dist\electron.exe'
        $arguments = @('.')
        $workingDirectory = $managerRoot
        $managerImage = [System.IO.Path]::GetFullPath($target)
        $launcherImage = Join-Path $projectRoot 'native\dist\cac-native-launch.exe'
    }
    'unpacked' {
        $target = Join-Path $managerRoot 'dist\win-unpacked\CAC Account Manager.exe'
        $arguments = @()
        $workingDirectory = Split-Path -Parent $target
        $managerImage = [System.IO.Path]::GetFullPath($target)
        $launcherImage = Join-Path $managerRoot 'dist\win-unpacked\resources\cac-runtime\native\dist\cac-native-launch.exe'
    }
    'portable' {
        $target = Join-Path $managerRoot "dist\cac-account-manager-$($package.version)-x64-portable.exe"
        $arguments = @()
        $workingDirectory = Split-Path -Parent $target
        $managerImage = $null
        $launcherImage = $null
    }
}

if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
    throw "Bootstrap smoke target is missing: $target"
}
if ($launcherImage -and -not (Test-Path -LiteralPath $launcherImage -PathType Leaf)) {
    throw "Bootstrap smoke launcher is missing: $launcherImage"
}

function Test-CandidateProcess([object]$Process) {
    $image = [string]$Process.ExecutablePath
    if ($Mode -eq 'portable') {
        return $Process.Name -in @('CAC Account Manager.exe', 'cac-native-launch.exe') -or
            $image -eq [System.IO.Path]::GetFullPath($target)
    }
    return $image -eq $managerImage -or $image -eq [System.IO.Path]::GetFullPath($launcherImage)
}

$baseline = @(Get-CimInstance Win32_Process | Where-Object { Test-CandidateProcess $_ })
if ($baseline.Count -gt 0) {
    throw "Account Manager smoke requires no existing candidate processes: $(@($baseline.ProcessId) -join ',')"
}
$baselineIds = @($baseline.ProcessId)
Remove-Item -LiteralPath $auditPath -Force -ErrorAction SilentlyContinue

$startArgs = @{
    FilePath = $target
    WorkingDirectory = $workingDirectory
    WindowStyle = 'Hidden'
    PassThru = $true
}
if ($arguments.Count -gt 0) { $startArgs.ArgumentList = $arguments }
$bootstrap = Start-Process @startArgs

try {
    Start-Sleep -Seconds 10
    $processes = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ProcessId -notin $baselineIds -and (Test-CandidateProcess $_)
    })
    if ($processes.Count -lt 6) {
        throw "Bootstrap process tree is incomplete: observed=$($processes.Count), bootstrap=$($bootstrap.Id)"
    }

    $rows = @($processes | ForEach-Object {
        $type = 'main'
        if ([string]$_.CommandLine -match '--type=([^\s\"]+)') { $type = $matches[1] }
        [pscustomobject]@{
            pid = [int]$_.ProcessId
            parent = [int]$_.ParentProcessId
            name = [string]$_.Name
            path = [string]$_.ExecutablePath
            type = $type
            childSwitch = [bool]([string]$_.CommandLine -match '--cac-native-manager-child')
        }
    })
    $outer = @($rows | Where-Object { $_.type -eq 'main' -and -not $_.childSwitch -and $_.name -ne 'cac-native-launch.exe' })
    $launcher = @($rows | Where-Object { $_.name -eq 'cac-native-launch.exe' })
    $childMain = @($rows | Where-Object { $_.type -eq 'main' -and $_.childSwitch -and $_.name -ne 'cac-native-launch.exe' })
    $renderer = @($rows | Where-Object { $_.type -eq 'renderer' })
    $utility = @($rows | Where-Object { $_.type -eq 'utility' })
    $gpu = @($rows | Where-Object { $_.type -eq 'gpu-process' })
    if ($outer.Count -lt 1 -or $launcher.Count -ne 1 -or $childMain.Count -ne 1 -or
        $renderer.Count -lt 1 -or $utility.Count -lt 1 -or $gpu.Count -lt 1) {
        $detail = $rows | ConvertTo-Json -Compress -Depth 3
        throw "Bootstrap topology mismatch: outer=$($outer.Count), launcher=$($launcher.Count), childMain=$($childMain.Count), renderer=$($renderer.Count), utility=$($utility.Count), gpu=$($gpu.Count); rows=$detail"
    }
    if (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
        throw "Native manager audit is missing: $auditPath"
    }

    $injectedPids = @(@($childMain.pid) + @($renderer.pid) + @($utility.pid) + @($gpu.pid) | Select-Object -Unique)
    $events = @(Get-Content -LiteralPath $auditPath | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { $null }
    } | Where-Object { $null -ne $_ -and [int]$_.pid -in $injectedPids })
    $readyPids = @($events | Where-Object {
        $_.surface -eq 'native.bridge' -and $_.action -eq 'ready'
    } | ForEach-Object { [int]$_.pid } | Select-Object -Unique)
    $failed = @($events | Where-Object { $_.action -eq 'failed' })
    if ($failed.Count -gt 0) { throw "NativeBridge failure events were recorded: $($failed.Count)" }
    foreach ($processId in $injectedPids) {
        if ($processId -notin $readyPids) { throw "NativeBridge ready evidence is missing for PID $processId" }
    }

    $secondStarted = Get-Date
    $second = Start-Process @startArgs
    $secondTimeoutMs = if ($Mode -eq 'portable') { 45000 } else { 15000 }
    if (-not $second.WaitForExit($secondTimeoutMs)) {
        Stop-Process -Id $second.Id -Force -ErrorAction SilentlyContinue
        throw "Second Account Manager instance did not exit after the single-instance handoff within $secondTimeoutMs ms"
    }
    if ($second.ExitCode -ne 0) {
        throw "Second Account Manager instance exited with code $($second.ExitCode)"
    }

    [pscustomobject]@{
        status = 'PASS'
        mode = $Mode
        bootstrapPid = $bootstrap.Id
        processCount = $rows.Count
        outer = $outer.Count
        launcher = $launcher.Count
        childMain = $childMain.Count
        renderer = $renderer.Count
        utility = $utility.Count
        gpu = $gpu.Count
        nativeReady = $readyPids.Count
        secondInstanceExitCode = $second.ExitCode
        secondInstanceElapsedMs = [int]((Get-Date) - $secondStarted).TotalMilliseconds
        audit = $auditPath
    } | ConvertTo-Json -Depth 4
} finally {
    $current = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ProcessId -notin $baselineIds -and (Test-CandidateProcess $_)
    })
    $ids = @($current.ProcessId)
    $roots = @($current | Where-Object { $_.ParentProcessId -notin $ids } | Select-Object -ExpandProperty ProcessId)
    foreach ($root in $roots) {
        & taskkill.exe /PID $root /T /F 2>$null | Out-Null
    }
    Start-Sleep -Milliseconds 750
    $leftovers = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ProcessId -notin $baselineIds -and (Test-CandidateProcess $_)
    })
    foreach ($process in $leftovers) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
}
