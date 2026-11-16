$ErrorActionPreference = 'Continue'
Start-Sleep -Seconds 30
Set-Location 'C:\cacmac'
Start-Transcript -Path 'C:\cacmac\soak.log' -Append

$share = '\\vmware-host\Shared Folders\cacvm'
$evidence = Join-Path $share 'evidence'
$logDir = Join-Path $share 'guest-logs'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

try {
    & (Join-Path $PWD 'run-macfilter-soak.ps1') `
        -AdapterName 'Ethernet0' `
        -Mac '02:11:22:33:44:55' `
        -DisableEnableCycles 3 `
        -RestartCycles 2 `
        -SleepCycles 0 `
        -TrafficSeconds 0 `
        -ConcurrentTcp 0 `
        -SkipTraffic
    & (Join-Path $PWD 'run-macfilter-fault.ps1') -OidStormIterations 5
} catch {
    $_ | Out-String | Add-Content -LiteralPath 'C:\cacmac\soak-error.log'
}

Copy-Item -Path 'C:\cacmac\evidence\*' -Destination $evidence -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path 'C:\cacmac\*.log' -Destination $logDir -Force -ErrorAction SilentlyContinue
Stop-Transcript
