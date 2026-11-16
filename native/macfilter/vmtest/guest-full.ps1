$ErrorActionPreference = 'Continue'
Set-Location 'C:\cacmac'
Start-Transcript -Path 'C:\cacmac\full.log' -Append

try {
    & (Join-Path $PWD 'run-macfilter-soak.ps1') `
        -AdapterName 'Ethernet0' `
        -Mac '02:11:22:33:44:55' `
        -DisableEnableCycles 30 `
        -RestartCycles 10 `
        -SleepCycles 0 `
        -TrafficSeconds 7200 `
        -ConcurrentTcp 100 `
        -TrafficTarget '192.168.174.2:443'
} catch {
    $_ | Out-String | Add-Content -LiteralPath 'C:\cacmac\full-error.log'
}

$share = '\\vmware-host\Shared Folders\cacvm'
Copy-Item -Path 'C:\cacmac\evidence\*' -Destination (Join-Path $share 'evidence') -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path 'C:\cacmac\full.log' -Destination (Join-Path $share 'guest-logs') -Force -ErrorAction SilentlyContinue
Stop-Transcript
