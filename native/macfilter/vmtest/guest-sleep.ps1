$ErrorActionPreference = 'Continue'
Set-Location 'C:\cacmac'

for ($i = 1; $i -le 3; $i++) {
    Start-Transcript -Path "C:\cacmac\sleep-$i.log" -Append
    & (Join-Path $PWD 'run-macfilter-soak.ps1') `
        -AdapterName 'Ethernet0' `
        -Mac '02:11:22:33:44:55' `
        -OutputDir "C:\cacmac\evidence\sleep-$i" `
        -DisableEnableCycles 0 `
        -RestartCycles 0 `
        -SleepCycles 1 `
        -TrafficSeconds 0 `
        -SkipTraffic
    Stop-Transcript
}

$share = '\\vmware-host\Shared Folders\cacvm'
Copy-Item -Path 'C:\cacmac\evidence\*' -Destination (Join-Path $share 'evidence') -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path 'C:\cacmac\sleep-*.log' -Destination (Join-Path $share 'guest-logs') -Force -ErrorAction SilentlyContinue
