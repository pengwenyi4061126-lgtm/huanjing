$ErrorActionPreference = 'Continue'
$countPath = 'C:\cacmac\boot-count.txt'
$count = 0
if (Test-Path -LiteralPath $countPath) {
    $count = [int]((Get-Content -LiteralPath $countPath -Raw).Trim())
}
$count++
Set-Content -LiteralPath $countPath -Value $count -Encoding ASCII

Set-Location 'C:\cacmac'
Start-Transcript -Path 'C:\cacmac\boot.log' -Append
& (Join-Path $PWD 'run-macfilter-soak.ps1') `
    -AdapterName 'Ethernet0' `
    -Mac '02:11:22:33:44:55' `
    -OutputDir "C:\cacmac\evidence\boot-$count" `
    -RecordBoot
Stop-Transcript

if ($count -lt 5) {
    $cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\cacmac\guest-boot.ps1"'
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' `
        -Name 'CacMacLwfBoot' -Value $cmd -Force
    shutdown /r /t 10 /c "CacMacLwf boot cycle $count"
} else {
    $share = '\\vmware-host\Shared Folders\cacvm'
    Copy-Item -Path 'C:\cacmac\evidence\*' -Destination (Join-Path $share 'evidence') -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path 'C:\cacmac\boot.log' -Destination (Join-Path $share 'guest-logs') -Force -ErrorAction SilentlyContinue
}
