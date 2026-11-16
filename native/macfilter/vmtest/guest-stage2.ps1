$ErrorActionPreference = 'Stop'
Set-Location 'C:\cacmac'
Start-Transcript -Path 'C:\cacmac\stage2.log' -Append

$runOnce = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
$stage2Cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\cacmac\guest-stage2.ps1"'
$soakCmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\cacmac\guest-soak.ps1"'

$bcd = (bcdedit /enum '{current}' 2>&1 | Out-String)
if ($bcd -notmatch '(?im)^\s*testsigning\s+Yes\s*$') {
    bcdedit /set testsigning on | Out-Null
    Set-ItemProperty -Path $runOnce -Name 'CacMacLwfStage2' -Value $stage2Cmd -Force
    Write-Output 'testsigning-on; rebooting'
    Stop-Transcript
    shutdown /r /t 5 /c 'CacMacLwf testsigning enable'
    exit 0
}

& (Join-Path $PWD 'install-macfilter.ps1') -Enable
Set-ItemProperty -Path $runOnce -Name 'CacMacLwfSoak' -Value $soakCmd -Force
Write-Output 'install-complete; rebooting for binding'
Stop-Transcript
shutdown /r /t 5 /c 'CacMacLwf binding activation'
