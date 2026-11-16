$ErrorActionPreference = 'Continue'
$user = 'caclow'
$pass = 'CacLow!2026'

if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
    net user $user $pass /add | Out-Null
}

$secure = ConvertTo-SecureString $pass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $secure)

Set-Location 'C:\cacmac'
& (Join-Path $PWD 'run-macfilter-fault.ps1') `
    -LowPrivCredential $cred `
    -SkipInvalidIoctl `
    -OidStormIterations 1

$share = '\\vmware-host\Shared Folders\cacvm'
Copy-Item -Path 'C:\cacmac\evidence\*' -Destination (Join-Path $share 'evidence') -Recurse -Force -ErrorAction SilentlyContinue
