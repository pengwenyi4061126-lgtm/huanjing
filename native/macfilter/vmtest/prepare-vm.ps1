[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,

    [Parameter(Mandatory = $true)]
    [SecureString]$GuestPassword,

    [string]$GuestUser = 'Administrator',
    [string]$GuestNic = 'Ethernet0',
    [string]$ResultPath = (Join-Path $PSScriptRoot 'vm-prepare-result.json'),
    [switch]$RebootAfterPrepare
)

$ErrorActionPreference = 'Stop'

function Get-VmrunPath {
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $candidate = Join-Path $programFilesX86 'VMware\VMware Workstation\vmrun.exe'
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }

    $command = Get-Command vmrun.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw 'vmrun.exe was not found.'
}

function Invoke-Vmrun {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & $script:Vmrun @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "vmrun failed ($LASTEXITCODE): $($output -join ' ')"
    }
    return ($output -join [Environment]::NewLine).Trim()
}

function Convert-SecureStringToPlainText {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Value
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

if (-not (Test-Path -LiteralPath $VmxPath)) {
    throw "VMX not found: $VmxPath"
}

$script:Vmrun = Get-VmrunPath
$guestPasswordPlain = Convert-SecureStringToPlainText -Value $GuestPassword
$guestPasswordB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($guestPasswordPlain))
$guestNicB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($GuestNic))
$guestResultPath = 'C:\Windows\Temp\cac-vm-prepare-result.json'

$toolsReady = $false
$deadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $deadline) {
    $toolsState = & $script:Vmrun -T ws -gu $GuestUser -gp $guestPasswordPlain checkToolsState $VmxPath 2>&1
    if (($toolsState -join ' ') -match 'running') {
        $toolsReady = $true
        break
    }

    Start-Sleep -Seconds 3
}

if (-not $toolsReady) {
    throw 'VMware Tools did not become ready within 180 seconds.'
}

$guestScript = @"
`$ErrorActionPreference = 'Stop'
`$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
`$password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$guestPasswordB64'))
`$nic = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$guestNicB64'))
try {
    New-ItemProperty -LiteralPath `$key -Name 'AutoAdminLogon' -PropertyType String -Value '1' -Force | Out-Null
    New-ItemProperty -LiteralPath `$key -Name 'DefaultUserName' -PropertyType String -Value '$GuestUser' -Force | Out-Null
    New-ItemProperty -LiteralPath `$key -Name 'DefaultPassword' -PropertyType String -Value `$password -Force | Out-Null
    New-ItemProperty -LiteralPath `$key -Name 'ForceAutoLogon' -PropertyType String -Value '1' -Force | Out-Null
    Enable-NetAdapter -Name `$nic -Confirm:`$false -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 3
    `$os = Get-CimInstance Win32_OperatingSystem
    `$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    `$wl = Get-ItemProperty -LiteralPath `$key
    `$adapter = Get-NetAdapter -Name `$nic -IncludeHidden -ErrorAction SilentlyContinue |
        Select-Object Name, Status, MacAddress, InterfaceDescription, Virtual, HardwareInterface, ifIndex
    `$svc = Get-CimInstance Win32_SystemDriver -Filter "Name='CacMacLwf'" -ErrorAction SilentlyContinue |
        Select-Object Name, State, StartMode, PathName
    [pscustomobject]@{
        ok = `$true
        time = (Get-Date).ToString('o')
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        os = [pscustomobject]@{ Caption = `$os.Caption; Build = `$cv.CurrentBuild; UBR = `$cv.UBR; DisplayVersion = `$cv.DisplayVersion }
        autoLogin = [pscustomobject]@{ AutoAdminLogon = `$wl.AutoAdminLogon; DefaultUserName = `$wl.DefaultUserName; ForceAutoLogon = `$wl.ForceAutoLogon }
        adapter = `$adapter
        cacMacLwf = `$svc
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath '$guestResultPath' -Encoding UTF8
}
catch {
    [pscustomobject]@{ ok = `$false; time = (Get-Date).ToString('o'); error = `$_.Exception.Message } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath '$guestResultPath' -Encoding UTF8
    exit 1
}
"@

$encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($guestScript))
Invoke-Vmrun -Arguments @(
    '-T', 'ws', '-gu', $GuestUser, '-gp', $guestPasswordPlain,
    'runProgramInGuest', $VmxPath, '-activeWindow',
    'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-EncodedCommand', $encodedScript
) | Out-Null

$resultDirectory = Split-Path -Parent $ResultPath
if ($resultDirectory) {
    New-Item -ItemType Directory -Force -Path $resultDirectory | Out-Null
}
Invoke-Vmrun -Arguments @(
    '-T', 'ws', '-gu', $GuestUser, '-gp', $guestPasswordPlain,
    'CopyFileFromGuestToHost', $VmxPath, $guestResultPath, $ResultPath
) | Out-Null

$result = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
$result | ConvertTo-Json -Depth 8

if (-not $result.ok) {
    throw "Guest preparation failed: $($result.error)"
}

if ($RebootAfterPrepare) {
    Invoke-Vmrun -Arguments @('-T', 'ws', 'reset', $VmxPath, 'soft') | Out-Null
    Write-Host 'VM reset requested after auto-login preparation.'
}
