[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$NoBind,
    [switch]$RebootNow
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$sysPath = Join-Path $root 'bin\CacMacLwf.sys'
$infPath = Join-Path $root 'CacMacLwf.inf'
$driverTarget = Join-Path $env:SystemRoot 'System32\drivers\CacMacLwf.sys'
$component = 'CacMacLwf'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges are required to install an NDIS filter.'
    }
}

function Assert-TestSigning {
    $bcd = & bcdedit /enum '{current}' 2>$null
    if (-not ($bcd | Select-String -Pattern '^\s*testsigning\s+Yes\s*$' -Quiet)) {
        throw 'This driver is test-signed. Enable test signing (bcdedit /set testsigning on), reboot, then retry.'
    }
}

Assert-Administrator

if ($Uninstall) {
    $unbind = & netcfg -u $component 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Unbound $component" -ForegroundColor Green
    } else {
        Write-Host "netcfg -u: $($unbind -join ' ')" -ForegroundColor Yellow
    }
    if (Test-Path -LiteralPath $driverTarget) {
        Remove-Item -LiteralPath $driverTarget -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'CAC MAC LWF removed.' -ForegroundColor Green
    return
}

if (-not (Test-Path -LiteralPath $sysPath -PathType Leaf)) {
    throw "Driver not found: $sysPath. Run build-macfilter.ps1 first."
}
if (-not (Test-Path -LiteralPath $infPath -PathType Leaf)) {
    throw "INF not found: $infPath"
}

# The INF's CopyFiles pulls the binary from next to the INF (SourceDisksFiles).
Copy-Item -LiteralPath $sysPath -Destination (Join-Path $root 'CacMacLwf.sys') -Force

$signtool = Get-ChildItem 'D:\huanjing\WindowsKits' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($signtool) {
    & $signtool.FullName verify /pa /q $sysPath 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Driver signature is not valid.' }
}
Assert-TestSigning

Copy-Item -LiteralPath $sysPath -Destination $driverTarget -Force

$serviceState = sc.exe query $component 2>$null
if ($LASTEXITCODE -ne 0) {
    sc.exe create $component type= kernel start= demand error= normal `
        binPath= "\SystemRoot\System32\drivers\CacMacLwf.sys" `
        DisplayName= "CAC Profile MAC Lightweight Filter" | Out-Null
}

if (-not $NoBind) {
    $bind = & netcfg -l $infPath -c s -i $component 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "netcfg bind failed: $($bind -join ' ')"
    }
    Write-Host 'CAC MAC LWF installed and bound to ethernet adapters.' -ForegroundColor Green
} else {
    Write-Host 'Driver copied; filter not bound.' -ForegroundColor Yellow
}

$ctl = Join-Path $root 'bin\cac-macctl.exe'
if (Test-Path -LiteralPath $ctl -PathType Leaf) {
    Start-Sleep -Seconds 1
    & $ctl state
}

if ($RebootNow) {
    shutdown /r /t 15 /c "CacMacLwf bindings activation"
}
