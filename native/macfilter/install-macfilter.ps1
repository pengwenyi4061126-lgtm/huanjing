[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$NoBind,
    [switch]$RebootNow,
    [switch]$DryRun,
    [switch]$Enable
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$sysPath = Join-Path $root 'bin\CacMacLwf.sys'
$shaPath = Join-Path $root 'bin\CacMacLwf.sha256'
$catPath = Join-Path $root 'bin\CacMacLwf.cat'
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

function Assert-FileHash {
    param(
        [string]$Path,
        [string]$Expected,
        [string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label missing: $Path"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    if ($actual -ne $Expected) {
        throw "$Label hash mismatch. expected=$Expected actual=$actual path=$Path"
    }
}

Assert-Administrator

if ($Uninstall) {
    sc.exe stop $component 2>$null | Out-Null
    Start-Sleep -Seconds 2
    $unbind = & netcfg -u $component 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Unbound $component" -ForegroundColor Green
    } else {
        Write-Host "netcfg -u: $($unbind -join ' ')" -ForegroundColor Yellow
    }
    if (Test-Path -LiteralPath $driverTarget) {
        Remove-Item -LiteralPath $driverTarget -Force -ErrorAction SilentlyContinue
    }
    sc.exe delete $component 2>$null | Out-Null
    $rootCat = Join-Path $root 'CacMacLwf.cat'
    if (Test-Path -LiteralPath $rootCat) {
        Remove-Item -LiteralPath $rootCat -Force -ErrorAction SilentlyContinue
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
if (-not (Test-Path -LiteralPath $shaPath -PathType Leaf)) {
    throw "Hash manifest not found: $shaPath. Run build-macfilter.ps1 first."
}

$expectedHash = (Get-Content -LiteralPath $shaPath -Raw).Trim()
Assert-FileHash -Path $sysPath -Expected $expectedHash -Label 'bin driver'

if ($DryRun) {
    $dryRoot = Join-Path $env:TEMP ("cac-macfilter-dryrun-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dryRoot -Force | Out-Null
    try {
        $dryCopy = Join-Path $dryRoot 'CacMacLwf.sys'
        Copy-Item -LiteralPath $sysPath -Destination $dryCopy -Force
        Assert-FileHash -Path $dryCopy -Expected $expectedHash -Label 'dry-run staged driver'
        Write-Host "Dry run passed: $expectedHash" -ForegroundColor Green
    } finally {
        Remove-Item -LiteralPath $dryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    return
}

# The INF's CopyFiles pulls the binary from next to the INF (SourceDisksFiles).
Copy-Item -LiteralPath $sysPath -Destination (Join-Path $root 'CacMacLwf.sys') -Force
Assert-FileHash -Path (Join-Path $root 'CacMacLwf.sys') -Expected $expectedHash -Label 'staged driver'

if (Test-Path -LiteralPath $catPath -PathType Leaf) {
    Copy-Item -LiteralPath $catPath -Destination (Join-Path $root 'CacMacLwf.cat') -Force
}

$signtool = Get-ChildItem 'D:\huanjing\WindowsKits' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($signtool) {
    & $signtool.FullName verify /pa /q $sysPath 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Driver signature is not valid.' }
}
Assert-TestSigning

sc.exe stop $component 2>$null | Out-Null
Start-Sleep -Seconds 2
Copy-Item -LiteralPath $sysPath -Destination $driverTarget -Force
Assert-FileHash -Path $driverTarget -Expected $expectedHash -Label 'installed driver'

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

if ($Enable) {
    sc.exe config $component start= demand | Out-Null
    sc.exe start $component 2>$null | Out-Null
} else {
    sc.exe config $component start= disabled | Out-Null
    Write-Host 'Service left DISABLED. Use -Enable on an isolated test machine.' -ForegroundColor Yellow
}

$ctl = Join-Path $root 'bin\cac-macctl.exe'
if (Test-Path -LiteralPath $ctl -PathType Leaf) {
    Start-Sleep -Seconds 1
    & $ctl state
}

if ($RebootNow) {
    shutdown /r /t 15 /c "CacMacLwf bindings activation"
}
