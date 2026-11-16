[CmdletBinding()]
param(
    [string]$DataRoot = 'C:\ProgramData\CAC',
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$serviceName = 'CacServiceInjector'
$nativeTarget = Join-Path $DataRoot 'native'
$dist = Join-Path (Split-Path -Parent $PSScriptRoot) 'native\dist'

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run as Administrator.'
    }
}

function Assert-Hash([string]$Path, [string]$HashFile) {
    $expected = (Get-Content -LiteralPath $HashFile -Raw).Trim()
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $expected) {
        throw "SHA-256 mismatch: $Path"
    }
}

Assert-Admin

if ($Uninstall) {
    & sc.exe stop $serviceName 2>$null | Out-Null
    & sc.exe delete $serviceName 2>$null | Out-Null
    & (Join-Path $PSScriptRoot 'set-cowork-service-env.ps1') -Remove -NoRestart | Out-Null
    Write-Host "Service removed: $serviceName"
    return
}

$coworkService = Get-Service -Name 'CoworkVMService' -ErrorAction SilentlyContinue
$coworkWasRunning = $coworkService -and $coworkService.Status -eq 'Running'
& sc.exe stop $serviceName 2>$null | Out-Null
if ($coworkWasRunning) {
    & sc.exe stop 'CoworkVMService' 2>$null | Out-Null
    Start-Sleep -Seconds 3
}

$required = @(
    'NativeBridge.dll',
    'NativeBridge.sha256',
    'cac-service-injector.exe',
    'cac-service-injector.sha256'
)
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $dist $name))) {
        throw "Missing build output: $(Join-Path $dist $name)"
    }
}

New-Item -ItemType Directory -Force -Path $nativeTarget, (Join-Path $DataRoot 'logs') | Out-Null
$coworkKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\CoworkVMService'
$coworkImage = (Get-ItemProperty -Path $coworkKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
if ($coworkImage) {
    $coworkImage = $coworkImage.Trim('"')
    if (Test-Path -LiteralPath $coworkImage) {
        $coworkItem = Get-Item -LiteralPath $coworkImage
        $coworkHash = (Get-FileHash -LiteralPath $coworkImage -Algorithm SHA256).Hash
        $cachePath = Join-Path $nativeTarget 'cowork-svc.hash'
        "$coworkImage|$($coworkItem.Length)|$($coworkItem.LastWriteTimeUtc.ToFileTimeUtc())|$coworkHash" |
            Set-Content -LiteralPath $cachePath -Encoding ASCII
    }
}
$nativeAudit = Join-Path $DataRoot 'logs\cowork-svc-native.jsonl'
$injectorAudit = Join-Path $DataRoot 'logs\service-injector.jsonl'
foreach ($log in @($nativeAudit, $injectorAudit)) {
    if (-not (Test-Path -LiteralPath $log)) {
        New-Item -ItemType File -Path $log | Out-Null
    }
}
Copy-Item -LiteralPath (Join-Path $dist 'NativeBridge.dll') -Destination $nativeTarget -Force
Copy-Item -LiteralPath (Join-Path $dist 'NativeBridge.sha256') -Destination $nativeTarget -Force
Copy-Item -LiteralPath (Join-Path $dist 'cac-service-injector.exe') -Destination $nativeTarget -Force
Copy-Item -LiteralPath (Join-Path $dist 'cac-service-injector.sha256') -Destination $nativeTarget -Force

Assert-Hash (Join-Path $nativeTarget 'NativeBridge.dll') (Join-Path $nativeTarget 'NativeBridge.sha256')
Assert-Hash (Join-Path $nativeTarget 'cac-service-injector.exe') (Join-Path $nativeTarget 'cac-service-injector.sha256')

& icacls.exe $DataRoot /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "icacls failed with exit code $LASTEXITCODE"
}
Get-ChildItem -LiteralPath $DataRoot -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    & icacls.exe $_.FullName /reset | Out-Null
    & icacls.exe $_.FullName /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
}

$exe = Join-Path $nativeTarget 'cac-service-injector.exe'
$binPath = "`"$exe`" --service"
$existing = & sc.exe query $serviceName 2>$null
if ($LASTEXITCODE -eq 0) {
    & sc.exe config $serviceName binPath= $binPath start= auto obj= LocalSystem | Out-Null
} else {
    & sc.exe create $serviceName type= own start= auto error= normal `
        binPath= $binPath obj= LocalSystem DisplayName= 'CAC Service Injector' | Out-Null
}
if ($LASTEXITCODE -ne 0) {
    throw "sc.exe create/config failed with exit code $LASTEXITCODE"
}
& sc.exe description $serviceName 'Injects NativeBridge into Claude Cowork service processes.' | Out-Null
& sc.exe start $serviceName | Out-Null
& (Join-Path $PSScriptRoot 'set-cowork-service-env.ps1') -NoRestart | Out-Null
if ($coworkWasRunning) {
    & sc.exe start 'CoworkVMService' | Out-Null
}

Start-Sleep -Seconds 2
& sc.exe query $serviceName
Write-Host "Native files: $nativeTarget"
Write-Host "Audit log: $(Join-Path $DataRoot 'logs\service-injector.jsonl')"
