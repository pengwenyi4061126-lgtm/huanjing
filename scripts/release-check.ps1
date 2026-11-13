# Verify that the source tree, npm tarball, and optional installed Native layer
# all refer to the same release artifact.
[CmdletBinding()]
param(
    [string]$PackagePath,
    [string]$InstalledNativeDir = (Join-Path $env:USERPROFILE '.cac\native'),
    [switch]$SkipPack
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$packageJsonPath = Join-Path $root 'package.json'
$distDir = Join-Path $root 'native\dist'

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Assert-File([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
}

function Assert-Equal([string]$Expected, [string]$Actual, [string]$Label) {
    if (-not [string]::Equals($Expected, $Actual, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label mismatch: expected $Expected, got $Actual"
    }
}

$package = Get-Content -LiteralPath $packageJsonPath -Raw | ConvertFrom-Json
$version = [string]$package.version
$dll = Join-Path $distDir 'NativeBridge.dll'
$launcher = Join-Path $distDir 'cac-native-launch.exe'
$hashFile = Join-Path $distDir 'NativeBridge.sha256'
Assert-File $dll 'workspace NativeBridge.dll'
Assert-File $launcher 'workspace native launcher'
Assert-File $hashFile 'workspace NativeBridge.sha256'

$dllHash = Get-Sha256 $dll
$declaredHash = (Get-Content -LiteralPath $hashFile -Raw).Trim().ToUpperInvariant()
Assert-Equal $dllHash $declaredHash 'workspace NativeBridge SHA-256'

$result = [ordered]@{
    version = $version
    workspace = [ordered]@{
        dll = $dll
        dllSha256 = $dllHash
        launcherSha256 = Get-Sha256 $launcher
        declaredSha256 = $declaredHash
    }
    package = $null
    installed = $null
}

if (-not $SkipPack) {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('cac-release-check-' + [guid]::NewGuid().ToString('N'))
    $extractRoot = Join-Path $tempRoot 'extract'
    New-Item -ItemType Directory -Path $tempRoot, $extractRoot -Force | Out-Null
    try {
        if ([string]::IsNullOrWhiteSpace($PackagePath)) {
            $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
            if (-not $npm) { $npm = Get-Command npm -ErrorAction Stop }
            $packJson = @(& $npm.Source pack $root --ignore-scripts --pack-destination $tempRoot --json 2>&1)
            if ($LASTEXITCODE -ne 0) { throw "npm pack failed: $($packJson -join [Environment]::NewLine)" }
            $packInfo = ($packJson -join [Environment]::NewLine) | ConvertFrom-Json
            $PackagePath = Join-Path $tempRoot ([string]$packInfo[0].filename)
        }
        Assert-File $PackagePath 'npm package'
        $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
        if (-not $tar) { throw 'tar.exe is required to inspect the npm package' }
        & $tar.Source -xzf $PackagePath -C $extractRoot
        if ($LASTEXITCODE -ne 0) { throw "tar extraction failed: $PackagePath" }

        $embeddedDll = Join-Path $extractRoot 'package\native\dist\NativeBridge.dll'
        $embeddedHashFile = Join-Path $extractRoot 'package\native\dist\NativeBridge.sha256'
        $embeddedPackageJson = Join-Path $extractRoot 'package\package.json'
        Assert-File $embeddedDll 'package NativeBridge.dll'
        Assert-File $embeddedHashFile 'package NativeBridge.sha256'
        Assert-File $embeddedPackageJson 'package package.json'
        $embedded = Get-Content -LiteralPath $embeddedPackageJson -Raw | ConvertFrom-Json
        Assert-Equal $version ([string]$embedded.version) 'package version'
        $embeddedDllHash = Get-Sha256 $embeddedDll
        $embeddedDeclaredHash = (Get-Content -LiteralPath $embeddedHashFile -Raw).Trim().ToUpperInvariant()
        Assert-Equal $dllHash $embeddedDllHash 'package NativeBridge SHA-256'
        Assert-Equal $dllHash $embeddedDeclaredHash 'package declared NativeBridge SHA-256'
        $result.package = [ordered]@{
            path = [System.IO.Path]::GetFullPath($PackagePath)
            version = [string]$embedded.version
            dllSha256 = $embeddedDllHash
            declaredSha256 = $embeddedDeclaredHash
        }
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path -LiteralPath $InstalledNativeDir -PathType Container) {
    $installedDll = Join-Path $InstalledNativeDir 'NativeBridge.dll'
    $installedHashFile = Join-Path $InstalledNativeDir 'NativeBridge.sha256'
    Assert-File $installedDll 'installed NativeBridge.dll'
    Assert-File $installedHashFile 'installed NativeBridge.sha256'
    $installedHash = Get-Sha256 $installedDll
    $installedDeclared = (Get-Content -LiteralPath $installedHashFile -Raw).Trim().ToUpperInvariant()
    Assert-Equal $dllHash $installedHash 'installed NativeBridge SHA-256'
    Assert-Equal $dllHash $installedDeclared 'installed declared NativeBridge SHA-256'
    $result.installed = [ordered]@{
        dir = [System.IO.Path]::GetFullPath($InstalledNativeDir)
        dllSha256 = $installedHash
        declaredSha256 = $installedDeclared
    }
}

$result | ConvertTo-Json -Depth 8
Write-Host "[PASS] release artifacts are consistent at $version" -ForegroundColor Green
