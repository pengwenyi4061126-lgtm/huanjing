# Verify that the source tree, npm tarball, and optional installed Native layer
# all refer to the same release artifact. This script intentionally uses the
# .NET hashing API instead of Get-FileHash so it remains reliable when a
# caller has an incomplete or reordered Windows PowerShell module path.
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
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToUpperInvariant()
    } finally {
        if ($stream) { $stream.Dispose() }
        $sha.Dispose()
    }
}

function Get-DeclaredSha256([string]$Path, [string]$Label) {
    $raw = Get-Content -LiteralPath $Path -Raw
    $matches = [regex]::Matches($raw, '(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')
    if ($matches.Count -ne 1) {
        throw "$Label must contain exactly one SHA-256 value"
    }
    return $matches[0].Value.ToUpperInvariant()
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
$cacSource = Get-Content -LiteralPath (Join-Path $root 'cac.ps1') -Raw
$cacVersionMatch = [regex]::Match($cacSource, '\$CAC_VERSION\s*=\s*"([^"]+)"')
if (-not $cacVersionMatch.Success) { throw 'cac.ps1 version source is missing' }
Assert-Equal $version $cacVersionMatch.Groups[1].Value 'cac.ps1 version'
$readme = Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw
$readmeHead = (($readme -split "`r?`n") | Select-Object -First 12) -join [Environment]::NewLine
$readmeVersionMatch = [regex]::Match($readmeHead, '(\d+\.\d+\.\d+)')
if (-not $readmeVersionMatch.Success) { throw 'README current version is missing' }
Assert-Equal $version $readmeVersionMatch.Groups[1].Value 'README version'
$audit = Get-Content -LiteralPath (Join-Path $root 'AUDIT-20261113.md') -Raw
$auditHead = (($audit -split "`r?`n") | Select-Object -First 80) -join [Environment]::NewLine
$auditVersionMatch = [regex]::Match($auditHead, '\| cac-windows \| `([^`]+)` \|')
if (-not $auditVersionMatch.Success) { throw 'AUDIT current version is missing' }
Assert-Equal $version $auditVersionMatch.Groups[1].Value 'AUDIT version'
$runtimeChainFiles = @(
    'cac',
    'cac.cmd',
    'cac.ps1',
    'package.json',
    'fingerprint-hook.js',
    'src/relay.js',
    'scripts/lib.ps1',
    'scripts/menu.ps1',
    'scripts/postinstall.js',
    'scripts/patch-cli.js',
    'scripts/verify-cli.js',
    'scripts/cleanup.ps1',
    'scripts/network-check.ps1',
    'scripts/profile-check.ps1',
    'scripts/native-boundary-check.ps1',
    'scripts/kernel-boundary-check.ps1',
    'scripts/desktop-native-check.ps1',
    'scripts/desktop-profile.ps1',
    'scripts/cert-silent.ps1',
    'scripts/proxy-pool-lib.ps1',
    'scripts/proxy-pool.ps1',
    'scripts/fingerprint-shim.js',
    'scripts/fingerprint-cdp.js',
    'scripts/fingerprint-test.js',
    'scripts/mitm_fingerprint.py',
    'native/dist/NativeBridge.dll',
    'native/dist/NativeBridge.sha256',
    'native/dist/cac-native-launch.exe',
    'native/dist/cac-native-launch.sha256',
    'native/kernel/RELEASE.md'
)
foreach ($relativePath in $runtimeChainFiles) {
    $workspacePath = Join-Path $root ($relativePath -replace '/', '\')
    Assert-File $workspacePath "workspace runtime chain file $relativePath"
    if ($relativePath -ne 'package.json' -and @($package.files) -notcontains $relativePath) {
        throw "package.json files is missing runtime chain entry: $relativePath"
    }
}
$dll = Join-Path $distDir 'NativeBridge.dll'
$launcher = Join-Path $distDir 'cac-native-launch.exe'
$hashFile = Join-Path $distDir 'NativeBridge.sha256'
$launcherHashFile = Join-Path $distDir 'cac-native-launch.sha256'
Assert-File $dll 'workspace NativeBridge.dll'
Assert-File $launcher 'workspace native launcher'
Assert-File $hashFile 'workspace NativeBridge.sha256'
Assert-File $launcherHashFile 'workspace cac-native-launch.sha256'

$dllHash = Get-Sha256 $dll
$declaredHash = Get-DeclaredSha256 $hashFile 'workspace NativeBridge.sha256'
Assert-Equal $dllHash $declaredHash 'workspace NativeBridge SHA-256'
$launcherHash = Get-Sha256 $launcher
$declaredLauncherHash = Get-DeclaredSha256 $launcherHashFile 'workspace cac-native-launch.sha256'
Assert-Equal $launcherHash $declaredLauncherHash 'workspace native launcher SHA-256'
$readmeHashMatch = [regex]::Match($readme, 'NativeBridge SHA-256[^\r\n`]*`([0-9A-Fa-f]{64})`')
if (-not $readmeHashMatch.Success) { throw 'README NativeBridge hash is missing' }
Assert-Equal $dllHash $readmeHashMatch.Groups[1].Value 'README NativeBridge SHA-256'
$auditHashMatch = [regex]::Match($auditHead, '\| NativeBridge SHA-256 \| `([0-9A-Fa-f]{64})` \|')
if (-not $auditHashMatch.Success) { throw 'AUDIT NativeBridge hash is missing' }
Assert-Equal $dllHash $auditHashMatch.Groups[1].Value 'AUDIT NativeBridge SHA-256'
$readmeLauncherHashMatch = [regex]::Match($readme, 'cac-native-launch\.exe[^\r\n]*([0-9A-Fa-f]{64})')
if (-not $readmeLauncherHashMatch.Success) { throw 'README launcher hash is missing' }
Assert-Equal $launcherHash $readmeLauncherHashMatch.Groups[1].Value 'README launcher SHA-256'
$auditLauncherHashMatch = [regex]::Match($auditHead, '\| cac-native-launch SHA-256 \| `([0-9A-Fa-f]{64})` \|')
if (-not $auditLauncherHashMatch.Success) { throw 'AUDIT launcher hash is missing' }
Assert-Equal $launcherHash $auditLauncherHashMatch.Groups[1].Value 'AUDIT launcher SHA-256'

$result = [ordered]@{
    version = $version
    workspace = [ordered]@{
        dll = $dll
        dllSha256 = $dllHash
        launcher = $launcher
        launcherSha256 = $launcherHash
        declaredSha256 = $declaredHash
        declaredLauncherSha256 = $declaredLauncherHash
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
        $embeddedLauncher = Join-Path $extractRoot 'package\native\dist\cac-native-launch.exe'
        $embeddedLauncherHashFile = Join-Path $extractRoot 'package\native\dist\cac-native-launch.sha256'
        $embeddedPackageJson = Join-Path $extractRoot 'package\package.json'
        Assert-File $embeddedDll 'package NativeBridge.dll'
        Assert-File $embeddedHashFile 'package NativeBridge.sha256'
        Assert-File $embeddedLauncher 'package native launcher'
        Assert-File $embeddedLauncherHashFile 'package cac-native-launch.sha256'
        Assert-File $embeddedPackageJson 'package package.json'
        foreach ($relativePath in $runtimeChainFiles) {
            $embeddedPath = Join-Path $extractRoot ('package\' + ($relativePath -replace '/', '\'))
            Assert-File $embeddedPath "package runtime chain file $relativePath"
        }
        $embedded = Get-Content -LiteralPath $embeddedPackageJson -Raw | ConvertFrom-Json
        Assert-Equal $version ([string]$embedded.version) 'package version'
        $embeddedDllHash = Get-Sha256 $embeddedDll
        $embeddedDeclaredHash = Get-DeclaredSha256 $embeddedHashFile 'package NativeBridge.sha256'
        Assert-Equal $dllHash $embeddedDllHash 'package NativeBridge SHA-256'
        Assert-Equal $dllHash $embeddedDeclaredHash 'package declared NativeBridge SHA-256'
        $embeddedLauncherHash = Get-Sha256 $embeddedLauncher
        $embeddedDeclaredLauncherHash = Get-DeclaredSha256 $embeddedLauncherHashFile 'package cac-native-launch.sha256'
        Assert-Equal $launcherHash $embeddedLauncherHash 'package native launcher SHA-256'
        Assert-Equal $launcherHash $embeddedDeclaredLauncherHash 'package declared native launcher SHA-256'
        $result.package = [ordered]@{
            path = [System.IO.Path]::GetFullPath($PackagePath)
            version = [string]$embedded.version
            dllSha256 = $embeddedDllHash
            declaredSha256 = $embeddedDeclaredHash
            launcherSha256 = $embeddedLauncherHash
            declaredLauncherSha256 = $embeddedDeclaredLauncherHash
            runtimeChainFiles = @($runtimeChainFiles)
        }
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path -LiteralPath $InstalledNativeDir -PathType Container) {
    $installedDll = Join-Path $InstalledNativeDir 'NativeBridge.dll'
    $installedLauncher = Join-Path $InstalledNativeDir 'cac-native-launch.exe'
    $installedHashFile = Join-Path $InstalledNativeDir 'NativeBridge.sha256'
    $installedLauncherHashFile = Join-Path $InstalledNativeDir 'cac-native-launch.sha256'
    Assert-File $installedDll 'installed NativeBridge.dll'
    Assert-File $installedLauncher 'installed native launcher'
    Assert-File $installedHashFile 'installed NativeBridge.sha256'
    Assert-File $installedLauncherHashFile 'installed cac-native-launch.sha256'
    $installedHash = Get-Sha256 $installedDll
    $installedDeclared = Get-DeclaredSha256 $installedHashFile 'installed NativeBridge.sha256'
    Assert-Equal $dllHash $installedHash 'installed NativeBridge SHA-256'
    Assert-Equal $dllHash $installedDeclared 'installed declared NativeBridge SHA-256'
    $installedLauncherHash = Get-Sha256 $installedLauncher
    $installedDeclaredLauncher = Get-DeclaredSha256 $installedLauncherHashFile 'installed cac-native-launch.sha256'
    Assert-Equal $launcherHash $installedLauncherHash 'installed native launcher SHA-256'
    Assert-Equal $launcherHash $installedDeclaredLauncher 'installed declared native launcher SHA-256'
    $result.installed = [ordered]@{
        dir = [System.IO.Path]::GetFullPath($InstalledNativeDir)
        dllSha256 = $installedHash
        declaredSha256 = $installedDeclared
        launcherSha256 = $installedLauncherHash
        declaredLauncherSha256 = $installedDeclaredLauncher
    }
}

$result | ConvertTo-Json -Depth 8
Write-Host "[PASS] release artifacts are consistent at $version" -ForegroundColor Green
