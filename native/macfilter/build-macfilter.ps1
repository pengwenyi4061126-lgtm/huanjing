[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SkipSign
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$nativeRoot = Split-Path -Parent $root
$bin = Join-Path $root 'bin'
$obj = Join-Path $root 'obj'

function Get-CacSha256([string]$Path) {
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

. (Join-Path $nativeRoot 'toolchain.ps1')
$toolchain = Set-CacToolchain
$msvc = $toolchain.Msvc

$wdkBases = @(
    'D:\huanjing\wdk\Microsoft.Windows.WDK.x64',
    'C:\Program Files (x86)\Windows Kits\10\WDK',
    'C:\Program Files\Windows Kits\10\WDK'
) | Where-Object { Test-Path -LiteralPath $_ }
$wdk = $null
foreach ($base in $wdkBases) {
    $cRoots = @((Join-Path $base 'c'))
    $cRoots += @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'c' })
    foreach ($cRoot in $cRoots) {
        $includeRoot = Join-Path $cRoot 'Include'
        if (-not (Test-Path -LiteralPath $includeRoot)) { continue }
        $version = Get-ChildItem -LiteralPath $includeRoot -Directory |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'km\ntddk.h') } |
            Sort-Object Name -Descending | Select-Object -First 1
        if (-not $version) { continue }
        $libRoot = Join-Path $cRoot "Lib\$($version.Name)\km\x64"
        if (-not (Test-Path -LiteralPath (Join-Path $libRoot 'ndis.lib'))) { continue }
        $wdk = [pscustomobject]@{
            Version = $version.Name
            Include = Join-Path $includeRoot $version.Name
            Lib = $libRoot
        }
        break
    }
    if ($wdk) { break }
}
if (-not $wdk) { throw 'WDK km headers with ndis.lib not found.' }

$signtool = Get-ChildItem 'D:\huanjing\WindowsKits' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'signtool.exe (x64) not found.' }

$userInclude = $env:INCLUDE
$userLib = $env:LIB

if ($Clean) {
    Remove-Item -LiteralPath $bin, $obj -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $bin, $obj -Force | Out-Null

$env:INCLUDE = @(
    (Join-Path $wdk.Include 'km'),
    (Join-Path $wdk.Include 'shared'),
    (Join-Path $toolchain.Sdk.Root "Include\$($toolchain.Sdk.Version)\shared"),
    (Join-Path $toolchain.Sdk.Root "Include\$($toolchain.Sdk.Version)\ucrt"),
    (Join-Path $msvc.MsvcVersion 'include')
) -join ';'
$env:LIB = @(
    $wdk.Lib,
    (Join-Path $msvc.MsvcVersion 'lib\x64')
) -join ';'

$cl = Join-Path $msvc.MsvcVersion 'bin\Hostx64\x64\cl.exe'
$link = Join-Path $msvc.MsvcVersion 'bin\Hostx64\x64\link.exe'
$source = Join-Path $root 'CacMacLwf.c'
$objFile = Join-Path $obj 'CacMacLwf.obj'
$sysPath = Join-Path $bin 'CacMacLwf.sys'

Write-Host 'Compiling CacMacLwf.sys ...' -ForegroundColor Cyan
& $cl /nologo /c /W4 /O2 /GS /GR- /Zl `
    /D_AMD64_ /DAMD64 /D_WIN64 /DWIN32=100 /D_KERNEL_MODE=1 `
    /DNDIS630 `
    /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000C `
    /DUNICODE /D_UNICODE `
    "/Fo$objFile" $source
if ($LASTEXITCODE -ne 0) { throw "CacMacLwf compile failed ($LASTEXITCODE)" }

Write-Host 'Linking CacMacLwf.sys ...' -ForegroundColor Cyan
& $link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB `
    /MACHINE:X64 "/OUT:$sysPath" $objFile `
    ntoskrnl.lib ndis.lib hal.lib BufferOverflowK.lib libcntpr.lib
if ($LASTEXITCODE -ne 0) { throw "CacMacLwf link failed ($LASTEXITCODE)" }

if (-not $SkipSign) {
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $cert = $null
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $cert = $store.Certificates |
            Where-Object { $_.Subject -eq 'CN=CAC Kernel Test Signing' -and $_.HasPrivateKey } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
    } finally { $store.Close() }
    if (-not $cert) { throw 'CAC signing certificate not found; run native/kernel/build-driver.ps1 once.' }
    & $signtool.FullName sign /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $sysPath
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed ($LASTEXITCODE)" }

    $inf2cat = Get-ChildItem 'D:\huanjing\wdk' -Recurse -Filter 'Inf2Cat.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $inf2cat) { throw 'Inf2Cat.exe not found in WDK.' }
    & $inf2cat.FullName "/driver:$root" /os:10_X64 /uselocaltime
    $catPath = Join-Path $root 'CacMacLwf.cat'
    if (-not (Test-Path -LiteralPath $catPath -PathType Leaf)) {
        throw 'inf2cat did not produce CacMacLwf.cat'
    }
    & $signtool.FullName sign /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $catPath
    if ($LASTEXITCODE -ne 0) { throw "catalog sign failed ($LASTEXITCODE)" }
}

$hash = Get-CacSha256 $sysPath
Set-Content -LiteralPath (Join-Path $bin 'CacMacLwf.sha256') -Value $hash -Encoding ASCII

$env:INCLUDE = @(
    (Join-Path $msvc.MsvcVersion 'include'),
    (Join-Path $toolchain.Sdk.Root "Include\$($toolchain.Sdk.Version)\ucrt"),
    (Join-Path $toolchain.Sdk.Root "Include\$($toolchain.Sdk.Version)\um"),
    (Join-Path $toolchain.Sdk.Root "Include\$($toolchain.Sdk.Version)\shared")
) -join ';'
$env:LIB = @(
    (Join-Path $msvc.MsvcVersion 'lib\x64'),
    (Join-Path $toolchain.Sdk.Root "Lib\$($toolchain.Sdk.Version)\ucrt\x64"),
    (Join-Path $toolchain.Sdk.Root "Lib\$($toolchain.Sdk.Version)\um\x64")
) -join ';'

Write-Host 'Building cac-macctl.exe ...' -ForegroundColor Cyan
& $cl /nologo /std:c++17 /EHsc /MT /O2 /W3 `
    /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
    "/I$root" `
    (Join-Path $root 'tools\cac-macctl.cpp') `
    "/Fo$obj\" "/Fe:$bin\cac-macctl.exe"
if ($LASTEXITCODE -ne 0) { throw "cac-macctl build failed ($LASTEXITCODE)" }

$env:INCLUDE = $userInclude
$env:LIB = $userLib

Write-Host "MAC filter build complete: $bin" -ForegroundColor Green
