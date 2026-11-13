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

function Find-CacWdk {
    $bases = @(
        'D:\huanjing\wdk\Microsoft.Windows.WDK.x64',
        'C:\Program Files (x86)\Windows Kits\10\WDK',
        'C:\Program Files\Windows Kits\10\WDK'
    ) | Where-Object { Test-Path -LiteralPath $_ }

    foreach ($base in $bases) {
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
            if (-not (Test-Path -LiteralPath (Join-Path $libRoot 'ntoskrnl.lib'))) { continue }
            return [pscustomobject]@{
                CRoot = $cRoot
                Version = $version.Name
                Include = Join-Path $includeRoot $version.Name
                Lib = $libRoot
            }
        }
    }
    throw 'WDK 10 kernel headers/libs not found.'
}

function Find-CacSignTool {
    $roots = @(
        'D:\huanjing\WindowsKits',
        'C:\Program Files (x86)\Windows Kits\10',
        'C:\Program Files\Windows Kits\10'
    ) | Where-Object { Test-Path -LiteralPath $_ }
    foreach ($rootPath in $roots) {
        $tool = Get-ChildItem -LiteralPath $rootPath -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($tool) { return $tool.FullName }
    }
    throw 'signtool.exe (x64) not found.'
}

function Get-CacSigningCertificate {
    $subject = 'CN=CAC Kernel Test Signing'
    $cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) {
        Write-Host 'Creating test code-signing certificate ...' -ForegroundColor Cyan
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
            -CertStoreLocation 'Cert:\LocalMachine\My' -HashAlgorithm SHA256 `
            -KeyLength 2048 -NotAfter (Get-Date).AddYears(5)
    }

    $cerPath = Join-Path $env:TEMP ("cac-kernel-test-$($cert.Thumbprint).cer")
    try {
        Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
        foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
            if (-not (Test-Path -LiteralPath (Join-Path $store $cert.Thumbprint))) {
                Write-Host "Trusting test certificate in $store ..." -ForegroundColor Cyan
                Import-Certificate -FilePath $cerPath -CertStoreLocation $store | Out-Null
            }
        }
    } finally {
        Remove-Item -LiteralPath $cerPath -Force -ErrorAction SilentlyContinue
    }
    return $cert
}

. (Join-Path $nativeRoot 'toolchain.ps1')
$toolchain = Set-CacToolchain
$msvc = $toolchain.Msvc
$wdk = Find-CacWdk
$userInclude = $env:INCLUDE
$userLib = $env:LIB

Write-Host "MSVC : $($msvc.MsvcVersion)" -ForegroundColor Cyan
Write-Host "WDK  : $($wdk.CRoot) $($wdk.Version)" -ForegroundColor Cyan

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
$source = Join-Path $root 'CacKernel.c'
$objFile = Join-Path $obj 'CacKernel.obj'
$sysPath = Join-Path $bin 'CacKernel.sys'
$hashPath = Join-Path $bin 'CacKernel.sha256'

Write-Host 'Compiling CacKernel.sys ...' -ForegroundColor Cyan
& $cl /nologo /c /W4 /O2 /GS- /GR- /Zl `
    /D_AMD64_ /DAMD64 /D_WIN64 /DWIN32=100 /D_KERNEL_MODE=1 `
    /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000C `
    /DUNICODE /D_UNICODE `
    "/Fo$objFile" $source
if ($LASTEXITCODE -ne 0) { throw "driver compile failed ($LASTEXITCODE)" }

Write-Host 'Linking CacKernel.sys ...' -ForegroundColor Cyan
& $link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB `
    /MACHINE:X64 "/OUT:$sysPath" $objFile `
    ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowK.lib libcntpr.lib
if ($LASTEXITCODE -ne 0) { throw "driver link failed ($LASTEXITCODE)" }

if (-not $SkipSign) {
    $signtool = Find-CacSignTool
    $cert = Get-CacSigningCertificate
    Write-Host "Signing with $($cert.Subject) ..." -ForegroundColor Cyan
    & $signtool sign /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $sysPath
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed ($LASTEXITCODE)" }
    & $signtool verify /pa /v $sysPath
    if ($LASTEXITCODE -ne 0) { throw "signtool verify failed ($LASTEXITCODE)" }
}

$hash = Get-CacSha256 $sysPath
Set-Content -LiteralPath $hashPath -Value $hash -Encoding ASCII

$env:INCLUDE = $userInclude
$env:LIB = $userLib

Write-Host 'Building kernel-smoke.exe ...' -ForegroundColor Cyan
& $cl /nologo /std:c++17 /EHsc /MT /O2 /W3 `
    /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
    "/I$root" `
    (Join-Path $root 'tests\kernel-smoke.cpp') `
    "/Fo$obj\" "/Fe:$bin\kernel-smoke.exe"
if ($LASTEXITCODE -ne 0) { throw "kernel-smoke build failed ($LASTEXITCODE)" }

Write-Host 'Building cac-kernelctl.exe ...' -ForegroundColor Cyan
& $cl /nologo /std:c++17 /EHsc /MT /O2 /W3 `
    /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
    "/I$root" `
    (Join-Path $root 'tools\cac-kernelctl.cpp') `
    "/Fo$obj\" "/Fe:$bin\cac-kernelctl.exe"
if ($LASTEXITCODE -ne 0) { throw "cac-kernelctl build failed ($LASTEXITCODE)" }

[pscustomobject]@{
    Driver = $sysPath
    Sha256 = $hash
    Signer = if ($SkipSign) { $null } else { [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromSignedFile($sysPath).Subject }
    Smoke = Join-Path $bin 'kernel-smoke.exe'
    Control = Join-Path $bin 'cac-kernelctl.exe'
} | Format-List

Write-Host "Kernel build complete: $bin" -ForegroundColor Green
