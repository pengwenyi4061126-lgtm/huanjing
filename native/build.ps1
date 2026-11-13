[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [switch]$Clean,
    [switch]$ToolchainOnly
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root "dist"
$obj = Join-Path $root "obj"

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

. (Join-Path $root "toolchain.ps1")
$toolchain = Set-CacToolchain
$msvc = $toolchain.Msvc
$sdk = $toolchain.Sdk

Write-Host "MSVC : $($msvc.MsvcVersion)" -ForegroundColor Cyan
Write-Host "SDK  : $($sdk.Root) $($sdk.Version)" -ForegroundColor Cyan

if ($ToolchainOnly) {
    Write-Host "INCLUDE=$env:INCLUDE"
    Write-Host "LIB=$env:LIB"
    return
}

if ($Clean) {
    Remove-Item -LiteralPath $dist, $obj -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $dist, $obj -Force | Out-Null

$runtime = if ($Configuration -eq "Debug") { "/MTd" } else { "/MT" }
$optimize = if ($Configuration -eq "Debug") { "/Od /Zi" } else { "/O2" }

$dllSources = @(
    "NativeBridge\Identity.cpp",
    "NativeBridge\Audit.cpp",
    "NativeBridge\HookEngine.cpp",
    "NativeBridge\Firmware.cpp",
    "NativeBridge\ApiHooks.cpp",
    "NativeBridge\ChildInject.cpp",
    "NativeBridge\WmiHooks.cpp",
    "NativeBridge\NetworkHooks.cpp",
    "NativeBridge\KernelPolicy.cpp",
    "NativeBridge\WfpPolicy.cpp",
    "NativeBridge\NativeBridge.cpp"
) | ForEach-Object { Join-Path $root $_ }

Push-Location $root
try {
    Write-Host "Building NativeBridge.dll ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime /LD `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        $dllSources `
        "/Fo$obj\" "/Fe:$dist\NativeBridge.dll" `
        /link /DLL /guard:cf /Brepro iphlpapi.lib bcrypt.lib wbemuuid.lib ole32.lib oleaut32.lib fwpuclnt.lib ws2_32.lib
    if ($LASTEXITCODE -ne 0) { throw "NativeBridge.dll build failed ($LASTEXITCODE)" }

    $dllPath = Join-Path $dist "NativeBridge.dll"
    $dllHash = Get-CacSha256 $dllPath
    Set-Content -LiteralPath (Join-Path $obj "expected_dll_hash.h") `
        -Value "#define CAC_EXPECTED_DLL_SHA256 `"$dllHash`"" -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $dist "NativeBridge.sha256") -Value $dllHash -Encoding ASCII

    Write-Host "Building cac-native-launch.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        "/I$obj" `
        (Join-Path $root "Launcher\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-native-launch.exe" /link /guard:cf /Brepro
    if ($LASTEXITCODE -ne 0) { throw "cac-native-launch.exe build failed ($LASTEXITCODE)" }

    $launcherPath = Join-Path $dist "cac-native-launch.exe"
    $launcherHash = Get-CacSha256 $launcherPath
    Set-Content -LiteralPath (Join-Path $dist "cac-native-launch.sha256") -Value $launcherHash -Encoding ASCII
} finally {
    Pop-Location
}

Get-ChildItem -LiteralPath $dist -File | ForEach-Object {
    $hash = Get-CacSha256 $_.FullName
    [pscustomobject]@{ File = $_.FullName; Size = $_.Length; Sha256 = $hash }
} | Format-Table -AutoSize

Write-Host "Build complete: $dist" -ForegroundColor Green
