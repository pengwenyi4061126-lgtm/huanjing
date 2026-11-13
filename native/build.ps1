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
    "NativeBridge\NativeBridge.cpp"
) | ForEach-Object { Join-Path $root $_ }

Push-Location $root
try {
    Write-Host "Building NativeBridge.dll ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime /LD `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        $dllSources `
        "/Fo$obj\" "/Fe:$dist\NativeBridge.dll" `
        /link /DLL /guard:cf iphlpapi.lib bcrypt.lib
    if ($LASTEXITCODE -ne 0) { throw "NativeBridge.dll build failed ($LASTEXITCODE)" }

    Write-Host "Building cac-native-launch.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "Launcher\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-native-launch.exe" /link /guard:cf
    if ($LASTEXITCODE -ne 0) { throw "cac-native-launch.exe build failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}

Get-ChildItem -LiteralPath $dist -File | ForEach-Object {
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    [pscustomobject]@{ File = $_.FullName; Size = $_.Length; Sha256 = $hash }
} | Format-Table -AutoSize

Write-Host "Build complete: $dist" -ForegroundColor Green
