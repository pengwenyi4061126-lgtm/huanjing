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
    "NativeBridge\GpuHooks.cpp",
    "NativeBridge\KernelPolicy.cpp",
    "NativeBridge\WfpPolicy.cpp",
    "NativeBridge\NativeBridge.cpp"
) | ForEach-Object { Join-Path $root $_ }

$ml64 = Join-Path $msvc.MsvcVersion "bin\Hostx64\x64\ml64.exe"
$asmSource = Join-Path $root "NativeBridge\GoCpuDetours.asm"
$asmObject = Join-Path $obj "GoCpuDetours.obj"

Push-Location $root
try {
    Write-Host "Assembling Go CPU detours ..." -ForegroundColor Cyan
    & $ml64 /nologo /c "/Fo$asmObject" $asmSource
    if ($LASTEXITCODE -ne 0) { throw "GoCpuDetours.asm build failed ($LASTEXITCODE)" }

    Write-Host "Building NativeBridge.dll ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime /LD `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        ($dllSources + $asmObject) `
        "/Fo$obj\" "/Fe:$dist\NativeBridge.dll" `
        /link /DLL /guard:cf /Brepro iphlpapi.lib bcrypt.lib wbemuuid.lib ole32.lib oleaut32.lib fwpuclnt.lib ws2_32.lib uuid.lib mmdevapi.lib propsys.lib
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

    Write-Host "Building cac-service-injector.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "ServiceInjector\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-service-injector.exe" `
        /link /guard:cf /Brepro advapi32.lib bcrypt.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-service-injector.exe build failed ($LASTEXITCODE)" }

    $injectorPath = Join-Path $dist "cac-service-injector.exe"
    $injectorHash = Get-CacSha256 $injectorPath
    Set-Content -LiteralPath (Join-Path $dist "cac-service-injector.sha256") -Value $injectorHash -Encoding ASCII

    Write-Host "Building cac-cpu-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "CpuProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-cpu-probe.exe" `
        /link /guard:cf /Brepro advapi32.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-cpu-probe.exe build failed ($LASTEXITCODE)" }

    $probePath = Join-Path $dist "cac-cpu-probe.exe"
    $probeHash = Get-CacSha256 $probePath
    Set-Content -LiteralPath (Join-Path $dist "cac-cpu-probe.sha256") -Value $probeHash -Encoding ASCII

    Write-Host "Building cac-hardware-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "HardwareProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-hardware-probe.exe" `
        /link /guard:cf /Brepro psapi.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-hardware-probe.exe build failed ($LASTEXITCODE)" }

    $hardwareProbePath = Join-Path $dist "cac-hardware-probe.exe"
    $hardwareProbeHash = Get-CacSha256 $hardwareProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-hardware-probe.sha256") -Value $hardwareProbeHash -Encoding ASCII

    Write-Host "Building cac-gpu-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "GpuProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-gpu-probe.exe" `
        /link /guard:cf /Brepro ole32.lib mmdevapi.lib propsys.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-gpu-probe.exe build failed ($LASTEXITCODE)" }

    $gpuProbePath = Join-Path $dist "cac-gpu-probe.exe"
    $gpuProbeHash = Get-CacSha256 $gpuProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-gpu-probe.sha256") -Value $gpuProbeHash -Encoding ASCII

    Write-Host "Building cac-cpu-deep-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "CpuDeepProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-cpu-deep-probe.exe" `
        /link /guard:cf /Brepro psapi.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-cpu-deep-probe.exe build failed ($LASTEXITCODE)" }

    $cpuDeepProbePath = Join-Path $dist "cac-cpu-deep-probe.exe"
    $cpuDeepProbeHash = Get-CacSha256 $cpuDeepProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-cpu-deep-probe.sha256") -Value $cpuDeepProbeHash -Encoding ASCII

    Write-Host "Building cac-disk-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "DiskProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-disk-probe.exe" `
        /link /guard:cf /Brepro
    if ($LASTEXITCODE -ne 0) { throw "cac-disk-probe.exe build failed ($LASTEXITCODE)" }

    $diskProbePath = Join-Path $dist "cac-disk-probe.exe"
    $diskProbeHash = Get-CacSha256 $diskProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-disk-probe.sha256") -Value $diskProbeHash -Encoding ASCII

    Write-Host "Building cac-display-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "DisplayProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-display-probe.exe" `
        /link /guard:cf /Brepro user32.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-display-probe.exe build failed ($LASTEXITCODE)" }

    $displayProbePath = Join-Path $dist "cac-display-probe.exe"
    $displayProbeHash = Get-CacSha256 $displayProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-display-probe.sha256") -Value $displayProbeHash -Encoding ASCII

    Write-Host "Building cac-hid-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "HidProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-hid-probe.exe" `
        /link /guard:cf /Brepro hid.lib setupapi.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-hid-probe.exe build failed ($LASTEXITCODE)" }

    $hidProbePath = Join-Path $dist "cac-hid-probe.exe"
    $hidProbeHash = Get-CacSha256 $hidProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-hid-probe.sha256") -Value $hidProbeHash -Encoding ASCII

    Write-Host "Building cac-nvml-probe.exe ..." -ForegroundColor Cyan
    $nvmlDef = Join-Path $root "NvmlProbe\nvml.def"
    $nvmlLib = Join-Path $obj "nvml.lib"
    & lib.exe /nologo "/def:$nvmlDef" "/out:$nvmlLib" /machine:x64
    if ($LASTEXITCODE -ne 0) { throw "nvml.lib generation failed ($LASTEXITCODE)" }
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "NvmlProbe\main.cpp") $nvmlLib `
        "/Fo$obj\" "/Fe:$dist\cac-nvml-probe.exe" `
        /link /guard:cf /Brepro
    if ($LASTEXITCODE -ne 0) { throw "cac-nvml-probe.exe build failed ($LASTEXITCODE)" }

    $nvmlProbePath = Join-Path $dist "cac-nvml-probe.exe"
    $nvmlProbeHash = Get-CacSha256 $nvmlProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-nvml-probe.sha256") -Value $nvmlProbeHash -Encoding ASCII

    Write-Host "Building cac-audio-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "AudioProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-audio-probe.exe" `
        /link /guard:cf /Brepro ole32.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-audio-probe.exe build failed ($LASTEXITCODE)" }

    $audioProbePath = Join-Path $dist "cac-audio-probe.exe"
    $audioProbeHash = Get-CacSha256 $audioProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-audio-probe.sha256") -Value $audioProbeHash -Encoding ASCII

    Write-Host "Building cac-pnp-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "PnpProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-pnp-probe.exe" `
        /link /guard:cf /Brepro setupapi.lib ole32.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-pnp-probe.exe build failed ($LASTEXITCODE)" }

    $pnpProbePath = Join-Path $dist "cac-pnp-probe.exe"
    $pnpProbeHash = Get-CacSha256 $pnpProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-pnp-probe.sha256") -Value $pnpProbeHash -Encoding ASCII

    Write-Host "Building cac-pnp-wmi-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "PnpWmiProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-pnp-wmi-probe.exe" `
        /link /guard:cf /Brepro wbemuuid.lib ole32.lib oleaut32.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-pnp-wmi-probe.exe build failed ($LASTEXITCODE)" }

    $pnpWmiProbePath = Join-Path $dist "cac-pnp-wmi-probe.exe"
    $pnpWmiProbeHash = Get-CacSha256 $pnpWmiProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-pnp-wmi-probe.sha256") -Value $pnpWmiProbeHash -Encoding ASCII

    Write-Host "Building cac-opencl-probe.exe ..." -ForegroundColor Cyan
    $openclDef = Join-Path $root "OpenCLProbe\opencl.def"
    $openclLib = Join-Path $obj "opencl.lib"
    & lib.exe /nologo "/def:$openclDef" "/out:$openclLib" /machine:x64
    if ($LASTEXITCODE -ne 0) { throw "opencl.lib generation failed ($LASTEXITCODE)" }
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "OpenCLProbe\main.cpp") $openclLib `
        "/Fo$obj\" "/Fe:$dist\cac-opencl-probe.exe" `
        /link /guard:cf /Brepro
    if ($LASTEXITCODE -ne 0) { throw "cac-opencl-probe.exe build failed ($LASTEXITCODE)" }

    $openclProbePath = Join-Path $dist "cac-opencl-probe.exe"
    $openclProbeHash = Get-CacSha256 $openclProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-opencl-probe.sha256") -Value $openclProbeHash -Encoding ASCII

    Write-Host "Building cac-vulkan-probe.exe ..." -ForegroundColor Cyan
    $vulkanDef = Join-Path $root "VulkanProbe\vulkan.def"
    $vulkanLib = Join-Path $obj "vulkan.lib"
    & lib.exe /nologo "/def:$vulkanDef" "/out:$vulkanLib" /machine:x64
    if ($LASTEXITCODE -ne 0) { throw "vulkan.lib generation failed ($LASTEXITCODE)" }
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "VulkanProbe\main.cpp") $vulkanLib `
        "/Fo$obj\" "/Fe:$dist\cac-vulkan-probe.exe" `
        /link /guard:cf /Brepro
    if ($LASTEXITCODE -ne 0) { throw "cac-vulkan-probe.exe build failed ($LASTEXITCODE)" }

    $vulkanProbePath = Join-Path $dist "cac-vulkan-probe.exe"
    $vulkanProbeHash = Get-CacSha256 $vulkanProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-vulkan-probe.sha256") -Value $vulkanProbeHash -Encoding ASCII

    Write-Host "Building cac-smart-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "SmartProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-smart-probe.exe" `
        /link /guard:cf /Brepro
    if ($LASTEXITCODE -ne 0) { throw "cac-smart-probe.exe build failed ($LASTEXITCODE)" }

    $smartProbePath = Join-Path $dist "cac-smart-probe.exe"
    $smartProbeHash = Get-CacSha256 $smartProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-smart-probe.sha256") -Value $smartProbeHash -Encoding ASCII

    Write-Host "Building cac-monitor-wmi-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "MonitorWmiProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-monitor-wmi-probe.exe" `
        /link /guard:cf /Brepro wbemuuid.lib ole32.lib oleaut32.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-monitor-wmi-probe.exe build failed ($LASTEXITCODE)" }

    $monitorWmiProbePath = Join-Path $dist "cac-monitor-wmi-probe.exe"
    $monitorWmiProbeHash = Get-CacSha256 $monitorWmiProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-monitor-wmi-probe.sha256") -Value $monitorWmiProbeHash -Encoding ASCII

    Write-Host "Building cac-usb-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "UsbProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-usb-probe.exe" `
        /link /guard:cf /Brepro setupapi.lib
    if ($LASTEXITCODE -ne 0) { throw "cac-usb-probe.exe build failed ($LASTEXITCODE)" }

    $usbProbePath = Join-Path $dist "cac-usb-probe.exe"
    $usbProbeHash = Get-CacSha256 $usbProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-usb-probe.sha256") -Value $usbProbeHash -Encoding ASCII

    Write-Host "Building cac-cache-probe.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "CacheProbe\main.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-cache-probe.exe" `
        /link /guard:cf /Brepro
    if ($LASTEXITCODE -ne 0) { throw "cac-cache-probe.exe build failed ($LASTEXITCODE)" }

    $cacheProbePath = Join-Path $dist "cac-cache-probe.exe"
    $cacheProbeHash = Get-CacSha256 $cacheProbePath
    Set-Content -LiteralPath (Join-Path $dist "cac-cache-probe.sha256") -Value $cacheProbeHash -Encoding ASCII

    Write-Host "Building cac-nvme-patch-test.exe ..." -ForegroundColor Cyan
    & cl.exe /nologo /utf-8 /std:c++17 /EHsc /W3 /guard:cf $optimize $runtime `
        /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE `
        (Join-Path $root "tests\nvme_patch_test.cpp") `
        "/Fo$obj\" "/Fe:$dist\cac-nvme-patch-test.exe" `
        /link /guard:cf /Brepro
    if ($LASTEXITCODE -ne 0) { throw "cac-nvme-patch-test.exe build failed ($LASTEXITCODE)" }

    $nvmeTestPath = Join-Path $dist "cac-nvme-patch-test.exe"
    $nvmeTestHash = Get-CacSha256 $nvmeTestPath
    Set-Content -LiteralPath (Join-Path $dist "cac-nvme-patch-test.sha256") -Value $nvmeTestHash -Encoding ASCII

    Write-Host "Verifying dist artifact hashes ..." -ForegroundColor Cyan
    $manifest = New-Object System.Collections.Generic.List[string]
    $mismatches = New-Object System.Collections.Generic.List[string]
    foreach ($binary in Get-ChildItem -LiteralPath $dist -File |
             Where-Object { $_.Extension -in @('.exe', '.dll') }) {
        $declaredName = [System.IO.Path]::GetFileNameWithoutExtension($binary.Name) + '.sha256'
        $declaredPath = Join-Path $dist $declaredName
        if (-not (Test-Path -LiteralPath $declaredPath -PathType Leaf)) {
            $mismatches.Add("$($binary.Name): missing $declaredName")
            continue
        }
        $actual = Get-CacSha256 $binary.FullName
        $declared = (Get-Content -LiteralPath $declaredPath -Raw).Trim().ToUpperInvariant()
        if ($actual -ne $declared) {
            $mismatches.Add("$($binary.Name): declared=$declared actual=$actual")
            continue
        }
        $manifest.Add(("{0} *{1}" -f $actual, $binary.Name))
    }
    if ($mismatches.Count -gt 0) {
        throw ("dist hash mismatch:`n" + ($mismatches -join "`n"))
    }
    Set-Content -LiteralPath (Join-Path $dist "manifest.sha256") -Value $manifest -Encoding ASCII
} finally {
    Pop-Location
}

Get-ChildItem -LiteralPath $dist -File | ForEach-Object {
    $hash = Get-CacSha256 $_.FullName
    [pscustomobject]@{ File = $_.FullName; Size = $_.Length; Sha256 = $hash }
} | Format-Table -AutoSize

Write-Host "Build complete: $dist" -ForegroundColor Green
