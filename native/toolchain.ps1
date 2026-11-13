function Find-CacMsvc {
    $candidates = @(
        "D:\huanjing\BuildTools",
        $env:VSINSTALLDIR,
        "$env:ProgramFiles\Microsoft Visual Studio\2022\BuildTools",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Community",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Professional",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Enterprise"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($candidate in $candidates) {
        $toolRoot = Join-Path $candidate "VC\Tools\MSVC"
        if (-not (Test-Path -LiteralPath $toolRoot)) { continue }
        $version = Get-ChildItem -LiteralPath $toolRoot -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($version -and (Test-Path -LiteralPath (Join-Path $version.FullName "bin\Hostx64\x64\cl.exe"))) {
            return [pscustomobject]@{ VsRoot = $candidate; MsvcVersion = $version.FullName }
        }
    }
    return $null
}

function Find-CacSdk {
    $candidates = @(
        "D:\huanjing\WindowsKits",
        "$env:ProgramFiles\Windows Kits\10",
        "${env:ProgramFiles(x86)}\Windows Kits\10"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    foreach ($candidate in $candidates) {
        $includeRoot = Join-Path $candidate "Include"
        if (-not (Test-Path -LiteralPath $includeRoot)) { continue }
        $version = Get-ChildItem -LiteralPath $includeRoot -Directory |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "um\windows.h") } |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($version) {
            return [pscustomobject]@{ Root = $candidate; Version = $version.Name }
        }
    }
    return $null
}

function Set-CacToolchain {
    $msvc = Find-CacMsvc
    if (-not $msvc) { throw "MSVC x64 toolset not found. Install Visual Studio Build Tools with the C++ workload." }
    $sdk = Find-CacSdk
    if (-not $sdk) { throw "Windows SDK not found. Install the Windows 10/11 SDK." }

    $env:Path = (Join-Path $msvc.MsvcVersion "bin\Hostx64\x64") + ";" + $env:Path
    $env:INCLUDE = @(
        (Join-Path $msvc.MsvcVersion "include"),
        (Join-Path $sdk.Root "Include\$($sdk.Version)\ucrt"),
        (Join-Path $sdk.Root "Include\$($sdk.Version)\um"),
        (Join-Path $sdk.Root "Include\$($sdk.Version)\shared")
    ) -join ";"
    $env:LIB = @(
        (Join-Path $msvc.MsvcVersion "lib\x64"),
        (Join-Path $sdk.Root "Lib\$($sdk.Version)\ucrt\x64"),
        (Join-Path $sdk.Root "Lib\$($sdk.Version)\um\x64")
    ) -join ";"

    return [pscustomobject]@{ Msvc = $msvc; Sdk = $sdk }
}
