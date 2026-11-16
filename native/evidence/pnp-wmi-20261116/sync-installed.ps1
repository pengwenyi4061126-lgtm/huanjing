$ErrorActionPreference = 'Stop'
$dist = 'E:\环境\huanjing\native\dist'
$target = 'C:\Users\Administrator\.cac\native'
New-Item -ItemType Directory -Path $target -Force | Out-Null
foreach ($name in @('NativeBridge.dll', 'NativeBridge.sha256', 'cac-native-launch.exe', 'cac-native-launch.sha256')) {
    Copy-Item -LiteralPath (Join-Path $dist $name) -Destination (Join-Path $target $name) -Force
}
$declaredDll = (Get-Content -LiteralPath (Join-Path $target 'NativeBridge.sha256') -Raw).Trim().ToUpperInvariant()
$actualDll = (Get-FileHash -LiteralPath (Join-Path $target 'NativeBridge.dll') -Algorithm SHA256).Hash
$declaredLauncher = (Get-Content -LiteralPath (Join-Path $target 'cac-native-launch.sha256') -Raw).Trim().ToUpperInvariant()
$actualLauncher = (Get-FileHash -LiteralPath (Join-Path $target 'cac-native-launch.exe') -Algorithm SHA256).Hash
[pscustomobject]@{
    dll_match = ($declaredDll -eq $actualDll)
    dll = $actualDll
    launcher_match = ($declaredLauncher -eq $actualLauncher)
    launcher = $actualLauncher
} | Format-List
if ($declaredDll -ne $actualDll -or $declaredLauncher -ne $actualLauncher) { throw 'installed native layer hash mismatch' }

$accidental = 'C:\Users\Administrator\.cac\envs\audit-clean'
if (Test-Path -LiteralPath $accidental -PathType Container) {
    $resolved = (Resolve-Path -LiteralPath $accidental).Path
    if ($resolved -eq $accidental) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
        Write-Output "removed accidental env profile: $resolved"
    }
}
