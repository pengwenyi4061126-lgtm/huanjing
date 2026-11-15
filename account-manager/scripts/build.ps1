# Build both Windows targets without allowing portable and NSIS to overwrite
# each other. electron-builder 25 does not accept artifactName per target.
$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$package = Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw | ConvertFrom-Json
$dist = [System.IO.Path]::GetFullPath((Join-Path $root 'dist'))
$baseName = "cac-account-manager-$($package.version)-x64.exe"
$portableName = "cac-account-manager-$($package.version)-x64-portable.exe"
$setupName = "cac-account-manager-$($package.version)-x64-setup.exe"
$portablePath = Join-Path $dist $baseName
$portableTarget = Join-Path $dist $portableName
$setupTarget = Join-Path $dist $setupName
$blockMapPath = "$portablePath.blockmap"
$portableBlockMap = "$portableTarget.blockmap"
$setupBlockMap = "$setupTarget.blockmap"

New-Item -ItemType Directory -Path $dist -Force | Out-Null
foreach ($path in @($portablePath, $portableTarget, $setupTarget, $blockMapPath, $portableBlockMap, $setupBlockMap)) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    try {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    } catch {
        throw "Cannot remove stale build artifact: $path. Close the running portable app and retry. $($_.Exception.Message)"
    }
    if (Test-Path -LiteralPath $path) { throw "Stale build artifact still exists after cleanup: $path" }
}

Push-Location $root
try {
    & npx.cmd electron-builder --win portable
    if ($LASTEXITCODE -ne 0) { throw "portable build failed with exit code $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $portablePath -PathType Leaf)) { throw "portable artifact missing: $portablePath" }
    Move-Item -LiteralPath $portablePath -Destination $portableTarget -Force
    if (Test-Path -LiteralPath $blockMapPath -PathType Leaf) { Move-Item -LiteralPath $blockMapPath -Destination $portableBlockMap -Force }

    & npx.cmd electron-builder --win nsis
    if ($LASTEXITCODE -ne 0) { throw "NSIS build failed with exit code $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $portablePath -PathType Leaf)) { throw "NSIS artifact missing: $portablePath" }
    Move-Item -LiteralPath $portablePath -Destination $setupTarget -Force
    if (Test-Path -LiteralPath $blockMapPath -PathType Leaf) { Move-Item -LiteralPath $blockMapPath -Destination $setupBlockMap -Force }
    Write-Host "[PASS] $portableTarget"
    Write-Host "[PASS] $setupTarget"
} finally {
    Pop-Location
}
