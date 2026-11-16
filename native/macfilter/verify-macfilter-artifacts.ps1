#requires -Version 5.1
<#
  Verify CacMacLwf source/binary/docs consistency without loading the driver.
  Safe to run on the host while the service is DISABLED.
#>
[CmdletBinding()]
param(
    [string]$CodeCommit = 'de2d8d1abc42b927a754d6468f5e663e829d3fe9',
    [switch]$Json,
    [switch]$AllowDirty
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $root)
$binSys = Join-Path $root 'bin\CacMacLwf.sys'
$binCat = Join-Path $root 'bin\CacMacLwf.cat'
$shaPath = Join-Path $root 'bin\CacMacLwf.sha256'
$buildPath = Join-Path $root 'bin\BUILD.json'
$evidenceRoot = Join-Path $root 'evidence\builds\build-20261116-acl'
$infPath = Join-Path $root 'CacMacLwf.inf'
$results = New-Object System.Collections.Generic.List[object]
$fails = 0
$warns = 0

function Add-Result {
    param([string]$Check, [string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{ check = $Check; status = $Status; detail = $Detail })
    if ($Status -eq 'FAIL') { $script:fails++ }
    if ($Status -eq 'WARN') { $script:warns++ }
}

function Get-Sha([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
}

# 1. Source commit ancestry and source freeze.
git -C $repoRoot merge-base --is-ancestor $CodeCommit HEAD 2>$null
if ($LASTEXITCODE -eq 0) {
    Add-Result 'source.fix-commit' 'PASS' "$CodeCommit is in HEAD"
} else {
    Add-Result 'source.fix-commit' 'FAIL' "$CodeCommit is not in HEAD"
}
$sourceDirty = @(git -C $repoRoot status --porcelain -- native/macfilter/CacMacLwf.c 2>$null)
if ($sourceDirty.Count -eq 0) {
    Add-Result 'source.freeze' 'PASS' 'CacMacLwf.c matches HEAD'
} else {
    Add-Result 'source.freeze' 'FAIL' "CacMacLwf.c has uncommitted changes"
}
$dirty = @(git -C $repoRoot status --porcelain 2>$null)
if ($dirty.Count -eq 0 -or $AllowDirty) {
    Add-Result 'source.worktree' 'PASS' "dirty entries: $($dirty.Count)"
} else {
    Add-Result 'source.worktree' 'WARN' "working tree dirty: $($dirty.Count) entries"
}

# 2. Binary/hash/BUILD consistency.
$sysHash = Get-Sha $binSys
$catHash = Get-Sha $binCat
$manifestHash = if (Test-Path -LiteralPath $shaPath) {
    (Get-Content -LiteralPath $shaPath -Raw).Trim()
} else { $null }
$build = if (Test-Path -LiteralPath $buildPath) {
    Get-Content -LiteralPath $buildPath -Raw | ConvertFrom-Json
} else { $null }

if ($sysHash -and $manifestHash -and $sysHash -eq $manifestHash) {
    Add-Result 'binary.sha256' 'PASS' $sysHash
} else {
    Add-Result 'binary.sha256' 'FAIL' "bin=$sysHash manifest=$manifestHash"
}
if ($build -and $sysHash -eq $build.sysSha256) {
    Add-Result 'build.sys' 'PASS' $build.sysSha256
} else {
    Add-Result 'build.sys' 'FAIL' "bin=$sysHash build=$($build.sysSha256)"
}
if ($build -and $catHash -eq $build.catSha256) {
    Add-Result 'build.cat' 'PASS' $build.catSha256
} else {
    Add-Result 'build.cat' 'FAIL' "cat=$catHash build=$($build.catSha256)"
}

# 3. Signature.
foreach ($pair in @(
    @{ name = 'signature.sys'; path = $binSys },
    @{ name = 'signature.cat'; path = $binCat }
)) {
    if (Test-Path -LiteralPath $pair.path -PathType Leaf) {
        $sig = Get-AuthenticodeSignature -LiteralPath $pair.path
        if ($sig.Status -eq 'Valid') {
            Add-Result $pair.name 'PASS' $sig.SignerCertificate.Subject
        } else {
            Add-Result $pair.name 'FAIL' $sig.Status.ToString()
        }
    } else {
        Add-Result $pair.name 'FAIL' 'file missing'
    }
}

# 4. INF version.
$infText = Get-Content -LiteralPath $infPath -Raw
$infVer = if ($infText -match '(?m)^DriverVer\s*=\s*(.+)$') { $Matches[1].Trim() } else { $null }
if ($build -and $infVer -eq $build.infDriverVer) {
    Add-Result 'inf.driverver' 'PASS' $infVer
} else {
    Add-Result 'inf.driverver' 'FAIL' "inf=$infVer build=$($build.infDriverVer)"
}

# 5. Evidence archive consistency.
$evidenceSys = Join-Path $evidenceRoot 'CacMacLwf.sys'
$evidenceHash = Get-Sha $evidenceSys
if ($evidenceHash -and $evidenceHash -eq $sysHash) {
    Add-Result 'evidence.sys' 'PASS' $evidenceHash
} else {
    Add-Result 'evidence.sys' 'FAIL' "evidence=$evidenceHash bin=$sysHash"
}

# 6. Service and stale artifacts.
$service = Get-Service -Name 'CacMacLwf' -ErrorAction SilentlyContinue
if ($service) {
    if ($service.StartType -eq 'Disabled' -and $service.Status -eq 'Stopped') {
        Add-Result 'service.state' 'PASS' 'Stopped / Disabled'
    } else {
        Add-Result 'service.state' 'WARN' "$($service.Status) / $($service.StartType)"
    }
} else {
    Add-Result 'service.state' 'WARN' 'service not installed'
}
$rootSys = Join-Path $root 'CacMacLwf.sys'
$rootHash = Get-Sha $rootSys
if ($rootHash -and $rootHash -ne $sysHash) {
    Add-Result 'artifact.root' 'WARN' "stale root copy $rootHash"
} elseif ($rootHash) {
    Add-Result 'artifact.root' 'PASS' 'matches bin'
}
$installed = Join-Path $env:SystemRoot 'System32\drivers\CacMacLwf.sys'
$installedHash = Get-Sha $installed
if ($installedHash -and $installedHash -ne $sysHash) {
    Add-Result 'artifact.installed' 'WARN' "installed driver is stale $installedHash"
} elseif ($installedHash) {
    Add-Result 'artifact.installed' 'PASS' 'matches bin'
}

$summary = [ordered]@{
    schema = 1
    pass = ($fails -eq 0)
    failures = $fails
    warnings = $warns
    binSys = $sysHash
    binCat = $catHash
    build = $build
    results = $results
}
if ($Json) {
    $summary | ConvertTo-Json -Depth 8
} else {
    $results | Format-Table -AutoSize
    Write-Output ""
    Write-Output "PASS=$($summary.pass) FAIL=$fails WARN=$warns"
}
if ($fails -gt 0) { exit 1 }
