#requires -Version 5.1
#!/usr/bin/env pwsh
# Clear tracking data inside one isolated Profile only.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigDir,
    [Parameter(Mandatory = $true)]
    [string]$HomeDir,
    [Parameter(Mandatory = $true)]
    [string]$ProfileRoot,
    [string]$CacheDir,
    [string]$TempDir,
    [string]$AppData,
    [string]$LocalAppData,
    [string]$XdgConfigHome,
    [string]$XdgCacheHome,
    [string]$CredentialsDir,
    [string]$LogsDir
)

$ErrorActionPreference = 'Stop'
$failures = New-Object 'System.Collections.Generic.List[string]'
$residuals = New-Object 'System.Collections.Generic.List[string]'
$profileLock = $null

function Write-OK($Text) { Write-Host "  [OK] $Text" -ForegroundColor Green }
function Write-Skip($Text) { Write-Host "  [SKIP] $Text" -ForegroundColor Yellow }
function Write-Del($Text) { Write-Host "  [DEL] $Text" -ForegroundColor Red }
function Add-Failure([string]$Text) { [void]$script:failures.Add($Text); Write-Host "  [FAIL] $Text" -ForegroundColor Red }
function Add-Residual([string]$Path) {
    if (-not ($script:residuals -contains $Path)) { [void]$script:residuals.Add($Path) }
}
function Normalize-Path([string]$Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}
function Get-ProfileMutexName([string]$Root) {
    $fullRoot = (Normalize-Path $Root).ToUpperInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fullRoot))
        $hex = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        return "Global\cac-profile-$($hex.Substring(0, 32))"
    } finally { $sha.Dispose() }
}
function Enter-ProfileMutex([string]$Root) {
    $mutex = [System.Threading.Mutex]::new($false, (Get-ProfileMutexName $Root))
    try {
        $acquired = $false
        try { $acquired = [bool]$mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { $mutex.Dispose(); return $null }
        return [pscustomobject][ordered]@{ Mutex = $mutex; Acquired = $true }
    } catch { try { $mutex.Dispose() } catch { }; throw }
}
function Exit-ProfileMutex([object]$Lock) {
    if ($null -eq $Lock) { return }
    try { if ([bool]$Lock.Acquired) { [void]$Lock.Mutex.ReleaseMutex() } } catch { }
    finally { try { $Lock.Mutex.Dispose() } catch { } }
}
function Test-UnderRoot([string]$Path, [string]$Root) {
    $pathFull = Normalize-Path $Path
    $rootFull = Normalize-Path $Root
    return [string]::Equals($pathFull, $rootFull, [StringComparison]::OrdinalIgnoreCase) -or
        $pathFull.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)
}
function Assert-NoReparsePoints([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing cleanup of reparse point: $Path"
    }
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop)) {
        if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing cleanup because a descendant is a reparse point: $($child.FullName)"
        }
    }
}
function Resolve-BoundDirectory([string]$Name, [string]$Supplied, [string]$Expected, [string]$Root) {
    $expectedFull = Normalize-Path $Expected
    if (-not (Test-UnderRoot $expectedFull $Root)) {
        throw "Derived $Name is outside ProfileRoot: $expectedFull"
    }
    if (-not [string]::IsNullOrWhiteSpace($Supplied)) {
        $suppliedFull = Normalize-Path $Supplied
        if (-not [string]::Equals($suppliedFull, $expectedFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing external $Name path: $suppliedFull"
        }
    }
    return $expectedFull
}
function Remove-PathSafely([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        Assert-NoReparsePoints $Path
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $Path) {
            Add-Residual $Path
        } else {
            Write-Del "${Label}: $Path"
        }
    } catch {
        Add-Failure "$Label removal failed: $Path : $($_.Exception.Message)"
        if (Test-Path -LiteralPath $Path) { Add-Residual $Path }
    }
}
function Clear-DirectorySafely([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    try {
        Assert-NoReparsePoints $Path
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)) {
            Remove-PathSafely -Path $child.FullName -Label 'cleanup'
        }
        $remaining = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        foreach ($child in $remaining) { Add-Residual $child.FullName }
        if ($remaining.Count -eq 0) { Write-Del $Path }
    } catch {
        Add-Failure "directory cleanup failed: $Path : $($_.Exception.Message)"
    }
}

$jsonScript = $null
try {
    $root = Normalize-Path $ProfileRoot
    if ([string]::IsNullOrWhiteSpace($root) -or
        [string]::Equals($root, (Normalize-Path ([System.IO.Path]::GetPathRoot($root))), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unsafe ProfileRoot: $ProfileRoot"
    }
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "ProfileRoot does not exist: $root"
    }
    $profileLock = Enter-ProfileMutex $root
    if ($null -eq $profileLock) { throw "Profile is busy: $root" }
    Assert-NoReparsePoints $root

    $expected = [ordered]@{
        ConfigDir      = Join-Path $root '.claude'
        HomeDir        = Join-Path $root 'home'
        CacheDir       = Join-Path $root 'cache'
        TempDir        = Join-Path $root 'temp'
        AppData        = Join-Path $root 'AppData\Roaming'
        LocalAppData   = Join-Path $root 'AppData\Local'
        XdgConfigHome  = Join-Path $root 'xdg\config'
        XdgCacheHome   = Join-Path $root 'xdg\cache'
        CredentialsDir = Join-Path $root 'credentials'
        LogsDir        = Join-Path $root 'logs'
    }
    $bound = [ordered]@{}
    $bound.ConfigDir = Resolve-BoundDirectory 'ConfigDir' $ConfigDir $expected.ConfigDir $root
    $bound.HomeDir = Resolve-BoundDirectory 'HomeDir' $HomeDir $expected.HomeDir $root
    $bound.CacheDir = Resolve-BoundDirectory 'CacheDir' $CacheDir $expected.CacheDir $root
    $bound.TempDir = Resolve-BoundDirectory 'TempDir' $TempDir $expected.TempDir $root
    $bound.AppData = Resolve-BoundDirectory 'AppData' $AppData $expected.AppData $root
    $bound.LocalAppData = Resolve-BoundDirectory 'LocalAppData' $LocalAppData $expected.LocalAppData $root
    $bound.XdgConfigHome = Resolve-BoundDirectory 'XdgConfigHome' $XdgConfigHome $expected.XdgConfigHome $root
    $bound.XdgCacheHome = Resolve-BoundDirectory 'XdgCacheHome' $XdgCacheHome $expected.XdgCacheHome $root
    $bound.CredentialsDir = Resolve-BoundDirectory 'CredentialsDir' $CredentialsDir $expected.CredentialsDir $root
    $bound.LogsDir = Resolve-BoundDirectory 'LogsDir' $LogsDir $expected.LogsDir $root

    foreach ($path in @($bound.Values)) { Assert-NoReparsePoints $path }

    Write-Host ''
    Write-Host 'Claude Code Cleanup - current Profile only' -ForegroundColor Cyan
    Write-Host "  ProfileRoot: $root" -ForegroundColor DarkGray
    Write-Host ''

    Write-Host 'Resetting profile identity and account linkage...' -ForegroundColor White
    $jsonScript = Join-Path $root ('.cac-cleanup-json-{0}.js' -f [Guid]::NewGuid().ToString('N'))
    $source = @(
        'const fs = require("fs"), p = process.argv[2];',
        'const keys = ["userID", "anonymousId", "firstStartTime", "claudeCodeFirstTokenDate",',
        '  "oauthAccount", "s1mAccessCache", "groveConfigCache", "passesEligibilityCache",',
        '  "clientDataCache", "cachedExtraUsageDisabledReason", "githubRepoPaths", "hasExtraUsageEnabled"];',
        'const j = JSON.parse(fs.readFileSync(p, "utf8").replace(/^\uFEFF/, ""));',
        'const removed = keys.filter(k => k in j);',
        'removed.forEach(k => delete j[k]);',
        'if (removed.length) fs.writeFileSync(p, JSON.stringify(j, null, 2));',
        'removed.forEach(k => console.log(k));'
    ) -join [Environment]::NewLine
    foreach ($claudeJson in @(
        (Join-Path $bound.ConfigDir '.claude.json'),
        (Join-Path $bound.HomeDir '.claude.json')
    ) | Select-Object -Unique) {
        if (-not (Test-Path -LiteralPath $claudeJson -PathType Leaf)) { continue }
        try {
            Set-Content -LiteralPath $jsonScript -Value $source -Encoding ASCII
            $removed = @(& node $jsonScript $claudeJson 2>&1)
            if ($LASTEXITCODE -ne 0) {
                Add-Failure "JSON parse failed; not modified: $claudeJson"
            } elseif ($removed.Count -gt 0) {
                $removed | ForEach-Object { Write-Del "$(Split-Path $claudeJson -Leaf): $_" }
                Write-OK "cleaned $claudeJson"
            } else {
                Write-Skip "$claudeJson has no cleanup fields"
            }
        } catch {
            Add-Failure "JSON cleanup failed: $claudeJson : $($_.Exception.Message)"
        }
    }

    Write-Host 'Clearing profile telemetry and caches...' -ForegroundColor White
    foreach ($name in @('telemetry', 'statsig', 'stats-cache.json', 'debug', 'Crashpad')) {
        Remove-PathSafely -Path (Join-Path $bound.ConfigDir $name) -Label 'remove'
    }

    Write-Host 'Clearing profile-only caches, temp files and file credentials...' -ForegroundColor White
    foreach ($dir in @($bound.CacheDir, $bound.TempDir, $bound.AppData, $bound.LocalAppData,
            $bound.XdgConfigHome, $bound.XdgCacheHome, $bound.CredentialsDir, $bound.LogsDir)) {
        Clear-DirectorySafely $dir
    }

    Write-Host 'Credential Manager: unchanged' -ForegroundColor White
    Write-Skip 'Windows Credential Manager is account-global; profile cleanup does not modify it'
} catch {
    Add-Failure $_.Exception.Message
} finally {
    if ($jsonScript -and (Test-Path -LiteralPath $jsonScript)) {
        try { Remove-Item -LiteralPath $jsonScript -Force -ErrorAction Stop }
        catch { Add-Failure "temporary script removal failed: $jsonScript : $($_.Exception.Message)"; Add-Residual $jsonScript }
    }
    Exit-ProfileMutex $profileLock
}

Write-Host ''
foreach ($path in @($residuals)) { Write-Host "  [RESIDUAL] $path" -ForegroundColor Red }
if ($failures.Count -gt 0 -or $residuals.Count -gt 0) {
    Write-Host "[FAIL] Profile cleanup incomplete: failures=$($failures.Count), residuals=$($residuals.Count)" -ForegroundColor Red
    exit 1
}
Write-OK 'Current Profile tracking data cleared; global user files were not modified'
exit 0
