# cac-windows — shared utility functions
$ErrorActionPreference = "Stop"

$CAC_DIR = Join-Path $env:USERPROFILE ".cac"
$ENVS_DIR = Join-Path $CAC_DIR "envs"

function Write-OK($t) { Write-Host "  [OK] $t" -ForegroundColor Green }
function Write-Err($t) { Write-Host "  [!!] $t" -ForegroundColor Red }
function Write-Warn($t) { Write-Host "  [--] $t" -ForegroundColor Yellow }

function Read-FileValue {
    param([string]$Path, [string]$Default = "")
    if (Test-Path $Path) { return (Get-Content $Path -Raw).Trim() }
    return $Default
}

function New-Uuid    { return [guid]::NewGuid().ToString().ToUpper() }
function New-Sid     { return [guid]::NewGuid().ToString().ToLower() }
function New-UserId  { return -join ((1..32) | ForEach-Object { "{0:x2}" -f (Get-Random -Maximum 256) }) }
function New-MachineId { return [guid]::NewGuid().ToString().Replace("-","").ToLower() }
function New-FakeHostname { return "host-$([guid]::NewGuid().ToString().Split('-')[0].ToLower())" }
function New-FakeMac {
    $bytes = @(0x02) + (1..5 | ForEach-Object { Get-Random -Maximum 256 })
    return ($bytes | ForEach-Object { "{0:x2}" -f $_ }) -join ":"
}

function Parse-Proxy {
    param([string]$Raw)
    if ($Raw -match "^(http|https|socks5)://") { return $Raw }
    $parts = $Raw -split ":"
    if ($parts.Count -ge 4) {
        return "http://$($parts[2]):$($parts[3])@$($parts[0]):$($parts[1])"
    } elseif ($parts.Count -ge 2) {
        return "http://$($parts[0]):$($parts[1])"
    }
    return $null
}

function Test-ProxyReachable {
    param([string]$ProxyUrl)
    $hp = ($ProxyUrl -replace ".*@", "" -replace ".*://", "") -split ":"
    if ($hp.Count -lt 2) { return $false }
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $result = $tcp.BeginConnect($hp[0], [int]$hp[1], $null, $null)
        $ok = $result.AsyncWaitHandle.WaitOne(5000)
        $tcp.Close()
        return $ok
    } catch { return $false }
}

function Find-RealClaude {
    $npmBase = Join-Path $env:APPDATA "npm\node_modules\@anthropic-ai\claude-code"
    foreach ($name in @("claude.exe", "claude")) {
        $c = Join-Path $npmBase "bin\$name"
        if (Test-Path $c) { return $c }
    }
    return $null
}

function Get-CurrentEnv { return Read-FileValue (Join-Path $CAC_DIR "current") }

function Get-EnvDir {
    param([string]$Name)
    return Join-Path $ENVS_DIR $Name
}

# Ensure ~/.cac/bin sits BEFORE npm's dir in the user PATH so `claude` resolves
# to our wrapper. Only rewrites when actually out of order — preserves existing
# ordering otherwise. Returns $true if PATH was modified.
function Ensure-CacInPath {
    $binDir = (Join-Path $CAC_DIR "bin").TrimEnd("\")
    $npmDir = (Join-Path $env:APPDATA "npm").TrimEnd("\")
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if (-not $userPath) { $userPath = "" }
    $parts = [System.Collections.ArrayList]@()
    foreach ($p in ($userPath -split ";")) { if ($p) { [void]$parts.Add($p) } }
    $binIdx = -1; $npmIdx = -1
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $t = $parts[$i].TrimEnd("\")
        if ($binIdx -lt 0 -and $t -eq $binDir) { $binIdx = $i }
        if ($npmIdx -lt 0 -and $t -eq $npmDir) { $npmIdx = $i }
    }
    # Already correct: bin present and (npm absent OR bin before npm)
    if ($binIdx -ge 0 -and ($npmIdx -lt 0 -or $binIdx -lt $npmIdx)) { return $false }
    # Drop any existing bin entry
    $rest = [System.Collections.ArrayList]@()
    foreach ($p in $parts) { if ($p.TrimEnd("\") -ne $binDir) { [void]$rest.Add($p) } }
    # Find npm position in rest; insert bin right before it, else at front
    $at = 0
    for ($i = 0; $i -lt $rest.Count; $i++) { if ($rest[$i].TrimEnd("\") -eq $npmDir) { $at = $i; break } }
    [void]$rest.Insert($at, $binDir)
    [Environment]::SetEnvironmentVariable("PATH", ($rest -join ";"), "User")
    return $true
}

# Which `claude` does a fresh shell actually run? Returns "wrapper", "npm", or "none".
function Test-ClaudeResolution {
    $binDir = Join-Path $CAC_DIR "bin"
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $machPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    foreach ($dir in (("$userPath;$machPath") -split ";")) {
        if (-not $dir) { continue }
        foreach ($n in @("claude.ps1", "claude.cmd", "claude.exe", "claude")) {
            if (Test-Path (Join-Path $dir $n)) {
                if ($dir.TrimEnd("\") -eq $binDir.TrimEnd("\")) { return "wrapper" }
                return "npm"
            }
        }
    }
    return "none"
}

function Update-Statsig {
    param([string]$StableId)
    $d = Join-Path $env:USERPROFILE ".claude\statsig"
    if (-not (Test-Path $d)) { return }
    Get-ChildItem (Join-Path $d "statsig.stable_id.*") -ErrorAction SilentlyContinue | ForEach-Object {
        if ((Get-Content $_.FullName -Raw).Trim() -ne "`"$StableId`"") { Set-Content $_.FullName "`"$StableId`"" }
    }
}

function Update-ClaudeJsonUserId {
    param([string]$UserId)
    $p = Join-Path $env:USERPROFILE ".claude.json"
    if (-not (Test-Path $p)) { return }
    # node instead of ConvertFrom-Json: PS is case-insensitive on keys and
    # chokes on .claude.json "projects" paths that differ only by case.
    # Script goes via a temp file — PS mangles quotes when passing -e inline.
    $js = Join-Path $env:TEMP "cac-set-userid.js"
    Set-Content $js @'
const fs=require("fs"),p=process.argv[2],w=process.argv[3];
const j=JSON.parse(fs.readFileSync(p,"utf8"));
if(j.userID!==w){j.userID=w;fs.writeFileSync(p,JSON.stringify(j,null,2));}
'@ -Encoding ASCII
    & node $js $p $UserId 2>$null
}

function Write-Wrapper {
    $binDir = Join-Path $CAC_DIR "bin"
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null

    # CMD wrapper
    $cmd = @'
@echo off
setlocal enabledelayedexpansion
set "CAC_DIR=%USERPROFILE%\.cac"
set "ENVS_DIR=!CAC_DIR!\envs"
if not exist "!CAC_DIR!\current" (
    echo [cac] no active env >&2 & exit /b 1
)
for /f "usebackq delims=" %%i in ("!CAC_DIR!\current") do set "ENV_NAME=%%i"
set "ENV_DIR=!ENVS_DIR!\!ENV_NAME!"
if exist "!ENV_DIR!\proxy" (
    for /f "usebackq delims=" %%i in ("!ENV_DIR!\proxy") do set "PROXY=%%i"
    set "HTTPS_PROXY=!PROXY!" & set "HTTP_PROXY=!PROXY!"
    set "ALL_PROXY=!PROXY!" & set "NO_PROXY=localhost,127.0.0.1"
)
if exist "!ENV_DIR!\tz" (
    for /f "usebackq delims=" %%i in ("!ENV_DIR!\tz") do set "TZ=%%i"
)
set "LANG=en_US.UTF-8"
if exist "!ENV_DIR!\lang" (
    for /f "usebackq delims=" %%i in ("!ENV_DIR!\lang") do set "LANG=%%i"
)
set "BUN_JSC_useCodeCache=false"
if exist "!ENV_DIR!\stable_id" (
    for /f "usebackq delims=" %%i in ("!ENV_DIR!\stable_id") do set "STABLE_ID=%%i"
    for %%f in ("%USERPROFILE%\.claude\statsig\statsig.stable_id.*") do (
        if exist "%%f" echo "!STABLE_ID!"> "%%f"
    )
)
for /f "usebackq delims=" %%i in ("!CAC_DIR!\real_claude") do set "REAL_CLAUDE=%%i"
"!REAL_CLAUDE!" %*
exit /b !ERRORLEVEL!
'@

    # PowerShell wrapper
    $ps1 = @'
$ErrorActionPreference = "SilentlyContinue"
$d = Join-Path $env:USERPROFILE ".cac"
$cf = Join-Path $d "current"
if (-not (Test-Path $cf)) { Write-Error "[cac] no active env"; exit 1 }
$en = (Get-Content $cf -Raw).Trim()
$ed = Join-Path $d "envs\$en"
$pf = Join-Path $ed "proxy"
if (Test-Path $pf) {
    $px = (Get-Content $pf -Raw).Trim()
    $env:HTTPS_PROXY=$px; $env:HTTP_PROXY=$px
    $env:ALL_PROXY=$px; $env:NO_PROXY="localhost,127.0.0.1"
}
$tf = Join-Path $ed "tz"
if (Test-Path $tf) { $env:TZ = (Get-Content $tf -Raw).Trim() }
$lf = Join-Path $ed "lang"
if (Test-Path $lf) { $env:LANG = (Get-Content $lf -Raw).Trim() } else { $env:LANG = "en_US.UTF-8" }
# claude.exe ships precompiled JSC bytecode; without this the patched JS source is never executed
$env:BUN_JSC_useCodeCache = "false"
$sf = Join-Path $ed "stable_id"
if (Test-Path $sf) {
    $sid = (Get-Content $sf -Raw).Trim()
    $sd = Join-Path $env:USERPROFILE ".claude\statsig"
    if (Test-Path $sd) {
        Get-ChildItem (Join-Path $sd "statsig.stable_id.*") -ErrorAction SilentlyContinue | ForEach-Object {
            if ((Get-Content $_.FullName -Raw).Trim() -ne "`"$sid`"") { Set-Content $_.FullName "`"$sid`"" }
        }
    }
}
$uf = Join-Path $ed "user_id"
if (Test-Path $uf) {
    $cj = Join-Path $env:USERPROFILE ".claude.json"
    if (Test-Path $cj) {
        $js = Join-Path $env:TEMP "cac-set-userid.js"
        Set-Content $js 'const fs=require("fs"),p=process.argv[2],w=process.argv[3];const j=JSON.parse(fs.readFileSync(p,"utf8"));if(j.userID!==w){j.userID=w;fs.writeFileSync(p,JSON.stringify(j,null,2));}' -Encoding ASCII
        & node $js $cj (Get-Content $uf -Raw).Trim() 2>$null
    }
}
$real = (Get-Content (Join-Path $d "real_claude") -Raw).Trim()
if (-not (Test-Path $real)) { Write-Error "[cac] claude not found"; exit 1 }
& $real @args
exit $LASTEXITCODE
'@
    $ps1Path = Join-Path $binDir "claude.ps1"
    $cmdPath = Join-Path $binDir "claude.cmd"
    $changed = $false
    if ((Read-FileValue $ps1Path) -ne $ps1.Trim()) { Set-Content $ps1Path $ps1 -Encoding UTF8; $changed = $true }
    if ((Read-FileValue $cmdPath) -ne $cmd.Trim()) { Set-Content $cmdPath $cmd -Encoding ASCII; $changed = $true }
    return $changed
}
