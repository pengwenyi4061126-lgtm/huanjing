# Deterministic A/B Profile isolation check.
[CmdletBinding()]
param(
    [string[]]$EnvNames
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "lib.ps1")

function Invoke-ProfileProbe([System.Collections.IDictionary]$Environment, [string]$ConfigMarker, [string]$HomeMarker) {
    $node = (Get-Command node -ErrorAction SilentlyContinue).Source
    if (-not $node) { throw "node not found" }
    $probeRoot = Join-Path $CAC_DIR "audit"
    New-Item -ItemType Directory -Path $probeRoot -Force | Out-Null
    $probe = Join-Path $probeRoot "profile-probe-$([guid]::NewGuid().ToString('N')).js"
    $source = @'
const fs = require("fs"), os = require("os"), path = require("path");
const configMarker = process.env.CAC_PROBE_CONFIG_FILE || "";
const homeMarker = process.env.CAC_PROBE_HOME_FILE || "";
let username = "";
try { username = os.userInfo().username || ""; } catch (_) {}
const macs = [];
try {
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of (entries || [])) {
      if (entry && entry.mac && entry.mac !== "00:00:00:00:00:00") macs.push(entry.mac);
    }
  }
} catch (_) {}
console.log(JSON.stringify({
  homedir: os.homedir(),
  userprofile: process.env.USERPROFILE || "",
  config: process.env.CLAUDE_CONFIG_DIR || "",
  appdata: process.env.APPDATA || "",
  localappdata: process.env.LOCALAPPDATA || "",
  temp: process.env.TEMP || "",
  tmp: process.env.TMP || "",
  hostname: os.hostname(),
  username,
  macSeed: process.env.CAC_MAC || "",
  macs,
  machineId: process.env.CAC_MACHINE_ID || "",
  hookMode: process.env.CAC_HOOK_MODE || "",
  configMarker: !!configMarker && fs.existsSync(path.join(process.env.CLAUDE_CONFIG_DIR, configMarker)),
  homeMarker: !!homeMarker && fs.existsSync(path.join(os.homedir(), homeMarker)),
}));
'@
    Set-Content -LiteralPath $probe -Value $source -Encoding ASCII
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $node
        $psi.Arguments = "`"$probe`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        foreach ($key in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "TZ")) {
            [void]$psi.EnvironmentVariables.Remove($key)
        }
        foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }
        $psi.EnvironmentVariables["CAC_PROBE_CONFIG_FILE"] = $ConfigMarker
        $psi.EnvironmentVariables["CAC_PROBE_HOME_FILE"] = $HomeMarker
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $out = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { throw "probe exit code $($proc.ExitCode)" }
        return ($out.Trim() | ConvertFrom-Json)
    } finally {
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
}

function Get-PathState([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{ exists = $false; kind = "missing"; entries = 0; sha256 = $null }
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer) {
            return [ordered]@{
                exists = $true
                kind = "file"
                entries = 1
                sha256 = Get-CacSha256 $Path
            }
        }
        $lines = @(
            Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $relative = $_.FullName.Substring($Path.Length).TrimStart("\")
                    "{0}|{1}|{2}" -f $relative, $_.Length, $_.LastWriteTimeUtc.Ticks
                }
        )
        $payload = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
        $sha = [BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($payload)).Replace("-", "").ToUpperInvariant()
        return [ordered]@{ exists = $true; kind = "directory"; entries = $lines.Count; sha256 = $sha }
    } catch {
        return [ordered]@{ exists = $true; kind = "unreadable"; entries = 0; sha256 = $null; error = $_.Exception.Message }
    }
}

if ($null -eq $EnvNames -or $EnvNames.Count -eq 0) {
    $EnvNames = @(Get-ChildItem -LiteralPath $ENVS_DIR -Directory -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name | Where-Object { Test-ProfileName $_ })
}
$EnvNames = @($EnvNames | Select-Object -Unique)

Write-Host ""
Write-Host "Profile A/B isolation check" -ForegroundColor Cyan
if ($EnvNames.Count -lt 2) {
    Write-Host "  [FAIL] 至少需要两个 Profile 才能执行 A/B 交叉读取测试" -ForegroundColor Red
    exit 1
}

$globalPaths = @(
    (Join-Path $env:USERPROFILE ".claude"),
    (Join-Path $env:USERPROFILE ".claude.json")
)
$globalBefore = [ordered]@{}
foreach ($path in $globalPaths) { $globalBefore[$path] = Get-PathState $path }

$profiles = @{}
foreach ($name in $EnvNames) {
    $profiles[$name] = Ensure-ProfileLayout $name
    Remove-Item -LiteralPath $profiles[$name].HookAuditPath -Force -ErrorAction SilentlyContinue
}

$results = @()
foreach ($sourceName in $EnvNames) {
    $sourcePaths = $profiles[$sourceName]
    $markerName = "__cac_profile_probe_$([guid]::NewGuid().ToString('N')).txt"
    $homeMarkerName = ".__cac_home_probe_$([guid]::NewGuid().ToString('N')).json"
    Set-Content -LiteralPath (Join-Path $sourcePaths.ConfigDir $markerName) -Value $sourceName -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $sourcePaths.HomeDir $homeMarkerName) -Value $sourceName -Encoding ASCII
    try {
        foreach ($targetName in $EnvNames) {
            $targetPaths = $profiles[$targetName]
            $values = Get-ProfileEnvironment $targetPaths
            $probe = Invoke-ProfileProbe $values $markerName $homeMarkerName
            $targetIdentity = Read-ProfileIdentity $targetPaths
            $expectedUser = "user-$targetName"
            $hookEvents = @()
            if (Test-Path -LiteralPath $targetPaths.HookAuditPath) {
                $hookEvents = @(Get-Content -LiteralPath $targetPaths.HookAuditPath -ErrorAction SilentlyContinue |
                    ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
                    Where-Object { $null -ne $_ })
            }
            $hookUsed = @($hookEvents | Where-Object { $_.surface -in @("os.hostname", "os.networkInterfaces", "os.userInfo") }).Count -gt 0
            $identityOk = ($probe.hostname -eq [string]$targetIdentity.hostname -and
                $probe.username -eq $expectedUser -and
                $probe.machineId -eq [string]$targetIdentity.machine_id -and
                $probe.macSeed -eq [string]$targetIdentity.mac_address -and
                @($probe.macs).Count -gt 0 -and
                $probe.hookMode -eq "node-userland-only" -and $hookUsed)
            $expectedSource = ($targetName -eq $sourceName)
            $pathOk = ($probe.homedir -eq $targetPaths.HomeDir -and
                $probe.userprofile -eq $targetPaths.HomeDir -and
                $probe.config -eq $targetPaths.ConfigDir -and
                $probe.appdata -eq $targetPaths.AppData -and
                $probe.localappdata -eq $targetPaths.LocalAppData -and
                $probe.temp -eq $targetPaths.TempDir -and
                $probe.tmp -eq $targetPaths.TempDir)
            $crossReadOk = $false
            if ($expectedSource) {
                $crossReadOk = ([bool]$probe.configMarker -and [bool]$probe.homeMarker)
            } else {
                $crossReadOk = (-not [bool]$probe.configMarker -and -not [bool]$probe.homeMarker)
            }
            $ok = $pathOk -and $crossReadOk -and $identityOk
            $status = "FAIL"
            $color = "Red"
            if ($ok) { $status = "PASS"; $color = "Green" }
            Write-Host ("  [{0}] {1} -> {2}: paths={3}, identity={4}, hook={5}, cross-read={6}" -f $status, $sourceName, $targetName, $pathOk, $identityOk, $hookUsed, $crossReadOk) -ForegroundColor $color
            $results += [ordered]@{
                sourceProfile = $sourceName
                targetProfile = $targetName
                status = $status
                pathIsolation = $pathOk
                crossReadIsolation = $crossReadOk
                identityIsolation = $identityOk
                nodeHookUsed = $hookUsed
                homedir = $probe.homedir
                config = $probe.config
                temp = $probe.temp
                runtimeHostname = $probe.hostname
                runtimeUsername = $probe.username
                runtimeMacSeed = $probe.macSeed
                runtimeMacs = $probe.macs
            }
        }
    } finally {
        Remove-Item -LiteralPath (Join-Path $sourcePaths.ConfigDir $markerName) -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $sourcePaths.HomeDir $homeMarkerName) -Force -ErrorAction SilentlyContinue
    }
}

$globalAfter = [ordered]@{}
$globalUnchanged = $true
foreach ($path in $globalPaths) {
    $globalAfter[$path] = Get-PathState $path
    $beforeJson = $globalBefore[$path] | ConvertTo-Json -Compress -Depth 5
    $afterJson = $globalAfter[$path] | ConvertTo-Json -Compress -Depth 5
    if ($beforeJson -ne $afterJson) { $globalUnchanged = $false }
    if (Test-Path -LiteralPath $path) {
        Write-Host "  [INFO] 全局路径未修改: $path" -ForegroundColor Yellow
    }
}
if (-not $globalUnchanged) {
    Write-Host "  [FAIL] 检测到全局 .claude/.claude.json 状态变化" -ForegroundColor Red
}

$evidence = [ordered]@{
    schema = 1
    checkedUtc = [DateTime]::UtcNow.ToString("o")
    profiles = $results
    globalPaths = $globalPaths
    globalPathsBefore = $globalBefore
    globalPathsAfter = $globalAfter
    globalPathsModified = (-not $globalUnchanged)
    note = "本测试验证 Profile 路径、Node 用户态身份 Hook 与默认 home/config 路径不交叉；不代表 Native API、驱动或物理硬件隔离。"
}
$auditDir = Join-Path $CAC_DIR "audit"
New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
$outPath = Join-Path $auditDir "profile-check.json"
Set-Content -LiteralPath $outPath -Value ($evidence | ConvertTo-Json -Depth 8) -Encoding UTF8
Write-Host "  证据: $outPath" -ForegroundColor DarkGray
if (-not $globalUnchanged -or @($results | Where-Object { $_.status -eq "FAIL" }).Count -gt 0) { exit 1 }
