#!/usr/bin/env pwsh
# Clear tracking data inside one isolated Profile only.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigDir,
    [Parameter(Mandatory = $true)]
    [string]$HomeDir
)

$ErrorActionPreference = "Stop"

function Write-OK($t) { Write-Host "  [OK] $t" -ForegroundColor Green }
function Write-Skip($t) { Write-Host "  [SKIP] $t" -ForegroundColor Yellow }
function Write-Del($t) { Write-Host "  [DEL] $t" -ForegroundColor Red }

foreach ($dir in @($ConfigDir, $HomeDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

Write-Host ""
Write-Host "Claude Code Cleanup — current Profile only" -ForegroundColor Cyan
Write-Host "  Config: $ConfigDir" -ForegroundColor DarkGray
Write-Host "  Home:   $HomeDir" -ForegroundColor DarkGray
Write-Host ""

Write-Host "Resetting profile identity and account linkage..." -ForegroundColor White
$jsonPaths = @(
    (Join-Path $ConfigDir ".claude.json"),
    (Join-Path $HomeDir ".claude.json")
)
foreach ($claudeJson in $jsonPaths | Select-Object -Unique) {
    if (-not (Test-Path $claudeJson)) { continue }
    $js = Join-Path $ConfigDir ".cac-cleanup-json.js"
    $source = @'
const fs = require("fs"), p = process.argv[2];
const keys = ["userID", "anonymousId", "firstStartTime", "claudeCodeFirstTokenDate",
  "oauthAccount", "s1mAccessCache", "groveConfigCache", "passesEligibilityCache",
  "clientDataCache", "cachedExtraUsageDisabledReason", "githubRepoPaths", "hasExtraUsageEnabled"];
const j = JSON.parse(fs.readFileSync(p, "utf8").replace(/^\uFEFF/, ""));
const removed = keys.filter(k => k in j);
removed.forEach(k => delete j[k]);
if (removed.length) fs.writeFileSync(p, JSON.stringify(j, null, 2));
removed.forEach(k => console.log(k));
'@
    Set-Content $js $source -Encoding ASCII
    try {
        $removed = @(& node $js $claudeJson 2>&1)
        if ($LASTEXITCODE -ne 0) {
            Write-Skip "$claudeJson 解析失败，未修改"
        } elseif ($removed.Count -gt 0) {
            $removed | ForEach-Object { Write-Del "$(Split-Path $claudeJson -Leaf): $_" }
            Write-OK "已清理 $claudeJson"
        } else {
            Write-Skip "$claudeJson 没有待清理字段"
        }
    } finally {
        Remove-Item -LiteralPath $js -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Clearing profile telemetry and caches..." -ForegroundColor White
foreach ($name in @("telemetry", "statsig", "stats-cache.json", "debug", "Crashpad")) {
    $path = Join-Path $ConfigDir $name
    if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force; Write-Del $path }
}

Write-Host "Credential Manager: unchanged" -ForegroundColor White
Write-Skip "Windows Credential Manager is account-global; profile cleanup does not modify it"

Write-Host ""
Write-OK "Current Profile tracking data cleared; global user files were not modified"
Write-Host ""
