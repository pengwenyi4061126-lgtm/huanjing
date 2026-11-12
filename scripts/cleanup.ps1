#!/usr/bin/env pwsh
# Claude Code Tracking Data Cleanup — Windows
# Clears all tracking data while preserving config (MCP, Skills, Settings, Hooks)
$ErrorActionPreference = "Stop"

function Write-OK($t) { Write-Host "  [OK] $t" -ForegroundColor Green }
function Write-Skip($t) { Write-Host "  [SKIP] $t" -ForegroundColor Yellow }
function Write-Del($t) { Write-Host "  [DEL] $t" -ForegroundColor Red }

$claudeJson = Join-Path $env:USERPROFILE ".claude.json"
$claudeDir = Join-Path $env:USERPROFILE ".claude"

Write-Host ""
Write-Host "Claude Code Cleanup — clearing tracking data (config preserved)" -ForegroundColor Cyan
Write-Host ""

# ── 1. Strip identity + account keys from .claude.json ──
# Done in node: PowerShell's ConvertFrom-Json is case-insensitive on keys and
# fails on .claude.json "projects" paths differing only by case; ConvertTo-Json
# silently truncates deep objects. node preserves the file byte-for-byte otherwise.
Write-Host "Resetting device identity & account linkage..." -ForegroundColor White
if (Test-Path $claudeJson) {
    $js = Join-Path $env:TEMP "cac-cleanup-json.js"
    Set-Content $js @'
const fs = require("fs"), p = process.argv[2];
const keys = ["userID","anonymousId","firstStartTime","claudeCodeFirstTokenDate",
  "oauthAccount","s1mAccessCache","groveConfigCache","passesEligibilityCache",
  "clientDataCache","cachedExtraUsageDisabledReason","githubRepoPaths","hasExtraUsageEnabled"];
const j = JSON.parse(fs.readFileSync(p, "utf8"));
const removed = keys.filter(k => k in j);
removed.forEach(k => delete j[k]);
if (removed.length) fs.writeFileSync(p, JSON.stringify(j, null, 2));
removed.forEach(k => console.log(k));
'@ -Encoding ASCII
    $removed = @(& node $js $claudeJson 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Write-Skip ".claude.json 解析失败，未修改: $($removed -join ' ')"
    } elseif ($removed.Count -gt 0) {
        $removed | ForEach-Object { Write-Del $_ }
        Write-OK "Removed $($removed.Count) keys from .claude.json"
    } else {
        Write-Skip "No identity/account keys in .claude.json"
    }
} else { Write-Skip ".claude.json not found" }

# ── 2. Clear telemetry, analytics, debug caches ──
Write-Host "Clearing telemetry & caches..." -ForegroundColor White
foreach ($t in @("telemetry", "statsig", "stats-cache.json", "debug")) {
    $p = Join-Path $claudeDir $t
    if (Test-Path $p) { Remove-Item $p -Recurse -Force; Write-Del $t }
}

# ── 3. Clear Credential Manager entries ──
# Match on "target=" not the localized label ("Target:" / "目标:") so it works on any UI language.
# cmdkey /delete needs the full target name including the "LegacyGeneric:target=" prefix.
Write-Host "Clearing Credential Manager..." -ForegroundColor White
$targets = @(cmdkey /list 2>$null | Where-Object { $_ -match 'target=' -and $_ -match '(?i)claude' } | ForEach-Object { ($_ -split ':', 2)[1].Trim() })
if ($targets.Count -eq 0) {
    Write-Skip "No Claude credentials found"
} else {
    foreach ($t in $targets) { cmdkey /delete:"$t" 2>&1 | Out-Null; Write-Del $t }
}

Write-Host ""
Write-Host "Done. Tracking data cleared, config preserved." -ForegroundColor Green
Write-Host "Run 'claude login' to login with new account." -ForegroundColor White
Write-Host ""
