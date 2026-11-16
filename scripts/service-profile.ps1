[CmdletBinding()]
param(
    [string]$ProfilePath = (Join-Path $env:USERPROFILE '.cac\desktop\1'),
    [string]$Name = 'desktop-1',
    [string]$DataRoot = 'C:\ProgramData\CAC'
)

$ErrorActionPreference = 'Stop'

$identitySource = Join-Path $ProfilePath 'identity.json'
if (-not (Test-Path -LiteralPath $identitySource)) {
    throw "identity.json not found: $identitySource"
}

$identity = Get-Content -LiteralPath $identitySource -Raw | ConvertFrom-Json
if (-not $identity.mac_address -or -not $identity.machine_id) {
    throw "identity.json is missing mac_address or machine_id: $identitySource"
}

$profileDir = Join-Path $DataRoot "profiles\$Name"
$profileIdentity = Join-Path $profileDir 'identity.json'
$logDir = Join-Path $DataRoot 'logs'
New-Item -ItemType Directory -Force -Path $profileDir, $logDir | Out-Null
Copy-Item -LiteralPath $identitySource -Destination $profileIdentity -Force
$nativeAudit = Join-Path $logDir 'cowork-svc-native.jsonl'
if (-not (Test-Path -LiteralPath $nativeAudit)) {
    New-Item -ItemType File -Path $nativeAudit | Out-Null
}

$cpuManifest = Join-Path $profileDir 'service-cpu-manifest.txt'
$manifestLine = $null
try {
    & (Join-Path $PSScriptRoot 'build-cowork-cpu-manifest.ps1') -Output $cpuManifest | Out-Null
    if (Test-Path -LiteralPath $cpuManifest) {
        $manifestLine = "manifest=$cpuManifest"
    }
} catch {
    Write-Warning "CPU manifest generation skipped: $($_.Exception.Message)"
}

$iniPath = Join-Path $DataRoot 'active-profile.ini'
$lines = @(
    "profile_dir=$profileDir"
    "profile_identity=$profileIdentity"
    "mac=$($identity.mac_address)"
    "machine_id=$($identity.machine_id)"
    "hostname=$($identity.hostname)"
    "username=$($identity.username)"
    'read_policy=profile'
    'cpuid_mode=neutral'
    'redirect_ant_did=1'
    "audit=$nativeAudit"
)
if ($manifestLine) { $lines += $manifestLine }
$lines | Set-Content -LiteralPath $iniPath -Encoding Unicode

# Keep the handoff readable by LocalSystem and Administrators only.
& icacls.exe $DataRoot /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "icacls failed with exit code $LASTEXITCODE"
}
Get-ChildItem -LiteralPath $DataRoot -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    & icacls.exe $_.FullName /reset | Out-Null
    & icacls.exe $_.FullName /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
}

[pscustomobject]@{
    profile_dir = $profileDir
    profile_identity = $profileIdentity
    active_profile = $iniPath
    mac = [string]$identity.mac_address
    machine_id = [string]$identity.machine_id
    hostname = [string]$identity.hostname
} | ConvertTo-Json -Depth 4
