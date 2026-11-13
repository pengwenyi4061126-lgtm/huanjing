[CmdletBinding()]
param(
    [string]$Profile,
    [string]$Probe
)

$ErrorActionPreference = 'Stop'
$testsRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Profile)) { $Profile = Join-Path $testsRoot 'smoke-profile' }
if ([string]::IsNullOrWhiteSpace($Probe)) { $Probe = Join-Path $testsRoot 'bin\network_probe.exe' }
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$launcher = Join-Path $dist 'cac-native-launch.exe'
$dll = Join-Path $dist 'NativeBridge.dll'
$identity = Join-Path $Profile 'identity.json'
$audit = Join-Path $Profile 'audit\wfp-smoke.jsonl'

foreach ($path in @($launcher, $dll, $Probe, $identity)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "WFP smoke input is missing: $path"
    }
}
New-Item -ItemType Directory -Path (Split-Path -Parent $audit) -Force | Out-Null
Remove-Item -LiteralPath $audit -Force -ErrorAction SilentlyContinue

$env:CAC_PROFILE_DIR = $Profile
$env:CAC_PROFILE_IDENTITY = $identity
$env:CAC_NATIVE_AUDIT = $audit
$env:CAC_NATIVE_DLL = $dll
$env:CAC_NATIVE_READ_POLICY = 'profile'
$env:CAC_NATIVE_CPUID_MODE = 'neutral'
$env:CAC_NETWORK_MODE = 'enforce'
$env:CAC_NETWORK_ENFORCE = '1'
$env:CAC_WFP_REQUIRED = '1'
$env:CAC_KERNEL_POLICY_REQUIRED = '1'

$probeOutput = @(& $launcher $Probe 2>&1)
$probeOutput | ForEach-Object { Write-Output $_ }
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    throw "WFP smoke target exited with $exitCode"
}
if (-not (Test-Path -LiteralPath $audit -PathType Leaf)) {
    throw "WFP audit log is missing: $audit"
}

$events = @(Get-Content -LiteralPath $audit | ForEach-Object {
    try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $null -ne $_ })
$kernel = @($events | Where-Object { $_.surface -eq 'kernel.policy' -and $_.action -eq 'verified' })
$wfp = @($events | Where-Object { $_.surface -eq 'wfp.policy' -and $_.action -eq 'installed' })
$failed = @($events | Where-Object { $_.surface -eq 'wfp.policy' -and $_.action -eq 'failed' })

if ($kernel.Count -eq 0) { throw 'Kernel policy verification evidence is missing' }
if ($wfp.Count -eq 0) { throw 'WFP installation evidence is missing' }
if ($failed.Count -ne 0) { throw "WFP installation failure evidence found: $($failed.Count)" }
$probeText = $probeOutput -join [Environment]::NewLine
if ($probeText -match '(?i)VMware|VirtualBox|WireGuard|Tailscale|Teredo|Meta Tunnel') {
    throw 'enforce mode still exposed a known virtual/tunnel adapter'
}

[pscustomobject]@{
    status = 'PASS'
    kernelPolicyVerified = $kernel.Count
    wfpInstalled = $wfp.Count
    audit = $audit
} | ConvertTo-Json
