[CmdletBinding()]
param(
    [string]$ArtifactRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts')
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$launcher = Join-Path $root 'native\dist\cac-native-launch.exe'
$dll = Join-Path $root 'native\dist\NativeBridge.dll'
$template = 'C:\ProgramData\CAC\profiles\desktop-1\identity.json'
foreach ($path in @($launcher, $dll, $template)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "missing input: $path" }
}

$id = [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path $ArtifactRoot ("redirect-" + $id)
$profile = Join-Path $testRoot 'profile'
$appdata = Join-Path $testRoot 'appdata'
New-Item -ItemType Directory -Force -Path $profile, $appdata, (Join-Path $appdata 'Claude'),
    (Join-Path $appdata 'Claude-3p') | Out-Null
Copy-Item -LiteralPath $template -Destination (Join-Path $profile 'identity.json') -Force

$script = Join-Path $testRoot 'write-antdid.cmd'
@(
    '@echo off'
    'echo ant-did-test> "%APPDATA%\Claude\ant-did"'
    'echo claude-3p-test> "%APPDATA%\Claude-3p\ant-did"'
) | Set-Content -LiteralPath $script -Encoding ASCII

$saved = @{}
foreach ($name in @('CAC_PROFILE_DIR', 'CAC_PROFILE_IDENTITY', 'CAC_NATIVE_DLL',
                    'CAC_REDIRECT_ANT_DID', 'CAC_NATIVE_AUDIT', 'APPDATA')) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $env:CAC_PROFILE_DIR = $profile
    $env:CAC_PROFILE_IDENTITY = Join-Path $profile 'identity.json'
    $env:CAC_NATIVE_DLL = $dll
    $env:CAC_REDIRECT_ANT_DID = '1'
    $env:CAC_NATIVE_AUDIT = Join-Path $testRoot 'native.jsonl'
    $env:APPDATA = $appdata

    & $launcher $env:ComSpec '/c' $script
    if ($LASTEXITCODE -ne 0) { throw "launcher failed: $LASTEXITCODE" }
} finally {
    foreach ($name in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
    }
}

$targetAntDid = Join-Path $profile 'ant-did'
$target3p = Join-Path $profile 'Claude-3p\ant-did'
$originalAntDid = Join-Path $appdata 'Claude\ant-did'
$original3p = Join-Path $appdata 'Claude-3p\ant-did'

[pscustomobject]@{
    test_root = $testRoot
    target_ant_did = (Test-Path -LiteralPath $targetAntDid)
    target_claude_3p = (Test-Path -LiteralPath $target3p)
    original_ant_did = (Test-Path -LiteralPath $originalAntDid)
    original_claude_3p = (Test-Path -LiteralPath $original3p)
    target_ant_did_content = if (Test-Path -LiteralPath $targetAntDid) {
        (Get-Content -LiteralPath $targetAntDid -Raw).Trim()
    } else { $null }
    target_claude_3p_content = if (Test-Path -LiteralPath $target3p) {
        (Get-Content -LiteralPath $target3p -Raw).Trim()
    } else { $null }
} | ConvertTo-Json -Depth 4

if (-not (Test-Path -LiteralPath $targetAntDid) -or
    -not (Test-Path -LiteralPath $target3p) -or
    (Test-Path -LiteralPath $originalAntDid) -or
    (Test-Path -LiteralPath $original3p)) {
    throw 'redirect verification failed'
}
