$ErrorActionPreference = 'Stop'
$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $env:TEMP ('cac-audit-smoke-' + [guid]::NewGuid().ToString('N'))))
$expectedParent = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
if (-not $temporaryRoot.StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Audit fixture path is outside TEMP'
}
$profileRoot = Join-Path $temporaryRoot '.cac\desktop\fixture'
$auditRoot = Join-Path $profileRoot 'audit'
$auditFile = Join-Path $auditRoot 'native-hook.jsonl'
$auditScript = Join-Path $PSScriptRoot 'desktop-native-check.ps1'
$originalUserProfile = $env:USERPROFILE

try {
    New-Item -ItemType Directory -Path $auditRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $profileRoot 'proxy') -Value 'socks5h://fixture.invalid:3010' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $profileRoot 'network_mode') -Value 'enforce' -Encoding ASCII
    $events = @(
        @{ utc = '2026-11-15T00:00:00Z'; pid = 999999; surface = 'native.bridge'; action = 'attach'; detail = 'process=main' },
        @{ utc = '2026-11-15T00:00:01Z'; pid = 999999; surface = 'native.bridge'; action = 'ready'; detail = '' },
        @{ utc = '2026-11-15T00:00:02Z'; pid = 999999; surface = 'wfp.policy'; action = 'installed'; detail = '' }
    )
    $env:USERPROFILE = $temporaryRoot
    $events | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content -LiteralPath $auditFile -Encoding UTF8
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $auditScript -Profile fixture -AllowPartial *> $null
    $withoutRoute = Get-Content -LiteralPath (Join-Path $auditRoot 'desktop-native-check.json') -Raw | ConvertFrom-Json
    if ($withoutRoute.status -ne 'FAIL' -or 'proxy-runtime-evidence-missing' -notin $withoutRoute.failureReasons) {
        throw 'WFP-only evidence incorrectly passed the proxy route check'
    }

    $events += @{ utc = '2026-11-15T00:00:03Z'; pid = 999999; surface = 'api.winhttp.proxy'; action = 'enforce-local'; detail = '' }
    $events | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content -LiteralPath $auditFile -Encoding UTF8
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $auditScript -Profile fixture -AllowPartial *> $null
    $withRoute = Get-Content -LiteralPath (Join-Path $auditRoot 'desktop-native-check.json') -Raw | ConvertFrom-Json
    if ('proxy-runtime-evidence-missing' -in $withRoute.failureReasons -or $withRoute.session.proxyRuntimeEvents -ne 1) {
        throw 'Local proxy evidence was not recognized'
    }
    Write-Host '[PASS] WFP-only evidence fails; local proxy route evidence is counted separately'
} finally {
    $env:USERPROFILE = $originalUserProfile
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolved = [IO.Path]::GetFullPath($temporaryRoot)
        if ($resolved.StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path -Leaf $resolved) -like 'cac-audit-smoke-*') {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
}
