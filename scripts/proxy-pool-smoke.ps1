#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$module = Join-Path $PSScriptRoot 'proxy-pool-lib.ps1'
. $module
$oldPath = [Environment]::GetEnvironmentVariable('CAC_PROXY_POOL_PATH', 'Process')
$path = Join-Path $env:TEMP ("cac-proxy-pool-smoke-{0}.json" -f ([guid]::NewGuid().ToString('N')))
try {
    [Environment]::SetEnvironmentVariable('CAC_PROXY_POOL_PATH', $path, 'Process')
    Add-CacProxyPoolEntry 'socks5://user:pass@127.0.0.1:21001' | Out-Null
    Add-CacProxyPoolEntry 'socks5h://user:pass@127.0.0.1:21002' | Out-Null
    $state = Get-CacProxyPoolState
    if (@($state.proxies).Count -ne 2) { throw 'proxy count mismatch' }
    if (@($state.proxies | Where-Object { $_.url -notlike 'socks5h://*' }).Count -ne 0) { throw 'socks5 was not normalized to socks5h' }
    $keys = @('account-1','account-2','account-3','account-4','account-5')
    $result = Rebalance-CacProxyBindings -AccountKeys $keys
    if (@($result.state.bindings).Count -ne 5) { throw 'binding count mismatch' }
    if (-not [bool]$result.warning.warning) { throw 'capacity warning was not raised at 2x proxy count' }
    $bound = Get-CacProxyForAccount -AccountKey 'account-1'
    if ($null -eq $bound -or $bound.url -notlike 'socks5h://*') { throw 'account binding lookup failed' }
    Write-Host '[PASS] proxy pool normalization, auto binding and capacity warning' -ForegroundColor Green
    exit 0
} finally {
    [Environment]::SetEnvironmentVariable('CAC_PROXY_POOL_PATH', $oldPath, 'Process')
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
