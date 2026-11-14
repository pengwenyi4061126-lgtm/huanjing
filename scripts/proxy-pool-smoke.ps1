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
    $explicit = Set-CacProxyBinding -AccountKey 'desktop:single-key-check' -ProxyId ([string]$state.proxies[0].id)
    if ($null -eq $explicit -or [string]$explicit.accountKey -ne 'desktop:single-key-check') { throw 'explicit single-key bind mismatch' }
    Remove-CacProxyBinding -AccountKey 'desktop:single-key-check' | Out-Null
    $keys = @('account-1','account-2','account-3','account-4')
    $result = Rebalance-CacProxyBindings -AccountKeys $keys
    if (@($result.state.bindings).Count -ne 4) { throw 'binding count mismatch at hard capacity' }
    if ([bool]$result.warning.warning) { throw 'capacity warning was raised below hard capacity' }
    $counts = @($result.state.bindings | Group-Object proxyId)
    if ($counts.Count -ne 2 -or @($counts | Where-Object { $_.Count -ne 2 }).Count -ne 0) { throw 'accountsPerProxy distribution mismatch' }
    try {
        Rebalance-CacProxyBindings -AccountKeys ($keys + 'account-5') | Out-Null
        throw 'capacity exhaustion was not rejected'
    } catch {
        if ($_.Exception.Message -notmatch 'capacity exhausted') { throw }
    }
    $warning = Get-CacProxyPoolCapacityWarning -State (Get-CacProxyPoolState) -AccountCount 5
    if (-not [bool]$warning.warning) { throw 'capacity warning was not raised above hard capacity' }
    $bound = Get-CacProxyForAccount -AccountKey 'account-1'
    if ($null -eq $bound -or $bound.url -notlike 'socks5h://*') { throw 'account binding lookup failed' }
    Set-Content -LiteralPath $path -Value '{"version":99,"settings":{},"proxies":[],"bindings":[]}' -Encoding ASCII
    try {
        Get-CacProxyPoolState | Out-Null
        throw 'unknown proxy pool schema was accepted'
    } catch {
        if ($_.Exception.Message -notmatch 'cannot be read or normalized|Unsupported proxy pool schema') { throw }
    }
    Set-Content -LiteralPath $path -Value '{"version":1,"settings":{},"proxies":[{"id":"bad","url":"not a proxy"}],"bindings":[]}' -Encoding ASCII
    try {
        Get-CacProxyPoolState | Out-Null
        throw 'invalid proxy entry was accepted'
    } catch {
        if ($_.Exception.Message -notmatch 'cannot be read or normalized|invalid proxy URL') { throw }
    }
    Write-Host '[PASS] proxy pool normalization, auto binding and capacity warning' -ForegroundColor Green
    exit 0
} finally {
    [Environment]::SetEnvironmentVariable('CAC_PROXY_POOL_PATH', $oldPath, 'Process')
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
