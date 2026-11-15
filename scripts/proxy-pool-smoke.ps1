#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$module = Join-Path $PSScriptRoot 'proxy-pool-lib.ps1'
. $module
$oldPath = [Environment]::GetEnvironmentVariable('CAC_PROXY_POOL_PATH', 'Process')
$path = Join-Path $env:TEMP ("cac-proxy-pool-smoke-{0}.json" -f ([guid]::NewGuid().ToString('N')))
try {
    [Environment]::SetEnvironmentVariable('CAC_PROXY_POOL_PATH', $path, 'Process')
    foreach ($legacy in @('127.0.0.1:21003:user:pass', '127.0.0.1|21004|user|pass', 'user:pass@127.0.0.1:21005')) {
        $normalizedLegacy = ConvertTo-CacProxyUrl $legacy
        if ([string]::IsNullOrWhiteSpace($normalizedLegacy) -or $normalizedLegacy -notlike 'socks5h://*') { throw "legacy proxy format was not normalized: $legacy" }
    }
    $encodedCity = ConvertTo-CacProxyUrl 'host.example:1080:miya_g-US_c-Kansas%20City_sid-1:pass'
    $storedUser = ([Uri]$encodedCity).UserInfo.Split(':')[0]
    if ([Uri]::UnescapeDataString($storedUser) -cne 'miya_g-US_c-Kansas%20City_sid-1') { throw 'encoded city was changed in SOCKS username' }
    if ((ConvertTo-CacProxyUrl $encodedCity) -cne $encodedCity) { throw 'encoded proxy changed after pool normalization' }
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
    Clear-CacProxyPoolBindings | Out-Null
    Add-CacProxyPoolEntry 'socks5h://user:pass@127.0.0.1:21003' | Out-Null
    Set-CacProxyPoolSettings -AccountsPerProxy 1 | Out-Null
    $state = Get-CacProxyPoolState
    $ids = @($state.proxies | ForEach-Object { [string]$_.id })
    Set-CacProxyBinding -AccountKey 'claude-code:profile-a' -ProxyId $ids[0] | Out-Null
    Set-CacProxyBinding -AccountKey 'desktop:1' -ProxyId $ids[1] | Out-Null
    $second = Ensure-CacProxyBinding -AccountKey 'desktop:2'
    if ($null -eq $second -or [string]$second.proxyId -ne $ids[2]) { throw 'one-IP-per-account did not use the last free proxy' }
    if ($null -ne (Ensure-CacProxyBinding -AccountKey 'desktop:3')) { throw 'occupied proxy was assigned twice' }
    Remove-CacProxyBinding -AccountKey 'claude-code:profile-a' | Out-Null
    $third = Ensure-CacProxyBinding -AccountKey 'desktop:3'
    if ($null -eq $third -or [string]$third.proxyId -ne $ids[0]) { throw 'deleting an account did not release its proxy' }
    Remove-CacProxyBinding -AccountKey 'desktop:1' | Out-Null
    $code = Ensure-CacProxyBinding -AccountKey 'claude-code:profile-b'
    if ($null -eq $code -or [string]$code.proxyId -ne $ids[1]) { throw 'Desktop deletion did not release its proxy for Claude Code' }
    Remove-CacProxyBinding -AccountKey 'desktop:3' | Out-Null
    Set-CacProxyBinding -AccountKey 'claude-code:old' -ProxyId $ids[0] | Out-Null
    $script:CAC_DIR = Join-Path $env:TEMP ("cac-env-delete-smoke-{0}" -f ([guid]::NewGuid().ToString('N')))
    $script:ENVS_DIR = Join-Path $CAC_DIR 'envs'
    $resolvedTestRoot = [System.IO.Path]::GetFullPath($CAC_DIR)
    $tempPrefix = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    if (-not $resolvedTestRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe test root' }
    try {
        New-Item -ItemType Directory -Path (Join-Path $ENVS_DIR 'active'), (Join-Path $ENVS_DIR 'old') -Force | Out-Null
        $tokens = $null; $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\cac.ps1'), [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) { throw 'cac.ps1 parse failed' }
        $deleteFunction = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Action-EnvDelete' }, $true)
        if ($null -eq $deleteFunction) { throw 'delete action not found' }
        Invoke-Expression $deleteFunction.Extent.Text
        function Get-EnvDir { param($Name) return (Join-Path $script:ENVS_DIR $Name) }
        function Get-CurrentEnv { return 'active' }
        function Show-Menu { return 0 }
        function Read-Input { return 'y' }
        function Wait-AnyKey { }
        function Write-OK { param($Text) }
        function Write-Err { param($Text) throw $Text }
        Action-EnvDelete
        if (@((Get-CacProxyPoolState).bindings | Where-Object { $_.accountKey -eq 'claude-code:old' }).Count -ne 0) { throw 'menu deletion left the proxy bound' }
        if (Test-Path -LiteralPath (Join-Path $ENVS_DIR 'old')) { throw 'deleted profile still exists' }
        if (@(Get-ChildItem -LiteralPath (Join-Path $CAC_DIR 'recycle') -Directory).Count -ne 1) { throw 'deleted profile not in recycle' }
        $released = Ensure-CacProxyBinding -AccountKey 'desktop:3'
        if ($null -eq $released -or [string]$released.proxyId -ne $ids[0]) { throw 'menu deletion did not free capacity' }
    } finally {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
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
