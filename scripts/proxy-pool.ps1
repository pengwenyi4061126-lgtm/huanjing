#requires -Version 5.1
param(
    [ValidateSet('list','add','remove','bind','unbind','auto-bind','rebalance','unbind-all','settings')][string]$Action = 'list',
    [string]$Proxy,
    [string]$Id,
    [string[]]$AccountKey,
    [string]$AccountsFile,
    [switch]$DisableAuto,
    [int]$AccountsPerProxy = 2,
    [int]$WarningMultiplier = 2
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'proxy-pool-lib.ps1')

function Get-RequestedAccountKeys {
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($AccountKey)) {
        foreach ($part in ([string]$key -split ',')) {
            if (-not [string]::IsNullOrWhiteSpace($part)) { $keys.Add($part.Trim()) }
        }
    }
    if ($AccountsFile) {
        if (-not (Test-Path -LiteralPath $AccountsFile -PathType Leaf)) { throw "Account list does not exist: $AccountsFile" }
        foreach ($line in @(Get-Content -LiteralPath $AccountsFile)) {
            $value = ([string]$line).Trim()
            if ($value -and -not $value.StartsWith('#')) { $keys.Add($value) }
        }
    }
    return @($keys | Sort-Object -Unique)
}

function Show-Pool {
    $state = Get-CacProxyPoolState
    $counts = Get-CacProxyBindingCounts $state
    Write-Host "[PROXY POOL] $(Get-CacProxyPoolPath)"
    Write-Host ("  autoBindOnNewAccount={0} accountsPerProxy={1} warning={2}x" -f $state.settings.autoBindOnNewAccount, $state.settings.accountsPerProxy, $state.settings.warningMultiplier)
    foreach ($proxy in @(Get-CacProxyPoolActiveEntries $state | Sort-Object id)) {
        Write-Host ("  {0}`taccounts={1}`t{2}" -f $proxy.id, $counts[[string]$proxy.id], (Mask-CacProxyUrl $proxy.url))
    }
    foreach ($binding in @($state.bindings | Sort-Object accountKey)) {
        $proxy = Get-CacProxyPoolEntry $state ([string]$binding.proxyId)
        Write-Host ("  BIND`t{0}`t{1}" -f $binding.accountKey, $(if ($proxy) { $proxy.id } else { '<missing>' }))
    }
}

try {
    switch ($Action) {
        'list' { Show-Pool }
        'add' {
            if (-not $Proxy) { $Proxy = [Environment]::GetEnvironmentVariable('CAC_PROXY_POOL_INPUT', 'Process') }
            if (-not $Proxy) { throw 'add requires -Proxy socks5h://user:pass@host:port' }
            $entry = Add-CacProxyPoolEntry -ProxyUrl $Proxy -ProxyId $Id
            Write-Host ("[ADD] {0} {1}" -f $entry.id, (Mask-CacProxyUrl $entry.url)) -ForegroundColor Green
        }
        'remove' {
            if (-not $Id) { throw 'remove requires -Id proxy-xxxxxxxxxxxx' }
            Remove-CacProxyPoolEntry -ProxyId $Id | Out-Null
            Write-Host "[REMOVE] $Id" -ForegroundColor Green
        }
        'bind' {
            $keys = @(Get-RequestedAccountKeys)
            if ($keys.Count -ne 1 -or -not $Id) { throw 'bind requires exactly one -AccountKey and -Id proxy-xxxxxxxxxxxx' }
            $binding = Set-CacProxyBinding -AccountKey ([string]$keys[0]) -ProxyId $Id
            Write-Host ("[BIND] {0} -> {1}" -f $binding.accountKey, $binding.proxyId) -ForegroundColor Green
        }
        'unbind' {
            $keys = @(Get-RequestedAccountKeys)
            if ($keys.Count -ne 1) { throw 'unbind requires exactly one -AccountKey' }
            Remove-CacProxyBinding -AccountKey ([string]$keys[0]) | Out-Null
            Write-Host ("[UNBIND] {0}" -f ([string]$keys[0])) -ForegroundColor Green
        }
        'unbind-all' {
            Clear-CacProxyPoolBindings | Out-Null
            Write-Host '[UNBIND] all account bindings cleared' -ForegroundColor Green
        }
        'settings' {
            Set-CacProxyPoolSettings -AutoBindOnNewAccount (-not $DisableAuto) -AccountsPerProxy $AccountsPerProxy -WarningMultiplier $WarningMultiplier | Out-Null
            Write-Host '[SETTINGS] saved' -ForegroundColor Green
        }
        'auto-bind' {
            $keys = Get-RequestedAccountKeys
            if ($keys.Count -eq 0) { throw 'auto-bind requires -AccountKey or -AccountsFile' }
            $result = Rebalance-CacProxyBindings -AccountKeys $keys -OnlyUnbound
            Show-CacProxyCapacityWarning $result.warning
            Write-Host ("[AUTO-BIND] {0} accounts" -f $keys.Count) -ForegroundColor Green
        }
        'rebalance' {
            $keys = Get-RequestedAccountKeys
            if ($keys.Count -eq 0) { throw 'rebalance requires -AccountKey or -AccountsFile' }
            $result = Rebalance-CacProxyBindings -AccountKeys $keys
            Show-CacProxyCapacityWarning $result.warning
            Write-Host ("[REBALANCE] {0} accounts" -f $keys.Count) -ForegroundColor Green
        }
    }
    if ($Action -ne 'list') { Show-Pool }
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
