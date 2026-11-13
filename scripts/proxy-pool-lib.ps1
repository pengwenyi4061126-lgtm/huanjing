# cac-windows — profile proxy pool and DNS-safe local relay helpers
# PowerShell 5.1 compatible. Launched processes receive only the local relay.

$script:CacProxyPoolSchema = 1

function Get-CacProxyPoolPath {
    $configured = [Environment]::GetEnvironmentVariable('CAC_PROXY_POOL_PATH', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($configured)) { return [System.IO.Path]::GetFullPath($configured) }
    return [System.IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.cac\proxy-pool.json'))
}

function New-CacProxyPoolState {
    return [pscustomobject][ordered]@{
        version  = $script:CacProxyPoolSchema
        settings = [pscustomobject][ordered]@{
            autoBindOnNewAccount = $true
            accountsPerProxy     = 2
            warningMultiplier    = 2
        }
        proxies  = @()
        bindings = @()
    }
}

function ConvertTo-CacProxyUrl {
    param([string]$Raw)
    $value = ([string]$Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    if ($value -notmatch '^[a-z][a-z0-9+.-]*://') { $value = 'http://' + $value }
    try {
        $uri = [Uri]$value
        $scheme = $uri.Scheme.ToLowerInvariant()
        if ($uri.Host -and $uri.Port -gt 0 -and $uri.Port -le 65535 -and
            $scheme -in @('http', 'https', 'socks5', 'socks5h')) {
            if ($scheme -in @('socks5', 'socks5h')) {
                return ($value -replace '^(?i)socks5h?://', 'socks5h://')
            }
            return $value
        }
    } catch { }
    return $null
}

function Get-CacProxyId {
    param([string]$ProxyUrl)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ProxyUrl.ToLowerInvariant()))
        return 'proxy-' + (([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant().Substring(0, 12))
    } finally { $sha.Dispose() }
}

function New-CacProxyPoolStateNormalized {
    param([object]$State)
    $fresh = New-CacProxyPoolState
    if ($null -eq $State) { return $fresh }
    if ($null -ne $State.settings) {
        if ($null -ne $State.settings.autoBindOnNewAccount) { $fresh.settings.autoBindOnNewAccount = [bool]$State.settings.autoBindOnNewAccount }
        if ($null -ne $State.settings.accountsPerProxy) { $fresh.settings.accountsPerProxy = [int]$State.settings.accountsPerProxy }
        if ($null -ne $State.settings.warningMultiplier) { $fresh.settings.warningMultiplier = [int]$State.settings.warningMultiplier }
    }
    if ($fresh.settings.accountsPerProxy -lt 1) { $fresh.settings.accountsPerProxy = 2 }
    if ($fresh.settings.warningMultiplier -lt 1) { $fresh.settings.warningMultiplier = 2 }

    $proxies = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($State.proxies)) {
        if ($null -eq $item -or [string]::IsNullOrWhiteSpace([string]$item.url)) { continue }
        $url = ConvertTo-CacProxyUrl ([string]$item.url)
        if ([string]::IsNullOrWhiteSpace($url)) { continue }
        $id = [string]$item.id
        if ([string]::IsNullOrWhiteSpace($id)) { $id = Get-CacProxyId $url }
        $proxies.Add([pscustomobject][ordered]@{
            id = $id; url = $url
            enabled = if ($null -eq $item.enabled) { $true } else { [bool]$item.enabled }
            createdUtc = [string]$item.createdUtc
            lastError = [string]$item.lastError
            lastChecked = [string]$item.lastChecked
        })
    }
    $bindings = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($State.bindings)) {
        if ($null -eq $item -or [string]::IsNullOrWhiteSpace([string]$item.accountKey) -or
            [string]::IsNullOrWhiteSpace([string]$item.proxyId)) { continue }
        $bindings.Add([pscustomobject][ordered]@{
            accountKey = [string]$item.accountKey
            proxyId = [string]$item.proxyId
            updatedUtc = [string]$item.updatedUtc
        })
    }
    $fresh.proxies = $proxies.ToArray()
    $fresh.bindings = $bindings.ToArray()
    return $fresh
}

function Get-CacProxyPoolState {
    $path = Get-CacProxyPoolPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return (New-CacProxyPoolState) }
    try { return New-CacProxyPoolStateNormalized (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) }
    catch { throw "Proxy pool JSON cannot be read: $path : $($_.Exception.Message)" }
}

function Save-CacProxyPoolState {
    param([object]$State)
    $normalized = New-CacProxyPoolStateNormalized $State
    $path = Get-CacProxyPoolPath
    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    $tmp = "$path.$PID.tmp"
    $utf8 = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($tmp, (($normalized | ConvertTo-Json -Depth 12) + [Environment]::NewLine), $utf8)
    Move-Item -LiteralPath $tmp -Destination $path -Force
    return $normalized
}

function Mask-CacProxyUrl {
    param([string]$ProxyUrl)
    try {
        $uri = [Uri]$ProxyUrl
        $hostPort = $uri.Host
        if ($uri.Port -gt 0) { $hostPort += ':' + $uri.Port }
        if ($uri.UserInfo) { return "$($uri.Scheme)://***:***@$hostPort" }
        return "$($uri.Scheme)://$hostPort"
    } catch { return '<invalid-proxy>' }
}

function Get-CacProxyPoolEntry {
    param([object]$State, [string]$ProxyId)
    foreach ($item in @($State.proxies)) { if ([string]$item.id -eq $ProxyId) { return $item } }
    return $null
}

function Get-CacProxyPoolActiveEntries {
    param([object]$State)
    return @($State.proxies | Where-Object { [bool]$_.enabled -and -not [string]::IsNullOrWhiteSpace([string]$_.url) })
}

function Get-CacProxyBindingCounts {
    param([object]$State)
    $counts = @{}
    foreach ($proxy in @($State.proxies)) { $counts[[string]$proxy.id] = 0 }
    foreach ($binding in @($State.bindings)) {
        $id = [string]$binding.proxyId
        if ($counts.ContainsKey($id)) { $counts[$id]++ }
    }
    return $counts
}

function Get-CacProxyPoolCapacityWarning {
    param([object]$State, [int]$AccountCount)
    $active = @(Get-CacProxyPoolActiveEntries $State)
    $multiplier = [Math]::Max(1, [int]$State.settings.warningMultiplier)
    $threshold = $active.Count * $multiplier
    return [pscustomobject][ordered]@{
        warning = ($active.Count -eq 0 -or $AccountCount -gt $threshold)
        accountCount = $AccountCount; proxyCount = $active.Count
        multiplier = $multiplier; threshold = $threshold
        message = if ($active.Count -eq 0) { 'No enabled proxy is available for account binding' } elseif ($AccountCount -gt $threshold) { "Account count $AccountCount exceeds proxy count $($active.Count) x $multiplier = $threshold" } else { '' }
    }
}

function Show-CacProxyCapacityWarning {
    param([object]$Warning)
    if ($null -eq $Warning -or -not [bool]$Warning.warning) { return }
    Write-Warning $Warning.message
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [System.Windows.Forms.MessageBox]::Show($Warning.message, 'cac proxy pool capacity', 'OK', 'Warning') | Out-Null
    } catch { }
}

function Get-CacKnownAccountKeys {
    $root = Join-Path $env:USERPROFILE '.cac'
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($kind in @(@('envs', 'claude-code'), @('desktop', 'desktop'))) {
        $base = Join-Path $root $kind[0]
        if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
            $keys.Add("$($kind[1]):$($item.Name)")
        }
    }
    return $keys.ToArray()
}

function Get-CacKnownAccountCapacityWarning {
    $state = Get-CacProxyPoolState
    $keys = @(Get-CacKnownAccountKeys)
    return Get-CacProxyPoolCapacityWarning -State $state -AccountCount $keys.Count
}

function Add-CacProxyPoolEntry {
    param([Parameter(Mandatory=$true)][string]$ProxyUrl, [string]$ProxyId, [switch]$Disabled)
    $url = ConvertTo-CacProxyUrl $ProxyUrl
    if ([string]::IsNullOrWhiteSpace($url)) { throw "Invalid proxy URL: $ProxyUrl" }
    $state = Get-CacProxyPoolState
    $existing = @($state.proxies | Where-Object { [string]$_.url -ieq $url } | Select-Object -First 1)[0]
    if ($null -ne $existing) {
        $existing.enabled = -not $Disabled
        Save-CacProxyPoolState $state | Out-Null
        return $existing
    }
    if ([string]::IsNullOrWhiteSpace($ProxyId)) { $ProxyId = Get-CacProxyId $url }
    $entry = [pscustomobject][ordered]@{
        id = $ProxyId; url = $url; enabled = -not $Disabled
        createdUtc = [DateTime]::UtcNow.ToString('o'); lastError = ''; lastChecked = ''
    }
    $state.proxies = @($state.proxies) + @($entry)
    Save-CacProxyPoolState $state | Out-Null
    return $entry
}

function Remove-CacProxyPoolEntry {
    param([Parameter(Mandatory=$true)][string]$ProxyId)
    $state = Get-CacProxyPoolState
    $state.proxies = @($state.proxies | Where-Object { [string]$_.id -ne $ProxyId })
    $state.bindings = @($state.bindings | Where-Object { [string]$_.proxyId -ne $ProxyId })
    Save-CacProxyPoolState $state | Out-Null
    return $state
}

function Clear-CacProxyPoolBindings {
    $state = Get-CacProxyPoolState
    $state.bindings = @()
    Save-CacProxyPoolState $state | Out-Null
    return $state
}

function Set-CacProxyPoolSettings {
    param([bool]$AutoBindOnNewAccount = $true, [int]$AccountsPerProxy = 2, [int]$WarningMultiplier = 2)
    if ($AccountsPerProxy -lt 1 -or $WarningMultiplier -lt 1) { throw 'Proxy pool settings must be greater than zero' }
    $state = Get-CacProxyPoolState
    $state.settings.autoBindOnNewAccount = $AutoBindOnNewAccount
    $state.settings.accountsPerProxy = $AccountsPerProxy
    $state.settings.warningMultiplier = $WarningMultiplier
    Save-CacProxyPoolState $state | Out-Null
    return $state
}

function Ensure-CacProxyBinding {
    param([Parameter(Mandatory=$true)][string]$AccountKey)
    $state = Get-CacProxyPoolState
    $binding = @($state.bindings | Where-Object { [string]$_.accountKey -ieq $AccountKey } | Select-Object -First 1)[0]
    if ($null -ne $binding) {
        $existingProxy = Get-CacProxyPoolEntry $state ([string]$binding.proxyId)
        if ($null -ne $existingProxy -and [bool]$existingProxy.enabled) { return $binding }
    }
    if (-not [bool]$state.settings.autoBindOnNewAccount) { return $null }
    $active = @(Get-CacProxyPoolActiveEntries $state)
    if ($active.Count -eq 0) { return $null }
    $counts = Get-CacProxyBindingCounts $state
    $chosen = $active | Sort-Object @{Expression={ [int]$counts[[string]$_.id] }}, @{Expression={ [string]$_.id }} | Select-Object -First 1
    $now = [DateTime]::UtcNow.ToString('o')
    if ($null -ne $binding) {
        $binding.proxyId = [string]$chosen.id
        $binding.updatedUtc = $now
    } else {
        $state.bindings = @($state.bindings) + @([pscustomobject][ordered]@{ accountKey = $AccountKey; proxyId = [string]$chosen.id; updatedUtc = $now })
    }
    Save-CacProxyPoolState $state | Out-Null
    return @((Get-CacProxyPoolState).bindings | Where-Object { [string]$_.accountKey -ieq $AccountKey } | Select-Object -First 1)[0]
}

function Get-CacProxyForAccount {
    param([Parameter(Mandatory=$true)][string]$AccountKey, [string]$ExplicitProxy)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitProxy)) {
        $url = ConvertTo-CacProxyUrl $ExplicitProxy
        if ([string]::IsNullOrWhiteSpace($url)) { throw "Invalid proxy URL: $ExplicitProxy" }
        return [pscustomobject][ordered]@{ accountKey = $AccountKey; proxyId = $null; url = $url; source = 'profile' }
    }
    $state = Get-CacProxyPoolState
    $binding = @($state.bindings | Where-Object { [string]$_.accountKey -ieq $AccountKey } | Select-Object -First 1)[0]
    if ($null -eq $binding -and [bool]$state.settings.autoBindOnNewAccount) {
        $binding = Ensure-CacProxyBinding $AccountKey
        $state = Get-CacProxyPoolState
    }
    if ($null -eq $binding) { return $null }
    $proxy = Get-CacProxyPoolEntry $state ([string]$binding.proxyId)
    if ($null -eq $proxy -or -not [bool]$proxy.enabled) { return $null }
    return [pscustomobject][ordered]@{ accountKey = $AccountKey; proxyId = [string]$proxy.id; url = [string]$proxy.url; source = 'pool' }
}

function Rebalance-CacProxyBindings {
    param([Parameter(Mandatory=$true)][string[]]$AccountKeys, [switch]$OnlyUnbound)
    $state = Get-CacProxyPoolState
    $active = @(Get-CacProxyPoolActiveEntries $state | Sort-Object id)
    if ($active.Count -eq 0) { throw 'Proxy pool has no enabled proxies' }
    $keys = @($AccountKeys | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    $kept = if ($OnlyUnbound) { @($state.bindings) } else { @($state.bindings | Where-Object { $keys -notcontains [string]$_.accountKey }) }
    $next = New-Object System.Collections.Generic.List[object]
    foreach ($item in $kept) { $next.Add($item) }
    $index = 0
    foreach ($key in $keys) {
        if ($OnlyUnbound -and @($state.bindings | Where-Object { [string]$_.accountKey -ieq $key }).Count -gt 0) { continue }
        $proxy = $active[$index % $active.Count]
        $next.Add([pscustomobject][ordered]@{ accountKey = $key; proxyId = [string]$proxy.id; updatedUtc = [DateTime]::UtcNow.ToString('o') })
        $index++
    }
    $state.bindings = $next.ToArray()
    Save-CacProxyPoolState $state | Out-Null
    return [pscustomobject][ordered]@{ state = $state; warning = Get-CacProxyPoolCapacityWarning $state $keys.Count }
}

function Get-CacFreeTcpPort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    try { $listener.Start(); return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Get-CacRelayScriptPath {
    $source = Join-Path (Split-Path $PSScriptRoot -Parent) 'src\relay.js'
    if (Test-Path -LiteralPath $source -PathType Leaf) { return $source }
    $installed = Join-Path $env:USERPROFILE '.cac\proxy-relay.js'
    if (Test-Path -LiteralPath $installed -PathType Leaf) { return $installed }
    return $null
}

function Test-CacTcpPort {
    param([int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(250)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch { return $false } finally { $client.Dispose() }
}

function Start-CacProxyRelay {
    param([string]$UpstreamProxyUrl, [string]$LogsDir)
    $url = ConvertTo-CacProxyUrl $UpstreamProxyUrl
    if ([string]::IsNullOrWhiteSpace($url)) { throw "Invalid proxy URL: $UpstreamProxyUrl" }
    $uri = [Uri]$url
    if ($uri.Scheme -eq 'https') { throw 'HTTPS upstream proxy is not supported by this relay; use socks5h:// or http://' }
    if ($uri.Host -in @('127.0.0.1', 'localhost', '::1') -and $uri.Port -gt 0) {
        return [pscustomobject][ordered]@{ owned = $false; process = $null; port = $uri.Port; url = "http://127.0.0.1:$($uri.Port)"; upstream = $url; pidFile = $null }
    }
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    $port = Get-CacFreeTcpPort
    $pidFile = Join-Path $LogsDir 'proxy-relay.pid'
    $logFile = Join-Path $LogsDir 'proxy-relay.log'
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    $node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
    if (-not $node) { $node = (Get-Command node -ErrorAction SilentlyContinue).Source }
    $relay = Get-CacRelayScriptPath
    if (-not $node -or -not $relay) { throw 'node.exe or proxy-relay.js is missing; fail-closed relay cannot start' }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $node
    $psi.Arguments = ('"{0}" {1} "{2}" "{3}"' -f $relay, $port, $url, $pidFile)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $deadline = (Get-Date).AddSeconds(8)
    while ((Get-Date) -lt $deadline) {
        if ($process.HasExited) { throw "Proxy relay failed to start: $logFile" }
        if (Test-CacTcpPort $port) {
            return [pscustomobject][ordered]@{ owned = $true; process = $process; port = $port; url = "http://127.0.0.1:$port"; upstream = $url; pidFile = $pidFile; logFile = $logFile }
        }
        Start-Sleep -Milliseconds 150
    }
    try { $process.Kill() } catch { }
    throw "Proxy relay did not listen on 127.0.0.1:${port}: $logFile"
}

function Stop-CacProxyRelay {
    param([object]$Relay)
    if ($null -eq $Relay -or -not [bool]$Relay.owned) { return }
    if ($Relay.process) {
        try { if (-not $Relay.process.HasExited) { $Relay.process.Kill() } } catch { }
        try { [void]$Relay.process.WaitForExit(3000) } catch { }
    }
    if ($Relay.pidFile) { Remove-Item -LiteralPath $Relay.pidFile -Force -ErrorAction SilentlyContinue }
}
