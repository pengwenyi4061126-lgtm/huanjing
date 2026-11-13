# cac-windows - profile proxy pool and DNS-safe local relay helpers
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

function Get-CacProxyDefaultPort {
    param([string]$Scheme)
    switch ($Scheme.ToLowerInvariant()) {
        'http' { return 80 }
        'https' { return 443 }
        'socks5' { return 1080 }
        'socks5h' { return 1080 }
        default { return 0 }
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
        if ($scheme -notin @('http', 'https', 'socks5', 'socks5h') -or [string]::IsNullOrWhiteSpace($uri.Host)) { return $null }
        $port = [int]$uri.Port
        if ($port -le 0) { $port = Get-CacProxyDefaultPort $scheme }
        if ($port -le 0 -or $port -gt 65535) { return $null }
        $builder = New-Object System.UriBuilder($uri)
        $builder.Scheme = $scheme
        $builder.Port = $port
        $normalized = $builder.ToString()
        if ($scheme -in @('socks5', 'socks5h')) { $normalized = $normalized -replace '^(?i)socks5h?://', 'socks5h://' }
        return $normalized
    } catch { return $null }
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
    if ($null -ne $State.version -and [int]$State.version -ne [int]$script:CacProxyPoolSchema) {
        throw "Unsupported proxy pool schema: $($State.version)"
    }
    if ($null -ne $State.settings) {
        if ($null -ne $State.settings.autoBindOnNewAccount) { $fresh.settings.autoBindOnNewAccount = [bool]$State.settings.autoBindOnNewAccount }
        if ($null -ne $State.settings.accountsPerProxy) { $fresh.settings.accountsPerProxy = [int]$State.settings.accountsPerProxy }
        if ($null -ne $State.settings.warningMultiplier) { $fresh.settings.warningMultiplier = [int]$State.settings.warningMultiplier }
    }
    if ($fresh.settings.accountsPerProxy -lt 1) { $fresh.settings.accountsPerProxy = 2 }
    if ($fresh.settings.warningMultiplier -lt 1) { $fresh.settings.warningMultiplier = 2 }

    $proxies = New-Object System.Collections.Generic.List[object]
    $seenIds = @{}
    foreach ($item in @($State.proxies)) {
        if ($null -eq $item -or [string]::IsNullOrWhiteSpace([string]$item.url)) { throw 'Proxy pool contains an invalid proxy entry' }
        $url = ConvertTo-CacProxyUrl ([string]$item.url)
        if ([string]::IsNullOrWhiteSpace($url)) { throw "Proxy pool contains an invalid proxy URL: $($item.url)" }
        $id = ([string]$item.id).Trim()
        if ([string]::IsNullOrWhiteSpace($id)) { $id = Get-CacProxyId $url }
        if ($seenIds.ContainsKey($id)) { throw "Proxy pool contains duplicate proxyId: $id" }
        $seenIds[$id] = $true
        $proxies.Add([pscustomobject][ordered]@{
            id = $id; url = $url
            enabled = if ($null -eq $item.enabled) { $true } else { [bool]$item.enabled }
            createdUtc = [string]$item.createdUtc
            lastError = [string]$item.lastError
            lastChecked = [string]$item.lastChecked
        })
    }
    $bindings = New-Object System.Collections.Generic.List[object]
    $seenAccounts = @{}
    foreach ($item in @($State.bindings)) {
        if ($null -eq $item -or [string]::IsNullOrWhiteSpace([string]$item.accountKey) -or
            [string]::IsNullOrWhiteSpace([string]$item.proxyId)) { throw 'Proxy pool contains an invalid account binding' }
        $accountKey = [string]$item.accountKey
        if ($seenAccounts.ContainsKey($accountKey.ToLowerInvariant())) { throw "Proxy pool contains duplicate account binding: $accountKey" }
        $seenAccounts[$accountKey.ToLowerInvariant()] = $true
        $bindings.Add([pscustomobject][ordered]@{
            accountKey = $accountKey
            proxyId = [string]$item.proxyId
            updatedUtc = [string]$item.updatedUtc
        })
    }
    $fresh.proxies = $proxies.ToArray()
    $fresh.bindings = $bindings.ToArray()
    return $fresh
}

function Get-CacProxyPoolStateCore {
    $path = Get-CacProxyPoolPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return (New-CacProxyPoolState) }
    try { return New-CacProxyPoolStateNormalized (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) }
    catch { throw 'Proxy pool JSON cannot be read or normalized' }
}

function Get-CacProxyPoolMutexName {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes((Get-CacProxyPoolPath).ToLowerInvariant()))
        $key = ([System.BitConverter]::ToString($bytes)).Replace('-', '').Substring(0, 32)
        return 'Global\cac-proxy-pool-' + $key
    } finally { $sha.Dispose() }
}

function Invoke-CacProxyPoolLocked {
    param([Parameter(Mandatory=$true)][scriptblock]$ScriptBlock)
    $created = $false
    $mutex = $null
    $acquired = $false
    try {
        $mutex = [System.Threading.Mutex]::new($false, (Get-CacProxyPoolMutexName), [ref]$created)
        try { $acquired = $mutex.WaitOne(15000) } catch [System.Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'Proxy pool is busy' }
        return (& $ScriptBlock)
    } finally {
        if ($acquired -and $mutex) { try { $mutex.ReleaseMutex() | Out-Null } catch { } }
        if ($mutex) { $mutex.Dispose() }
    }
}

function Save-CacProxyPoolStateCore {
    param([object]$State)
    $normalized = New-CacProxyPoolStateNormalized $State
    $path = Get-CacProxyPoolPath
    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    $json = (($normalized | ConvertTo-Json -Depth 12) + [Environment]::NewLine)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $lastError = $null
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $tmp = "$path.$PID.$([guid]::NewGuid().ToString('N')).tmp"
        $backup = "$path.$PID.$([guid]::NewGuid().ToString('N')).bak"
        $stream = $null
        $writer = $null
        try {
            $stream = [System.IO.File]::Open($tmp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $writer = New-Object System.IO.StreamWriter($stream, $utf8)
            $writer.Write($json)
            $writer.Flush()
            $stream.Flush($true)
            $writer.Dispose(); $writer = $null
            $stream.Dispose(); $stream = $null
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                [System.IO.File]::Replace($tmp, $path, $backup, $true)
                Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
            }
            else { [System.IO.File]::Move($tmp, $path) }
            return $normalized
        } catch {
            $lastError = $_
            Start-Sleep -Milliseconds (50 * ($attempt + 1))
        } finally {
            if ($writer) { try { $writer.Dispose() } catch { } }
            if ($stream) { try { $stream.Dispose() } catch { } }
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
        }
    }
    throw 'Proxy pool state save failed after retries'
}

function Get-CacProxyPoolState {
    return Invoke-CacProxyPoolLocked { Get-CacProxyPoolStateCore }
}

function Save-CacProxyPoolState {
    param([object]$State)
    return Invoke-CacProxyPoolLocked { Save-CacProxyPoolStateCore $State }
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
    foreach ($item in @($State.proxies)) {
        if ([string]::Equals([string]$item.id, [string]$ProxyId, [StringComparison]::OrdinalIgnoreCase)) { return $item }
    }
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
    $perProxy = [Math]::Max(1, [int]$State.settings.accountsPerProxy)
    $threshold = $active.Count * $multiplier
    $capacity = $active.Count * $perProxy
    $warning = ($active.Count -eq 0 -or $AccountCount -gt $threshold -or $AccountCount -gt $capacity)
    $message = if ($active.Count -eq 0) { 'No enabled proxy is available for account binding' }
        elseif ($AccountCount -gt $capacity) { "Account count $AccountCount exceeds hard capacity $capacity" }
        elseif ($AccountCount -gt $threshold) { "Account count $AccountCount exceeds proxy count $($active.Count) x $multiplier = $threshold" }
        else { '' }
    return [pscustomobject][ordered]@{
        warning = $warning; accountCount = $AccountCount; proxyCount = $active.Count
        accountsPerProxy = $perProxy; capacity = $capacity; multiplier = $multiplier; threshold = $threshold; message = $message
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
        foreach ($item in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) { $keys.Add("$($kind[1]):$($item.Name)") }
    }
    return $keys.ToArray()
}

function Get-CacKnownAccountCapacityWarning {
    $state = Get-CacProxyPoolState
    return Get-CacProxyPoolCapacityWarning -State $state -AccountCount @((Get-CacKnownAccountKeys)).Count
}

function Add-CacProxyPoolEntry {
    param([Parameter(Mandatory=$true)][string]$ProxyUrl, [string]$ProxyId, [switch]$Disabled)
    return Invoke-CacProxyPoolLocked {
        $url = ConvertTo-CacProxyUrl $ProxyUrl
        if ([string]::IsNullOrWhiteSpace($url)) { throw 'Invalid proxy URL' }
        $state = Get-CacProxyPoolStateCore
        $existing = @($state.proxies | Where-Object { [string]$_.url -ieq $url } | Select-Object -First 1)[0]
        if ($null -ne $existing) {
            if (-not [string]::IsNullOrWhiteSpace($ProxyId) -and [string]$existing.id -ine $ProxyId.Trim()) { throw 'ProxyId does not match the existing proxy URL' }
            $existing.enabled = -not $Disabled
            Save-CacProxyPoolStateCore $state | Out-Null
            return $existing
        }
        $ProxyId = ([string]$ProxyId).Trim()
        if ([string]::IsNullOrWhiteSpace($ProxyId)) { $ProxyId = Get-CacProxyId $url }
        if (@($state.proxies | Where-Object { [string]$_.id -ieq $ProxyId }).Count -gt 0) { throw "Duplicate proxyId: $ProxyId" }
        $entry = [pscustomobject][ordered]@{
            id = $ProxyId; url = $url; enabled = -not $Disabled
            createdUtc = [DateTime]::UtcNow.ToString('o'); lastError = ''; lastChecked = ''
        }
        $state.proxies = @($state.proxies) + @($entry)
        Save-CacProxyPoolStateCore $state | Out-Null
        return $entry
    }
}

function Remove-CacProxyPoolEntry {
    param([Parameter(Mandatory=$true)][string]$ProxyId)
    return Invoke-CacProxyPoolLocked {
        $state = Get-CacProxyPoolStateCore
        $state.proxies = @($state.proxies | Where-Object { -not [string]::Equals([string]$_.id, [string]$ProxyId, [StringComparison]::OrdinalIgnoreCase) })
        $state.bindings = @($state.bindings | Where-Object { -not [string]::Equals([string]$_.proxyId, [string]$ProxyId, [StringComparison]::OrdinalIgnoreCase) })
        Save-CacProxyPoolStateCore $state | Out-Null
        return $state
    }
}

function Clear-CacProxyPoolBindings {
    return Invoke-CacProxyPoolLocked {
        $state = Get-CacProxyPoolStateCore
        $state.bindings = @()
        Save-CacProxyPoolStateCore $state | Out-Null
        return $state
    }
}

function Set-CacProxyPoolSettings {
    param([bool]$AutoBindOnNewAccount = $true, [int]$AccountsPerProxy = 2, [int]$WarningMultiplier = 2)
    if ($AccountsPerProxy -lt 1 -or $WarningMultiplier -lt 1) { throw 'Proxy pool settings must be greater than zero' }
    return Invoke-CacProxyPoolLocked {
        $state = Get-CacProxyPoolStateCore
        $state.settings.autoBindOnNewAccount = $AutoBindOnNewAccount
        $state.settings.accountsPerProxy = $AccountsPerProxy
        $state.settings.warningMultiplier = $WarningMultiplier
        Save-CacProxyPoolStateCore $state | Out-Null
        return $state
    }
}

function Ensure-CacProxyBinding {
    param([Parameter(Mandatory=$true)][string]$AccountKey)
    return Invoke-CacProxyPoolLocked {
        $state = Get-CacProxyPoolStateCore
        $binding = @($state.bindings | Where-Object { [string]$_.accountKey -ieq $AccountKey } | Select-Object -First 1)[0]
        if ($null -ne $binding) {
            $existingProxy = Get-CacProxyPoolEntry $state ([string]$binding.proxyId)
            if ($null -ne $existingProxy -and [bool]$existingProxy.enabled) { return $binding }
            return $null
        }
        if (-not [bool]$state.settings.autoBindOnNewAccount) { return $null }
        $active = @(Get-CacProxyPoolActiveEntries $state)
        if ($active.Count -eq 0) { return $null }
        $limit = [Math]::Max(1, [int]$state.settings.accountsPerProxy)
        $counts = Get-CacProxyBindingCounts $state
        $chosen = @($active | Where-Object { [int]$counts[[string]$_.id] -lt $limit } |
            Sort-Object @{Expression={ [int]$counts[[string]$_.id] }}, @{Expression={ [string]$_.id }} | Select-Object -First 1)[0]
        if ($null -eq $chosen) { return $null }
        $state.bindings = @($state.bindings) + @([pscustomobject][ordered]@{ accountKey = $AccountKey; proxyId = [string]$chosen.id; updatedUtc = [DateTime]::UtcNow.ToString('o') })
        Save-CacProxyPoolStateCore $state | Out-Null
        return @((Get-CacProxyPoolStateCore).bindings | Where-Object { [string]$_.accountKey -ieq $AccountKey } | Select-Object -First 1)[0]
    }
}

function Get-CacProxyForAccount {
    param([Parameter(Mandatory=$true)][string]$AccountKey, [string]$ExplicitProxy)
    if (-not [string]::IsNullOrWhiteSpace($ExplicitProxy)) {
        $url = ConvertTo-CacProxyUrl $ExplicitProxy
        if ([string]::IsNullOrWhiteSpace($url)) { throw 'Invalid proxy URL' }
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
    return Invoke-CacProxyPoolLocked {
        $state = Get-CacProxyPoolStateCore
        $active = @(Get-CacProxyPoolActiveEntries $state | Sort-Object id)
        if ($active.Count -eq 0) { throw 'Proxy pool has no enabled proxies' }
        $keys = @($AccountKeys | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $requested = @{}
        foreach ($key in $keys) { $requested[$key.ToLowerInvariant()] = $true }
        $protected = @($state.bindings | Where-Object {
            $key = [string]$_.accountKey
            $proxy = Get-CacProxyPoolEntry $state ([string]$_.proxyId)
            (-not $OnlyUnbound -and $requested.ContainsKey($key.ToLowerInvariant()) -and ($null -eq $proxy -or -not [bool]$proxy.enabled))
        })
        $kept = if ($OnlyUnbound) { @($state.bindings) } else { @($state.bindings | Where-Object { -not $requested.ContainsKey(([string]$_.accountKey).ToLowerInvariant()) }) + $protected }
        $assigned = New-Object System.Collections.Generic.List[object]
        foreach ($item in $kept) { $assigned.Add($item) }
        $counts = Get-CacProxyBindingCounts ([pscustomobject]@{ proxies = $state.proxies; bindings = $assigned.ToArray() })
        $limit = [Math]::Max(1, [int]$state.settings.accountsPerProxy)
        foreach ($key in $keys) {
            if (@($state.bindings | Where-Object { [string]$_.accountKey -ieq $key }).Count -gt 0 -and $OnlyUnbound) { continue }
            if (@($protected | Where-Object { [string]$_.accountKey -ieq $key }).Count -gt 0) { continue }
            $chosen = @($active | Where-Object { [int]$counts[[string]$_.id] -lt $limit } |
                Sort-Object @{Expression={ [int]$counts[[string]$_.id] }}, @{Expression={ [string]$_.id }} | Select-Object -First 1)[0]
            if ($null -eq $chosen) { throw 'Proxy pool accountsPerProxy capacity exhausted' }
            $assigned.Add([pscustomobject][ordered]@{ accountKey = $key; proxyId = [string]$chosen.id; updatedUtc = [DateTime]::UtcNow.ToString('o') })
            $counts[[string]$chosen.id]++
        }
        $state.bindings = $assigned.ToArray()
        Save-CacProxyPoolStateCore $state | Out-Null
        return [pscustomobject][ordered]@{ state = $state; warning = Get-CacProxyPoolCapacityWarning $state $keys.Count }
    }
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

function Test-CacRelayHandshake {
    param([int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(250)) { return $false }
        $client.EndConnect($async)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 600
        $request = [System.Text.Encoding]::ASCII.GetBytes("GET http://cac-relay.local/__cac_relay_health__ HTTP/1.1`r`nHost: cac-relay.local`r`nConnection: close`r`n`r`n")
        $stream.Write($request, 0, $request.Length)
        $stream.Flush()
        $buffer = New-Object byte[] 2048
        $data = New-Object System.IO.MemoryStream
        for ($i = 0; $i -lt 8; $i++) {
            $count = $stream.Read($buffer, 0, $buffer.Length)
            if ($count -le 0) { break }
            $data.Write($buffer, 0, $count)
            $text = [System.Text.Encoding]::ASCII.GetString($data.ToArray())
            if ($text -match 'HTTP/1\.1 200 OK' -and $text -match '(?im)^X-Cac-Relay:\s*ready\s*$') { return $true }
        }
        return $false
    } catch { return $false } finally { $client.Dispose() }
}

function Start-CacProxyRelay {
    param([string]$UpstreamProxyUrl, [string]$LogsDir)
    $url = ConvertTo-CacProxyUrl $UpstreamProxyUrl
    if ([string]::IsNullOrWhiteSpace($url)) { throw 'Invalid proxy URL' }
    $uri = [Uri]$url
    $scheme = $uri.Scheme.ToLowerInvariant()
    if ($scheme -eq 'https') { throw 'HTTPS upstream proxy is not supported by this relay' }
    $parsedIp = $null
    $isLoopback = ([System.Net.IPAddress]::TryParse($uri.DnsSafeHost, [ref]$parsedIp) -and $parsedIp.IsLoopback) -or $uri.DnsSafeHost -ieq 'localhost'
    if ($scheme -eq 'http' -and $isLoopback -and [string]::IsNullOrWhiteSpace($uri.UserInfo)) {
        $localHost = if ($parsedIp -and $parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { "[$($uri.DnsSafeHost)]" } else { '127.0.0.1' }
        return [pscustomobject][ordered]@{ owned = $false; process = $null; port = $uri.Port; url = "http://$($localHost):$($uri.Port)"; upstream = $url; pidFile = $null }
    }

    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    $pidFile = Join-Path $LogsDir 'proxy-relay.pid'
    $logFile = Join-Path $LogsDir 'proxy-relay.log'
    [System.IO.File]::WriteAllText($logFile, '', (New-Object System.Text.UTF8Encoding($false)))
    $node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
    if (-not $node) { $node = (Get-Command node -ErrorAction SilentlyContinue).Source }
    $relay = Get-CacRelayScriptPath
    if (-not $node -or -not $relay) { throw 'node.exe or proxy-relay.js is missing; fail-closed relay cannot start' }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $appendLog = [System.Diagnostics.DataReceivedEventHandler]{
        param($sender, $event)
        if ($null -ne $event.Data) { try { [System.IO.File]::AppendAllText($logFile, $event.Data + [Environment]::NewLine, $utf8) } catch { } }
    }

    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $port = Get-CacFreeTcpPort
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $node
        $psi.Arguments = ('"{0}" {1} "{2}"' -f $relay, $port, $pidFile)
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables['CAC_RELAY_UPSTREAM_URL'] = $url
        $psi.EnvironmentVariables['CAC_RELAY_PID_FILE'] = $pidFile
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi
        $process.add_OutputDataReceived($appendLog)
        $process.add_ErrorDataReceived($appendLog)
        try {
            [void]$process.Start()
            $process.BeginOutputReadLine()
            $process.BeginErrorReadLine()
            $ready = $false
            $deadline = (Get-Date).AddSeconds(8)
            while ((Get-Date) -lt $deadline) {
                if ($process.HasExited) { break }
                if (Test-CacRelayHandshake $port) { $ready = $true; break }
                Start-Sleep -Milliseconds 100
            }
            if ($ready -and -not $process.HasExited) {
                return [pscustomobject][ordered]@{ owned = $true; process = $process; port = $port; url = "http://127.0.0.1:$port"; upstream = $url; pidFile = $pidFile; logFile = $logFile; outputHandler = $appendLog }
            }
        } catch { }
        try { if (-not $process.HasExited) { $process.Kill() } } catch { }
        try { [void]$process.WaitForExit(3000) } catch { }
        try { $process.remove_OutputDataReceived($appendLog); $process.remove_ErrorDataReceived($appendLog) } catch { }
        $process.Dispose()
        Start-Sleep -Milliseconds 100
    }
    throw "Proxy relay did not pass startup handshake; see $logFile"
}

function Stop-CacProxyRelay {
    param([object]$Relay)
    if ($null -eq $Relay -or -not [bool]$Relay.owned) { return }
    if ($Relay.process) {
        try { if (-not $Relay.process.HasExited) { $Relay.process.Kill() } } catch { }
        try { [void]$Relay.process.WaitForExit(3000) } catch { }
        if ($Relay.outputHandler) {
            try { $Relay.process.remove_OutputDataReceived($Relay.outputHandler); $Relay.process.remove_ErrorDataReceived($Relay.outputHandler) } catch { }
        }
        try { $Relay.process.Dispose() } catch { }
    }
    if ($Relay.pidFile) { Remove-Item -LiteralPath $Relay.pidFile -Force -ErrorAction SilentlyContinue }
}
