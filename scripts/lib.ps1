# cac-windows — shared utility functions
$ErrorActionPreference = "Stop"

$CAC_DIR = Join-Path $env:USERPROFILE ".cac"
$ENVS_DIR = Join-Path $CAC_DIR "envs"
$CAC_PACKAGE_ROOT = Split-Path $PSScriptRoot -Parent
$proxyPoolModule = Join-Path $PSScriptRoot "proxy-pool-lib.ps1"
if (Test-Path -LiteralPath $proxyPoolModule -PathType Leaf) { . $proxyPoolModule }

function Write-OK($t) { Write-Host "  [OK] $t" -ForegroundColor Green }
function Write-Err($t) { Write-Host "  [!!] $t" -ForegroundColor Red }
function Write-Warn($t) { Write-Host "  [--] $t" -ForegroundColor Yellow }

function Read-FileValue {
    param([string]$Path, [string]$Default = "")
    if (Test-Path $Path) { return (Get-Content $Path -Raw).Trim() }
    return $Default
}

function Get-CacSha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToUpperInvariant()
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
}

function Get-CacDeclaredSha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw
        $matches = [regex]::Matches($raw, '(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')
        if ($matches.Count -ne 1) { return $null }
        return $matches[0].Value.ToUpperInvariant()
    } catch {
        return $null
    }
}

function Test-ProfileName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -in @('.', '..')) { return $false }
    if ($Name -match '[. ]$') { return $false }
    if ($Name -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$') { return $false }
    return $Name -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
}

function New-Uuid    { return [guid]::NewGuid().ToString().ToUpper() }
function New-Sid     { return [guid]::NewGuid().ToString().ToLower() }
function New-UserId  { return -join ((1..32) | ForEach-Object { "{0:x2}" -f (Get-Random -Maximum 256) }) }
function New-MachineId { return [guid]::NewGuid().ToString().Replace("-","").ToLower() }
function New-FakeHostname { return "host-$([guid]::NewGuid().ToString().Split('-')[0].ToLower())" }
function New-FakeMac {
    $bytes = @(0x02) + (1..5 | ForEach-Object { Get-Random -Maximum 256 })
    return ($bytes | ForEach-Object { "{0:x2}" -f $_ }) -join ":"
}

function Get-DerivedHex {
    param([string]$Seed, [int]$Length)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Seed))
        $hex = ([System.BitConverter]::ToString($bytes)).Replace("-", "").ToLowerInvariant()
        if ($hex.Length -lt $Length) { return $hex }
        return $hex.Substring(0, $Length)
    } finally {
        $sha.Dispose()
    }
}

function Sync-NativeLayer {
    $source = Join-Path $CAC_PACKAGE_ROOT "native\dist"
    $target = Join-Path $CAC_DIR "native"
    if (-not (Test-Path -LiteralPath $source)) { return $false }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    $changed = $false
    $required = @("NativeBridge.dll", "cac-native-launch.exe", "NativeBridge.sha256", "cac-native-launch.sha256")
    $missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $source $_) -PathType Leaf) })
    if ($missing.Count -gt 0) {
        Write-Warn "Native 层发布物不完整，缺少: $($missing -join ', ')"
        return $false
    }
    foreach ($name in $required) {
        $from = Join-Path $source $name
        $to = Join-Path $target $name
        if (-not (Test-Path -LiteralPath $to) -or
            (Get-CacSha256 $from) -ne (Get-CacSha256 $to)) {
            Copy-Item -LiteralPath $from -Destination $to -Force
            $changed = $true
        }
    }
    return $changed
}

function Sync-IdentityHook {
    $source = Join-Path $CAC_PACKAGE_ROOT "fingerprint-hook.js"
    $target = Join-Path $CAC_DIR "fingerprint-hook.js"
    if (-not (Test-Path -LiteralPath $source)) { return $false }
    if (-not (Test-Path -LiteralPath $target) -or
        (Get-CacSha256 $source) -ne (Get-CacSha256 $target)) {
        New-Item -ItemType Directory -Path $CAC_DIR -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $target -Force
        return $true
    }
    return $false
}

function Get-NativeLayerStatus {
    $dir = Join-Path $CAC_DIR "native"
    $dll = Join-Path $dir "NativeBridge.dll"
    $launcher = Join-Path $dir "cac-native-launch.exe"
    $dllHashFile = Join-Path $dir "NativeBridge.sha256"
    $launcherHashFile = Join-Path $dir "cac-native-launch.sha256"
    $manifest = Join-Path $dir "native-hook-manifest.txt"
    $dllHash = if (Test-Path -LiteralPath $dll -PathType Leaf) { Get-CacSha256 $dll } else { $null }
    $dllDeclaredHash = Get-CacDeclaredSha256 $dllHashFile
    $launcherHash = if (Test-Path -LiteralPath $launcher -PathType Leaf) { Get-CacSha256 $launcher } else { $null }
    $launcherDeclaredHash = Get-CacDeclaredSha256 $launcherHashFile
    $integrityOk = ($dllHash -and $dllDeclaredHash -and
        $launcherHash -and $launcherDeclaredHash -and
        $dllHash -eq $dllDeclaredHash -and $launcherHash -eq $launcherDeclaredHash)
    return [pscustomobject]@{
        Dir        = $dir
        Dll        = $dll
        Launcher   = $launcher
        DllHashFile = $dllHashFile
        LauncherHashFile = $launcherHashFile
        Manifest   = $manifest
        DllPresent = (Test-Path -LiteralPath $dll)
        LauncherPresent = (Test-Path -LiteralPath $launcher)
        DllHash    = $dllHash
        DllDeclaredHash = $dllDeclaredHash
        LauncherHash = $launcherHash
        LauncherDeclaredHash = $launcherDeclaredHash
        IntegrityOk = [bool]$integrityOk
        ManifestPresent = (Test-Path -LiteralPath $manifest)
        Available  = [bool]$integrityOk
    }
}

function Parse-Proxy {
    param([string]$Raw)
    $value = ([string]$Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    $allowedSchemes = @('http', 'https', 'socks5', 'socks5h')
    if ($value -match '^[a-z][a-z0-9+.-]*://') {
        try {
            $uri = [Uri]$value
            if ($uri.Scheme -in $allowedSchemes -and $uri.Host -and $uri.Port -gt 0 -and $uri.Port -le 65535) {
                if ($uri.Scheme -in @('socks5', 'socks5h')) { return ($value -replace '^(?i)socks5h?://', 'socks5h://') }
                return $value
            }
        } catch { }
        return $null
    }

    # Legacy input: user:password:host:port. Passwords containing ':' are
    # accepted by using the final field as the port and the last ':' before it
    # as the host separator.
    if ($value -match '^(?<user>[^:]+):(?<password>.+):(?<host>\[[^\]]+\]|[^:]+):(?<port>\d+)$') {
        $port = [int]$Matches.port
        if ($port -gt 0 -and $port -le 65535) {
            $user = [Uri]::EscapeDataString($Matches.user)
            $password = [Uri]::EscapeDataString($Matches.password)
            return "http://$user`:$password@$($Matches.host):$port"
        }
        return $null
    }
    if ($value -match '^(?<user>[^:]+):(?<password>[^@]+)@(?<host>\[[^\]]+\]|[^:]+):(?<port>\d+)$') {
        $port = [int]$Matches.port
        if ($port -gt 0 -and $port -le 65535) {
            $user = [Uri]::EscapeDataString($Matches.user)
            $password = [Uri]::EscapeDataString($Matches.password)
            return "http://$user`:$password@$($Matches.host):$port"
        }
        return $null
    }
    if ($value -match '^(?<host>\[[^\]]+\]|[^:]+):(?<port>\d+)$') {
        $port = [int]$Matches.port
        if ($port -gt 0 -and $port -le 65535) { return "http://$($Matches.host):$port" }
    }
    return $null
}

function Test-ProxyReachable {
    param([string]$ProxyUrl)
    try { $uri = [Uri]$ProxyUrl } catch { return $false }
    if (-not $uri.IsAbsoluteUri -or [string]::IsNullOrWhiteSpace($uri.Host) -or $uri.Port -le 0) { return $false }
    $tcp = $null
    $async = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($uri.DnsSafeHost, $uri.Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) { return $false }
        $tcp.EndConnect($async)
        return $tcp.Connected
    } catch { return $false }
    finally {
        if ($async -and $async.AsyncWaitHandle) { $async.AsyncWaitHandle.Close() }
        if ($tcp) { $tcp.Dispose() }
    }
}

function Get-NpmGlobalPrefix {
    if (-not [string]::IsNullOrWhiteSpace($env:npm_config_prefix)) {
        return $env:npm_config_prefix.Trim()
    }
    try {
        $lines = @(& npm prefix -g 2>$null)
        if ($lines.Count -gt 0) {
            $value = ([string]($lines | Select-Object -Last 1)).Trim()
            if ($value) { return $value }
        }
    } catch { }
    return (Join-Path $env:APPDATA "npm")
}

function Get-ClaudeCodeInstallDir {
    return Join-Path (Get-NpmGlobalPrefix) "node_modules\@anthropic-ai\claude-code"
}

function Find-RealClaude {
    $npmBase = Get-ClaudeCodeInstallDir
    foreach ($name in @("claude.exe", "claude")) {
        $c = Join-Path $npmBase "bin\$name"
        if (Test-Path $c) { return $c }
    }
    $command = Get-Command claude -ErrorAction SilentlyContinue
    if ($command -and $command.Source) { return $command.Source }
    return $null
}

function Get-CurrentEnv { return Read-FileValue (Join-Path $CAC_DIR "current") }

function Get-EnvDir {
    param([string]$Name)
    if (-not (Test-ProfileName $Name)) { throw "无效环境名: $Name" }
    return [System.IO.Path]::GetFullPath((Join-Path $ENVS_DIR $Name))
}

function Get-CacProfileMutexName {
    param([Parameter(Mandatory = $true)][string]$ProfileRoot)
    $fullRoot = [System.IO.Path]::GetFullPath($ProfileRoot).TrimEnd('\').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($fullRoot)) { throw "Profile root is empty" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fullRoot))
        $hex = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        return "Global\cac-profile-$($hex.Substring(0, 32))"
    } finally { $sha.Dispose() }
}

function Enter-CacProfileMutex {
    param(
        [Parameter(Mandatory = $true)][string]$ProfileRoot,
        [int]$TimeoutMilliseconds = 0
    )
    $name = Get-CacProfileMutexName -ProfileRoot $ProfileRoot
    $mutex = [System.Threading.Mutex]::new($false, $name)
    try {
        $acquired = $false
        try {
            $acquired = [bool]$mutex.WaitOne($TimeoutMilliseconds)
        } catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        if (-not $acquired) {
            $mutex.Dispose()
            return $null
        }
        return [pscustomobject][ordered]@{ Name = $name; Mutex = $mutex; Acquired = $true }
    } catch {
        try { $mutex.Dispose() } catch { }
        throw
    }
}

function Exit-CacProfileMutex {
    param([object]$Lock)
    if ($null -eq $Lock) { return }
    try {
        if ([bool]$Lock.Acquired) { [void]$Lock.Mutex.ReleaseMutex() }
    } catch { }
    finally { try { $Lock.Mutex.Dispose() } catch { } }
}

function Get-CacIsolatedHomeEnvironment {
    param([Parameter(Mandatory = $true)][string]$HomeDir)
    $fullHome = [System.IO.Path]::GetFullPath($HomeDir)
    $homeRoot = [System.IO.Path]::GetPathRoot($fullHome)
    if ([string]::IsNullOrWhiteSpace($homeRoot) -or $homeRoot -notmatch '^[A-Za-z]:\\$') {
        throw "Unable to derive isolated HOMEDRIVE/HOMEPATH for $HomeDir"
    }
    $homeDrive = $homeRoot.Substring(0, 2)
    $homePath = $fullHome.Substring(2)
    if ([string]::IsNullOrWhiteSpace($homePath) -or
        -not [string]::Equals(($homeDrive + $homePath).TrimEnd('\'), $fullHome.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unable to derive isolated HOMEDRIVE/HOMEPATH for $HomeDir"
    }
    return [ordered]@{
        HOME       = $fullHome
        USERPROFILE = $fullHome
        HOMEDRIVE  = $homeDrive
        HOMEPATH   = $homePath
    }
}

function Resolve-CacProxyBinding {
    param(
        [Parameter(Mandatory = $true)][string]$AccountKey,
        [string]$ExplicitProxy
    )
    $binding = Get-CacProxyForAccount -AccountKey $AccountKey -ExplicitProxy $ExplicitProxy
    if ($null -eq $binding -and [string]::IsNullOrWhiteSpace($ExplicitProxy)) {
        [void](Ensure-CacProxyBinding -AccountKey $AccountKey)
        $binding = Get-CacProxyForAccount -AccountKey $AccountKey
    }
    return $binding
}

function Get-ProfilePaths {
    param([string]$Name)
    $root = Get-EnvDir $Name
    return [pscustomobject]@{
        Name          = $Name
        Root          = $root
        ConfigDir     = Join-Path $root ".claude"
        HomeDir       = Join-Path $root "home"
        CacheDir      = Join-Path $root "cache"
        TempDir       = Join-Path $root "temp"
        AppData       = Join-Path $root "AppData\Roaming"
        LocalAppData  = Join-Path $root "AppData\Local"
        XdgConfigHome = Join-Path $root "xdg\config"
        XdgCacheHome  = Join-Path $root "xdg\cache"
        CredentialsDir = Join-Path $root "credentials"
        LogsDir       = Join-Path $root "logs"
        AuditDir      = Join-Path $root "audit"
        IdentityPath  = Join-Path $root "identity.json"
        HookAuditPath = Join-Path $root "audit\fingerprint-hook.jsonl"
    }
}

function Ensure-ProfileLayout {
    param([string]$Name)
    $paths = Get-ProfilePaths $Name
    foreach ($dir in @(
        $paths.Root, $paths.ConfigDir, $paths.HomeDir, $paths.CacheDir, $paths.TempDir,
        $paths.AppData, $paths.LocalAppData, $paths.XdgConfigHome, $paths.XdgCacheHome,
        $paths.CredentialsDir, $paths.LogsDir, $paths.AuditDir, (Join-Path $paths.ConfigDir "statsig")
    )) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $identityFiles = [ordered]@{
        uuid        = @{ Path = Join-Path $paths.Root "uuid";        Value = { New-Uuid } }
        stable_id   = @{ Path = Join-Path $paths.Root "stable_id";   Value = { New-Sid } }
        user_id     = @{ Path = Join-Path $paths.Root "user_id";     Value = { New-UserId } }
        machine_id  = @{ Path = Join-Path $paths.Root "machine_id";  Value = { New-MachineId } }
        hostname    = @{ Path = Join-Path $paths.Root "hostname";    Value = { New-FakeHostname } }
        mac_address = @{ Path = Join-Path $paths.Root "mac_address"; Value = { New-FakeMac } }
    }
    foreach ($entry in $identityFiles.GetEnumerator()) {
        if (-not (Test-Path $entry.Value.Path)) {
            Set-Content -LiteralPath $entry.Value.Path -Value (& $entry.Value.Value) -Encoding ASCII
        }
    }
    if (-not (Test-Path (Join-Path $paths.Root "lang"))) {
        Set-Content -LiteralPath (Join-Path $paths.Root "lang") -Value "en_US.UTF-8" -Encoding ASCII
    }
    $nativePolicyPath = Join-Path $paths.Root "native_read_policy"
    if (-not (Test-Path -LiteralPath $nativePolicyPath)) {
        Set-Content -LiteralPath $nativePolicyPath -Value "profile" -Encoding ASCII
    }
    $cpuidModePath = Join-Path $paths.Root "cpuid_mode"
    if (-not (Test-Path -LiteralPath $cpuidModePath)) {
        Set-Content -LiteralPath $cpuidModePath -Value "neutral" -Encoding ASCII
    }
    $networkModePath = Join-Path $paths.Root "network_mode"
    if (-not (Test-Path -LiteralPath $networkModePath)) {
        Set-Content -LiteralPath $networkModePath -Value "profile" -Encoding ASCII
    }

    $existingIdentity = $null
    if (Test-Path -LiteralPath $paths.IdentityPath) {
        try { $existingIdentity = Get-Content -LiteralPath $paths.IdentityPath -Raw | ConvertFrom-Json } catch { $existingIdentity = $null }
    }
    $requiredIdentityFields = @("uuid", "stable_id", "user_id", "machine_id", "hostname", "mac_address")
    $identityValid = ($null -ne $existingIdentity)
    if ($identityValid) {
        foreach ($field in $requiredIdentityFields) {
            $prop = $existingIdentity.PSObject.Properties[$field]
            if ($null -eq $prop -or [string]::IsNullOrWhiteSpace([string]$prop.Value)) { $identityValid = $false }
        }
    }
    $identity = $existingIdentity
    if (-not $identityValid) {
        $identity = [pscustomobject][ordered]@{
            schema      = 1
            name        = $paths.Name
            uuid        = Read-FileValue (Join-Path $paths.Root "uuid")
            stable_id   = Read-FileValue (Join-Path $paths.Root "stable_id")
            user_id     = Read-FileValue (Join-Path $paths.Root "user_id")
            machine_id  = Read-FileValue (Join-Path $paths.Root "machine_id")
            hostname    = Read-FileValue (Join-Path $paths.Root "hostname")
            mac_address = Read-FileValue (Join-Path $paths.Root "mac_address")
            created_utc = [DateTime]::UtcNow.ToString("o")
        }
    }

    # Native-layer fields are deterministic from machine_id so both layers see
    # the same device identity across restarts. Existing values are preserved.
    $uuidValue = [string]$identity.uuid
    $machineValue = [string]$identity.machine_id
    $derived = [ordered]@{
        system_uuid   = ($uuidValue -replace '-', '').ToUpperInvariant()
        disk_serial   = "WD-" + (Get-DerivedHex "$machineValue|disk" 12)
        bios_serial   = "PF" + (Get-DerivedHex "$machineValue|bios" 10)
        board_serial  = "MB" + (Get-DerivedHex "$machineValue|board" 10)
        system_serial = "SYS" + (Get-DerivedHex "$machineValue|system" 10)
        processor_id  = (Get-DerivedHex "$machineValue|cpu" 16).ToUpperInvariant()
        hid_serial    = "HID" + (Get-DerivedHex "$machineValue|hid" 10).ToUpperInvariant()
        volume_serial = (Get-DerivedHex "$machineValue|volume" 8).ToUpperInvariant()
    }
    $identityChanged = (-not $identityValid)
    foreach ($key in $derived.Keys) {
        $existing = $identity.PSObject.Properties[$key]
        if ($null -eq $existing -or [string]::IsNullOrWhiteSpace([string]$existing.Value)) {
            Add-Member -InputObject $identity -NotePropertyName $key -NotePropertyValue $derived[$key] -Force
            $identityChanged = $true
        }
    }
    if ($identityChanged) {
        Set-Content -LiteralPath $paths.IdentityPath -Value ($identity | ConvertTo-Json -Depth 5) -Encoding UTF8
    }
    [void](Resolve-CacProxyBinding -AccountKey ("claude-code:{0}" -f $paths.Name) -ExplicitProxy (Read-FileValue (Join-Path $paths.Root "proxy")))
    return $paths
}

function Read-ProfileIdentity {
    param([psobject]$Paths)
    if (Test-Path -LiteralPath $Paths.IdentityPath) {
        try {
            $identity = Get-Content -LiteralPath $Paths.IdentityPath -Raw | ConvertFrom-Json
            if ($null -ne $identity -and -not [string]::IsNullOrWhiteSpace([string]$identity.machine_id)) {
                return $identity
            }
        } catch { }
    }
    return [pscustomobject]@{
        uuid        = Read-FileValue (Join-Path $Paths.Root "uuid")
        stable_id   = Read-FileValue (Join-Path $Paths.Root "stable_id")
        user_id     = Read-FileValue (Join-Path $Paths.Root "user_id")
        machine_id  = Read-FileValue (Join-Path $Paths.Root "machine_id")
        hostname    = Read-FileValue (Join-Path $Paths.Root "hostname")
        mac_address = Read-FileValue (Join-Path $Paths.Root "mac_address")
        system_uuid   = ""
        disk_serial   = ""
        bios_serial   = ""
        board_serial  = ""
        system_serial = ""
        processor_id  = ""
        hid_serial    = ""
        volume_serial = ""
    }
}

function Get-ProfileEnvironment {
    param([psobject]$Paths)
    [void](Sync-IdentityHook)
    $identity = Read-ProfileIdentity $Paths
    $profileProxy = Read-FileValue (Join-Path $Paths.Root "proxy")
    $proxyBinding = Resolve-CacProxyBinding -AccountKey ("claude-code:{0}" -f $Paths.Name) -ExplicitProxy $profileProxy
    $proxy = if ($null -ne $proxyBinding) { [string]$proxyBinding.url } else { $null }
    $tz = Read-FileValue (Join-Path $Paths.Root "tz")
    $lang = Read-FileValue (Join-Path $Paths.Root "lang") "en_US.UTF-8"
    $nativeReadPolicy = Read-FileValue (Join-Path $Paths.Root "native_read_policy") "profile"
    if ($nativeReadPolicy -notin @("profile", "empty")) { $nativeReadPolicy = "profile" }
    $cpuidMode = Read-FileValue (Join-Path $Paths.Root "cpuid_mode") ""
    if ([string]::IsNullOrWhiteSpace($cpuidMode)) {
        $cpuidMode = if ($nativeReadPolicy -eq "empty") { "empty" } else { "neutral" }
    }
    if ($cpuidMode -notin @("neutral", "empty", "passthrough")) { $cpuidMode = "neutral" }
    $networkMode = Read-FileValue (Join-Path $Paths.Root "network_mode") "profile"
    if ($networkMode -notin @("profile", "clean", "enforce")) { $networkMode = "profile" }
    if ($nativeReadPolicy -eq "empty" -and $networkMode -ne "enforce") { $networkMode = "clean" }
    if ($proxy -and $networkMode -eq "profile") { $networkMode = "enforce" }
    $hostname = [string]$identity.hostname
    $mac = [string]$identity.mac_address
    $machineId = [string]$identity.machine_id
    $stableId = [string]$identity.stable_id
    $userId = [string]$identity.user_id
    $profileUser = "user-$($Paths.Name)"
    $hookPath = Join-Path $CAC_DIR "fingerprint-hook.js"
    $hookPathForNode = $hookPath -replace '\\', '/'
    $hookAuditPath = $Paths.HookAuditPath
    $homeEnvironment = Get-CacIsolatedHomeEnvironment -HomeDir $Paths.HomeDir
    if ($networkMode -eq 'enforce' -and $null -eq $proxyBinding) {
        throw "network_mode=enforce requires a verified proxy binding for $($Paths.Name)"
    }
    $values = [ordered]@{
        CLAUDE_CONFIG_DIR = $Paths.ConfigDir
        HOME              = $homeEnvironment.HOME
        USERPROFILE       = $homeEnvironment.USERPROFILE
        HOMEDRIVE         = $homeEnvironment.HOMEDRIVE
        HOMEPATH          = $homeEnvironment.HOMEPATH
        APPDATA           = $Paths.AppData
        LOCALAPPDATA      = $Paths.LocalAppData
        TEMP              = $Paths.TempDir
        TMP               = $Paths.TempDir
        XDG_CONFIG_HOME   = $Paths.XdgConfigHome
        XDG_CACHE_HOME    = $Paths.XdgCacheHome
        CAC_PROFILE_DIR   = $Paths.Root
        CAC_PROFILE_NAME  = $Paths.Name
        CAC_PROFILE_IDENTITY = $Paths.IdentityPath
        CAC_HOOK_AUDIT     = $hookAuditPath
        CAC_HOOK_MODE      = "node-userland-only"
        CAC_USERNAME      = $profileUser
        CAC_HOSTNAME      = $hostname
        CAC_MAC           = $mac
        CAC_MACHINE_ID    = $machineId
        CAC_NATIVE_READ_POLICY = $nativeReadPolicy
        CAC_NATIVE_CPUID_MODE  = $cpuidMode
        CAC_NETWORK_MODE       = $networkMode
        CAC_NETWORK_ENFORCE    = if ($networkMode -eq "enforce") { "1" } else { "0" }
        CAC_WFP_REQUIRED       = if ($networkMode -eq "enforce") { "1" } else { "0" }
        CAC_KERNEL_POLICY_REQUIRED = if ($networkMode -eq "enforce") { "1" } else { "0" }
        USER              = $profileUser
        USERNAME          = $profileUser
        COMPUTERNAME      = $hostname
        HOSTNAME          = $hostname
        STABLE_ID         = $stableId
        USER_ID           = $userId
        LANG              = $lang
        BUN_JSC_useCodeCache = "false"
        NO_PROXY          = "localhost,127.0.0.1"
    }
    if ($null -ne $proxyBinding) {
        $values.CAC_PROXY_SOURCE = [string]$proxyBinding.source
        if ($proxyBinding.proxyId) { $values.CAC_PROXY_ID = [string]$proxyBinding.proxyId }
    }
    if (Test-Path -LiteralPath $hookPath) {
        $hookOption = '--require "' + $hookPathForNode + '"'
        $preloadOption = '--preload "' + $hookPathForNode + '"'
        # Do not inherit another Profile's preload. Extra runtime options must
        # be added deliberately inside the Profile, never through the parent shell.
        $values.NODE_OPTIONS = $hookOption
        $values.BUN_OPTIONS = $preloadOption
    } else {
        $values.NODE_OPTIONS = ""
        $values.BUN_OPTIONS = ""
    }
    if ($tz) { $values.TZ = $tz }
    if ($proxy) {
        $normalizedProxy = Parse-Proxy $proxy
        if ([string]::IsNullOrWhiteSpace($normalizedProxy)) {
            throw "Invalid proxy configuration in $($Paths.Root): $proxy"
        }
        $proxy = $normalizedProxy
        $values.HTTPS_PROXY = $proxy
        $values.HTTP_PROXY = $proxy
        $values.ALL_PROXY = $proxy
    }
    return $values
}

function Save-ProcessEnvironment {
    param([string[]]$Names)
    $snapshot = @{}
    foreach ($name in $Names) {
        $snapshot[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    return $snapshot
}

function Set-ProcessEnvironment {
    param([System.Collections.IDictionary]$Values, [string[]]$Names)
    foreach ($name in $Names) {
        $value = $null
        if ($Values.Keys -contains $name) { $value = $Values[$name] }
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

function Restore-ProcessEnvironment {
    param([hashtable]$Snapshot)
    foreach ($name in $Snapshot.Keys) {
        [Environment]::SetEnvironmentVariable($name, $Snapshot[$name], "Process")
    }
}

function Get-ClaudeProcesses {
    return @(Get-Process -Name "claude" -ErrorAction SilentlyContinue)
}

function Get-ClaudeProcessTreeIds {
    $rows = @()
    try {
        $rows = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            Select-Object ProcessId, ParentProcessId, Name)
    } catch {
        return @((Get-ClaudeProcesses | ForEach-Object Id))
    }

    $roots = @($rows | Where-Object { $_.Name -ieq "claude.exe" } |
        ForEach-Object { [int]$_.ProcessId })
    if ($roots.Count -eq 0) { return @() }

    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($root in $roots) { [void]$seen.Add($root) }
    do {
        $changed = $false
        foreach ($row in $rows) {
            if ($seen.Contains([int]$row.ParentProcessId) -and $seen.Add([int]$row.ProcessId)) {
                $changed = $true
            }
        }
    } while ($changed)
    return @($seen | ForEach-Object { [int]$_ })
}

function Stop-ClaudeProcesses {
    param([int]$TimeoutSeconds = 10)
    $processIds = @(Get-ClaudeProcessTreeIds)
    if ($processIds.Count -eq 0) { return $true }
    foreach ($processId in ($processIds | Sort-Object -Descending)) {
        try {
            Stop-Process -Id ([int]$processId) -Force -ErrorAction Stop
        } catch {
            if (Get-Process -Id ([int]$processId) -ErrorAction SilentlyContinue) {
                Write-Err "无法结束 Claude 进程树 PID $processId`: $($_.Exception.Message)"
                return $false
            }
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 200
        $remaining = @(Get-ClaudeProcessTreeIds)
    } while ($remaining.Count -gt 0 -and [DateTime]::UtcNow -lt $deadline)
    if ($remaining.Count -gt 0) {
        Write-Err "仍有 $($remaining.Count) 个 Claude 进程树节点未退出"
            return $false
    }
    return $true
}

# Ensure ~/.cac/bin sits BEFORE npm's dir in the user PATH so `claude` resolves
# to our wrapper. Only rewrites when actually out of order — preserves existing
# ordering otherwise. Returns $true if PATH was modified.
function Ensure-CacInPath {
    $binDir = (Join-Path $CAC_DIR "bin").TrimEnd("\")
    $npmDir = (Get-NpmGlobalPrefix).TrimEnd("\")
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if (-not $userPath) { $userPath = "" }
    $parts = [System.Collections.ArrayList]@()
    foreach ($p in ($userPath -split ";")) { if ($p) { [void]$parts.Add($p) } }
    $binIdx = -1; $npmIdx = -1
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $t = $parts[$i].TrimEnd("\")
        if ($binIdx -lt 0 -and $t -eq $binDir) { $binIdx = $i }
        if ($npmIdx -lt 0 -and $t -eq $npmDir) { $npmIdx = $i }
    }
    # Already correct: bin present and (npm absent OR bin before npm)
    if ($binIdx -ge 0 -and ($npmIdx -lt 0 -or $binIdx -lt $npmIdx)) { return $false }
    # Drop any existing bin entry
    $rest = [System.Collections.ArrayList]@()
    foreach ($p in $parts) { if ($p.TrimEnd("\") -ne $binDir) { [void]$rest.Add($p) } }
    # Find npm position in rest; insert bin right before it, else at front
    $at = 0
    for ($i = 0; $i -lt $rest.Count; $i++) { if ($rest[$i].TrimEnd("\") -eq $npmDir) { $at = $i; break } }
    [void]$rest.Insert($at, $binDir)
    [Environment]::SetEnvironmentVariable("PATH", ($rest -join ";"), "User")
    return $true
}

# Which `claude` does a fresh shell actually run? Returns "wrapper", "npm", or "none".
function Test-ClaudeResolution {
    $binDir = Join-Path $CAC_DIR "bin"
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $machPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    foreach ($dir in (("$userPath;$machPath") -split ";")) {
        if (-not $dir) { continue }
        foreach ($n in @("claude.ps1", "claude.cmd", "claude.exe", "claude")) {
            if (Test-Path (Join-Path $dir $n)) {
                if ($dir.TrimEnd("\") -eq $binDir.TrimEnd("\")) { return "wrapper" }
                return "npm"
            }
        }
    }
    return "none"
}

function Update-Statsig {
    param([string]$ConfigDir, [string]$StableId)
    if ([string]::IsNullOrWhiteSpace($ConfigDir) -or [string]::IsNullOrWhiteSpace($StableId)) { return }
    $d = Join-Path $ConfigDir "statsig"
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $files = @(Get-ChildItem (Join-Path $d "statsig.stable_id.*") -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) {
        Set-Content -LiteralPath (Join-Path $d "statsig.stable_id.cac") -Value "`"$StableId`"" -Encoding ASCII
        return
    }
    $files | ForEach-Object {
        if ((Get-Content $_.FullName -Raw).Trim() -ne "`"$StableId`"") { Set-Content $_.FullName "`"$StableId`"" }
    }
}

function Update-ClaudeJsonUserId {
    param([string]$ConfigDir, [string]$UserId, [string]$HomeDir)
    if ([string]::IsNullOrWhiteSpace($ConfigDir) -or [string]::IsNullOrWhiteSpace($UserId)) { return }
    # node instead of ConvertFrom-Json: PS is case-insensitive on keys and
    # chokes on .claude.json "projects" paths that differ only by case.
    # Script goes via a temp file — PS mangles quotes when passing -e inline.
    $js = Join-Path $ConfigDir ".cac-set-userid.js"
    $source = @'
const fs=require("fs"),p=process.argv[2],w=process.argv[3];
const j=JSON.parse(fs.readFileSync(p,"utf8").replace(/^\uFEFF/,""));
if(j.userID!==w){j.userID=w;fs.writeFileSync(p,JSON.stringify(j,null,2));}
'@
    Set-Content $js $source -Encoding ASCII
    $targets = @((Join-Path $ConfigDir ".claude.json"))
    if (-not [string]::IsNullOrWhiteSpace($HomeDir)) { $targets += Join-Path $HomeDir ".claude.json" }
    try {
        foreach ($target in ($targets | Select-Object -Unique)) {
            if (Test-Path $target) { & node $js $target $UserId 2>$null }
        }
    } finally { Remove-Item -LiteralPath $js -Force -ErrorAction SilentlyContinue }
}

function Write-Wrapper {
    $binDir = Join-Path $CAC_DIR "bin"
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    $hookSource = Join-Path $CAC_PACKAGE_ROOT "fingerprint-hook.js"
    $hookTarget = Join-Path $CAC_DIR "fingerprint-hook.js"
    if (Test-Path -LiteralPath $hookSource) {
        Copy-Item -LiteralPath $hookSource -Destination $hookTarget -Force
    }
    $poolSource = Join-Path $PSScriptRoot "proxy-pool-lib.ps1"
    $poolTarget = Join-Path $CAC_DIR "proxy-pool-lib.ps1"
    if (Test-Path -LiteralPath $poolSource) { Copy-Item -LiteralPath $poolSource -Destination $poolTarget -Force }
    $relaySource = Join-Path $CAC_PACKAGE_ROOT "src\relay.js"
    $relayTarget = Join-Path $CAC_DIR "proxy-relay.js"
    if (Test-Path -LiteralPath $relaySource) { Copy-Item -LiteralPath $relaySource -Destination $relayTarget -Force }

    # CMD wrapper delegates to the single PowerShell implementation so both
    # entry points enforce identical profile and integrity rules.
    $cmd = @'
@echo off
setlocal
set "CAC_BIN=%USERPROFILE%\.cac\bin\claude.ps1"
if not exist "%CAC_BIN%" (
    echo [cac] wrapper not initialized >&2
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%CAC_BIN%" %*
exit /b %ERRORLEVEL%
'@

    # PowerShell wrapper
    $ps1 = @'
$ErrorActionPreference = "Stop"
function Get-CacSha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToUpperInvariant()
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
}
function Get-CacDeclaredSha256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw
        $matches = [regex]::Matches($raw, '(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')
        if ($matches.Count -ne 1) { return $null }
        return $matches[0].Value.ToUpperInvariant()
    } catch { return $null }
}
function Get-CacProfileMutexName([string]$ProfileRoot) {
    $fullRoot = [System.IO.Path]::GetFullPath($ProfileRoot).TrimEnd('\').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($fullRoot)) { throw "[cac] profile root is empty" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fullRoot))
        $hex = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        return "Global\cac-profile-$($hex.Substring(0, 32))"
    } finally { $sha.Dispose() }
}
function Enter-CacProfileMutex([string]$ProfileRoot) {
    $name = Get-CacProfileMutexName $ProfileRoot
    $mutex = [System.Threading.Mutex]::new($false, $name)
    try {
        $acquired = $false
        try { $acquired = [bool]$mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { $mutex.Dispose(); return $null }
        return [pscustomobject][ordered]@{ Name = $name; Mutex = $mutex; Acquired = $true }
    } catch {
        try { $mutex.Dispose() } catch { }
        throw
    }
}
function Exit-CacProfileMutex($Lock) {
    if ($null -eq $Lock) { return }
    try { if ([bool]$Lock.Acquired) { [void]$Lock.Mutex.ReleaseMutex() } } catch { }
    finally { try { $Lock.Mutex.Dispose() } catch { } }
}
function Resolve-CacProxyBinding([string]$AccountKey, [string]$ExplicitProxy) {
    $binding = Get-CacProxyForAccount -AccountKey $AccountKey -ExplicitProxy $ExplicitProxy
    if ($null -eq $binding -and [string]::IsNullOrWhiteSpace($ExplicitProxy)) {
        [void](Ensure-CacProxyBinding -AccountKey $AccountKey)
        $binding = Get-CacProxyForAccount -AccountKey $AccountKey
    }
    return $binding
}
function Get-CacHomeEnvironment([string]$HomeDir) {
    $fullHome = [System.IO.Path]::GetFullPath($HomeDir)
    $homeRoot = [System.IO.Path]::GetPathRoot($fullHome)
    if ($homeRoot -notmatch '^[A-Za-z]:\\$') { throw "[cac] unable to derive HOMEDRIVE/HOMEPATH" }
    $homePath = $fullHome.Substring(2)
    if ([string]::IsNullOrWhiteSpace($homePath)) { throw "[cac] unable to derive HOMEDRIVE/HOMEPATH" }
    return [ordered]@{ HOME = $fullHome; USERPROFILE = $fullHome; HOMEDRIVE = $homeRoot.Substring(0, 2); HOMEPATH = $homePath }
}
$cacHome = $env:USERPROFILE
$d = Join-Path $cacHome ".cac"
$proxyPoolModule = Join-Path $d "proxy-pool-lib.ps1"
if (-not (Test-Path -LiteralPath $proxyPoolModule -PathType Leaf)) { Write-Error "[cac] proxy pool module is missing; reinitialize cac-windows"; exit 1 }
. $proxyPoolModule
$hook = Join-Path $d "fingerprint-hook.js"
if (-not (Test-Path -LiteralPath $hook)) { Write-Error "[cac] Profile identity hook is missing; reinitialize cac-windows"; exit 1 }
$cf = Join-Path $d "current"
$realFile = Join-Path $d "real_claude"
if (-not (Test-Path $cf)) { Write-Error "[cac] no active env"; exit 1 }
if (-not (Test-Path $realFile)) { Write-Error "[cac] real claude path is missing"; exit 1 }
$en = (Get-Content $cf -Raw).Trim()
if ($en -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { Write-Error "[cac] invalid active env"; exit 1 }
$ed = Join-Path $d "envs\$en"
$profileRoot = [System.IO.Path]::GetFullPath($ed)
$profileLock = Enter-CacProfileMutex $profileRoot
if ($null -eq $profileLock) {
    Write-Error "[cac] Profile '$en' is already in use"
    exit 1
}
$config = Join-Path $ed ".claude"
$homeDir = Join-Path $ed "home"
$appData = Join-Path $ed "AppData\Roaming"
$localAppData = Join-Path $ed "AppData\Local"
$cache = Join-Path $ed "cache"
$temp = Join-Path $ed "temp"
$xdgConfig = Join-Path $ed "xdg\config"
$xdgCache = Join-Path $ed "xdg\cache"
$credentials = Join-Path $ed "credentials"
$logs = Join-Path $ed "logs"
$audit = Join-Path $ed "audit"
try {
foreach ($dir in @($ed,$config,$homeDir,$appData,$localAppData,$cache,$temp,$xdgConfig,$xdgCache,$credentials,$logs,$audit)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$running = @(Get-Process -Name "claude" -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Write-Error "[cac] another Claude session is running; switch profiles only after it exits"
    exit 1
}

$real = (Get-Content $realFile -Raw).Trim()
if (-not (Test-Path $real)) { Write-Error "[cac] claude not found: $real"; exit 1 }
$ccDir = Split-Path (Split-Path $real -Parent) -Parent
$pkg = Join-Path $ccDir "package.json"
$manifest = Join-Path $d "claude-binary-manifest.json"
if (-not (Test-Path $pkg)) { Write-Error "[cac] Claude Code package.json is missing"; exit 1 }
if (-not (Test-Path $manifest)) { Write-Error "[cac] binary integrity manifest is missing; run cac to repair"; exit 1 }
$cc = Get-Content $pkg -Raw | ConvertFrom-Json
if ($cc.version -ne "2.1.294") { Write-Error "[cac] unsupported Claude Code version: $($cc.version)"; exit 1 }
$manifestData = Get-Content $manifest -Raw | ConvertFrom-Json
if ($manifestData.claudeVersion -ne "2.1.294" -or -not $manifestData.markersOk) {
    Write-Error "[cac] binary manifest is incomplete; run cac to repair"
    exit 1
}
$actualHash = Get-CacSha256 $real
if ($actualHash -ne ([string]$manifestData.sha256).ToUpperInvariant()) {
    Write-Error "[cac] claude.exe SHA-256 mismatch; launch refused"
    exit 1
}

$proxyFile = Join-Path $ed "proxy"
$profileProxy = if (Test-Path $proxyFile) { (Get-Content $proxyFile -Raw).Trim() } else { '' }
$proxyBinding = Resolve-CacProxyBinding -AccountKey ("claude-code:{0}" -f $en) -ExplicitProxy $profileProxy
$upstreamProxy = if ($null -ne $proxyBinding) { [string]$proxyBinding.url } else { $null }
$relay = $null
if ($upstreamProxy) {
    try { $relay = Start-CacProxyRelay -UpstreamProxyUrl $upstreamProxy -LogsDir $logs }
    catch { throw "[cac] proxy relay failed closed: $($_.Exception.Message)" }
    $env:HTTPS_PROXY=$relay.url; $env:HTTP_PROXY=$relay.url; $env:ALL_PROXY=$relay.url
    $env:CAC_HTTP_PROXY_LOCAL=$relay.url
    if ($null -ne $proxyBinding -and $proxyBinding.proxyId) { $env:CAC_PROXY_ID=[string]$proxyBinding.proxyId }
    $env:CAC_PROXY_SOURCE=[string]$proxyBinding.source
} else {
    Remove-Item Env:HTTPS_PROXY,Env:HTTP_PROXY,Env:ALL_PROXY,Env:CAC_HTTP_PROXY_LOCAL,Env:CAC_PROXY_UPSTREAM,Env:CAC_PROXY_ID,Env:CAC_PROXY_SOURCE -ErrorAction SilentlyContinue
}
$env:NO_PROXY = "localhost,127.0.0.1"
$tz = Join-Path $ed "tz"
if (Test-Path $tz) { $env:TZ = (Get-Content $tz -Raw).Trim() } else { Remove-Item Env:TZ -ErrorAction SilentlyContinue }
$lang = Join-Path $ed "lang"
if (Test-Path $lang) { $env:LANG = (Get-Content $lang -Raw).Trim() } else { $env:LANG = "en_US.UTF-8" }

# Bind all home/config/cache/temp surfaces to this profile before starting Claude.
$homeEnvironment = Get-CacHomeEnvironment $homeDir
$env:CLAUDE_CONFIG_DIR = $config
$env:HOME = $homeEnvironment.HOME
$env:USERPROFILE = $homeEnvironment.USERPROFILE
$env:HOMEDRIVE = $homeEnvironment.HOMEDRIVE
$env:HOMEPATH = $homeEnvironment.HOMEPATH
$env:APPDATA = $appData
$env:LOCALAPPDATA = $localAppData
$env:TEMP = $temp
$env:TMP = $temp
$env:XDG_CONFIG_HOME = $xdgConfig
$env:XDG_CACHE_HOME = $xdgCache
$env:CAC_PROFILE_DIR = $ed
$env:CAC_PROFILE_NAME = $en
$identityPath = Join-Path $ed "identity.json"
$identity = $null
if (Test-Path -LiteralPath $identityPath) {
    try { $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json } catch { $identity = $null }
}
if ($null -eq $identity) {
    $identity = [pscustomobject]@{
        machine_id = (Get-Content (Join-Path $ed "machine_id") -Raw).Trim()
        hostname = (Get-Content (Join-Path $ed "hostname") -Raw).Trim()
        mac_address = (Get-Content (Join-Path $ed "mac_address") -Raw).Trim()
    }
}
$profileUser = "user-$en"
$env:CAC_PROFILE_IDENTITY = $identityPath
$env:CAC_HOOK_AUDIT = Join-Path $audit "fingerprint-hook.jsonl"
$env:CAC_HOOK_MODE = "node-userland-only"
$env:CAC_USERNAME = $profileUser
$env:USER = $profileUser
$env:USERNAME = $profileUser
$env:CAC_HOSTNAME = [string]$identity.hostname
$env:HOSTNAME = [string]$identity.hostname
$env:COMPUTERNAME = [string]$identity.hostname
$env:CAC_MAC = [string]$identity.mac_address
$env:CAC_MACHINE_ID = [string]$identity.machine_id
$nativeReadPolicy = if (Test-Path (Join-Path $ed "native_read_policy")) {
    (Get-Content (Join-Path $ed "native_read_policy") -Raw).Trim()
} else { "profile" }
if ($nativeReadPolicy -notin @("profile", "empty")) { $nativeReadPolicy = "profile" }
$cpuidMode = if (Test-Path (Join-Path $ed "cpuid_mode")) {
    (Get-Content (Join-Path $ed "cpuid_mode") -Raw).Trim()
} else { "" }
if ([string]::IsNullOrWhiteSpace($cpuidMode)) {
    $cpuidMode = if ($nativeReadPolicy -eq "empty") { "empty" } else { "neutral" }
}
if ($cpuidMode -notin @("neutral", "empty", "passthrough")) { $cpuidMode = "neutral" }
$env:CAC_NATIVE_READ_POLICY = $nativeReadPolicy
$env:CAC_NATIVE_CPUID_MODE = $cpuidMode
$networkMode = if (Test-Path (Join-Path $ed "network_mode")) {
    (Get-Content (Join-Path $ed "network_mode") -Raw).Trim().ToLowerInvariant()
} else { "profile" }
if ($networkMode -notin @("profile", "clean", "enforce")) { $networkMode = "profile" }
if ($nativeReadPolicy -eq "empty" -and $networkMode -ne "enforce") { $networkMode = "clean" }
if ($upstreamProxy -and $networkMode -eq "profile") { $networkMode = "enforce" }
if ($networkMode -eq "enforce" -and -not $upstreamProxy) {
    throw "[cac] network_mode=enforce requires a verified proxy binding"
}
$env:CAC_NETWORK_MODE = $networkMode
$env:CAC_NETWORK_ENFORCE = if ($networkMode -eq "enforce") { "1" } else { "0" }
$env:CAC_WFP_REQUIRED = if ($networkMode -eq "enforce") { "1" } else { "0" }
$env:BUN_JSC_useCodeCache = "false"

if (Test-Path -LiteralPath $hook) {
    $hookForNode = $hook -replace '\\', '/'
    $nodeHook = '--require "' + $hookForNode + '"'
    $env:NODE_OPTIONS = $nodeHook
    $bunHook = '--preload "' + $hookForNode + '"'
    $env:BUN_OPTIONS = $bunHook
}

$sid = Join-Path $ed "stable_id"
if (Test-Path $sid) {
    $stable = (Get-Content $sid -Raw).Trim()
    $sd = Join-Path $config "statsig"
    New-Item -ItemType Directory -Path $sd -Force | Out-Null
    $statsigFiles = @(Get-ChildItem (Join-Path $sd "statsig.stable_id.*") -ErrorAction SilentlyContinue)
    if ($statsigFiles.Count -eq 0) {
        Set-Content -LiteralPath (Join-Path $sd "statsig.stable_id.cac") -Value "`"$stable`"" -Encoding ASCII
    } else {
        $statsigFiles | ForEach-Object {
            Set-Content $_.FullName "`"$stable`"" -Encoding ASCII
        }
    }
}
$uid = Join-Path $ed "user_id"
$cjTargets = @((Join-Path $config ".claude.json"), (Join-Path $homeDir ".claude.json"))
if (Test-Path $uid) {
    $js = Join-Path $config ".cac-set-userid.js"
    Set-Content $js 'const fs=require("fs"),p=process.argv[2],w=process.argv[3];const j=JSON.parse(fs.readFileSync(p,"utf8").replace(/^\uFEFF/,""));if(j.userID!==w){j.userID=w;fs.writeFileSync(p,JSON.stringify(j,null,2));}' -Encoding ASCII
    try {
        foreach ($cj in ($cjTargets | Select-Object -Unique)) {
            if (Test-Path $cj) { & node $js $cj (Get-Content $uid -Raw).Trim() 2>$null }
        }
    } finally { Remove-Item -LiteralPath $js -Force -ErrorAction SilentlyContinue }
}

$nativeLauncher = Join-Path $d "native\cac-native-launch.exe"
$nativeDll = Join-Path $d "native\NativeBridge.dll"
$nativeDllHashFile = Join-Path $d "native\NativeBridge.sha256"
$nativeLauncherHashFile = Join-Path $d "native\cac-native-launch.sha256"
$nativeManifest = Join-Path $d "native\native-hook-manifest.txt"
$env:CAC_NATIVE_AUDIT = Join-Path $audit "native-hook.jsonl"
$env:CAC_KERNEL_POLICY_REQUIRED = "0"
if ((Test-Path -LiteralPath $nativeLauncher) -and (Test-Path -LiteralPath $nativeDll) -and ($real -like "*.exe")) {
    if (-not (Test-Path -LiteralPath $nativeDllHashFile -PathType Leaf) -or
        -not (Test-Path -LiteralPath $nativeLauncherHashFile -PathType Leaf)) {
        Write-Error "[cac] Native integrity manifests are missing; run cac to resync the release artifacts"
        exit 1
    }
    $expectedDllHash = Get-CacDeclaredSha256 $nativeDllHashFile
    $expectedLauncherHash = Get-CacDeclaredSha256 $nativeLauncherHashFile
    if (-not $expectedDllHash -or -not $expectedLauncherHash -or
        (Get-CacSha256 $nativeDll) -ne $expectedDllHash -or
        (Get-CacSha256 $nativeLauncher) -ne $expectedLauncherHash) {
        Write-Error "[cac] NativeBridge or launcher SHA-256 mismatch; launch refused"
        exit 1
    }
    $env:CAC_NATIVE_DLL = $nativeDll
    $env:CAC_KERNEL_POLICY_REQUIRED = if ($networkMode -eq "enforce") { "1" } else { "0" }
    if (Test-Path -LiteralPath $nativeManifest) { $env:CAC_NATIVE_MANIFEST = $nativeManifest }
    & $nativeLauncher $real @args
} elseif ($networkMode -eq "enforce") {
    Write-Error "[cac] network_mode=enforce requires the verified NativeBridge launcher"
    exit 1
} else {
    & $real @args
}
    $exitCode = $LASTEXITCODE
} finally {
    Stop-CacProxyRelay $relay
    Exit-CacProfileMutex $profileLock
}
exit $exitCode
'@
    $ps1Path = Join-Path $binDir "claude.ps1"
    $cmdPath = Join-Path $binDir "claude.cmd"
    $changed = $false
    if ((Read-FileValue $ps1Path) -ne $ps1.Trim()) { Set-Content $ps1Path $ps1 -Encoding UTF8; $changed = $true }
    if ((Read-FileValue $cmdPath) -ne $cmd.Trim()) { Set-Content $cmdPath $cmd -Encoding ASCII; $changed = $true }
    return $changed
}
