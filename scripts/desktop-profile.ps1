#requires -Version 5.1
# Isolated Claude Desktop launcher. Built-in PowerShell cmdlets only.
#
# Examples:
#   powershell -NoProfile -File .\desktop-profile.ps1 -Action create -Profile work
#   powershell -NoProfile -File .\desktop-profile.ps1 -Action list
#   powershell -NoProfile -File .\desktop-profile.ps1 -Action status -Profile work
#   powershell -NoProfile -File .\desktop-profile.ps1 -Action launch -Profile work
#   powershell -NoProfile -File .\desktop-profile.ps1 -Action ab -WaitSeconds 45
#   powershell -NoProfile -File .\desktop-profile.ps1 -Action cleanup -Profile work

param(
    [ValidateSet('create','list','launch','status','stop','ab','cleanup','remove-ca','monitor')][string]$Action = 'status',
    [string]$Profile,
    [string]$Exe = 'C:\Program Files\WindowsApps\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\app\claude.exe',
    [string]$MitmDump,
    [switch]$Inject,
    [switch]$Fingerprint,
    [switch]$RequireKernel,
    [int]$WaitSeconds = 30,
    [int]$WatchPid = 0,
    [int]$RelayPid = 0,
    [int]$MitmPid = 0,
    [string]$WatchPath,
    [string]$WatchStartUtc,
    [string]$RelayPath,
    [string]$RelayStartUtc,
    [string]$MitmPath,
    [string]$MitmStartUtc,
    [string]$RelayPidFile,
    [string]$MitmPidFile,
    [string]$MitmProcessPidFile,
    [string]$CaPath,
    [string]$LaunchStateFile,
    [string]$LaunchGeneration,
    [string]$MonitorReadyFile,
    [switch]$NativeRequired,
    [switch]$RemoveCaAfterExit,
    [switch]$SuppressProxyWarning
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'cert-silent.ps1')
. (Join-Path $PSScriptRoot 'proxy-pool-lib.ps1')

if (-not ('CacPathNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class CacPathNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetShortPathName(string longPath, StringBuilder shortPath, uint bufferLength);
}
'@
}

$script:OriginalUserProfile = $env:USERPROFILE
$script:DesktopRoot = [System.IO.Path]::GetFullPath((Join-Path $script:OriginalUserProfile '.cac\desktop'))
$script:DesktopScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Definition }
$script:ProfilePattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
$script:LayoutFolders = @(
    'config',
    'home',
    'home\AppData\Roaming',
    'home\AppData\Local',
    'home\AppData\Roaming\Claude',
    'home\AppData\Local\Claude-3p',
    'home\AppData\Roaming\Claude-3p',
    'mitmproxy',
    'temp',
    'audit',
    'logs'
)

function Get-Sha256 {
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

function Get-StringSha256 {
    param([string]$Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Value)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToUpperInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-DeclaredSha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "SHA-256 manifest is missing: $Path"
    }
    $matches = [regex]::Matches((Get-Content -LiteralPath $Path -Raw), '(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')
    if ($matches.Count -ne 1) {
        throw "SHA-256 manifest must contain exactly one digest: $Path"
    }
    return $matches[0].Value.ToUpperInvariant()
}

function Read-FileValue {
    param([string]$Path, [string]$Default = '')
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return (Get-Content -LiteralPath $Path -Raw).Trim()
    }
    return $Default
}

function Get-IanaTimeZone {
    $id = (Get-TimeZone).Id
    $map = @{
        'China Standard Time'          = 'Asia/Shanghai'
        'Tokyo Standard Time'          = 'Asia/Tokyo'
        'Korea Standard Time'          = 'Asia/Seoul'
        'Taipei Standard Time'         = 'Asia/Taipei'
        'Singapore Standard Time'      = 'Asia/Singapore'
        'India Standard Time'          = 'Asia/Kolkata'
        'Pacific Standard Time'        = 'America/Los_Angeles'
        'Mountain Standard Time'       = 'America/Denver'
        'Central Standard Time'        = 'America/Chicago'
        'Eastern Standard Time'        = 'America/New_York'
        'GMT Standard Time'            = 'Europe/London'
        'W. Europe Standard Time'      = 'Europe/Berlin'
        'Central Europe Standard Time' = 'Europe/Budapest'
        'Romance Standard Time'        = 'Europe/Paris'
        'Russian Standard Time'        = 'Europe/Moscow'
        'AUS Eastern Standard Time'    = 'Australia/Sydney'
    }
    if ($map.ContainsKey($id)) { return $map[$id] }
    if (-not [string]::IsNullOrWhiteSpace($env:TZ)) { return $env:TZ.Trim() }
    return 'UTC'
}

function Get-NormalizedProxy {
    param([string]$Value)
    $normalized = ConvertTo-CacProxyUrl $Value
    if ($null -eq $normalized) { return '' }
    return $normalized
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Get-ChromiumPersonaVersion {
    param(
        [string]$ExePath,
        [switch]$IgnoreConfigured
    )

    $electronVersion = ''
    if (-not [string]::IsNullOrWhiteSpace($ExePath)) {
        $versionPath = Join-Path (Split-Path -Parent $ExePath) 'version'
        $electronVersion = Read-FileValue -Path $versionPath
    }
    if ($electronVersion -notmatch '^\d+\.\d+\.\d+') {
        $electronVersion = '45.0.0'
    }

    $electronMajor = 45
    if ($electronVersion -match '^(\d+)') {
        $electronMajor = [int]$Matches[1]
    }

    $configuredChromium = $null
    if (-not $IgnoreConfigured) {
        $configuredChromium = [Environment]::GetEnvironmentVariable('CAC_CHROMIUM_VERSION', 'Process')
    }
    if ($configuredChromium -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        $configuredChromium = $null
    }
    $knownChromium = @{
        '45.2.1' = '156.0.8078.75'
        '45.2.2' = '156.0.8078.80'
        '45.2.3' = '156.0.8078.80'
        '45.3.0' = '156.0.8078.96'
        '45.3.1' = '156.0.8078.96'
        '45.3.2' = '156.0.8078.100'
    }
    $knownChromiumMajor = @{
        45 = 156
        44 = 152
        43 = 150
        42 = 148
        41 = 146
    }
    if ($configuredChromium) {
        $chromiumVersion = $configuredChromium
    } elseif ($knownChromium.ContainsKey($electronVersion)) {
        $chromiumVersion = $knownChromium[$electronVersion]
    } elseif ($knownChromiumMajor.ContainsKey($electronMajor)) {
        $chromiumVersion = "$($knownChromiumMajor[$electronMajor]).0.0.0"
    } else {
        throw "Chromium version is unknown for Electron $electronVersion; set CAC_CHROMIUM_VERSION before fingerprint launch"
    }

    return [pscustomobject]@{
        electronVersion = $electronVersion
        electronMajor   = $electronMajor
        chromiumVersion = $chromiumVersion
        chromiumMajor   = [int]($chromiumVersion.Split('.')[0])
    }
}

function Initialize-ProfilePersona {
    param(
        [psobject]$Paths,
        [string]$ExePath
    )
    New-Item -ItemType Directory -Path $Paths.Root -Force | Out-Null
    $path = Join-Path $Paths.Root 'fingerprint.json'
    $lockPath = Join-Path $Paths.Root 'device-image.lock.json'
    $hasLock = Test-Path -LiteralPath $lockPath -PathType Leaf
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try {
            $existingPersona = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
            foreach ($field in @('seed', 'ua', 'timezone', 'locale', 'uaElectronVersion', 'uaChromiumVersion')) {
                if ([string]::IsNullOrWhiteSpace([string]$existingPersona.$field)) {
                    throw "fingerprint.json is missing required field: $field"
                }
            }
            if ($null -eq $existingPersona.uaBrands -or $null -eq $existingPersona.languages) {
                throw 'fingerprint.json is missing uaBrands or languages'
            }
            $textEncoding = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText((Join-Path $Paths.Root 'tz'), ([string]$existingPersona.timezone + [Environment]::NewLine), $textEncoding)
            [System.IO.File]::WriteAllText((Join-Path $Paths.Root 'locale'), ([string]$existingPersona.locale + [Environment]::NewLine), $textEncoding)
            [System.IO.File]::WriteAllText((Join-Path $Paths.Root 'languages'), ((@($existingPersona.languages) -join ',') + [Environment]::NewLine), $textEncoding)
            return $path
        } catch {
            if ($hasLock) { throw "Locked fingerprint.json is invalid: $($_.Exception.Message)" }
        }
    }
    if ($hasLock) { throw "Locked fingerprint.json is missing: $path" }

    $browser = Get-ChromiumPersonaVersion -ExePath $ExePath
    $identity = Initialize-ProfileIdentity -Paths $Paths
    $locale = ([string]$env:CAC_PROFILE_LOCALE).Trim()
    if ([string]::IsNullOrWhiteSpace($locale)) { $locale = 'en-US' }
    $configuredLanguages = @(([string]$env:CAC_PROFILE_LANGUAGES -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($configuredLanguages.Count -eq 0) { $configuredLanguages = @('en-US', 'en') }
    $languages = @(@($locale) + $configuredLanguages) | Select-Object -Unique
    if ($languages.Count -eq 0) { $languages = @($locale) }
    $timezone = ([string]$env:CAC_PROFILE_TIMEZONE).Trim()
    if ([string]::IsNullOrWhiteSpace($timezone)) { $timezone = 'America/New_York' }

    $originProxyId = ([string]$env:CAC_PROFILE_ORIGIN_PROXY_ID).Trim()
    $origin = $null
    if (-not [string]::IsNullOrWhiteSpace($originProxyId)) {
        $originProvider = ([string]$env:CAC_PROFILE_ORIGIN_PROVIDER).Trim()
        $originIp = ([string]$env:CAC_PROFILE_ORIGIN_IP).Trim()
        $originCountry = ([string]$env:CAC_PROFILE_ORIGIN_COUNTRY).Trim().ToUpperInvariant()
        $originDnsMode = ([string]$env:CAC_PROFILE_ORIGIN_DNS_MODE).Trim()
        $originCapturedUtc = ([string]$env:CAC_PROFILE_ORIGIN_CAPTURED_UTC).Trim()
        foreach ($required in @($originProvider, $originIp, $originCountry, $originDnsMode, $originCapturedUtc)) {
            if ([string]::IsNullOrWhiteSpace($required)) { throw 'First SOCKS5 Profile origin is incomplete' }
        }
        $origin = [ordered]@{
            source      = 'first-socks5'
            provider    = $originProvider
            proxyId     = $originProxyId
            externalIp  = $originIp
            countryCode = $originCountry
            region      = ([string]$env:CAC_PROFILE_ORIGIN_REGION).Trim()
            city        = ([string]$env:CAC_PROFILE_ORIGIN_CITY).Trim()
            dnsMode     = $originDnsMode
            capturedUtc = $originCapturedUtc
        }
    }

    $gpu = $null
    try {
        $gpu = (Get-CimInstance Win32_VideoController -ErrorAction Stop |
            Where-Object { $_.Name } | Select-Object -First 1).Name
    } catch { }
    if ([string]::IsNullOrWhiteSpace($gpu)) { $gpu = 'Generic Display Adapter' }
    $shortVendor = 'Google'
    if ($gpu -match 'NVIDIA') { $shortVendor = 'NVIDIA' }
    elseif ($gpu -match 'AMD|Radeon') { $shortVendor = 'AMD' }
    elseif ($gpu -match 'Intel') { $shortVendor = 'Intel' }
    $renderer = if ($gpu -match 'Basic Display|SwiftShader') {
        'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)'
    } else {
        "ANGLE ($shortVendor, $gpu Direct3D11 vs_5_0 ps_5_0, D3D11)"
    }

    $width = 1920
    $height = 1080
    try {
        $video = Get-CimInstance Win32_VideoController -ErrorAction Stop |
            Where-Object { $_.CurrentHorizontalResolution -and $_.CurrentVerticalResolution } |
            Select-Object -First 1
        if ($video) {
            $width = [int]$video.CurrentHorizontalResolution
            $height = [int]$video.CurrentVerticalResolution
        }
    } catch { }

    $cores = [Environment]::ProcessorCount
    if ($cores -lt 1) { $cores = 8 }
    $memoryGb = 8
    try {
        $bytes = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory
        $memoryGb = [Math]::Min(8, [Math]::Max(4, [Math]::Round($bytes / 1GB)))
    } catch { }

    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$($browser.chromiumVersion) Safari/537.36 Electron/$($browser.electronVersion)"
    $uaBrands = @(
        [ordered]@{ brand = 'Not_A Brand'; version = '99' },
        [ordered]@{ brand = 'Chromium'; version = [string]$browser.chromiumMajor }
    )
    $uaHighEntropy = [ordered]@{
        brands          = @($uaBrands)
        mobile          = $false
        platform        = 'Windows'
        platformVersion = [Environment]::OSVersion.Version.ToString()
        architecture    = 'x86'
        bitness         = '64'
        model           = ''
        uaFullVersion   = $browser.chromiumVersion
        fullVersionList = @($uaBrands)
        wow64           = $false
    }

    $persona = [ordered]@{
            schema              = if ($null -ne $origin) { 2 } else { 1 }
            seed                = "$($Paths.Name)|$([string]$identity.machine_id)"
            timezone            = $timezone
            locale              = $locale
            languages           = @($languages)
            platform            = 'Win32'
            maxTouchPoints      = 0
            ua                  = $ua
            uaMobile            = $false
            uaPlatform          = 'Windows'
            uaBrands            = @($uaBrands)
            uaHighEntropy       = $uaHighEntropy
            uaElectronVersion   = $browser.electronVersion
            uaChromiumVersion   = $browser.chromiumVersion
            hardwareConcurrency = $cores
            deviceMemory        = $memoryGb
            connection          = [ordered]@{
                effectiveType = '4g'
                rtt           = 50
                downlink      = 10
                saveData      = $false
            }
            screen              = [ordered]@{
                width      = $width
                height     = $height
                availWidth = $width
                availHeight = [Math]::Max(600, $height - 40)
                colorDepth = 24
                pixelDepth = 24
                dpr        = 1
            }
            webgl               = [ordered]@{
                vendor   = "Google Inc. ($shortVendor)"
                renderer = $renderer
            }
            canvasNoise         = 1
            audioNoise          = 0.0000001
            webrtc              = 'filter-private'
            origin              = $origin
    }
    $json = $persona | ConvertTo-Json -Depth 8
    $textEncoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $json + [Environment]::NewLine, $textEncoding)
    [System.IO.File]::WriteAllText((Join-Path $Paths.Root 'tz'), ($timezone + [Environment]::NewLine), $textEncoding)
    [System.IO.File]::WriteAllText((Join-Path $Paths.Root 'locale'), ($locale + [Environment]::NewLine), $textEncoding)
    [System.IO.File]::WriteAllText((Join-Path $Paths.Root 'languages'), (($languages -join ',') + [Environment]::NewLine), $textEncoding)
    return $path
}

function Test-ProfileName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($Name -match $script:ProfilePattern)
}

function Resolve-ProfileName {
    param([string]$Requested)
    $name = $Requested
    if ([string]::IsNullOrWhiteSpace($name)) {
        $name = [Environment]::GetEnvironmentVariable('CAC_PROFILE_NAME', 'Process')
    }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = 'default' }
    if (-not (Test-ProfileName $name)) {
        throw "Profile name is invalid: $name"
    }
    return $name
}

function Get-ProfilePaths {
    param([string]$Name)
    if (-not (Test-ProfileName $Name)) {
        throw "Profile name is invalid: $Name"
    }
    $root = [System.IO.Path]::GetFullPath((Join-Path $script:DesktopRoot $Name))
    return [pscustomobject]@{
        Name             = $Name
        Root             = $root
        AppData          = (Join-Path $root 'home\AppData\Roaming')
        LocalAppData     = (Join-Path $root 'home\AppData\Local')
        Home             = (Join-Path $root 'home')
        ConfigDir        = (Join-Path $root 'config')
        Temp             = (Join-Path $root 'temp')
        ClaudeDir        = (Join-Path $root 'Claude')
        Claude3pDir      = (Join-Path $root 'Claude-3p')
        MitmDir          = (Join-Path $root 'mitmproxy')
        AuditDir         = (Join-Path $root 'audit')
        LogsDir          = (Join-Path $root 'logs')
        UserDataDir      = (Join-Path $root 'home\AppData\Roaming\Claude')
        IdentityPath     = (Join-Path $root 'identity.json')
        DeviceImageLock  = (Join-Path $root 'device-image.lock.json')
        AntDidPrimary    = (Join-Path $root 'home\AppData\Roaming\Claude\ant-did')
        AntDidFallback   = (Join-Path $root 'home\AppData\Local\Claude-3p\ant-did')
    }
}

function Get-DesktopProfileMutexName {
    param([Parameter(Mandatory = $true)][string]$ProfileRoot)
    $fullRoot = [System.IO.Path]::GetFullPath($ProfileRoot).TrimEnd('\').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($fullRoot)) { throw 'Profile root is empty' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fullRoot))
        $hex = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        return "Global\cac-profile-$($hex.Substring(0, 32))"
    } finally { $sha.Dispose() }
}

function Enter-DesktopProfileMutex {
    param(
        [Parameter(Mandatory = $true)][string]$ProfileRoot,
        [int]$TimeoutMilliseconds = 0
    )
    $mutex = New-Object System.Threading.Mutex($false, (Get-DesktopProfileMutexName $ProfileRoot))
    try {
        $acquired = $false
        try { $acquired = [bool]$mutex.WaitOne($TimeoutMilliseconds) }
        catch [System.Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) {
            $mutex.Dispose()
            return $null
        }
        return [pscustomobject][ordered]@{ Mutex = $mutex; Acquired = $true }
    } catch {
        try { $mutex.Dispose() } catch { }
        throw
    }
}

function Exit-DesktopProfileMutex {
    param([object]$Lock)
    if ($null -eq $Lock) { return }
    try {
        if ([bool]$Lock.Acquired) { [void]$Lock.Mutex.ReleaseMutex() }
    } catch { }
    finally { try { $Lock.Mutex.Dispose() } catch { } }
}

function Test-TextPathMarker {
    param(
        [string]$Text,
        [string]$Marker
    )
    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Marker)) { return $false }
    $needle = $Marker.TrimEnd([char[]]@('\', '/'))
    if ([string]::IsNullOrWhiteSpace($needle)) { return $false }
    $offset = 0
    while ($offset -lt $Text.Length) {
        $index = $Text.IndexOf($needle, $offset, [StringComparison]::OrdinalIgnoreCase)
        if ($index -lt 0) { return $false }
        $beforeOk = ($index -eq 0 -or $Text[$index - 1] -notmatch '[A-Za-z0-9._-]')
        $afterIndex = $index + $needle.Length
        $afterOk = ($afterIndex -ge $Text.Length -or $Text[$afterIndex] -match '[\\/"''\s=;]')
        if ($beforeOk -and $afterOk) { return $true }
        $offset = $index + 1
    }
    return $false
}

function Write-DesktopStateFile {
    param(
        [string]$Path,
        [string]$State,
        [string]$Generation,
        [int]$RootPid = 0,
        [string]$RootPath,
        [string]$RootStartUtc,
        [string]$ErrorText,
        [string]$CaPath,
        [bool]$RemoveCa = $false
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [pscustomobject][ordered]@{
        state       = $State
        generation  = $Generation
        rootPid     = $RootPid
        rootPath    = $RootPath
        rootStartUtc = $RootStartUtc
        monitorPid  = $PID
        caPath      = $CaPath
        removeCa    = $RemoveCa
        error       = $ErrorText
        updatedUtc  = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Read-DesktopStateFile {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { return $null }
}

function Write-DesktopHealthFile {
    param(
        [string]$Path,
        [string]$State,
        [string]$Generation,
        [int]$RootPid = 0,
        [string]$RootPath,
        [string]$RootStartUtc,
        [string]$RelayState = 'not-configured',
        [string]$MitmState = 'not-configured',
        [string[]]$Warnings = @(),
        [string[]]$Faults = @(),
        [bool]$Fatal = $false,
        [string]$FatalReason
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $tempPath = '{0}.{1}.{2}.tmp' -f $Path, $PID, ([Guid]::NewGuid().ToString('N'))
    $payload = [ordered]@{
        schema       = 1
        state        = $State
        generation   = $Generation
        rootPid      = $RootPid
        rootPath     = $RootPath
        rootStartUtc = $RootStartUtc
        relayState   = $RelayState
        mitmState    = $MitmState
        warnings     = @($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        faults       = @($Faults | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        fatal        = $Fatal
        fatalReason  = $FatalReason
        updatedUtc   = [DateTime]::UtcNow.ToString('o')
    }
    try {
        $payload | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath $tempPath -Encoding UTF8
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
    } catch {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-DesktopNativeFaults {
    param(
        [string]$AuditPath,
        [int[]]$ProcessIds = @(),
        [DateTime]$SinceUtc = [DateTime]::MinValue
    )
    if ([string]::IsNullOrWhiteSpace($AuditPath) -or -not (Test-Path -LiteralPath $AuditPath -PathType Leaf)) {
        return @()
    }
    $pidSet = @{}
    foreach ($processId in @($ProcessIds)) {
        if ([int]$processId -gt 0) { $pidSet[[int]$processId] = $true }
    }
    $faults = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @(Get-Content -LiteralPath $AuditPath -Tail 512 -ErrorAction SilentlyContinue)) {
        try {
            $event = $line | ConvertFrom-Json
            $eventPid = [int]$event.pid
            if ($pidSet.Count -gt 0 -and -not $pidSet.ContainsKey($eventPid)) { continue }
            if ($SinceUtc -ne [DateTime]::MinValue -and -not [string]::IsNullOrWhiteSpace([string]$event.utc)) {
                try {
                    $eventUtc = [DateTime]::Parse([string]$event.utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
                    if ($eventUtc -lt $SinceUtc.AddSeconds(-2)) { continue }
                } catch { }
            }
            $surface = [string]$event.surface
            $action = [string]$event.action
            $detail = [string]$event.detail
            $fault = $null
            if ($surface -eq 'native.bridge' -and $action -eq 'failed') {
                $fault = "native.bridge failed: $detail"
            } elseif ($surface -eq 'wfp.policy' -and $action -eq 'failed') {
                $fault = "wfp.policy failed: $detail"
            } elseif ($surface -eq 'kernel.policy' -and $action -match '^(unavailable|register-failed|query-failed|verify-failed)$') {
                $fault = "kernel.policy ${action}: $detail"
            } elseif ($surface -eq 'api.install' -and $action -eq 'complete' -and $detail -match 'failures=(\d+)' -and [int]$Matches[1] -gt 0) {
                $fault = "api.install complete: $detail"
            }
            if (-not [string]::IsNullOrWhiteSpace($fault) -and -not ($faults -contains $fault)) {
                [void]$faults.Add($fault)
            }
        } catch { }
    }
    return @($faults)
}

function Get-DesktopProxyHealthWarning {
    param(
        [psobject]$Paths,
        [string]$RelayState,
        [string]$MitmState
    )
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    if ($RelayState -notin @('not-configured', 'alive')) {
        [void]$warnings.Add("proxy relay state: $RelayState")
    }
    if ($MitmState -notin @('not-configured', 'alive')) {
        [void]$warnings.Add("MITM state: $MitmState")
    }
    $relayLog = Join-Path $Paths.LogsDir 'proxy-relay.log'
    if (Test-Path -LiteralPath $relayLog -PathType Leaf) {
        $lastHealthLine = @(Get-Content -LiteralPath $relayLog -Tail 80 -ErrorAction SilentlyContinue |
            Where-Object { $_ -match 'upstream (unreachable|recovered):' } | Select-Object -Last 1)
        if ($lastHealthLine.Count -gt 0 -and [string]$lastHealthLine[0] -match 'upstream unreachable:') {
            [void]$warnings.Add('SOCKS upstream unreachable; Claude remains loopback-only')
        }
    }
    return @($warnings)
}

function Remove-StaleProfileLaunchCa {
    param([Parameter(Mandatory = $true)][psobject]$Paths)

    $statePath = Join-Path $Paths.LogsDir 'desktop-launch.json'
    $launchState = Read-DesktopStateFile -Path $statePath
    if ($null -eq $launchState -or -not [bool]$launchState.removeCa) { return }

    $expectedCaPath = [System.IO.Path]::GetFullPath((Join-Path $Paths.MitmDir 'mitmproxy-ca-cert.cer'))
    $recordedCaPath = ''
    if (-not [string]::IsNullOrWhiteSpace([string]$launchState.caPath)) {
        try { $recordedCaPath = [System.IO.Path]::GetFullPath([string]$launchState.caPath) } catch { $recordedCaPath = '' }
    }
    if (-not [string]::Equals($recordedCaPath, $expectedCaPath, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host '[RECOVER] stale launch state has no matching Profile CA path; leaving certificate untouched.' -ForegroundColor Yellow
        return
    }

    try {
        if (-not (Remove-MitmCa -Path $expectedCaPath)) {
            throw "Profile CA remains after removal: $expectedCaPath"
        }
        Write-DesktopStateFile -Path $statePath -State 'stopped' -Generation ([string]$launchState.generation)
        Write-Host '[RECOVER] stale Profile CA removed.' -ForegroundColor Green
    } catch {
        throw "Stale Profile CA cleanup failed: $($_.Exception.Message)"
    }
}

function Assert-DesktopNoReparsePoints {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing operation on reparse-point path: $Path"
    }
    if (-not $root.PSIsContainer) { return }

    $pending = New-Object System.Collections.Queue
    $pending.Enqueue($root.FullName)
    while ($pending.Count -gt 0) {
        $current = [string]$pending.Dequeue()
        foreach ($child in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing operation because a descendant is a reparse point: $($child.FullName)"
            }
            if ($child.PSIsContainer) { $pending.Enqueue($child.FullName) }
        }
    }
}

function Resolve-DesktopProxyBinding {
    param([Parameter(Mandatory = $true)][string]$ProfileName)
    $accountKey = "desktop:$ProfileName"
    $binding = Get-CacProxyForAccount -AccountKey $accountKey
    if ($null -eq $binding) {
        [void](Ensure-CacProxyBinding -AccountKey $accountKey)
        $binding = Get-CacProxyForAccount -AccountKey $accountKey
    }
    return $binding
}

function Get-DerivedHex {
    param([string]$Seed, [int]$Length)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Seed))
        $hex = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        if ($hex.Length -lt $Length) { return $hex }
        return $hex.Substring(0, $Length)
    } finally {
        $sha.Dispose()
    }
}

function Initialize-ProfileIdentity {
    param([psobject]$Paths)
    $hasLock = Test-Path -LiteralPath $Paths.DeviceImageLock -PathType Leaf
    if (Test-Path -LiteralPath $Paths.IdentityPath -PathType Leaf) {
        try {
            $existing = Get-Content -LiteralPath $Paths.IdentityPath -Raw | ConvertFrom-Json -ErrorAction Stop
            foreach ($field in @('machine_id', 'hostname', 'mac_address', 'username')) {
                if ([string]::IsNullOrWhiteSpace([string]$existing.$field)) {
                    throw "identity.json is missing required field: $field"
                }
            }
            return $existing
        } catch {
            if ($hasLock) { throw "Locked identity.json is invalid: $($_.Exception.Message)" }
        }
    }
    if ($hasLock) { throw "Locked identity.json is missing: $($Paths.IdentityPath)" }

    $machineId = [guid]::NewGuid().ToString('N')
    $uuid = [guid]::NewGuid().ToString().ToUpperInvariant()
    $macBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($machineId + '|mac'))
    $mac = '00:E0:4C:' + (($macBytes[0..2] | ForEach-Object { $_.ToString('x2') }) -join ':')
    $userNames = @('alex', 'david', 'mike', 'chris', 'sarah')
    $username = $userNames[[int]$macBytes[4] % $userNames.Count]
    $identity = [ordered]@{
        schema        = 1
        name          = $Paths.Name
        uuid          = $uuid
        stable_id     = [guid]::NewGuid().ToString().ToLowerInvariant()
        user_id       = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
        machine_id    = $machineId
        hostname      = 'DESKTOP-' + (Get-DerivedHex ($machineId + '|host') 7).ToUpperInvariant()
        mac_address   = $mac
        system_uuid   = ($uuid -replace '-', '').ToUpperInvariant()
        disk_serial   = ('WD-' + (Get-DerivedHex ($machineId + '|disk') 12)).ToUpperInvariant()
        bios_serial   = ('PF' + (Get-DerivedHex ($machineId + '|bios') 10)).ToUpperInvariant()
        board_serial  = ('MB' + (Get-DerivedHex ($machineId + '|board') 10)).ToUpperInvariant()
        system_serial = ('SYS' + (Get-DerivedHex ($machineId + '|system') 10)).ToUpperInvariant()
        processor_id  = (Get-DerivedHex ($machineId + '|cpu') 16).ToUpperInvariant()
        volume_serial = (Get-DerivedHex ($machineId + '|volume') 8).ToUpperInvariant()
        hid_serial    = 'HID' + (Get-DerivedHex ($machineId + '|hid') 10).ToUpperInvariant()
        username      = $username
        system_manufacturer = 'ASUSTeK COMPUTER INC.'
        system_product = 'PRIME B550M-K'
        system_version = 'System Version'
        board_manufacturer = 'ASUSTeK COMPUTER INC.'
        board_product = 'PRIME B550M-K'
        board_version = 'Rev X.0x'
        bios_vendor = 'American Megatrends Inc.'
        bios_version = '5.17'
        bios_release_date = '01/01/2024'
        processor_name = 'AMD Ryzen 3 3100 4-Core Processor'
        cpu_vendor = 'AuthenticAMD'
        cpu_identifier = 'AMD64 Family 23 Model 113 Stepping 0'
        gpu_name = 'NVIDIA GeForce GTX 1650'
        gpu_vendor = 'NVIDIA'
        gpu_pci_id = 'PCI\VEN_10DE&DEV_1F82&SUBSYS_1F8210DE&REV_A1'
        gpu_memory_mb = 4096
        gpu_driver_version = '31.0.15.3699'
        gpu_serial = '1321919076543'
        gpu_uuid = 'GPU-8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f'
        memory_vendor = 'Samsung'
        memory_part = 'M378A1K43CB2-CRC'
        memory_total_mb = 16384
        memory_available_mb = 12288
        memory_module_mb = 8192
        memory_speed_mhz = 3200
        disk_total_gb = 512
        disk_free_gb = 256
        disk_model = 'WDC WDS500G2B0A-00SM50'
        nic_name = 'Realtek PCIe GbE Family Controller'
        cpu_cores = 4
        cpu_logical = 8
        cpu_max_mhz = 3600
        l2_cache_kb = 2048
        l3_cache_kb = 16384
        display_width = 1920
        display_height = 1080
        display_refresh = 60
        hypervisor_present = $false
        tpm_present = $false
        volume_label = 'System'
        filesystem = 'NTFS'
        monitor_name = 'Dell U2419H'
        monitor_pnp_id = 'DEL41A9'
        monitor_edid_manufacturer = 0x10AC
        monitor_edid_product = 0x41A9
        hid_vendor_id = 0x046D
        hid_product_id = 0xC52B
        hid_version = 0x0111
        hid_manufacturer = 'Logitech'
        hid_product = 'USB Receiver'
    }
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Paths.IdentityPath, ($identity | ConvertTo-Json -Depth 5), $encoding)
    return [pscustomobject]$identity
}

function Assert-ProfileDeviceImageLock {
    param(
        [psobject]$Paths,
        [switch]$InitializeIfMissing
    )
    if (-not (Test-Path -LiteralPath $Paths.IdentityPath -PathType Leaf)) {
        throw "Device image identity is missing: $($Paths.IdentityPath)"
    }
    $personaPath = Join-Path $Paths.Root 'fingerprint.json'
    if (-not (Test-Path -LiteralPath $personaPath -PathType Leaf)) {
        throw "Device image persona is missing: $personaPath"
    }

    try { $identity = Get-Content -LiteralPath $Paths.IdentityPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Device image identity is invalid: $($_.Exception.Message)" }
    try { $persona = Get-Content -LiteralPath $personaPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Device image persona is invalid: $($_.Exception.Message)" }
    if ([string]::IsNullOrWhiteSpace([string]$identity.machine_id)) { throw 'Device image machine_id is empty' }
    if ([string]::IsNullOrWhiteSpace([string]$persona.seed)) { throw 'Device image seed is empty' }

    $identitySha = Get-Sha256 -Path $Paths.IdentityPath
    $personaSha = Get-Sha256 -Path $personaPath
    $imageSha = Get-StringSha256 -Value "$identitySha`:$personaSha"
    $personaLanguages = @($persona.languages | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    if ($personaLanguages.Count -eq 0) { throw 'Device image persona languages are empty' }
    $personaOrigin = $persona.origin
    $hasFirstProxyOrigin = ($null -ne $personaOrigin -and
        [string]$personaOrigin.source -eq 'first-socks5')
    if ([int]$persona.schema -eq 2 -and -not $hasFirstProxyOrigin) {
        throw 'Device image persona schema 2 is missing its first SOCKS5 origin'
    }
    $lockPath = $Paths.DeviceImageLock
    if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
        try { $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "Device image lock is invalid: $($_.Exception.Message)" }
        $lockSchema = [int]$lock.schema
        if ($lockSchema -notin @(1, 2)) { throw "Unsupported device image lock schema: $([string]$lock.schema)" }
        if (-not [string]::Equals([string]$lock.profile, [string]$Paths.Name, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Device image lock belongs to another Profile: $([string]$lock.profile)"
        }
        if ([string]$lock.identitySha256 -ne $identitySha) { throw 'identity.json changed after the device image was locked' }
        if ([string]$lock.personaSha256 -ne $personaSha) { throw 'fingerprint.json changed after the device image was locked' }
        if ([string]$lock.imageSha256 -ne $imageSha) { throw 'Device image composite digest does not match the locked files' }
        if ([string]$lock.machineId -ne [string]$identity.machine_id) { throw 'Device image machine_id does not match its lock' }
        if ([string]$lock.seed -ne [string]$persona.seed) { throw 'Device image seed does not match its lock' }
        if ([string]$lock.electronVersion -ne [string]$persona.uaElectronVersion) { throw 'Device image Electron version does not match its lock' }
        if ([string]$lock.chromiumVersion -ne [string]$persona.uaChromiumVersion) { throw 'Device image Chromium version does not match its lock' }
        if ($lockSchema -eq 1 -and $hasFirstProxyOrigin) {
            throw 'Device image lock schema 1 does not preserve the first SOCKS5 origin'
        }
        if ($lockSchema -eq 2) {
            if (-not $hasFirstProxyOrigin) { throw 'Device image lock is missing its first SOCKS5 origin' }
            if ([string]$lock.timezone -ne [string]$persona.timezone) { throw 'Device image timezone does not match its lock' }
            if ([string]$lock.locale -ne [string]$persona.locale) { throw 'Device image locale does not match its lock' }
            $lockLanguages = @($lock.languages | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
            if (($lockLanguages -join [char]0x1f) -ne ($personaLanguages -join [char]0x1f)) {
                throw 'Device image languages do not match its lock'
            }
            foreach ($field in @('source', 'provider', 'proxyId', 'externalIp', 'countryCode', 'dnsMode', 'capturedUtc')) {
                if ([string]$lock.origin.$field -ne [string]$personaOrigin.$field) {
                    throw "Device image SOCKS5 origin $field does not match its lock"
                }
            }
        }
        return $lock
    }
    if (-not $InitializeIfMissing) { throw "Device image lock is missing: $lockPath" }

    $lockSchema = if ($hasFirstProxyOrigin) { 2 } else { 1 }
    $lock = [ordered]@{
        schema            = $lockSchema
        profile           = $Paths.Name
        lockedUtc         = [DateTime]::UtcNow.ToString('o')
        identitySha256    = $identitySha
        personaSha256     = $personaSha
        imageSha256       = $imageSha
        machineId         = [string]$identity.machine_id
        seed              = [string]$persona.seed
        electronVersion   = [string]$persona.uaElectronVersion
        chromiumVersion   = [string]$persona.uaChromiumVersion
    }
    if ($lockSchema -eq 2) {
        $lock['timezone'] = [string]$persona.timezone
        $lock['locale'] = [string]$persona.locale
        $lock['languages'] = @($personaLanguages)
        $lock['origin'] = [ordered]@{
            source      = [string]$personaOrigin.source
            provider    = [string]$personaOrigin.provider
            proxyId     = [string]$personaOrigin.proxyId
            externalIp  = [string]$personaOrigin.externalIp
            countryCode = [string]$personaOrigin.countryCode
            region      = [string]$personaOrigin.region
            city        = [string]$personaOrigin.city
            dnsMode     = [string]$personaOrigin.dnsMode
            capturedUtc = [string]$personaOrigin.capturedUtc
        }
    }
    $temporary = "$lockPath.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        Write-JsonNoBom -Path $temporary -Value $lock
        Move-Item -LiteralPath $temporary -Destination $lockPath -ErrorAction Stop
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]$lock
}

function Assert-ProfilePersonaRuntime {
    param(
        [psobject]$Paths,
        [string]$ExePath
    )
    $personaPath = Join-Path $Paths.Root 'fingerprint.json'
    try { $persona = Get-Content -LiteralPath $personaPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Device image persona is invalid: $($_.Exception.Message)" }
    $runtime = Get-ChromiumPersonaVersion -ExePath $ExePath -IgnoreConfigured
    if ([string]$persona.uaElectronVersion -ne [string]$runtime.electronVersion -or
        [string]$persona.uaChromiumVersion -ne [string]$runtime.chromiumVersion) {
        throw ("Desktop runtime {0}/{1} does not match locked device image {2}/{3}" -f
            $runtime.electronVersion, $runtime.chromiumVersion,
            [string]$persona.uaElectronVersion, [string]$persona.uaChromiumVersion)
    }
}

function Push-DesktopKernelIdentity {
    param([psobject]$Identity, [string]$TempDir, [string]$ProfileRoot)
    if ($null -eq $Identity) { return $false }
    $kernelCtl = Join-Path $script:OriginalUserProfile '.cac\native\kernel\bin\cac-kernelctl.exe'
    if (-not (Test-Path -LiteralPath $kernelCtl -PathType Leaf)) { return $false }
    if ([string]::IsNullOrWhiteSpace([string]$TempDir)) { return $false }
    $moduleFlags = 1  # storage only. SMBIOS physical probe is opt-in.
    if ($ProfileRoot -and (Test-Path -LiteralPath (Join-Path $ProfileRoot 'kernel_smbios'))) {
        if ((Get-Content -LiteralPath (Join-Path $ProfileRoot 'kernel_smbios') -Raw).Trim() -eq '1') {
            $moduleFlags = 3
        }
    }
    $payload = [ordered]@{
        module_flags          = $moduleFlags
        mac_address           = [string]$Identity.mac_address
        system_uuid           = [string]$Identity.system_uuid
        disk_serial           = [string]$Identity.disk_serial
        disk_vendor           = 'ATA'
        disk_product          = 'WDC WD10EZEX-08WN4A0'
        disk_revision         = '01.01A01'
        bios_vendor           = 'American Megatrends Inc.'
        bios_version          = '5.17'
        system_manufacturer   = 'ASUS'
        system_product        = 'System Product Name'
        system_version        = 'System Version'
        system_serial         = [string]$Identity.system_serial
        baseboard_manufacturer = 'ASUSTeK COMPUTER INC.'
        baseboard_product     = 'PRIME B550M-K'
        baseboard_serial      = [string]$Identity.board_serial
    }
    $tmp = Join-Path $TempDir 'kernel-identity.json'
    try {
        $payload | ConvertTo-Json -Compress |
            Set-Content -LiteralPath $tmp -Encoding ASCII
        & $kernelCtl identity-set --file $tmp 2>$null | Out-Null
        $kernelOk = ($LASTEXITCODE -eq 0)
        $macCtl = Join-Path $script:OriginalUserProfile '.cac\native\macfilter\bin\cac-macctl.exe'
        if ((Test-Path -LiteralPath $macCtl -PathType Leaf) -and
            -not [string]::IsNullOrWhiteSpace([string]$Identity.mac_address)) {
            & $macCtl set --mac ([string]$Identity.mac_address) 2>$null | Out-Null
        }
        return $kernelOk
    } catch {
        return $false
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Register-DesktopKernelPid {
    param([int]$ProcessId, [psobject]$Paths, [string]$NativeReadPolicy)
    $kernelCtl = Join-Path $script:OriginalUserProfile '.cac\native\kernel\bin\cac-kernelctl.exe'
    if (-not (Test-Path -LiteralPath $kernelCtl -PathType Leaf)) { return $false }
    if ($ProcessId -le 0 -or $null -eq $Paths) { return $false }
    $flags = 1
    if ($NativeReadPolicy -eq 'empty') { $flags = 3 }
    try {
        & $kernelCtl register --pid $ProcessId --profile $Paths.Name --flags $flags 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Get-PathSummary {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{ exists = $false; files = 0; bytes = 0; lastWriteTime = $null }
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer) {
            return [ordered]@{ exists = $true; files = 1; bytes = [long]$item.Length; lastWriteTime = $item.LastWriteTime.ToString('o') }
        }
        $files = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue)
        $bytes = [long]0
        $last = $item.LastWriteTime
        foreach ($file in $files) {
            $bytes += [long]$file.Length
            if ($file.LastWriteTime -gt $last) { $last = $file.LastWriteTime }
        }
        return [ordered]@{ exists = $true; files = $files.Count; bytes = $bytes; lastWriteTime = $last.ToString('o') }
    } catch {
        return [ordered]@{ exists = $true; files = 0; bytes = 0; lastWriteTime = $null; error = $_.Exception.Message }
    }
}

function Get-ProfileState {
    param([psobject]$Paths)
    $userData = $Paths.UserDataDir
    $trackedPaths = @(
        $Paths.Root,
        $Paths.Home,
        $Paths.ConfigDir,
        $Paths.AppData,
        $Paths.LocalAppData,
        $Paths.Temp,
        $Paths.MitmDir,
        $userData,
        (Join-Path $Paths.LocalAppData 'Claude-3p'),
        (Join-Path $Paths.AppData 'Claude-3p'),
        (Join-Path $userData 'sessions'),
        (Join-Path $userData 'Crashpad'),
        (Join-Path $userData 'Local State'),
        (Join-Path $userData 'Network\Cookies')
    ) | ForEach-Object { [System.IO.Path]::GetFullPath($_) }
    $rootPrefix = ([System.IO.Path]::GetFullPath($Paths.Root)).TrimEnd('\') + '\'
    $outsideRoot = @($trackedPaths | Where-Object {
        -not $_.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        -not [string]::Equals($_, $Paths.Root, [StringComparison]::OrdinalIgnoreCase)
    })
    return [ordered]@{
        root             = [System.IO.Path]::GetFullPath($Paths.Root)
        trackedPaths     = @($trackedPaths)
        outsideRootPaths = @($outsideRoot)
        userData        = Get-PathSummary $userData
        configDir       = Get-PathSummary $Paths.ConfigDir
        claude3pLocal   = Get-PathSummary (Join-Path $Paths.LocalAppData 'Claude-3p')
        claude3pRoaming = Get-PathSummary (Join-Path $Paths.AppData 'Claude-3p')
        mitmproxy       = Get-PathSummary $Paths.MitmDir
        sessions        = Get-PathSummary (Join-Path $userData 'sessions')
        crashpad        = Get-PathSummary (Join-Path $userData 'Crashpad')
        config          = Get-PathSummary (Join-Path $userData 'claude_desktop_config.json')
        localState      = Get-PathSummary (Join-Path $userData 'Local State')
        cookies         = Get-PathSummary (Join-Path $userData 'Network\Cookies')
    }
}

function Remove-ProfileAntDid {
    param([psobject]$Paths)
    foreach ($candidate in @($Paths.AntDidPrimary, $Paths.AntDidFallback)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        }
    }
}

function Initialize-ProfileLayout {
    param(
        [psobject]$Paths,
        [switch]$ForLaunch
    )
    $folders = New-Object System.Collections.ArrayList
    [void]$folders.Add($Paths.Root)
    foreach ($relative in $script:LayoutFolders) {
        [void]$folders.Add((Join-Path $Paths.Root $relative))
    }
    if ($ForLaunch) { [void]$folders.Add($Paths.UserDataDir) }
    foreach ($folder in $folders) {
        New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null
    }
    $nativePolicy = 'profile'
    $nativePolicyPath = Join-Path $Paths.Root 'native_read_policy'
    if (-not (Test-Path -LiteralPath $nativePolicyPath -PathType Leaf)) {
        [System.IO.File]::WriteAllText($nativePolicyPath, "profile`r`n", (New-Object System.Text.UTF8Encoding($false)))
    }
    $cpuidModePath = Join-Path $Paths.Root 'cpuid_mode'
    if (-not (Test-Path -LiteralPath $cpuidModePath -PathType Leaf)) {
        [System.IO.File]::WriteAllText($cpuidModePath, "neutral`r`n", (New-Object System.Text.UTF8Encoding($false)))
    }
    $networkModePath = Join-Path $Paths.Root 'network_mode'
    if (-not (Test-Path -LiteralPath $networkModePath -PathType Leaf)) {
        [System.IO.File]::WriteAllText($networkModePath, "profile`r`n", (New-Object System.Text.UTF8Encoding($false)))
    }
    [void](Resolve-DesktopProxyBinding -ProfileName $Paths.Name)
    return $Paths
}

function Sync-NativeLayer {
    $source = Join-Path (Split-Path $PSScriptRoot -Parent) 'native\dist'
    $target = Join-Path $script:OriginalUserProfile '.cac\native'
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Native layer directory is missing: $source"
    }
    $required = @('NativeBridge.dll', 'cac-native-launch.exe', 'NativeBridge.sha256', 'cac-native-launch.sha256')
    foreach ($name in $required) {
        $path = Join-Path $source $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Native layer artifact is missing: $path"
        }
    }
    $sourceDllHash = Get-Sha256 (Join-Path $source 'NativeBridge.dll')
    $sourceDllDeclared = Get-DeclaredSha256 (Join-Path $source 'NativeBridge.sha256')
    $sourceLauncherHash = Get-Sha256 (Join-Path $source 'cac-native-launch.exe')
    $sourceLauncherDeclared = Get-DeclaredSha256 (Join-Path $source 'cac-native-launch.sha256')
    if ($sourceDllHash -ne $sourceDllDeclared) { throw "NativeBridge.dll SHA-256 mismatch: $source" }
    if ($sourceLauncherHash -ne $sourceLauncherDeclared) { throw "cac-native-launch.exe SHA-256 mismatch: $source" }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    foreach ($name in $required) {
        $from = Join-Path $source $name
        $to = Join-Path $target $name
        $needsCopy = -not (Test-Path -LiteralPath $to -PathType Leaf)
        if (-not $needsCopy) {
            $needsCopy = (Get-Sha256 $from) -ne (Get-Sha256 $to)
        }
        if ($needsCopy) {
            Copy-Item -LiteralPath $from -Destination $to -Force
            Write-Host "  [SYNC] $name" -ForegroundColor DarkGray
        }
    }
    if ((Get-Sha256 (Join-Path $target 'NativeBridge.dll')) -ne $sourceDllHash -or
        (Get-Sha256 (Join-Path $target 'cac-native-launch.exe')) -ne $sourceLauncherHash -or
        (Get-DeclaredSha256 (Join-Path $target 'NativeBridge.sha256')) -ne $sourceDllHash -or
        (Get-DeclaredSha256 (Join-Path $target 'cac-native-launch.sha256')) -ne $sourceLauncherHash) {
        throw "Native layer synchronization failed integrity verification: $target"
    }
}

function Get-AntDidInfo {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer) { return $null }
        $hash = Get-Sha256 $Path
        return [pscustomobject][ordered]@{
            path          = $item.FullName
            length        = [long]$item.Length
            lastWriteTime = $item.LastWriteTime.ToString('o')
            sha256        = [string]$hash
        }
    } catch {
        return $null
    }
}

function Find-AntDid {
    param([psobject]$Paths)
    # Primary path wins when both files exist.
    foreach ($candidate in @($Paths.AntDidPrimary, $Paths.AntDidFallback)) {
        $info = Get-AntDidInfo -Path $candidate
        if ($null -ne $info) { return $info }
    }
    return $null
}

function Wait-AntDid {
    param(
        [psobject]$Paths,
        [int]$Seconds
    )
    if ($Seconds -lt 0) { $Seconds = 0 }
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ($true) {
        $info = Find-AntDid -Paths $Paths
        if ($null -ne $info) { return $info }
        if ([DateTime]::UtcNow -ge $deadline) { return $null }
        Start-Sleep -Milliseconds 250
    }
}

function Wait-DesktopRuntimeWindow {
    param(
        [DateTime]$StartedUtc,
        [int]$Seconds,
        [string]$ProfileName
    )
    $remaining = [int][Math]::Ceiling($Seconds - ([DateTime]::UtcNow - $StartedUtc).TotalSeconds)
    if ($remaining -gt 0) {
        Write-Host ("[AB] {0} runtime window remaining: {1}s" -f $ProfileName, $remaining) -ForegroundColor DarkGray
        Start-Sleep -Seconds $remaining
    }
}

function Get-ClaudeProcessRows {
    $result = @()
    try {
        $rows = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='claude.exe'" -ErrorAction Stop)
        foreach ($row in $rows) {
            $processPath = [string]$row.ExecutablePath
            if ([string]::IsNullOrWhiteSpace($processPath)) {
                try {
                    $processPath = [string](Get-Process -Id ([int]$row.ProcessId) -ErrorAction Stop).Path
                } catch {
                    $processPath = $null
                }
            }
            $result += [pscustomobject]@{
                Id          = [int]$row.ProcessId
                Name        = [string]$row.Name
                Path        = $processPath
                CommandLine = [string]$row.CommandLine
            }
        }
    } catch {
        try {
            foreach ($process in @(Get-Process -Name 'claude' -ErrorAction Stop)) {
                $processPath = $null
                try { $processPath = [string]$process.Path } catch { $processPath = $null }
                $result += [pscustomobject]@{
                    Id          = [int]$process.Id
                    Name        = [string]$process.ProcessName
                    Path        = $processPath
                    CommandLine = $null
                }
            }
        } catch {
            $result = @()
        }
    }
    return @($result)
}

function Get-ClaudeDesktopProcesses {
    param([string]$ExePath)
    $result = @()
    foreach ($process in @(Get-ClaudeProcessRows)) {
        $processPath = [string]$process.Path
        $isDesktop = $false
        if ([string]::IsNullOrWhiteSpace($processPath)) {
            # Unknown path is treated conservatively for launch refusal.
            $isDesktop = $true
        } elseif ($processPath -ieq $ExePath) {
            $isDesktop = $true
        } elseif ($processPath -match '(?i)\\WindowsApps\\Claude_[^\\]+\\app\\claude\.exe$') {
            $isDesktop = $true
        }
        if ($isDesktop) { $result += $process }
    }
    return @($result)
}

function Wait-ClaudeDesktopRoot {
    param(
        [string]$ExePath,
        [System.Diagnostics.Process]$LauncherProcess,
        [string]$AuditPath,
        [bool]$NativeRequired,
        [string]$ExpectedUserDataDir,
        [DateTime]$LaunchStartedUtc,
        [int]$TimeoutSeconds = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $candidates = @(Get-ClaudeDesktopProcesses -ExePath $ExePath)
        if (-not [string]::IsNullOrWhiteSpace($ExpectedUserDataDir)) {
            $expectedMarker = $ExpectedUserDataDir.TrimEnd('\')
            $matchedCandidates = @($candidates | Where-Object {
                try {
                    $candidatePath = [System.IO.Path]::GetFullPath([string]$_.Path)
                    $expectedPath = [System.IO.Path]::GetFullPath($ExePath)
                    if (-not [string]::Equals($candidatePath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
                        return $false
                    }
                    $process = Get-Process -Id ([int]$_.Id) -ErrorAction Stop
                    if ($LaunchStartedUtc -ne [DateTime]::MinValue -and
                        $process.StartTime.ToUniversalTime() -lt $LaunchStartedUtc.AddSeconds(-2)) {
                        return $false
                    }
                } catch {
                    return $false
                }
                $commandLine = [string]$_.CommandLine
                if (-not [string]::IsNullOrWhiteSpace($commandLine)) {
                    Test-TextPathMarker -Text $commandLine -Marker $expectedMarker
                } else {
                    $true
                }
            })
            $candidates = $matchedCandidates
        }
        if ($candidates.Count -gt 0) {
            $candidate = $candidates | Sort-Object Id | Select-Object -First 1
            if (-not $NativeRequired) {
                return (Get-Process -Id ([int]$candidate.Id) -ErrorAction Stop)
            }
            $ready = $false
            $failed = $false
            if (Test-Path -LiteralPath $AuditPath -PathType Leaf) {
                foreach ($line in @(Get-Content -LiteralPath $AuditPath -Tail 256 -ErrorAction SilentlyContinue)) {
                    try {
                        $event = $line | ConvertFrom-Json
                        if ([int]$event.pid -ne [int]$candidate.Id -or [string]$event.surface -ne 'native.bridge') { continue }
                        if ([string]$event.action -eq 'ready') { $ready = $true }
                        if ([string]$event.action -eq 'failed') { $failed = $true }
                    } catch { }
                }
            }
            if ($failed) { throw "NativeBridge failed for Claude Desktop PID $($candidate.Id)" }
            if ($ready) { return (Get-Process -Id ([int]$candidate.Id) -ErrorAction Stop) }
        }
        if ($null -ne $LauncherProcess -and $LauncherProcess.HasExited -and $LauncherProcess.ExitCode -ne 0) {
            throw "Claude Desktop launcher exited with code $($LauncherProcess.ExitCode)"
        }
        Start-Sleep -Milliseconds 200
    }
    throw "Claude Desktop root process was not observed within $TimeoutSeconds seconds"
}

function ConvertTo-ProcessArgument {
    param([string]$Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Resolve-MitmdumpPath {
    param([string]$Requested)
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in @($Requested, [Environment]::GetEnvironmentVariable('CAC_MITMDUMP', 'Process'))) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) { [void]$candidates.Add($candidate.Trim().Trim('"')) }
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source) -and
            (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
            return [System.IO.Path]::GetFullPath($command.Source)
        }
    }
    foreach ($name in @('mitmdump.exe', 'mitmdump')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source) -and
            (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
            return [System.IO.Path]::GetFullPath($command.Source)
        }
    }
    return $null
}

function Stop-DesktopLaunchResources {
    param(
        [psobject]$Paths,
        [System.Diagnostics.Process]$DesktopProcess,
        [int]$DesktopPid = 0,
        [psobject]$RootIdentity,
        [System.Diagnostics.Process]$MitmProcess,
        [object]$Relay,
        [string[]]$PidFiles,
        [string]$CaPath,
        [bool]$RemoveCa
    )
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $rootProcessId = 0
    if ($null -ne $DesktopProcess) {
        try { $rootProcessId = [int]$DesktopProcess.Id } catch { $rootProcessId = 0 }
    } elseif ($DesktopPid -gt 0) {
        $rootProcessId = $DesktopPid
    }
    if ($rootProcessId -gt 0 -and $null -ne $Paths) {
        $treeCleanupFailed = $false
        try {
            $stop = Stop-ClaudeProcessTree -RootProcessId $rootProcessId -Paths $Paths -RootIdentity $RootIdentity
            if ($stop.error) { [void]$errors.Add([string]$stop.error) }
            if (@($stop.remainingPids).Count -gt 0) { [void]$errors.Add("Desktop processes remain: $(@($stop.remainingPids) -join ',')") }
            $treeCleanupFailed = [bool]$stop.error -or @($stop.remainingPids).Count -gt 0
        } catch { [void]$errors.Add("Desktop stop failed: $($_.Exception.Message)") }
        if ($treeCleanupFailed) {
            try {
                Stop-ProfileProcesses -Paths $Paths
                Start-Sleep -Milliseconds 250
                $residual = @(Get-ProfileProcessIds -Paths $Paths)
                if ($residual.Count -gt 0) { [void]$errors.Add("Desktop Profile processes remain after fallback cleanup: $($residual -join ',')") }
            } catch { [void]$errors.Add("Desktop Profile fallback cleanup failed: $($_.Exception.Message)") }
        }
    } elseif ($null -ne $Paths) {
        # The native launcher may exit before the target root is authenticated.
        # Clean only processes carrying this Profile's path markers; never fall
        # back to a global claude.exe kill.
        try {
            Stop-ProfileProcesses -Paths $Paths
            Start-Sleep -Milliseconds 250
            $residual = @(Get-ProfileProcessIds -Paths $Paths)
            if ($residual.Count -gt 0) { [void]$errors.Add("Desktop Profile processes remain: $($residual -join ',')") }
        } catch { [void]$errors.Add("Desktop Profile cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $MitmProcess) {
        try { Stop-TrackedProcess -Process $MitmProcess } catch { [void]$errors.Add("MITM stop failed: $($_.Exception.Message)") }
    }
    if ($null -ne $Relay) {
        try { Stop-CacProxyRelay $Relay } catch { [void]$errors.Add("relay stop failed: $($_.Exception.Message)") }
    }
    foreach ($pidFile in @($PidFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        try {
            if (Test-Path -LiteralPath $pidFile) { Remove-Item -LiteralPath $pidFile -Force -ErrorAction Stop }
            if (Test-Path -LiteralPath $pidFile) { [void]$errors.Add("PID file remains: $pidFile") }
        } catch { [void]$errors.Add("PID file cleanup failed: $pidFile : $($_.Exception.Message)") }
    }
    if ($RemoveCa) {
        if ([string]::IsNullOrWhiteSpace($CaPath)) {
            [void]$errors.Add('Profile CA rollback skipped: CA path is empty')
        } else {
            try {
                if (-not (Remove-MitmCa -Path $CaPath)) { [void]$errors.Add("Profile CA remains: $CaPath") }
            } catch { [void]$errors.Add("Profile CA rollback failed: $($_.Exception.Message)") }
        }
    }
    return $errors.ToArray()
}

function Start-DesktopLifecycleMonitor {
    param(
        [psobject]$Paths,
        [int]$DesktopPid,
        [object]$Relay,
        [System.Diagnostics.Process]$MitmProcess,
        [string]$MitmPidFile,
        [string]$MitmProcessPidFile,
        [bool]$RemoveCa,
        [string]$CaPath,
        [string]$LaunchStateFile,
        [string]$LaunchGeneration,
        [string]$MonitorReadyFile,
        [bool]$NativeRequired = $false
    )
    if ($DesktopPid -le 0) { throw 'Desktop lifecycle monitor requires a root PID' }
    $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (ConvertTo-ProcessArgument $script:DesktopScriptPath),
        '-Action', 'monitor', '-Profile', $Paths.Name, '-WatchPid', [string]$DesktopPid
    )
    $watchPath = $null
    $watchStartUtc = $null
    try {
        $watchProcess = Get-Process -Id $DesktopPid -ErrorAction Stop
        $watchPath = [string]$watchProcess.Path
        $watchStartUtc = $watchProcess.StartTime.ToUniversalTime().ToString('o')
    } catch {
        throw "Desktop root identity unavailable for PID ${DesktopPid}: $($_.Exception.Message)"
    }
    if ([string]::IsNullOrWhiteSpace($watchPath) -or [string]::IsNullOrWhiteSpace($watchStartUtc)) {
        throw "Desktop root identity is incomplete for PID ${DesktopPid}"
    }
    $arguments += @('-WatchPath', (ConvertTo-ProcessArgument $watchPath))
    $arguments += @('-WatchStartUtc', (ConvertTo-ProcessArgument $watchStartUtc))
    $relayPid = 0
    $relayPidFile = $null
    $relayPath = $null
    $relayStartUtc = $null
    if ($null -ne $Relay -and [bool]$Relay.owned) {
        if ($null -eq $Relay.process) { throw 'Owned proxy relay has no process identity' }
        $relayPid = [int]$Relay.process.Id
        $relayPidFile = [string]$Relay.pidFile
        try { $relayPath = [string]$Relay.process.StartInfo.FileName } catch { }
        try { if (-not $relayPath) { $relayPath = [string]$Relay.process.Path } } catch { }
        try { $relayStartUtc = $Relay.process.StartTime.ToUniversalTime().ToString('o') } catch { }
        if ([string]::IsNullOrWhiteSpace($relayPath) -or [string]::IsNullOrWhiteSpace($relayStartUtc)) {
            throw "Proxy relay identity is incomplete for PID $relayPid"
        }
    }
    if ($relayPid -gt 0) { $arguments += @('-RelayPid', [string]$relayPid) }
    if ($relayPidFile) { $arguments += @('-RelayPidFile', (ConvertTo-ProcessArgument $relayPidFile)) }
    if ($relayPath) { $arguments += @('-RelayPath', (ConvertTo-ProcessArgument $relayPath)) }
    if ($relayStartUtc) { $arguments += @('-RelayStartUtc', (ConvertTo-ProcessArgument $relayStartUtc)) }
    $mitmPath = $null
    $mitmStartUtc = $null
    if ($null -ne $MitmProcess) {
        $arguments += @('-MitmPid', [string]$MitmProcess.Id)
        try { $mitmPath = [string]$MitmProcess.Path } catch { }
        try { $mitmStartUtc = $MitmProcess.StartTime.ToUniversalTime().ToString('o') } catch { }
        if ([string]::IsNullOrWhiteSpace($mitmPath) -or [string]::IsNullOrWhiteSpace($mitmStartUtc)) {
            throw "MITM process identity is incomplete for PID $($MitmProcess.Id)"
        }
    }
    if ($mitmPath) { $arguments += @('-MitmPath', (ConvertTo-ProcessArgument $mitmPath)) }
    if ($mitmStartUtc) { $arguments += @('-MitmStartUtc', (ConvertTo-ProcessArgument $mitmStartUtc)) }
    if ($MitmPidFile) { $arguments += @('-MitmPidFile', (ConvertTo-ProcessArgument $MitmPidFile)) }
    if ($MitmProcessPidFile) { $arguments += @('-MitmProcessPidFile', (ConvertTo-ProcessArgument $MitmProcessPidFile)) }
    if ($CaPath) { $arguments += @('-CaPath', (ConvertTo-ProcessArgument $CaPath)) }
    if ($LaunchStateFile) { $arguments += @('-LaunchStateFile', (ConvertTo-ProcessArgument $LaunchStateFile)) }
    if ($LaunchGeneration) { $arguments += @('-LaunchGeneration', (ConvertTo-ProcessArgument $LaunchGeneration)) }
    if ($MonitorReadyFile) { $arguments += @('-MonitorReadyFile', (ConvertTo-ProcessArgument $MonitorReadyFile)) }
    if ($NativeRequired) { $arguments += '-NativeRequired' }
    if ($RemoveCa) { $arguments += '-RemoveCaAfterExit' }
    $monitor = Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -WindowStyle Hidden -ErrorAction Stop
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($monitor.HasExited) { throw "Desktop lifecycle monitor exited with code $($monitor.ExitCode) before ready" }
            $state = Read-DesktopStateFile -Path $MonitorReadyFile
            if ($null -ne $state -and [string]$state.state -eq 'ready' -and
                [string]$state.generation -eq [string]$LaunchGeneration -and
                [int]$state.rootPid -eq $DesktopPid) {
                return [int]$monitor.Id
            }
            Start-Sleep -Milliseconds 100
        }
        throw 'Desktop lifecycle monitor did not publish a ready state'
    } catch {
        try {
            if (-not $monitor.HasExited) { $monitor.Kill(); [void]$monitor.WaitForExit(3000) }
        } catch { }
        throw
    }
}

function Invoke-DesktopMonitorAction {
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $paths = $null
    $profileLock = $null
    $rootIdentity = $null
    $allowCleanup = $false
    $hardFailure = $false
    $failureReason = $null
    $healthPath = $null
    $rootIdentityValid = ($WatchPid -gt 0 -and
        -not [string]::IsNullOrWhiteSpace($WatchPath) -and
        -not [string]::IsNullOrWhiteSpace($WatchStartUtc))
    try {
        try { $paths = Get-ProfilePaths -Name (Resolve-ProfileName -Requested $Profile) } catch {
            [void]$errors.Add("Desktop monitor profile resolution failed: $($_.Exception.Message)")
        }
        if ($null -ne $paths) {
            $healthPath = Join-Path $paths.LogsDir 'desktop-health.json'
            Write-DesktopHealthFile -Path $healthPath -State 'starting' -Generation $LaunchGeneration `
                -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc -Fatal:$false
        }
        if (-not $rootIdentityValid) {
            [void]$errors.Add("Desktop root identity is incomplete; refusing PID-only monitoring")
        } else {
            try {
                $rootStart = [DateTime]::Parse($WatchStartUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
                $rootIdentity = [pscustomobject]@{ Id = $WatchPid; Path = $WatchPath; StartUtc = $rootStart }
            } catch {
                [void]$errors.Add("Desktop root start time is invalid: $WatchStartUtc")
            }
            if ($null -ne $rootIdentity) {
                Write-DesktopStateFile -Path $MonitorReadyFile -State 'ready' -Generation $LaunchGeneration `
                    -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc
                $state = Get-TrackedProcessState -ProcessId $WatchPid -ExpectedPath $WatchPath -ExpectedStartUtc $WatchStartUtc
                while ($state -eq 'alive') {
                    $relayState = 'not-configured'
                    if ($RelayPid -gt 0) {
                        $relayState = Get-TrackedProcessState -ProcessId $RelayPid -ExpectedPath $RelayPath -ExpectedStartUtc $RelayStartUtc
                    }
                    $mitmState = 'not-configured'
                    if ($MitmPid -gt 0) {
                        $mitmState = Get-TrackedProcessState -ProcessId $MitmPid -ExpectedPath $MitmPath -ExpectedStartUtc $MitmStartUtc
                    }
                    $profileProcessIds = @()
                    try { $profileProcessIds = @(Get-ProfileProcessIds -Paths $paths) } catch { }
                    $nativeFaults = if ($NativeRequired) {
                        @(Get-DesktopNativeFaults -AuditPath (Join-Path $paths.AuditDir 'native-hook.jsonl') `
                            -ProcessIds $profileProcessIds -SinceUtc $rootStart)
                    } else { @() }
                    $proxyWarnings = @(Get-DesktopProxyHealthWarning -Paths $paths -RelayState $relayState -MitmState $mitmState)
                    if ($nativeFaults.Count -gt 0) {
                        $hardFailure = $true
                        $failureReason = ($nativeFaults -join '; ')
                        $allowCleanup = $true
                        Write-DesktopHealthFile -Path $healthPath -State 'failed' -Generation $LaunchGeneration `
                            -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc `
                            -RelayState $relayState -MitmState $mitmState -Warnings $proxyWarnings `
                            -Faults $nativeFaults -Fatal:$true -FatalReason $failureReason
                        break
                    }
                    $healthState = if ($proxyWarnings.Count -gt 0) { 'degraded' } else { 'ready' }
                    Write-DesktopHealthFile -Path $healthPath -State $healthState -Generation $LaunchGeneration `
                        -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc `
                        -RelayState $relayState -MitmState $mitmState -Warnings $proxyWarnings `
                        -Faults @() -Fatal:$false
                    Start-Sleep -Milliseconds 500
                    $state = Get-TrackedProcessState -ProcessId $WatchPid -ExpectedPath $WatchPath -ExpectedStartUtc $WatchStartUtc
                }
                if ($state -eq 'exited' -and -not $hardFailure) {
                    $allowCleanup = $true
                } elseif ($state -eq 'reused') {
                    [void]$errors.Add("Desktop root PID $WatchPid was reused; cleanup refused")
                } elseif (-not $hardFailure) {
                    [void]$errors.Add("Desktop root PID $WatchPid identity became unavailable; cleanup refused")
                }
            }
        }
    } finally {
        if ($null -ne $paths) {
            try { $profileLock = Enter-DesktopProfileMutex -ProfileRoot $paths.Root } catch {
                [void]$errors.Add("Desktop monitor mutex failed: $($_.Exception.Message)")
            }
            if ($null -eq $profileLock) {
                if ($errors.Count -eq 0) { [void]$errors.Add("Desktop monitor could not acquire Profile mutex") }
            } else {
                try {
                    $launchState = Read-DesktopStateFile -Path $LaunchStateFile
                    $statePathMatches = ($null -ne $launchState -and
                        [string]::Equals([string]$launchState.rootPath, [string]$WatchPath, [StringComparison]::OrdinalIgnoreCase))
                    $stateStartMatches = $false
                    if ($null -ne $launchState -and -not [string]::IsNullOrWhiteSpace([string]$launchState.rootStartUtc)) {
                        try {
                            $stateStart = [DateTime]::Parse([string]$launchState.rootStartUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
                            $watchStart = [DateTime]::Parse($WatchStartUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
                            $stateStartMatches = ([Math]::Abs(($stateStart - $watchStart).TotalSeconds) -le 2)
                        } catch { $stateStartMatches = $false }
                    }
                    $stateMatches = ($null -ne $launchState -and
                        [string]$launchState.generation -eq [string]$LaunchGeneration -and
                        [int]$launchState.rootPid -eq $WatchPid -and
                        $statePathMatches -and $stateStartMatches)
                    if (-not $stateMatches) {
                        Write-Host '[CLEANUP] stale Desktop monitor ignored; Profile has a newer launch generation' -ForegroundColor Yellow
                        $allowCleanup = $false
                    }
                    $mitm = $null
                    if ($MitmPid -gt 0) {
                        if ([string]::IsNullOrWhiteSpace($MitmPath) -or [string]::IsNullOrWhiteSpace($MitmStartUtc)) {
                            [void]$errors.Add("MITM identity is incomplete; refusing PID-only cleanup")
                        } else {
                            $mitm = Get-TrackedProcess -ProcessId $MitmPid -ExpectedPath $MitmPath -ExpectedStartUtc $MitmStartUtc
                        }
                    }
                    $relayProcess = $null
                    if ($RelayPid -gt 0) {
                        if ([string]::IsNullOrWhiteSpace($RelayPath) -or [string]::IsNullOrWhiteSpace($RelayStartUtc)) {
                            [void]$errors.Add("Relay identity is incomplete; refusing PID-only cleanup")
                        } else {
                            $relayProcess = Get-TrackedProcess -ProcessId $RelayPid -ExpectedPath $RelayPath -ExpectedStartUtc $RelayStartUtc
                        }
                    }
                    $relay = if ($null -ne $relayProcess) {
                        [pscustomobject]@{ owned = $true; process = $relayProcess; pidFile = $RelayPidFile }
                    } else { $null }
                    if ($rootIdentityValid -and $allowCleanup -and $stateMatches) {
                        $cleanupErrors = @(Stop-DesktopLaunchResources -Paths $paths -DesktopPid $WatchPid `
                            -RootIdentity $rootIdentity `
                            -MitmProcess $mitm -Relay $relay `
                            -PidFiles @($RelayPidFile, $MitmPidFile, $MitmProcessPidFile) `
                            -CaPath $CaPath -RemoveCa ([bool]$RemoveCaAfterExit))
                        foreach ($errorText in $cleanupErrors) { [void]$errors.Add($errorText) }
                        if ($cleanupErrors.Count -eq 0) {
                            if ($hardFailure) {
                                Write-DesktopStateFile -Path $LaunchStateFile -State 'failed' -Generation $LaunchGeneration `
                                    -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc -ErrorText $failureReason
                                Write-DesktopHealthFile -Path $healthPath -State 'failed' -Generation $LaunchGeneration `
                                    -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc `
                                    -RelayState 'stopped' -MitmState 'stopped' -Faults @($failureReason) `
                                    -Fatal:$true -FatalReason $failureReason
                            } else {
                                Write-DesktopStateFile -Path $LaunchStateFile -State 'stopped' -Generation $LaunchGeneration `
                                    -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc
                                Write-DesktopHealthFile -Path $healthPath -State 'stopped' -Generation $LaunchGeneration `
                                    -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc `
                                    -RelayState 'stopped' -MitmState 'stopped' -Fatal:$false
                            }
                        }
                    } else {
                        if ($rootIdentityValid -and -not $stateMatches) {
                            Write-Host '[CLEANUP] Desktop tree cleanup skipped for stale launch generation' -ForegroundColor Yellow
                        } else {
                            [void]$errors.Add('Desktop root tree cleanup skipped because root identity was not authenticated')
                        }
                    }
                } finally {
                    Exit-DesktopProfileMutex $profileLock
                }
            }
        }
        foreach ($errorText in $errors) { Write-Host "[CLEANUP] $errorText" -ForegroundColor Red }
        $script:MonitorExitCode = if ($errors.Count -gt 0) { 1 } else { 0 }
    }
    return $script:MonitorExitCode
}

function Start-ClaudeDesktop {
    param(
        [psobject]$Paths,
        [string]$ExePath,
        [bool]$UseInject,
        [bool]$UseFingerprint
    )

    $mitmProcess = $null
    $mitmPort = $null
    $mitmPidFile = $null
    $mitmProcessPidFile = $null
    $personaPath = $null
    $relay = $null
    $relayPidFile = $null
    $proxyBinding = $null
    $mitm = $null
    $caPath = $null
    $caInstalledByLaunch = $false
    $startedProcess = $null
    $startedRootIdentity = $null
    $launcherProcess = $null
    $launcherStdoutFile = $null
    $launcherStderrFile = $null
    $resourceTransferred = $false
    $monitorPid = $null
    $launchGeneration = $null
    $launchStateFile = $null
    $monitorReadyFile = $null
    $result = $null
    $profileLock = $null
    $persona = $null

    try {
    $profileLock = Enter-DesktopProfileMutex -ProfileRoot $Paths.Root
    if ($null -eq $profileLock) { throw "Profile is busy: $($Paths.Root)" }
    Assert-DesktopNoReparsePoints -Path $Paths.Root

    # A killed launcher can leave Claude children, relay, or MITM alive while
    # the UI has already forgotten the runtime. Recover only processes proven
    # to belong to this Profile before creating a new proxy generation.
    $residual = @(Get-ProfileProcessIds -Paths $Paths)
    if ($residual.Count -gt 0) {
        Write-Host ("[RECOVER] stopping residual Profile processes: {0}" -f ($residual -join ', ')) -ForegroundColor Yellow
        Stop-ProfileProcesses -Paths $Paths
        Start-Sleep -Milliseconds 300
        $remainingResidual = @(Get-ProfileProcessIds -Paths $Paths)
        if ($remainingResidual.Count -gt 0) {
            throw "Profile residual processes could not be stopped: $($remainingResidual -join ', ')"
        }
        Write-Host '[RECOVER] residual Profile processes cleared.' -ForegroundColor Green
    }
    Remove-StaleProfileLaunchCa -Paths $Paths

    # Fail before starting MITM or touching the profile when the Desktop process
    # is already active or the requested WindowsApps path is unavailable. The
    # second check below remains for races between preflight and CreateProcess.
    $preflightRunning = @(Get-ClaudeDesktopProcesses -ExePath $ExePath)
    if ($preflightRunning.Count -gt 0) {
        Write-Host "[BLOCKED] Claude Desktop is already running." -ForegroundColor Yellow
        foreach ($process in $preflightRunning) {
            Write-Host ("          PID {0}" -f $process.Id) -ForegroundColor DarkGray
        }
        return [pscustomobject]@{
            started        = $false
            blocked        = $true
            error          = $null
            mode           = $null
            processId      = $null
            launchFile     = $null
            arguments      = $null
            userDataDir    = $Paths.UserDataDir
            nativeRequested = $UseInject
            nativeUsed     = $false
        }
    }
    if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
        return [pscustomobject]@{
            started        = $false
            blocked        = $false
            error          = "Executable not found: $ExePath"
            mode           = $null
            processId      = $null
            launchFile     = $null
            arguments      = $null
            userDataDir    = $Paths.UserDataDir
            nativeRequested = $UseInject
            nativeUsed     = $false
        }
    }

    # Create log/mitm directories before the addon starts; otherwise a fresh
    # profile cannot publish its PID file and fail-closed monitoring breaks.
    Initialize-ProfileLayout -Paths $Paths -ForLaunch | Out-Null
    Assert-DesktopNoReparsePoints -Path $Paths.Root
    if ($UseFingerprint) {
        $personaPath = Initialize-ProfilePersona -Paths $Paths -ExePath $ExePath
        Assert-ProfileDeviceImageLock -Paths $Paths -InitializeIfMissing | Out-Null
        Assert-ProfilePersonaRuntime -Paths $Paths -ExePath $ExePath
    }
    $launchGeneration = [Guid]::NewGuid().ToString('N')
    $launchStateFile = Join-Path $Paths.LogsDir 'desktop-launch.json'
    $monitorReadyFile = Join-Path $Paths.LogsDir ('.desktop-monitor-{0}.json' -f $launchGeneration)
    Remove-Item -LiteralPath $monitorReadyFile -Force -ErrorAction SilentlyContinue

    $proxyBinding = Resolve-DesktopProxyBinding -ProfileName $Paths.Name
    if ($null -ne $proxyBinding) {
        $relay = Start-CacProxyRelay -UpstreamProxyUrl ([string]$proxyBinding.url) -LogsDir $Paths.LogsDir
        if ([bool]$relay.owned) { $relayPidFile = [string]$relay.pidFile }
    }

    if ($UseFingerprint) {
        $mitm = Resolve-MitmdumpPath -Requested $MitmDump
        $addon = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\mitm_fingerprint.py'
        $shim = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\fingerprint-shim.js'
        if (-not $mitm -or -not (Test-Path -LiteralPath $addon -PathType Leaf) -or
            -not (Test-Path -LiteralPath $shim -PathType Leaf)) {
            return [pscustomobject]@{
                started = $false; blocked = $true; error = 'mitmdump or fingerprint assets missing'
                mode = $null; processId = $null; launchFile = $null; arguments = $null
                userDataDir = $Paths.UserDataDir; nativeRequested = $UseInject; nativeUsed = $false
                mitmPort = $null; fingerprintPersona = $null
            }
        }
        $mitmPort = Get-FreeTcpPort
        $mitmPidFile = Join-Path $Paths.LogsDir 'mitm-claude.pid'
        $mitmProcessPidFile = Join-Path $Paths.LogsDir 'mitm-proxy.pid'
        Remove-Item -LiteralPath $mitmPidFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $mitmProcessPidFile -Force -ErrorAction SilentlyContinue
        $saved = @{}
        foreach ($name in @('CAC_PERSONA', 'CAC_SHIM', 'CAC_MITM_LOG', 'CAC_MITM_PIDFILE')) {
            $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        }
        try {
            $env:CAC_PERSONA = $personaPath
            $env:CAC_SHIM = $shim
            $env:CAC_MITM_LOG = Join-Path $Paths.LogsDir 'mitm-fingerprint.log'
            $env:CAC_MITM_PIDFILE = $mitmPidFile
            New-Item -ItemType Directory -Path $Paths.MitmDir -Force | Out-Null
            $mitmArguments = @('-q', '-s', $addon, '--listen-port', "$mitmPort",
                '--set', "confdir=$($Paths.MitmDir)")
            if ($null -ne $relay) { $mitmArguments += @('--mode', "upstream:$($relay.url)") }
            $mitmStdout = Join-Path $Paths.LogsDir 'mitm-proxy.stdout.log'
            $mitmStderr = Join-Path $Paths.LogsDir 'mitm-proxy.stderr.log'
            Remove-Item -LiteralPath $mitmStdout, $mitmStderr -Force -ErrorAction SilentlyContinue
            $mitmProcess = Start-Process -FilePath $mitm `
                -ArgumentList $mitmArguments `
                -RedirectStandardOutput $mitmStdout `
                -RedirectStandardError $mitmStderr `
                -PassThru -WindowStyle Hidden
            Set-Content -LiteralPath $mitmProcessPidFile -Value "$($mitmProcess.Id)" -Encoding ASCII
        } finally {
            foreach ($name in $saved.Keys) {
                [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
            }
        }
        $mitmReady = $false
        $deadline = (Get-Date).AddSeconds(10)
        do {
            try {
                if ($mitmProcess -and $mitmProcess.HasExited) { break }
            } catch { break }
            $client = $null
            try {
                $client = [System.Net.Sockets.TcpClient]::new()
                $client.Connect('127.0.0.1', $mitmPort)
                $mitmReady = $true
                break
            } catch {
                Start-Sleep -Milliseconds 200
            } finally {
                if ($client) { $client.Dispose() }
            }
        } while ((Get-Date) -lt $deadline)

        if (-not $mitmReady) {
            return [pscustomobject]@{
                started = $false; blocked = $true
                error = "MITM did not listen on 127.0.0.1:$mitmPort"
                mode = $null; processId = $null; launchFile = $null; arguments = $null
                userDataDir = $Paths.UserDataDir; nativeRequested = $UseInject; nativeUsed = $false
                mitmPort = $mitmPort; fingerprintPersona = $personaPath; mitmPid = $null
            }
        }

        $caPath = Join-Path $Paths.MitmDir 'mitmproxy-ca-cert.cer'
        $caDeadline = (Get-Date).AddSeconds(5)
        while (-not (Test-Path -LiteralPath $caPath -PathType Leaf) -and (Get-Date) -lt $caDeadline) {
            try {
                if ($mitmProcess -and $mitmProcess.HasExited) { break }
            } catch { break }
            Start-Sleep -Milliseconds 200
        }
        $caInstalled = $false
        $caInstallError = ''
        $caThumbprint = if (Test-Path -LiteralPath $caPath -PathType Leaf) {
            Get-CertificateThumbprintFromFile -Path $caPath
        } else { $null }
        $caWasPresent = ($null -ne $caThumbprint -and @(Get-MitmCa | Where-Object {
            $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $caThumbprint
        }).Count -gt 0)
        if (Test-Path -LiteralPath $caPath -PathType Leaf) {
            try {
                $caInstalled = [bool](Install-MitmCa -Path $caPath)
                $caInstallError = [string]$script:MitmCaInstallError
                $caInstalledByLaunch = $caInstalled -and -not $caWasPresent
            } catch {
                $caInstalled = $false
                $caInstallError = $_.Exception.Message
            }
        }
        if (-not $caInstalled) {
            $caErrorSuffix = if ([string]::IsNullOrWhiteSpace($caInstallError)) { '' } else { " ($caInstallError)" }
            return [pscustomobject]@{
                started = $false; blocked = $true
                error = "MITM CA installation failed for profile $($Paths.Name): $caPath$caErrorSuffix"
                mode = $null; processId = $null; launchFile = $null; arguments = $null
                userDataDir = $Paths.UserDataDir; nativeRequested = $UseInject; nativeUsed = $false
                mitmPort = $mitmPort; fingerprintPersona = $personaPath; mitmPid = $null
            }
        }
    }

    $running = @(Get-ClaudeDesktopProcesses -ExePath $ExePath)
    if ($running.Count -gt 0) {
        Write-Host "[BLOCKED] Claude Desktop is already running." -ForegroundColor Yellow
        foreach ($process in $running) {
            Write-Host ("          PID {0}" -f $process.Id) -ForegroundColor DarkGray
        }
        Write-Host "          Close all Claude Desktop windows manually, then retry." -ForegroundColor Yellow
        Write-Host "          This script does not terminate existing user sessions." -ForegroundColor Yellow
        return [pscustomobject]@{
            started        = $false
            blocked        = $true
            error          = $null
            mode           = $null
            processId      = $null
            launchFile     = $null
            arguments      = $null
            userDataDir    = $Paths.UserDataDir
            nativeRequested = $UseInject
            nativeUsed     = $false
        }
    }

    if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
        return [pscustomobject]@{
            started        = $false
            blocked        = $false
            error          = "Executable not found: $ExePath"
            mode           = $null
            processId      = $null
            launchFile     = $null
            arguments      = $null
            userDataDir    = $Paths.UserDataDir
            nativeRequested = $UseInject
            nativeUsed     = $false
        }
    }

    $identity = Initialize-ProfileIdentity -Paths $Paths

    $fingerprintPort = $null
    $fingerprintArgs = @()
    $localProxyEndpoint = $null
    if ($UseFingerprint -and $mitmPort -and $personaPath) {
        $persona = Get-Content -LiteralPath $personaPath -Raw | ConvertFrom-Json
        $localProxyEndpoint = "http://127.0.0.1:$mitmPort"
        if ($persona.locale) { $fingerprintArgs += "--lang=$($persona.locale)" }
    } elseif ($null -ne $relay) {
        $localProxyEndpoint = [string]$relay.url
    }

    $nativeDir = Join-Path $script:OriginalUserProfile '.cac\native'
    $nativeLauncher = Join-Path $nativeDir 'cac-native-launch.exe'
    $nativeDll = Join-Path $nativeDir 'NativeBridge.dll'
    $nativeUsed = $false

    if ($UseInject) {
        Sync-NativeLayer
        if ((Test-Path -LiteralPath $nativeLauncher -PathType Leaf) -and
            (Test-Path -LiteralPath $nativeDll -PathType Leaf)) {
            $nativeUsed = $true
        } else {
            throw "Native injection requested but the verified Native layer is unavailable: $nativeDir"
        }
    }

    $userDataArgument = '--user-data-dir=' + (ConvertTo-ProcessArgument -Value $Paths.UserDataDir)
    $extraArguments = if ($fingerprintArgs.Count -gt 0) { ' ' + ($fingerprintArgs -join ' ') } else { '' }
    if ($nativeUsed) {
        $launchFile = $nativeLauncher
        # Unsigned DLL injection into Chromium renderer/GPU processes is blocked
        # once ACG/CIG is active. Native mode deliberately starts Claude without
        # the renderer sandbox so every child can be intercepted before it reads
        # device identity. Direct (non-Native) mode keeps the stock sandbox.
        $arguments = (ConvertTo-ProcessArgument -Value $ExePath) + ' ' + $userDataArgument +
                     ' --no-sandbox --disable-gpu-sandbox' + $extraArguments
        $mode = 'native'
    } else {
        $launchFile = $ExePath
        $arguments = $userDataArgument + $extraArguments
        $mode = 'direct'
    }
    if ($RequireKernel -and -not $nativeUsed) {
        throw '-RequireKernel requires -Inject so NativeBridge can register the process policy'
    }
    if ($UseFingerprint) { $mode += '+fingerprint' }

    $homeDrive = ''
    $homePath = ''
    $homeRoot = [System.IO.Path]::GetPathRoot($Paths.Home)
    if ($homeRoot -match '^[A-Za-z]:\\$') {
        $homeDrive = $homeRoot.Substring(0, 2)
        $homePath = $Paths.Home.Substring(2)
    } else {
        throw "Unable to derive isolated HOMEDRIVE/HOMEPATH for $($Paths.Home)"
    }
    if ([string]::IsNullOrWhiteSpace($homeDrive) -or [string]::IsNullOrWhiteSpace($homePath)) {
        throw "Unable to derive isolated HOMEDRIVE/HOMEPATH for $($Paths.Home)"
    }

    $environment = [ordered]@{
        APPDATA              = $Paths.AppData
        LOCALAPPDATA         = $Paths.LocalAppData
        USERPROFILE          = $Paths.Home
        HOME                 = $Paths.Home
        HOMEDRIVE            = $homeDrive
        HOMEPATH             = $homePath
        CLAUDE_CONFIG_DIR    = $Paths.ConfigDir
        TEMP                 = $Paths.Temp
        TMP                  = $Paths.Temp
        CAC_DESKTOP_PROFILE  = $Paths.Name
        CAC_PROFILE_DIR      = $Paths.Root
        CAC_PROFILE_NAME     = $Paths.Name
        CAC_PROFILE_IDENTITY = $Paths.IdentityPath
        CAC_HOSTNAME         = [string]$identity.hostname
        CAC_MACHINE_ID       = [string]$identity.machine_id
        CAC_MAC              = [string]$identity.mac_address
        CAC_USERNAME         = [string]$identity.username
        CAC_NATIVE_READ_POLICY = 'profile'
        CAC_NATIVE_CPUID_MODE  = 'neutral'
        CAC_NATIVE_AUDIT     = (Join-Path $Paths.AuditDir 'native-hook.jsonl')
        CAC_KERNEL_POLICY_REQUIRED = if ($RequireKernel -and $nativeUsed) { '1' } else { '0' }
        HTTP_PROXY           = if ($null -ne $localProxyEndpoint) { [string]$localProxyEndpoint } else { '' }
        HTTPS_PROXY          = if ($null -ne $localProxyEndpoint) { [string]$localProxyEndpoint } else { '' }
        ALL_PROXY            = if ($null -ne $localProxyEndpoint) { [string]$localProxyEndpoint } else { '' }
        NO_PROXY             = 'localhost,127.0.0.1,::1'
        CAC_HTTP_PROXY_LOCAL = if ($null -ne $localProxyEndpoint) { [string]$localProxyEndpoint } else { '' }
        CAC_PROXY_ID         = if ($null -ne $proxyBinding) { [string]$proxyBinding.proxyId } else { '' }
        CAC_PROXY_SOURCE     = if ($null -ne $proxyBinding) { [string]$proxyBinding.source } else { '' }
        # Claude 5.1231.2 rejects proxy/DNS/QUIC/WebRTC override switches on
        # its command line. NativeBridge must provide the per-process proxy
        # through WinHTTP/WinINet discovery, with WFP blocking direct egress.
        CAC_NATIVE_DISABLE_NETWORK_HOOKS = '0'
    }
    if ($null -ne $persona) {
        $lockedLanguages = @($persona.languages | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        if ([string]::IsNullOrWhiteSpace([string]$persona.timezone) -or
            [string]::IsNullOrWhiteSpace([string]$persona.locale) -or
            $lockedLanguages.Count -eq 0) {
            throw 'Locked fingerprint.json is missing timezone, locale, or languages'
        }
        $environment['TZ'] = [string]$persona.timezone
        $environment['LANG'] = [string]$persona.locale
        $environment['LANGUAGE'] = $lockedLanguages -join ':'
        $environment['LC_ALL'] = [string]$persona.locale
    }
    $nativePolicyPath = Join-Path $Paths.Root 'native_read_policy'
    if (Test-Path -LiteralPath $nativePolicyPath -PathType Leaf) {
        $nativePolicy = (Get-Content -LiteralPath $nativePolicyPath -Raw).Trim().ToLowerInvariant()
        if ($nativePolicy -in @('profile', 'empty')) {
            $environment['CAC_NATIVE_READ_POLICY'] = $nativePolicy
            if ($nativePolicy -eq 'empty') { $environment['CAC_NATIVE_CPUID_MODE'] = 'empty' }
        }
    }
    $cpuidModePath = Join-Path $Paths.Root 'cpuid_mode'
    if (Test-Path -LiteralPath $cpuidModePath -PathType Leaf) {
        $cpuidMode = (Get-Content -LiteralPath $cpuidModePath -Raw).Trim().ToLowerInvariant()
        if ($cpuidMode -in @('neutral', 'empty', 'passthrough')) {
            $environment['CAC_NATIVE_CPUID_MODE'] = $cpuidMode
        }
    }
    $networkMode = 'profile'
    $networkModePath = Join-Path $Paths.Root 'network_mode'
    if (Test-Path -LiteralPath $networkModePath -PathType Leaf) {
        $configured = (Get-Content -LiteralPath $networkModePath -Raw).Trim().ToLowerInvariant()
        if ($configured -in @('profile', 'clean', 'enforce')) { $networkMode = $configured }
    }
    if ($environment['CAC_NATIVE_READ_POLICY'] -eq 'empty' -and $networkMode -ne 'enforce') { $networkMode = 'clean' }
    if ($null -ne $relay -and $networkMode -eq 'profile') { $networkMode = 'enforce' }
    if ($networkMode -eq 'enforce' -and $null -eq $proxyBinding) {
        throw 'network_mode=enforce requires a verified proxy binding'
    }
    if ($networkMode -eq 'enforce' -and -not $nativeUsed) {
        throw 'network_mode=enforce requires -Inject so NativeBridge can install the per-process WFP boundary'
    }
    $environment['CAC_NETWORK_MODE'] = $networkMode
    $environment['CAC_NETWORK_ENFORCE'] = if ($networkMode -eq 'enforce') { '1' } else { '0' }
    $environment['CAC_WFP_REQUIRED'] = if ($networkMode -eq 'enforce' -and $nativeUsed) { '1' } else { '0' }
    $manifest = Join-Path $nativeDir 'native-hook-manifest.txt'
    if (Test-Path -LiteralPath $manifest -PathType Leaf) { $environment['CAC_NATIVE_MANIFEST'] = $manifest }
    if ($nativeUsed) { $environment['CAC_NATIVE_DLL'] = $nativeDll }

    $saved = @{}
    foreach ($name in $environment.Keys) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }

    $startedProcess = $null
    $startError = $null
    $launchStartedUtc = [DateTime]::UtcNow
    $launcherStdoutFile = Join-Path $Paths.LogsDir 'desktop-launcher.stdout.log'
    $launcherStderrFile = Join-Path $Paths.LogsDir 'desktop-launcher.stderr.log'
    Remove-Item -LiteralPath $launcherStdoutFile, $launcherStderrFile -Force -ErrorAction SilentlyContinue
    try {
        foreach ($name in $environment.Keys) {
            [Environment]::SetEnvironmentVariable($name, [string]$environment[$name], 'Process')
        }
        [void](Push-DesktopKernelIdentity -Identity $identity -TempDir $Paths.Temp -ProfileRoot $Paths.Root)
        $launcherProcess = Start-Process -FilePath $launchFile -ArgumentList $arguments `
            -RedirectStandardOutput $launcherStdoutFile -RedirectStandardError $launcherStderrFile `
            -PassThru -WindowStyle Hidden -ErrorAction Stop
    } catch {
        $startError = $_.Exception.Message
    } finally {
        foreach ($name in $saved.Keys) {
            [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
        }
    }

    if ($null -eq $launcherProcess) { throw "Claude Desktop failed to start: $startError" }
    $desktopProcess = Wait-ClaudeDesktopRoot -ExePath $ExePath -LauncherProcess $launcherProcess `
        -AuditPath (Join-Path $Paths.AuditDir 'native-hook.jsonl') -NativeRequired $nativeUsed `
        -ExpectedUserDataDir $Paths.UserDataDir -LaunchStartedUtc $launchStartedUtc
    $startedProcess = $desktopProcess
    $processId = [int]$desktopProcess.Id
    $startedRootIdentity = Get-ProcessIdentity -ProcessId $processId
    if ($null -eq $startedRootIdentity) { throw "Desktop root identity unavailable for PID $processId" }
    [void](Register-DesktopKernelPid -ProcessId $processId -Paths $Paths -NativeReadPolicy $nativePolicy)
    $desktopStartUtc = $desktopProcess.StartTime.ToUniversalTime().ToString('o')
    Write-DesktopStateFile -Path $launchStateFile -State 'active' -Generation $launchGeneration `
        -RootPid $processId -RootPath ([string]$desktopProcess.Path) -RootStartUtc $desktopStartUtc `
        -CaPath $caPath -RemoveCa ([bool]$caInstalledByLaunch)

    if ($UseFingerprint -and $processId -and $mitmPidFile) {
        Set-Content -LiteralPath $mitmPidFile -Value "$processId" -Encoding ASCII
    }
    # Always keep a lifecycle monitor so direct launches also clean detached
    # renderer/utility processes after the Desktop root exits.
    $monitorPid = Start-DesktopLifecycleMonitor -Paths $Paths -DesktopPid $processId `
        -Relay $relay -MitmProcess $mitmProcess -MitmPidFile $mitmPidFile `
        -MitmProcessPidFile $mitmProcessPidFile -RemoveCa $caInstalledByLaunch -CaPath $caPath `
        -LaunchStateFile $launchStateFile -LaunchGeneration $launchGeneration -MonitorReadyFile $monitorReadyFile `
        -NativeRequired ([bool]$nativeUsed)
    $resourceTransferred = $true

    return [pscustomobject]@{
        started         = ($null -ne $startedProcess)
        blocked         = $false
        error           = $startError
        mode            = $mode
        processId       = $processId
        launchFile      = $launchFile
        arguments       = $arguments
        userDataDir     = $Paths.UserDataDir
        nativeRequested = $UseInject
        nativeUsed      = $nativeUsed
        fingerprintPort = $fingerprintPort
        fingerprintPersona = $personaPath
        mitmPort        = $mitmPort
        mitmPid         = if ($mitmProcess) { $mitmProcess.Id } else { $null }
        proxyId         = if ($null -ne $proxyBinding) { [string]$proxyBinding.proxyId } else { $null }
        proxySource     = if ($null -ne $proxyBinding) { [string]$proxyBinding.source } else { $null }
        relayPort       = if ($null -ne $relay) { [int]$relay.port } else { $null }
        relayPid        = if ($null -ne $relay -and $relay.process) { [int]$relay.process.Id } else { $null }
        monitorPid      = $monitorPid
    }
    } catch {
        $exceptionText = [string]$_.Exception.Message
        $invocation = $_.InvocationInfo
        if ($null -ne $invocation -and $invocation.ScriptLineNumber -gt 0) {
            $lineText = ([string]$invocation.Line).Trim()
            if ($lineText.Length -gt 240) { $lineText = $lineText.Substring(0, 240) }
            if (-not [string]::IsNullOrWhiteSpace($lineText)) {
                $exceptionText = "{0} [desktop-profile.ps1:{1}] {2}" -f $exceptionText, $invocation.ScriptLineNumber, $lineText
            } else {
                $exceptionText = "{0} [desktop-profile.ps1:{1}]" -f $exceptionText, $invocation.ScriptLineNumber
            }
        }
        $result = [pscustomobject]@{
            started         = $false
            blocked         = $true
            error           = $exceptionText
            mode            = $null
            processId       = $null
            launchFile      = $null
            arguments       = $null
            userDataDir     = $Paths.UserDataDir
            nativeRequested = $UseInject
            nativeUsed      = $false
            cleanupErrors   = @()
        }
    } finally {
        if (-not $resourceTransferred) {
            $cleanupErrors = @(Stop-DesktopLaunchResources -Paths $Paths -DesktopProcess $startedProcess `
                -RootIdentity $startedRootIdentity `
                -MitmProcess $mitmProcess -Relay $relay `
                -PidFiles @($relayPidFile, $mitmPidFile, $mitmProcessPidFile) `
                -CaPath $caPath -RemoveCa $caInstalledByLaunch)
            foreach ($errorText in $cleanupErrors) {
                Write-Host "[CLEANUP] $errorText" -ForegroundColor Red
            }
            if (-not [string]::IsNullOrWhiteSpace($launcherStderrFile) -and
                (Test-Path -LiteralPath $launcherStderrFile -PathType Leaf)) {
                $launcherDiagnostic = (Get-Content -LiteralPath $launcherStderrFile -Tail 80 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
                if (-not [string]::IsNullOrWhiteSpace($launcherDiagnostic)) {
                    Write-Host "[LAUNCHER STDERR] $launcherDiagnostic" -ForegroundColor Yellow
                }
            }
            if ($null -ne $result) { $result.cleanupErrors = @($cleanupErrors) }
            if (-not [string]::IsNullOrWhiteSpace($launchStateFile) -and
                -not [string]::IsNullOrWhiteSpace($launchGeneration)) {
                $failureText = if ($null -ne $result -and $result.error) { [string]$result.error } else { 'Desktop launch failed before lifecycle ownership was transferred' }
                Write-DesktopStateFile -Path $launchStateFile -State 'failed' -Generation $launchGeneration -ErrorText $failureText
            }
        }
        Exit-DesktopProfileMutex $profileLock
    }
    return $result
}

function Get-ProcessSnapshot {
    try {
        return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            Select-Object ProcessId, ParentProcessId)
    } catch {
        try {
            return @(Get-WmiObject -Class Win32_Process -ErrorAction Stop |
                Select-Object ProcessId, ParentProcessId)
        } catch {
            throw "Unable to enumerate the process tree through CIM/WMI: $($_.Exception.Message)"
        }
    }
}

function Get-ProcessTreeIds {
    param([int]$RootProcessId)
    $rows = @(Get-ProcessSnapshot)
    $children = @{}
    foreach ($row in $rows) {
        $parentId = [int]$row.ParentProcessId
        $childId = [int]$row.ProcessId
        if (-not $children.ContainsKey($parentId)) {
            $children[$parentId] = New-Object 'System.Collections.Generic.List[int]'
        }
        [void]$children[$parentId].Add($childId)
    }

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($RootProcessId)
    $seen = @{}
    $ordered = New-Object 'System.Collections.Generic.List[int]'
    while ($queue.Count -gt 0) {
        $currentId = [int]$queue.Dequeue()
        if ($seen.ContainsKey($currentId)) { continue }
        $seen[$currentId] = $true
        [void]$ordered.Add($currentId)
        if ($children.ContainsKey($currentId)) {
            foreach ($childId in $children[$currentId]) {
                if (-not $seen.ContainsKey($childId)) { $queue.Enqueue($childId) }
            }
        }
    }
    return @($ordered)
}

function Get-ProcessIdentity {
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return $null }
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $path = [string]$process.Path
        if ([string]::IsNullOrWhiteSpace($path)) { return $null }
        $startUtc = $process.StartTime.ToUniversalTime()
        return [pscustomobject]@{
            Id       = $ProcessId
            Path     = $path
            StartUtc = $startUtc
        }
    } catch {
        return $null
    }
}

function Test-ProcessIdentity {
    param([psobject]$Identity)
    if ($null -eq $Identity) { return $false }
    $current = Get-ProcessIdentity -ProcessId ([int]$Identity.Id)
    if ($null -eq $current) { return $false }
    if (-not [string]::Equals([string]$current.Path, [string]$Identity.Path, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    return ([Math]::Abs(($current.StartUtc - $Identity.StartUtc).TotalSeconds) -le 2)
}

function Get-ClaudeRootIdentity {
    param(
        [int]$ProcessId,
        [psobject]$Paths
    )
    $identity = Get-ProcessIdentity -ProcessId $ProcessId
    if ($null -eq $identity) { return $null }
    try {
        if (-not [string]::Equals([System.IO.Path]::GetFileName($identity.Path), 'claude.exe', [StringComparison]::OrdinalIgnoreCase)) {
            return $null
        }
    } catch { return $null }

    if ($null -ne $Paths -and -not [string]::IsNullOrWhiteSpace([string]$Paths.UserDataDir)) {
        $row = @(Get-ClaudeProcessRows | Where-Object { [int]$_.Id -eq $ProcessId } | Select-Object -First 1)
        if ($row.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$row[0].CommandLine)) {
            $marker = ([string]$Paths.UserDataDir).TrimEnd('\')
            if (-not (Test-TextPathMarker -Text ([string]$row[0].CommandLine) -Marker $marker)) {
                return $null
            }
        }
    }
    return $identity
}

function Get-ProfileProcessIds {
    param([psobject]$Paths)

    $markerList = New-Object 'System.Collections.Generic.List[string]'
    $rawRoot = $null
    if (-not [string]::IsNullOrWhiteSpace($script:OriginalUserProfile) -and
        $Paths.Root.StartsWith($script:DesktopRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $relative = $Paths.Root.Substring($script:DesktopRoot.Length).TrimStart('\')
        $rawRoot = Join-Path (Join-Path $script:OriginalUserProfile '.cac\desktop') $relative
    }
    $pathsToMark = @(
        $Paths.Root,
        $Paths.UserDataDir,
        $Paths.MitmDir,
        $rawRoot,
        $(if ($rawRoot) { Join-Path $rawRoot 'home\AppData\Roaming\Claude' }),
        $(if ($rawRoot) { Join-Path $rawRoot 'mitmproxy' })
    )
    foreach ($path in $pathsToMark) {
        foreach ($marker in @(Get-PathMarkers -Path $path)) {
            if (-not [string]::IsNullOrWhiteSpace($marker) -and -not ($markerList -contains $marker)) {
                [void]$markerList.Add($marker)
            }
        }
    }
    $markers = @($markerList)
    $relevantNames = @(
        'claude.exe',
        'cac-native-launch.exe',
        'mitmdump.exe',
        'mitmproxy.exe',
        'python.exe',
        'pythonw.exe',
        'node.exe',
        'powershell.exe'
    )

    try {
        $rows = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    } catch {
        try {
            $rows = @(Get-WmiObject -Class Win32_Process -ErrorAction Stop)
        } catch {
            throw "Unable to inspect processes before touching profile $($Paths.Name): $($_.Exception.Message)"
        }
    }

    $byId = @{}
    $ids = @()
    foreach ($row in $rows) {
        $id = [int]$row.ProcessId
        $byId[$id] = $row
        $name = [string]$row.Name
        if ($relevantNames -notcontains $name.ToLowerInvariant()) { continue }
        $commandLine = [string]$row.CommandLine
        $executablePath = [string]$row.ExecutablePath
        if ($name -ieq 'powershell.exe' -and
            $commandLine -notmatch '(?i)(?:^|\s)-Action\s+monitor(?:\s|$)') { continue }
        $matched = $false
        foreach ($marker in $markers) {
            if ((Test-TextPathMarker -Text $commandLine -Marker $marker) -or
                (Test-TextPathMarker -Text $executablePath -Marker $marker)) {
                $matched = $true
                break
            }
        }
        if ($matched -and -not ($ids -contains $id)) { $ids += $id }
    }

    # The PID file tracks the Desktop root process and remains useful when
    # Windows returns an empty CommandLine during early process startup.
    foreach ($pidFileName in @('mitm-claude.pid', 'mitm-proxy.pid', 'proxy-relay.pid')) {
        $pidFile = Join-Path $Paths.LogsDir $pidFileName
        if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) { continue }
        $pidText = (Get-Content -LiteralPath $pidFile -Raw -ErrorAction SilentlyContinue).Trim()
        $pidValue = 0
        if ([int]::TryParse($pidText, [ref]$pidValue) -and $pidValue -gt 0 -and $byId.ContainsKey($pidValue)) {
            $pidRow = $byId[$pidValue]
            $pidName = [string]$pidRow.Name
            $pidCommandLine = [string]$pidRow.CommandLine
            $pidExecutablePath = [string]$pidRow.ExecutablePath
            $pidMatchesProfile = $false
            foreach ($marker in $markers) {
                if ((Test-TextPathMarker -Text $pidCommandLine -Marker $marker) -or
                    (Test-TextPathMarker -Text $pidExecutablePath -Marker $marker)) {
                    $pidMatchesProfile = $true
                    break
                }
            }
            if ($pidMatchesProfile -and
                $pidName -in @('claude.exe', 'mitmdump.exe', 'mitmproxy.exe', 'python.exe', 'pythonw.exe', 'node.exe') -and
                -not ($ids -contains $pidValue)) {
                $ids += $pidValue
            }
        }
    }
    return @($ids)
}

function Stop-ProfileProcesses {
    param([psobject]$Paths)
    try {
        $ids = @(Get-ProfileProcessIds -Paths $Paths)
    } catch {
        return
    }
    foreach ($targetId in @($ids | Sort-Object -Descending)) {
        if ([int]$targetId -eq $PID) { continue }
        try { Stop-Process -Id ([int]$targetId) -Force -ErrorAction Stop } catch { }
    }
}

function Stop-TrackedProcess {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) { $Process.Kill() }
    } catch { }
    try { [void]$Process.WaitForExit(3000) } catch { }
}

function Get-TrackedProcess {
    param(
        [int]$ProcessId,
        [string]$ExpectedPath,
        [string]$ExpectedStartUtc
    )
    if ($ProcessId -le 0 -or [string]::IsNullOrWhiteSpace($ExpectedPath) -or
        [string]::IsNullOrWhiteSpace($ExpectedStartUtc)) { return $null }
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    try {
        $actualPath = [System.IO.Path]::GetFullPath([string]$process.Path)
        $wantedPath = [System.IO.Path]::GetFullPath($ExpectedPath)
        if (-not [string]::Equals($actualPath, $wantedPath, [StringComparison]::OrdinalIgnoreCase)) { return $null }
        $expected = [DateTime]::Parse($ExpectedStartUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        $actual = $process.StartTime.ToUniversalTime()
        if ([Math]::Abs(($actual - $expected).TotalSeconds) -gt 2) { return $null }
    } catch { return $null }
    return $process
}

function Get-TrackedProcessState {
    param(
        [int]$ProcessId,
        [string]$ExpectedPath,
        [string]$ExpectedStartUtc
    )
    if ($ProcessId -le 0 -or [string]::IsNullOrWhiteSpace($ExpectedPath) -or
        [string]::IsNullOrWhiteSpace($ExpectedStartUtc)) { return 'unknown' }
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
    } catch {
        return 'exited'
    }
    try {
        $actualPath = [System.IO.Path]::GetFullPath([string]$process.Path)
        $wantedPath = [System.IO.Path]::GetFullPath($ExpectedPath)
        if (-not [string]::Equals($actualPath, $wantedPath, [StringComparison]::OrdinalIgnoreCase)) { return 'reused' }
        $expected = [DateTime]::Parse($ExpectedStartUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        $actual = $process.StartTime.ToUniversalTime()
        if ([Math]::Abs(($actual - $expected).TotalSeconds) -gt 2) { return 'reused' }
        return 'alive'
    } catch {
        return 'unknown'
    }
}

function Get-PathMarkers {
    param([string]$Path)
    $markers = New-Object 'System.Collections.Generic.List[string]'
    foreach ($candidate in @($Path)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $normalized = $candidate.TrimEnd('\')
        if (-not ($markers -contains $normalized)) { [void]$markers.Add($normalized) }
        try {
            $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).ProviderPath.TrimEnd('\')
            if (-not ($markers -contains $resolved)) { [void]$markers.Add($resolved) }
        } catch { }
        try {
            $capacity = 512
            do {
                $buffer = New-Object System.Text.StringBuilder $capacity
                $length = [CacPathNative]::GetShortPathName($candidate, $buffer, [uint32]$capacity)
                if ($length -eq 0) { break }
                if ($length -lt ($capacity - 1)) {
                    $short = $buffer.ToString().TrimEnd('\')
                    if (-not ($markers -contains $short)) { [void]$markers.Add($short) }
                    break
                }
                $capacity *= 2
            } while ($capacity -le 32768)
        } catch { }
    }
    return @($markers)
}

function Stop-ClaudeProcessTree {
    param(
        [int]$RootProcessId,
        [psobject]$Paths,
        [psobject]$RootIdentity
    )

    $rootIdentity = if ($null -ne $RootIdentity) { $RootIdentity } else {
        Get-ClaudeRootIdentity -ProcessId $RootProcessId -Paths $Paths
    }
    if ($null -ne $rootIdentity -and [int]$rootIdentity.Id -ne $RootProcessId) { $rootIdentity = $null }
    if ($null -eq $rootIdentity) {
        return [pscustomobject]@{
            collectedPids = @()
            remainingPids = @($RootProcessId)
            error        = "Refused PID-only Desktop cleanup for root PID $RootProcessId"
        }
    }

    $collected = @()
    $identityById = @{}
    $remaining = @()
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        # Rebuild both views every pass so detached/reparented profile
        # processes are collected after the original tree is gone.
        $scan = @(Get-ProcessTreeIds -RootProcessId $RootProcessId)
        if ($null -ne $Paths) {
            $scan += @(Get-ProfileProcessIds -Paths $Paths)
        }
        $scan = @($scan | Where-Object { $_ -and [int]$_ -ne $PID } | Select-Object -Unique)
        foreach ($targetId in $scan) {
            $targetIdentity = Get-ProcessIdentity -ProcessId ([int]$targetId)
            if ($null -eq $targetIdentity) { continue }
            if (-not $identityById.ContainsKey([int]$targetId)) {
                $identityById[[int]$targetId] = $targetIdentity
            }
            if (-not ($collected -contains [int]$targetId)) { $collected += [int]$targetId }
        }

        for ($index = $scan.Count - 1; $index -ge 0; $index--) {
            $targetId = [int]$scan[$index]
            if ($identityById.ContainsKey($targetId) -and (Test-ProcessIdentity -Identity $identityById[$targetId])) {
                try { Stop-Process -Id $targetId -Force -ErrorAction Stop } catch { }
            }
        }

        Start-Sleep -Milliseconds 200
        $remaining = @($collected | Where-Object {
            $identityById.ContainsKey([int]$_) -and (Test-ProcessIdentity -Identity $identityById[[int]$_])
        } | Select-Object -Unique)
        if ($null -ne $Paths) {
            $remaining += @(Get-ProfileProcessIds -Paths $Paths)
            $remaining = @($remaining | Select-Object -Unique)
        }
        if ($remaining.Count -eq 0) { break }
    } while ([DateTime]::UtcNow -lt $deadline)

    if ($null -ne $Paths -and $remaining.Count -eq 0) {
        foreach ($pidFileName in @('mitm-claude.pid', 'mitm-proxy.pid', 'proxy-relay.pid')) {
            Remove-Item -LiteralPath (Join-Path $Paths.LogsDir $pidFileName) -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{
        collectedPids = @($collected)
        remainingPids = @($remaining)
        error        = $null
    }
}

function Write-AntDidInfo {
    param([psobject]$Info)
    if ($null -eq $Info) {
        Write-Host "  ant-did: NOT FOUND" -ForegroundColor Yellow
        return
    }
    Write-Host "  ant-did: $($Info.path)" -ForegroundColor Gray
    Write-Host ("    length={0}  LastWriteTime={1}" -f $Info.length, $Info.lastWriteTime) -ForegroundColor Gray
    Write-Host "    SHA256=$($Info.sha256)" -ForegroundColor Gray
}

function Invoke-StopAction {
    $name = Resolve-ProfileName -Requested $Profile
    $paths = Get-ProfilePaths -Name $name
    $profileLock = $null
    try {
        $profileLock = Enter-DesktopProfileMutex -ProfileRoot $paths.Root
        if ($null -eq $profileLock) { throw "Profile is busy: $($paths.Root)" }
        if (-not (Test-Path -LiteralPath $paths.Root -PathType Container)) {
            Write-Host "[STOP] profile not found: $name" -ForegroundColor Yellow
            return 0
        }

        $stopped = New-Object 'System.Collections.Generic.List[int]'
        $roots = @()
        try {
            $profileIds = @(Get-ProfileProcessIds -Paths $paths)
            foreach ($candidateId in $profileIds) {
                $root = Get-ClaudeRootIdentity -ProcessId ([int]$candidateId) -Paths $paths
                if ($null -ne $root) { $roots += $root }
            }
        } catch {
            throw "Unable to inspect profile processes: $($_.Exception.Message)"
        }

        foreach ($root in @($roots | Sort-Object Id -Unique)) {
            $result = Stop-ClaudeProcessTree -RootProcessId ([int]$root.Id) -Paths $paths -RootIdentity $root
            foreach ($collectedPid in @($result.collectedPids)) {
                if (-not $stopped.Contains([int]$collectedPid)) { [void]$stopped.Add([int]$collectedPid) }
            }
            if ($result.error) { Write-Host "[STOP] $($result.error)" -ForegroundColor Yellow }
        }

        # Stop detached profile-owned helpers after the authenticated root tree
        # pass. Get-ProfileProcessIds requires a path/profile marker, so this
        # does not fall back to a global `claude.exe` kill.
        Stop-ProfileProcesses -Paths $paths
        Start-Sleep -Milliseconds 250
        $remaining = @(Get-ProfileProcessIds -Paths $paths)
        $cleanupFailed = $false
        $launchStateFile = Join-Path $paths.LogsDir 'desktop-launch.json'
        $launchState = Read-DesktopStateFile -Path $launchStateFile
        if ($null -ne $launchState -and [bool]$launchState.removeCa) {
            $expectedCaPath = [System.IO.Path]::GetFullPath((Join-Path $paths.MitmDir 'mitmproxy-ca-cert.cer'))
            $recordedCaPath = if ($launchState.caPath) { [System.IO.Path]::GetFullPath([string]$launchState.caPath) } else { '' }
            if ([string]::Equals($recordedCaPath, $expectedCaPath, [StringComparison]::OrdinalIgnoreCase)) {
                try {
                    if (-not (Remove-MitmCa -Path $expectedCaPath)) {
                        Write-Host "[STOP] Profile CA removal failed: $expectedCaPath" -ForegroundColor Red
                        $cleanupFailed = $true
                    }
                } catch {
                    Write-Host "[STOP] Profile CA removal failed: $($_.Exception.Message)" -ForegroundColor Red
                    $cleanupFailed = $true
                }
            }
        }
        if ($remaining.Count -eq 0 -and -not $cleanupFailed -and $null -ne $launchState) {
            Write-DesktopStateFile -Path $launchStateFile -State 'stopped' -Generation ([string]$launchState.generation)
        }
        Write-Host ("[STOP] {0} stopped={1} remaining={2}" -f $name, $stopped.Count, $remaining.Count)
        if ($remaining.Count -gt 0) {
            Write-Host ("[STOP] remaining PIDs: {0}" -f ($remaining -join ', ')) -ForegroundColor Red
            return 1
        }
        return [int]$cleanupFailed
    } finally {
        Exit-DesktopProfileMutex $profileLock
    }
}

function Write-JsonNoBom {
    param(
        [string]$Path,
        [object]$Value
    )
    $json = $Value | ConvertTo-Json -Depth 10
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $encoding)
}

function Invoke-CreateAction {
    $name = Resolve-ProfileName -Requested $Profile
    $paths = Get-ProfilePaths -Name $name
    Initialize-ProfileLayout -Paths $paths | Out-Null
    Initialize-ProfileIdentity -Paths $paths | Out-Null
    if ($Fingerprint) {
        Initialize-ProfilePersona -Paths $paths -ExePath $Exe | Out-Null
        Assert-ProfileDeviceImageLock -Paths $paths -InitializeIfMissing | Out-Null
    }
    if (-not $SuppressProxyWarning) { Show-CacProxyCapacityWarning (Get-CacKnownAccountCapacityWarning) }
    Write-Host "[CREATE] $($paths.Name)"
    Write-Host "  root: $($paths.Root)"
    foreach ($relative in $script:LayoutFolders) {
        Write-Host ("  {0}" -f (Join-Path $paths.Root $relative))
    }
    return 0
}

function Invoke-ListAction {
    Write-Host "[LIST] $script:DesktopRoot"
    if (-not (Test-Path -LiteralPath $script:DesktopRoot -PathType Container)) {
        Write-Host "  (no profiles)"
        return 0
    }
    $directories = @(Get-ChildItem -LiteralPath $script:DesktopRoot -Directory -Force -ErrorAction Stop |
        Sort-Object Name)
    if ($directories.Count -eq 0) {
        Write-Host "  (no profiles)"
        return 0
    }
    foreach ($directory in $directories) {
        $paths = Get-ProfilePaths -Name $directory.Name
        $info = Find-AntDid -Paths $paths
        if ($null -eq $info) {
            Write-Host ("  {0}`t-" -f $directory.Name)
        } else {
            Write-Host ("  {0}`tant-did length={1} LastWriteTime={2} SHA256={3}" -f
                $directory.Name, $info.length, $info.lastWriteTime, $info.sha256)
        }
    }
    return 0
}

function Invoke-StatusAction {
    $name = Resolve-ProfileName -Requested $Profile
    $paths = Get-ProfilePaths -Name $name
    $rootExists = Test-Path -LiteralPath $paths.Root -PathType Container
    Write-Host "[STATUS] $($paths.Name)"
    Write-Host "  root: $($paths.Root)"
    Write-Host "  APPDATA: $($paths.AppData)"
    Write-Host "  LOCALAPPDATA: $($paths.LocalAppData)"
    Write-Host "  USERPROFILE/HOME: $($paths.Home)"
    Write-Host "  TEMP/TMP: $($paths.Temp)"
    Write-Host "  userData: $($paths.UserDataDir)"
    Write-Host ("  profile directory: {0}" -f $(if ($rootExists) { 'OK' } else { 'MISSING' }))

    $info = Find-AntDid -Paths $paths
    Write-AntDidInfo -Info $info

    $allProcesses = @(Get-ClaudeProcessRows)
    $desktopProcesses = @(Get-ClaudeDesktopProcesses -ExePath $Exe)
    Write-Host ("  running claude.exe processes: {0} (Desktop: {1})" -f
        $allProcesses.Count, $desktopProcesses.Count)
    return 0
}

function Invoke-LaunchAction {
    $name = Resolve-ProfileName -Requested $Profile
    $paths = Get-ProfilePaths -Name $name
    $launch = Start-ClaudeDesktop -Paths $paths -ExePath $Exe -UseInject ([bool]$Inject) -UseFingerprint ([bool]$Fingerprint)

    if (-not $launch.started) {
        if ($launch.error) { Write-Host "[ERROR] $($launch.error)" -ForegroundColor Red }
        return 1
    }

    Write-Host "[LAUNCH] $($paths.Name)"
    Write-Host "  mode: $($launch.mode)  PID: $($launch.processId)"
    if ($launch.relayPort) { Write-Host "  proxy relay: 127.0.0.1:$($launch.relayPort)  source=$($launch.proxySource)" }
    if ($launch.mitmPort) { Write-Host "  fingerprint MITM: 127.0.0.1:$($launch.mitmPort)" }
    Write-Host "  userData: $($launch.userDataDir)"
    Write-Host "  waiting up to $WaitSeconds seconds for ant-did ..."
    $info = Wait-AntDid -Paths $paths -Seconds $WaitSeconds
    Write-AntDidInfo -Info $info
    if ($null -eq $info) {
        Write-Host "[FAIL] ant-did was not created within the timeout." -ForegroundColor Red
        $stop = Stop-ClaudeProcessTree -RootProcessId $launch.processId -Paths $paths
        if (@($stop.remainingPids).Count -gt 0) {
            Write-Host ("[CLEANUP] Desktop processes remain: {0}" -f (@($stop.remainingPids) -join ', ')) -ForegroundColor Red
        }
        return 1
    }
    Write-Host "[OK] ant-did is ready." -ForegroundColor Green
    return 0
}

function ConvertTo-LaunchEvidence {
    param(
        [psobject]$Launch,
        [psobject]$StopResult
    )
    $stopped = @()
    $remaining = @()
    if ($null -ne $StopResult) {
        $stopped = @($StopResult.collectedPids)
        $remaining = @($StopResult.remainingPids)
    }
    return [ordered]@{
        started        = [bool]$Launch.started
        blocked        = [bool]$Launch.blocked
        error          = $Launch.error
        mode           = $Launch.mode
        pid            = $Launch.processId
        nativeUsed     = [bool]$Launch.nativeUsed
        stoppedPids    = $stopped
        remainingPids  = $remaining
    }
}

function Invoke-AbAction {
    $nameA = 'profile-a'
    $nameB = 'profile-b'
    $pathsA = Get-ProfilePaths -Name $nameA
    $pathsB = Get-ProfilePaths -Name $nameB
    Initialize-ProfileLayout -Paths $pathsA | Out-Null
    Initialize-ProfileLayout -Paths $pathsB | Out-Null
    Remove-ProfileAntDid -Paths $pathsA
    Remove-ProfileAntDid -Paths $pathsB

    $launchA = Start-ClaudeDesktop -Paths $pathsA -ExePath $Exe -UseInject ([bool]$Inject) -UseFingerprint ([bool]$Fingerprint)
    $antA = $null
    $stopA = $null
    if ($launchA.started) {
        Write-Host "[AB] profile-a launched: PID $($launchA.processId), mode $($launchA.mode)"
        $startedA = [DateTime]::UtcNow
        $antA = Wait-AntDid -Paths $pathsA -Seconds $WaitSeconds
        Wait-DesktopRuntimeWindow -StartedUtc $startedA -Seconds $WaitSeconds -ProfileName 'profile-a'
        $stopA = Stop-ClaudeProcessTree -RootProcessId $launchA.processId -Paths $pathsA
        Write-Host ("[AB] profile-a tree stopped: {0}" -f (@($stopA.collectedPids) -join ', '))
    } else {
        Write-Host "[AB] profile-a did not start." -ForegroundColor Red
    }

    $launchB = $null
    $antB = $null
    $stopB = $null
    if ($launchA.started) {
        Initialize-ProfileLayout -Paths $pathsB | Out-Null
        $launchB = Start-ClaudeDesktop -Paths $pathsB -ExePath $Exe -UseInject ([bool]$Inject) -UseFingerprint ([bool]$Fingerprint)
        if ($launchB.started) {
            Write-Host "[AB] profile-b launched: PID $($launchB.processId), mode $($launchB.mode)"
            $startedB = [DateTime]::UtcNow
            $antB = Wait-AntDid -Paths $pathsB -Seconds $WaitSeconds
            Wait-DesktopRuntimeWindow -StartedUtc $startedB -Seconds $WaitSeconds -ProfileName 'profile-b'
            $stopB = Stop-ClaudeProcessTree -RootProcessId $launchB.processId -Paths $pathsB
            Write-Host ("[AB] profile-b tree stopped: {0}" -f (@($stopB.collectedPids) -join ', '))
        } else {
            Write-Host "[AB] profile-b did not start." -ForegroundColor Red
        }
    }

    $bothExist = (($null -ne $antA) -and ($null -ne $antB))
    $pathsDiffer = $false
    $hashesDiffer = $false
    if ($bothExist) {
        $pathsDiffer = -not [string]::Equals([string]$antA.path, [string]$antB.path, [StringComparison]::OrdinalIgnoreCase)
        $hashesDiffer = -not [string]::Equals([string]$antA.sha256, [string]$antB.sha256, [StringComparison]::OrdinalIgnoreCase)
    }
    $stopAClean = ($null -eq $stopA) -or (@($stopA.remainingPids).Count -eq 0)
    $stopBClean = ($null -eq $stopB) -or (@($stopB.remainingPids).Count -eq 0)
    $stateA = Get-ProfileState -Paths $pathsA
    $stateB = Get-ProfileState -Paths $pathsB
    $trackedA = @($stateA.trackedPaths)
    $trackedB = @($stateB.trackedPaths)
    $pathOverlap = @($trackedA | Where-Object { $trackedB -contains $_ })
    $pathBoundaryOk = ($pathOverlap.Count -eq 0 -and
        @($stateA.outsideRootPaths).Count -eq 0 -and
        @($stateB.outsideRootPaths).Count -eq 0)
    $passed = ($bothExist -and $pathsDiffer -and $hashesDiffer -and $pathBoundaryOk)

    $launchAEvidence = $null
    if ($null -ne $launchA) { $launchAEvidence = ConvertTo-LaunchEvidence -Launch $launchA -StopResult $stopA }
    $launchBEvidence = $null
    if ($null -ne $launchB) { $launchBEvidence = ConvertTo-LaunchEvidence -Launch $launchB -StopResult $stopB }

    $evidence = [ordered]@{
        schema       = 1
        checkedUtc   = [DateTime]::UtcNow.ToString('o')
        waitSeconds  = $WaitSeconds
        profiles     = [ordered]@{
            'profile-a' = $pathsA.Root
            'profile-b' = $pathsB.Root
        }
        launches     = [ordered]@{
            'profile-a' = $launchAEvidence
            'profile-b' = $launchBEvidence
        }
        antDid       = [ordered]@{
            'profile-a' = $antA
            'profile-b' = $antB
        }
        state        = [ordered]@{
            'profile-a' = $stateA
            'profile-b' = $stateB
        }
        comparisons  = [ordered]@{
            bothExist    = [bool]$bothExist
            pathsDiffer  = [bool]$pathsDiffer
            hashesDiffer = [bool]$hashesDiffer
            pathBoundaryOk = [bool]$pathBoundaryOk
            pathOverlap = @($pathOverlap)
            stopAClean   = [bool]$stopAClean
            stopBClean   = [bool]$stopBClean
        }
        result       = $(if ($passed -and $stopAClean -and $stopBClean) { 'PASS' } else { 'FAIL' })
        note         = 'Records ant-did metadata and verifies that the sensitive Desktop paths for profile-a/profile-b are disjoint and remain under their own roots. It does not prove kernel or DPAPI isolation.'
    }

    $evidencePath = Join-Path $pathsA.AuditDir 'desktop-ab.json'
    Write-JsonNoBom -Path $evidencePath -Value $evidence

    Write-Host "[AB] ant-did profile-a:"
    Write-AntDidInfo -Info $antA
    Write-Host "[AB] ant-did profile-b:"
    Write-AntDidInfo -Info $antB
    Write-Host ("[AB] bothExist={0} pathsDiffer={1} hashesDiffer={2}" -f
        $bothExist, $pathsDiffer, $hashesDiffer)
    Write-Host ("[AB] pathBoundaryOk={0} overlap={1}" -f $pathBoundaryOk, $pathOverlap.Count)
    Write-Host "  evidence: $evidencePath" -ForegroundColor DarkGray

    Write-Host ("[AB] profile-a userData: exists={0} files={1} bytes={2}" -f
        $stateA.userData.exists, $stateA.userData.files, $stateA.userData.bytes)
    Write-Host ("[AB] profile-b userData: exists={0} files={1} bytes={2}" -f
        $stateB.userData.exists, $stateB.userData.files, $stateB.userData.bytes)
    Write-Host ("[AB] stopA={0} stopB={1}" -f $stopAClean, $stopBClean)
    if ($passed -and $stopAClean -and $stopBClean) {
        Write-Host "[PASS] Desktop A/B profile isolation check." -ForegroundColor Green
        return 0
    }
    Write-Host "[FAIL] Desktop A/B profile isolation check." -ForegroundColor Red
    return 1
}

function Invoke-CleanupAction {
    $name = Resolve-ProfileName -Requested $Profile
    $paths = Get-ProfilePaths -Name $name
    $profileLock = $null
    try {
        $profileLock = Enter-DesktopProfileMutex -ProfileRoot $paths.Root
        if ($null -eq $profileLock) { throw "Profile is busy: $($paths.Root)" }
        if (-not (Test-Path -LiteralPath $paths.Root -PathType Container)) {
            Write-Host "[CLEANUP] not found: $($paths.Root)" -ForegroundColor Yellow
            return 1
        }

        $baseFull = [System.IO.Path]::GetFullPath($script:DesktopRoot).TrimEnd('\')
        $resolved = (Resolve-Path -LiteralPath $paths.Root -ErrorAction Stop).ProviderPath
        $resolvedFull = [System.IO.Path]::GetFullPath($resolved).TrimEnd('\')
        $basePrefix = $baseFull + '\'
        if (-not $resolvedFull.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing cleanup outside the profile root: $resolvedFull"
        }
        $relative = $resolvedFull.Substring($basePrefix.Length)
        if (-not [string]::Equals($relative, $name, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing cleanup: resolved path does not match the requested profile: $resolvedFull"
        }

        $item = Get-Item -LiteralPath $resolvedFull -Force -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing cleanup of a reparse-point profile directory: $resolvedFull"
        }
        Assert-DesktopNoReparsePoints -Path $resolvedFull

        $liveProcesses = @(Get-ProfileProcessIds -Paths $paths)
        if ($liveProcesses.Count -gt 0) {
            Write-Host ("[CLEANUP] refused: profile processes are still running: {0}" -f ($liveProcesses -join ', ')) -ForegroundColor Yellow
            return 1
        }

        $caPath = Join-Path $paths.MitmDir 'mitmproxy-ca-cert.cer'
        if (Test-Path -LiteralPath $caPath -PathType Leaf) {
            if (-not (Remove-MitmCa -Path $caPath)) {
                throw "Profile mitmproxy CA removal failed: $caPath"
            }
        }

        $files = @(Get-ChildItem -LiteralPath $resolvedFull -Recurse -Force -File -ErrorAction SilentlyContinue)
        $bytes = 0
        foreach ($file in $files) { $bytes += [long]$file.Length }

        # Re-scan immediately before deletion to close the check/delete race.
        $liveProcesses = @(Get-ProfileProcessIds -Paths $paths)
        if ($liveProcesses.Count -gt 0) {
            Write-Host ("[CLEANUP] refused: profile processes appeared during cleanup: {0}" -f ($liveProcesses -join ', ')) -ForegroundColor Yellow
            return 1
        }
        Assert-DesktopNoReparsePoints -Path $resolvedFull

        Write-Host "[CLEANUP] removing: $resolvedFull"
        Remove-Item -LiteralPath $resolvedFull -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $resolvedFull) {
            throw "Cleanup did not remove the profile: $resolvedFull"
        }
        Write-Host ("[CLEANUP] removed: {0} (files={1}, bytes={2})" -f $resolvedFull, $files.Count, $bytes) -ForegroundColor Green
        return 0
    } finally {
        Exit-DesktopProfileMutex $profileLock
    }
}

function Invoke-RemoveCaAction {
    if ([string]::IsNullOrWhiteSpace($Profile) -or -not (Test-ProfileName $Profile)) {
        throw "remove-ca requires a valid -Profile name; global mitmproxy certificate removal is disabled"
    }
    $paths = Get-ProfilePaths -Name $Profile
    $profileLock = $null
    try {
        $profileLock = Enter-DesktopProfileMutex -ProfileRoot $paths.Root
        if ($null -eq $profileLock) { throw "Profile is busy: $($paths.Root)" }
        if (-not (Test-Path -LiteralPath $paths.Root -PathType Container)) {
            throw "Refusing mitmproxy CA removal: profile does not exist: $($paths.Name)"
        }
        Assert-DesktopNoReparsePoints -Path $paths.Root
        $caPath = Join-Path $paths.MitmDir 'mitmproxy-ca-cert.cer'
        if (Remove-MitmCa -Path $caPath) {
            Write-Host "[CA] Profile mitmproxy root certificate removed: $caPath" -ForegroundColor Green
            return 0
        }
        Write-Host "[CA] mitmproxy root certificate is still present" -ForegroundColor Red
        return 1
    } finally {
        Exit-DesktopProfileMutex $profileLock
    }
}

$exitCode = 0
try {
    switch ($Action) {
        'create'  { $exitCode = Invoke-CreateAction }
        'list'    { $exitCode = Invoke-ListAction }
        'status'  { $exitCode = Invoke-StatusAction }
        'stop'    { $exitCode = Invoke-StopAction }
        'launch'  { $exitCode = Invoke-LaunchAction }
        'ab'      { $exitCode = Invoke-AbAction }
        'cleanup' { $exitCode = Invoke-CleanupAction }
        'remove-ca' { $exitCode = Invoke-RemoveCaAction }
        'monitor' { $exitCode = Invoke-DesktopMonitorAction }
    }
} catch {
    $errorText = [string]$_.Exception.Message
    $invocation = $_.InvocationInfo
    if ($null -ne $invocation -and $invocation.ScriptLineNumber -gt 0) {
        $lineText = ([string]$invocation.Line).Trim()
        if ($lineText.Length -gt 240) { $lineText = $lineText.Substring(0, 240) }
        if (-not [string]::IsNullOrWhiteSpace($lineText)) {
            $errorText = "{0} [desktop-profile.ps1:{1}] {2}" -f $errorText, $invocation.ScriptLineNumber, $lineText
        } else {
            $errorText = "{0} [desktop-profile.ps1:{1}]" -f $errorText, $invocation.ScriptLineNumber
        }
    }
    Write-Host "[ERROR] $errorText" -ForegroundColor Red
    $exitCode = 1
}
exit $exitCode
