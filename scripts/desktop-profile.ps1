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
    [ValidateSet('create','list','launch','status','ab','cleanup','remove-ca','monitor')][string]$Action = 'status',
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
    [switch]$RemoveCaAfterExit
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
    param([string]$ExePath)

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

    $configuredChromium = [Environment]::GetEnvironmentVariable('CAC_CHROMIUM_VERSION', 'Process')
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
    $browser = Get-ChromiumPersonaVersion -ExePath $ExePath
    $existingPersona = $null
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        try {
            $existingPersona = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($existingPersona.ua -and $existingPersona.uaBrands -and
                [string]$existingPersona.uaChromiumVersion -eq $browser.chromiumVersion) {
                return $path
            }
        } catch {
            $existingPersona = $null
        }
    }

    $identity = Initialize-ProfileIdentity -Paths $Paths
    $locale = (Get-Culture).Name
    if ([string]::IsNullOrWhiteSpace($locale)) { $locale = 'en-US' }
    $languages = @($locale, 'en-US') | Select-Object -Unique

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

    if ($null -ne $existingPersona) {
        $persona = $existingPersona
        $updates = [ordered]@{
            ua                = $ua
            uaBrands          = @($uaBrands)
            uaMobile          = $false
            uaPlatform        = 'Windows'
            uaHighEntropy     = $uaHighEntropy
            uaElectronVersion = $browser.electronVersion
            uaChromiumVersion = $browser.chromiumVersion
        }
        foreach ($entry in $updates.GetEnumerator()) {
            $persona | Add-Member -MemberType NoteProperty -Name $entry.Key -Value $entry.Value -Force
        }
    } else {
        $persona = [ordered]@{
            schema              = 1
            seed                = "$($Paths.Name)|$([string]$identity.machine_id)"
            timezone            = Get-IanaTimeZone
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
        }
    }
    $json = $persona | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($path, $json + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
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
        Temp             = (Join-Path $root 'temp')
        ClaudeDir        = (Join-Path $root 'Claude')
        Claude3pDir      = (Join-Path $root 'Claude-3p')
        MitmDir          = (Join-Path $root 'mitmproxy')
        AuditDir         = (Join-Path $root 'audit')
        LogsDir          = (Join-Path $root 'logs')
        UserDataDir      = (Join-Path $root 'home\AppData\Roaming\Claude')
        IdentityPath     = (Join-Path $root 'identity.json')
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
        [string]$ErrorText
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
        error       = $ErrorText
        updatedUtc  = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Read-DesktopStateFile {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { return $null }
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
    if (Test-Path -LiteralPath $Paths.IdentityPath -PathType Leaf) {
        try {
            $existing = Get-Content -LiteralPath $Paths.IdentityPath -Raw | ConvertFrom-Json
            if ($null -ne $existing -and -not [string]::IsNullOrWhiteSpace([string]$existing.machine_id)) {
                return $existing
            }
        } catch { }
    }

    $machineId = [guid]::NewGuid().ToString('N')
    $uuid = [guid]::NewGuid().ToString().ToUpperInvariant()
    $macBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($machineId + '|mac'))
    $mac = '02:' + (($macBytes[0..4] | ForEach-Object { $_.ToString('x2') }) -join ':')
    $identity = [ordered]@{
        schema        = 1
        name          = $Paths.Name
        uuid          = $uuid
        stable_id     = [guid]::NewGuid().ToString().ToLowerInvariant()
        user_id       = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
        machine_id    = $machineId
        hostname      = 'host-' + $machineId.Substring(0, 8)
        mac_address   = $mac
        system_uuid   = ($uuid -replace '-', '').ToUpperInvariant()
        disk_serial   = 'WD-' + (Get-DerivedHex ($machineId + '|disk') 12)
        bios_serial   = 'PF' + (Get-DerivedHex ($machineId + '|bios') 10)
        board_serial  = 'MB' + (Get-DerivedHex ($machineId + '|board') 10)
        system_serial = 'SYS' + (Get-DerivedHex ($machineId + '|system') 10)
        processor_id  = (Get-DerivedHex ($machineId + '|cpu') 16).ToUpperInvariant()
        volume_serial = (Get-DerivedHex ($machineId + '|volume') 8).ToUpperInvariant()
        hid_serial    = 'HID' + (Get-DerivedHex ($machineId + '|hid') 10).ToUpperInvariant()
        username      = 'user-' + $Paths.Name
    }
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Paths.IdentityPath, ($identity | ConvertTo-Json -Depth 5), $encoding)
    return [pscustomobject]$identity
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
        if ($null -ne $LauncherProcess -and $LauncherProcess.HasExited -and $LauncherProcess.ExitCode -ne 0) {
            throw "Claude Desktop launcher exited with code $($LauncherProcess.ExitCode)"
        }
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
        try {
            $stop = Stop-ClaudeProcessTree -RootProcessId $rootProcessId -Paths $Paths -RootIdentity $RootIdentity
            if ($stop.error) { [void]$errors.Add([string]$stop.error) }
            if (@($stop.remainingPids).Count -gt 0) { [void]$errors.Add("Desktop processes remain: $(@($stop.remainingPids) -join ',')") }
        } catch { [void]$errors.Add("Desktop stop failed: $($_.Exception.Message)") }
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
        try {
            if (-not (Remove-MitmCa -Path $CaPath)) { [void]$errors.Add("Profile CA remains: $CaPath") }
        } catch { [void]$errors.Add("Profile CA rollback failed: $($_.Exception.Message)") }
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
        [string]$MonitorReadyFile
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
    $rootIdentityValid = ($WatchPid -gt 0 -and
        -not [string]::IsNullOrWhiteSpace($WatchPath) -and
        -not [string]::IsNullOrWhiteSpace($WatchStartUtc))
    try {
        try { $paths = Get-ProfilePaths -Name (Resolve-ProfileName -Requested $Profile) } catch {
            [void]$errors.Add("Desktop monitor profile resolution failed: $($_.Exception.Message)")
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
                    Start-Sleep -Milliseconds 500
                    $state = Get-TrackedProcessState -ProcessId $WatchPid -ExpectedPath $WatchPath -ExpectedStartUtc $WatchStartUtc
                }
                if ($state -eq 'exited') {
                    $allowCleanup = $true
                } elseif ($state -eq 'reused') {
                    [void]$errors.Add("Desktop root PID $WatchPid was reused; cleanup refused")
                } else {
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
                            Write-DesktopStateFile -Path $LaunchStateFile -State 'stopped' -Generation $LaunchGeneration `
                                -RootPid $WatchPid -RootPath $WatchPath -RootStartUtc $WatchStartUtc
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
    $launcherProcess = $null
    $resourceTransferred = $false
    $monitorPid = $null
    $launchGeneration = $null
    $launchStateFile = $null
    $monitorReadyFile = $null
    $result = $null
    $profileLock = $null

    try {
    $profileLock = Enter-DesktopProfileMutex -ProfileRoot $Paths.Root
    if ($null -eq $profileLock) { throw "Profile is busy: $($Paths.Root)" }
    Assert-DesktopNoReparsePoints -Path $Paths.Root
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
        $personaPath = Initialize-ProfilePersona -Paths $Paths -ExePath $ExePath
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
        $mitmProcess = Start-Process -FilePath $mitm `
            -ArgumentList $mitmArguments `
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
        $caThumbprint = if (Test-Path -LiteralPath $caPath -PathType Leaf) {
            Get-CertificateThumbprintFromFile -Path $caPath
        } else { $null }
        $caWasPresent = ($null -ne $caThumbprint -and @(Get-MitmCa | Where-Object {
            $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $caThumbprint
        }).Count -gt 0)
        if (Test-Path -LiteralPath $caPath -PathType Leaf) {
            try {
                $caInstalled = [bool](Install-MitmCa -Path $caPath)
                $caInstalledByLaunch = $caInstalled -and -not $caWasPresent
            } catch {
                $caInstalled = $false
            }
        }
        if (-not $caInstalled) {
            return [pscustomobject]@{
                started = $false; blocked = $true
                error = "MITM CA installation failed for profile $($Paths.Name): $caPath"
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
    if ($UseFingerprint -and $mitmPort -and $personaPath) {
        $persona = Get-Content -LiteralPath $personaPath -Raw | ConvertFrom-Json
        $fingerprintArgs += "--proxy-server=http://127.0.0.1:$mitmPort"
        $fingerprintArgs += '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'
        if ($persona.locale) { $fingerprintArgs += "--lang=$($persona.locale)" }
    } elseif ($null -ne $relay) {
        $fingerprintArgs += "--proxy-server=$($relay.url)"
    }
    if ($null -ne $relay) {
        $fingerprintArgs += '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1, EXCLUDE ::1'
        $fingerprintArgs += '--disable-quic'
        $fingerprintArgs += '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'
        $fingerprintArgs += '--proxy-bypass-list=localhost;127.0.0.1;[::1]'
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
        HTTP_PROXY           = if ($null -ne $relay) { [string]$relay.url } else { '' }
        HTTPS_PROXY          = if ($null -ne $relay) { [string]$relay.url } else { '' }
        ALL_PROXY            = if ($null -ne $relay) { [string]$relay.url } else { '' }
        NO_PROXY             = 'localhost,127.0.0.1,::1'
        CAC_HTTP_PROXY_LOCAL = if ($null -ne $relay) { [string]$relay.url } else { '' }
        CAC_PROXY_ID         = if ($null -ne $proxyBinding) { [string]$proxyBinding.proxyId } else { '' }
        CAC_PROXY_SOURCE     = if ($null -ne $proxyBinding) { [string]$proxyBinding.source } else { '' }
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
    try {
        foreach ($name in $environment.Keys) {
            [Environment]::SetEnvironmentVariable($name, [string]$environment[$name], 'Process')
        }
            $launcherProcess = Start-Process -FilePath $launchFile -ArgumentList $arguments -PassThru -ErrorAction Stop
            $startedProcess = $launcherProcess
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
    $desktopStartUtc = $desktopProcess.StartTime.ToUniversalTime().ToString('o')
    Write-DesktopStateFile -Path $launchStateFile -State 'active' -Generation $launchGeneration `
        -RootPid $processId -RootPath ([string]$desktopProcess.Path) -RootStartUtc $desktopStartUtc

    if ($UseFingerprint -and $processId -and $mitmPidFile) {
        Set-Content -LiteralPath $mitmPidFile -Value "$processId" -Encoding ASCII
    }
    # Always keep a lifecycle monitor so direct launches also clean detached
    # renderer/utility processes after the Desktop root exits.
    $monitorPid = Start-DesktopLifecycleMonitor -Paths $Paths -DesktopPid $processId `
        -Relay $relay -MitmProcess $mitmProcess -MitmPidFile $mitmPidFile `
        -MitmProcessPidFile $mitmProcessPidFile -RemoveCa $caInstalledByLaunch -CaPath $caPath `
        -LaunchStateFile $launchStateFile -LaunchGeneration $launchGeneration -MonitorReadyFile $monitorReadyFile
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
        $result = [pscustomobject]@{
            started         = $false
            blocked         = $true
            error           = $_.Exception.Message
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
                -MitmProcess $mitmProcess -Relay $relay `
                -PidFiles @($relayPidFile, $mitmPidFile, $mitmProcessPidFile) `
                -CaPath $caPath -RemoveCa $caInstalledByLaunch)
            foreach ($errorText in $cleanupErrors) {
                Write-Host "[CLEANUP] $errorText" -ForegroundColor Red
            }
            if ($null -ne $result) { $result.cleanupErrors = @($cleanupErrors) }
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
        'node.exe'
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
    Show-CacProxyCapacityWarning (Get-CacKnownAccountCapacityWarning)
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
        'launch'  { $exitCode = Invoke-LaunchAction }
        'ab'      { $exitCode = Invoke-AbAction }
        'cleanup' { $exitCode = Invoke-CleanupAction }
        'remove-ca' { $exitCode = Invoke-RemoveCaAction }
        'monitor' { $exitCode = Invoke-DesktopMonitorAction }
    }
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
exit $exitCode
