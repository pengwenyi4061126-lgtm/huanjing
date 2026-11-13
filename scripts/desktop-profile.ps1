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
    [ValidateSet('create','list','launch','status','ab','cleanup','remove-ca')][string]$Action = 'status',
    [string]$Profile,
    [string]$Exe = 'C:\Program Files\WindowsApps\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\app\claude.exe',
    [switch]$Inject,
    [switch]$Fingerprint,
    [int]$WaitSeconds = 30
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'cert-silent.ps1')

$script:OriginalUserProfile = $env:USERPROFILE
$script:DesktopRoot = [System.IO.Path]::GetFullPath((Join-Path $script:OriginalUserProfile '.cac\desktop'))
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
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $Value = $Value.Trim()
    if ($Value -notmatch '^[a-z][a-z0-9+.-]*://') { return 'http://' + $Value }
    return $Value
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

function Initialize-ProfilePersona {
    param([psobject]$Paths)
    New-Item -ItemType Directory -Path $Paths.Root -Force | Out-Null
    $path = Join-Path $Paths.Root 'fingerprint.json'
    if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }

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

    $persona = [ordered]@{
        schema              = 1
        seed                = "$($Paths.Name)|$([string]$identity.machine_id)"
        timezone            = Get-IanaTimeZone
        locale              = $locale
        languages           = @($languages)
        platform            = 'Win32'
        maxTouchPoints      = 0
        uaMobile            = $false
        uaPlatform          = 'Windows'
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
    return $Paths
}

function Sync-NativeLayer {
    $source = Join-Path (Split-Path $PSScriptRoot -Parent) 'native\dist'
    $target = Join-Path $script:OriginalUserProfile '.cac\native'
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { return }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    foreach ($name in @('NativeBridge.dll', 'cac-native-launch.exe', 'NativeBridge.sha256')) {
        $from = Join-Path $source $name
        if (-not (Test-Path -LiteralPath $from -PathType Leaf)) { continue }
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
                Id   = [int]$row.ProcessId
                Name = [string]$row.Name
                Path = $processPath
            }
        }
    } catch {
        try {
            foreach ($process in @(Get-Process -Name 'claude' -ErrorAction Stop)) {
                $processPath = $null
                try { $processPath = [string]$process.Path } catch { $processPath = $null }
                $result += [pscustomobject]@{
                    Id   = [int]$process.Id
                    Name = [string]$process.ProcessName
                    Path = $processPath
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

function ConvertTo-ProcessArgument {
    param([string]$Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('"', '\"') + '"'
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
    $personaPath = $null

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

    if ($UseFingerprint) {
        $mitm = (Get-Command mitmdump -ErrorAction SilentlyContinue).Source
        if (-not $mitm) {
            $candidate = 'D:\zhibo\runtime\py312\python\Scripts\mitmdump.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $mitm = $candidate }
        }
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
        $personaPath = Initialize-ProfilePersona -Paths $Paths
        $mitmPort = Get-FreeTcpPort
        $mitmPidFile = Join-Path $Paths.LogsDir 'mitm-claude.pid'
        Remove-Item -LiteralPath $mitmPidFile -Force -ErrorAction SilentlyContinue
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
        $mitmProcess = Start-Process -FilePath $mitm `
            -ArgumentList @('-q', '-s', $addon, '--listen-port', "$mitmPort",
                '--set', "confdir=$($Paths.MitmDir)") `
                -PassThru -WindowStyle Hidden
        } finally {
            foreach ($name in $saved.Keys) {
                [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
            }
        }
        $deadline = (Get-Date).AddSeconds(10)
        do {
            try {
                $client = [System.Net.Sockets.TcpClient]::new()
                $client.Connect('127.0.0.1', $mitmPort)
                $client.Close()
                break
            } catch {
                Start-Sleep -Milliseconds 200
            }
        } while ((Get-Date) -lt $deadline)
        $ca = Join-Path $Paths.MitmDir 'mitmproxy-ca-cert.cer'
        if (Test-Path -LiteralPath $ca -PathType Leaf) {
            [void](Install-MitmCa -Path $ca)
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
        if ($mitmProcess) { Stop-Process -Id $mitmProcess.Id -Force -ErrorAction SilentlyContinue }
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
        if ($mitmProcess) { Stop-Process -Id $mitmProcess.Id -Force -ErrorAction SilentlyContinue }
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

    Initialize-ProfileLayout -Paths $Paths -ForLaunch | Out-Null
    $identity = Initialize-ProfileIdentity -Paths $Paths

    $fingerprintPort = $null
    $fingerprintArgs = @()
    if ($UseFingerprint -and $mitmPort -and $personaPath) {
        $persona = Get-Content -LiteralPath $personaPath -Raw | ConvertFrom-Json
        $fingerprintArgs += "--proxy-server=http://127.0.0.1:$mitmPort"
        $fingerprintArgs += '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'
        if ($persona.locale) { $fingerprintArgs += "--lang=$($persona.locale)" }
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
            Write-Host "[WARN] Native launcher or NativeBridge.dll is missing; launching directly." -ForegroundColor Yellow
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
    if ($UseFingerprint) { $mode += '+fingerprint' }

    $environment = [ordered]@{
        APPDATA              = $Paths.AppData
        LOCALAPPDATA         = $Paths.LocalAppData
        USERPROFILE          = $Paths.Home
        HOME                 = $Paths.Home
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
        if ($configured -in @('profile', 'clean')) { $networkMode = $configured }
    }
    if ($environment['CAC_NATIVE_READ_POLICY'] -eq 'empty') { $networkMode = 'clean' }
    $environment['CAC_NETWORK_MODE'] = $networkMode
    $manifest = Join-Path $nativeDir 'native-hook-manifest.txt'
    if (Test-Path -LiteralPath $manifest -PathType Leaf) { $environment['CAC_NATIVE_MANIFEST'] = $manifest }
    if ($nativeUsed) { $environment['CAC_NATIVE_DLL'] = $nativeDll }

    $saved = @{}
    foreach ($name in $environment.Keys) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }

    $startedProcess = $null
    $startError = $null
    try {
        foreach ($name in $environment.Keys) {
            [Environment]::SetEnvironmentVariable($name, [string]$environment[$name], 'Process')
        }
        $startedProcess = Start-Process -FilePath $launchFile -ArgumentList $arguments -PassThru -ErrorAction Stop
    } catch {
        $startError = $_.Exception.Message
    } finally {
        foreach ($name in $saved.Keys) {
            [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
        }
    }

    $processId = $null
    if ($null -ne $startedProcess) { $processId = [int]$startedProcess.Id }

    if ($UseFingerprint -and $processId -and $mitmPidFile) {
        Set-Content -LiteralPath $mitmPidFile -Value "$processId" -Encoding ASCII
    }
    if ($UseFingerprint -and -not $processId -and $mitmProcess) {
        Stop-Process -Id $mitmProcess.Id -Force -ErrorAction SilentlyContinue
    }

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
    }
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
            return @()
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

function Stop-ClaudeProcessTree {
    param([int]$RootProcessId)
    # Collect the tree before stopping anything, then stop children first.
    $ids = @(Get-ProcessTreeIds -RootProcessId $RootProcessId)
    for ($index = $ids.Count - 1; $index -ge 0; $index--) {
        $targetId = [int]$ids[$index]
        if ($targetId -eq $PID) { continue }
        try {
            Stop-Process -Id $targetId -Force -ErrorAction Stop
        } catch {
            # The process may have already exited.
        }
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    $remaining = @()
    while ($true) {
        $remaining = @()
        foreach ($targetId in $ids) {
            if (Get-Process -Id $targetId -ErrorAction SilentlyContinue) {
                $remaining += [int]$targetId
            }
        }
        if ($remaining.Count -eq 0 -or [DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 200
    }

    return [pscustomobject]@{
        collectedPids = @($ids)
        remainingPids = @($remaining)
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
    if ($launch.mitmPort) { Write-Host "  fingerprint MITM: 127.0.0.1:$($launch.mitmPort)" }
    Write-Host "  userData: $($launch.userDataDir)"
    Write-Host "  waiting up to $WaitSeconds seconds for ant-did ..."
    $info = Wait-AntDid -Paths $paths -Seconds $WaitSeconds
    Write-AntDidInfo -Info $info
    if ($null -eq $info) {
        Write-Host "[FAIL] ant-did was not created within the timeout." -ForegroundColor Red
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
        $stopA = Stop-ClaudeProcessTree -RootProcessId $launchA.processId
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
            $stopB = Stop-ClaudeProcessTree -RootProcessId $launchB.processId
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

    $files = @(Get-ChildItem -LiteralPath $resolvedFull -Recurse -Force -File -ErrorAction SilentlyContinue)
    $bytes = 0
    foreach ($file in $files) { $bytes += [long]$file.Length }

    Write-Host "[CLEANUP] removing: $resolvedFull"
    Remove-Item -LiteralPath $resolvedFull -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $resolvedFull) {
        throw "Cleanup did not remove the profile: $resolvedFull"
    }
    Write-Host ("[CLEANUP] removed: {0} (files={1}, bytes={2})" -f $resolvedFull, $files.Count, $bytes) -ForegroundColor Green
    return 0
}

function Invoke-RemoveCaAction {
    $caPath = $null
    if ($Profile -and (Test-ProfileName $Profile)) {
        $caPath = Join-Path (Get-ProfilePaths -Name $Profile).MitmDir 'mitmproxy-ca-cert.cer'
    }
    if (Remove-MitmCa -Path $caPath) {
        if ($caPath) {
            Write-Host "[CA] Profile mitmproxy root certificate removed: $caPath" -ForegroundColor Green
        } else {
            Write-Host "[CA] mitmproxy root certificates removed" -ForegroundColor Green
        }
        return 0
    }
    Write-Host "[CA] mitmproxy root certificate is still present" -ForegroundColor Red
    return 1
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
    }
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
exit $exitCode
