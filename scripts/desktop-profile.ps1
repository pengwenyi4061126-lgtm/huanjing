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
    [ValidateSet('create','list','launch','status','ab','cleanup')][string]$Action = 'status',
    [string]$Profile,
    [string]$Exe = 'C:\Program Files\WindowsApps\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\app\claude.exe',
    [switch]$Inject,
    [int]$WaitSeconds = 30
)

$ErrorActionPreference = 'Stop'

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
    return [ordered]@{
        userData        = Get-PathSummary $userData
        claude3pLocal   = Get-PathSummary (Join-Path $Paths.LocalAppData 'Claude-3p')
        claude3pRoaming = Get-PathSummary (Join-Path $Paths.AppData 'Claude-3p')
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
        [bool]$UseInject
    )

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

    Initialize-ProfileLayout -Paths $Paths -ForLaunch | Out-Null
    $identity = Initialize-ProfileIdentity -Paths $Paths

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
    if ($nativeUsed) {
        $launchFile = $nativeLauncher
        # Unsigned DLL injection into Chromium renderer/GPU processes is blocked
        # once ACG/CIG is active. Native mode deliberately starts Claude without
        # the renderer sandbox so every child can be intercepted before it reads
        # device identity. Direct (non-Native) mode keeps the stock sandbox.
        $arguments = (ConvertTo-ProcessArgument -Value $ExePath) + ' ' + $userDataArgument +
                     ' --no-sandbox --disable-gpu-sandbox'
        $mode = 'native'
    } else {
        $launchFile = $ExePath
        $arguments = $userDataArgument
        $mode = 'direct'
    }

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
    $launch = Start-ClaudeDesktop -Paths $paths -ExePath $Exe -UseInject ([bool]$Inject)

    if (-not $launch.started) {
        if ($launch.error) { Write-Host "[ERROR] $($launch.error)" -ForegroundColor Red }
        return 1
    }

    Write-Host "[LAUNCH] $($paths.Name)"
    Write-Host "  mode: $($launch.mode)  PID: $($launch.processId)"
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

    $launchA = Start-ClaudeDesktop -Paths $pathsA -ExePath $Exe -UseInject ([bool]$Inject)
    $antA = $null
    $stopA = $null
    if ($launchA.started) {
        Write-Host "[AB] profile-a launched: PID $($launchA.processId), mode $($launchA.mode)"
        $antA = Wait-AntDid -Paths $pathsA -Seconds $WaitSeconds
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
        $launchB = Start-ClaudeDesktop -Paths $pathsB -ExePath $Exe -UseInject ([bool]$Inject)
        if ($launchB.started) {
            Write-Host "[AB] profile-b launched: PID $($launchB.processId), mode $($launchB.mode)"
            $antB = Wait-AntDid -Paths $pathsB -Seconds $WaitSeconds
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
    $passed = ($bothExist -and $pathsDiffer -and $hashesDiffer)

    $stopAClean = ($null -eq $stopA) -or (@($stopA.remainingPids).Count -eq 0)
    $stopBClean = ($null -eq $stopB) -or (@($stopB.remainingPids).Count -eq 0)
    $stateA = Get-ProfileState -Paths $pathsA
    $stateB = Get-ProfileState -Paths $pathsB

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
            stopAClean   = [bool]$stopAClean
            stopBClean   = [bool]$stopBClean
        }
        result       = $(if ($passed -and $stopAClean -and $stopBClean) { 'PASS' } else { 'FAIL' })
        note         = 'Only ant-did metadata (path, length, LastWriteTime, SHA-256) is recorded; file contents are never printed.'
    }

    $evidencePath = Join-Path $pathsA.AuditDir 'desktop-ab.json'
    Write-JsonNoBom -Path $evidencePath -Value $evidence

    Write-Host "[AB] ant-did profile-a:"
    Write-AntDidInfo -Info $antA
    Write-Host "[AB] ant-did profile-b:"
    Write-AntDidInfo -Info $antB
    Write-Host ("[AB] bothExist={0} pathsDiffer={1} hashesDiffer={2}" -f
        $bothExist, $pathsDiffer, $hashesDiffer)
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

$exitCode = 0
try {
    switch ($Action) {
        'create'  { $exitCode = Invoke-CreateAction }
        'list'    { $exitCode = Invoke-ListAction }
        'status'  { $exitCode = Invoke-StatusAction }
        'launch'  { $exitCode = Invoke-LaunchAction }
        'ab'      { $exitCode = Invoke-AbAction }
        'cleanup' { $exitCode = Invoke-CleanupAction }
    }
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
exit $exitCode
