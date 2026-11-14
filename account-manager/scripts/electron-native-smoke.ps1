[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$managerRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Split-Path -Parent $managerRoot
$nativeRoot = Join-Path $projectRoot 'native\dist'
$launcher = Join-Path $nativeRoot 'cac-native-launch.exe'
$bridge = Join-Path $nativeRoot 'NativeBridge.dll'
$electron = Join-Path $managerRoot 'node_modules\electron\dist\electron.exe'
$probe = Join-Path $PSScriptRoot 'electron-native-smoke.js'

foreach ($path in @($launcher, $bridge, $electron, $probe)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Electron Native smoke input is missing: $path"
    }
}

$root = Join-Path $env:TEMP ('cac-electron-native-' + [guid]::NewGuid().ToString('N'))
$auditDir = Join-Path $root 'audit'
$identityPath = Join-Path $root 'identity.json'
$auditPath = Join-Path $auditDir 'native-hook.jsonl'
New-Item -ItemType Directory -Path $auditDir -Force | Out-Null

$identity = [ordered]@{
    schema = 1
    name = 'electron-native-smoke'
    uuid = '11111111-2222-3333-4444-555555555555'
    stable_id = 'electron-native-smoke'
    user_id = 'electron-native-smoke'
    machine_id = '0123456789abcdef0123456789abcdef'
    hostname = 'electron-smoke'
    mac_address = '02:AA:BB:CC:DD:EE'
    disk_serial = 'WD-ELECTRON01'
    bios_serial = 'PF-ELECTRON'
    board_serial = 'MB-ELECTRON'
    system_serial = 'SYS-ELECTRON'
    system_uuid = '11111111222233334444555555555555'
    processor_id = 'ABCDEF0123456789'
    hid_serial = 'HID-ELECTRON'
    volume_serial = 'A1B2C3D4'
    username = 'electron-user'
}
$identity | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $identityPath -Encoding UTF8

$previous = @{}
$variables = [ordered]@{
    CAC_PROFILE_DIR = $root
    CAC_PROFILE_IDENTITY = $identityPath
    CAC_NATIVE_DLL = $bridge
    CAC_NATIVE_AUDIT = $auditPath
    CAC_NATIVE_READ_POLICY = 'profile'
    CAC_NATIVE_CPUID_MODE = 'neutral'
    CAC_NATIVE_DISABLE_NETWORK_HOOKS = '1'
    CAC_NETWORK_ENFORCE = '0'
    CAC_WFP_REQUIRED = '0'
    CAC_KERNEL_POLICY_REQUIRED = '0'
}

try {
    foreach ($entry in $variables.GetEnumerator()) {
        $previous[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
    }
    & $launcher $electron $probe
    if ($LASTEXITCODE -ne 0) {
        throw "Electron Native launcher exited with $LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
        throw 'Electron Native audit log was not created'
    }

    $events = @(Get-Content -LiteralPath $auditPath | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { $null }
    } | Where-Object { $null -ne $_ })
    $attach = @($events | Where-Object { $_.surface -eq 'native.bridge' -and $_.action -eq 'attach' })
    $readyPids = @($events | Where-Object { $_.surface -eq 'native.bridge' -and $_.action -eq 'ready' } |
        ForEach-Object { [int]$_.pid } | Select-Object -Unique)
    $failed = @($events | Where-Object { $_.action -eq 'failed' })
    $injected = @($events | Where-Object { $_.surface -eq 'native.child' -and $_.action -eq 'injected' })
    $types = @($attach | ForEach-Object { [string]$_.detail })

    if ($failed.Count -ne 0) { throw "Electron Native failures were recorded: $($failed.Count)" }
    if ($attach.Count -lt 2) { throw "Electron Native attach coverage is too small: $($attach.Count)" }
    if ($injected.Count -eq 0) { throw 'Electron renderer/utility child injection was not recorded' }
    foreach ($event in $attach) {
        if ([int]$event.pid -notin $readyPids) {
            throw "Electron Native process did not become ready: PID $($event.pid) $($event.detail)"
        }
    }
    if (-not ($types -contains 'process=main')) { throw 'Electron main process was not injected' }
    if (-not ($types -contains 'process=renderer')) { throw 'Electron renderer process was not injected' }
    if (-not ($types -contains 'process=utility')) { throw 'Electron utility process was not injected' }

    [pscustomobject]@{
        status = 'PASS'
        attached = $attach.Count
        childInjected = $injected.Count
        processTypes = @($types | Select-Object -Unique)
        audit = $auditPath
    } | ConvertTo-Json -Depth 4
} finally {
    foreach ($entry in $variables.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $previous[$entry.Key], 'Process')
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
