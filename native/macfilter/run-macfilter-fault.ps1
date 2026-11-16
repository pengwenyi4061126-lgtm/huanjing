#requires -Version 5.1
<#
  CacMacLwf fault-injection harness.

  Requires the filter installed, bound and RUNNING on an isolated test
  machine. The driver exposes a lab-only IOCTL fault mode:
    0 = off, 1 = fail clone allocation, 2 = fail lower OID completion.

  This script also probes invalid IOCTL lengths. It does not test a
  low-privilege token automatically; use -LowPrivUser with a standard
  account on the isolated machine.
#>
[CmdletBinding()]
param(
    [string]$AdapterName,
    [int]$OidStormIterations = 30,
    [switch]$SkipInvalidIoctl,
    [switch]$DryRun,
    [System.Management.Automation.PSCredential]$LowPrivCredential,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$ctl = Join-Path $root 'bin\cac-macctl.exe'
$component = 'CacMacLwf'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutputDir) {
    $OutputDir = Join-Path $root "evidence\fault-$stamp"
}
$logPath = Join-Path $OutputDir 'fault.jsonl'
$startUtc = (Get-Date).ToUniversalTime()
$failures = New-Object System.Collections.Generic.List[string]

function Write-Record {
    param([hashtable]$Record)
    $Record['utc'] = (Get-Date).ToUniversalTime().ToString('o')
    $line = ($Record | ConvertTo-Json -Compress -Depth 6)
    [System.IO.File]::AppendAllText(
        $logPath, $line + [Environment]::NewLine,
        (New-Object System.Text.UTF8Encoding($false)))
}

function Get-MacState {
    $raw = & $ctl state 2>&1
    if ($LASTEXITCODE -ne 0) { throw "cac-macctl state failed: $($raw -join ' ')" }
    return ($raw | Out-String | ConvertFrom-Json)
}

function Get-DumpSet {
    return @(Get-ChildItem -LiteralPath "$env:SystemRoot\Minidump" -Filter '*.dmp' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name)
}

function Get-BugCheckEvents {
    param([datetime]$SinceUtc)
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001 } -MaxEvents 20 -ErrorAction Stop |
            Where-Object { $_.TimeCreated.ToUniversalTime() -ge $SinceUtc })
    } catch { return @() }
}

function Invoke-OidStorm {
    param([int]$Iterations)
    for ($i = 0; $i -lt $Iterations; $i++) {
        [void][System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        [void](Get-CimInstance Win32_NetworkAdapter -Property Name, MacAddress -ErrorAction SilentlyContinue)
        [void](& getmac.exe /fo csv 2>$null)
        [void](& ipconfig.exe /all 2>$null)
    }
}

function Set-FaultMode {
    param([string]$Mode)
    $raw = & $ctl fault --mode $Mode 2>&1
    if ($LASTEXITCODE -ne 0) { throw "fault mode $Mode failed: $($raw -join ' ')" }
    return ($raw | Out-String | ConvertFrom-Json)
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CacMacIoctlProbe {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(IntPtr handle, uint code,
        byte[] input, uint inputSize, byte[] output, uint outputSize,
        out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

function Test-DeviceIoctl {
    param([uint32]$Code, [byte[]]$Input, [uint32]$OutputSize)
    $handle = [CacMacIoctlProbe]::CreateFileW(
        '\\.\CacMacLwf', 0xC0000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    if ($handle.ToInt64() -eq -1) {
        return [pscustomobject]@{ ok = $false; error = [Runtime.InteropServices.Marshal]::GetLastWin32Error(); note = 'open' }
    }
    try {
        $buffer = if ($OutputSize -gt 0) { [byte[]]::new([int]$OutputSize) } else { $null }
        $returned = [uint32]0
        $ok = [CacMacIoctlProbe]::DeviceIoControl(
            $handle, $Code, $Input, [uint32]($Input.Length), $buffer, $OutputSize,
            [ref]$returned, [IntPtr]::Zero)
        return [pscustomobject]@{ ok = $ok; error = [Runtime.InteropServices.Marshal]::GetLastWin32Error(); returned = $returned }
    } finally {
        [void][CacMacIoctlProbe]::CloseHandle($handle)
    }
}

$service = Get-Service -Name $component -ErrorAction SilentlyContinue
if (-not $service) { throw "Service $component not installed." }
if ($DryRun) {
    [ordered]@{
        service = $component
        status = $service.Status.ToString()
        startType = $service.StartType.ToString()
        oidStormIterations = $OidStormIterations
        skipInvalidIoctl = [bool]$SkipInvalidIoctl
        outputDir = $OutputDir
    } | ConvertTo-Json -Depth 4
    return
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
if ($service.Status -ne 'Running') {
    Start-Service -Name $component
    Start-Sleep -Seconds 3
}

$baselineDumps = Get-DumpSet
$baseline = Get-MacState
Write-Record @{ phase = 'baseline'; state = $baseline; dumpCount = $baselineDumps.Count }

try {
    foreach ($mode in @('clone', 'lower')) {
        $before = Get-MacState
        $set = Set-FaultMode -Mode $mode
        Invoke-OidStorm -Iterations $OidStormIterations
        $after = Get-MacState
        $expectedMode = if ($mode -eq 'clone') { 1 } else { 2 }
        $ok = ([int]$after.faultMode -eq $expectedMode) -and
              ([int64]$after.oidQueriesSeen -ge [int64]$before.oidQueriesSeen)
        if (-not $ok) { $failures.Add("fault mode $mode did not behave as expected") }
        Write-Record @{ phase = 'fault-mode'; mode = $mode; ok = $ok; before = $before; after = $after }
    }
} finally {
    $reset = Set-FaultMode -Mode 'off'
    Write-Record @{ phase = 'fault-mode'; mode = 'off'; state = $reset }
}

if (-not $SkipInvalidIoctl) {
    # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900/0x901/0x902, METHOD_BUFFERED, access)
    $setCode = 0x0022A400
    $stateCode = 0x00226404
    $faultCode = 0x0022A408
    $cases = @(
        @{ name = 'set-short'; code = $setCode; input = ([byte[]]::new(5)); output = 0 },
        @{ name = 'set-long'; code = $setCode; input = ([byte[]]::new(7)); output = 0 },
        @{ name = 'state-short'; code = $stateCode; input = ([byte[]]::new(0)); output = 4 },
        @{ name = 'fault-invalid'; code = $faultCode; input = [BitConverter]::GetBytes([uint32]3); output = 0 }
    )
    foreach ($case in $cases) {
        $result = Test-DeviceIoctl -Code $case.code -Input $case.input -OutputSize $case.output
        $ok = -not $result.ok
        if (-not $ok) { $failures.Add("invalid IOCTL $($case.name) unexpectedly succeeded") }
        Write-Record @{ phase = 'invalid-ioctl'; name = $case.name; ok = $ok; result = $result }
    }
}

if ($LowPrivCredential) {
    $probe = Join-Path $env:TEMP 'cac-macctl-lowpriv.exe'
    Copy-Item -LiteralPath $ctl -Destination $probe -Force
    try {
        $out = Join-Path $env:TEMP 'cac-macctl-lowpriv.out'
        $err = Join-Path $env:TEMP 'cac-macctl-lowpriv.err'
        $proc = Start-Process -FilePath $probe -ArgumentList 'state' -Credential $LowPrivCredential `
            -RedirectStandardOutput $out -RedirectStandardError $err -Wait -PassThru -WindowStyle Hidden
        $ok = ($proc.ExitCode -ne 0)
        if (-not $ok) { $failures.Add('low-priv state unexpectedly succeeded') }
        Write-Record @{ phase = 'low-priv'; ok = $ok; exitCode = $proc.ExitCode;
            stdout = (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue);
            stderr = (Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue) }
    } finally {
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
}

$finalDumps = Get-DumpSet
$newDumps = @($finalDumps | Where-Object { $_ -notin $baselineDumps })
$newBugChecks = @(Get-BugCheckEvents -SinceUtc $startUtc)
$pass = ($newDumps.Count -eq 0) -and ($newBugChecks.Count -eq 0) -and ($failures.Count -eq 0)
$summary = [ordered]@{
    schema = 1
    pass = $pass
    startedUtc = $startUtc.ToString('o')
    finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
    oidStormIterations = $OidStormIterations
    newDumps = $newDumps
    newBugChecks = $newBugChecks.Count
    failures = $failures
    log = $logPath
}
$summary | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $OutputDir 'summary.json') -Encoding UTF8
Write-Output ($summary | ConvertTo-Json -Depth 6)
if (-not $pass) { exit 1 }
