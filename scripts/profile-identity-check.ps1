[CmdletBinding()]
param(
    [string]$Root = (Join-Path $env:USERPROFILE '.cac')
)

$ErrorActionPreference = 'Stop'
$failures = New-Object System.Collections.Generic.List[string]
$rows = New-Object System.Collections.Generic.List[object]

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "CAC root not found: $Root"
}

foreach ($sub in @('desktop', 'envs')) {
    $base = Join-Path $Root $sub
    if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
    Get-ChildItem -LiteralPath $base -Directory | ForEach-Object {
        $file = Join-Path $_.FullName 'identity.json'
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return }
        $identity = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        $key = "$sub\$($_.Name)"
        $rows.Add([pscustomobject]@{
            Profile = $key
            MachineId = [string]$identity.machine_id
            Uuid = [string]$identity.uuid
            SystemUuid = [string]$identity.system_uuid
            Mac = [string]$identity.mac_address
            Hostname = [string]$identity.hostname
            DiskSerial = [string]$identity.disk_serial
            Realism = $identity.realism_schema
            Path = $file
        })
    }
}

foreach ($row in $rows) {
    if ([string]::IsNullOrWhiteSpace($row.MachineId)) { $failures.Add("$($row.Profile): machine_id missing") }
    if ([string]::IsNullOrWhiteSpace($row.Uuid)) { $failures.Add("$($row.Profile): uuid missing") }
    if ([string]::IsNullOrWhiteSpace($row.SystemUuid)) {
        $failures.Add("$($row.Profile): system_uuid missing")
    } elseif ($row.SystemUuid -ne $row.Uuid.Replace('-', '').ToUpperInvariant()) {
        $failures.Add("$($row.Profile): system_uuid does not match uuid")
    }
    if ([string]$row.Realism -lt 2) {
        $failures.Add("$($row.Profile): realism_schema < 2")
    }
    if ($row.Mac -notmatch '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$') {
        $failures.Add("$($row.Profile): MAC format invalid ($($row.Mac))")
    } else {
        $first = [Convert]::ToByte(($row.Mac -split ':')[0], 16)
        if (($first -band 0x03) -ne 0) {
            $failures.Add("$($row.Profile): MAC is not globally administered unicast ($($row.Mac))")
        }
    }
    if ($row.Hostname -notmatch '^(DESKTOP|LAPTOP|WIN)-[A-Z0-9]{7}$') {
        $failures.Add("$($row.Profile): hostname format invalid ($($row.Hostname))")
    }
}

foreach ($field in @('MachineId', 'Uuid', 'SystemUuid', 'Mac', 'Hostname', 'DiskSerial')) {
    $groups = $rows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.$field) } |
        Group-Object -Property $field | Where-Object { $_.Count -gt 1 }
    foreach ($group in $groups) {
        $names = ($group.Group | ForEach-Object { $_.Profile }) -join ','
        $failures.Add("duplicate $field '$($group.Name)' in: $names")
    }
}

$rows | Format-Table Profile, MachineId, Mac, Hostname, DiskSerial, Realism -AutoSize |
    Out-String -Width 200
if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Output "FAIL: $_" }
    Write-Output ("profile_identity_check=fail count={0}" -f $failures.Count)
    exit 1
}
Write-Output 'profile_identity_check=pass'
