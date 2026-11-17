[CmdletBinding()]
param(
    [string]$Root = (Join-Path $env:USERPROFILE '.cac'),
    [string[]]$RegenerateDevice = @(),
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

function Get-DerivedHex {
    param([string]$Seed, [int]$Length)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Seed))
        $hex = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        return $hex.Substring(0, [Math]::Min($Length, $hex.Length))
    } finally {
        $sha.Dispose()
    }
}

function New-RealisticMac {
    param([string]$Seed)
    $ouis = @('00:E0:4C', '3C:7C:3F', 'B0:83:FE', '00:1B:21', 'A4:BB:6D')
    $hex = Get-DerivedHex "$Seed|mac" 8
    $index = [Convert]::ToByte($hex.Substring(0, 2), 16) % $ouis.Count
    return ('{0}:{1}:{2}:{3}' -f $ouis[$index], $hex.Substring(2, 2), $hex.Substring(4, 2), $hex.Substring(6, 2))
}

function Test-RealisticMac {
    param([string]$Value)
    if ($Value -notmatch '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$') { return $false }
    $first = [Convert]::ToByte(($Value -split ':')[0], 16)
    if (($first -band 0x03) -ne 0) { return $false }
    if ($Value -match '^00:00:00:00:00:00$') { return $false }
    return $true
}

function New-SerialToken {
    param([string]$Seed, [int]$Length)
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $hex = Get-DerivedHex "$Seed|serial" ($Length * 2)
    $text = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        $byte = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
        [void]$text.Append($alphabet[$byte % $alphabet.Length])
    }
    return $text.ToString()
}

function New-NumericSerial {
    param([string]$Seed, [int]$Length)
    $hex = Get-DerivedHex "$Seed|numeric" ($Length * 2)
    $text = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        $byte = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
        [void]$text.Append(([string]($byte % 10)))
    }
    return $text.ToString()
}

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "CAC root not found: $Root"
}

$identityFiles = @()
foreach ($sub in @('desktop', 'envs')) {
    $base = Join-Path $Root $sub
    if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
    Get-ChildItem -LiteralPath $base -Directory | ForEach-Object {
        $file = Join-Path $_.FullName 'identity.json'
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            $identityFiles += [pscustomobject]@{
                Key  = "$sub\$($_.Name)"
                Path = $file
            }
        }
    }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$results = New-Object System.Collections.Generic.List[object]
foreach ($entry in $identityFiles) {
    $identity = Get-Content -LiteralPath $entry.Path -Raw | ConvertFrom-Json
    foreach ($name in @('machine_id', 'uuid', 'stable_id', 'system_uuid', 'realism_schema',
                        'hostname', 'mac_address', 'disk_serial', 'bios_serial', 'board_serial',
                        'system_serial', 'hid_serial', 'nic_pci_id')) {
        if ($null -eq $identity.PSObject.Properties[$name]) {
            Add-Member -InputObject $identity -NotePropertyName $name -NotePropertyValue $null
        }
    }
    $regenerate = $RegenerateDevice -contains $entry.Key
    $changes = New-Object System.Collections.Generic.List[string]
    if ($regenerate) {
        $identity.machine_id = [guid]::NewGuid().ToString('N')
        $identity.uuid = [guid]::NewGuid().ToString().ToUpperInvariant()
        $identity.stable_id = [guid]::NewGuid().ToString().ToLowerInvariant()
        $identity.system_uuid = $identity.uuid.Replace('-', '').ToUpperInvariant()
        $changes.Add('machine_id')
        $changes.Add('uuid')
        $changes.Add('stable_id')
        $changes.Add('system_uuid')
    }

    $seed = [string]$identity.machine_id
    if ([string]::IsNullOrWhiteSpace($seed)) {
        throw "machine_id missing: $($entry.Path)"
    }
    $needsRealism = ([int]$identity.realism_schema -lt 2) -or $regenerate
    if ($needsRealism) {
        $identity.hostname = 'DESKTOP-' + (Get-DerivedHex "$seed|host" 7).ToUpperInvariant()
        $identity.mac_address = New-RealisticMac $seed
        $identity.disk_serial = 'WD-W' + (New-SerialToken "$seed|disk" 11)
        $identity.bios_serial = New-SerialToken "$seed|bios" 12
        $identity.board_serial = New-NumericSerial "$seed|board" 15
        $identity.system_serial = New-SerialToken "$seed|system" 12
        $identity.hid_serial = New-NumericSerial "$seed|hid" 10
        $identity.nic_pci_id = 'PCI\VEN_10EC&DEV_8168&SUBSYS_86761043&REV_15'
        $identity.realism_schema = 2
        $changes.Add('hostname')
        $changes.Add('mac_address')
        $changes.Add('serials')
        $changes.Add('realism_schema')
    } else {
        if ([string]$identity.hostname -notmatch '^(DESKTOP|LAPTOP|WIN)-[A-Z0-9]{7}$') {
            $identity.hostname = 'DESKTOP-' + (Get-DerivedHex "$seed|host" 7).ToUpperInvariant()
            $changes.Add('hostname')
        }
        if (-not (Test-RealisticMac ([string]$identity.mac_address))) {
            $identity.mac_address = New-RealisticMac $seed
            $changes.Add('mac_address')
        }
        if ([string]::IsNullOrWhiteSpace([string]$identity.nic_pci_id)) {
            $identity.nic_pci_id = 'PCI\VEN_10EC&DEV_8168&SUBSYS_86761043&REV_15'
            $changes.Add('nic_pci_id')
        }
    }

    $results.Add([pscustomobject]@{
        Profile = $entry.Key
        Changed = if ($changes.Count) { ($changes | Select-Object -Unique) -join ',' } else { '' }
        MachineId = $identity.machine_id
        Uuid = $identity.uuid
        Mac = $identity.mac_address
        Hostname = $identity.hostname
        Realism = $identity.realism_schema
        Path = $entry.Path
    })
    if (-not $WhatIf -and $changes.Count) {
        $backup = "$($entry.Path).bak-$stamp"
        if (-not (Test-Path -LiteralPath $backup)) {
            Copy-Item -LiteralPath $entry.Path -Destination $backup -Force
        }
        $identity | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $entry.Path -Encoding UTF8
    }
}

$results | Format-Table Profile, Changed, Mac, Hostname, Realism -AutoSize | Out-String -Width 180
if ($WhatIf) {
    Write-Output 'WHATIF: no files written'
}
