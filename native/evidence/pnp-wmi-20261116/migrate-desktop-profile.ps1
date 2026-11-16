param([Parameter(Mandatory = $true)][string]$IdentityPath)

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

$identity = Get-Content -LiteralPath $IdentityPath -Raw | ConvertFrom-Json
$seed = [string]$identity.machine_id
if ([string]::IsNullOrWhiteSpace($seed)) { throw "machine_id is missing in $IdentityPath" }
if ([int]$identity.realism_schema -ge 2) {
    Write-Output 'realism_schema=2 already; no change'
    return
}
$repairs = [ordered]@{
    hostname       = if ([string]$identity.hostname -match '^host-') { 'DESKTOP-' + (Get-DerivedHex "$seed|host" 7).ToUpperInvariant() } else { [string]$identity.hostname }
    mac_address    = if (Test-RealisticMac ([string]$identity.mac_address)) { [string]$identity.mac_address } else { New-RealisticMac $seed }
    disk_serial    = 'WD-W' + (New-SerialToken "$seed|disk" 11)
    bios_serial    = New-SerialToken "$seed|bios" 12
    board_serial   = New-NumericSerial "$seed|board" 15
    system_serial  = New-SerialToken "$seed|system" 12
    hid_serial     = New-NumericSerial "$seed|hid" 10
    nic_pci_id     = 'PCI\VEN_10EC&DEV_8168&SUBSYS_86761043&REV_15'
    realism_schema = 2
}
foreach ($key in $repairs.Keys) {
    Add-Member -InputObject $identity -NotePropertyName $key -NotePropertyValue $repairs[$key] -Force
}
$identity | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $IdentityPath -Encoding UTF8
[pscustomobject]@{
    hostname = $identity.hostname
    mac_address = $identity.mac_address
    disk_serial = $identity.disk_serial
    bios_serial = $identity.bios_serial
    board_serial = $identity.board_serial
    system_serial = $identity.system_serial
    hid_serial = $identity.hid_serial
    realism_schema = $identity.realism_schema
} | Format-List
