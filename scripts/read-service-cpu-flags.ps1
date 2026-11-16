[CmdletBinding()]
param(
    [int]$ProcessId = 0,
    [string]$Module = 'cowork-svc.exe',
    [string]$InternalHex,
    [string]$VendorHex
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$probe = Join-Path $root 'native\dist\cac-cpu-probe.exe'
if (-not $InternalHex -or -not $VendorHex) {
    if (-not $ProcessId) {
        $ProcessId = (Get-Process -Name 'cowork-svc' -ErrorAction Stop | Select-Object -First 1).Id
    }
    if (-not (Test-Path -LiteralPath $probe)) { throw "probe not built: $probe" }
    if (-not $InternalHex) {
        $InternalHex = (& $probe --pid $ProcessId --module $Module --read 0x123b980 --length 0x60 |
            ConvertFrom-Json).hex
    }
    if (-not $VendorHex) {
        $VendorHex = (& $probe --pid $ProcessId --module $Module --read 0x123bac0 --length 0x80 |
            ConvertFrom-Json).hex
    }
}

$internalNames = @(
    'HasAES', 'HasADX', 'HasAVX', 'HasAVX2', 'HasAVX512F', 'HasAVX512BW',
    'HasAVX512VL', 'HasBMI1', 'HasBMI2', 'HasERMS', 'HasFSRM', 'HasFMA',
    'HasOSXSAVE', 'HasPCLMULQDQ', 'HasPOPCNT', 'HasRDTSCP', 'HasSHA',
    'HasSSE3', 'HasSSSE3', 'HasSSE41', 'HasSSE42'
)
$vendorNames = @(
    'HasAES', 'HasADX', 'HasAVX', 'HasAVX2', 'HasAVX512', 'HasAVX512F',
    'HasAVX512CD', 'HasAVX512ER', 'HasAVX512PF', 'HasAVX512VL', 'HasAVX512BW',
    'HasAVX512DQ', 'HasAVX512IFMA', 'HasAVX512VBMI', 'HasAVX5124VNNIW',
    'HasAVX5124FMAPS', 'HasAVX512VPOPCNTDQ', 'HasAVX512VPCLMULQDQ',
    'HasAVX512VNNI', 'HasAVX512GFNI', 'HasAVX512VAES', 'HasAVX512VBMI2',
    'HasAVX512BITALG', 'HasAVX512BF16', 'HasAMXTile', 'HasAMXInt8',
    'HasAMXBF16', 'HasBMI1', 'HasBMI2', 'HasCX16', 'HasERMS', 'HasFMA',
    'HasOSXSAVE', 'HasPCLMULQDQ', 'HasPOPCNT', 'HasRDRAND', 'HasRDSEED',
    'HasSSE2', 'HasSSE3', 'HasSSSE3', 'HasSSE41', 'HasSSE42', 'HasAVXIFMA',
    'HasAVXVNNI', 'HasAVXVNNIInt8'
)

$internalBytes = [Convert]::FromHexString($InternalHex)
$vendorBytes = [Convert]::FromHexString($VendorHex)
$internal = [ordered]@{}
$vendor = [ordered]@{}
for ($i = 0; $i -lt $internalNames.Count; $i++) {
    $internal[$internalNames[$i]] = [int]$internalBytes[0x40 + $i]
}
for ($i = 0; $i -lt $vendorNames.Count; $i++) {
    $vendor[$vendorNames[$i]] = [int]$vendorBytes[0x40 + $i]
}

[pscustomobject]@{
    pid = $ProcessId
    module = $Module
    internal_hex = $InternalHex
    vendor_hex = $VendorHex
    internal = $internal
    vendor = $vendor
} | ConvertTo-Json -Depth 5
