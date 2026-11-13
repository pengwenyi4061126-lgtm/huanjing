[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Target,
    [string]$Output = "",
    [int]$MaxCandidatesPerModule = 8
)

$ErrorActionPreference = "Stop"
if (-not $Output) { $Output = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "native-hook-manifest.txt" }

function Get-InstructionLength {
    param([byte[]]$Code, [int]$Offset, [int]$End)
    $left = $End - $Offset
    if ($left -le 0) { return 0 }

    if ($left -ge 4 -and $Code[$Offset] -eq 0xF3 -and $Code[$Offset + 1] -eq 0x0F -and
        $Code[$Offset + 2] -eq 0x1E -and $Code[$Offset + 3] -eq 0xFA) { return 4 }

    if ($left -ge 5 -and ($Code[$Offset] -eq 0x48 -or $Code[$Offset] -eq 0x4C) -and
        $Code[$Offset + 1] -eq 0x89 -and (($Code[$Offset + 2] -band 0xC7) -eq 0x44) -and
        $Code[$Offset + 3] -eq 0x24) { return 5 }
    if ($left -ge 5 -and $Code[$Offset] -eq 0x4C -and $Code[$Offset + 1] -eq 0x89 -and
        $Code[$Offset + 2] -eq 0x4C -and $Code[$Offset + 3] -eq 0x24) { return 5 }

    if ($left -ge 4 -and $Code[$Offset] -eq 0x89 -and (($Code[$Offset + 1] -band 0xC7) -eq 0x44) -and
        $Code[$Offset + 2] -eq 0x24) { return 4 }
    if ($left -ge 4 -and $Code[$Offset] -eq 0x8B -and (($Code[$Offset + 1] -band 0xC7) -eq 0x44) -and
        $Code[$Offset + 2] -eq 0x24) { return 4 }
    if ($left -ge 5 -and $Code[$Offset] -eq 0x48 -and $Code[$Offset + 1] -eq 0x8B -and
        (($Code[$Offset + 2] -band 0xC7) -eq 0x44) -and $Code[$Offset + 3] -eq 0x24) { return 5 }

    if ($left -ge 5 -and ($Code[$Offset] -eq 0xB8 -or $Code[$Offset] -eq 0xB9 -or $Code[$Offset] -eq 0xBA)) { return 5 }
    if ($left -ge 2 -and $Code[$Offset] -eq 0x33 -and
        ($Code[$Offset + 1] -eq 0xC9 -or $Code[$Offset + 1] -eq 0xC0 -or $Code[$Offset + 1] -eq 0xD2)) { return 2 }
    if ($left -ge 3 -and $Code[$Offset] -eq 0x45 -and $Code[$Offset + 1] -eq 0x33 -and $Code[$Offset + 2] -eq 0xC0) { return 3 }
    if ($left -ge 3 -and $Code[$Offset] -eq 0x83 -and $Code[$Offset + 1] -eq 0xEC) { return 3 }

    if ($left -ge 4 -and $Code[$Offset] -eq 0x48 -and $Code[$Offset + 1] -eq 0x83 -and
        $Code[$Offset + 2] -eq 0xEC) { return 4 }
    if ($left -ge 7 -and $Code[$Offset] -eq 0x48 -and $Code[$Offset + 1] -eq 0x81 -and
        $Code[$Offset + 2] -eq 0xEC) { return 7 }

    if ($left -ge 2 -and $Code[$Offset] -eq 0x40 -and $Code[$Offset + 1] -ge 0x50 -and
        $Code[$Offset + 1] -le 0x57) { return 2 }
    if ($Code[$Offset] -ge 0x50 -and $Code[$Offset] -le 0x57) { return 1 }

    if ($left -ge 3 -and $Code[$Offset] -eq 0x48 -and $Code[$Offset + 1] -eq 0x8B -and
        ($Code[$Offset + 2] -eq 0xC4 -or $Code[$Offset + 2] -eq 0xDC)) { return 3 }
    if ($left -ge 5 -and $Code[$Offset] -eq 0x48 -and $Code[$Offset + 1] -eq 0x8D -and
        $Code[$Offset + 2] -eq 0x64 -and $Code[$Offset + 3] -eq 0x24) { return 5 }
    if ($left -ge 6 -and $Code[$Offset] -eq 0x48 -and $Code[$Offset + 1] -eq 0x83 -and
        $Code[$Offset + 2] -eq 0x64 -and $Code[$Offset + 3] -eq 0x24) { return 6 }
    if ($left -ge 3 -and $Code[$Offset] -eq 0x4C -and $Code[$Offset + 1] -eq 0x8B -and
        ($Code[$Offset + 2] -eq 0xD1 -or $Code[$Offset + 2] -eq 0xD9 -or $Code[$Offset + 2] -eq 0xDC)) { return 3 }
    if ($left -ge 4 -and $Code[$Offset] -eq 0x55 -and $Code[$Offset + 1] -eq 0x48 -and
        $Code[$Offset + 2] -eq 0x89 -and $Code[$Offset + 3] -eq 0xE5) { return 1 }
    if ($left -ge 3 -and $Code[$Offset] -eq 0x48 -and $Code[$Offset + 1] -eq 0x89 -and
        $Code[$Offset + 2] -eq 0xE5) { return 3 }

    if ($left -ge 3 -and $Code[$Offset] -eq 0x0F -and $Code[$Offset + 1] -eq 0x1F) {
        $modrm = $Code[$Offset + 2]
        $mod = $modrm -shr 6
        $rm = $modrm -band 7
        if ($mod -eq 0 -and $rm -eq 5) { return 7 }
        if ($mod -eq 0 -and $rm -eq 4 -and $left -ge 4 -and $Code[$Offset + 3] -eq 0x00) { return 5 }
        if ($mod -eq 0 -and $rm -lt 4) { return 3 }
        if ($mod -eq 1 -and $rm -eq 4) { return 5 }
        if ($mod -eq 1) { return 4 }
        if ($mod -eq 2 -and $rm -eq 4) { return 8 }
        if ($mod -eq 2) { return 7 }
        return 0
    }

    return 0
}

function Test-Prologue {
    param([byte[]]$Code, [int]$Start, [int]$Hit)
    $offset = $Start
    $total = 0
    while ($total -lt 5) {
        $length = Get-InstructionLength -Code $Code -Offset $offset -End $Hit
        if ($length -le 0) { return $null }
        $offset += $length
        $total += $length
        if ($offset -gt $Hit) { return $null }
    }
    return $total
}

function Find-PrologueStart {
    param([byte[]]$Code, [int]$Hit)
    $lower = [Math]::Max(0, $Hit - 128)
    for ($start = $Hit - 1; $start -ge $lower; $start--) {
        $ret = $false
        for ($i = $start; $i -lt $Hit; $i++) {
            if ($Code[$i] -eq 0xC3 -or $Code[$i] -eq 0xC2) { $ret = $true; break }
        }
        if ($ret) { break }
        $length = Test-Prologue -Code $Code -Start $start -Hit $Hit
        if ($null -ne $length) { return $start }
    }
    return -1
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# cac native CPU hook manifest")
$lines.Add("# module|sha256|rva|kind|prologue_hex")

foreach ($path in $Target) {
    $full = [IO.Path]::GetFullPath($path)
    if (-not (Test-Path -LiteralPath $full)) { throw "target not found: $full" }
    $bytes = [IO.File]::ReadAllBytes($full)
    if ($bytes.Length -lt 0x100) { throw "not a PE file: $full" }
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ([BitConverter]::ToUInt32($bytes, $pe) -ne 0x00004550) { throw "invalid PE signature: $full" }
    $sections = [BitConverter]::ToUInt16($bytes, $pe + 6)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
    $sectionTable = $pe + 24 + $optionalSize
    $hash = Get-FileSha256 $full
    $found = 0

    for ($s = 0; $s -lt $sections; $s++) {
        $entry = $sectionTable + $s * 40
        $characteristics = [BitConverter]::ToUInt32($bytes, $entry + 36)
        if (($characteristics -band 0x20000000) -eq 0) { continue }
        $virtualAddress = [BitConverter]::ToUInt32($bytes, $entry + 12)
        $rawSize = [BitConverter]::ToUInt32($bytes, $entry + 16)
        $rawPointer = [BitConverter]::ToUInt32($bytes, $entry + 20)
        if ($rawSize -eq 0 -or $rawPointer + $rawSize -gt $bytes.Length) { continue }
        $end = [int]($rawPointer + $rawSize) - 4
        for ($i = [int]$rawPointer; $i -lt $end; $i++) {
            $kind = $null
            if ($bytes[$i] -eq 0x0F -and $bytes[$i + 1] -eq 0xA2) { $kind = "cpuid" }
            elseif ($bytes[$i] -eq 0x0F -and $bytes[$i + 1] -eq 0x01 -and $bytes[$i + 2] -eq 0xD0) { $kind = "xgetbv" }
            if (-not $kind) { continue }
            $start = Find-PrologueStart -Code $bytes -Hit $i
            if ($start -lt 0) { continue }
            if ($kind -eq "cpuid") {
                for ($k = [Math]::Max($start, $i - 24); $k + 1 -lt $i; $k++) {
                    if (($bytes[$k] -eq 0x44 -and $bytes[$k + 1] -eq 0x89 -and $bytes[$k + 2] -eq 0xC1) -or
                        ($bytes[$k] -eq 0x41 -and $bytes[$k + 1] -eq 0x8B -and $bytes[$k + 2] -eq 0xC8)) {
                        $kind = "cpuidex"
                        break
                    }
                }
            }
            $rva = $virtualAddress + ($start - $rawPointer)
            $prologueLength = [Math]::Min(16, $i - $start)
            $prologue = -join ($bytes[$start..($start + $prologueLength - 1)] | ForEach-Object { $_.ToString("x2") })
            $lines.Add(("{0}|{1}|0x{2:X}|{3}|{4}" -f $full, $hash, $rva, $kind, $prologue))
            Write-Host ("{0}  {1}  RVA=0x{2:X}  entry-offset=-0x{3:X}" -f (Split-Path $full -Leaf), $kind, $rva, ($i - $start)) -ForegroundColor Cyan
            $found++
            if ($found -ge $MaxCandidatesPerModule) { break }
        }
        if ($found -ge $MaxCandidatesPerModule) { break }
    }
    Write-Host ("{0}: {1} candidate(s), sha256={2}" -f (Split-Path $full -Leaf), $found, $hash) -ForegroundColor Yellow
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($Output, ($lines -join "`r`n") + "`r`n", $utf8)
Write-Host "Manifest: $Output" -ForegroundColor Green
