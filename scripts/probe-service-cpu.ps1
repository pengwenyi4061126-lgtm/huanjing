[CmdletBinding()]
param(
    [int]$ProcessId = 0,
    [string]$Manifest = 'C:\ProgramData\CAC\profiles\desktop-1\service-cpu-manifest.txt'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$probe = Join-Path $root 'native\dist\cac-cpu-probe.exe'
if (-not (Test-Path -LiteralPath $probe)) {
    throw "probe not built: $probe"
}
if (-not $ProcessId) {
    $ProcessId = (Get-Process -Name 'cowork-svc' -ErrorAction Stop | Select-Object -First 1).Id
}

$lines = Get-Content -LiteralPath $Manifest |
    Where-Object { $_ -and -not $_.StartsWith('#') -and $_ -match '\|' }
if (-not $lines) {
    throw "manifest has no entries: $Manifest"
}

$results = New-Object System.Collections.Generic.List[object]
foreach ($line in $lines) {
    $fields = $line.Split('|')
    if ($fields.Count -lt 5) { continue }
    $rvaText = $fields[2] -replace '^0x', ''
    $rva = [Convert]::ToUInt64($rvaText, 16)
    $kind = $fields[3]
    $rvaArg = '0x{0:x}' -f $rva

    if ($kind -eq 'gocpuid') {
        $json = & $probe --pid $ProcessId --module cowork-svc.exe --rva $rvaArg --kind cpuid --leaf 0x40000000 --subleaf 0
        if ($LASTEXITCODE -ne 0) { throw "probe failed for $line" }
        $result = $json | ConvertFrom-Json
        if (($result.results -join '') -ne '00000000000000000000000000000000') {
            throw "cpuid leaf 0x40000000 was not neutral at RVA $rvaArg"
        }
    } elseif ($kind -eq 'goxgetbv') {
        $json = & $probe --pid $ProcessId --module cowork-svc.exe --rva $rvaArg --kind xgetbv
        if ($LASTEXITCODE -ne 0) { throw "probe failed for $line" }
        $result = $json | ConvertFrom-Json
        if ($result.results[0] -ne $result.host[0] -or $result.results[1] -ne $result.host[1]) {
            throw "xgetbv result mismatch at RVA $rvaArg"
        }
    } else {
        continue
    }
    $results.Add($result)
}

$results | ConvertTo-Json -Depth 6
