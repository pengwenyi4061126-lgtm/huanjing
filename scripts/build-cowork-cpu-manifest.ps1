[CmdletBinding()]
param(
    [string]$Output = 'C:\ProgramData\CAC\profiles\desktop-1\service-cpu-manifest.txt'
)

$ErrorActionPreference = 'Stop'

$claudeDir = Get-ChildItem -LiteralPath 'C:\Program Files\WindowsApps' -Directory -Filter 'Claude_*' |
    Sort-Object Name -Descending |
    Select-Object -First 1
if (-not $claudeDir) {
    throw 'Claude WindowsApps directory not found.'
}

$resources = Join-Path $claudeDir.FullName 'app\resources'
$targets = @(
    (Join-Path $resources 'cowork-svc.exe'),
    (Join-Path $resources 'claude-ssh-broker.exe'),
    (Join-Path $resources 'claude-ssh-proxy.exe'),
    (Join-Path $resources 'claude-ssh-askpass.exe'),
    (Join-Path $resources 'app.asar.unpacked\resources\github-mcp\github-mcp-server.exe')
) | Where-Object { Test-Path -LiteralPath $_ }

if (-not ($targets | Where-Object { [IO.Path]::GetFileName($_) -eq 'cowork-svc.exe' })) {
    throw "cowork-svc.exe not found under $resources"
}

$scanner = Join-Path (Split-Path -Parent $PSScriptRoot) 'native\scan-native-target.ps1'
$temp = Join-Path $env:TEMP ("cac-cpu-manifest-" + [Guid]::NewGuid().ToString('N') + '.txt')
try {
    $result = New-Object System.Collections.Generic.List[string]
    $result.Add('# cac native CPU hook manifest (multi-image Go ABI)')
    $result.Add('# module|sha256|rva|kind|prologue_hex')

    foreach ($target in $targets) {
        & $scanner -Target $target -Output $temp -MaxCandidatesPerModule 64 | Out-Null
        $countBefore = $result.Count
        foreach ($line in Get-Content -LiteralPath $temp) {
            if ($line -notmatch '^[A-Za-z]:\\' -or $line -notmatch '\|') { continue }
            $fields = $line.Split('|')
            if ($fields.Count -lt 5) { continue }
            $kind = $fields[3]
            $prologue = $fields[4]
            $goKind = $null
            if ($kind -eq 'cpuid' -and $prologue -eq '8b4424088b4c240c') {
                $goKind = 'gocpuid'
            } elseif ($kind -eq 'xgetbv' -and $prologue -eq 'b900000000') {
                $goKind = 'goxgetbv'
            }
            if (-not $goKind) { continue }
            $fields[3] = $goKind
            $result.Add(($fields -join '|'))
        }
        Write-Host ("CPU manifest: {0} -> {1} entries" -f [IO.Path]::GetFileName($target), ($result.Count - $countBefore))
    }

    if ($result.Count -le 2) {
        throw 'No Go ABI cpuid/xgetbv entries found; refusing to write an empty manifest.'
    }

    $directory = Split-Path -Parent $Output
    if ($directory) { New-Item -ItemType Directory -Force -Path $directory | Out-Null }
    $result | Set-Content -LiteralPath $Output -Encoding UTF8
    & icacls.exe $Output /reset | Out-Null
    & icacls.exe $Output /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    Write-Host "Manifest: $Output"
    Get-Content -LiteralPath $Output
}
finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}
