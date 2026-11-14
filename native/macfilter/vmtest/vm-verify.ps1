# Run after the post-install reboot. Writes vm-result.json next to this script.
$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$ctl = Join-Path $root 'cac-macctl.exe'
$result = [ordered]@{
    time          = (Get-Date).ToString('o')
    osBuild       = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    osUbr         = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    installed     = (& netcfg -q CacMacLwf 2>&1) -join ' '
    state         = $null
}

if (Test-Path -LiteralPath $ctl) {
    $stateJson = & $ctl state 2>&1 | Out-String
    $result['state'] = $stateJson.Trim()
    try { $result['stateParsed'] = ($stateJson | ConvertFrom-Json) } catch { }

    # Set a test MAC and re-read counters.
    & $ctl set --mac 02:11:22:33:44:55 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $after = & $ctl state 2>&1 | Out-String
    $result['stateAfterSet'] = $after.Trim()
}

$result | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $root 'vm-result.json') -Encoding UTF8
Write-Host 'Result written to vm-result.json'
Get-Content -LiteralPath (Join-Path $root 'vm-result.json')
