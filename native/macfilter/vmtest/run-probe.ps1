param(
    [string]$Only = 'all'
)

$ErrorActionPreference = 'Stop'

try {
    & (Join-Path $PSScriptRoot 'probe-api.ps1') -Only $Only
    exit 0
}
catch {
    $detail = @(
        "Type: $($_.Exception.GetType().FullName)"
        "Message: $($_.Exception.Message)"
        "Stack: $($_.ScriptStackTrace)"
        "Inner: $($_.Exception.InnerException)"
        ($_ | Out-String)
    ) -join [Environment]::NewLine
    $detail | Set-Content -LiteralPath 'C:\Windows\Temp\cac-probe-error.txt' -Encoding UTF8
    exit 1
}
