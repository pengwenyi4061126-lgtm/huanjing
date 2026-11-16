[CmdletBinding()]
param(
    [string]$ServiceName = 'CoworkVMService',
    [string]$Godebug = 'cpu.all=off',
    [switch]$Remove,
    [switch]$NoRestart
)

$ErrorActionPreference = 'Stop'
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (-not (Test-Path -LiteralPath $key)) {
    throw "service registry key not found: $key"
}

$current = @()
$property = Get-ItemProperty -Path $key -Name Environment -ErrorAction SilentlyContinue
if ($property -and $property.Environment) {
    $current = @($property.Environment)
}
if ($Remove) {
    $next = @($current | Where-Object { $_ -and $_ -ne "GODEBUG=$Godebug" })
} else {
    $next = @($current | Where-Object { $_ -and $_ -notmatch '^GODEBUG=' })
    $next += "GODEBUG=$Godebug"
}

if ($next.Count -gt 0) {
    Set-ItemProperty -Path $key -Name Environment -Value ([string[]]$next) -Type MultiString
} else {
    Remove-ItemProperty -Path $key -Name Environment -ErrorAction SilentlyContinue
}

$restarted = $false
$service = Get-Service -Name $ServiceName -ErrorAction Stop
if (-not $NoRestart -and $service.Status -eq 'Running') {
    & sc.exe stop $ServiceName | Out-Null
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 700
        $query = & sc.exe query $ServiceName 2>&1 | Out-String
    } while ((Get-Date) -lt $deadline -and $query -notmatch 'STOPPED')
    & sc.exe start $ServiceName | Out-Null
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 700
        $query = & sc.exe query $ServiceName 2>&1 | Out-String
    } while ((Get-Date) -lt $deadline -and $query -notmatch 'RUNNING')
    $restarted = $true
}

$result = Get-ItemProperty -Path $key -Name Environment -ErrorAction SilentlyContinue
$environment = @()
if ($result -and $result.Environment) {
    $environment = @($result.Environment)
}
[pscustomobject]@{
    service = $ServiceName
    environment = $environment
    restarted = $restarted
} | ConvertTo-Json -Depth 4
