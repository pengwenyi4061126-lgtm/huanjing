[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [string]$DriverPath,
    [string]$ManifestPath,
    [string]$SmokePath,
    [string]$EvidencePath,
    [switch]$Uninstall,
    [switch]$NoStart,
    [switch]$SkipSmoke,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
if (-not $DriverPath) { $DriverPath = Join-Path $PSScriptRoot 'bin\CacKernel.sys' }
if (-not $ManifestPath) { $ManifestPath = Join-Path $PSScriptRoot 'bin\CacKernel.sha256' }
if (-not $SmokePath) { $SmokePath = Join-Path $PSScriptRoot 'bin\kernel-smoke.exe' }
if (-not $EvidencePath) { $EvidencePath = Join-Path $env:USERPROFILE '.cac\kernel\driver-install.json' }

$serviceName = 'CacKernel'
$driverTarget = Join-Path $env:SystemRoot 'System32\drivers\CacKernel.sys'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges are required to install or remove a kernel driver.'
    }
}

function Get-CacSha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToUpperInvariant()
    } finally {
        if ($stream) { $stream.Dispose() }
        $sha.Dispose()
    }
}

function Find-CacSignTool {
    $roots = @(
        'D:\huanjing\WindowsKits',
        'C:\Program Files (x86)\Windows Kits\10',
        'C:\Program Files\Windows Kits\10'
    ) | Where-Object { Test-Path -LiteralPath $_ }
    foreach ($root in $roots) {
        $tool = Get-ChildItem -LiteralPath $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($tool) { return $tool.FullName }
    }
    return $null
}

function Get-CacSignatureInfo([string]$Path) {
    $cert = $null
    try {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromSignedFile($Path)
    } catch {
        return [pscustomobject]@{ Status = 'NotSigned'; Signer = $null }
    }
    $signtool = Find-CacSignTool
    if (-not $signtool) {
        return [pscustomobject]@{ Status = 'Unknown'; Signer = $cert.Subject }
    }
    & $signtool verify /pa /q $Path 2>$null | Out-Null
    return [pscustomobject]@{
        Status = if ($LASTEXITCODE -eq 0) { 'Valid' } else { 'Invalid' }
        Signer = $cert.Subject
    }
}

function Invoke-Sc {
    param([string[]]$Arguments)
    $output = & sc.exe @Arguments 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join [Environment]::NewLine) }
}

function Get-ServiceState {
    $result = Invoke-Sc -Arguments @('query', $serviceName)
    if ($result.ExitCode -ne 0) {
        return 'Absent'
    }
    if ($result.Output -match 'RUNNING') { return 'Running' }
    if ($result.Output -match 'STOPPED') { return 'Stopped' }
    return 'Present'
}

function Assert-TestSigning {
    $bcd = & bcdedit /enum '{current}' 2>$null
    if (-not ($bcd | Select-String -Pattern '^\s*testsigning\s+Yes\s*$' -Quiet)) {
        throw 'This driver is test-signed. Enable test signing (bcdedit /set testsigning on), reboot, then retry.'
    }
}

function Remove-CacService {
    $state = Get-ServiceState
    if ($state -eq 'Absent') { return }
    if ($state -eq 'Running') {
        Invoke-Sc -Arguments @('stop', $serviceName) | Out-Null
        Start-Sleep -Seconds 2
    }
    Invoke-Sc -Arguments @('delete', $serviceName) | Out-Null
    Start-Sleep -Milliseconds 500
}

Assert-Administrator

if ($Uninstall) {
    Remove-CacService
    if (Test-Path -LiteralPath $driverTarget) {
        $remove = $true
        if ((Test-Path -LiteralPath $ManifestPath) -and -not $Force) {
            $expected = (Get-Content -LiteralPath $ManifestPath -Raw).Trim().ToUpperInvariant()
            $actual = Get-CacSha256 $driverTarget
            if ($expected -ne $actual) { $remove = $false }
        }
        if ($remove) {
            Remove-Item -LiteralPath $driverTarget -Force
            Write-Host "Removed $driverTarget" -ForegroundColor Green
        } else {
            Write-Host "Kept $driverTarget (hash does not match this build; use -Force to remove)" -ForegroundColor Yellow
        }
    }
    Write-Host 'CAC kernel service removed.' -ForegroundColor Green
    return
}

if (-not (Test-Path -LiteralPath $DriverPath -PathType Leaf)) {
    throw "Driver not found: $DriverPath. Run build-driver.ps1 first."
}
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Driver manifest not found: $ManifestPath"
}

$expectedHash = (Get-Content -LiteralPath $ManifestPath -Raw).Trim().ToUpperInvariant()
$actualHash = Get-CacSha256 $DriverPath
if ($expectedHash -ne $actualHash) {
    throw "Driver hash mismatch: manifest=$expectedHash actual=$actualHash"
}

$signature = Get-CacSignatureInfo $DriverPath
if ($signature.Status -ne 'Valid') {
    throw "Driver signature is not valid: $($signature.Status) $($signature.StatusMessage)"
}
Assert-TestSigning

$existingState = Get-ServiceState
if ($existingState -ne 'Absent') {
    if (-not $Force) {
        $existingHash = if (Test-Path -LiteralPath $driverTarget) { Get-CacSha256 $driverTarget } else { '' }
        if ($existingHash -ne $actualHash) {
            throw "Service $serviceName already exists with a different binary. Use -Force to replace it."
        }
    }
    Remove-CacService
}

New-Item -ItemType Directory -Path (Split-Path -Parent $driverTarget) -Force | Out-Null
Copy-Item -LiteralPath $DriverPath -Destination $driverTarget -Force

$created = $false
try {
    $create = Invoke-Sc -Arguments @(
        'create', $serviceName, 'type=', 'kernel', 'start=', 'demand', 'error=', 'normal',
        'binPath=', '\SystemRoot\System32\drivers\CacKernel.sys',
        'DisplayName=', 'CAC Kernel Boundary'
    )
    if ($create.ExitCode -ne 0) {
        throw "sc create failed: $($create.Output)"
    }
    $created = $true
    Invoke-Sc -Arguments @('description', $serviceName, 'CAC kernel control plane: per-process policy and audit ring.') | Out-Null

    if (-not $NoStart) {
        $start = Invoke-Sc -Arguments @('start', $serviceName)
        if ($start.ExitCode -ne 0) {
            throw "sc start failed: $($start.Output)"
        }
        Start-Sleep -Seconds 1
        if ((Get-ServiceState) -ne 'Running') {
            throw 'Service did not reach Running state.'
        }
    }
} catch {
    if ($created) { Remove-CacService }
    if (Test-Path -LiteralPath $driverTarget) { Remove-Item -LiteralPath $driverTarget -Force }
    throw
}

$smokeResult = $null
if (-not $NoStart -and -not $SkipSmoke) {
    if (-not (Test-Path -LiteralPath $SmokePath -PathType Leaf)) {
        throw "Smoke client not found: $SmokePath"
    }
    $smokeJson = Join-Path $env:TEMP ('cac-kernel-smoke-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        & $SmokePath --json $smokeJson
        $smokeExit = $LASTEXITCODE
        $smokeResult = [ordered]@{
            exitCode = $smokeExit
            output = if (Test-Path -LiteralPath $smokeJson) {
                Get-Content -LiteralPath $smokeJson -Raw | ConvertFrom-Json
            } else { $null }
        }
        if ($smokeExit -ne 0) {
            throw "Kernel smoke test failed with exit code $smokeExit"
        }
    } finally {
        Remove-Item -LiteralPath $smokeJson -Force -ErrorAction SilentlyContinue
    }
}

$state = Get-ServiceState
$evidence = [ordered]@{
    timestampUtc = [DateTime]::UtcNow.ToString('o')
    driver = [ordered]@{
        source = [System.IO.Path]::GetFullPath($DriverPath)
        installed = $driverTarget
        sha256 = $actualHash
        signatureStatus = [string]$signature.Status
        signer = $signature.Signer
    }
    service = [ordered]@{
        name = $serviceName
        state = $state
        startType = 'demand'
        binPath = '\SystemRoot\System32\drivers\CacKernel.sys'
    }
    smoke = $smokeResult
    note = 'Control plane only. This driver does not spoof CPUID, SMBIOS, NICs, disks, or firmware.'
}

New-Item -ItemType Directory -Path (Split-Path -Parent $EvidencePath) -Force | Out-Null
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
$evidence | ConvertTo-Json -Depth 8
Write-Host "Evidence: $EvidencePath" -ForegroundColor DarkGray
Write-Host "[PASS] $serviceName is $state" -ForegroundColor Green
