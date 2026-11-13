[CmdletBinding()]
param(
    [string]$DriverPath,
    [string]$OutputPath = (Join-Path $env:USERPROFILE '.cac\kernel\kernel-boundary.json'),
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'

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
    if ($script:CacSignToolPath -and (Test-Path -LiteralPath $script:CacSignToolPath)) {
        return $script:CacSignToolPath
    }
    $roots = @(
        'D:\huanjing\WindowsKits',
        'C:\Program Files (x86)\Windows Kits\10',
        'C:\Program Files\Windows Kits\10'
    ) | Where-Object { Test-Path -LiteralPath $_ }
    foreach ($root in $roots) {
        $tool = Get-ChildItem -LiteralPath $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($tool) {
            $script:CacSignToolPath = $tool.FullName
            return $script:CacSignToolPath
        }
    }
    return $null
}

function Get-CacSignatureInfo([string]$Path) {
    $cert = $null
    try {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromSignedFile($Path)
    } catch {
        return [pscustomobject]@{
            Status = 'NotSigned'
            AuthenticodeStatus = 'NotSigned'
            KernelPolicyStatus = 'NotSigned'
            Signer = $null
        }
    }
    $signtool = Find-CacSignTool
    if (-not $signtool) {
        return [pscustomobject]@{
            Status = 'Unknown'
            AuthenticodeStatus = 'Unknown'
            KernelPolicyStatus = 'Unknown'
            Signer = $cert.Subject
        }
    }
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $signtool verify /pa /q $Path 2>$null | Out-Null
        $authCode = $LASTEXITCODE
        & $signtool verify /kp /q $Path 2>$null | Out-Null
        $kernelCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    $kernelStatus = if ($kernelCode -eq 0) {
        'Valid'
    } elseif ((Get-BcdValue 'testsigning') -match '(?i)\bYes\b') {
        'TestSigned'
    } else {
        'Invalid'
    }
    return [pscustomobject]@{
        Status = if ($authCode -eq 0) { 'Valid' } else { 'Invalid' }
        AuthenticodeStatus = if ($authCode -eq 0) { 'Valid' } else { 'Invalid' }
        KernelPolicyStatus = $kernelStatus
        Signer = $cert.Subject
    }
}

function Get-BcdValue {
    param([string]$Name)
    $line = @(bcdedit /enum '{current}' 2>$null | Select-String "^\s*$Name\s+") | Select-Object -First 1
    if (-not $line) { return $null }
    return ([string]$line).Trim()
}

function Get-FileRecord {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ present = $false; path = $Path }
    }
    $item = Get-Item -LiteralPath $Path
    $hash = Get-CacSha256 $Path
    $signature = Get-CacSignatureInfo $Path
    return [ordered]@{
        present = $true
        path = $item.FullName
        length = $item.Length
        sha256 = $hash
        signatureStatus = [string]$signature.Status
        authenticodeStatus = [string]$signature.AuthenticodeStatus
        kernelPolicyStatus = [string]$signature.KernelPolicyStatus
        signer = $signature.Signer
    }
}

function Find-MapperHints {
    param([string[]]$Roots)
    $patterns = @(
        'PdFwKrnl', 'DriverMapper', 'kdmapper', 'iqvw64e', 'gdrv', 'RTCore',
        'WinIo', 'AsIO', 'dbutil', 'vulnerable.*driver', 'manual.*map'
    )
    $hits = @()
    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $hits += @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $name = $_.Name
                $full = $_.FullName
                @($patterns | Where-Object { $name -match $_ -or $full -match $_ }).Count -gt 0
            } |
            Select-Object -First 100 -ExpandProperty FullName)
    }
    return @($hits | Sort-Object -Unique)
}

function Find-Wdk {
    $bases = @(
        'D:\huanjing\wdk\Microsoft.Windows.WDK.x64',
        'C:\Program Files (x86)\Windows Kits\10\WDK',
        'C:\Program Files\Windows Kits\10\WDK'
    ) | Where-Object { Test-Path -LiteralPath $_ }
    foreach ($base in $bases) {
        $cRoots = @((Join-Path $base 'c'))
        $cRoots += @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'c' })
        foreach ($cRoot in $cRoots) {
            $includeRoot = Join-Path $cRoot 'Include'
            if (-not (Test-Path -LiteralPath $includeRoot)) { continue }
            $version = Get-ChildItem -LiteralPath $includeRoot -Directory |
                Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'km\ntddk.h') } |
                Sort-Object Name -Descending | Select-Object -First 1
            if (-not $version) { continue }
            $kernelLib = Join-Path $cRoot "Lib\$($version.Name)\km\x64\ntoskrnl.lib"
            if (-not (Test-Path -LiteralPath $kernelLib)) { continue }
            return [pscustomobject]@{
                Root = $cRoot
                Version = $version.Name
                Headers = Join-Path $version.FullName 'km\ntddk.h'
                KernelLib = $kernelLib
            }
        }
    }
    return $null
}

$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$ci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction SilentlyContinue
$projectRoot = Split-Path -Parent $PSScriptRoot
$wdk = Find-Wdk

if (-not $DriverPath) {
    $DriverPath = Join-Path $projectRoot 'native\kernel\bin\CacKernel.sys'
}

$mapperHints = @(Find-MapperHints @(
    (Join-Path $projectRoot 'native'),
    (Join-Path $projectRoot 'scripts')
))
$driver = Get-FileRecord $DriverPath
$manifestPath = Join-Path (Split-Path -Parent $DriverPath) 'CacKernel.sha256'
$declaredHash = if (Test-Path -LiteralPath $manifestPath) {
    (Get-Content -LiteralPath $manifestPath -Raw).Trim().ToUpperInvariant()
} else { $null }
$hashMatch = [bool]($driver.present -and $declaredHash -and $declaredHash -eq $driver.sha256)
$installedDriverPath = Join-Path $env:SystemRoot 'System32\drivers\CacKernel.sys'
$installedDriver = Get-FileRecord $installedDriverPath
$installedHashMatch = [bool]($driver.present -and $installedDriver.present -and
    $installedDriver.sha256 -eq $driver.sha256)

$service = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='CacKernel'" -ErrorAction SilentlyContinue
$serviceState = if ($service) { [string]$service.State } else { 'Absent' }
$serviceInstalled = $serviceState -ne 'Absent'

$installEvidencePath = Join-Path $env:USERPROFILE '.cac\kernel\driver-install.json'
$installEvidence = $null
if (Test-Path -LiteralPath $installEvidencePath) {
    try { $installEvidence = Get-Content -LiteralPath $installEvidencePath -Raw | ConvertFrom-Json } catch { $installEvidence = $null }
}
$smokeVerified = [bool](
    $installEvidence -and
    $installEvidence.smoke -and
    $installEvidence.smoke.exitCode -eq 0 -and
    $installEvidence.driver -and
    $installEvidence.driver.sha256 -eq $driver.sha256 -and
    $installEvidence.smoke.output -and
    $installEvidence.smoke.output.notifyRegistered -eq 1 -and
    $installEvidence.smoke.output.capabilities -band 8
)
$lifecycleVerified = [bool]($smokeVerified -and
    $installEvidence.smoke.output.notifyRegistered -eq 1 -and
    ($installEvidence.smoke.output.capabilities -band 8))

$status = 'NOT_IMPLEMENTED'
$capability = 'NOT_IMPLEMENTED'
if ($driver.present) {
    if (-not $hashMatch) {
        $status = 'HASH_MISMATCH'
        $capability = 'DRIVER_INVALID'
    } elseif ($driver.signatureStatus -ne 'Valid') {
        $status = 'BUILT_UNSIGNED'
        $capability = 'DRIVER_INVALID'
    } elseif (-not $installedHashMatch) {
        $status = 'INSTALLED_HASH_MISMATCH'
        $capability = 'DRIVER_INVALID'
    } elseif (-not $serviceInstalled) {
        $status = 'SIGNED_DRIVER_READY'
        $capability = 'CONTROL_PLANE_READY'
    } elseif ($serviceState -ne 'Running') {
        $status = 'SERVICE_INSTALLED'
        $capability = 'CONTROL_PLANE_READY'
    } elseif ($smokeVerified -and $lifecycleVerified) {
        $status = 'RUNNING_VERIFIED'
        $capability = 'CONTROL_PLANE_ONLY'
    } else {
        $status = 'RUNNING_UNVERIFIED'
        $capability = 'CONTROL_PLANE_ONLY'
    }
}

$result = [ordered]@{
    timestampUtc = [DateTime]::UtcNow.ToString('o')
    policy = [ordered]@{
        loader = 'scm-inf'
        manualMapper = 'rejected'
        vulnerableDriver = 'rejected'
        dsePatch = 'rejected'
        patchGuardPatch = 'rejected'
    }
    os = [ordered]@{
        caption = $os.Caption
        version = $os.Version
        build = $cv.CurrentBuildNumber
        ubr = $cv.UBR
        architecture = $os.OSArchitecture
    }
    integrity = [ordered]@{
        vbs = if ($dg) { $dg.VirtualizationBasedSecurityStatus } else { $null }
        hvci = if ($dg) { $dg.CodeIntegrityPolicyEnforcementStatus } else { $null }
        vulnerableDriverBlocklistEnable = if ($ci) { $ci.VulnerableDriverBlocklistEnable } else { $null }
        testSigning = Get-BcdValue 'testsigning'
        noIntegrityChecks = Get-BcdValue 'nointegritychecks'
    }
    wdk = [ordered]@{
        root = if ($wdk) { $wdk.Root } else { $null }
        headers = [bool]($wdk -and (Test-Path -LiteralPath $wdk.Headers))
        kernelLib = [bool]($wdk -and (Test-Path -LiteralPath $wdk.KernelLib))
        version = if ($wdk) { $wdk.Version } else { $null }
    }
    repository = [ordered]@{
        mapperHints = $mapperHints
        mapperHintsCount = $mapperHints.Count
        kernelSysPresent = @(
            Get-ChildItem -LiteralPath (Join-Path $projectRoot 'native') -Recurse -File -Filter '*.sys' -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName
        )
    }
    driver = [ordered]@{
        present = $driver.present
        path = $driver.path
        length = $driver.length
        sha256 = $driver.sha256
        declaredSha256 = $declaredHash
        hashMatch = $hashMatch
        signatureStatus = $driver.signatureStatus
        authenticodeStatus = $driver.authenticodeStatus
        kernelPolicyStatus = $driver.kernelPolicyStatus
        signer = $driver.signer
        serviceName = 'CacKernel'
        serviceState = $serviceState
        serviceInstalled = $serviceInstalled
        smokeVerified = $smokeVerified
        lifecycleVerified = $lifecycleVerified
        installed = $installedDriver
        installedHashMatch = $installedHashMatch
        productionKernelPolicyReady = $driver.kernelPolicyStatus -eq 'Valid'
        installEvidence = $installEvidencePath
    }
    capability = $capability
    status = $status
    notes = @(
        'WDK availability is not proof that a kernel driver exists or is loaded.'
        'A signed driver must be installed through the approved SCM/INF path.'
        'Manual mapping and vulnerable-driver loading are rejected by project policy.'
        'RUNNING_VERIFIED proves the Authenticode-valid control-plane IOCTL, installed-file hash, per-PID policy, lifecycle callback, and audit smoke test.'
        'kernelPolicyStatus=TestSigned means local test-signing mode; it is not Microsoft production kernel-policy validation.'
        'The driver does not spoof CPUID, SMBIOS, NICs, disks, firmware, or DPAPI; it is not hardware isolation.'
    )
}

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$result | ConvertTo-Json -Depth 10
Write-Host "Evidence: $OutputPath" -ForegroundColor DarkGray

if ($Strict -and $result.status -ne 'RUNNING_VERIFIED') {
    Write-Host '[FAIL] Signed driver is not installed and smoke-verified.' -ForegroundColor Red
    exit 1
}
Write-Host ("[{0}] Kernel boundary policy: {1}" -f $result.status, $result.policy.loader) -ForegroundColor Yellow
