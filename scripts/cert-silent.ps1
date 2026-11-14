#requires -Version 5.1

function Get-MitmCa {
    $store = $null
    try {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        return @($store.Certificates | Where-Object { $_.Subject -match 'mitmproxy' })
    } catch {
        return @()
    } finally {
        if ($null -ne $store) {
            try { $store.Close() } catch { }
            try { $store.Dispose() } catch { }
        }
    }
}

function Remove-MitmCertificateRegistryEntry {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::CurrentUser,
        [Microsoft.Win32.RegistryView]::Default)
    $parent = $null
    try {
        $parent = $base.OpenSubKey(
            'Software\Microsoft\SystemCertificates\Root\Certificates',
            $true)
        if ($null -ne $parent) {
            try { $parent.DeleteSubKey($Thumbprint, $false) } catch [ArgumentException] { }
        }
    } finally {
        if ($parent) { $parent.Close() }
        if ($base) { $base.Close() }
    }
}

function Get-CertificateThumbprintFromFile {
    param([string]$Path)
    try {
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path)
        return $certificate.Thumbprint.Replace(' ', '').ToUpperInvariant()
    } catch {
        return $null
    }
}

function Test-MitmCaInstalled {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    $normalized = $Thumbprint.Replace(' ', '').ToUpperInvariant()
    return (@(Get-MitmCa | Where-Object {
        $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $normalized
    }).Count -gt 0)
}

$script:MitmCaInstallError = ''

function Install-MitmCa {
    param(
        [string]$Path,
        [int]$Attempts = 10,
        [int]$DelayMilliseconds = 250
    )

    $script:MitmCaInstallError = ''
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $script:MitmCaInstallError = "certificate file is missing: $Path"
        return $false
    }

    $attemptCount = [Math]::Max(1, $Attempts)
    $delay = [Math]::Max(50, $DelayMilliseconds)
    for ($attempt = 1; $attempt -le $attemptCount; $attempt++) {
        $expectedThumbprint = Get-CertificateThumbprintFromFile -Path $Path
        if ([string]::IsNullOrWhiteSpace($expectedThumbprint)) {
            $script:MitmCaInstallError = "certificate file is not readable yet (attempt $attempt/$attemptCount)"
            if ($attempt -lt $attemptCount) { Start-Sleep -Milliseconds $delay }
            continue
        }

        if (Test-MitmCaInstalled -Thumbprint $expectedThumbprint) { return $true }

        $errors = New-Object 'System.Collections.Generic.List[string]'
        try {
            Import-Module PKI -ErrorAction Stop
            Import-Certificate -FilePath $Path -CertStoreLocation Cert:\CurrentUser\Root -ErrorAction Stop | Out-Null
        } catch {
            [void]$errors.Add("Import-Certificate: $($_.Exception.Message)")
        }
        if (Test-MitmCaInstalled -Thumbprint $expectedThumbprint) { return $true }

        $certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
        if (Test-Path -LiteralPath $certutil -PathType Leaf) {
            try {
                $certutilOutput = @(& $certutil '-user' '-f' '-addstore' 'Root' $Path 2>&1)
                $certutilExitCode = $LASTEXITCODE
                if (Test-MitmCaInstalled -Thumbprint $expectedThumbprint) { return $true }
                $summary = (($certutilOutput | ForEach-Object { [string]$_ }) -join ' ').Trim()
                if ($summary.Length -gt 240) { $summary = $summary.Substring(0, 240) }
                if ($certutilExitCode -ne 0) {
                    [void]$errors.Add("certutil exit ${certutilExitCode}: $summary")
                } elseif (-not [string]::IsNullOrWhiteSpace($summary)) {
                    [void]$errors.Add("certutil did not publish the certificate: $summary")
                }
            } catch {
                [void]$errors.Add("certutil: $($_.Exception.Message)")
            }
        } else {
            [void]$errors.Add("certutil not found: $certutil")
        }

        if ($errors.Count -gt 0) {
            $script:MitmCaInstallError = ($errors -join ' | ')
        } else {
            $script:MitmCaInstallError = "certificate was not visible in CurrentUser\\Root after attempt $attempt/$attemptCount"
        }
        if ($attempt -lt $attemptCount) { Start-Sleep -Milliseconds $delay }
    }
    return $false
}

function Remove-MitmCa {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # A missing or unreadable profile certificate must never widen the delete
    # scope to every mitmproxy certificate in the user store.
    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Refusing mitmproxy CA removal: profile certificate is missing: $Path"
    }

    $thumbprint = Get-CertificateThumbprintFromFile -Path $Path
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        throw "Refusing mitmproxy CA removal: profile certificate is invalid or unreadable: $Path"
    }

    $certs = @(Get-MitmCa | Where-Object {
        $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $thumbprint
    })
    if ($certs.Count -eq 0) { return $true }
    Remove-MitmCertificateRegistryEntry -Thumbprint $thumbprint
    return (@(Get-MitmCa | Where-Object {
        $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $thumbprint
    }).Count -eq 0)
}
