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

function Quote-CertutilArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-CertutilSilent {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int]$TimeoutMilliseconds = 15000
    )

    $certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
    if (-not (Test-Path -LiteralPath $certutil -PathType Leaf)) {
        return [pscustomobject]@{ ExitCode = -1; Output = ''; Error = "certutil not found: $certutil" }
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $certutil
    $startInfo.Arguments = ($Arguments | ForEach-Object { Quote-CertutilArgument -Value ([string]$_) }) -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            return [pscustomobject]@{ ExitCode = -1; Output = ''; Error = 'certutil process failed to start' }
        }
        # A hidden, redirected stdin prevents any certificate trust prompt from
        # waiting on an interactive console. The command remains non-interactive.
        try { $process.StandardInput.Close() } catch { }
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            try { $process.Kill() } catch { }
            try { $process.WaitForExit(2000) } catch { }
            return [pscustomobject]@{ ExitCode = -2; Output = ''; Error = "certutil timed out after $TimeoutMilliseconds ms" }
        }
        $output = ''
        $errorText = ''
        try { $output = $process.StandardOutput.ReadToEnd() } catch { }
        try { $errorText = $process.StandardError.ReadToEnd() } catch { }
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            Output = (($output, $errorText | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' ').Trim()
            Error = ''
        }
    } catch {
        return [pscustomobject]@{ ExitCode = -1; Output = ''; Error = $_.Exception.Message }
    } finally {
        try { $process.Dispose() } catch { }
    }
}

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
        $certutilResult = Invoke-CertutilSilent -Arguments @('-user', '-f', '-addstore', 'Root', $Path)
        if (Test-MitmCaInstalled -Thumbprint $expectedThumbprint) { return $true }
        $summary = [string]$certutilResult.Output
        if ($summary.Length -gt 240) { $summary = $summary.Substring(0, 240) }
        if (-not [string]::IsNullOrWhiteSpace([string]$certutilResult.Error)) {
            [void]$errors.Add("certutil: $($certutilResult.Error)")
        } elseif ([int]$certutilResult.ExitCode -ne 0) {
            [void]$errors.Add("certutil exit $($certutilResult.ExitCode): $summary")
        } elseif (-not [string]::IsNullOrWhiteSpace($summary)) {
            [void]$errors.Add("certutil did not publish the certificate: $summary")
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
    # Do not call certutil -delstore here. Windows can surface a Root-store
    # deletion confirmation for that operation even when the process is hidden.
    # Remove only the exact Profile thumbprint from HKCU, then verify the store.
    Remove-MitmCertificateRegistryEntry -Thumbprint $thumbprint
    return (@(Get-MitmCa | Where-Object {
        $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $thumbprint
    }).Count -eq 0)
}
