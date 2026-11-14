# CacMacLwf VM install (run as Administrator inside the VM).
# Stage A target: Win10 22H2 / any Win10+ NDIS 6 host.
# Stage B target: Win11 23H2 22631 (crash repro, same build as the host).
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run as Administrator.'
    }
}

Assert-Admin

# 1. Trust the test certificate.
certutil -addstore Root (Join-Path $root 'cac-test.cer') | Out-Null
certutil -addstore TrustedPublisher (Join-Path $root 'cac-test.cer') | Out-Null

# 2. Driver binary + kernel service.
Copy-Item -LiteralPath (Join-Path $root 'CacMacLwf.sys') `
    -Destination (Join-Path $env:SystemRoot 'System32\drivers\CacMacLwf.sys') -Force
sc.exe create CacMacLwf type= kernel start= demand error= normal `
    binPath= "\SystemRoot\System32\drivers\CacMacLwf.sys" `
    DisplayName= "CAC Profile MAC Lightweight Filter" 2>&1 | Out-Null

# 3. Register + bind the filter component (requires a signed catalog).
$bind = & netcfg -l (Join-Path $root 'CacMacLwf.inf') -c s -i CacMacLwf 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "netcfg failed: $($bind -join ' ')"
}

Write-Host 'Installed. Rebooting in 10 seconds for binding activation.'
shutdown /r /t 10
