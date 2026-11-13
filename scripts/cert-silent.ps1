Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class CacDialog {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc proc, IntPtr param);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}
'@

function Confirm-CertificateDialog {
    $confirmed = $false
    $callback = [CacDialog+EnumProc]{
        param([IntPtr]$hWnd, [IntPtr]$lParam)
        if ([CacDialog]::IsWindowVisible($hWnd)) {
            $title = New-Object System.Text.StringBuilder 256
            $class = New-Object System.Text.StringBuilder 256
            [void][CacDialog]::GetWindowText($hWnd, $title, 256)
            [void][CacDialog]::GetClassName($hWnd, $class, 256)
            if ($class.ToString() -eq '#32770' -and
                $title.ToString() -match 'Security|安全|证书|警告|Warning') {
                [void][CacDialog]::PostMessage($hWnd, 0x0111, [IntPtr]6, [IntPtr]::Zero)
                $script:CertDialogConfirmed = $true
            }
        }
        return $true
    }
    $script:CertDialogConfirmed = $false
    [void][CacDialog]::EnumWindows($callback, [IntPtr]::Zero)
    return $script:CertDialogConfirmed
}

function Get-MitmCa {
    return @(Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match 'mitmproxy' })
}

function Install-MitmCa {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if ((Get-MitmCa).Count -gt 0) { return $true }
    $process = Start-Process -FilePath 'certutil.exe' `
        -ArgumentList @('-user', '-addstore', 'Root', $Path) `
        -PassThru -WindowStyle Hidden
    $deadline = (Get-Date).AddSeconds(25)
    while (-not $process.HasExited -and (Get-Date) -lt $deadline) {
        [void](Confirm-CertificateDialog)
        Start-Sleep -Milliseconds 200
    }
    if (-not $process.HasExited) {
        try { $process.Kill() } catch { }
    }
    return ((Get-MitmCa).Count -gt 0)
}

function Remove-MitmCa {
    $certs = @(Get-MitmCa)
    if ($certs.Count -eq 0) { return $true }
    foreach ($cert in $certs) {
        $process = Start-Process -FilePath 'certutil.exe' `
            -ArgumentList @('-user', '-delstore', 'Root', $cert.Thumbprint) `
            -PassThru -WindowStyle Hidden
        $deadline = (Get-Date).AddSeconds(15)
        while (-not $process.HasExited -and (Get-Date) -lt $deadline) {
            [void](Confirm-CertificateDialog)
            Start-Sleep -Milliseconds 200
        }
        if (-not $process.HasExited) {
            try { $process.Kill() } catch { }
        }
    }
    return ((Get-MitmCa).Count -eq 0)
}
