[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,

    [string]$MacAddress,

    [string]$GuestUser = 'Administrator',
    [SecureString]$GuestPassword,
    [string]$GuestNic = 'Ethernet0',
    [string]$ResultPath = (Join-Path $PSScriptRoot 'vm-mac-result.json'),

    [switch]$Rollback,
    [switch]$ForceStop,
    [switch]$SkipGuestCleanup
)

$ErrorActionPreference = 'Stop'

function Get-VmrunPath {
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $candidate = Join-Path $programFilesX86 'VMware\VMware Workstation\vmrun.exe'
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }

    $command = Get-Command vmrun.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw 'vmrun.exe was not found.'
}

function Convert-SecureStringToPlainText {
    param([Parameter(Mandatory = $true)][SecureString]$Value)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-RunningVmPaths {
    $output = & $script:Vmrun -T ws list 2>&1
    return @($output | Where-Object { $_ -match '\.vmx$' } | ForEach-Object { $_.Trim() })
}

function Test-VmRunning {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    return @(Get-RunningVmPaths | Where-Object { $_ -ieq $full }).Count -gt 0
}

function Stop-VmAndWait {
    param([Parameter(Mandatory = $true)][string]$Path)

    & $script:Vmrun -T ws stop $Path soft | Out-Null
    $deadline = (Get-Date).AddSeconds(120)
    while ((Test-VmRunning -Path $Path) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
    }

    if (Test-VmRunning -Path $Path) {
        throw 'VM did not power off within 120 seconds.'
    }
}

function Restore-VmxBackup {
    param([Parameter(Mandatory = $true)][string]$Path)

    $backup = Get-ChildItem -LiteralPath (Split-Path -Parent $Path) -Filter ((Split-Path -Leaf $Path) + '.bak-*') -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $backup) {
        throw "No VMX backup found next to $Path"
    }

    Copy-Item -LiteralPath $backup.FullName -Destination $Path -Force
    Write-Host "Restored VMX backup: $($backup.FullName)"
}

function Convert-MacToHex {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -notmatch '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$') {
        throw "Invalid MAC address: $Value"
    }

    $hex = ($Value -replace '[:-]', '').ToUpperInvariant()
    $firstOctet = [Convert]::ToByte($hex.Substring(0, 2), 16)
    if (($firstOctet -band 1) -ne 0) {
        throw "Multicast MAC is not allowed: $Value"
    }

    return [pscustomobject]@{
        Colon = ($hex -replace '(..)(?=.)', '$1:').ToLowerInvariant()
        Hex   = $hex
    }
}

function Set-VmxStaticMac {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ColonMac
    )

    $lines = Get-Content -LiteralPath $Path
    $output = New-Object System.Collections.Generic.List[string]
    $addressWritten = $false

    foreach ($line in $lines) {
        if ($line -match '^ethernet0\.addressType\s*=') {
            $output.Add('ethernet0.addressType = "static"')
            if (-not $addressWritten) {
                $output.Add("ethernet0.address = `"$ColonMac`"")
                $addressWritten = $true
            }
            continue
        }

        if ($line -match '^ethernet0\.address\s*=') {
            if (-not $addressWritten) {
                $output.Add("ethernet0.address = `"$ColonMac`"")
                $addressWritten = $true
            }
            continue
        }

        if ($line -match '^ethernet0\.(generatedAddress|generatedAddressOffset)\s*=') {
            continue
        }

        $output.Add($line)
    }

    if (-not $addressWritten) {
        $output.Add('ethernet0.addressType = "static"')
        $output.Add("ethernet0.address = `"$ColonMac`"")
    }

    [IO.File]::WriteAllLines($Path, $output, (New-Object Text.UTF8Encoding($false)))
}

function Wait-VmwareTools {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$User,
        [Parameter(Mandatory = $true)][string]$Password,
        [int]$TimeoutSeconds = 180
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = (& $script:Vmrun -T ws -gu $User -gp $Password checkToolsState $Path 2>&1) -join ' '
        if ($state -match 'running') {
            return $true
        }
        Start-Sleep -Seconds 3
    }

    return $false
}

function Invoke-GuestVerify {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$User,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$Nic,
        [Parameter(Mandatory = $true)][string]$LocalResultPath,
        [switch]$ClearNetworkAddress
    )

    $nicB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Nic))
    $clear = if ($ClearNetworkAddress) { '$true' } else { '$false' }
    $guestScript = @'
$ErrorActionPreference = 'Stop'
$nic = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__NIC_B64__'))
$clearNetworkAddress = __CLEAR__
if ($clearNetworkAddress) {
    Remove-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword 'NetworkAddress' -NoRestart -Confirm:$false -ErrorAction SilentlyContinue
    Restart-NetAdapter -Name $nic -Confirm:$false
}
Start-Sleep -Seconds 5
$deadline = (Get-Date).AddSeconds(60)
do { Start-Sleep -Seconds 2; $adapter = Get-NetAdapter -Name $nic -ErrorAction SilentlyContinue } while (($null -eq $adapter -or $adapter.Status -ne 'Up') -and (Get-Date) -lt $deadline)
$advanced = Get-NetAdapterAdvancedProperty -Name $nic -RegistryKeyword 'NetworkAddress' -ErrorAction SilentlyContinue |
    Select-Object DisplayName, RegistryKeyword, DisplayValue, RegistryValue
$wmi = Get-CimInstance Win32_NetworkAdapter -Filter 'NetEnabled=True' |
    Select-Object Name, MACAddress, PNPDeviceID
$pnp = Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
    Where-Object FriendlyName -eq 'Intel(R) 82574L Gigabit Network Connection' |
    Select-Object Status, Problem, FriendlyName, InstanceId
$duid = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name Dhcpv6DUID -ErrorAction SilentlyContinue).Dhcpv6DUID
$duidHex = if ($duid) { ($duid | ForEach-Object { '{0:X2}' -f $_ }) -join '-' } else { $null }
$ipconfig = (& ipconfig.exe /all 2>&1 | Out-String)
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$os = Get-CimInstance Win32_OperatingSystem
$service = Get-CimInstance Win32_SystemDriver -Filter "Name='CacMacLwf'" -ErrorAction SilentlyContinue |
    Select-Object Name, State, StartMode
[pscustomobject]@{
    ok = $true
    time = (Get-Date).ToString('o')
    user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    build = $cv.CurrentBuild
    ubr = $cv.UBR
    lastBoot = $os.LastBootUpTime
    adapter = $adapter | Select-Object Name, Status, MacAddress, InterfaceDescription, ifIndex, InterfaceGuid
    networkAddress = $advanced
    wmi = @($wmi)
    pnp = @($pnp)
    dhcpv6Duid = $duidHex
    autoLogin = [pscustomobject]@{ AutoAdminLogon = $wl.AutoAdminLogon; DefaultUserName = $wl.DefaultUserName; ForceAutoLogon = $wl.ForceAutoLogon }
    cacMacLwf = $service
    ipconfig = $ipconfig
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'C:\Windows\Temp\cac-vm-mac.json' -Encoding UTF8
'@
    $guestScript = $guestScript.Replace('__NIC_B64__', $nicB64).Replace('__CLEAR__', $clear)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($guestScript))

    & $script:Vmrun -T ws -gu $User -gp $Password runProgramInGuest $Path -activeWindow `
        'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        '-NoProfile' '-NonInteractive' '-ExecutionPolicy' 'Bypass' '-EncodedCommand' $encoded | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Guest verification failed with exit code $LASTEXITCODE"
    }

    $directory = Split-Path -Parent $LocalResultPath
    if ($directory) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    & $script:Vmrun -T ws -gu $User -gp $Password CopyFileFromGuestToHost $Path 'C:\Windows\Temp\cac-vm-mac.json' $LocalResultPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy guest result with exit code $LASTEXITCODE"
    }

    return (Get-Content -LiteralPath $LocalResultPath -Raw | ConvertFrom-Json)
}

if (-not (Test-Path -LiteralPath $VmxPath)) {
    throw "VMX not found: $VmxPath"
}

$script:Vmrun = Get-VmrunPath
$fullVmxPath = [IO.Path]::GetFullPath($VmxPath)
$isRunning = Test-VmRunning -Path $fullVmxPath

if ($Rollback) {
    if ($isRunning) {
        if (-not $ForceStop) {
            throw 'VM is running. Re-run with -ForceStop to roll back.'
        }
        Stop-VmAndWait -Path $fullVmxPath
    }
    Restore-VmxBackup -Path $fullVmxPath
    return
}

if (-not $MacAddress) {
    throw '-MacAddress is required unless -Rollback is used.'
}

$mac = Convert-MacToHex -Value $MacAddress

if ($isRunning) {
    if (-not $ForceStop) {
        throw 'VM is running. Shut it down or re-run with -ForceStop.'
    }
    Stop-VmAndWait -Path $fullVmxPath
}

$backupPath = "$fullVmxPath.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -LiteralPath $fullVmxPath -Destination $backupPath -Force
Set-VmxStaticMac -Path $fullVmxPath -ColonMac $mac.Colon
Write-Host "VMX static MAC set to $($mac.Colon); backup: $backupPath"

& $script:Vmrun -T ws start $fullVmxPath nogui | Out-Null
if ($LASTEXITCODE -ne 0) {
    Restore-VmxBackup -Path $fullVmxPath
    throw "VM failed to start with the new MAC; VMX restored from backup."
}

$result = [ordered]@{
    ok              = $false
    clean           = $false
    time            = (Get-Date).ToString('o')
    vmx             = $fullVmxPath
    mac             = $mac.Colon
    backup          = $backupPath
    guest           = $null
    residualWarning = $null
}

if ($GuestPassword -and -not $SkipGuestCleanup) {
    $plainPassword = Convert-SecureStringToPlainText -Value $GuestPassword
    if (-not (Wait-VmwareTools -Path $fullVmxPath -User $GuestUser -Password $plainPassword)) {
        throw 'VMware Tools did not become ready; check the VM console.'
    }

    $result.guest = Invoke-GuestVerify -Path $fullVmxPath -User $GuestUser -Password $plainPassword `
        -Nic $GuestNic -LocalResultPath $ResultPath -ClearNetworkAddress

    $adapterMac = [string]$result.guest.adapter.MacAddress
    if (($adapterMac -replace '[:-]', '').ToUpperInvariant() -ne $mac.Hex) {
        $result.residualWarning = "Guest adapter reports $adapterMac, expected $($mac.Colon)"
    }
    else {
        $result.ok = $true
    }

    $pnpInstance = @($result.guest.pnp)[0].InstanceId
    if ($result.ok -and [string]$pnpInstance -and ([string]$pnpInstance) -notmatch $mac.Hex) {
        $result.residualWarning = 'PnP InstanceId does not contain the new MAC; a retrofitted VM can retain the original PCI serial. Rebuild the VM for a clean serial.'
    }
}
else {
    $result.residualWarning = 'Guest cleanup skipped; run again with -GuestPassword to verify NDIS/WMI/ipconfig.'
}

$result.clean = $result.ok -and [string]::IsNullOrEmpty($result.residualWarning)
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
$result | ConvertTo-Json -Depth 8
