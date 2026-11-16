param(
    [ValidateSet('all', 'info', 'setup')]
    [string]$Only = 'all'
)

$ErrorActionPreference = 'Stop'

$typeDefinition = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class ProbeRow {
    public string Source { get; set; }
    public string Name { get; set; }
    public string Mac { get; set; }
    public string Detail { get; set; }
}

public static class ApiProbe {
    [DllImport("iphlpapi.dll", CharSet = CharSet.Ansi)]
    private static extern uint GetAdaptersInfo(IntPtr info, ref uint size);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct IP_ADAPTER_INFO {
        public IntPtr Next;
        public uint ComboIndex;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string AdapterName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 132)]
        public string Description;
        public uint AddressLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Address;
        public uint Index;
        public uint Type;
        public uint DhcpEnabled;
    }

    public static ProbeRow[] GetAdaptersInfoRows() {
        var rows = new List<ProbeRow>();
        uint size = 0;
        uint ret = GetAdaptersInfo(IntPtr.Zero, ref size);
        if (ret != 111 && ret != 0) {
            throw new Exception("GetAdaptersInfo size failed: " + ret);
        }

        IntPtr buffer = Marshal.AllocHGlobal((int)size);
        try {
            ret = GetAdaptersInfo(buffer, ref size);
            if (ret != 0) {
                throw new Exception("GetAdaptersInfo failed: " + ret);
            }

            IntPtr current = buffer;
            while (current != IntPtr.Zero) {
                var adapter = (IP_ADAPTER_INFO)Marshal.PtrToStructure(current, typeof(IP_ADAPTER_INFO));
                string mac = "";
                if (adapter.Address != null && adapter.AddressLength > 0) {
                    int length = Math.Min((int)adapter.AddressLength, adapter.Address.Length);
                    var bytes = new byte[length];
                    Array.Copy(adapter.Address, bytes, length);
                    mac = BitConverter.ToString(bytes).Replace("-", ":");
                }
                rows.Add(new ProbeRow {
                    Source = "GetAdaptersInfo",
                    Name = adapter.Description,
                    Mac = mac,
                    Detail = adapter.AdapterName
                });
                current = adapter.Next;
            }
        }
        finally {
            Marshal.FreeHGlobal(buffer);
        }
        return rows.ToArray();
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, uint memberIndex, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetupDiGetDeviceInstanceId(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, StringBuilder deviceInstanceId, uint deviceInstanceIdSize, out uint requiredSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    public static ProbeRow[] GetSetupApiRows() {
        var rows = new List<ProbeRow>();
        Guid netClass = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
        IntPtr set = SetupDiGetClassDevs(ref netClass, IntPtr.Zero, IntPtr.Zero, 0x2);
        if (set == new IntPtr(-1)) {
            throw new Exception("SetupDiGetClassDevs failed: " + Marshal.GetLastWin32Error());
        }

        try {
            uint index = 0;
            var data = new SP_DEVINFO_DATA();
            data.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
            while (SetupDiEnumDeviceInfo(set, index, ref data)) {
                var buffer = new StringBuilder(1024);
                uint required = 0;
                if (SetupDiGetDeviceInstanceId(set, ref data, buffer, (uint)buffer.Capacity, out required)) {
                    rows.Add(new ProbeRow {
                        Source = "SetupAPI",
                        Name = "",
                        Mac = "",
                        Detail = buffer.ToString()
                    });
                }
                data = new SP_DEVINFO_DATA();
                data.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
                index++;
            }
        }
        finally {
            SetupDiDestroyDeviceInfoList(set);
        }
        return rows.ToArray();
    }
}
'@

Add-Type -TypeDefinition $typeDefinition -Language CSharp

$rows = New-Object System.Collections.Generic.List[object]
if ($Only -in @('all', 'info')) {
    foreach ($row in [ApiProbe]::GetAdaptersInfoRows()) { $rows.Add($row) }
}
if ($Only -in @('all', 'setup')) {
    foreach ($row in [ApiProbe]::GetSetupApiRows()) { $rows.Add($row) }
}

Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object {
    $rows.Add([pscustomobject]@{
        Source = 'Get-NetAdapter'
        Name   = $_.Name
        Mac    = $_.MacAddress
        Detail = "$($_.InterfaceDescription) status=$($_.Status) index=$($_.ifIndex)"
    })
}

$getmacRows = (& getmac.exe /v /fo csv 2>&1) | ConvertFrom-Csv -ErrorAction SilentlyContinue
foreach ($row in $getmacRows) {
    $values = @($row.PSObject.Properties | ForEach-Object { $_.Value })
    if ($values.Count -ge 3) {
        $rows.Add([pscustomobject]@{
            Source = 'getmac'
            Name   = $values[0]
            Mac    = $values[2]
            Detail = $values[1]
        })
    }
}

Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object MacAddress | ForEach-Object {
    $rows.Add([pscustomobject]@{
        Source = 'WMI'
        Name   = $_.Name
        Mac    = $_.MACAddress
        Detail = $_.PNPDeviceID
    })
}

$duid = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name Dhcpv6DUID -ErrorAction SilentlyContinue).Dhcpv6DUID
$duidHex = if ($duid) { ($duid | ForEach-Object { '{0:X2}' -f $_ }) -join '-' } else { $null }
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$service = Get-CimInstance Win32_SystemDriver -Filter "Name='CacMacLwf'" -ErrorAction SilentlyContinue |
    Select-Object Name, State, StartMode

$result = @{}
$result['time'] = (Get-Date).ToString('o')
$result['computer'] = $env:COMPUTERNAME
$result['user'] = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$result['build'] = $cv.CurrentBuild
$result['ubr'] = $cv.UBR
$result['duid'] = $duidHex
$result['autoLogin'] = @{
    AutoAdminLogon = $wl.AutoAdminLogon
    DefaultUserName = $wl.DefaultUserName
    ForceAutoLogon = $wl.ForceAutoLogon
}
$result['cacMacLwf'] = $service
$result['rows'] = $rows.ToArray()

$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'C:\Windows\Temp\cac-api-probe.json' -Encoding UTF8
