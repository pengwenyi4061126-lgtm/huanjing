# 硬件画像扩展证据（2026-11-16）

## 范围

在 `cowork-svc` 注入和 CPU flags/hooks 的基础上，补齐：

```text
主机内存总量/可用量
磁盘总容量/剩余空间
卷标/文件系统/卷序列号
CPU 核心数/逻辑处理器/主频/缓存
GPU 名称/显存/驱动版本
显示器名称/分辨率/刷新率/EDID
SMBIOS Type 1/2/3/4/9/10/11/12/13/16/17/39/41/42/43
ACPI/FIRM 固件表隐藏
驱动/模块枚举中的虚拟化组件过滤
WMI 数值/布尔/字符串字段
TPM WMI/TBS 可选隐藏
```

## 实现位置

```text
native/NativeBridge/Identity.h/.cpp
  新增 memory/disk/CPU/GPU/display/TPM/SMBIOS 字段和默认值

native/NativeBridge/ApiHooks.cpp
  GlobalMemoryStatusEx
  GetPhysicallyInstalledSystemMemory
  GetDiskFreeSpaceExW/A
  GetSystemInfo / GetNativeSystemInfo
  GetVolumeInformationW / ByHandle 的卷标/文件系统
  EnumSystemFirmwareTables + ACPI/FIRM hide
  EnumDisplayDevicesW / EnumDisplaySettingsW / GetMonitorInfoW
  EnumDeviceDrivers 的虚拟驱动过滤
  NtQuerySystemInformation class 11 的虚拟模块过滤
  RegQueryValueExW/RegGetValueW 的 EDID
  TBS 可选 Hook

native/NativeBridge/WmiHooks.cpp
  数值/布尔 VARIANT 支持
  内存/磁盘/CPU/GPU/显示器/TPM/网络适配器规则

native/NativeBridge/Firmware.cpp
  SMBIOS 扩展类型与字段

native/HardwareProbe/main.cpp
  基线/注入 A/B 硬件探针
```

## 基线 vs Profile A/B

`baseline-hardware.txt` 是本机未注入真实值；
`profile-a-hardware.txt` 是 desktop-1；
`profile-b-hardware.txt` 是 desktop-b。

| 面 | 基线真实值 | Profile A | Profile B |
|---|---|---|---|
| 内存 | 32589 MB / 16777 MB | 16384 / 12288 MB | 32768 / 24576 MB |
| 物理内存 | 32768 MB | 16384 MB | 32768 MB |
| 磁盘 | 80 GB / 16 GB | 512 / 256 GB | 1024 / 768 GB |
| 卷标 | Win10EntNLTSC2019 X64 | System | SystemB |
| 卷序列号 | 186a3a24 | 18e541cf | bbbbbbbb |
| 处理器数 | 24 | 8 | 16 |
| 显示 | 1440x900@75 | 1920x1080@60 | 2560x1440@144 |
| GPU | NVIDIA GTX 1050 Ti | Generic Display Adapter | Generic GPU B |
| GPU 显存 | 真实 | 128 MB | 4096 MB（WMI clamp 为 0xFFFFFFFF） |
| SMBIOS Type 17 | 144F4681 / M393B2G70QH0-YK0 | SYS674a... / Generic DDR / 8192 MB | SYSbbbb... / Generic DDR / 16384 MB |

## WMI 数值/布尔字段

`profile-a-wmi.txt` / `profile-b-wmi.txt` 来自 `artifacts/wmi_probe.exe`
（C++ `IWbemLocator`，与 `wmi_probe.cpp` 同源）。

| 字段 | Profile A | Profile B |
|---|---|---|
| `Win32_ComputerSystem.TotalPhysicalMemory` | 17179869184 | 34359738368 |
| `Win32_ComputerSystem.HypervisorPresent` | false | false |
| `Win32_OperatingSystem.TotalVisibleMemorySize` | 16777216 KB | 33554432 KB |
| `Win32_OperatingSystem.FreePhysicalMemory` | 12582912 KB | 25165824 KB |
| `Win32_LogicalDisk.Size` | 549755813888 | 1099511627776 |
| `Win32_LogicalDisk.FreeSpace` | 274877906944 | 824633720832 |
| `Win32_LogicalDisk.VolumeName` | System | SystemB |
| `Win32_DiskDrive.Size` | 549755813888 | 1099511627776 |
| `Win32_PhysicalMemory.Capacity` | 8589934592 | 17179869184 |
| `Win32_PhysicalMemory.Speed` | 3200 | 2933 |
| `Win32_Processor.NumberOfCores` | 4 | 8 |
| `Win32_Processor.NumberOfLogicalProcessors` | 8 | 16 |
| `Win32_Processor.MaxClockSpeed` | 3000 | 3600 |
| `Win32_VideoController.Name` | Generic Display Adapter | Generic GPU B |
| `Win32_VideoController.AdapterRAM` | 134217728 | 4294967295 |
| `Win32_VideoController.DriverVersion` | 1.0.0.0 | 2.0.0.0 |
| `Win32_NetworkAdapter.Name` | Generic Ethernet Adapter | Generic Ethernet Adapter |

## 固件 / SMBIOS / 显示 / 驱动

`profile-a-hardware.txt` / `profile-b-hardware.txt`：

```text
smbios_size=4496
smbios_type1_serial=<profile system serial>
smbios_type4_version=Generic x64 Processor / Generic B Processor
smbios_type17_serial=<profile serial prefix>
smbios_type17_part=Generic DDR
smbios_type17_size=8192 / 16384
acpi_size=0          # 基线为 268
edid_status=0 type=3 size=128 head=00ffffffffffff00
drivers=190          # 基线 191，过滤 1 个虚拟化驱动
modules=190          # 基线 191，过滤 1 个虚拟化模块
```

`service-install-audit.jsonl` 证明服务 PID 25236 内：

```text
api.install complete failures=0
GlobalMemoryStatusEx / GetPhysicallyInstalledSystemMemory / GetDiskFreeSpaceExW/A
GetSystemInfo / GetNativeSystemInfo / EnumSystemFirmwareTables
K32EnumDeviceDrivers
cpu.manifest complete entries=4 installed=4
cpu.flags neutralized
native.bridge ready
```

## 边界

- **TPM**：WMI `Win32_Tpm` 规则和 TBS 可选 Hook 已接入；本机没有 TPM
  实例，未取得 live A/B。真实 TPM quote 是密码学证明，用户态 Hook
  不能伪造，只能隐藏/拒绝查询；完整等价需要 vTPM。
- **SetupDi/PNP**：虚拟设备（VMBUS/VEN_1414/Hyper-V/WSL 等）在
  `profile` 下隐藏实例 ID/属性；真实 PCI/GPU/显示器属性仍透传，
  尚未生成完整合成 PnP 图。
- **网络适配器名称**：WMI 名称已泛化，但 `GetAdaptersAddresses`
  的 `FriendlyName/Description` 仍可能返回真实网卡名。
- **GPU 深层接口**：DXGI `GetDesc`、NVAPI/ADL、DisplayConfig EDID
  尚未 Hook；当前覆盖 WMI/EnumDisplay/EDID 注册表。
- **CPUID**：仅 4 个 Go ABI 入口 + flags；`0x79356/0x79381/0x170BBD/0x504C4F`
  仍未按 ABI 分类挂载。
- **PowerShell/.NET WMI**：注入后的 Windows PowerShell `Get-WmiObject`
  会 0xC0000005 崩溃；C++ `IWbemLocator` probe 正常。该问题在关闭
  WMI 数值 spoof 后仍存在，暂按既有 .NET/WMI 兼容缺口记录，不作为
  已覆盖证据。

## 文件

```text
baseline-hardware.txt
profile-a-hardware.txt
profile-b-hardware.txt
profile-a-wmi.txt
profile-b-wmi.txt
service-install-audit.jsonl
hashes.txt
```
