# CacMacLwf VM 测试套件

两阶段验证，结论分阶段回灌：

## 当前 VM 事实（2026-11-16）

`D:\Downloads\vm\Windows 10 x64.vmx` 的名称与 Guest 实际版本不一致。通过
VMware Tools 读取到的 Guest 是 **Windows 11 专业版 23H2 / Build 22631.7376**，
因此它只能作为 Stage B 的 NDIS 崩溃复现环境，不能作为 Win10 稳定验收环境。

当前基线状态：

- VMware Tools：`running`。
- Guest 自动登录：`AutoAdminLogon=1`、`DefaultUserName=Administrator`、`ForceAutoLogon=1`。
- `Ethernet0`：Guest PnP 已从 `Problem 22` 恢复为 `OK`，状态为 `Up`。
- `CacMacLwf`：已安装但保持 `Stopped / Manual`，不在当前基线中启动。

## 先准备 Guest，再回滚或重启

使用 VMware Tools 直接执行，不依赖 VMware 窗口中的鼠标键盘。密码只在本次
PowerShell 进程内转换为 `vmrun -gp` 参数，不写入脚本或结果文件：

```powershell
$pw = Read-Host 'Guest password' -AsSecureString
.\prepare-vm.ps1 `
    -VmxPath 'D:\Downloads\vm\Windows 10 x64.vmx' `
    -GuestPassword $pw `
    -ResultPath '.\vm-prepare-result.json'
```

脚本会等待 VMware Tools、写入 Guest 自动登录项、启用 `Ethernet0`、采集系统和
驱动状态；只有需要验证重启登录时才追加 `-RebootAfterPrepare`。它不会启动
`CacMacLwf`，也不会在宿主机安装或加载 NDIS/LWF。

每次快照回滚后先执行该准备脚本，再进行任何驱动实验。

## MAC 层验证结果（2026-11-16，Build 22631.7376）

目标 MAC：`02:44:08:1a:18:33`（当前 CAC `profile-a` 的 `mac_address`）。

| 检查点 | 结果 |
| --- | --- |
| VMX `ethernet0.addressType` | `static` |
| VMX `ethernet0.address` | `02:44:08:1a:18:33` |
| Guest `NetworkAddress` | 空（已清除，确认 MAC 来自虚拟硬件） |
| `Get-NetAdapter` / WMI / `ipconfig /all` | 三处均为 `02-44-08-1A-18-33` |
| 整机重启后 | 仍为 `02-44-08-1A-18-33` |
| DHCPv6 DUID | 重启后变为 `...-02-44-08-1A-18-33` |
| 自动登录 | `1 / Administrator / 1`，重启后直接进桌面 |
| `CacMacLwf` | `Stopped / Manual`，未加载，无蓝屏 |
| PnP 实例 ID | 仍是 `...\000C29FFFFF2A9EA00`（原 VMware PCI 序列号） |

结论：

- MAC 本身在 VM 硬件层稳定，不依赖 `CacMacLwf`，也不依赖 Guest
  `NetworkAddress` 覆盖。
- 22631 上不稳定的不是“改 MAC”，而是 NDIS LWF 的 OID 完成链；
  因此 MAC 用 VMX 静态地址，LWF 保持停止。
- 改装现有 VM 会保留原 PCI 序列号。要彻底消除，必须在**首次安装
  Windows 之前**给新 VM 设好静态 MAC，或每个 Profile 重建 VM；新装后
  PnP 序列号、DUID、NDIS、WMI 才会从第一刻起一致。

### 原生 API 回读

`probe-api.ps1` 在 Guest 内用 `GetAdaptersInfo`、`SetupAPI`、`getmac`、WMI、
`Get-NetAdapter` 回读，结果写入 `C:\Windows\Temp\cac-api-probe.json`。本次结果在
`evidence\2026-11-16-06-api-probe.json`：

- `GetAdaptersInfo` / `getmac` / `Get-NetAdapter` / WMI：`02:44:08:1A:18:33`
- SetupAPI 实例 ID：`...\000C29FFFFF2A9EA00`（旧 PCI 序列号残留）
- DUID：`...-02-44-08-1A-18-33`

`GetAdaptersAddresses` 的 C# 结构体在当前 Guest 触发访问冲突，已从探针移除；
`getmac` 走同一 IP Helper 层，作为替代证据。

执行：

```powershell
$pw = Read-Host 'Guest password' -AsSecureString
.\set-vm-mac.ps1 `
    -VmxPath 'D:\Downloads\vm\Windows 10 x64.vmx' `
    -MacAddress '02:44:08:1a:18:33' `
    -GuestPassword $pw `
    -ForceStop `
    -ResultPath '.\vm-mac-result.json'
```

回滚最近一次 VMX 备份：

```powershell
.\set-vm-mac.ps1 `
    -VmxPath 'D:\Downloads\vm\Windows 10 x64.vmx' `
    -Rollback -ForceStop
```

脚本会备份 VMX、设置静态 MAC、清空 Guest `NetworkAddress`、回读三处 MAC，
并输出 `clean`。`clean=false` 表示 MAC 已生效但仍有 PnP 等硬件历史残留。
本次原始证据在 `evidence\2026-11-16-*.json`。

## Stage A（现有 Win10 22H2 VM 即可）

验证我们自己的代码：注册成功、模块附着、OID 重写计数、
MAC 设置回读、stop/start 安全、反复绑定。

```powershell
Copy-Item -Recurse 宿主机:\...\vmtest  VM内C:\cacvm
# VM 内（管理员）：
bcdedit /set testsigning on   # 然后重启一次
powershell -NoProfile -ExecutionPolicy Bypass -File C:\cacvm\vm-install.ps1
# 安装脚本会自动重启；重启后：
powershell -NoProfile -ExecutionPolicy Bypass -File C:\cacvm\vm-verify.ps1
```

判定：`registerStatus=0` 且 `attached>=1` 且 `oidRewrites` 随查询增长 =
我们的驱动在 Win10 上功能完整。这验证的是**驱动代码**。

## Stage B（Win11 23H2 22631 VM，与宿主机同构建号）

复现宿主机蓝屏（`AV_wfplwfs!LwfLowerOidRequestComplete`，
OID_PNP_SET_POWER 完成链 + 扩展栈守护页）。

1. Win11 23H2 安装 + 更新到 UBR 7376（与宿主机 winver 一致）。
2. 快照 clean。
3. 按 Stage A 同样步骤安装 + 重启。
4. 故意触发电源转换（睡眠/唤醒/禁用启用网卡），观察是否 2 分钟内
   复现 0x1E。
5. 复现 → 快照回滚 → 挂内核调试器再来一次抓现场；
   不复现 → 宿主机问题是环境特异性组合，回宿主机考虑只绑物理网卡。

## 判定出口

```text
Stage A 失败           → 修我们自己的代码（有快照，随便崩）
Stage A 通过 + B 通过   → LWF 本机可启用（保守：只绑物理网卡，不热卸载）
Stage A 通过 + B 复现   → NDIS/WFP 交互缺陷，拿 Stage B 现场找规避
                          （换绑定顺序 / 只绑物理网卡 / 放弃内核 MAC）
```

## 环境要求（重要教训）

- **必须用原版（未做任何去虚拟化/去VM标识/防封加固）的干净 VM。**
  加固类 VM 常改动 BCD、精简 KDCOM/串口组件，导致内核调试通道
  （串口/kdnet）和崩溃转储双双失效——实测：调试参数全对、网络全通，
  但目标从不发出 kdnet 探测包，蓝屏也不落转储。
- 新 VM 第一件事（改任何东西之前）：

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Value 3 -Type DWord
bcdedit /set testsigning on
```

- 崩溃转储 + 内核调试是排查内核问题的两条命脉，加固 VM 两者皆失。
