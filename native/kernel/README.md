# CAC 内核控制面（WDM）

当前状态：`RUNNING_VERIFIED`，能力级别 `STORAGE_FILTER_PLUS_CONTROL_PLANE`。这是一套**签名 WDM
控制面 + 身份过滤模块**：磁盘 IRP 过滤、内核级 SMBIOS 物理表重写（opt-in），
per-process 策略与审计环。CPUID/XGETBV 仍由用户态 manifest 精确 inline hook
覆盖（CPU 指令不产生 Ring-0 陷入，内核驱动原理上无法拦截）。

## 组件

| 文件 | 作用 |
|---|---|
| `CacKernel.c` | WDM 驱动：设备对象、5 个 IOCTL、per-PID 策略表、进程退出清理、审计环 |
| `IdentityFilter.c/h` | 磁盘 / SMBIOS 身份过滤模块 |
| `CacKernelIoctl.h` | 用户态/内核态共享 ABI，无指针、固定宽度 |
| `CacKernel.inf` | 遗留 INF 服务定义（SCM 安装是已验证路径） |
| `build-driver.ps1` | WDK 26100 编译、链接、测试签名、SHA-256 清单 |
| `install-driver.ps1` | 哈希/签名校验、SCM 安装、启动、冒烟、证据落盘 |
| `tools/cac-kernelctl.cpp` | 控制客户端：ping/register/unregister/query/audit/identity-set/module-state |
| `tests/kernel-smoke.cpp` | 端到端自检 |

## 驱动做了什么

```text
\Device\CacKernel
    -> DACL: SYSTEM + Administrators only
    -> IOCTL_PING            版本/能力/策略数/审计数
    -> IOCTL_POLICY_REGISTER  PID + 创建时间 + flags + 16 字节 profile id
    -> IOCTL_POLICY_UNREGISTER
    -> IOCTL_POLICY_QUERY
    -> IOCTL_AUDIT_QUERY     128 条环形审计记录
    -> IOCTL_IDENTITY_SET    身份 + 模块开关（协议 v2）
    -> IOCTL_MODULE_QUERY    模块状态/计数/重写统计
```

- 策略表上限 64 个 PID；注册时记录 `PsGetProcessCreateTimeQuadPart`，防止 PID 复用。
- 查询、注册和 ping 时用 `PsGetProcessExitStatus` 惰性清理已退出进程，并写 `event=6` 审计。
- 审计事件：驱动加载、设备创建、策略注册/注销/拒绝、进程退出清理、未知 IOCTL、通知注册状态。
- 驱动不含 SSDT/IDT/inline hook，不触碰 PatchGuard 关心的结构。
- 本机测试签名构建会先尝试 `PsSetCreateProcessNotifyRoutineEx`，失败时回退到兼容的 `PsSetCreateProcessNotifyRoutine`；smoke 必须看到 `notifyRegistered=1` 和 `CAC_CAP_PROCESS_LIFECYCLE`，否则审计不再把控制面标记为完整。
- NativeBridge 在每个注入进程内执行 register/query 回读；`-RequireKernel` 会在设备不可用、策略注册失败或回读不一致时拒绝 `ready`。

## 身份过滤模块（非 VM 上限）

`IdentityFilter.c` 实现三个模块，全部受 `CAC_IOCTL_IDENTITY_SET` 控制：

```text
storage filter
    -> 通过 GUID_DEVINTERFACE_DISK 枚举磁盘类设备，附加过滤设备
    -> 拦截 IOCTL_STORAGE_QUERY_PROPERTY 完成例程
    -> 对策略表内 PID 重写 StorageDeviceProperty 的
       Vendor/Product/Revision/Serial 字符串（只缩短、原位零填充）
    -> STRICT_EMPTY 策略清空字符串并清零 StorageDeviceUniqueIdProperty 偏移

smbios rewrite
    -> 在 ntoskrnl 镜像中扫描 (物理地址, 长度) 全局变量对
    -> MmMapIoSpace 映射候选并做 SMBIOS 结构走查校验（含 __try 保护）
    -> 对 Win 启动时缓存的物理 SMBIOS 表本体原位改写 Type 0/1/2/3
       身份字符串和 Type 1 UUID（首次定位时保存各字符串原始容量）
    -> 禁用或卸载时从保存副本恢复原表
```

边界：

- 磁盘序列号已覆盖到**内核读取路径**并通过注册 PID 的 smoke 验证。SMBIOS
  物理表模块属于显式 opt-in 实验路径，默认关闭，不计入稳定验收能力。
- `GetSystemFirmwareTable` 等 API 返回的缓冲区被重写；宿主机固件芯片中的
  原始表没有被修改，DMA/固件直读仍可见真实值。
- CPUID/XGETBV 不产生陷入，WDM 驱动无法拦截；由 NativeBridge 的
  `native-hook-manifest.txt` 精确入口 patch 覆盖（见 `native/README.md`）。
- `native/macfilter` 中保留 NDIS LWF 实验代码与崩溃证据，但服务保持禁用。
  Windows 11 22631 上 OID 参与路径可复现蓝屏，因此物理 MAC 不计入内核稳定
  覆盖；用户态 `GetAdaptersAddresses`/`GetIfTable*`/WMI 路径仍由 NativeBridge 覆盖。
- SMBIOS 物理探测默认关闭：Profile 根目录放 `kernel_smbios` 内容 `1`
  才会启用（module_flags=3）。探测只扫描内核镜像内 (物理地址, 长度)
  全局变量对，候选上限 64，物理地址限制 < 1GB。
- 所有过滤 IRP 走 remove-lock 生命周期：dispatch 获取、完成例程释放、
  卸载前 `IoReleaseRemoveLockAndWait`，消除飞行中 IRP 的释放竞态。

验证证据（本机 Win11 23H2 22631）：

```text
kernel-smoke.exe --identity
  [PASS] storage serial rewritten for registered pid
  [INFO] disk serial after rewrite: CAC-DISK-01
module-state: storageRewrites=1 storageCompletionSeen=1 lastPolicyHit=1
```

下发通道：

```powershell
# CLI 路径：scripts/lib.ps1 每次启动把 profile identity.json 推给驱动
cac-kernelctl identity-set --file <profile>\temp\kernel-identity.json

# Desktop 路径：scripts/desktop-profile.ps1 在启动前推送、启动后注册 PID
cac-kernelctl register --pid <PID> --profile <name> --flags 1
```

## 构建

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/build-driver.ps1
```

产物：

```text
native/kernel/bin/CacKernel.sys
native/kernel/bin/CacKernel.sha256
native/kernel/bin/kernel-smoke.exe
native/kernel/bin/cac-kernelctl.exe
```

## 安装 / 卸载

```powershell
# 需要管理员 + testsigning
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/install-driver.ps1 -Force

# 只验证当前已运行实例，不停止或热重载驱动
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/install-driver.ps1 -VerifyOnly

# 只暂存下次启动所需文件和服务配置，不自动重启
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/install-driver.ps1 -RebootInstall

# 卸载（停止服务、删除服务、删除匹配哈希的驱动文件）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/install-driver.ps1 -Uninstall
```

安装脚本会依次校验 SHA-256、`signtool verify /pa`、testsigning，然后：

```text
copy -> %SystemRoot%\System32\drivers\CacKernel.sys
sc create CacKernel type= kernel start= demand
sc start CacKernel
kernel-smoke.exe --json <temp>
```

证据写入 `%USERPROFILE%\.cac\kernel\driver-install.json`。

## 控制命令

```powershell
native/kernel/bin/cac-kernelctl.exe ping
native/kernel/bin/cac-kernelctl.exe register --pid 1234 --profile profile-a --flags 1
native/kernel/bin/cac-kernelctl.exe query --pid 1234
native/kernel/bin/cac-kernelctl.exe audit --max 32
native/kernel/bin/cac-kernelctl.exe unregister --pid 1234
```

## 审计状态机

`npm run audit:kernel` 按以下顺序判定：

```text
NOT_IMPLEMENTED -> BUILT_UNSIGNED / HASH_MISMATCH -> SIGNED_DRIVER_READY
                -> SERVICE_INSTALLED -> RUNNING_UNVERIFIED -> RUNNING_VERIFIED
```

`-Strict` 只接受 `RUNNING_VERIFIED`。

## 明确边界

- 测试签名驱动只用于本机验证，不可作为发行包直接分发。
- 设备 DACL 限制为 SYSTEM/Administrators；本地管理员本来就能加载/卸载驱动，这不是提权边界。
- 驱动对注册 PID 的存储查询重写序列号；它不修改磁盘固件本体。SMBIOS 物理表模块默认关闭，未计入当前稳定能力。
- 驱动不修改 CPUID、XGETBV、物理网卡、BIOS 固件芯片或 DPAPI；NativeBridge 负责已覆盖用户态 API 的 Profile/empty 语义。
- `network_mode=enforce` 使用 NativeBridge 的动态 WFP 会话对 Claude 镜像做回环允许/非回环阻断；这不是本驱动内的 NDIS LWF 或 WFP callout。
- NDIS LWF 实验路径因可复现蓝屏保持禁用；物理 NIC、宿主 CPUID/XGETBV、固件芯片、DPAPI 和外部驱动直接读取仍不属于稳定虚拟化能力。
