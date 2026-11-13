# CAC 内核控制面（WDM）

当前状态：`RUNNING_VERIFIED`，能力级别 `CONTROL_PLANE_ONLY`。这是一套**签名 WDM 控制面**，不是硬件伪装层。

## 组件

| 文件 | 作用 |
|---|---|
| `CacKernel.c` | WDM 驱动：设备对象、5 个 IOCTL、per-PID 策略表、进程退出清理、审计环 |
| `CacKernelIoctl.h` | 用户态/内核态共享 ABI，无指针、固定宽度 |
| `CacKernel.inf` | 遗留 INF 服务定义（SCM 安装是已验证路径） |
| `build-driver.ps1` | WDK 26100 编译、链接、测试签名、SHA-256 清单 |
| `install-driver.ps1` | 哈希/签名校验、SCM 安装、启动、冒烟、证据落盘 |
| `tools/cac-kernelctl.cpp` | 控制客户端：ping/register/unregister/query/audit |
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
```

- 策略表上限 64 个 PID；注册时记录 `PsGetProcessCreateTimeQuadPart`，防止 PID 复用。
- 查询、注册和 ping 时用 `PsGetProcessExitStatus` 惰性清理已退出进程，并写 `event=6` 审计。
- 审计事件：驱动加载、设备创建、策略注册/注销/拒绝、进程退出清理、未知 IOCTL、通知注册状态。
- 驱动不含 SSDT/IDT/inline hook，不触碰 PatchGuard 关心的结构。
- 本机测试签名构建会先尝试 `PsSetCreateProcessNotifyRoutineEx`，失败时回退到兼容的 `PsSetCreateProcessNotifyRoutine`；smoke 必须看到 `notifyRegistered=1` 和 `CAC_CAP_PROCESS_LIFECYCLE`，否则审计不再把控制面标记为完整。
- NativeBridge 在每个注入进程内执行 register/query 回读；`-RequireKernel` 会在设备不可用、策略注册失败或回读不一致时拒绝 `ready`。

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
- 驱动不修改 CPUID、XGETBV、SMBIOS、物理网卡、磁盘固件、BIOS 或 DPAPI。
- 当前策略是“可注册、可查询、可审计”，内核驱动本身不重写硬件返回值；NativeBridge 负责已覆盖用户态 API 的 Profile/empty 语义。
- `network_mode=enforce` 使用 NativeBridge 的动态 WFP 会话对 Claude 镜像做回环允许/非回环阻断；这不是本驱动内的 NDIS LWF 或 WFP callout。
- 物理硬件、BIOS/SMBIOS、CPUID、XGETBV、DPAPI 和驱动内部读取仍不属于该控制面的虚拟化能力。
