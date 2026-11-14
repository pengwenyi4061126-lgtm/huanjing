# Kernel 发布边界

`CacKernel.sys` 是本机 WDK 构建产物，不随默认 npm 包发布。npm 包只包含本目录的源码、INF、策略、构建和安装脚本；`native/kernel/bin/` 与 `native/kernel/obj/` 被 `.gitignore` 排除，避免把测试签名驱动误当作可复现的公共发布二进制。

## 本机验收快照

| 项目 | 当前值 |
|---|---|
| WDK | `10.0.26100.0` |
| 架构 | `x64` |
| 驱动 SHA-256 | `2D9BCFB150A8FDA3B4E700BC8E1B9A7EFC8C8A40A87550A1023C8CA71466136C` |
| 状态 | `RUNNING_VERIFIED / STORAGE_FILTER_PLUS_CONTROL_PLANE` |
| 签名 | 测试签名；不代表生产发布签名 |

## 可复现命令

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/build-driver.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/install-driver.ps1 -Force
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/install-driver.ps1 -VerifyOnly
npm run audit:kernel
```

当前稳定能力包括窄 IOCTL、per-PID 策略注册/查询、审计事件和注册 PID 的存储查询序列号重写；它不修改磁盘固件本体。SMBIOS 物理表模块是默认关闭的 opt-in 实验路径。驱动不实现 NDIS/WFP callout、SSDT/IDT/inline kernel hook，也不修改 CPUID、物理网卡、BIOS 固件芯片或 DPAPI。
