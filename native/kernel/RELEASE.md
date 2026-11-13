# Kernel 发布边界

`CacKernel.sys` 是本机 WDK 构建产物，不随默认 npm 包发布。npm 包只包含本目录的源码、INF、策略、构建和安装脚本；`native/kernel/bin/` 与 `native/kernel/obj/` 被 `.gitignore` 排除，避免把测试签名驱动误当作可复现的公共发布二进制。

## 本机验收快照

| 项目 | 当前值 |
|---|---|
| WDK | `10.0.26100.0` |
| 架构 | `x64` |
| 驱动 SHA-256 | `8C012E96F3A5FE713B98CBC87FB25F836EEBC3D2AD47899DD5B4D13880B63ABE` |
| 状态 | `RUNNING_VERIFIED / CONTROL_PLANE_ONLY` |
| 签名 | 测试签名；不代表生产发布签名 |

## 可复现命令

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/build-driver.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/kernel/install-driver.ps1 -Force
npm run audit:kernel
```

该控制面只提供窄 IOCTL、per-PID 策略注册/查询和审计事件；它不实现 NDIS/WFP callout、SSDT/IDT/inline kernel hook，也不修改 CPUID、SMBIOS、物理网卡、磁盘固件、BIOS 或 DPAPI。
