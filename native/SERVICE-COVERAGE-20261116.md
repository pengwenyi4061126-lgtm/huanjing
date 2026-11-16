# Claude SYSTEM 服务覆盖（2026-11-16）

## 目标

覆盖 Claude Desktop 的 `cowork-svc.exe`。它运行在 LocalSystem，
不属于 Claude Electron 主进程，原有 NativeBridge 注入覆盖不到。

## 发现

```text
服务名: CoworkVMService
类型:   WIN32_PACKAGED_PROCESS
账户:   LocalSystem
启动:   Automatic
签名:   Anthropic, PBC
保护:   不是 PPL / PP
OpenProcess(0x1F0FFF): 成功
缓解:   ACG/CIG/BinarySignature/ChildProcess/CFG 全部 OFF
```

二进制字符串包含：

```text
cpuid xgetbv GetAdaptersAddresses SetupDi TPM Hyper-V WSL vmcompute
```

`app.asar` 包含 `ant-did`、`hostname`、`networkInterfaces`、`Tpm`；
`resources` 包含 `smol-bin.x64.vhdx`。

## 实现

1. `native/ServiceInjector/main.cpp`
   - `--once` 单次注入
   - `--watch` 监控服务重启/更新
   - `--service` 作为 `CacServiceInjector` 服务运行
   - 按进程名查找，不写死 PID
   - 注入后等待 NativeBridge ready 事件并校验模块

2. `NativeBridge` 服务 profile 引导
   - 如果进程没有 `CAC_PROFILE_DIR`，读取：

```text
C:\ProgramData\CAC\active-profile.ini
```

   - 设置 profile dir / identity / MAC / machine_id / audit 等环境；
   - `native.identity loaded` 审计记录 MAC/hostname/machine_id/disk。

3. `scripts/service-profile.ps1`
   - 从 Desktop profile 生成 `C:\ProgramData\CAC\profiles\desktop-1`；
   - 写 `active-profile.ini`；
   - 预建审计文件并授权 SYSTEM/Administrators。

4. `scripts/install-service-injector.ps1`
   - 复制 NativeBridge / injector 到 `C:\ProgramData\CAC\native`；
   - 校验 SHA-256；
   - 创建 `CacServiceInjector` 服务；
   - 更新时自动停止注入器/Cowork 服务，再重启。

5. `ant-did` / `Claude-3p` 文件路径观察
   - NativeBridge 的 CreateFileW/A/2、NtCreateFile 现在记录
     `claudeprofile observed` 审计事件；
   - 尚未观察到 cowork-svc 读取 ant-did，后续按实际调用决定是否重定向。

## 实测结果

```text
注入器服务: CacServiceInjector RUNNING
目标进程:   cowork-svc.exe PID 25764
模块:       NativeBridge.dll
审计:       native.bridge ready
身份:       mac=02:2a:09:f6:66:f2
            host=host-7105ecbc
            machine=7105ecbcb4a642a685ea9848ddd5d3ba
            disk=WD-84490e004894
内核策略:   kernel.policy verified
```

NativeBridge 安装的关键 Hook：

```text
GetAdaptersAddresses / GetAdaptersInfo
GetVolumeInformationW / NtQueryVolumeInformationFile
GetSystemFirmwareTable / NtQuerySystemInformation class 76
DeviceIoControl / NtDeviceIoControlFile
RegGetValueW / RegQueryValueExW / RegEnumValueW
HidD_GetSerialNumberString
SetupDiGetDevicePropertyW / RegistryPropertyW / InstanceIdW
GetIfTable2 / GetIfEntry2 / GetIfTable
WMI COM
CreateProcess / NtCreateUserProcess
CreateFileW/A/2 / NtCreateFile
```

## 当前边界

- 注入器服务 Auto 启动，但 CoworkVMService 也 Auto；启动顺序不是强绑定，
  首次启动可能存在约 0-2 秒未注入窗口。后续可加服务依赖/触发器。
- MSIX 更新会替换 `cowork-svc.exe`，注入器按进程名/模块重新注入。
- `ant-did` 尚未观察到实际读取；已加观察 Hook，等实际调用再重定向。
- CPU manifest 当前未配置；`cpuid/xgetbv` 仍是用户态 Hook 的下一步。
- 该服务是用户态 SYSTEM，不是 Ring-0；注入可以覆盖它的用户态 API，
  但 TPM quote / Ring-0 CPUID / PCI/DMA 仍不在非 VM 可解范围。

## 运维命令

```powershell
# 生成/更新 active profile
.\scripts\service-profile.ps1 `
  -ProfilePath 'C:\Users\Administrator\.cac\desktop\1' `
  -Name 'desktop-1'

# 安装/更新注入器服务
.\scripts\install-service-injector.ps1

# 停止并删除服务
.\scripts\install-service-injector.ps1 -Uninstall
```

审计：

```text
C:\ProgramData\CAC\logs\service-injector.jsonl
C:\ProgramData\CAC\logs\cowork-svc-native.jsonl
```
