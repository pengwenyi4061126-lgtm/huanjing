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
   - `redirect_ant_did=1` 时，`...\Claude\ant-did` 重定向到
     `%CAC_PROFILE_DIR%\ant-did`，`...\Claude-3p\ant-did` 重定向到
     `%CAC_PROFILE_DIR%\Claude-3p\ant-did`；
   - 用 `cac-native-launch.exe` + cmd 独立验证通过，原路径不落文件。

6. Go ABI CPU manifest
   - `native/NativeBridge/GoCpuDetours.asm` 按 Go 1.25
     `internal/cpu` 的栈式参数/结果布局保存 rbp 并回写；
   - `scripts/build-cowork-cpu-manifest.ps1` 扫描
     `cowork-svc.exe`，只保留 prologue 精确匹配的 Go ABI 入口；
   - 当前版本命中 4 条：`0x2BA0/0x2BC0/0x212A60/0x212A80`；
   - `native/CpuProbe` + `scripts/probe-service-cpu.ps1` 在服务进程内
     调用被 hook 的入口，验证 neutral 结果。

## 实测结果

```text
注入器服务: CacServiceInjector RUNNING
目标进程:   cowork-svc.exe PID 4980
模块:       NativeBridge.dll
审计:       native.bridge ready
身份:       mac=02:2a:09:f6:66:f2
            host=host-7105ecbc
            machine=7105ecbcb4a642a685ea9848ddd5d3ba
            disk=WD-84490e004894
CPU:        cpu.manifest complete entries=4 installed=4
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
- `ant-did` 重定向已实现并独立验证；尚未观察到 cowork-svc 自身读取
  ant-did，服务内仍保留观察审计。
- CPU manifest 只覆盖 4 个精确 Go ABI 入口；其他 cpuid 包含函数
  （RVA 0x79356/0x79381/0x170BBD/0x504C4F）没有匹配的 Go 布局，
  未挂载。
- Go runtime 的 `internal/cpu.Initialize` 在 DLL 注入前已经执行；
  manifest 不能追溯修改启动时算出的 feature flags，只覆盖注入后
  经过这 4 个入口的调用。
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

## A/B 验证

测试 Profile B（临时，PID 23912）：

```text
MAC:        02:bb:bb:bb:bb:bb
hostname:   host-bbbb
machine_id: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
disk:       WD-bbbbbbbbbbbb
```

日志：

```text
native.identity loaded mac=02:bb:bb:bb:bb:bb host=host-bbbb machine=bbbb... disk=WD-bbbbbbbbbbbb
native.bridge ready
```

恢复 Desktop profile 1 后（PID 4980）：

```text
MAC:        02:2a:09:f6:66:f2
hostname:   host-7105ecbc
machine_id: 7105ecbcb4a642a685ea9848ddd5d3ba
disk:       WD-84490e004894
```

日志：

```text
native.identity loaded mac=02:2a:09:f6:66:f2 host=host-7105ecbc ...
native.bridge ready
```

结论：`cowork-svc` 的 identity 不是写死的，会随
`active-profile.ini` 切换；注入器在服务重启后重新注入新 PID。
每次服务启动都重新安装 CPU manifest，4/4 成功。

P1 第一阶段的完整证据和复现命令见
`native/evidence/P1-20261116/README.md`。
