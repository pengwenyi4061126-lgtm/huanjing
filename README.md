# cac-windows

Claude Code 的 Windows 隐私保护工具 — 二进制补丁抹除中国特征，遥测正常流转。

当前版本：`1.0.35`，适配 Claude Code `2.1.294`，并提供 Claude Desktop `5.1231.2` 的独立 Profile 启动器。

## 功能

- **隐私补丁** — 自动补丁 claude.exe，抹除时区（Asia/Shanghai → TZ）、语言（zh → en）、UTC 偏移（+08:00 → +00:00）
- **时区对齐** — 系统提示词日期和时区跟随 TZ 环境变量
- **代理支持** — HTTP / SOCKS5 / SOCKS5H 代理配置
- **Profile 隔离** — 每个环境独立配置、Home、AppData、缓存、临时目录和身份清单
- **生命周期保护** — 切换 Profile 前强制结束旧 Claude 会话，避免身份与配置混用
- **启动完整性** — 精确锁定 Claude Code 版本，校验补丁标记和 claude.exe SHA-256
- **网络验收** — 检查代理可达性、socks5h 远程 DNS 语义和子进程环境继承
- **A/B 验收** — 验证 Profile 默认 Home、配置、AppData、TEMP/TMP 不交叉
- **Node 用户态身份 Hook** — 通过 Profile 级 `NODE_OPTIONS/BUN_OPTIONS` 注入 `fingerprint-hook.js`，并记录运行时命中证据
- **NativeBridge 用户态层** — 可选 DLL 注入，覆盖网卡、卷序列号、SMBIOS、磁盘/固件、主机名、用户名、注册表、HID、SetupDi、驱动列表、原始设备打开以及哈希绑定的 `CPUID/XGETBV`
- **WMI/COM 隔离** — 在进程内包装 `CLSID_WbemLocator`，对 `Win32_BIOS`、`Win32_ComputerSystemProduct`、`Win32_DiskDrive`、`Win32_Processor`、`Win32_NetworkAdapter`、`Win32_LogicalDisk` 等结果按 Profile 改写或清空
- **renderer/utility 注入** — 对 Claude Desktop 的 browser/GPU/renderer/utility/crashpad 子进程做创建时注入，并带启动器后代补偿
- **干净网络视图** — `network_mode=clean` 时隐藏 VMware/Meta/Teredo/TAP/WireGuard/Tailscale 等虚拟网卡，清零 WinHTTP/IE/注册表代理配置，WMI 网络行同步过滤
- **Desktop Profile** — `scripts/desktop-profile.ps1` 为 Claude Desktop 重定向 `APPDATA`/`LOCALAPPDATA`/`USERPROFILE`/`TEMP`，隔离 `Claude`、`Claude-3p`、`ant-did`、sessions 和 Crashpad
- **Native/硬件证据** — 单独记录 Windows CIM、注册表、磁盘、网卡等主机共享面；不把它宣称为硬件隔离
- **Profile 清理** — 只清理当前 Profile，不修改全局 `.claude` 或全局凭据
- **零依赖** — 只需要 Node.js 和 PowerShell

## 环境要求

- Windows 10 / 11
- Node.js ≥ 14
- PowerShell 5.1（系统自带）或 PowerShell 7（推荐）
- Claude Code 2.1.294（`npm i -g @anthropic-ai/claude-code@2.1.294`，或在 cac 菜单里一键安装）

## 安装

```powershell
npm i -g cac-windows --registry https://registry.npmjs.org --force
cac
```

> 新版 npm（11+）默认拦截安装脚本，会看到 `install scripts not yet covered by allowScripts` 警告——这是正常的。包已经装好了，只是补丁没在 `npm i` 阶段完成。**装完运行一次 `cac`** 即可，它会解包 Claude Code 二进制、打补丁、设 PATH。
>
> 如果想让 npm 直接放行（可选）：
> ```powershell
> npm i -g cac-windows --allow-scripts=cac-windows,@anthropic-ai/claude-code --registry https://registry.npmjs.org --force
> ```

## 快速开始

`cac` 首次运行自动完成初始化：定位 claude.exe（未安装则自动安装 2.1.294）、生成 wrapper、把 `%USERPROFILE%\.cac\bin` 加到用户 PATH 中 npm 目录之前、应用补丁并登记二进制 SHA-256。之后进入菜单：

```
1. 启动 Claude Code
2. 环境管理        （切换 / 创建 / 删除环境，设时区、代理，清空回收站）
3. 版本更新并应用补丁
4. 清理追踪数据    （换号用）
5. 查看状态
6. 网络隔离检查
7. Profile A/B 隔离测试
8. Native/硬件边界证据
9. 生成 CPUID Hook 候选
10. Desktop Profile 管理
0. 退出
```

上下键选择，回车确认，Esc 返回。

配置完成后**重开一个终端**，之后直接敲 `claude` 即可。wrapper 会先校验当前 Claude Code 版本、补丁完整性和 SHA-256，再绑定当前 Profile 的 `CLAUDE_CONFIG_DIR`、`HOME`、`USERPROFILE`、`APPDATA`、`LOCALAPPDATA`、`TEMP`、`TMP`，并通过 `NODE_OPTIONS/BUN_OPTIONS` 加载 Profile 的用户态身份 Hook 后启动 claude.exe。Claude 会话运行时不能切换 Profile；切换操作会先强制结束旧 Claude 进程，防止两个 Profile 混用。

菜单顶部会显示 `claude 命令: 走 cac` 还是 `绕过 cac`。绕过说明 PATH 顺序有问题——先重开终端，仍不行就手动检查用户 PATH。

## 隐私补丁覆盖范围

| 泄露点 | 补丁方式 |
|--------|---------|
| 系统提示词日期 | 日期函数 → 跟随 TZ 环境变量 |
| 系统提示词时区 | resolvedOptions().timeZone → TZ 环境变量 |
| 系统时区名缓存 | 时区缓存函数 → TZ 环境变量 |
| 系统语言检测 | 语言缓存函数 → 固定 "en" |
| UTC 偏移 | getTimezoneOffset() → 固定 +00:00 |
| 日期格式化 locale | toLocaleDateString → 固定 "en" |
| 语言环境变量 | LANG = en_US.UTF-8 |

补丁签名与 Claude Code 版本绑定，当前支持 2.1.294。新版本发布后需要重新提取签名。

## Profile 文件布局

每个 `%USERPROFILE%\.cac\envs\<name>` 都包含独立运行面：

```text
<name>\
├─ .claude\           # CLAUDE_CONFIG_DIR、会话、设置、Statsig
├─ home\              # USERPROFILE/HOME
├─ AppData\           # APPDATA/LOCALAPPDATA
├─ cache\             # 应用缓存边界
├─ temp\              # TEMP/TMP
├─ xdg\               # XDG_CONFIG_HOME/XDG_CACHE_HOME
├─ credentials\      # Profile 范围的文件凭据缓存
├─ logs\              # Profile 范围日志
├─ audit\             # 网络、A/B 和用户态 Hook 证据
├─ native_read_policy # Native 读取策略：profile（默认）或 empty
├─ cpuid_mode         # neutral（默认）、empty 或 passthrough
├─ network_mode       # profile（默认）或 clean
├─ identity.json      # Profile 身份清单
└─ uuid/stable_id/user_id/machine_id/hostname/mac_address/disk_serial/bios_serial/system_serial/hid_serial
```

Windows 版本的隔离边界是**进程级 Profile 隔离 + Node 用户态 Hook + 可选 NativeBridge 用户态 Hook**。NativeBridge 覆盖 `GetAdaptersAddresses/Info`、`GetIfTable2/GetIfEntry2`、`GetVolumeInformationW/ByHandleW`、`GetFileInformationByHandle`、`NtQueryVolumeInformationFile`、`GetSystemFirmwareTable`、`NtQuerySystemInformation`、`DeviceIoControl`、`NtDeviceIoControlFile`、`GetComputerNameW/ExW`、`GetUserNameW`、`RegGetValueW/RegQueryValueExW`、`RegEnumValueW`、`EnumDeviceDrivers`、`SetupDiGetClassDevsW` 和 HID 序列号；WMI 通过 COM 包装覆盖。它不安装内核驱动，也不改变 NDIS/WFP 过滤器或物理硬件。`E:\claude` 中的 Native/硬件报告仍应作为独立观测证据，不能用本项目的 Node/PowerShell 结果替代。

菜单中的 **Native/硬件边界证据** 会把 Windows CIM、MachineGuid、磁盘、卷、处理器、主板、显卡和物理网卡等主机共享面写入 `audit/native-hardware-check.json`；敏感标识只保存存在性、长度和 SHA-256。报告会同时记录 Node 层 `fingerprint-hook.jsonl` 与 Native 层 `native-hook.jsonl` 的命中情况，并分别标记 `nativeUserland`、`cpuid`、`xgetbv`、`deviceIoControl` 和内核边界。

### NativeBridge 用户态层

`native/` 下是独立编译的 x64 DLL 和注入器。构建与清单生成见 [native/README.md](native/README.md)。构建产物同步到 `%USERPROFILE%\.cac\native\` 后，wrapper 会在目标为 `.exe` 时改用 `cac-native-launch.exe` 启动并注入 `NativeBridge.dll`；产物缺失时自动回退到原启动路径。

Native 层始终只做用户态返回值和用户态指令入口处理。它不会加载驱动、不会修改 NDIS/WFP，也不会改变物理硬件；内核设备对象和物理层仍是同一台机器。

Native 读取策略默认为 `profile`，保证返回值具有一致的 Profile 语义。将当前 Profile 的 `native_read_policy` 写为 `empty` 后，NativeBridge 会对已覆盖的设备身份读取返回空字符串、零序列号、无固件数据、无 WMI 属性或无设备枚举结果；`cpuid_mode` 默认为 `neutral`，在 `empty` 策略下自动改为 `empty`。`empty` 模式作用于主进程、renderer/utility 子进程和 WMI 同步查询；内核回调、NDIS/WFP 过滤器和物理固件仍不在覆盖范围。

启用某个 Code Profile 的严格空值策略：

```powershell
Set-Content "$env:USERPROFILE\.cac\envs\profile-a\native_read_policy" "empty" -Encoding ASCII
Set-Content "$env:USERPROFILE\.cac\envs\profile-a\cpuid_mode" "empty" -Encoding ASCII
```

### Claude Desktop Profile

Desktop 使用独立启动器，不复用 Claude Code 的 `CLAUDE_CONFIG_DIR`：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action create -Profile work
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action launch -Profile work -Inject
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action ab -Inject -WaitSeconds 45
```

启动器把 `APPDATA` 放在 `USERPROFILE\home\AppData\Roaming` 下，并隔离 `Claude`、`Claude-3p`、`ant-did`、sessions 和 Crashpad。不要用 `CLAUDE_USER_DATA_DIR`：Desktop 会删除/忽略该变量。

> **为什么必须通过 `claude` wrapper（或 cac 菜单）启动？** claude.exe 是 Bun 打包的单文件程序，内置了预编译的 JSC 字节码。默认情况下运行时直接执行字节码，**内嵌的 JS 源码根本不会被读取，补丁等于没打**。wrapper 启动时会设置 `BUN_JSC_useCodeCache=false`，强制 Bun 放弃字节码、回退到（已打补丁的）源码执行。代价是启动慢约 0.3 秒。直接双击或用绝对路径运行 claude.exe 不会带上这个变量，补丁不生效。

### Desktop 子进程注入与沙箱

`-Inject` 模式通过 `CreateProcessW`、`CreateProcessInternalW` 和 `NtCreateUserProcess` 三条创建路径注入子进程，并由启动器轮询补注入遗漏的后代进程。Chromium 的 GPU/renderer 在启用 ACG/CIG 后会拒绝加载未签名 DLL，因此 Native 模式会追加：

```text
--no-sandbox --disable-gpu-sandbox
```

这是让未签名 `NativeBridge.dll` 进入 renderer/GPU 的必要条件，同时也降低了 Chromium 自身的沙箱强度。不使用 `-Inject` 时不会追加这两个参数。

### 干净网络视图（network_mode=clean）

```powershell
Set-Content "$env:USERPROFILE\.cac\desktop\work\network_mode" "clean" -Encoding ASCII
```

`clean` 模式下，以下路径返回“没有虚拟网卡、没有代理”：

```text
GetAdaptersAddresses / GetAdaptersInfo
GetIfTable2 / GetIfEntry2 / GetIfTable
GetInterfaceInfo
ConvertInterfaceLuidToNameW / ToAlias / ConvertInterfaceNameToLuidW
WinHttpGetIEProxyConfigForCurrentUser / WinHttpGetProxyForUrl
WinHttpGetDefaultProxyConfiguration / WinHttpOpen
InternetQueryOptionW(INTERNET_OPTION_PROXY)
HKCU Internet Settings: ProxyEnable / ProxyServer / ProxyOverride / AutoConfigURL / AutoDetect
WMI Win32_NetworkAdapter / Win32_NetworkAdapterConfiguration 行
```

Node 实测：

```text
baseline: Meta, 以太网, VMware VMnet1, VMware VMnet8, Loopback
clean   : 以太网(02:aa:bb:cc:dd:ee), Loopback
```

边界：`clean` 只改变进程内的用户态视图，不改变实际路由和出口 IP。`GetBestRoute2` 仍可能返回隧道接口索引；服务端仍能看到真实出口。要让服务端也认为“没有代理/VPN”，必须使用住宅/移动出口并保持时区、语言、地理一致，或用 VM/独立网络边界。

### 内核 / NDIS / WFP / 物理硬件边界

用户态已覆盖这些表面的可访问路径：`EnumDeviceDrivers`、`NtQuerySystemInformation(SystemModuleInformation)`、`GetIfTable2/GetIfEntry2`、`GetAdapters*`、`SetupDiGetClassDevsW`、`NtDeviceIoControlFile` 和原始设备 `CreateFileW`。在 `empty` 策略下，驱动列表、设备枚举和原始设备打开会被清空或拒绝。

真正的内核回调、NDIS 轻量过滤器和 WFP 过滤器无法由用户态 DLL 安装。要覆盖驱动内部、其他进程的内核查询以及物理固件层，必须加载签名的内核驱动；本机未安装 WDK，也未启用测试签名，因此这一层没有实现，不能被宣称为已完成。

## 致谢

本项目基于 [cac](https://github.com/nmhjklnm/cac) 改造，原项目提供了完整的 macOS / Linux 支持。

## License

MIT
