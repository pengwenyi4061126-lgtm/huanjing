# cac-windows

Claude Code 的 Windows 隐私保护工具 — 二进制补丁抹除中国特征，遥测正常流转。

当前版本：`1.0.44`，适配 Claude Code `2.1.294`，并提供 Claude Desktop `5.1231.2` 的独立 Profile 启动器。

最终审计快照（2026-11-14，当前发布快照）记录的 `native/dist` NativeBridge SHA-256 为 `1C98CA2EA7E8ECE4EE28882D7D5A6048E404A2B373B95235A9C6B8C17FC3F58A`，`cac-native-launch.exe` SHA-256 为 `080D8E6EBCF9020C42D1D5A231BB8425B9B9532405C9778B17F8959B08717BDD`。本机 `%USERPROFILE%\.cac\native` 已同步到相同哈希；`npm run audit:release`、Native smoke、WFP smoke、代理池 smoke 和 relay smoke 均通过。Desktop 历史 PID 审计在未启动真实 Desktop 的情况下保持 `PARTIAL`，不会被静态日志冒充为完整运行时通过。

## 功能

- **隐私补丁** — 自动补丁 claude.exe，抹除时区（Asia/Shanghai → TZ）、语言（zh → en）、UTC 偏移（+08:00 → +00:00）
- **时区对齐** — 系统提示词日期和时区跟随 TZ 环境变量
- **代理支持** — HTTP / SOCKS5 / SOCKS5H 代理配置
- **Profile 隔离** — 每个环境独立配置、Home、AppData、缓存、临时目录和身份清单
- **生命周期保护** — 切换 Profile 前强制结束旧 Claude 会话；根进程按路径、启动时间和 Profile `--user-data-dir` 校验，进程树终止前再次校验 PID 身份
- **启动完整性** — 精确锁定 Claude Code 版本，校验补丁标记和 claude.exe SHA-256
- **网络验收** — 检查代理可达性、socks5h 远程 DNS 语义和子进程环境继承
- **A/B 验收** — 验证 Profile 默认 Home、配置、AppData、TEMP/TMP 不交叉
- **Node 用户态身份 Hook** — 通过 Profile 级 `NODE_OPTIONS/BUN_OPTIONS` 注入 `fingerprint-hook.js`，并记录运行时命中证据
- **NativeBridge 用户态层** — 可选 DLL 注入，覆盖网卡、卷序列号、SMBIOS、磁盘/固件、主机名、用户名、注册表、HID、SetupDi、驱动列表、原始设备打开以及哈希绑定的 `CPUID/XGETBV`
- **WMI/COM 隔离** — 在进程内包装 `CLSID_WbemLocator`，对 `Win32_BIOS`、`Win32_ComputerSystemProduct`、`Win32_DiskDrive`、`Win32_Processor`、`Win32_NetworkAdapter`、`Win32_LogicalDisk` 等结果按 Profile 改写或清空
- **renderer/utility 注入** — 对 Claude Desktop 的 browser/GPU/renderer/utility/crashpad 子进程做创建时注入，并带启动器后代补偿
- **干净网络视图** — `network_mode=clean` 时隐藏 VMware/Meta/Teredo/TAP/WireGuard/Tailscale 等虚拟网卡，清零 WinHTTP/IE/注册表代理配置，WMI 网络行同步过滤
- **动态出口边界** — `network_mode=enforce` 时由 NativeBridge 为 Claude 镜像安装动态 WFP 规则，仅允许回环代理连接并阻断非回环 ALE 出站，失败即拒绝 Native 模式启动
- **Desktop Profile** — `scripts/desktop-profile.ps1` 为 Claude Desktop 重定向 `APPDATA`/`LOCALAPPDATA`/`USERPROFILE`/`TEMP`，隔离 `Claude`、`Claude-3p`、`ant-did`、sessions 和 Crashpad
- **Native/硬件证据** — 单独记录 Windows CIM、注册表、磁盘、网卡等主机共享面；不把它宣称为硬件隔离
- **Profile 清理** — 只清理当前 Profile，不修改全局 `.claude` 或全局凭据
- **分层依赖** — 基础 Code Profile 只需要 Node.js 和 PowerShell；Desktop Native 使用仓库内已构建的 NativeBridge/launcher；Fingerprint MITM 需要 `mitmdump`；Kernel 控制面需要本机 WDK、MSVC、Windows SDK、`signtool`、管理员权限和测试签名环境

## 环境要求

- Windows 10 / 11
- Node.js ≥ 14（基础 Code Profile）
- PowerShell 5.1（系统自带）或 PowerShell 7（推荐）
- Claude Code 2.1.294（`npm i -g @anthropic-ai/claude-code@2.1.294`，或在 cac 菜单里一键安装）

可选组件的边界：

- Desktop Native：使用 `native/dist` 与 `%USERPROFILE%\.cac\native` 中的 NativeBridge/launcher。
- Fingerprint MITM：使用 `-Fingerprint` 前必须能解析 `mitmdump`，npm 包只携带 addon/shim，不携带 Python/mitmproxy 运行时。
- Kernel 控制面：`npm` 包只携带 `native/kernel` 源码和策略文档，不携带 `CacKernel.sys`；本机构建需要 WDK 10.0.26100、MSVC、Windows SDK、`signtool`、管理员权限和测试签名配置。该驱动目前是 `CONTROL_PLANE_ONLY`，不伪造物理硬件。

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
10. 代理池管理       （SOCKS5H 自动绑定、重分配、全部解绑）
11. Desktop Profile 管理
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
├─ network_mode       # profile（默认）、clean 或 enforce
├─ identity.json      # Profile 身份清单
└─ uuid/stable_id/user_id/machine_id/hostname/mac_address/disk_serial/bios_serial/system_serial/hid_serial
```

Windows 版本的隔离边界是**进程级 Profile 隔离 + Node 用户态 Hook + NativeBridge 用户态 Hook + 可选签名内核控制面 + 可选动态 WFP 出口边界**。NativeBridge 覆盖 `GetAdaptersAddresses/Info`、`GetIfTable2/GetIfEntry2`、`GetVolumeInformationW/ByHandleW`、`GetFileInformationByHandle`、`NtQueryVolumeInformationFile`、`GetSystemFirmwareTable`、`NtQuerySystemInformation`、`DeviceIoControl`、`NtDeviceIoControlFile`、`GetComputerNameW/ExW`、`GetUserNameW`、`RegGetValueW/RegQueryValueExW`、`RegEnumValueW`、`EnumDeviceDrivers`、`SetupDiGetClassDevsW` 和 HID 序列号；WMI 通过 COM 包装覆盖。`E:\claude` 中的 Native/硬件报告仍应作为独立观测证据，不能用本项目的 Node/PowerShell 结果替代。

菜单中的 **Native/硬件边界证据** 会把 Windows CIM、MachineGuid、磁盘、卷、处理器、主板、显卡和物理网卡等主机共享面写入 `audit/native-hardware-check.json`；敏感标识只保存存在性、长度和 SHA-256。报告会同时记录 Node 层 `fingerprint-hook.jsonl` 与 Native 层 `native-hook.jsonl` 的命中情况，并分别标记 `nativeUserland`、`cpuid`、`xgetbv`、`deviceIoControl` 和内核边界。

### NativeBridge 用户态层

`native/` 下是独立编译的 x64 DLL 和注入器。构建与清单生成见 [native/README.md](native/README.md)。构建产物同步到 `%USERPROFILE%\.cac\native\` 后，Desktop 的 `-Inject` 模式改用 `cac-native-launch.exe` 启动并注入 `NativeBridge.dll`；产物缺失、哈希不一致、DLL 注入失败或 `native.bridge=ready` 超时都会拒绝启动，不会回退到未注入进程。Code Profile 的非 Native 启动仍使用普通 wrapper 路径。

Native 层始终只做用户态返回值和用户态指令入口处理。内核边界在 [native/kernel/](native/kernel/) 单独实现：`CacKernel.sys` 提供 5 个窄 IOCTL、per-PID 策略表、进程退出清理和 128 条审计环，通过 SCM 安装；NativeBridge 会把主进程及被注入的同镜像子进程注册到该策略表，并回读确认。当前本机验收状态为 `RUNNING_VERIFIED` / `CONTROL_PLANE_ONLY`，`kernelPolicyStatus=TestSigned` 表示本机启用了测试签名，不等于 Microsoft 生产内核签名。该控制面不 hook SSDT/IDT、不伪造 CPUID、SMBIOS、物理网卡、磁盘或固件；手动映射器和易受攻击驱动加载器仍被拒绝。

内核控制面命令：

```powershell
npm run kernel:build
npm run kernel:install -- -Force
npm run audit:kernel -- -Strict
npm run kernel:smoke
npm run kernel:uninstall
```

控制客户端：

```powershell
native/kernel/bin/cac-kernelctl.exe ping
native/kernel/bin/cac-kernelctl.exe register --pid 1234 --profile profile-a --flags 1
native/kernel/bin/cac-kernelctl.exe query --pid 1234
native/kernel/bin/cac-kernelctl.exe audit --max 32
```

发布前一致性检查：

```powershell
npm run audit:release
npm run audit:native -- -EnvName profile-a
npm run audit:desktop -- -Profile profile-a -RequireChild -RequireRendererUtility -AllowPartial
npm run audit:desktop -- -Profile profile-b -RequireChild -RequireRendererUtility -AllowPartial
npm run audit:kernel
npm run audit:kernel -- -Strict
npm run native:wfp:smoke
```

`audit:desktop` 默认对未观察到的 WMI、异步 DeviceIoControl、CPU manifest 或进程快照返回非零；`-RequireKernel` 要求看到 `kernel.policy=verified`，`-RequireWfp` 要求看到 WFP 安装证据；`-AllowPartial` 只允许查看当前会话证据，不会把未观察到的路径标记为已覆盖。完整验收仍以 `desktop-native-check.json` 的 `status=PASS` 为准。

Desktop 审计会按 NativeBridge 会话中的每个 PID读取 `ParentProcessId`、`ExecutablePath` 和 `CommandLine`，并把父子 PID、`--user-data-dir` Profile 参数、仅回环的 `--proxy-server`/DNS/QUIC/WebRTC 参数以及 Native 模式的 Chromium `--no-sandbox`、`--disable-gpu-sandbox` 和子进程 `--type` 参数写入 `processMetadata`/`processAssertions`。进程树已在审计前退出时，字段写为 `observed=false`，结果为 `PARTIAL`；这类查看命令不会启动真实 Desktop。

`audit:native` 只读取 `%USERPROFILE%\.cac\envs\<name>` 下的 Claude Code 证据；Claude Desktop 必须使用 `audit:desktop`，两者的日志目录和结论不能混用。

Native 读取策略默认为 `profile`，保证返回值具有一致的 Profile 语义。将当前 Profile 的 `native_read_policy` 写为 `empty` 后，NativeBridge 会对已覆盖的设备身份读取返回空字符串、零序列号、无固件数据、无 WMI 属性或无设备枚举结果；`cpuid_mode` 默认为 `neutral`，在 `empty` 策略下自动改为 `empty`。`empty` 模式作用于主进程、renderer/utility 子进程和 WMI 同步查询；CacKernel 负责注册/生命周期审计，WFP 出口规则需要单独启用。

启用某个 Code Profile 的严格空值策略：

```powershell
Set-Content "$env:USERPROFILE\.cac\envs\profile-a\native_read_policy" "empty" -Encoding ASCII
Set-Content "$env:USERPROFILE\.cac\envs\profile-a\cpuid_mode" "empty" -Encoding ASCII
```

### Claude Desktop Profile

Desktop 使用独立启动器，不复用 Claude Code 的 `CLAUDE_CONFIG_DIR`：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action create -Profile work
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action launch -Profile work -Inject
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action launch -Profile work -Inject -RequireKernel
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action ab -Inject -WaitSeconds 45
```

启动器把 `APPDATA` 放在 `USERPROFILE\home\AppData\Roaming` 下，并隔离 `Claude`、`Claude-3p`、`ant-did`、sessions 和 Crashpad。不要用 `CLAUDE_USER_DATA_DIR`：Desktop 会删除/忽略该变量。

### Profile 代理池与无 DNS 泄漏链

代理池文件位于 `%USERPROFILE%\.cac\proxy-pool.json`。新建 Code/ Desktop Profile 时，会按 `claude-code:<name>` 或 `desktop:<name>` 自动绑定当前负载最小的启用代理；显式写入 Profile 的 `proxy` 文件时，显式代理优先。推荐统一使用 `socks5h://user:pass@host:port`，输入 `socks5://` 也会自动规范为 `socks5h://`。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\proxy-pool.ps1 -Action add -Proxy socks5h://user:pass@proxy.example:1080
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\proxy-pool.ps1 -Action list
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\proxy-pool.ps1 -Action auto-bind -AccountKey claude-code:profile-a,desktop:profile-a
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\proxy-pool.ps1 -Action rebalance -AccountsFile .\accounts.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\proxy-pool.ps1 -Action unbind-all
```

启动时不会把上游 SOCKS5 地址直接交给 Claude。cac 会先启动 Profile 专属的 `proxy-relay.js`，进程和所有后代只拿到 `http://127.0.0.1:<port>`；relay 对 HTTPS `CONNECT` 和明文 HTTP 请求都通过 SOCKS5 的域名地址类型 `ATYP=3` 发送目标主机名，因此目标 DNS 在上游代理解析，失败时本地 relay 断开且 `network_mode=enforce` 的动态 WFP 规则只允许回环连接。Desktop 还追加 `--proxy-server`、`--host-resolver-rules`、`--disable-quic` 和 WebRTC 禁止非代理 UDP，renderer/utility/GPU/登录页继承同一代理链。

只要 Profile 配置了代理，启动器会自动把 `network_mode=profile` 提升为 `enforce`；没有已校验的 NativeBridge/WFP 时拒绝启动，避免某个不遵守代理环境变量的 Node、Bun、WinHTTP 或 Socket 子进程直连。

代理池容量提示默认按“账号数 > 启用代理数 × 2”弹窗；每代理承载数默认 2，可用 `-Action settings -AccountsPerProxy N -WarningMultiplier 2` 调整。上游代理服务器自己的域名仍由本机解析；目标站点域名不会在本机解析。Claude Code 调起系统外部浏览器的场景不受 Desktop Chromium 参数控制，Desktop 内嵌登录浏览器会继承该链。

### CAC Account Manager EXE

仓库内新增 `account-manager` Electron 工程，提供账号卡片、Profile 切换、网页登录会话、JSON 导入/导出、SOCKS5 代理池、显式绑定/解绑、代理远端 DNS 验活和活动日志。管理器复用本目录的 Desktop/代理脚本，不维护第二套 Profile 或 relay 状态。

```powershell
cd E:\环境\huanjing\account-manager
npm install
npm run lint
npm run smoke
npm run dist
```

产物位于 `account-manager\dist\`：`cac-account-manager-0.1.0-x64-portable.exe` 和 `cac-account-manager-0.1.0-x64-setup.exe`。账号 JSON 默认只导出元数据；包含登录会话时使用 Windows DPAPI 保护的 `safeStorage` 快照，不把 Cookie 明文写入导出文件。管理器删除账号只移除索引和代理绑定，不删除 Profile 目录。

> **为什么必须通过 `claude` wrapper（或 cac 菜单）启动？** claude.exe 是 Bun 打包的单文件程序，内置了预编译的 JSC 字节码。默认情况下运行时直接执行字节码，**内嵌的 JS 源码根本不会被读取，补丁等于没打**。wrapper 启动时会设置 `BUN_JSC_useCodeCache=false`，强制 Bun 放弃字节码、回退到（已打补丁的）源码执行。代价是启动慢约 0.3 秒。直接双击或用绝对路径运行 claude.exe 不会带上这个变量，补丁不生效。

### Desktop 子进程注入与沙箱

`-Inject` 模式通过 `CreateProcessW`、`CreateProcessInternalW` 和 `NtCreateUserProcess` 三条创建路径注入子进程，并由启动器轮询补注入遗漏的后代进程。每次子进程注入都必须收到对应 `native.bridge=ready` 信号；注入失败或 ready 超时会终止该子进程，不会放行未覆盖的 renderer/utility。Chromium 的 GPU/renderer 在启用 ACG/CIG 后会拒绝加载未签名 DLL，因此 Native 模式会追加：

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

### 动态出口边界（network_mode=enforce）

```powershell
Set-Content "$env:USERPROFILE\.cac\desktop\work\network_mode" "enforce" -Encoding ASCII
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action launch -Profile work -Inject -RequireKernel
```

`enforce` 仅在 NativeBridge 进程内安装动态 WFP 规则：允许 `127.0.0.1` / `::1` 回环连接，阻断该 Claude 镜像的非回环 ALE Connect；安装失败会记录 `wfp.policy=failed` 并拒绝启动。它是用户态创建的动态 WFP 策略，不是 NDIS 轻量过滤器、WFP callout 驱动，也不会改变物理网卡、路由器或服务端看到的出口地址。

### 浏览器指纹 MITM（-Fingerprint）

Claude Desktop 拒绝 `--remote-debugging-port` / `--remote-debugging-pipe` / `--inspect`，因此指纹层改用 MITM：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action launch -Profile work -Fingerprint
```

启动器会生成 Profile 内的 `fingerprint.json`，使用 Profile 专属的 `mitmproxy` `confdir` 启动 `mitmdump`，安装该 Profile CA 到 CurrentUser Root，并给 Claude 加 `--proxy-server=http://127.0.0.1:<port>`。登录页和 hCaptcha iframe 的 HTML 会注入 `fingerprint-shim.js`。证书校验按当前 Profile CA 的 SHA-1 指纹匹配，不按宽泛 Subject 匹配。

实测：

```text
inject claude.ai/login
inject newassets.hcaptcha.com/.../hcaptcha.html
probe {"hc":24,"tz":"Asia/Shanghai","offset":-480,"persona":true}
```

`fingerprint.json` 可编辑 timezone / locale / screen / webgl / canvasNoise / audioNoise。`-Inject` 与 `-Fingerprint` 可同时使用。

安全提示：`-Fingerprint` 会安装 mitmproxy CA 到当前用户 Root 存储，并用 `--proxy-server` 接管 Claude 的 Chromium 流量；不使用该开关时不安装 CA、不改代理。

CA 安装/删除已改为静默自动化：`cert-silent.ps1` 检测标准安全警告窗口并自动确认，不再需要手动点击。删除命令：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-profile.ps1 -Action remove-ca -Profile work
```

`remove-ca` 必须传入 `-Profile`，只按该 Profile 的 CA 文件指纹删除；缺少 Profile、CA 文件缺失或指纹无效都会拒绝执行，避免误删其他 Profile 的证书。Windows CurrentUser Root 本身是用户级共享证书存储，因此 Profile 隔离依赖“独立 CA 文件 + 精确指纹删除”，不能宣称证书存储是内核级隔离。

### 内核 / NDIS / WFP / 物理硬件边界

用户态已覆盖这些表面的可访问路径：`EnumDeviceDrivers`、`NtQuerySystemInformation(SystemModuleInformation)`、`GetIfTable2/GetIfEntry2`、`GetAdapters*`、`SetupDiGetClassDevsW`、`NtDeviceIoControlFile` 和原始设备 `CreateFileW`。在 `empty` 策略下，驱动列表、设备枚举和原始设备打开会被清空或拒绝。

当前最高上限已经实现为：签名（本机为测试签名）WDM 控制面、per-PID 策略注册/退出清理、NativeBridge 子进程注册、动态 WFP 出口规则和用户态设备读取覆盖。仍未实现的是 NDIS 轻量过滤器、WFP callout 驱动、驱动内部的硬件读取重写、DPAPI/凭据硬件绑定以及物理 BIOS/SMBIOS/CPUID 的宿主级替换；这些不是普通 DLL Hook 能可靠完成的功能，审计不会把它们标记为已隔离。

## 致谢

本项目基于 [cac](https://github.com/nmhjklnm/cac) 改造，原项目提供了完整的 macOS / Linux 支持。

## License

MIT
