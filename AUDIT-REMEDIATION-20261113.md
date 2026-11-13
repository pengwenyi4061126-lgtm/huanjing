# 修复清单 2026-11-13

> 2026-11-14 复核补充：Desktop 启动实例绑定、PID 身份复核和 cleanup 临时脚本竞态已修复；下方历史文件名保留不变。

| 优先级 | 问题 | 修复 | 验收 |
|---|---|---|---|
| P0 | `psapi!EnumDeviceDrivers` 重复 inline hook 被误报失败 | `HookEngine` 增加已安装 target 的 trampoline 复用；forwarder alias 记录为 `api.install=alias` | Desktop A/B 两个 Profile `apiInstallFailures=0` |
| P0 | `hid!HidD_GetSerialNumberString` 常见 `lea r64,[rsp+disp8]` 无法解码 | 扩展 x64 前导指令解码器，继续 fail-closed | Native smoke HID 通过；Desktop A/B 失败数 0 |
| P0 | Native DLL/启动器清单不同步 | 发布检查和启动器同时校验 DLL、启动器及两份 SHA-256 manifest，并在构建后同步安装目录 | `1.0.44` 工作树、npm 包、安装目录和两份 manifest 哈希一致；`npm run audit:release` 通过 |
| P0 | Desktop renderer/utility 证据不足 | 保留创建时注入、后代补偿和进程类型统计 | A/B 每个 Profile 均观测 renderer=5、utility=1 |
| P0 | Desktop 进程树证据缺少 PID 级命令行校验 | `desktop-native-check.ps1` 按 PID 采集 `ParentProcessId`、`ExecutablePath`、`CommandLine`，并断言 Profile `--user-data-dir`、回环代理参数和 Chromium `--type`/Native 沙箱参数；历史 PID 已退出时输出 `observed=false`/`PARTIAL` | A/B `schema=2`；本轮每个 Profile known PID=9、历史进程已退出，未伪造 PASS |
| P0 | 子进程注入失败后仍可能放行未覆盖进程 | 子进程与 launcher 后代注入统一等待 `native.bridge=ready`；失败或超时终止目标进程 | Native smoke 子进程通过；A/B childInjectionFailures=0 |
| P0 | Native 子进程注入失败只能等超时 | `CreateProcess*` 和 `NtCreateUserProcess` 同时等待 `Ready/Failed` 事件，失败立即终止并返回错误 | Native smoke 子进程注入通过；源码路径统一使用双事件 |
| P1 | 关键 API 可被动态 `GetProcAddress` 绕过 | 网络、存储、注册表、设备、句柄和 completion 入口改为 inline-primary，再补 IAT/delay-IAT | Native smoke 动态 SetupDi、raw device、delay import 全部通过 |
| P1 | CA 删除可能误删共享证书 | 删除必须使用 Profile 现有 CA 指纹；缺失/无效证书直接拒绝 | CA 安装/删除 fail-closed |
| P1 | MITM 启动或证书安装失败仍继续启动 | MITM/CA 任一失败就停止关联进程、删除 PID 文件并阻止 Desktop 启动 | 启动流程返回 `blocked=true` |
| P1 | 审计脚本把无证据写成 PASS | `native-boundary-check` 和 Desktop check 区分 FAIL/PARTIAL/NOT_CONFIGURED/NOT_OBSERVED | 缺少证据返回非零；`-AllowPartial` 仅用于查看 |
| P1 | Node/CDP 运行时版本和 WebRTC shim 覆盖不足 | 增加 Node 内建 HTTP/TLS fallback、UA/UA-CH、WebRTC listener/getStats 和重复注入保护 | JS/Python 语法检查通过 |
| P1 | 网络检查只看环境变量 | 增加 DNS、路由、直连 socket 和代理继承证据，明确不修改系统路由 | 无代理结果为 `NOT_CONFIGURED` |
| P1 | 发布入口和版本漂移 | `cac.ps1`/README/package 当前统一到 1.0.44，npm `bin` 指向 `cac.cmd`，CI/发布流程改读 Windows 版本源 | 版本、npm 包、安装目录和 Native manifest 一致；`npm run audit:release` 通过 |
| P1 | CI shell 与本机 Windows PowerShell 不一致 | Windows audit workflow 的四个 PowerShell 步骤统一为 `shell: powershell` | workflow 源码检查通过 |
| P1 | Desktop 生命周期和清理存在并发竞态 | 启动、monitor、cleanup、remove-ca 使用 Profile mutex；monitor 验证路径/启动时间并清理已认证进程树；cleanup 递归拒绝 reparse point | Windows PowerShell 5.1 parser 24/24 通过；未启动真实 Desktop |
| P1 | 上游代理凭据泄漏到 Claude 子进程和转发头 | 子进程只继承本地 relay、proxyId/source；relay 拒绝 URL argv 并过滤 Proxy-Authorization/Proxy-Connection/hop-by-hop headers | relay smoke、代理池 smoke 通过 |
| P2 | Cookies/登录态没有真实账号证据 | 当前报告只记录路径和哈希，不再宣称登录隔离完成 | 需登录后补 Cookie/Token/DPAPI 读取审计 |
| P2 | WDK/内核边界缺失 | 实现签名 WDM 控制面 `CacKernel.sys`：5 个窄 IOCTL、per-PID 策略、128 条审计环、SCM 安装/卸载、哈希与签名校验；保留 `audit:kernel` 证据门并拒绝手动映射器和易受攻击驱动 | 本机 `RUNNING_VERIFIED` / `CONTROL_PLANE_ONLY`；NDIS/WFP/物理硬件仍未实现 |

## 最终修复：当前验收命令

```powershell
Set-Location E:\环境\huanjing
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/release-check.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/tests/run-smoke.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/tests/run-wfp-smoke.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/proxy-pool-smoke.ps1
node scripts/proxy-relay-smoke.js
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/desktop-native-check.ps1 -Profile profile-a -RequireChild -RequireRendererUtility -AllowPartial
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/desktop-native-check.ps1 -Profile profile-b -RequireChild -RequireRendererUtility -AllowPartial
```

Windows PowerShell 5.1 parser 对 24 个脚本全部返回 `errors=0`。Native、WFP、代理池、relay 和 release 门禁均通过。A/B Desktop audit 命令均退出码 0，证据文件 `schema=2`、状态 `PARTIAL`；known PID 各 9 个但进程已退出，所以 `ParentProcessId`、`ExecutablePath`、`CommandLine` 当前均为未观察到。未启动真实 Desktop。

当前工作树与安装目录 NativeBridge SHA-256 均为 `1C98CA2EA7E8ECE4EE28882D7D5A6048E404A2B373B95235A9C6B8C17FC3F58A`，launcher SHA-256 均为 `080D8E6EBCF9020C42D1D5A231BB8425B9B9532405C9778B17F8959B08717BDD`。Desktop 真实启动、登录态 Cookie/DPAPI、WMI/COM 运行时和异步 pending `NtDeviceIoControlFile` 仍未在本轮获得完整实机证据，按 `PARTIAL` 记录。

第一轮包含真实 Desktop A/B 的启动命令，保留为历史流程；第二轮命令只读取已存在的 NativeBridge 日志，不启动真实 Desktop。
