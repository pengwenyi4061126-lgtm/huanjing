# 修复清单 2026-11-13

| 优先级 | 问题 | 修复 | 验收 |
|---|---|---|---|
| P0 | `psapi!EnumDeviceDrivers` 重复 inline hook 被误报失败 | `HookEngine` 增加已安装 target 的 trampoline 复用；forwarder alias 记录为 `api.install=alias` | Desktop A/B 两个 Profile `apiInstallFailures=0` |
| P0 | `hid!HidD_GetSerialNumberString` 常见 `lea r64,[rsp+disp8]` 无法解码 | 扩展 x64 前导指令解码器，继续 fail-closed | Native smoke HID 通过；Desktop A/B 失败数 0 |
| P0 | Native DLL/启动器清单不同步 | 发布检查和启动器同时校验 DLL、启动器及两份 SHA-256 manifest | `npm run audit:release` 通过 |
| P0 | Desktop renderer/utility 证据不足 | 保留创建时注入、后代补偿和进程类型统计 | A/B 每个 Profile 均观测 renderer=5、utility=1 |
| P0 | 子进程注入失败后仍可能放行未覆盖进程 | 子进程与 launcher 后代注入统一等待 `native.bridge=ready`；失败或超时终止目标进程 | Native smoke 子进程通过；A/B childInjectionFailures=0 |
| P1 | 关键 API 可被动态 `GetProcAddress` 绕过 | 网络、存储、注册表、设备、句柄和 completion 入口改为 inline-primary，再补 IAT/delay-IAT | Native smoke 动态 SetupDi、raw device、delay import 全部通过 |
| P1 | CA 删除可能误删共享证书 | 删除必须使用 Profile 现有 CA 指纹；缺失/无效证书直接拒绝 | CA 安装/删除 fail-closed |
| P1 | MITM 启动或证书安装失败仍继续启动 | MITM/CA 任一失败就停止关联进程、删除 PID 文件并阻止 Desktop 启动 | 启动流程返回 `blocked=true` |
| P1 | 审计脚本把无证据写成 PASS | `native-boundary-check` 和 Desktop check 区分 FAIL/PARTIAL/NOT_CONFIGURED/NOT_OBSERVED | 缺少证据返回非零；`-AllowPartial` 仅用于查看 |
| P1 | Node/CDP 运行时版本和 WebRTC shim 覆盖不足 | 增加 Node 内建 HTTP/TLS fallback、UA/UA-CH、WebRTC listener/getStats 和重复注入保护 | JS/Python 语法检查通过 |
| P1 | 网络检查只看环境变量 | 增加 DNS、路由、直连 socket 和代理继承证据，明确不修改系统路由 | 无代理结果为 `NOT_CONFIGURED` |
| P1 | 发布入口和版本漂移 | `cac.ps1`/README 更新到 1.0.41，npm `bin` 指向 `cac.cmd`，CI/发布流程改读 Windows 版本源 | npm dry-run 显示 `cac-windows@1.0.41` |
| P2 | Cookies/登录态没有真实账号证据 | 当前报告只记录路径和哈希，不再宣称登录隔离完成 | 需登录后补 Cookie/Token/DPAPI 读取审计 |
| P2 | WDK/内核边界缺失 | 保持明确标记为未实现，不用用户态 hook 冒充 NDIS/WFP/物理硬件隔离 | Native README 和审计表均标记 `NOT_IMPLEMENTED` |

## 当前验收命令

```powershell
Set-Location E:\环境\huanjing
npm run audit:release
npm run audit:profiles
powershell.exe -NoProfile -ExecutionPolicy Bypass -File native/tests/run-smoke.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/desktop-profile.ps1 -Action ab -Inject -WaitSeconds 15
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/desktop-native-check.ps1 -Profile profile-a -RequireChild -RequireRendererUtility -AllowPartial
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/desktop-native-check.ps1 -Profile profile-b -RequireChild -RequireRendererUtility -AllowPartial
```

`desktop-native-check.ps1` 去掉 `-AllowPartial` 后，未观察到 WMI、异步 pending sanitize 或 CPU manifest 会返回非零；这是严格证据门禁，不是把结果改成 PASS。Desktop A/B 的 `pathBoundaryOk` 只证明声明式 Profile 路径集合互不重叠且位于各自根目录，不等价于 ETW/Procmon 级别的实际文件访问追踪。
