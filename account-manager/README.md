# CAC Account Manager

Electron 账号管理器，面向 `cac-windows` 的 Claude Desktop Profile。

## 已实现

- 账号列表、创建、编辑、删除、启用状态和最近使用信息。
- 每个账号绑定独立 Desktop Profile，复用 `scripts/desktop-profile.ps1` 的 `APPDATA`、`LOCALAPPDATA`、`USERPROFILE`、`TEMP/TMP` 和 `--user-data-dir` 隔离。
- 网页登录窗口：每个账号使用 Profile 目录下独立的 Chromium `session.fromPath()`；登录期间监听 Claude Cookie 和页面导航事件，立即保存会话快照，关闭窗口时再做一次最终落盘。只有同时检测到 Claude 会话 Cookie 和有效 `lastActiveOrg` UUID 才标记为“已登录”，不会用 Cookie 数量冒充登录成功；备份只保存 Claude 域 Cookie，不收集 Google 等第三方站点 Cookie。验证成功后，管理器停止对应 Desktop Profile，将会话写入该 Profile 的 `Network\\Cookies`，回读 `sessionKey`/`lastActiveOrg` 验证成功后才允许启动 Desktop。
- 登录窗口复用对应 Desktop Profile 的 `fingerprint.json`；Electron Session 固定 User-Agent/Accept-Language，CDP 在文档创建前向主世界安装 shim，并同步设置 User-Agent、platform、时区和 locale。resolver 失败闭环、QUIC 禁用和非代理 WebRTC 策略同时生效，避免网页登录与 Desktop 使用两套 persona。
- 首次登录画像锁：创建 Profile 时生成 `identity.json`、`fingerprint.json` 和 `device-image.lock.json`，以原始文件 SHA-256 固定首次登录画像。首次认证成功后把同一画像摘要写入账号会话；以后只启动 Desktop EXE，启动前必须同时通过锁文件、账号会话摘要和 Electron/Chromium 版本校验。代理绑定和出口 IP 变化不参与画像摘要，不会触发画像重建。
- 登录 Native 覆盖：管理器启动时自动经已校验的 `cac-native-launch.exe` 重新启动；portable 外层自举进程同步托管 launcher，保持临时解包目录存活，真正 UI 只在已注入子实例中运行。打开登录页前把当前 Profile 的 `APPDATA`、`LOCALAPPDATA`、`USERPROFILE`、`TEMP/TMP`、Native identity 和独立审计路径传给新 renderer，并等待 `native.bridge=ready`。每次登录清空本次审计文件，历史失败不会污染新会话；独立 Electron smoke 已验证 main、GPU、utility、renderer 全部注入且无失败。
- 网页登录代理：必须使用账号绑定的 SOCKS5/SOCKS5H；打开登录页或完整 Magic Link 前自动校验 Chromium session 的本地 relay 解析结果和 `api.ipify.org` 实际出口 IP，未绑定、解析为 `DIRECT` 或出口探测失败时拒绝直连。
- Magic Link 登录：新建账号保存后可直接打开网页登录；邮箱收到登录邮件后，在网页登录对话框粘贴完整 `https://claude.ai/magic-link#...`，令牌不会写入活动日志。
- 登录窗口生命周期：同一时间只初始化一个登录窗口；切换账号前先保存上一窗口 Cookie，旧窗口的延迟 `closed` 回调不会清理新窗口的代理、环境或会话。
- 管理器单实例：第二次启动只激活现有主窗口并退出，不会并发修改账号索引、代理绑定或网页登录环境。
- 登录代理检查：网页登录对话框可通过 `api.ipify.org` 检查实际出口 IP，登录窗口和检查请求复用同一个独立 Chromium session。
- 代理池：复用 `%USERPROFILE%\\.cac\\proxy-pool.json`，支持添加、删除、显式绑定、解绑、自动绑定、容量告警和 SOCKS5 远端域名验活。
- JSON 导入/导出：默认 metadata-only；包含会话时使用 Electron `safeStorage`，Windows 下为 DPAPI 保护，导出的会话备份默认只能在同一 Windows 用户环境恢复。
- 账号切换：停止其他已登记 Profile，确保代理绑定，再调用现有 Desktop 启动器；Native/Fingerprint 固定启用，防止从管理器启动未应用首次登录画像的 Desktop。
- Desktop 会话同步：网页登录与 Desktop 使用不同的 Chromium/DPAPI 上下文，因此不依赖加密 Cookie 直接复制；管理器按 Cockpit 的方式写入 Desktop Profile 的 Chromium Cookie SQLite 数据库（`value` 明文、`encrypted_value` 为空），并在启动前检查两个必需会话 Cookie。同步失败时禁止启动，避免出现“网页显示已登录但 EXE 仍要求登录”的假成功状态。
- 事件审计：不记录 Cookie 值、代理密码和登录页面内容。
- 状态恢复：`accounts.json` 解析失败或版本异常时先保存为 `accounts.json.corrupt.<时间戳>.json`，再创建默认索引，避免启动过程覆盖损坏证据。

## 开发与构建

```powershell
cd E:\环境\huanjing\account-manager
npm install
npm run lint
npm run smoke
npm run smoke:electron
npm run smoke:native-electron
npm run smoke:bootstrap
npm run dist
npm run smoke:portable
```

构建产物位于 `dist\\`，包含 portable EXE 和 NSIS 安装包。打包后会把 Desktop 启动脚本、代理池脚本、relay 入口和 NativeBridge 目录放入 `resources\\cac-runtime\\`，因此 EXE 不依赖当前工作目录。

## 数据位置

管理器自身数据：`%APPDATA%\\cac-account-manager\\accounts.json`。

Profile 与代理池仍由主项目统一管理：

- `%USERPROFILE%\\.cac\\desktop\\<profile>`
- `%USERPROFILE%\\.cac\\proxy-pool.json`

删除管理器中的账号只删除管理器索引和对应的代理绑定，保留 Profile 数据，避免误删登录会话。需要清理 Profile 时使用现有 `desktop-profile.ps1 -Action cleanup -Profile <name>`。
