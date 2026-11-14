# CAC Account Manager

Electron 账号管理器，面向 `cac-windows` 的 Claude Desktop Profile。

## 已实现

- 账号列表、创建、编辑、删除、启用状态和最近使用信息。
- 每个账号绑定独立 Desktop Profile，复用 `scripts/desktop-profile.ps1` 的 `APPDATA`、`LOCALAPPDATA`、`USERPROFILE`、`TEMP/TMP` 和 `--user-data-dir` 隔离。
- 网页登录窗口：每个账号使用独立持久化 Chromium partition，关闭窗口时保存 Cookie 数量、域名和 DPAPI 加密的 Cookie JSON 快照。
- 登录窗口代理：使用账号绑定的 SOCKS5/SOCKS5H；未绑定时使用系统直连。
- 代理池：复用 `%USERPROFILE%\\.cac\\proxy-pool.json`，支持添加、删除、显式绑定、解绑、自动绑定、容量告警和 SOCKS5 远端域名验活。
- JSON 导入/导出：默认 metadata-only；包含会话时使用 Electron `safeStorage`，Windows 下为 DPAPI 保护，导出的会话备份默认只能在同一 Windows 用户环境恢复。
- 账号切换：停止其他已登记 Profile，确保代理绑定，再调用现有 Desktop 启动器；保留现有 Native/Fingerprint 开关。
- 事件审计：不记录 Cookie 值、代理密码和登录页面内容。

## 开发与构建

```powershell
cd E:\环境\huanjing\account-manager
npm install
npm run lint
npm run smoke
npm run dist
```

构建产物位于 `dist\\`，包含 portable EXE 和 NSIS 安装包。打包后会把 Desktop 启动脚本、代理池脚本、relay 入口和 NativeBridge 目录放入 `resources\\cac-runtime\\`，因此 EXE 不依赖当前工作目录。

## 数据位置

管理器自身数据：`%APPDATA%\\cac-account-manager\\accounts.json`。

Profile 与代理池仍由主项目统一管理：

- `%USERPROFILE%\\.cac\\desktop\\<profile>`
- `%USERPROFILE%\\.cac\\proxy-pool.json`

删除管理器中的账号只删除管理器索引和对应的代理绑定，保留 Profile 数据，避免误删登录会话。需要清理 Profile 时使用现有 `desktop-profile.ps1 -Action cleanup -Profile <name>`。
