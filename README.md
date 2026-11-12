# cac-windows

Claude Code 的 Windows 隐私保护工具 — 二进制补丁抹除中国特征，遥测正常流转。

当前版本：`1.0.27`，适配 Claude Code `2.1.294`。

## 功能

- **隐私补丁** — 自动补丁 claude.exe，抹除时区（Asia/Shanghai → TZ）、语言（zh → en）、UTC 偏移（+08:00 → +00:00）
- **时区对齐** — 系统提示词日期和时区跟随 TZ 环境变量
- **代理支持** — HTTP / SOCKS5 代理配置
- **环境切换** — 多环境管理（换号用）
- **封号清理** — 清除追踪数据
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

`cac` 首次运行自动完成初始化：定位 claude.exe（未安装则自动安装 2.1.294）、生成 wrapper、把 `%USERPROFILE%\.cac\bin` 加到用户 PATH 中 npm 目录之前、应用补丁。之后进入菜单：

```
1. 启动 Claude Code
2. 环境管理        （切换 / 创建 / 删除环境，设时区、代理，清空回收站）
3. 版本更新并应用补丁
4. 清理追踪数据    （换号用）
5. 查看状态
0. 退出
```

上下键选择，回车确认，Esc 返回。

配置完成后**重开一个终端**，之后直接敲 `claude` 即可——wrapper 会自动读取当前环境的时区、代理、身份并启动打过补丁的 claude.exe。日常不需要再打开 cac；只有 Claude Code 官方版本落后太多需要升级时，再运行 `cac` 选「版本更新并应用补丁」。

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

> **为什么必须通过 `claude` wrapper（或 cac 菜单）启动？** claude.exe 是 Bun 打包的单文件程序，内置了预编译的 JSC 字节码。默认情况下运行时直接执行字节码，**内嵌的 JS 源码根本不会被读取，补丁等于没打**。wrapper 启动时会设置 `BUN_JSC_useCodeCache=false`，强制 Bun 放弃字节码、回退到（已打补丁的）源码执行。代价是启动慢约 0.3 秒。直接双击或用绝对路径运行 claude.exe 不会带上这个变量，补丁不生效。

## 致谢

本项目基于 [cac](https://github.com/nmhjklnm/cac) 改造，原项目提供了完整的 macOS / Linux 支持。

## License

MIT
