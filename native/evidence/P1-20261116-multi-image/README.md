# 不同镜像子进程覆盖证据（2026-11-16）

## 覆盖策略

`NativeBridge` 的 child injection 现在区分：

```text
同镜像 child
硬件/网络工具镜像（cmd/powershell/wmic/systeminfo/reg/sc/...）
Claude 自有 Go helper（claude-ssh-*、github-mcp-server）
MCP host（node/bun/python/uvx/npx/...）
```

服务注入器额外轮询 `cowork-svc` 后代，只注入 allowlist 镜像；
`conhost`、`WerFault`、`vmcompute/vmwp/vmms`、`wslservice`、
`dllhost/wmiprvse/RuntimeBroker` 不 blanket 注入。

## 多镜像 CPU manifest

`service-cpu-manifest.txt` 现在包含 16 条：

```text
cowork-svc.exe             4
claude-ssh-broker.exe      2
claude-ssh-proxy.exe       2
claude-ssh-askpass.exe     2
github-mcp-server.exe      6
```

NativeBridge 只安装当前主模块的条目；其他模块记录
`cpu.manifest not-applicable`，不增加 required failure。

## 实测

### github-mcp-server.exe

`github-mcp-audit.jsonl`：

```text
native.child candidate image=github-mcp-server.exe same=0 tool=0 helper=1 mcp=0
cpu.install gocpuid 0x4DA0 / 0x237B80 / 0x3B7F60
cpu.install goxgetbv 0x4DC0 / 0x237BA0 / 0x3B7F80
cpu.manifest complete entries=16 installed=16
cpu.flags skipped no-flag-layout
api.install complete failures=0
native.bridge ready
```

`github-mcp-server --help` 正常输出，exit 0。

### claude-ssh-broker.exe

`ssh-broker-audit.jsonl`：

```text
cpu.install gocpuid 0x29C0 / goxgetbv 0x29E0
cpu.flags skipped no-flag-layout
api.install complete failures=0
native.bridge ready
```

直接运行时输出 `configuration unreadable`（exit 64），但注入/ready/CPU
hook 全部成功。

### claude-ssh-proxy.exe / claude-ssh-askpass.exe

`ssh-proxy-askpass-audit.jsonl`：

```text
proxy:    cpu.flags skipped no-flag-layout
askpass:  cpu.flags skipped no-flag-layout
两者 api.install complete failures=0，native.bridge ready
```

两个 helper 直接运行都返回“run directly does nothing”，但注入成功。

### 工具镜像

`cmd.exe` child 审计：

```text
native.child candidate image=cmd.exe same=1 tool=1 helper=0 mcp=0
```

说明硬件 profile 下 `toolImage` 已与 `NativeCleanNetworkEnabled` 解耦。

## 服务侧

`cac-service-injector.exe` 新增 `cowork-svc` 后代轮询：

```text
DescendantsOf(root) + allowlist
  → InjectAndWait(child)
  → audit descendant-injected / descendant-failed
```

当前 `cowork-svc` 没有活动子进程，所以本轮没有 live descendant 记录；
代码路径已编译并在服务重启后保持 ready。

## 边界

- `github-mcp-server` 的 CPUID/XGETBV 入口已挂载（6 条），但
  internal/vendor CPU flags 的镜像 RVA 尚未验证，当前明确跳过
  `no-flag-layout`。
- SSH helper 的 CPUID/XGETBV 入口已挂载（各 2 条），flags 同样
  未验证，当前跳过 `no-flag-layout`。
- `chrome-native-host.exe` 是 Rust，未命中硬件 API 字符串，暂不注入。
- `vmcompute/vmwp/vmms/wslservice`、`dllhost/wmiprvse/RuntimeBroker`
  不 blanket 注入；系统/PPL 组件需要 HCS/VM 边界或按 CLSID 选择性处理。
- 子进程注入失败仍然 fail-closed；没有 Job Object kill-on-close，
  父进程退出后的孤儿后代仍需独立清理。
- 短命工具进程（毫秒级）可能在被注入前退出；服务后代轮询是 50ms，
  Desktop launcher 是 300ms，不能证明零窗口。

## 文件

```text
multi-image-manifest.txt
github-mcp-audit.jsonl
ssh-broker-audit.jsonl
ssh-proxy-askpass-audit.jsonl
service-audit.jsonl
hashes.txt
```
