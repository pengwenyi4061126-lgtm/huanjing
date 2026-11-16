# CacMacLwf Coverage Matrix

更新时间：2026-11-16

| 面 | 覆盖点 | 状态 | 证据 |
|---|---|---|---|
| 代码 | Pause 返回 SUCCESS，不阻塞 | DONE | `CacMacLwf.c` / `de2d8d1` |
| 代码 | Send/Receive 完成链转发 | DONE | `NdisFSendNetBufferListsComplete` / `NdisFReturnNetBufferLists` |
| 代码 | OID clone 下发与完成回写 | DONE | `NdisAllocateCloneOidRequest` / `NdisFOidRequestComplete` |
| 代码 | 只改写 MAC OID | DONE | `CacMacFilterOidRequestComplete` |
| 代码 | 控制设备 ACL + IOCTL 边界 | DONE | `IoCreateDeviceSecure` / `CAC_MAC_IOCTL_*` |
| 代码 | 测试用 fault mode（clone/lower） | DONE | `CAC_MAC_IOCTL_FAULT` / `cac-macctl fault` |
| 构建 | `bin/CacMacLwf.sys` 单一源 | DONE | `bin/BUILD.json` |
| 构建 | SHA-256 manifest | DONE | `bin/CacMacLwf.sha256` |
| 构建 | cat + 签名 | DONE | `bin/CacMacLwf.cat` / Valid |
| 安装 | 安装前/复制后哈希闸门 | DONE | `install-macfilter.ps1` |
| 安装 | 卸载 stop/delete/unbind/cleanup | DONE | `install-macfilter.ps1 -Uninstall` |
| 测试 | `-DryRun` 无副作用校验 | DONE | `install` / `soak` / `fault` |
| 测试 | 5× Restart-NetAdapter + boot + ping | DONE（clone 构建） | `LWF-FIX-TEST-20261116.md` §8-9 |
| 测试 | 30× disable/enable + 10× restart + 3× sleep | READY（待隔离机执行） | `run-macfilter-soak.ps1` |
| 测试 | 2h 流量 + 100 并发 TCP + OID storm | READY（待隔离机执行） | `run-macfilter-soak.ps1` |
| 测试 | 5× boot | READY（手动 `-RecordBoot`） | `run-macfilter-soak.ps1` |
| 测试 | clone fail / lower fail / invalid IOCTL | READY（待隔离机执行） | `run-macfilter-fault.ps1` |
| 测试 | 低权限 IOCTL 拒绝 | READY（需标准账号） | `run-macfilter-fault.ps1 -LowPrivCredential` |
| 安全 | `SYSTEM + Administrators` ACL | DONE（待运行时验证） | `IoCreateDeviceSecure` |
| 文档 | STATUS/README/RESEARCH/AUDIT-CRASH 收敛 | DONE | `STATUS.md` + 三处横幅 |
| 边界 | 缓存 MAC 不改 | BOUNDARY | `getmac`/WMI/`ipconfig` 仍硬件 MAC |
| 边界 | 真实 MAC / 按进程 MAC | BOUNDARY | 不在 LWF 能力内 |
| 边界 | Ring-0 / TPM / PCI / DMA | OUT-OF-SCOPE | 不在本项目 |

## 状态定义

- `DONE`：代码/文档/构建已完成，且有本地可复核证据。
- `READY`：脚本与验收标准已就绪，等待隔离测试机执行并产出 JSONL。
- `BOUNDARY`：已确认的能力边界，不作为失败项。
- `OUT-OF-SCOPE`：明确不在本组件范围。

## 当前结论

```text
0x1E:        CLOSED (de2d8d1 + clone build 37012AD5...)
当前构建:    DA5AC063... (ACL/IOCTL/fault)
运行时 soak: PENDING (隔离测试机)
覆盖等级:    STABLE-PASSTHROUGH + OID-VIEW
```
