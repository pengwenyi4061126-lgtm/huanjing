# CacMacLwf guest smoke evidence (2026-11-16)

环境：隔离测试机，Windows 11 22631.7376，test signing，服务 RUNNING。

## Soak

```text
cycles: disableEnable=3, restart=2, sleep=0, traffic=0
pass: true
newDumps: []
newBugChecks: 0
failures: []
```

关键计数：

```text
baseline: oidQueriesSeen=225, oidRewrites=2, attached=1
final:    oidQueriesSeen=1508, oidRewrites=12, attached=6, detached=5
MAC:      02:11:22:33:44:55
```

## Fault injection

```text
clone fail (faultMode=1): ok
lower fail (faultMode=2): ok
fault reset (faultMode=0): ok
set-short:   rejected (Win32 122)
set-long:    rejected (Win32 122)
state-short: rejected (Win32 122)
fault-invalid: rejected (Win32 87)
pass: true
newDumps: []
newBugChecks: 0
```

## 文件

```text
soak-20261116-150444/soak.jsonl
soak-20261116-150444/summary.json
fault-20261116-150548/fault.jsonl
fault-20261116-150548/summary.json
soak.log
soak-error.log（包含修复前的两次失败记录，保留作为排查证据）
```

## 备注

- 本次 smoke 暴露并修复了两个测试脚本 bug：
  `Write-Record` 在创建目录前写文件；`$Input` 与 PowerShell 自动变量冲突。
- 完整 30× disable/enable、10× restart、2h 流量、5× boot 和低权限
  IOCTL 测试在后续独立运行中归档。
