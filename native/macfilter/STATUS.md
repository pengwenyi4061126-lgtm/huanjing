# CacMacLwf Status

更新时间：2026-11-16

## 当前状态

| 项 | 值 |
|---|---|
| 修复提交 | `de2d8d1` `fix: clone OID requests before forwarding` |
| 代码基线 | `git diff de2d8d1..HEAD -- CacMacLwf.c` 为 0 |
| 构建产物 | `bin/CacMacLwf.sys` |
| 驱动 SHA-256 | `DA5AC0634A92F36EB7FCFE303D5835A4647CA2E2D8C16DCEE6157DB96C22E670`（含 ACL/IOCTL/fault 加固） |
| 签名 | `CN=CAC Kernel Test Signing` / Valid |
| 服务状态 | `DISABLED`（默认不加载） |
| 覆盖等级 | `STABLE-PASSTHROUGH + OID-VIEW` |

安装脚本默认把服务设为 `DISABLED`；隔离测试机使用
`install-macfilter.ps1 -Enable` 才会切到 `demand` 并尝试启动。

## 已验证

- `FilterPause` 不再返回失败，直接返回 `NDIS_STATUS_SUCCESS`。
- `FilterSendNetBufferListsComplete` 转发 `NdisFSendNetBufferListsComplete`。
- `FilterReturnNetBufferLists` 转发 `NdisFReturnNetBufferLists`。
- OID 请求使用 `NdisAllocateCloneOidRequest`，不再把原始
  `NDIS_OID_REQUEST` 直接下发。
- clone 构建（`37012AD5...`）实测：45 次 OID 查询、2 次 MAC 改写、send 40、receive 10、
  `ping 10/10`、连续 5 次 `Restart-NetAdapter` 无 `0x1E`。
- 开机 `SYSTEM_START` 加载实测：服务 RUNNING、`attached=1`、
  `oidQueriesSeen=138`、`oidRewrites=2`。
- 当前 ACL/IOCTL/fault 加固构建（`DA5AC063...`）已编译、签名、
  `-DryRun` 哈希闸门通过；运行时 soak 仍待隔离测试机执行。
- 2h 流量 soak `soak-20261116-174921`：`pass=true`，7201 秒，
  `newDumps=[]`、`newBugChecks=0`、`failures=[]`；`oidQueriesSeen`
  12665 → 15524，`sendForwarded` 8744 → 16125。
- 5× 重启：每次开机 `CacMacLwf` 均为 RUNNING、`attached=1`、
  `registerStatus=0`，无新 dump / 1001。
- 低权限 IOCTL：标准账号 `cactest` 打开设备失败，
  `{"ok":false,"error":"open device","win32":5}`，harness `pass=true`。
- 开机自加载条件：INF 的 `FilterRunType=2`（optional）导致
  demand-start 重启后保持 STOPPED；安装脚本 `-Enable` 已改为
  `start= system`，该配置下 5/5 次开机自加载成功。
- 控制设备通过 `IoCreateDeviceSecure` 限制为 `SYSTEM + Administrators`；
  `CAC_MAC_IOCTL_SET` 只接受 6 字节，`STATE` 只接受 0 输入，
  `FAULT` 只接受 0/1/2。
- `verify-macfilter-artifacts.ps1` 当前结果：`PASS=True FAIL=0 WARN=1`；
  唯一警告是本机已安装的旧驱动 `E3A307C0...` 仍是 11-14 版本，服务
  `DISABLED`，未加载。

## 隔离测试机运行证据

- 2026-11-16 smoke：`evidence/2026-11-16-guest-smoke/`。
- Soak：3× disable/enable、2× restart、OID storm；`pass=true`，
  `newDumps=[]`，`newBugChecks=0`，`failures=[]`；
  `oidQueriesSeen 225 → 1508`，`oidRewrites 2 → 12`，
  `attached 1 → 6`，`detached 0 → 5`。
- Fault：clone fail、lower fail、fault reset、set-short/set-long/state-short、
  fault-invalid 全部按预期；`pass=true`。
- 第一次 full run `soak-20261116-150836` 完成了 30× disable/enable、
  10× restart 和 OID storm（`attached=59`、`detached=55`、
  `oidRewrites=114`、`oidDelta=569`），但测试机在 2h 窗口结束前被
  挂起/关机，未产出 traffic complete/summary；该结果保留为
  `evidence/2026-11-16-full-aborted/`，不算 2h 通过。
- 已修复 traffic 逻辑：`SetThreadExecutionState` 防止测试机睡眠，
  deadline 循环替代裸 `Start-Sleep`，每 5 分钟写 heartbeat，结束时写
  `traffic complete`。`soak-20261116-174921` 于 19:49:48 结束，
  7201 秒，`pass=true`，`newDumps=[]`，`newBugChecks=0`，
  `failures=[]`。
- 5× 开机（`boot-20261116-final`）：5 个不同的 `LastBootUpTime`，
  每次 `SERVICE RUNNING`、`attached=1`、`registerStatus=0`。
- 低权限（`lowpriv-20261116-clean`）：`cactest` 读状态被拒，
  `win32=5`，`exitCode=1`，`failures=[]`。
- 隔离测试机 `C:\Windows\System32\drivers\CacMacLwf.sys` 实测
  SHA-256 = `DA5AC0634A92F36EB7FCFE303D5835A4647CA2E2D8C16DCEE6157DB96C22E670`，
  与本仓库 `bin` 构建一致。
- 未运行：3× sleep/resume。该 VM 的 ACPI 只暴露 S1（`powercfg /a`
  显示 S3 / 休眠均“系统固件不支持”），无法执行 S3 睡眠/恢复；
  需要 S3 可用的物理机或支持 S3 的虚拟机配置。

## 明确边界

- LWF 只改写 OID 查询结果，不改变适配器真实 MAC。
- `getmac`、`ipconfig /all`、`Get-NetAdapter`、WMI 仍显示 IP 栈缓存的
  硬件 MAC；这是 NDIS 的能力边界，不是本驱动的 bug。
- 不支持按进程改 MAC：NDIS 数据路径没有可靠的 PID 上下文。
- 不宣称 Ring-0 / TPM / PCI / DMA / 物理硬件等价。

## 制品策略

- `bin/CacMacLwf.sys` 是唯一发布源。
- 根目录 `CacMacLwf.sys`、`exp*/`、`package*/`、`pkg*/`、`vmtest/`
  仅作为历史证据，不参与安装。
- `install-macfilter.ps1` 安装前校验 `bin/CacMacLwf.sha256`，复制到
  `System32\drivers` 后再校验一次；不匹配即拒绝。
- 本机已安装的旧版 `E3A307C0...` 保持 `DISABLED`；重新启用必须先
  通过安装脚本覆盖为当前 `bin` 构建。

## 下一步

1. 在具备 S3 的目标上补 3× sleep/resume；当前 VM 固件只支持 S1。
2. 如需在无 S3 的机器上验证恢复路径，用 30× disable/enable 与
   10× restart 作为替代证据，不得声称等价于睡眠/恢复。
3. 覆盖等级保持在 `STABLE-PASSTHROUGH + OID-VIEW`；不得写成
   `MAC-ISOLATED`。
