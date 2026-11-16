# CacMacLwf Soak / Fault Runbook

适用：隔离测试机（Windows 11 22631.7376 基线），不用于生产机。

## 0. 前置条件

```text
[ ] 已创建快照：pre-lwf-soak-20261116
[ ] bcdedit /enum {current} 显示 testsigning Yes
[ ] 已安装 CacMacLwf，服务状态 RUNNING，至少一个网卡绑定
[ ] 已记录基线：sc query CacMacLwf / cac-macctl state
[ ] 已记录 C:\Windows\Minidump 文件列表
```

## 1. 安装与哈希校验

```powershell
cd E:\环境\huanjing\native\macfilter
powershell -NoProfile -ExecutionPolicy Bypass -File install-macfilter.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File install-macfilter.ps1 -Enable
Restart-Computer
```

`-Enable` 会设置 `start= demand` 并尝试启动；不带该开关时服务保持
`DISABLED`，这是生产机的默认状态。

重启后：

```powershell
sc.exe query CacMacLwf
.\bin\cac-macctl.exe state
```

预期：

```text
STATE = RUNNING
running=1
attached >= 1
registerStatus=0
```

## 2. 主 soak

```powershell
.\run-macfilter-soak.ps1 `
  -AdapterName Ethernet0 `
  -Mac 02:11:22:33:44:55 `
  -DisableEnableCycles 30 `
  -RestartCycles 10 `
  -SleepCycles 3 `
  -TrafficSeconds 7200 `
  -ConcurrentTcp 100 `
  -TrafficTarget 192.168.1.10:443
```

没有固定 target 时去掉 `-TrafficTarget`；仍然会 ping 默认网关。

输出：

```text
evidence/soak-<timestamp>/soak.jsonl
evidence/soak-<timestamp>/summary.json
```

通过条件：

```text
summary.pass = true
newDumps = []
newBugChecks = 0
failures = []
```

## 3. 启动循环（5 次）

每次重启后执行：

```powershell
.\run-macfilter-soak.ps1 -RecordBoot
```

共 5 次；每次记录 `boot` 事件。若任意一次出现 `0x1E`，停止并收集：

```text
C:\Windows\Minidump\*.dmp
C:\Windows\MEMORY.DMP
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001}
```

## 4. 故障注入

```powershell
.\run-macfilter-fault.ps1 -OidStormIterations 30
```

覆盖：

```text
clone 分配失败（faultMode=1）
下层 OID 失败（faultMode=2）
SET 长度 5/7
STATE 输出 4 字节
FAULT mode=3
```

低权限测试（可选，标准账号）：

```powershell
$cred = Get-Credential
.\run-macfilter-fault.ps1 -LowPrivCredential $cred
```

预期：`cac-macctl state` 以非零退出，`DeviceIoControl` 返回
`ERROR_ACCESS_DENIED`。

## 5. 证据归档

```text
evidence/soak-<timestamp>/soak.jsonl
evidence/soak-<timestamp>/summary.json
evidence/fault-<timestamp>/fault.jsonl
evidence/fault-<timestamp>/summary.json
bin/BUILD.json
bin/CacMacLwf.sha256
Get-WinEvent 1001 导出
```

## 6. 失败处置

```powershell
sc.exe stop CacMacLwf
sc.exe config CacMacLwf start= disabled
```

然后：

1. 保存 minidump；
2. 记录 `cac-macctl state`（如果还能打开设备）；
3. 回滚到 `pre-lwf-soak-20261116` 快照；
4. 不要在同一台机器上反复 stop/start 驱动。

## 7. 验收

```text
[ ] 30x disable/enable 无蓝屏
[ ] 10x restart 无蓝屏
[ ] 3x sleep/resume 无蓝屏
[ ] 5x boot 无蓝屏
[ ] 2h 流量 + 100 并发 TCP 无蓝屏
[ ] OID storm 后 oidQueriesSeen 单调增长
[ ] fault clone/lower 均返回受控错误，不蓝屏
[ ] 非法 IOCTL 全部失败
[ ] 低权限 IOCTL 全部拒绝
[ ] summary.pass = true
```
