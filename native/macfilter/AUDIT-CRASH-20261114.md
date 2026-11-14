# CacMacLwf 蓝屏事故审计（2026-11-14）

## VM 对照实验矩阵（2026-11-15，原版 Win11 22631.7376 VM）

| 实验 | OID handlers | 结果 |
|---|---|---|
| exp1 | NULL | 安装 ✓、附着 ✓（registerStatus=0, attached=1）、15 分钟稳定 ✓ |
| exp2 | 纯透传（无计数/无改写/无暂停同步） | 安装 ✓，网卡 disable/enable 电源循环 → **0x1E 蓝屏**，`Failure.Bucket = AV_ndis!ndisFOidRequestCompleteInternal`（转储 111526-7203-01.dmp） |
| exp3 | NULL | 安装 ✓、附着 ✓，同样网卡电源循环 → **不崩** ✓ |

结论：**只要注册 OID handler（哪怕纯透传），OID_PNP_SET_POWER 完成链
即触发 NDIS/WFP 缺陷；与我们的逻辑无关。** LWF 内核 MAC 在 22631 上
不可用，保持 handlers NULL 或整盘退场；MAC 由用户态 NativeBridge 承担。

宿主机侧两次同族崩溃（`AV_wfplwfs!LwfLowerOidRequestComplete`）与
exp2 属同一完成链缺陷（归因层不同：宿主机栈帧落在 wfplwfs，VM 栈帧
落在 ndisFOidRequestCompleteInternal）。

## 事故 #4 / #5（0x1E，同一 Failure.Hash）

```text
Failure.Bucket = AV_wfplwfs!LwfLowerOidRequestComplete
Failure.Hash   = {2367c9dc-6fba-410b-26d9-1c0e854b8127}
```

两次蓝屏完全同源：故障指令在 `ndis!ndisOidRequestComplete+0x2eb`
（`mov ebp,[rdi+20h]`），栈证据（cdb + MSDL 符号）：

```text
ndisQueueOidRequest (OID_PNP_SET_POWER 0x00020106)
  -> ndisMDoOidRequest -> ndisOidRequestComplete
  -> wfplwfs!LwfLowerOidRequestComplete
  -> ndis!NdisFOidRequestComplete
  -> KeExpandKernelStackAndCalloutEx
  -> ndisFOidRequestCompleteInternal
  -> ndisOidRequestComplete+0x2eb  ← 扩展栈守护页访问违规
```

## 证据要点

- 故障发生在 OID_PNP_SET_POWER 完成链向上回卷、进入
  KeExpandKernelStackAndCalloutEx 扩展栈区域时（扩展区
  `d414d000..d4153000`，故障地址 `d4151fc8` 在区内）。
- CacMacLwf 已加载（base `fffff8039b5c0000`），每个网卡绑定恰好 1 条，
  无重复绑定。
- 我们的处理器不写请求结构（只做 6 字节缓冲区改写 + 计数器），
  没有直接的越界写证据。
- 结论：WFP LWF + 本机 4 网卡 + 电源 OID 完成链 + 扩展栈机制的组合下，
  过滤栈里多出的这一层触发了 NDIS/WFP 侧的堆栈/回卷缺陷。属本机
  环境特异性交互，非我们代码里可定位的单点内存破坏。

## 处置

- 服务 `start=disabled`：驱动不再加载，系统稳定（磁盘内核过滤、
  用户态 MAC 不受影响）。
- MAC 内核层验证改到隔离 VM：绑定后只整机重启、不做热卸载，
  逐步观察 OID_PNP_SET_POWER 完成链是否复现。
- 在本机复现率 2/2（两次绑定后 2 分钟内蓝屏），复现条件已记录，
  作为 VM 验证的对照基线。
