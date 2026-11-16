# CacMacLwf OID 修复测试与失败复现

日期：2026-11-16

## 1. 本次修改

按 Microsoft `FILTER_PAUSE` 文档和官方 `ndislwf` 样例，修改了
`CacMacLwf.c`：

- 删除 `Outstanding` / `PauseEvent`；`FilterPause` 不再返回
  `NDIS_STATUS_FAILURE`，而是直接返回 `NDIS_STATUS_SUCCESS`。
- `FilterSendNetBufferListsComplete` 转发
  `NdisFSendNetBufferListsComplete`。
- `FilterReturnNetBufferLists` 转发 `NdisFReturnNetBufferLists`。
- Pausing/Paused 时，新发送用 `NDIS_STATUS_PAUSED` 立即完成；
  新接收立即归还。
- 重新注册 `OidRequestHandler` / `OidRequestCompleteHandler`，并对
  `OID_802_3_CURRENT_ADDRESS`、`OID_802_11_MAC_ADDRESS`、
  `OID_802_11_PERMANENT_ADDRESS` 的查询结果写入 profile MAC。

新驱动：

```text
SHA-256 60D45B8135638B280FFEBB376D1377DD76D0CBA240E5D11BE6F2B83252B26CFA
签名状态 Valid
```

## 2. 测试步骤

1. VM：Windows 11 23H2 / 22631.7376，`Ethernet0`，Vmx 静态 MAC
   `02:44:08:1a:18:33`。
2. 创建快照 `pre-lwf-fix-20261116`。
3. 备份旧驱动到 `CacMacLwf.sys.bak-20261116-fixed`。
4. 替换新驱动，`sc start CacMacLwf`。
5. 调用 `cac-macctl state` / `set`，随后 `getmac`。

## 3. 结果

驱动启动后约 18 秒，Guest 蓝屏：

```text
KMODE_EXCEPTION_NOT_HANDLED (0x1E)
失败的操作: ndis.sys
Arg1: 0xffffffffc0000005
Arg2: 0xfffff8072f42d6f7
Arg3: 0xffffe38b5017dbf8
Arg4: 0xffffe38b5017d410
Dump: C:\Windows\Minidump\111626-7703-01.dmp
```

Dump 已复制到：

```text
native/macfilter/evidence/dumps/111626-7703-01.dmp
```

`!analyze -v` 关键结果：

```text
Failure.Bucket = AV_ndis!ndisFOidRequestCompleteInternal
Failure.Hash   = {d503e013-6b8f-0dbe-1635-3e559f545d6e}
```

故障栈（节选）：

```text
ndis!NdisFOidRequestComplete+0x1e2
  -> ndis!ndisOidRequestComplete+0x356
  -> wfplwfs!LwfLowerOidRequestComplete+0x27a
  -> ndis!NdisFOidRequestComplete+0x1e2
  -> ndis!ndisOidRequestComplete+0x356
  -> ndis!ndisFOidRequestCompleteInternal+0x83
  -> nt!KeExpandKernelStackAndCalloutEx
  -> ndis!ndisFOidRequestCompleteInternal+0x27
  -> nt!KiPageFault
```

`CacMacLwf` 模块已加载，但不在故障栈中；故障仍落在
`ndisFOidRequestCompleteInternal` 的扩展栈区域。

## 4. 结论

1. `FilterPause` 的返回值违规是真实缺陷，本次修复是必要的；
   但它不是这次 0x1E 的唯一原因。
2. 只要本驱动注册 OID handler 并参与 OID 转发/完成，在
   `22631 + wfplwfs + KeExpandKernelStackAndCalloutEx` 组合下就会再次
   触发 `AV_ndis!ndisFOidRequestCompleteInternal`。
3. 因此，**LWF OID 改 MAC 查询结果在这台 22631 上不可用**。
   继续在 LWF 里加逻辑没有意义，应该停止这条路线。
4. 之前“框架缺陷”的判断对这次现象是成立的；但 Pause 违规仍是
   独立存在的驱动 bug，不能因此忽略。

## 5. 恢复

- 旧驱动已从 `CacMacLwf.sys.bak-20261116-fixed` 还原：

```text
SHA-256 CD4F9276673D4AA13E5A17CC3F75486ACB07AE71C156223B6E4DBE5F2A55CE9B
签名状态 Valid
```

- 服务状态：`Stopped / Manual`。
- 当前 VM 使用 VMX 静态 MAC `02:44:08:1a:18:33`，未加载 LWF。

## 6. 安全 pass-through 复测

把 `OidRequestHandler` / `OidRequestCompleteHandler` 恢复为 `NULL` 后重新
构建并加载：

```text
SHA-256 5F66776CBE74AE10176C226EA60B81FC49502CB9AC40B80A48FCE1A35F08C5BA
服务状态 RUNNING
attached = 1
oidQueriesSeen = 0
oidRewrites = 0
getmac = 02-44-08-1A-18-33
ping 192.168.174.2 = 4/4
停止服务 = STOPPED，退出码 0
无新蓝屏
```

这说明：

- Pause 和完成链修复后的安全 pass-through 可以稳定加载；
- 蓝屏的触发点是 **OID handler 参与**，不是驱动加载本身；
- 由于 OID 参与在 22631 + wfplwfs 上不可用，LWF 不能承担 MAC 查询改写。

## 7. 决策

- HEAD 的 `CacMacLwf` 恢复 `OidRequestHandler = NULL` /
  `OidRequestCompleteHandler = NULL`，只保留安全的 pass-through 修复。
- MAC 覆盖继续使用：
  - VM：VMX 静态 MAC；
  - Claude 用户态：NativeBridge 视图；
  - 宿主机：需要时用 `Set-NetAdapter -MacAddress` / 厂商 LAA，
    这是整机全局，不是每进程。
- 不再尝试用 LWF 做按进程 MAC；Microsoft 在 OSR 也明确说 LWF
  不能真正替换 MAC。

## 8. Clone 修复成功（2026-11-16）

根因确认：**不能把原始 `NDIS_OID_REQUEST` 直接传给 `NdisFOidRequest`**。
Microsoft 文档明确要求：

```text
A filter driver ... should not forward the original NDIS_OID_REQUEST
structure to underlying drivers.
```

修正后的流程：

```text
NdisAllocateCloneOidRequest(original) -> clone
clone->SourceReserved[0] = original
NdisFOidRequest(clone)
完成时：
  改写 clone 的 MAC 查询结果
  把 BytesWritten/BytesNeeded 和查询数据拷回 original
  NdisFreeCloneOidRequest(clone)
  NdisFOidRequestComplete(original)
```

实测结果：

```text
服务 RUNNING
attached = 1
oidQueriesSeen = 45
oidRewrites = 2
lastOid = 0x01010102 (OID_802_3_CURRENT_ADDRESS)
lastRewriteOid = 0x01010102
sendPaused = 0
sendForwarded = 40
receivePaused = 0
receiveForwarded = 10
ping 10/10，0% 丢失
连续 5 次 Restart-NetAdapter 无蓝屏
```

这说明：

- 0x1E 的根因是原始 OID 请求被直接下发，完成链损坏；
- clone 模式后，OID 参与、网卡重启、数据路径都正常；
- MAC OID 确实被改写，但 `getmac`/WMI/`ipconfig` 仍显示硬件 MAC，
  原因是 IP 栈缓存，不是过滤器没命中。

下一步：让过滤器在开机时先于 IP 栈查询加载，再验证缓存是否采用
改写后的 MAC。

## 9. 来源

- FILTER_PAUSE:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nc-ndis-filter_pause
- ndislwf sample:
  https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/ndis-60-filter-driver/
- NdisFSendNetBufferListsComplete:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nf-ndis-ndisfsendnetbufferlistscomplete
- OSR MAC/LWF:
  https://community.osr.com/discussion/290816/ndis-filter-modifying-an-adapters-mac-address
- 研究总报告：`RESEARCH-MAC-20261116.md`
