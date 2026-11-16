# MAC 覆盖与 NDIS LWF 蓝屏：资料复核

日期：2026-11-16

## 0. 结论摘要

1. `CacMacLwf` 在 22631 上的 0x1E 不能继续归因于“NDIS/WFP 框架缺陷”。
   当前驱动至少违反了两条官方强制语义：
   - `FilterPause` 在 `Outstanding != 0` 时返回 `NDIS_STATUS_FAILURE`。
     Microsoft 明确写明：**NDIS drivers cannot fail a pause request.**
   - `FilterSendNetBufferListsComplete` 没有调用
     `NdisFSendNetBufferListsComplete`；`FilterReturnNetBufferLists` 没有调用
     `NdisFReturnNetBufferLists`。收发完成链没有被转发。
2. “按进程改 MAC”在 NDIS LWF 层不成立。LWF 能改
   `OID_802_3_CURRENT_ADDRESS` 的查询结果，但不能改适配器真实 MAC，
   也不能同步 NDIS/系统里的全部缓存。真正改 MAC 是**适配器全局**行为。
3. 宿主机物理网卡改 MAC 的官方路径是
   `Set-NetAdapter -MacAddress` 或厂商的 Locally Administered Address
   （Intel 叫 LAA / Network Address）。它是整机全局的，不是每进程的。
4. 每 Profile 的真实隔离边界只有两种：
   - 每个 Profile 一台 VM，VMX 里写静态 MAC；
   - 同一台机器一次只上线一个 Profile，切换时全局改 MAC。
5. 对 Claude 这类用户态程序，MAC 读取主要是
   `GetAdaptersAddresses` / `GetAdaptersInfo` / WMI / SetupAPI。
   用户态 Hook 或内核 IOCTL Hook 可以做“视图伪装”，但它仍不是
   物理网卡 MAC 改变。

## 1. 官方语义与证据

### 1.1 FilterPause 不能失败

Microsoft `FILTER_PAUSE` 文档原文：

> NDIS drivers cannot fail a pause request.

返回值只允许：

- `NDIS_STATUS_SUCCESS`
- `NDIS_STATUS_PENDING`（之后必须调用 `NdisFPauseComplete`）

同时要求：

- 把队列中的发送 NBL 用 `NdisFSendNetBufferListsComplete` 完成；
- 把队列中的接收 NBL 用 `NdisFReturnNetBufferLists` 归还；
- 等待自己发起的 outstanding send/receive 完成。

来源：

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nc-ndis-filter_pause
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/pausing-a-filter-module

### 1.2 官方 ndislwf 样例的实际写法

官方样例 `FilterPause` 只返回 `NDIS_STATUS_SUCCESS`，注释写明：

> No other return value is allowed (pause must succeed, eventually).

官方样例的完成路径：

```c
FilterSendNetBufferListsComplete(...)
{
    NdisFSendNetBufferListsComplete(pFilter->FilterHandle,
                                    NetBufferLists,
                                    SendCompleteFlags);
}

FilterReturnNetBufferLists(...)
{
    NdisFReturnNetBufferLists(pFilter->FilterHandle,
                              NetBufferLists,
                              ReturnFlags);
}
```

来源：

- https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/ndis-60-filter-driver/
- https://raw.githubusercontent.com/microsoft/Windows-driver-samples/main/network/ndis/filter/filter.c

### 1.3 NdisFSendNetBufferListsComplete 的语义

Microsoft 文档：

> A filter driver calls the NdisFSendNetBufferListsComplete function to
> complete send requests that NDIS made to the driver's
> FilterSendNetBufferLists function.

并且明确：

> A filter driver should keep track of send requests that it originates and
> make sure that it does not call NdisFSendNetBufferListsComplete when such
> requests are complete.

也就是说：

- 透传的 NBL：必须调用 `NdisFSendNetBufferListsComplete`；
- 驱动自己新分配的 NBL：不能调用，必须自己释放。

来源：

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nf-ndis-ndisfsendnetbufferlistscomplete

### 1.4 OID_PNP_SET_POWER 与电源转换

`OID_PNP_SET_POWER` 进入低功耗前，miniport 必须：

- 等待发送完成；
- 完成所有 pending send；
- 拒绝新的 send。

如果上面的 LWF 在 Pause 阶段返回失败、或没有把完成链转发，
电源转换就会在 OID 完成链上留下不一致状态。0x1E 的
`AV_wfplwfs!LwfLowerOidRequestComplete` 正好符合这个路径。

来源：

- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-pnp-set-power
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7c--bugcode-ndis-driver

## 2. 当前 CacMacLwf 对照

| 检查点 | 当前代码 | 官方要求 | 风险 |
| --- | --- | --- | --- |
| `FilterPause` 返回值 | `Outstanding != 0` 时返回 `NDIS_STATUS_FAILURE` | 只能 SUCCESS 或 PENDING | 高，直接违反强制语义 |
| `FilterPause` 等待 | `NdisWaitEvent(..., 0)`，0 超时 | 必须等 outstanding 清零，或异步 PENDING | 高 |
| `FilterSendNetBufferListsComplete` | 只减计数，不转发 | 必须调用 `NdisFSendNetBufferListsComplete` | 高，发送链断 |
| `FilterReturnNetBufferLists` | 只减计数，不转发 | 必须调用 `NdisFReturnNetBufferLists` | 高，接收链断 |
| `FilterSendNetBufferLists` | 无条件转发 | Pausing/Paused 时必须立即完成 `NDIS_STATUS_PAUSED` | 中 |
| `FilterReceiveNetBufferLists` | 无条件转发 | Pausing/Paused 时必须立即归还 | 中 |
| OID handler | NULL 或纯透传 | 透传可以，但不能破坏完成链 | 中 |
| `Outstanding` 计数 | 对所有 NBL 计数 | 透传 NBL 不必计数；自己发起/实质修改才需要 | 低/中 |

### 2.1 之前实验矩阵的重新解释

- exp1 / exp3（OID handlers = NULL）不崩：因为 NDIS 代劳了 OID 路径，
  没有触发我们自己的完成链缺陷。
- exp2（OID handlers = 纯透传）崩：不是因为“一注册 OID handler 就崩”，
  而是因为注册后电源 OID 真正走进了我们的 `FilterOidRequest` /
  `FilterOidRequestComplete` 路径，同时 Pause 在 outstanding 非零时
  返回失败，完成链被破坏。

因此，下一步必须先修 Pause 和收发完成转发，再复测 exp2。

## 3. 为什么“按进程 MAC”不成立

### 3.1 Microsoft 工程师在 OSR 的回复

OSR 帖子 `NDIS Filter - modifying an adapter's MAC Address` 中，
Microsoft 的 Jeffrey Tippet 明确说：

> I'm not sure it's really possible to replace a MAC address from a LWF.
> ... Simply editing one OID isn't enough to notify NDIS and the world to
> update all their various caches.

他给出的路径：

1. 最简单：`Set-NetAdapter -MacAddress`；
2. 真要在驱动层做：IM driver（Intermediate Driver）；
3. 系统自带的 LBFO / vSwitch 也能“改” MAC。

来源：

- https://community.osr.com/discussion/290816/ndis-filter-modifying-an-adapters-mac-address

### 3.2 NDIS 数据路径没有进程 ID

- LWF 的 `FilterSendNetBufferLists` 收到的是 NBL 链；
  NBL 上没有 PID、没有进程上下文。
- 发送线程可能是应用线程，也可能是协议栈/工作线程；
  用 `PsGetCurrentProcessId()` 不能可靠归属到发起进程。
- WFP 的 ALE 层能拿到进程信息，但 WFP 是 L3/L4；
  MAC 是 L2。把 WFP 的 flow context 和 NDIS 帧改写组合起来，
  仍然只能做“按流改帧”，不是适配器 MAC 改变。

结论：

```text
LWF 按进程改 MAC 查询结果：可以做，但只是视图；
LWF 按进程改真实 MAC：不成立；
真实 MAC 改变：适配器全局。
```

### 3.3 对 Claude 的实际影响

Claude 读取 MAC 的常见路径：

- `GetAdaptersAddresses` / `GetAdaptersInfo`
- WMI `Win32_NetworkAdapter.MACAddress`
- `getmac` / `ipconfig /all`
- SetupAPI 设备实例

用户态 Hook（现有 NativeBridge）可以改前三条的返回值；
SetupAPI 的 PnP 实例 ID、DHCPv6 DUID、SMBIOS、磁盘序列号仍然可能
保留原值。要做到“看起来完全一致”，必须从 VM/系统镜像层生成，
而不是只改一个 API。

## 4. 宿主机物理网卡 MAC

### 4.1 官方 PowerShell 路径

```powershell
Set-NetAdapter -Name "Ethernet" -MacAddress "02-44-08-1A-18-33"
```

Microsoft 文档说明：

- 该 cmdlet 设置网卡的基本属性，包括 MAC；
- **Not all network adapters support setting the MAC address**；
- 改动可能破坏网络功能；
- 地址会保存到 network addresses 属性。

来源：

- https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapter

### 4.2 厂商 LAA（Intel）

Intel 的 “Locally Administered Address”：

- 覆盖初始 MAC；
- 输入 12 位十六进制；
- 不能是组播地址（第一字节最低位不能为 1）；
- 位于设备管理器 Advanced 页或 PROSet。

PowerShell 等价路径：

```powershell
Set-NetAdapterAdvancedProperty -Name "Ethernet" `
  -RegistryKeyword "NetworkAddress" `
  -RegistryValue "0244081A1833"
Restart-NetAdapter -Name "Ethernet"
```

来源：

- https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapteradvancedproperty
- https://www.intel.com/content/www/us/en/support/articles/000005593/network-and-i-o/ethernet-products.html

### 4.3 持久化与兼容性

- `NetworkAddress` 存在注册表里，通常重启后仍在；
- 部分驱动忽略该值、只在启动时读、或继续向上报告原始 MAC；
- 有的网卡 `getmac` / `ipconfig` 会显示新值，有的仍显示原值
  （SpoofMAC 的 Windows 10 说明明确记录了这个差异）；
- 改动是**整机全局**的，不是每进程，也不是每用户。

来源：

- https://github.com/feross/SpoofMAC

### 4.4 现成工具

| 工具 | 方式 | 说明 |
| --- | --- | --- |
| `SpoofMAC` / `spoof` | 注册表 NetworkAddress | 开源，跨平台；Windows 兼容性依赖驱动 |
| Technitium MAC Address Changer | 驱动/注册表 | GUI，老牌工具 |
| Intel PROSet | 厂商 LAA | 只适用于 Intel 网卡 |
| WinpkFilter / ndisapi | NDIS 包过滤 | 能抓/改包，不是改适配器 MAC |
| `ndisGlobalFilterList` 遍历 / ndis.sys patch | 内核内存补丁 | 脆弱，PatchGuard/检测风险，不建议 |

## 5. 可行方案排序

### 方案 A：修复 LWF，再复测 22631

目标不是“让 LWF 真正改 MAC”，而是：

- 让 LWF 成为合法的 pass-through；
- 如果只做 `OID_802_3_CURRENT_ADDRESS` 查询改写，明确它只是全局视图伪装；
- 电源转换、热插拔、禁用/启用网卡不再蓝屏。

代码修复点：

```c
// Pause: 永远不返回 FAILURE
context->Running = FALSE;
NdisWaitEvent(&context->PauseEvent, 5000); // 有界等待
return NDIS_STATUS_SUCCESS;

// Send complete: 先转发，再减计数
NdisFSendNetBufferListsComplete(context->NdisFilterHandle,
                                NetBufferLists,
                                SendCompleteFlags);
CacMacMaybeSetPauseEvent(context);

// Return: 先归还，再减计数
NdisFReturnNetBufferLists(context->NdisFilterHandle,
                          NetBufferLists,
                          ReturnFlags);
CacMacMaybeSetPauseEvent(context);
```

同时：

- `FilterSendNetBufferLists` 在 `!Running` 时立即
  `NdisFSendNetBufferListsComplete(..., NDIS_STATUS_PAUSED)`；
- `FilterReceiveNetBufferLists` 在 `!Running` 时立即
  `NdisFReturnNetBufferLists(...)`；
- 如果只做透传，可以按 OSR 291474 的建议去掉全量 Outstanding 计数，
  只对自己发起/实质修改的 NBL 计数；
- 不要处理 `OID_PNP_SET_POWER`，让 NDIS 走默认电源路径。

来源：

- https://community.osr.com/discussion/291474/ndis-filter-driver-pausing-requirements

### 方案 B：宿主机物理网卡全局改 MAC

适用：一台机器只跑一个 Profile，或切换 Profile 时全局切换。

```powershell
# 查看当前值
Get-NetAdapter -Name "Ethernet" | Select-Object Name,MacAddress
Get-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword NetworkAddress

# 设置
Set-NetAdapter -Name "Ethernet" -MacAddress "02-44-08-1A-18-33"

# 或厂商 LAA
Set-NetAdapterAdvancedProperty -Name "Ethernet" `
  -RegistryKeyword NetworkAddress -RegistryValue "0244081A1833"
Restart-NetAdapter -Name "Ethernet"
```

验证：

```powershell
Get-NetAdapter -Name "Ethernet" | Select-Object MacAddress
Get-CimInstance Win32_NetworkAdapter -Filter "NetEnabled=True" |
  Select-Object Name,MacAddress
getmac /v /fo csv
ipconfig /all
```

注意：

- 不是所有网卡都支持；
- 会短暂断网；
- 重启后是否保持取决于驱动；
- 不能按进程区分。

### 方案 C：每 Profile 一台 VM

- VMX 里写 `ethernet0.addressType = "static"` 和 `ethernet0.address`；
- Guest 里不加载 LWF；
- 这是目前唯一能做到“稳定 MAC + 不蓝屏 + Profile 间不共享 MAC”的方案；
- 代价是每 Profile 一个 VM/快照。

### 方案 D：按进程视图伪装

如果目标只是让 Claude 读到指定的 MAC：

- 用户态 Hook `GetAdaptersAddresses` / `GetAdaptersInfo` / WMI；
- 或内核 IOCTL Hook，按 PID 改写返回缓冲区；
- 不要把它宣传成“物理 MAC 改变”；
- 必须同时处理 PnP 实例 ID、DUID、SMBIOS 等残留，否则一致性不成立。

## 6. 下一步测试计划

1. 在 VM 里创建“修复前”快照。
2. 按第 5 节方案 A 修改 `CacMacLwf.c`。
3. 用 WDK 重新编译、测试签名。
4. 在 VM 内替换驱动，绑定 `Ethernet0`。
5. 做以下动作并记录 0x1E / Minidump：
   - 禁用/启用网卡 10 次；
   - 重启 3 次；
   - 休眠/恢复 1 次；
   - 持续 ping 网关 10 分钟。
6. 若全部通过，再测试 `OID_802_3_CURRENT_ADDRESS` 查询改写；
   若仍复现 0x1E，停止 LWF 路线，改用方案 B/C。

## 7. Win11 成功案例核查（2026-11-16）

公开可检索到的结果：

| 对象 | 结论 |
| --- | --- |
| `CacMacLwf` | 没有公开项目/帖子；搜索结果只有无关的 CACWF、CAC For Mac 等 |
| GitHub `ndis lwf` | 只有 4 个仓库：NDIS LWF demo、Intel AVB/TSN、Rust 防火墙、流量捕获；没有 MAC 改写项目 |
| OSR / Microsoft | LWF 不能真正替换适配器 MAC；改 OID 不足以同步 NDIS/系统缓存 |
| `Set-NetAdapter -MacAddress` | Win11 可用，但取决于网卡驱动，且是整机全局 |
| Intel LAA | Win11 可用，12 位十六进制，不能是组播，整机全局 |
| `SpoofMAC` / `spoof` | 写注册表 NetworkAddress；Win10/11 是否生效取决于驱动，部分网卡 `getmac` 仍显示原值 |
| `btbd/hwid` | 开源内核 HWID spoofer，处理 NIC+ARP，但 README 明确只测到 Win10 1903，已归档，不是 Win11 LWF 案例 |
| UnknownCheats Win11 25H2 `ndisGlobalFilterList` | 走的是 patch `ndis.sys` 过滤器链表，不是 LWF；脆弱且与 PatchGuard/检测冲突 |
| DEV: WiFi MAC kernel driver | KMDF 驱动写 NetworkAddress，不是 NDIS LWF；依赖网卡驱动 |

结论：

```text
CacMacLwf 本身：没有公开成功案例
通用 NDIS LWF 改 MAC 查询：没有可引用的 Win11 开源成功项目
Win11 真正改 MAC：Set-NetAdapter / 厂商 LAA / 注册表 NetworkAddress
内核 HWID spoofer：有，但不是 LWF，且多为 Win10 或 patch ndis.sys
```

> 以下为 **clone 修复前**的结论。`de2d8d1` 改为下发
> `NdisAllocateCloneOidRequest` 之后，OID handler 参与已通过
> 5× `Restart-NetAdapter`、开机 `SYSTEM_START`、`ping 10/10`
> 实测，无 `0x1E`。最终结论见第 8 节与
> `LWF-FIX-TEST-20261116.md` 第 8-9 节。

早期（pre-clone）实测：OID handler 参与曾触发
`AV_ndis!ndisFOidRequestCompleteInternal`；OID handler 为 NULL 的
pass-through 才稳定。

## 8. IP 栈缓存与官方解决方式（2026-11-16）

### 8.1 官方原文

Microsoft `OID_802_3_CURRENT_ADDRESS` 文档：

> The network management software cannot set the current station address
> using the NDIS interface library. It must set this address as a
> configuration parameter.

来源：

- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-802-3-current-address

OSR `OID_GEN_MAC_ADDRESS` 帖子里也确认：

- `OID_GEN_MAC_ADDRESS`（0x00010205）不能用来改 MAC；
- 在 `FilterRestart` 里用 `NdisFOidRequest` 发送它会返回
  `STATUS_NOT_SUPPORTED`；
- 把它加进 restart attributes 也没有效果；
- `ndislwf` 样例里“可以在这里改 MAC”的注释会误导。

来源：

- https://community.osr.com/t/54879

### 8.2 官方正确的修改路径

```text
修改网卡的 configuration parameter（NetworkAddress / 厂商 LAA）
    -> 重启 miniport
    -> release / disable / enable / renew
    -> NDIS 和 IP 栈重新读取 MAC，缓存更新
```

用户态对应：

```powershell
Set-NetAdapter -Name "Ethernet" -MacAddress "02-11-22-33-44-55"
```

或厂商 LAA：

```powershell
Set-NetAdapterAdvancedProperty -Name "Ethernet" `
  -RegistryKeyword NetworkAddress `
  -RegistryValue "021122334455"
Restart-NetAdapter -Name "Ethernet"
```

这不是 LWF 能做到的；LWF 只能改 OID 查询结果，改不了 IP 栈在
miniport 注册时缓存的地址。

### 8.3 对功能的影响

```text
网络功能：不受影响。clone 修复后 ping 10/10，网卡重启 5 次无蓝屏。
指纹一致性：受影响。getmac / WMI / ipconfig / GetAdaptersAddresses
仍读硬件 MAC；除非 NativeBridge 同步伪装，或直接改网卡配置参数。
```

对本项目的正确组合：

```text
VM：VMX 静态 MAC（真实虚拟网卡地址，缓存一致）
Claude 用户态：NativeBridge Hook（与 profile MAC 同步）
宿主机物理网卡：Set-NetAdapter -MacAddress / 厂商 LAA（整机全局）
```

## 9. 来源清单

- Microsoft FILTER_PAUSE:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nc-ndis-filter_pause
- Microsoft Pausing a Filter Module:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/network/pausing-a-filter-module
- Microsoft ndislwf sample:
  https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/ndis-60-filter-driver/
- Microsoft ndislwf source:
  https://raw.githubusercontent.com/microsoft/Windows-driver-samples/main/network/ndis/filter/filter.c
- Microsoft NdisFSendNetBufferListsComplete:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nf-ndis-ndisfsendnetbufferlistscomplete
- Microsoft OID_PNP_SET_POWER:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-pnp-set-power
- Microsoft 0x7C BUGCODE_NDIS_DRIVER:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7c--bugcode-ndis-driver
- OSR: NDIS Filter - modifying an adapter's MAC Address:
  https://community.osr.com/discussion/290816/ndis-filter-modifying-an-adapters-mac-address
- OSR: NDIS filter driver pausing requirements:
  https://community.osr.com/discussion/291474/ndis-filter-driver-pausing-requirements
- OSR: Bluescreen when calling NdisFSendNetBufferLists:
  https://community.osr.com/t/bluescreen-when-calling-ndisfsendnetbufferlists/38106
- Microsoft Set-NetAdapter:
  https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapter
- Microsoft Set-NetAdapterAdvancedProperty:
  https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapteradvancedproperty
- Intel Locally Administered Address:
  https://www.intel.com/content/www/us/en/support/articles/000005593/network-and-i-o/ethernet-products.html
- SpoofMAC:
  https://github.com/feross/SpoofMAC
- spoof (Node port):
  https://github.com/feross/spoof
- WinpkFilter / ndisapi:
  https://github.com/wiresock/ndisapi-rs
- DEV: Spoofing WiFi MAC Addresses with a Windows Kernel Driver:
  https://dev.to/__43698c3f021/spoofing-wifi-mac-addresses-with-a-windows-kernel-driver-1mfd
