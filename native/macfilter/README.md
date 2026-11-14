# CAC Profile-MAC Lightweight Filter（NDIS 6 LWF）

> 状态：实验代码保留，`CacMacLwf` 服务必须保持 `DISABLED`。Windows 11
> 22631 的 OID 参与路径已有可复现蓝屏，本组件不属于当前稳定覆盖，也不得在
> 物理机上执行安装、启动或热重载流程。

内核级 MAC 覆盖：在 NDIS 标准过滤层重写
`OID_802_3_CURRENT_ADDRESS` / `OID_802_3_PERMANENT_ADDRESS` 与
`OID_802_11_MAC_ADDRESS` / `OID_802_11_PERMANENT_ADDRESS` 的查询结果。

这是替代"向 NDIS miniport 附加通用过滤设备"的正确实现。后者会收到按
miniport 自身 StackSize 分配的短栈 IRP，本机实测触发
`0x18 REFERENCE_BY_POINTER` 与 `0xEF CRITICAL_PROCESS_DIED`。
LWF 由 NDIS 全权驱动请求，无手工 IRP 操作。

## 组件

| 文件 | 作用 |
|---|---|
| `CacMacLwf.c` | NDIS 6 LWF：OID 查询重写 + 全透传 + 暂停同步 + 控制设备 |
| `CacMacLwfIoctl.h` | 与 `cac-macctl.exe` 的共享 ABI |
| `CacMacLwf.inf` | NetService 组件 INF（含 `NetCfgInstanceId`，否则 netcfg 报 0x800f0102） |
| `build-macfilter.ps1` | 编译、链接 ndis.lib、测试签名 sys + inf2cat 生成并签名 catalog |
| `install-macfilter.ps1` | 复制二进制、预建内核服务、`netcfg -l` 注册并绑定 |
| `tools/cac-macctl.cpp` | `set --mac AA:BB:..` / `state` |

## 安装（管理员 + testsigning）

```powershell
cd E:\环境\huanjing\native\macfilter
powershell -NoProfile -ExecutionPolicy Bypass -File build-macfilter.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File install-macfilter.ps1 -RebootNow
```

绑定激活需要重启一次（NDIS 在重启时处理 FilterList 并加载过滤服务）。
重启后验证：

```powershell
E:\环境\huanjing\native\macfilter\bin\cac-macctl.exe state
E:\环境\huanjing\native\macfilter\bin\cac-macctl.exe set --mac 02:11:22:33:44:55
```

`attached` 应等于绑定网卡数；`oidQueriesSeen/oidRewrites` 随 MAC OID 查询递增。

## 本机状态（2026-11-14）与事故记录

- 组件已通过 `netcfg -l` 注册并写入 4 个网卡的 FilterList 绑定。
- 注册失败根因（静态 + 反汇编证据）：`NDIS_FILTER_DRIVER_CHARACTERISTICS`
  的 `FriendlyName/UniqueName/ServiceName` 为空——NDIS 注册路径会对
  ServiceName 做字符串处理（ndis!NdisFRegisterFilterDriver → 内部
  字符串校验/拷贝），空串导致注册返回 `STATUS_UNSUCCESSFUL`。已用
  `NdisInitUnicodeString` 补齐三个字段。
- 蓝屏符号级归因（cdb + MSDL 符号，`!analyze -v`）：
  `Failure.Bucket = AV_wfplwfs!LwfLowerOidRequestComplete` ——
  故障模块是微软自己的 **wfplwfs.sys**（WFP LWF），不是 CacMacLwf。
  我们那个"注册半失败"实例的 stop/start 引发了一次绑定栈重构，
  WFP 过滤器在完成下层 OID 请求时踩中访问违规。属于第三方过滤组件
  卸载时触发的 WFP 竞态，而不是我们驱动代码里的内存破坏。
- 顺带加固：`FilterPause` 改为"无在途请求即 SetEvent，否则等待完成
  回调置位"的标准模式，替代原先的 decrement/increment 舞步。
- 已把服务设为 `start= disabled`：**过滤驱动不再加载，系统稳定**。
- 当前 MAC 覆盖仍由 NativeBridge 用户态路径承担（验证过）。

下一轮验证必须先在隔离机器/VM 上做：注册状态（预期成功）、
OID 重写计数、以及"绑定后不热卸载、只整机重启"的运维方式。
本机通过 `sc config CacMacLwf start= demand` 可恢复，但重试前必须先
完成隔离验证，并避免在运行中反复 stop/start（那是 WFP 竞态的触发器）。

## 卸载

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File install-macfilter.ps1 -Uninstall
```

## 边界

- 设计目标只重写**查询结果**，不改变线上帧的源 MAC；当前稳定版本仅验证
  NativeBridge 的 `GetAdaptersAddresses`/`GetIfTable*`/WMI 用户态覆盖，内核
  OID 路径因服务禁用不计入覆盖矩阵。
- OID 请求无请求进程上下文，MAC 按“当前 Profile”全局生效：切 Profile 时
  wrapper 调 `cac-macctl set` 换一次。
- 虚拟网卡（TAP/Wintun）同样被重写——查询结果统一为 Profile MAC。
