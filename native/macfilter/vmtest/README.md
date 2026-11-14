# CacMacLwf VM 测试套件

两阶段验证，结论分阶段回灌：

## Stage A（现有 Win10 22H2 VM 即可）

验证我们自己的代码：注册成功、模块附着、OID 重写计数、
MAC 设置回读、stop/start 安全、反复绑定。

```powershell
Copy-Item -Recurse 宿主机:\...\vmtest  VM内C:\cacvm
# VM 内（管理员）：
bcdedit /set testsigning on   # 然后重启一次
powershell -NoProfile -ExecutionPolicy Bypass -File C:\cacvm\vm-install.ps1
# 安装脚本会自动重启；重启后：
powershell -NoProfile -ExecutionPolicy Bypass -File C:\cacvm\vm-verify.ps1
```

判定：`registerStatus=0` 且 `attached>=1` 且 `oidRewrites` 随查询增长 =
我们的驱动在 Win10 上功能完整。这验证的是**驱动代码**。

## Stage B（Win11 23H2 22631 VM，与宿主机同构建号）

复现宿主机蓝屏（`AV_wfplwfs!LwfLowerOidRequestComplete`，
OID_PNP_SET_POWER 完成链 + 扩展栈守护页）。

1. Win11 23H2 安装 + 更新到 UBR 7376（与宿主机 winver 一致）。
2. 快照 clean。
3. 按 Stage A 同样步骤安装 + 重启。
4. 故意触发电源转换（睡眠/唤醒/禁用启用网卡），观察是否 2 分钟内
   复现 0x1E。
5. 复现 → 快照回滚 → 挂内核调试器再来一次抓现场；
   不复现 → 宿主机问题是环境特异性组合，回宿主机考虑只绑物理网卡。

## 判定出口

```text
Stage A 失败           → 修我们自己的代码（有快照，随便崩）
Stage A 通过 + B 通过   → LWF 本机可启用（保守：只绑物理网卡，不热卸载）
Stage A 通过 + B 复现   → NDIS/WFP 交互缺陷，拿 Stage B 现场找规避
                          （换绑定顺序 / 只绑物理网卡 / 放弃内核 MAC）
```

## 环境要求（重要教训）

- **必须用原版（未做任何去虚拟化/去VM标识/防封加固）的干净 VM。**
  加固类 VM 常改动 BCD、精简 KDCOM/串口组件，导致内核调试通道
  （串口/kdnet）和崩溃转储双双失效——实测：调试参数全对、网络全通，
  但目标从不发出 kdnet 探测包，蓝屏也不落转储。
- 新 VM 第一件事（改任何东西之前）：

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Value 3 -Type DWord
bcdedit /set testsigning on
```

- 崩溃转储 + 内核调试是排查内核问题的两条命脉，加固 VM 两者皆失。
