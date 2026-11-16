# P1 第一阶段证据：cowork-svc CPU manifest 与 profile 重定向

日期：2026-11-16

## 目标

在 `cowork-svc.exe`（Claude Desktop `CoworkVMService`，LocalSystem）
已能注入 `NativeBridge.dll` 并读取 `C:\ProgramData\CAC\active-profile.ini`
的基础上，完成：

1. 为 Go ABI 的 `cpuid` / `xgetbv` 精确入口生成并启用 manifest；
2. 在服务进程内验证 `cpuid leaf 0x40000000` 被中和；
3. 验证 `ant-did` 与 `Claude-3p\ant-did` 的 profile 重定向；
4. 做服务重启和 Profile A/B 切换回归。

## 环境

```text
Claude Desktop : 5.1231.2.0
目标           : C:\Program Files\WindowsApps\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe
服务           : CoworkVMService
运行账户       : LocalSystem
最终 PID       : 4980
NativeBridge   : 8789C6FB486B0263D2C15BECAB0245999A6E2922F8C6ED2F12F593D488FD0935
cowork-svc.exe : 88447B35800CD7A8C3DDE1F7E2ABB001DD14B93749637BF653D92DEBA4133646
```

## CPU manifest

Go 1.25 `internal/cpu` 的汇编 ABI 把参数和结果放在调用者栈上：

```text
cpuid(eaxArg, ecxArg) (eax, ebx, ecx, edx)
  entry rsp+08 : eaxArg
  entry rsp+0c : ecxArg
  entry rsp+10 : eax result
  entry rsp+14 : ebx result
  entry rsp+18 : ecx result
  entry rsp+1c : edx result

xgetbv() (eax, edx)
  entry rsp+08 : eax result
  entry rsp+0c : edx result
```

`native/NativeBridge/GoCpuDetours.asm` 按这个布局保存 `rbp`、读取参数、
调用 C helper，再把结果写回调用者栈。manifest 只接受以下精确入口：

```text
cpuid  prologue: 8b4424088b4c240c  -> gocpuid
xgetbv prologue: b900000000        -> goxgetbv
```

当前 `cowork-svc.exe` 的 4 条记录：

```text
RVA 0x2BA0    gocpuid
RVA 0x2BC0    goxgetbv
RVA 0x212A60  gocpuid
RVA 0x212A80  goxgetbv
```

服务启动审计：

```text
cpu.install installed gocpuid   11168   (0x2BA0)
cpu.install installed goxgetbv  11200   (0x2BC0)
cpu.install installed gocpuid   2173536 (0x212A60)
cpu.install installed goxgetbv  2173568 (0x212A80)
cpu.manifest complete entries=4 installed=4
native.bridge ready
```

## 服务内 CPU 验证

`native/CpuProbe/main.cpp` 在目标进程内分配一小段 x64 stub，用
`CreateRemoteThread` 调用被 hook 的 Go 入口，按 Go ABI 读取返回槽。
这不是另起进程模拟，而是在 `cowork-svc.exe` 进程内执行。

最终 PID 4980 的结果（`cpu-probe.json`）：

```text
RVA 0x2BA0   cpuid    entry e95bd4feff909090
             host   [00000000, 0000002f, 00000000, 00000002]
             result [00000000, 00000000, 00000000, 00000000]

RVA 0x2BC0   xgetbv   entry e93bd4fdff0f01d0
             host   [00000007, 00000000]
             result [00000007, 00000000]

RVA 0x212A60 cpuid    entry e99bd5dbff909090
             host   [00000000, 0000002f, 00000000, 00000002]
             result [00000000, 00000000, 00000000, 00000000]

RVA 0x212A80 xgetbv   entry e97bd5daff0f01d0
             host   [00000007, 00000000]
             result [00000007, 00000000]
```

`entry` 以 `e9` 开头，说明入口已被 5 字节跳转覆盖。`host` 是探测进程
自己执行的真实 CPUID；`result` 是服务进程内经过 detour 后的结果。
leaf `0x40000000` 从非零 hypervisor vendor 变为全零，说明
`CpuIdFilter` 的 neutral 分支在服务内生效。

对应审计：

```text
cpu.gocpuid filtered go leaf=0x40000000 subleaf=0x0 eax=0x0 ebx=0x0 ecx=0x0 edx=0x0
cpu.goxgetbv observed go xcr0=0x7
```

边界：Go runtime 的 `internal/cpu.Initialize` 在进程启动早期执行，
早于 DLL 注入；因此本 manifest 不能追溯修改启动时已经算出的 feature
flags。它覆盖的是注入后所有经过这 4 个精确入口的 `cpuid/xgetbv` 调用。
服务内探测证明 hook 路径和过滤逻辑有效，不把“启动前已算出的 flags”
误报成已伪装。

## ant-did / Claude-3p 重定向

实现位置：`native/NativeBridge/ApiHooks.cpp` 的 `RedirectClaudeProfilePath`，
接入 `CreateFileW`、`CreateFileA`、`CreateFile2`。开关：

```text
CAC_REDIRECT_ANT_DID=1
```

`scripts/service-profile.ps1` 在服务 profile 中写入
`redirect_ant_did=1`，只对服务注入生效。

独立验证（`redirect-test.json`、`redirect-audit.jsonl`）：

```text
%APPDATA%\Claude\ant-did
  -> %CAC_PROFILE_DIR%\ant-did

%APPDATA%\Claude-3p\ant-did
  -> %CAC_PROFILE_DIR%\Claude-3p\ant-did
```

测试结果：

```text
target_ant_did      true   content=ant-did-test
target_claude_3p    true   content=claude-3p-test
original_ant_did    false
original_claude_3p  false
```

审计同时出现 `api.createfile.claudeprofile observed`、
`api.claudeprofile redirect` 和最终落点
`api.ntcreatefile.claudeprofile observed ...\profile\...`。

## Profile A/B 回归

| 阶段 | Profile | PID | identity 审计 |
|---|---|---|---|
| A（切换前） | desktop-1 | 26336 | `mac=02:2a:09:f6:66:f2 host=host-7105ecbc machine=7105ecbcb4a642a685ea9848ddd5d3ba disk=WD-84490e004894` |
| B | desktop-b | 23912 | `mac=02:bb:bb:bb:bb:bb host=host-bbbb machine=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb disk=WD-bbbbbbbbbbbb` |
| A（恢复） | desktop-1 | 4980 | `mac=02:2a:09:f6:66:f2 host=host-7105ecbc machine=7105ecbcb4a642a685ea9848ddd5d3ba disk=WD-84490e004894` |

每次切换都执行 `CoworkVMService` 停止/启动；注入器在约 2 秒轮询内
重新注入新 PID。三次启动均为 `cpu.manifest complete entries=4 installed=4`
和 `native.bridge ready`。

## 复现命令

```powershell
# 生成/更新 manifest 与 active profile
.\scripts\service-profile.ps1

# 部署 NativeBridge/注入器（会重启 CoworkVMService）
.\scripts\install-service-injector.ps1

# 服务内 CPU 探测（4 条 manifest 全部断言）
.\scripts\probe-service-cpu.ps1

# ant-did / Claude-3p 重定向测试
.\scripts\test-claude-profile-redirect.ps1
```

## 文件

```text
native/evidence/P1-20261116/cpu-manifest-desktop-1.txt
native/evidence/P1-20261116/cpu-manifest-desktop-b.txt
native/evidence/P1-20261116/cpu-probe.json
native/evidence/P1-20261116/service-audit-pid-4980.jsonl
native/evidence/P1-20261116/profile-ab.jsonl
native/evidence/P1-20261116/redirect-test.json
native/evidence/P1-20261116/redirect-audit.jsonl
native/evidence/P1-20261116/hashes.txt
```

最终状态：`active-profile.ini` 指向 `desktop-1`，PID 4980，
`cpu.manifest complete entries=4 installed=4`，`redirect_ant_did=1`。
