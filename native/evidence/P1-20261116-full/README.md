# P1 完整 CPU 伪装证据：cowork-svc.exe

日期：2026-11-16

本目录补齐了 `P1-20261116` 中“启动阶段 CPU flags 未覆盖”的部分。
最终链路：

```text
服务启动前   : GODEBUG=cpu.all=off 作用于 vendor/golang.org/x/sys/cpu
进程出现后   : 注入器在 ~19 ms 内直接中和 internal/cpu 与 vendor cpu 的 flag 字节
NativeBridge : 再次校验并中和，安装 4 个 Go ABI cpuid/xgetbv 入口
运行时       : 4 个入口的 cpuid/xgetbv 结果按 neutral 过滤
```

## 环境

```text
Claude Desktop : 5.1231.2.0
服务           : CoworkVMService
目标           : C:\Program Files\WindowsApps\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe
Go             : go1.25.14 windows/amd64
cowork hash    : 88447B35800CD7A8C3DDE1F7E2ABB001DD14B93749637BF653D92DEBA4133646
NativeBridge   : 5B9506607428007B0EC140C31C282BB76D03A27D57698DF6246EDAF78E24C5BF
injector       : C5B0707899F3A44A37190F88B5277859E638DB14E6B448ECE36A1C81FA10BE0C
probe          : CBF9A000AF57BD03F6281095EF0AAEA824987775B5B4F5342CBEBC13D14FC6F3
最终 PID       : 13508
```

## 关键发现

Go 1.25 的 `runtime.getGodebugEarly()` 在 `GOOS=windows` 时直接返回
`"", false`：

```go
default:
    return "", false
```

所以 `GODEBUG=cpu.all=off` 在 Windows 上只会被
`vendor/golang.org/x/sys/cpu` 的 `init` 读取，**不会传给**
`internal/cpu.Initialize`。实际读取结果也验证了这一点：

```text
设置 GODEBUG=cpu.all=off 后：
  vendor cpu flags  -> 只保留 HasSSE2
  internal cpu flags -> 仍然是真实值
```

因此内部 flags 必须在进程出现后直接写内存中和，不能只靠环境变量。

## 实现

### 1. 服务环境

`scripts/set-cowork-service-env.ps1` 给 `CoworkVMService` 的注册表
`Environment` 增加值：

```text
GODEBUG=cpu.all=off
```

`install-service-injector.ps1` 在启动 Cowork 服务前自动调用它，
`-Uninstall` 时移除该值。当前 registry 输出见 `service-env.txt`。

安装器还把 `CacServiceInjector` 加入 `CoworkVMService` 的 SCM
`DependOnService`（保留原有 `staterepository`），让开机 auto-start
按注入器优先的顺序启动。手动 `sc start CoworkVMService` 不会自动
拉起依赖，运维脚本会先启动注入器。

### 2. 注入器早期中和

`native/ServiceInjector/main.cpp`：

- 轮询间隔从 2000 ms 改为 50 ms；
- 找到 `cowork-svc.exe` 后，先按文件 SHA-256 校验版本；
- 在 `NativeBridge.dll` 注入前，直接 `WriteProcessMemory`：

```text
internal/cpu.X86 : RVA 0x123B9C0, 21 bytes, 保留 HasOSXSAVE
vendor cpu.X86   : RVA 0x123BB00, 45 bytes, 保留 HasSSE2
```

- 读取 `active-profile.ini` 的 `cpuid_mode`，只有 `neutral` 才写；
- 审计 `service.injector cpu-flags`，记录改变数量。
- 哈希校验通过后创建 `Local\CACNativeBridgeCpuVerified_<pid>` 事件；
  NativeBridge 看到该事件（或看到 flags 已经是 neutral）就跳过重复
  的 60 MB SHA-256，直接安装 4 条 CPU hooks。
- `install-service-injector.ps1` 会写 `C:\ProgramData\CAC\native\cowork-svc.hash`：

```text
path|size|FILETIME|sha256
```

  注入器启动后直接读取缓存；命中时审计为 `hash=cache`，不再重算
  60 MB 文件哈希。

### 3. NativeBridge 二次中和

`ApiHooks.cpp` 的 `NeutralizeGoCpuFlags()` 在 `InstallCpuHooksFromManifest()`
之后执行同样的哈希校验和写入。它是对早期补丁的兜底：

```text
cpu.hash trusted injector
cpu.flags neutralized internal=0/21 vendor=0/45 osxsave-kept sse2-kept
```

### 4. 运行时入口

4 条 Go ABI manifest 不变：

```text
0x2BA0    gocpuid
0x2BC0    goxgetbv
0x212A60  gocpuid
0x212A80  goxgetbv
```

## 受控前/后对比

“前”：停止 `CacServiceInjector`、移除 `GODEBUG`，只启动
`CoworkVMService`，PID 16748。

“后”：恢复 `GODEBUG`、启动注入器、重启服务，PID 13508。

`cpu-flags-before.json` / `cpu-flags-after.json` 的统计：

| 区域 | 前（真实） | 后（neutral） |
|---|---|---|
| `internal/cpu.X86` | 15 个 true | 1 个 true（`HasOSXSAVE`） |
| `vendor x/sys/cpu.X86` | 17 个 true | 1 个 true（`HasSSE2`） |

前值：

```text
internal: HasAES, HasAVX, HasAVX2, HasBMI1, HasBMI2, HasERMS, HasFMA,
          HasOSXSAVE, HasPCLMULQDQ, HasPOPCNT, HasRDTSCP, HasSSE3,
          HasSSSE3, HasSSE41, HasSSE42
vendor:   HasAES, HasAVX, HasAVX2, HasBMI1, HasBMI2, HasCX16, HasERMS,
          HasFMA, HasOSXSAVE, HasPCLMULQDQ, HasPOPCNT, HasRDRAND,
          HasSSE2, HasSSE3, HasSSSE3, HasSSE41, HasSSE42
```

后值：

```text
internal: HasOSXSAVE=1，其余 20 个为 0
vendor:   HasSSE2=1，其余 44 个为 0
```

注入器对 PID 16748 的运行中补丁审计为：

```text
cpu-flags internal=14/21 vendor=16/45
```

对 PID 13508 的启动补丁审计为：

```text
cpu-flags internal=14/21 vendor=0/45 hash=cache
```

`vendor=0/45` 说明 `GODEBUG` 已在启动阶段先关掉 vendor flags；
`internal=14/21` 说明内部 flags 由注入器在进程内中和。

## 时间窗口

`timing.txt`：

```text
process_start          03:46:59.941
target_found           03:46:59.960  (+19 ms)
early_cpu_flags        03:46:59.960  (+19 ms)
native_bridge_attach   03:46:59.964  (+23 ms)
cpu_hash_trusted       03:46:59.964  (+23 ms)
service_log_start      03:46:59.967  (+26 ms)
manifest_complete      03:46:59.967  (+26 ms)
native_bridge_ready    03:47:00.025  (+84 ms)
signature_verification 03:47:00.095  (+154 ms)
service_ready          03:47:00.095  (+154 ms)
```

`C:\ProgramData\Claude\Logs\cowork-service.log` 显示服务自身在
`00.095` 才完成 signature verification 并开始监听 named pipe；
CPU flags 在 `59.960`、4 条 CPU hooks 在 `59.967` 已经就位，早于
服务 ready 约 128 ms。`hash=cache` 命中后，注入器从 target-found
到写完 flags 只用了不到 1 ms。

## 服务内 CPU 探测

`cpu-probe.json` 仍通过服务进程内远程线程调用 4 个被 hook 的入口：

```text
RVA 0x2BA0   leaf 0x40000000  host [0, 0x2f, 0, 2] -> result [0, 0, 0, 0]
RVA 0x212A60 leaf 0x40000000  host [0, 0x2f, 0, 2] -> result [0, 0, 0, 0]
RVA 0x2BC0   xgetbv           host 0x7 -> result 0x7
RVA 0x212A80 xgetbv           host 0x7 -> result 0x7
```

审计：

```text
cpu.manifest complete entries=4 installed=4
cpu.gocpuid filtered go leaf=0x40000000 ... eax=0x0 ebx=0x0 ecx=0x0 edx=0x0
cpu.goxgetbv observed go xcr0=0x7
```

## Profile A/B 回归

| 阶段 | Profile | PID | identity |
|---|---|---|---|
| A | desktop-1 | 7764 | `mac=02:2a:09:f6:66:f2 host=host-7105ecbc machine=7105ecbc... disk=WD-84490e004894` |
| B | desktop-b | 17764 | `mac=02:bb:bb:bb:bb:bb host=host-bbbb machine=bbbbbbbb... disk=WD-bbbbbbbbbbbb` |
| A | desktop-1 | 25300 | `mac=02:2a:09:f6:66:f2 host=host-7105ecbc machine=7105ecbc... disk=WD-84490e004894` |
| A（最终 clean restart） | desktop-1 | 13508 | 同上 |

三次启动都满足：

```text
cpu.manifest complete entries=4 installed=4
cpu.flags neutralized
native.bridge ready
```

## ant-did / Claude-3p 重定向

`redirect-test.json`：

```text
target_ant_did      true  content=ant-did-test
target_claude_3p    true  content=claude-3p-test
original_ant_did    false
original_claude_3p  false
```

`redirect-audit.jsonl` 包含两条 `api.claudeprofile redirect` 和最终
`profile\...` 落点。

## 边界

- 早期补丁发生在进程启动后约 19 ms。0-19 ms 内只有 Go runtime
  `cpuinit` 等初始化；服务日志显示应用层 signature verification 和
  named pipe ready 在 +154 ms，晚于补丁和 4 条 CPU hooks（+26 ms）。
  若未来服务把 CPU 指纹
  提前到 runtime 初始化期间，仍需进程入口前注入（内核 loader
  notify / IFEO / 服务 wrapper），不在本阶段。
- 本补丁修改 `internal/cpu.X86` 与 vendor `cpu.X86` 的对外特征表；
  Go runtime 内部用于指令选择的 `x86Has*` 缓存不在本次范围。
- `cpuid_mode=neutral` 时只中和 hypervisor 位和 >= 0x40000000 的
  leaf；`empty`/`passthrough` 模式保持原有语义，早期补丁会跳过。
- `ant-did` 重定向覆盖 `CreateFileW/A/2` 的精确后缀；直接
  `NtCreateFile` 路径只审计，不重写。
- SCM 依赖只约束开机 auto-start；手动单独 `sc start
  CoworkVMService` 不会启动 `CacServiceInjector`，应先启动注入器或
  使用 `install-service-injector.ps1`。

## 复现

```powershell
.\scripts\service-profile.ps1
.\scripts\install-service-injector.ps1
.\scripts\probe-service-cpu.ps1
.\scripts\read-service-cpu-flags.ps1
.\scripts\test-claude-profile-redirect.ps1

# 可选：设置/移除服务级 GODEBUG
.\scripts\set-cowork-service-env.ps1
.\scripts\set-cowork-service-env.ps1 -Remove
```

## 文件

```text
cpu-flags-before.json   停止注入器/GODEBUG 后的真实 flags
cpu-flags-after.json    最终 neutral flags
cpu-flags-audit.jsonl   注入器早期补丁 + NativeBridge 二次补丁审计
cpu-probe.json          4 个入口的服务内探测
profile-ab.jsonl        A/B/A identity 与 manifest/flags 审计
redirect-test.json      ant-did/Claude-3p 重定向结果
redirect-audit.jsonl    重定向审计
service-env.txt         服务级 GODEBUG
timing.txt              启动到补丁/ready 的时间
hashes.txt              产物哈希
```

最终状态：`desktop-1`，PID 13508，manifest 4/4，
`cpu.flags` neutral，`redirect_ant_did=1`，服务 ready。
