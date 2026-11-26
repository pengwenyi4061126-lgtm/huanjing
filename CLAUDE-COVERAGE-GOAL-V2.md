# Claude Desktop 设备画像隔离与反关联 · 目标契约 v2

- revision: `2026-11-25.32`
- supersedes: `2026-11-25.31`（G1b 闭合）、`2026-11-25.30`（G6 交付与回滚）、`2026-11-25.29`（目标文本对齐）、`2026-11-25.28`（G7 独立复核）、`2026-11-25.27`（G8 COA 归档）、`2026-11-25.26`（G1b 动态边关闭）、`2026-11-25.25`（G1b 1919 行关闭）、`2026-11-25.24`（P1b 登录门）、`2026-11-25.23`（目标收敛）、`2026-11-25.22`（G1b 非 app 文件关闭）、`2026-11-25.21`（G1b PE 关闭）、`2026-11-25.20`、`2026-11-25.19`、`2026-11-25.18`、`2026-11-25.17`、`2026-11-25.16`、`2026-11-25.15`、`2026-11-25.14`、`2026-11-25.13`、`2026-11-25.12`、`2026-11-25.11`、`2026-11-25.10`、`2026-11-25.9`、`2026-11-25.8`、`2026-11-25.7`、`2026-11-24.1` 与 `CLAUDE-COVERAGE-GOAL.md` (`2026-11-23.1`)；旧契约与旧证据保留为历史，不删除、不改写
- workspace: `E:\环境\huanjing`
- target: Claude Desktop `5.1231.2.0` Windows x64 MSIX（冻结，原始包只读）
- 状态: active
- 进度快照（2026-11-25T04:50+08:00）：G0 pass / G1 pass(分母) / **G1b pass** / G2 pass-bounded / G3 pass-partial / G4a partial / G4b blocked-external-input / G5a in_progress / G5b blocked-external-input / **G5c pass** / **G6 pass** / G7 pass / G8 pass；CRR 61 项中 pass 41，fail 0，unverified 9，unsupported 9，not-applicable 2；`device_image_subset_pass=false`、`supported_subset_pass=false`、`full_coverage_within_declared_scope=false`、`anti_association_pass=false`、`functional_pass=false`；`auxiliary_documented=true`。
- 本次修订动因：G5c 非登录交替 A/B 闭合，P3 非账号主线全部完成。两轮 8 次真实 Claude 运行（4 bare + 4 injected，A/B 顺序交替）全部 exit 0，网络 before/after 摘要单一且不变；bare 读回宿主 zh-CN/Asia-Shanghai/hc24/dm32/GTX 1050 Ti/1440x900，A 读回 en-US/America-New_York/hc8/dm16/Intel UHD 630/1920x1080，B 读回 en-GB/Europe-London/hc12/dm8/AMD RX 6600/2560x1440；A/B ant-did 稳定且互异；音频 label 脱敏为 0。CRR 状态不变；剩余仅 P2 账号门。

## 0. 目的与非目标

按优先级只做三件事：

1. **设备画像隔离**：同一台非 VM 宿主机上的多个 Claude Profile，不因主进程、renderer、preload、Sentry、Telemetry 或持久化存储中的设备/软件/外设字段而呈现为同一设备。
2. **环境一致性**：语言、时区、UTC 偏移、区域格式、屏幕、GPU、CPU、内存、软件与外设画像与声明的 persona 一致；网络出口与反关联网络隐藏另立目标。
3. **功能可用**：上述改动不得破坏登录、会话、MCP、更新、崩溃恢复与正常退出。

非目标（本契约内不做）：

- 伪造 TPM / attestation / 代码签名 / 硬件根信任。
- 修改原始 MSIX 安装目录；所有改动只发生在受控副本或 Profile 层。
- 改变宿主路由、DNS、代理、网卡、WFP、LWF、TUN；网络隐藏部署另立目标。
- 在本目标内宣称 `anti_association_pass`；共享出口/ASN/DNS 未改变时该判定恒为 false。
- 继续扩展 PnP、DDC/EDID、SMART/NVMe/ATA、raw HID、音频端点等 COA 能力；除非出现新的 Claude 可达证据，否则只归档，不再投入主线工时。
- 以“没测”冒充“通过”，以“钩子装了”冒充“Claude 读了”。

### 0.1 修订后的目标与执行顺序

本阶段的主交付是 **非 VM 设备画像的受支持子集**，不是网络反关联的最终完成：

| 目标 | 本阶段要求 | 当前是否可宣称 |
|---|---|---|
| `device_image_subset_pass` | M/E/B/D/S/A 组所有 required 项 pass，且 R-07 的 Sentry 存储/事件 sink 无宿主泄漏 | 否；R-07/B-09/M-05/A-06/E-10/S-04 已 pass，M/E/B/D/S/A 仍有 6 项 unverified（M-03/M-04、S-02、A-01/A-02/A-03），另有 L-03/R-05/R-06；B-08/S-05 已落 unsupported 边界 |
| `supported_subset_pass` | 全 CRR `fail=0`、`unverified=0`；unsupported 逐项带错误码/边界并由用户显式接受 | 否；unverified=9，unsupported=9 |
| `full_coverage_within_declared_scope` | `supported_subset_pass` + required unsupported=0 + G1b 清点闭合 + G7 独立复核 | 否；G1b 已于 v2.31 pass、G5c 已于 v2.32 pass，但 required unsupported=9（N-01…N-04/N-06、R-03、B-08、L-06、S-05）且 supported_subset_pass=false（unverified=9） |
| `anti_association_pass` | N-01…N-06 全闭合、D-06 零命中、R-03/R-06/R-07 可验证 | 否；N 组按用户决定暂缓，R-03 opaque |

冻结分母：**CRR 61 项、COA 10 项**。除非冻结源或真实运行出现新可达证据，否则不再新增检查点、不再把“可能相关”的硬件接口塞进 CRR。

执行顺序固定为：

1. **P0 — 关闭两个已定位的 sink（已完成）**：R-07 用 `scope_v3.json` + 真实 renderer-crash queue envelope 复验；B-09 用 A/B 主 frame、challenge iframe、checkbox iframe、preload、fingerprint 五面复验。两项已 pass，证据见 `goal-v2-r07b09-20261125-0139`。
2. **P1 — 无需账号即可闭合的 unverified，分三波**：
   - **P1a 静态/单次取证**：E-10 已于 v2.15 关闭；B-08 已于 v2.16 落 `unsupported:persona-gpu-reference-unavailable`；R-06 先从冻结源与已捕获队列列字段，缺真实 TelemetryEvent 时 `unverified + blocker:no-telemetry-credential`。
    - **P1b 已否证（v2.24）**：M-03 `getSystemInfo` IPC、M-04 utility-node env、S-02 `getHcsStatus`、A-01/A-02/A-03 computer-use 枚举均被登录页挡住；真实导航到 `/cowork` 后 5 个 native API 全为 0 调用，utility-node 未启动。六项全部落 `unverified + blocker:authentication-required`，不再用 UI/路由/CDP 重试。S-04 已于 v2.18 关闭，S-05 已于 v2.19 落边界，M-05/A-06/L-06 后续只做回归。
   - **P1c 收尾**：P1 全部落终态后做 G5c 交替 A/B 与 G7 独立复核；仍为 `unverified` 的项必须带 blocker，不得空挂。
3. **P2 — 外部输入门控**：L-03、R-05、R-06 需要真实测试账号/登录后快照/telemetry credential；S-02、M-03、M-04、A-01…A-03 也需要真实登录态。没有账号时全部保持 `blocked-external-input`，不得伪造，也不得再用未登录页面重试。
4. **P3 — 非账号收口（已完成）**：G6 构建/部署/回滚（v2.30 pass）、G1b 77 条观察终态化（v2.31 pass）、G5c 两轮交替 A/B（v2.32 pass）。1919 条 retained 行、373 条动态边、PE 资源树、非 app 包文件、G7 独立复核、G8 COA 归档均已关闭。剩余工作全部是 P2 账号/凭据门。

### 0.2 闭合规则（v2.12 新增，强制执行）

1. **终态**：每个 CRR 项在交付前只能落到 `pass`、`fail`、`unsupported`（带原始错误码/架构边界/复现）三类，或保持 `unverified` 但必须附 `blocker`（含 `blocker_class=blocked-external-input` 与缺哪一项外部输入）。交付清单中任何没有 `blocker` 的 `unverified` 视为未完成，不是“待办”；`blocked-external-input` 是 blocker 分类，不是新的 status 值。
2. **尝试上限**：同一项在同一个 revision 内最多 2 次真实运行尝试（A/B 各算 1 次）。2 次后仍不触发，必须写 `unverified + blocker` 或 `unsupported`，不得用相同方法继续复跑；换方法必须记录方法差异与理由。
3. **不扩项**：本 revision 不再新增 CRR/COA。新证据只允许两种去向：把有 Claude 可达证据的 COA 升级进 CRR，或重开已 pass 的对应项。静态关键词、辅助 exe 符号表、bundled 组件不触发升级。
4. **批次合并**：一次 A/B 真实运行同时采集当批所有可触发项（M-03/M-04/M-05、S-02/S-04/S-05、A-01/A-02/A-03/A-06、L-06），不允许一项一批。单批观察窗 ≤ 90 秒；需要长窗的 L-06 单独一批。
5. **时间盒**：P1 最多 6 个真实批次；P2 等账号；P3 在 P1 终态化后开始。超过预算仍未闭合的项按第 1 条落终态，不延长目标。
6. **证据最小化**：每项一个 `verification.json`（六面、原始行、输入哈希、命令、期望值来源、blocker）；日志只保留命中行与必要上下文，不整份复制 Profile。
7. **清理时点**：批次 `verification.json` 落盘后立即删除该批 `.tmp` copy/profile 根；只保留 `native/evidence/claude-coverage/<batch>/` 下的证据文件。保留任何 Profile 必须写 `retained_reason` + 预计释放空间，并在下一批前复核。

### 0.3 v2.23 目标收敛：只跟 Claude 可达证据

1. **硬件接口研究归档**：PnP / `Win32_PnPEntity`、`SetupDi*`、WMI 磁盘/BIOS/主板/序列号、SMART/NVMe/ATA Identify、DDC/CI/EDID、raw HID Report Descriptor、音频端点 ID、NVML/Vulkan/DXGI、MAC/网卡列表、卷序列号/`MachineGuid` 全部是 COA，不是 CRR。它们没有 Claude 可达调用证据；继续为它们写探针属于扩分母，不是补覆盖。G8 只归档“能力存在 + 零可达证据 + 搜索范围”，不再投入主线工时。
2. **A-06 是唯一保留的音频相关项**：Claude 真实调用 `enumerateDevices`，故保留“数量/kind 保留、label/deviceId/groupId 清空”的验收；该项已于 v2.14 pass。它不是继续研究音频端点 ID 的理由。
3. **P1b 已否证，不再复跑**：v2.24 的真实运行把 `https://claude.ai/cowork` 导航出来，但页面仍是登录页；5 个目标 native API 均 0 调用，utility-node 未启动。S-02、M-03、A-01…A-03、M-04 全部改为 `unverified + blocker:authentication-required`。在没有真实登录态前，禁止用 pushState、点击 Feedback、CDP 或 shim 直接调用重试这 6 项。
4. **外部输入门**：L-03（登录/登出/重登/换号）、R-05（登录后远端开关）、R-06（TelemetryEvent 真实体）缺真实测试账号或 telemetry credential 时，保持 `unverified + blocker:blocked-external-input`。v2.24 后除这 3 项外，S-02/M-03/A-01…A-03/M-04 也归入同一外部输入门。
5. **完成口径**：本阶段主交付仍是 `device_image_subset_pass`；`supported_subset_pass` 要求 `fail=0` 且 `unverified=0`；`full_coverage_within_declared_scope` 还要求 required unsupported=0、G1b 闭合、G7 复核；`anti_association_pass` 需要 N 组网络出口分离，继续暂缓，不能因设备画像通过而宣称反关联通过。
6. **反关联事实**：A/B 当前共享出口 `64.83.13.52 / AS979 / LAX`，这是 association link；在 TUN+clean 或等效网络分离落地前，`anti_association_pass=false`，且不得删除 N 组证据。

### 0.4 v2.29 目标重述与剩余路线（本次修订）

v2.29 不改变任何 CRR 状态，只把目标文本与当前证据对齐，并固定剩余非账号工作的验收口径。旧目标栏仍引用 `2026-11-24.1` 的 51 项分母；该分母已废弃，权威分母为 CRR 61 项。

**本阶段唯一主交付**：`device_image_subset_pass`。它要求 M/E/B/D/S/A 组 required 全 pass 且 R-07 无宿主泄漏；它不要求 N 组网络出口分离，也不等于 `anti_association_pass`。

**非账号主线（按序，P3）**：

| 工作包 | 内容 | 通过条件 | 批次上限 |
|---|---|---|---|
| P3.1 G6 交付与回滚（v2.30 已 pass） | 两链：源码/配置/工具链→构建→打包→安装→实际加载；Claude MSIX→实际资源。三项已知缺口 `G6-PROVENANCE-INCOMPLETE`、`G6-DRIVER-PAYLOAD-DIVERGENCE`、`G6-ACTUAL-MODULE-HASH-MISSING` 已逐项关闭。 | 每个产物有哈希；安装树/加载模块哈希与构建产物一致或差异有解释；回滚前后哈希与功能复验通过；原始 MSIX 未被修改 | 2 |
| P3.2 G1b 清点闭合（v2.31 已 pass） | 77 条历史观察逐条 disposition；保留未验证证据，不静默删除。 | 每条有 closure / boundary / blocked-external-input / false-positive 归类；`open=0`、`partial=0`、`unknown=0`；G7 在 v2.31 复核 | 2 |
| P3.3 G5c 非登录交替 A/B（v2.32 已 pass） | `bare→injected→bare→injected` 两轮；只采集不依赖登录的 E/B/D/S/A 项。 | 8 次运行全部 exit 0；bare/A/B 在主世界、preload、主进程三面读回一致；网络 before/after 单一摘要；A/B ant-did 稳定且互异；音频 label 脱敏；登录/会话/MCP/更新/退出留待 P2 | 2 |

G6 的当前证据链（v2.30，v2.31 只做门状态维护、不改变 G6 输入/验收）：`g6-delivery-v230-20261125-0341-final/g6-delivery.json` 为总验，`g6-service-sync-v229-20261125-0350/service-sync.json` 关闭 ProgramData 服务载荷漂移，`g6-module-current-guarded-20261125-031846` 与 `g6-memory-module-current-guarded-20261125-032130` 为真实 Claude 加载文件/内存哈希，`rollback-live-g6-v230-20261125-0335/rollback-result.json` 为可执行回滚。G6 pass 只关闭交付门，不改变 CRR 的 41/0/9/9/2。

G1b 的当前证据链（v2.31）：`g1b-current-v231-20261125-0410/g1b-current-disposition.json` 为 77 条逐条 disposition；`closure.json` 为门摘要；`sha256-manifest.json` 绑定全部证据哈希。39 closed、24 boundary、13 blocked-external-input、1 false-positive；blocked 项仍对应 9 个 unverified CRR 项，不冒充 pass。

G5c 的当前证据链（v2.32）：`g5c-v231-alternating-20261125-0500/sequence.json` 记录 8 次运行的顺序、时长、网络摘要和退出码；`g5c-verification.json` 为主世界/preload/主进程三面一致性、A/B ant-did、配置 locale、音频脱敏和网络不变的全部检查；`sha256-manifest.json` 绑定证据哈希。两轮顺序为 A/B 交替：cycle 1 `bare→A→bare→B`，cycle 2 `bare→B→bare→A`。

**账号门（P2，未开）**：S-02、M-03、M-04、A-01、A-02、A-03、L-03、R-05、R-06 九项保持 `unverified + blocked-external-input`。没有真实登录态/测试账号/telemetry credential 时不得重试，不得用 pushState、Feedback 点击、CDP 或 shim 直接调用绕过登录门。

**停止条件（已到达）**：G6、G1b、G5c 非登录部分全部 pass，P3 非账号主线完成；`device_image_subset_pass` 仍被 6 个登录门项阻塞，`supported_subset_pass` 仍被 9 个 unverified 和 9 个 unsupported 阻塞。剩余工作全部是 P2：S-02、M-03、M-04、A-01、A-02、A-03、L-03、R-05、R-06。不得以 G6/G1b/G5c 通过替代 CRR 判定。

**明确不做**：不新增 CRR/COA；不为 PnP、DDC/EDID、SMART/NVMe/ATA、raw HID、音频端点、NVML/Vulkan/DXGI、MAC、卷序列号写新探针；不部署 TUN+clean/LWF；不改宿主网络；不伪造 TPM/attestation/签名；不修改原始 MSIX。

## 1. 两个账本（本次修订的核心）

v1 的 `6032` 检查点混入了 Go/Rust 运行时符号表、Chromium 引擎资源、URL 解析属性和 bundled 第三方组件，分母不可闭合。v2 拆成两个账本，只有 CRR 参与完成判定。

### 1.1 CRR — `claude_reachable_required`

进入条件（全部满足）：

- 信号在 Claude 发行包内存在**真实代码路径**，不是符号表、不是引擎资源、不是 bundled 第三方组件；
- 且满足其一：运行时可观测；或有明确触发场景且已定义观测点；
- `classification` ∈ `confirmed-read` / `conditional`；`conditional` 的触发状态未知时计入有效分母；
- `status` ∈ `pass` / `fail` / `unsupported` / `unverified`；`unsupported` 必须带原始错误码或架构边界说明；`unverified` 必须带 `blocker`（`blocker_class` + 缺失输入），其中外部账号/凭据类记为 `blocked-external-input`；
- `applicability` ∈ `required` / `conditional` / `not-applicable`；`not-applicable` 时 `status=null`，不计 pass。

### 1.2 COA — `capability_only_auxiliary`

- 有钩子或探针能力，但**没有 Claude 可达证据**；
- 只记录三件事：能力存在、搜索方法、零命中证据；
- 不参与完成判定、不进 pass 分母、不阻塞任何门；
- 一旦出现新的可达证据（新版本、新配置、运行时命中），自动升级进 CRR 并重开对应门。

### 1.3 假阳性排除规则（强制）

下列命中一律**不得**计为可达证据：

- **运行时符号表**：同一组字符串在不同 Go/Rust 辅助 exe 中以相同次数出现、偏移连续（例：`SetupDi`、`DeviceIoControl`、`HidD_` 在 `claude.exe` 的 `220247672–220251112` 区间，且在 `github-mcp-server.exe`、`claude-ssh-*`、`cowork-svc.exe` 中同为 27 次）。
- **子串命中**：`ATA` ⊂ `toDataURL` / `CryptProtectData` / `navigator.userAgentData`；`machine` ⊂ `machineLearning`。
- **URL 属性混淆**：`url.hostname` / `URL.hostname` ≠ `os.hostname`。
- **Chromium 引擎资源**：`locales/*.pak`、`LICENSES.chromium.html`、`d3dcompiler_*`、`dxcompiler*`、`snapshot_blob.bin`、`v8_context_snapshot.bin`。
- **bundled 第三方组件**：`github-mcp-server.exe`、`office365-mcp*`、`msalruntime.dll`、`chrome-native-host.exe` 等，默认 `conditional`，不进入核心设备画像。
- **探针自证**：钩子自己写出的日志、探针自己发起的调用、探针进程自身的环境。

### 1.4 观测面（surface）纪律（本次新增，强制）

Claude 是 Electron 多进程程序，同一个信号在不同进程由不同 API 产生，**不允许跨面代替**：

| surface | 典型来源 | 不能代表 |
|---|---|---|
| `renderer-mainworld` | `navigator.*`、`Intl`、`screen`、WebGL、DOM | 主进程 `os.*`、`app.*`、Chromium 网络栈 |
| `renderer-preload` | preload/isolated world 的 `navigator.*`、`Intl`、`screen`、WebGL | 页面主世界；两者必须分别取证 |
| `main` | `app.getLocale()`、`app.getPreferredSystemLanguages()`、`os.totalmem()`、`process.getSystemVersion()` | renderer 的 `navigator.deviceMemory` / `Intl` |
| `utility-node` | MCP host、node child、`process.env` | main / renderer |
| `native` | `NativeBridge.dll`、Win32 / 注册表 / 设备接口 | Node 层 |
| `storage` | Profile 文件、Local State、Cookies、IndexedDB | 请求头 |
| `network` | 实际出站请求头 / body / 目的地 | 本地配置“应该会发什么” |

规则：

1. 每个 CRR 项必须声明 `required_surfaces`；任一面未取到真实值，该项不得判 `pass`。
2. 派生值必须回到**产生它的面**验收：`anthropic-client-*` 头由主进程 `os.*` 计算，就必须在主进程与 `network` 两面同时取证；renderer 的 `deviceMemory` 通过不算这一项通过。
2.1 `renderer-preload` 与 `renderer-mainworld` 是两个独立面。2026-11-25T00:34Z 已在同一轮抓到 preload=`hc24/dm32/Asia/Shanghai/GTX 1050 Ti`、mainworld=`hc8/dm16/America/New_York/Intel UHD 630`；只补主世界属于漏面。修复后 preload 读回 A=`en-US/8/16/America/New_York/1920x1080/Intel UHD 630`、B=`en-GB/12/8/Europe/London/2560x1440/AMD RX 6600`。
3. 观测记录必须带 `surface`、`pid`、`process_start_utc`；缺任一项视为不可归因。
4. 主进程源码位置必须落到冻结源内可复现的代码路径（例：`app.asar` 内 `U9t=Math.round(os.totalmem()/1024**3)`、`ab=H9t(os.totalmem())`、`H9t(e){return e<6e9?"le4":e<12e9?"8":e<2e10?"16":"gt16"}`）。
5. 宿主真实值只要出现在 persona 声明不同的面上，即 `fail`；不得用“另一个面已经改好”关闭。

### 1.5 完成分级与反关联边界（本次修订的核心）

旧契约把“CRR 无 fail/unverified + 用户接受 unsupported”直接称为完成，但未区分“设备画像子集通过”“声明的完整覆盖”“反关联通过”“功能可用”。这会允许一个仍共享出口 IP、仍有 opaque 遥测体、仍缺登录态证据的项目被误报为完成。v2.8 固定为四个独立判定：

| 判定 | 最低条件 | 不包含 |
|---|---|---|
| `device_image_subset_pass` | M/E/B/D/S/A 组所有 required 项 pass；N 组只记录不要求分离 | 不证明跨 Profile 不可关联 |
| `supported_subset_pass` | `fail=0`、`unverified=0`；unsupported 逐项列原始错误码/边界，且用户显式接受 | 不证明 required unsupported 为零 |
| `full_coverage_within_declared_scope` | `supported_subset_pass` + required unsupported=0 + G1b 清点闭合 + G7 独立复核 | 不允许把“没测”或“架构不支持”算作覆盖 |
| `anti_association_pass` | `supported_subset_pass` + N-01…N-06 全部闭合 + D-06 负向泄漏为零 + R-03/R-06/R-07 可验证 | 网络隐藏未部署时恒为 false |

强制规则：

1. `anti_association_pass` 与 `functional_pass` 分开声明；功能可用不能抵消关联面。
2. 两个 Profile 共享出口 IP/ASN、共享 DNS、共享代理残留、共享安装级 AUMID，均必须在报告中列为关联面；不能因为“设备画像已改”而忽略。
3. `R-03` 的 opaque body 未解时，不得声明“请求体设备字段已覆盖”；只能声明“该 sink 为未验证边界”。
4. 用户暂缓 TUN+clean 只关闭部署动作，不关闭 N 组事实记录；N-01…N-04/N-06 保持 `unsupported:user-deferred-network-hiding`，并阻塞 `anti_association_pass`。

### 1.6 清点闭合门（G1b，本次新增）

`G1` 只表示 CRR 分母冻结，不表示来源清点闭合。以下任一未闭合，`full_coverage_within_declared_scope=false`：

- PE 区段、资源目录、导入/导出、嵌入 payload 未逐节点清点（含 `claude.exe`、`claude-native-binding.node`、`ion-dist.asar`）；
- 旧账本 373 条未解析动态边（remote-fetch / webassembly-load / dynamic-require / dynamic-import / process-dlopen）无逐类 disposition；
- 77 条未归类观察无 closure 或明确 false-positive/third-party 归类；
- 1919 条 retained-but-not-CRR 行没有“为何不进 CRR”的可复核理由；
- CLI-only 子命令、bundled helper、MCP server、cowork/update 辅助程序被桌面实际拉起却未纳入条件路径。

`G1b` 的通过标准是“每个缺口有证据化 disposition”，不是“把所有东西都塞进 CRR”。无法归类的观察仍留在阻塞项，不得静默删除。

## 2. CRR 清单

共 61 项。每项都必须有：真实 Claude 进程内的观测点、`required_surfaces`、期望值来源、原始输出、可复现命令。

### 2.1 N — 网络姿态（只测不改）

| ID | 信号 | 验收 |
|---|---|---|
| N-01 | 出口 IP / ASN / 国家 | 记录真实值；与声明 persona 一致，或显式标为 `unverified` 并说明边界 |
| N-02 | 解析器与出口是否同源 | 记录 DNS 服务器与解析结果；不得出现“本地 ISP DNS + 海外出口”的裸泄漏 |
| N-03 | 代理可见性 | `WinHTTP` / `HKCU Internet Settings` / PAC 与 persona 一致，无残留 |
| N-04 | VPN / hosting 判定线索 | 只读观察请求头与 feature flag 状态，不主动探测 |
| N-05 | 批次前后网络不变 | `network-before.json` 与 `network-after.json` 摘要一致 |
| N-06 | 跨 Profile 出口分离 | A/B 的出口 IP、ASN、DNS 解析链、代理/PAC 至少有一项按 persona 分离；共享同一 IP/ASN 时必须标为 `association_link_present`，且 `anti_association_pass=false` |

### 2.2 E — 语言 / 时区 / 区域

| ID | 信号 | 验收 |
|---|---|---|
| E-01 | `navigator.language` / `navigator.languages` | 等于 persona；跨 Profile must-differ |
| E-02 | `Intl.DateTimeFormat().resolvedOptions().timeZone` | 等于 persona timezone |
| E-03 | `new Date().getTimezoneOffset()` | 与 persona timezone 自洽 |
| E-04 | `Intl.DateTimeFormat().resolvedOptions().locale` | 等于 persona locale |
| E-05 | 主进程 `app.getLocale()` / `app.getPreferredSystemLanguages()` | 等于 persona locale；surface=`main`+`renderer`，主进程空值或 `zh-*` 即 fail |
| E-06 | `Accept-Language` / `sec-ch-ua*` | 与 persona 一致，且不随宿主系统漂移；surface=`network`，必须取自真实请求头 |
| E-07 | 第三方 iframe 面（hCaptcha 等） | 不仅检查 `hl`，还要在同一 iframe 的 mainworld/preload 读回 `navigator.language(s)`、`Intl` timeZone/locale、`hardwareConcurrency`、`deviceMemory`、`screen`、WebGL 与 `maxTouchPoints`；任一值与 persona 冲突即 fail；iframe 未加载时记 `unverified`，不能拿主 frame 代替 |
| E-08 | 首文档 HTML `lang` 属性 | 与 persona 一致 |
| E-09 | 数字/日期区域格式 | 仅在 renderer 可达时计分，否则 `not-applicable` |
| E-10 | 持久化 `config.json locale` | `pass`（v2.15）。冻结源 `app.asar`：`V_="en-US"`、`dFt()` 用 `app.getPreferredSystemLanguages()/getLocale()` 选 catalog 并回退 `V_`、`gFt()` 用 `_o.set("locale",t)` 持久化、`_Ft()` 用 `_o.get("locale")` 读取。宿主 `zh-CN`，A/B 文件均为 `en-US`（app-default）；运行时 main/renderer/network A=`en-US`、B=`en-GB`。证据：`goal-v2-e10-verification-20261125-0215` |

### 2.3 D — 设备标识与关联

| ID | 信号 | 验收 |
|---|---|---|
| D-01 | `%APPDATA%\Claude\ant-did` | 每 Profile 唯一；形态为随机标识而非硬件派生哈希 |
| D-02 | `config.json` / `Local State` / `Preferences` 中的持久 ID | 全部枚举，跨 Profile must-differ |
| D-03 | `localStorage` / IndexedDB / Cookies / session partition | 同 Profile 稳定、跨 Profile 隔离 |
| D-04 | 安装级身份（MSIX package family / AUMID） | 记录真实值；不得被误当成 Profile 级隔离 |
| D-05 | 同 Profile 稳定性 | 连续两次启动 ID 不变 |
| D-06 | 负向泄漏 | A Profile 的任何 ID 不出现在 B Profile 的文件与请求中 |

### 2.4 S — 会话与环境标志

| ID | 信号 | 验收 |
|---|---|---|
| S-01 | `cuIsRemoteSession` | 返回值与 persona 声明一致 |
| S-02 | `getHcsStatus`（Hyper-V / WSL / HCS） | 记录真实值；非 VM 声明下不得呈现 VM 证据 |
| S-03 | `getWindowsElevationType` | 记录真实值并与启动方式一致 |
| S-04 | 进程谱系与命令行 | `pass`（v2.18）。bare 与 injected 两个 115 秒窗口都只调用 `readProcessTree`/`readProcessFootprints`；返回字段仅 `pid/parentPid/memory/cpu/creationTime` 与 `footprintBytes/commitBytes/creationTime`，无 name/path/cmdline/env；`path_like=0`、`extended_flag=0`、`matched=0`。证据：`goal-v2-s04-verification-20261125-0246` |
| S-05 | 进程、模块、命令行与环境标记 | `unsupported:controlled-copy-path-in-argv`（v2.19）。主进程 `installEnvSanitizer()` 已隐藏所有 `/^CAC_/` 键（`visible_cac_keys=0`），persona/登录页/请求头正常；进程面为 S-04 的数值字段，renderer 无 argv/execPath。残留：受控副本从 `.tmp\goal-v2-*-copy` 启动，`process.execPath`/`process.argv` 含 harness 路径，Claude 读 argv 做 flag/relaunch。证据：`goal-v2-s05-verification-20261125-0258` |
| S-06 | MSIX 包身份 | 记录并与副本/原包边界一致 |

### 2.5 A — 软件与外设枚举

| ID | 信号 | 验收 |
|---|---|---|
| A-01 | `cuListInstalledApps` | 记录输出；VPN / 代理 / 远程工具条目按 persona 处理 |
| A-02 | `cuListRunningApps` | 同上 |
| A-03 | `enumerateNetworkDrives` | 记录真实值，不泄漏宿主映射盘 |
| A-04 | `cuListDisplays` | 数量 / 分辨率 / DPI / 主屏与 persona 一致 |
| A-05 | 字体列表（renderer 可达时） | 记录；不得出现 persona 外的高辨识字体集合 |
| A-06 | 音频设备数量与标签存在性（`enumerateDevices`） | `pass`（v2.14，fail→pass）。基线 A/B 均为 5 个 audiooutput、5 个非空 label，5 个 label 哈希在 A/B 完全一致，判 `fail`；修复后 persona 未声明 `audioDevices` 时保留数量/kind，清空 `deviceId`/`groupId`/`label`，A/B 均 `label_present=0`、label 哈希集合为空、group 哈希仅空串哈希，数量仍 5/5，登录页正常。证据：`goal-v2-a06-verification-20261125-0210` |

### 2.6 B — 浏览器指纹

| ID | 信号 | 验收 |
|---|---|---|
| B-01 | `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL` | 与 persona GPU 一致 |
| B-02 | WebGPU adapter info（可用时） | 与 persona 一致，否则 `not-applicable` |
| B-03 | `navigator.hardwareConcurrency` | 与 persona CPU 一致 |
| B-04 | `navigator.deviceMemory` | 与 persona 内存一致（仅 renderer 面；主进程面见 M-01） |
| B-05 | `screen.*` / `devicePixelRatio` | 与 persona 显示配置自洽 |
| B-06 | `navigator.userAgent` / `navigator.platform` / UA-CH | Electron / Chromium 版本与真实二进制一致；`navigator.platform` 与 persona 自洽；若页面调用 `userAgentData.getHighEntropyValues`，必须记录返回的 architecture/bitness/platformVersion 等字段 |
| B-07 | `navigator.plugins` / `mimeTypes` | 记录真实值，跨 Profile 稳定 |
| B-08 | WebGL 扩展列表 | `unsupported:persona-gpu-reference-unavailable`（v2.16）。A/B 均为 35 项，SHA256 `0D881644BA4D80299928CBD6A557797BE8323711CF2AF9E990D24085FA89F78C`；相同只证明 allowed-same。缺 Intel UHD 630 / AMD RX 6600 真机或厂商 ANGLE 扩展表，宿主 GTX 1050 Ti 基线不能代替 persona。证据：`goal-v2-b08-verification-20261125-0222` |
| B-09 | `navigator.maxTouchPoints` | 非触屏 persona 必须为 `0`。A/B 的主 frame、hCaptcha challenge/checkbox iframe、preload、`renderer-fingerprint` 全部读回 `0`，判 `pass`。证据：`goal-v2-g5a-personaa2-20261125-013241`、`goal-v2-g5b-personab2-20261125-013621` |

### 2.7 R — 请求与遥测

| ID | 信号 | 验收 |
|---|---|---|
| R-01 | 请求目的地清单 | 含 `claude.ai`、hCaptcha、Sentry、GrowthBook 等，全部登记 |
| R-02 | 请求头集合 | UA、`Accept-Language`、`sec-ch-ua*`、自定义头逐项记录 |
| R-03 | 请求体中的设备/环境字段 | 键名 + 值哈希；不得出现宿主真实设备值。`x`+Z85 高熵体必须继续尝试从冻结源恢复编码/密钥；无密钥时保持 `unsupported:opaque-high-entropy-payload`，并阻塞 `anti_association_pass` |
| R-04 | 重定向 / 重试 | 记录链路；不得把宿主特征带到第三方域 |
| R-05 | 远端开关快照 | 必须同时有登录前与登录后两份快照；只有未登录 `fcache` 不算闭合；登录后 flag 可能改变，缺后态即 `unverified` |
| R-06 | TelemetryEvent 元数据字段 | 从冻结源确认 `cpu_model`、`os_release`、`os_build`、`os_build_revision`、`os_edition`、`device_class`、`total_memory`、`free_memory`、`available_memory`、`install_id`、`app_session_id`、`organization_id` 等字段进入事件；在真实队列/网络体/日志中逐字段取证，跨 Profile 不得出现宿主真实值或共享 `install_id` |
| R-07 | Sentry / Electron 事件上下文 | 检查 `scope_v3.json` 与真实 renderer-crash queue envelope（等价于 transport 前的序列化 body；有 on-wire capture 时优先）的 `contexts.device` / `contexts.gpu_*` / `contexts.culture` / `contexts.app`。A/B 均只含 persona 的 CPU、processor_count、screen、GPU 名称/驱动、locale/timezone，且 host `1440x900`/Xeon/GTX 1050 Ti/zh-CN/Asia/Shanghai 为 0 命中；判 `pass`。证据：`goal-v2-r07b09-20261125-0139` |

### 2.8 L — 生命周期与持久化

| ID | 信号 | 验收 |
|---|---|---|
| L-01 | Profile 目录树前后差异 | 仅预期写入；无跨 Profile 污染 |
| L-02 | 冷启动 / 热启动 | 两条路径都测 |
| L-03 | 登录 / 登出 / 同账号重登 / 换号 | 四个场景各一轮 |
| L-04 | 崩溃恢复（crashpad） | 不产生新的宿主特征泄漏 |
| L-05 | 正常退出 | 无残留进程、句柄、锁 |
| L-06 | 更新器 | `unsupported:updater-disabled-in-controlled-copy`（v2.17）。115 秒真实运行中 Claude 写出 `[updater] App is not installed, not enabling auto-updates`，无 update 主机请求；静态事件只含 `current_version`/`update_channel`/`target_version`/`install_method`/`is_manual`。真正 updater 只能在已安装 MSIX 运行。证据：`goal-v2-l06-verification-20261125-0232` |

### 2.9 M — 主进程派生画像（v2.7 新增，v2.8 补齐）

这几项由真实请求头、`app.asar` 主进程代码和 TelemetryEvent 构造函数反推得到，不是凑数：`anthropic-client-total-memory-gb` / `device-class` / `os-version` / `cpu_model` / `os_edition` 都在主进程侧计算或采集，renderer 补丁完全覆盖不到。

| ID | 信号 | 验收 |
|---|---|---|
| M-01 | 主进程 `os.totalmem()` / `os.freemem()` → `anthropic-client-total-memory-gb`、`anthropic-client-device-class` | 主进程读回等于 persona 内存；派生头等于 persona 档位（`le4`/`8`/`16`/`gt16`）；persona=16 GiB 时不得出现 `32`/`gt16`；跨 Profile 不同 persona 必须 must-differ |
| M-02 | 主进程 `os.release()` / `os.version()` / `process.getSystemVersion()` → `anthropic-client-os-version`、`anthropic-client-os-platform` | 等于 persona 声明的 OS；未声明时显式 `allowed-same` 并同时记录宿主基线、Claude 读回值与请求头值；不得出现未声明的 build 漂移 |
| M-03 | 主进程 `os.cpus()[0].model` → `cpu_model`；`os_build` / `os_build_revision` / `os_edition` / `os_release`；`app.runningUnderARM64Translation` | 从冻结源确认这些字段进入 `getSystemInfo` 与 TelemetryEvent；主进程读回与 persona CPU/OS 自洽；宿主真实 CPU 型号/OS edition 不得出现在 persona 不同的 Profile；缺 TelemetryEvent 真实体时 `unverified` |
| M-04 | 主进程环境块：`COMPUTERNAME`、`USERDOMAIN`、`USERNAME`、`USERPROFILE`、`PROCESSOR_IDENTIFIER`、`NUMBER_OF_PROCESSORS`、`os.userInfo().username`、`custom3p_win_account` | 记录 `Kyt()` 白名单 env 被传入 MCP node host / plugin env / frame-local worker 的实际值；`custom3p_win_account` 的 local/entra/domain 判定必须与 persona 声明自洽；main + utility-node + network 三面取证，不能用主进程值代替子进程 |
| M-05 | 日志/错误/遥测中的路径净化 | `pass`（v2.13）。`installMainLogSanitizer()` 覆盖 `createWriteStream` / `appendFileSync` / `appendFile` / `writeFileSync` / `writeFile` / `fs.promises.appendFile` / `fs.promises.writeFile`，对 `main*.log` 做 `...app/resources/app.asar`→`app://`、`E:\环境\huanjing…`→`<workspace>`、`C:\Users\…`→`<user>`。A/B 各新增 679 行，宿主路径/盘符路径/`app.asar`/`C:\Users` 均 0 命中，各 3 行 `app://`；Sentry 与 HTTPS 请求 0 命中 `file:///`/`%E7%8E%AF`。旧 84 处只作基线。证据：`goal-v2-m05-verification-20261125-0216` |

注：A 的 Sentry `contexts.device.cpu_description` 已随 `os.cpus()` hook 变为 persona CPU，只证明 R-07 的一个子面收敛，**不能关闭 M-03**；M-03 仍需 `getSystemInfo`/TelemetryEvent 真实体，因为两者是不同 sink。

## 3. COA 清单（辅助，不阻塞）

| ID | 能力 | 当前状态 |
|---|---|---|
| COA-01 | PnP 设备图 / `Win32_PnPEntity` | 能力存在；Claude 静态 0 命中、运行时 0 调用 |
| COA-02 | `SetupDi*` 设备属性 | 同上；`claude.exe` 命中为 Go 符号表 |
| COA-03 | WMI 磁盘 / BIOS / 主板 / 序列号 | 0 命中 |
| COA-04 | SMART / NVMe Identify / ATA Identify | 0 命中 |
| COA-05 | DDC/CI / EDID | 0 命中；显示器仅 `cuListDisplays` 可达 |
| COA-06 | raw HID Report Descriptor | 0 命中；`HidD_` 为符号表 |
| COA-07 | 音频端点 ID（IMMDevice / MMDevice） | 0 命中；仅设备数量可达 |
| COA-08 | NVML / Vulkan / DXGI 硬件枚举 | 0 命中 |
| COA-09 | MAC / 网卡列表（`GetAdapters*`） | 0 命中 |
| COA-10 | 卷序列号 / `MachineGuid` | 0 命中 |

每项必须附：搜索方法、搜索范围、零命中证据路径。COA 项不得写入完成门。

## 4. 六面（仅对 CRR 适用面）

`static-present` → `bare-baseline` → `injected-actual` → `profile-consistency` → `negative-leakage` → `lifecycle`

- 不适用面 `status=null`，不计入 pass，也不计入 fail。
- `bare-baseline` 必须是同一版本、同一权限、同一账号状态的裸机值。
- `injected-actual` 必须在真实 Claude 进程内取到实际值或可验证摘要，不接受“代码里有”。
- 至少两个交替顺序循环（bare→injected→bare→injected），防止顺序偏差。
- 每个面下面再按 `required_surfaces` 拆：`renderer-mainworld` / `main` / `utility-node` / `native` / `storage` / `network`。跨面一致性是前置检查，不是第七个面；任一必需面缺值即该项 `unverified`。
- 派生 sink 必须同时保留“输入面读回值”和“输出面实际值”。例：M-01 需要 `os.totalmem()` 主进程读回 + `anthropic-client-total-memory-gb` 请求头值两行证据。
- `pass` 的最小单位是“项 × 必需面”，不是“项”。同一项里一个面 pass、另一个面 fail，整项判 `fail`。

## 5. 证据要求

- 同 run 输入哈希、工具版本、进程身份（pid + creation time + image path + 镜像哈希）。
- 真实值或可验证摘要；期望值来源必须可追溯（persona 文件 + 哈希）。
- 原始输出 + 可重现命令 + 输出目录唯一（拒绝非空目录）。
- 采集器健康：provider/filter、权限、起止、丢事件、溢出、截断、磁盘、时钟对齐、flush。
- 独立观测与正例校验；区分探针自发调用；记录观测扰动与异步延迟。
- 任何未归类观察、未知 sink、未界定扫描缺口，保留为阻塞项，不得静默丢弃。
- 不输出真实秘密；凭据只记录存在性、作用域与哈希。

## 6. 资源与安全护栏

- 所有新运行使用唯一输出目录；`reject_nonempty_output_root=true`。
- 启动前预检：内存 reserve = `max(8 GiB, 25% 物理内存)`；E 盘剩余 ≥ `12 GiB`；全局证据上限 `24 GiB`。
- 单批次上限 `1 GiB`；单审计文件上限 `32 MiB`；超限即截断并标记 `truncated=true`，不得静默继续。
- 默认 `summary-only`：完成的批次哈希后删除生成的 ETL/CSV 与受控应用副本；失败批次保留原始。
- 每批 `verification.json` 落盘后立即执行 0.2 第 7 条清理；清理前后各记录一次 `free_gib`，写进该批 `progress.json`。
- 单批真实运行预算：最多 1 份受控副本 + 1 个 A Profile + 1 个 B Profile；禁止为同一批次复制多份安装树。90 秒窗口批次与 L-06 长窗批次分开计。
- 每个批次结束必须显式清理 `.tmp` 下的 copy / profile 根，除非下一批次要用同一 Profile 验证持久性；保留时必须写 `retained_reason`，验证完立即删除。
- 证据目录只保留：`*.json`、`*.jsonl`、`*.log`、哈希清单。缓存、崩溃转储、`Cache/`、`Code Cache/`、`GPUCache/` 不进证据目录。
- 磁盘水位在 `network-before` 同批次记录；E 盘低于 `12 GiB` 立即停止新批次，不删除未验证证据。
- 真实 Claude 运行、重建、部署、共享状态变更互斥取锁（`Global\cac-claude-coverage-runtime`）。
- 每批次记录 `network-before` / `network-after` 摘要；不一致即中止并保留现场。
- 不杀用户进程；不删除未验证证据；不越过 `E:\环境\huanjing` 与 `.tmp` 写入。
- 子代理：主代理 + 最多 3 个；按内存/commit/IO 降并发；文件唯一写者；独立输出目录。
- 新批次启动前必须先做去重预检：已 hash 验证过的受控副本/安装包不得重复复制；先清理已完成批次的 `.tmp` copy/profile 根，再创建新批次；保留项必须记录 `retained_reason`、大小和预计释放空间。若该预检无法把 E 盘保持在 `12 GiB` 以上，不启动新批次。

## 7. 门

| 门 | 内容 | 判定 |
|---|---|---|
| G0 | 冻结 Claude 源与项目构建 provenance | **pass**：7 个源哈希已冻结 |
| G1 | CRR 分母冻结 | **pass**：`.32` 维持 61 项；无新的 Claude 可达证据不再增项。M-01…M-05、R-07 的历史增项依据为真实请求头、TelemetryEvent/Sentry 构造函数与 `app.asar` 主进程代码路径 |
| G1b | 来源清点闭合 | **pass**：77 条观察全部终态 disposition：**closed 39 / boundary 24 / blocked-external-input 13 / false-positive 1**，`open=0`、`partial=0`、`unknown=0`；每条有 reason、证据路径和 CRR 锚点。373 条动态边、PE resource tree（19 文件/73 资源叶）、非 app 包文件（78 文件/unknown=0）、1919 条 retained 行（54 关键词/32 类别/unknown=0）均已关闭。24 条 boundary 是 CRR 范围/采集架构边界（legacy 6032 账本、optional hook、async device IO、CPU flags、route error、ETW、observer effect、B-08/N/S-05 等），13 条 blocked 仍对应 9 个 unverified CRR 项，不冒充 pass |
| G2 | 观测健康与真实调用 | **pass-bounded**：观察窗口、首读取、进程归因、采集器健康已取证；仍有未触发场景 |
| G3 | 最小修复 | **pass-partial**：persona 注入、preload/main/主进程 `os.totalmem/freemem/cpus/release/version`、`app.getLocale*`、存储身份键、负向泄漏扫描已落地；`maxTouchPoints`、Sentry scope 写入净化、Sentry integration sanitizer、GPU/screen 源补丁、日志路径净化、音频 label 脱敏均已通过 A/B；env 块/TelemetryEvent 未闭合；R-03 opaque |
| G4a | 设备画像核心六面 | **partial**：41 pass / 0 fail / 9 unverified / 9 unsupported / 2 not-applicable；B-09/R-07/M-05/A-06/E-10/S-04 已 pass；B-08/L-06/S-05 为边界；剩余 S-02、A-01…A-03、L-03、M-03/M-04、R-05/R-06 |
| G4b | 受门控运行时触发 | **blocked-external-input**：v2.24 真实运行把 `/cowork` 导航出来，但仍是登录页；S-02/M-03/A-01…A-03/M-04 全部 0 调用，utility-node 未启动。五项不再作为 P1b 待办，必须有真实登录态才能重开；禁止从 shim 直接调用冒充 |
| G5a | 请求/遥测 sink 闭合 | **in_progress**：R-01/R-02/R-04/R-07 已闭合；R-03 opaque unsupported；R-05 只有未登录快照；R-06 TelemetryEvent 元数据未逐字段取证 |
| G5b | 账号绑定生命周期 | **blocked-external-input**：L-03 登录/登出/重登/换号、登录后 R-05、登录后 feature flags 需要测试账号；无账号不得伪造 pass |
| G5c | A/B 交替循环与功能验收 | **pass（non-login）**：两轮 8 次真实 Claude 运行（4 bare + 4 injected，A/B 顺序交替）全部 exit 0；网络 before/after 单一摘要且不变；bare 读回宿主 zh-CN/Asia-Shanghai/hc24/dm32/GTX 1050 Ti/1440x900，A 读回 en-US/America-New_York/hc8/dm16/Intel UHD 630/1920x1080，B 读回 en-GB/Europe-London/hc12/dm8/AMD RX 6600/2560x1440；主世界/preload/主进程三面一致；A/B ant-did 稳定且互异；音频 label 脱敏为 0。登录/会话/MCP/更新/崩溃/退出仍属 functional_pass，留待 P2 |
| G6 | 交付与回滚 | **pass（carried from v2.30）**：`g6-delivery-v230-20261125-0341-final/g6-delivery.json` 全部检查通过、`gaps=[]`；构建 provenance 164 sources / 31 artifacts / 17 project inputs / 35 commands（85 条命令路径按工作区后缀解析，0 unresolved、0 hash mismatch）；npm pack 1.0.44 的 64 个 dist 文件无缺失/不一致；6 个核心文件 + ProgramData service binary + CacKernel.sys + CacMacLwf.sys 哈希一致；MSIX claude.exe/app.asar/ion-dist.asar/native binding 整文件哈希匹配；真实 Claude 文件/内存模块哈希与可执行回滚均 pass。v2.31/v2.32 未改 G6 输入或验收，故按 carry-forward 保留 |
| G7 | 独立复核 | **pass**：从 61 项原账本重算分组（N6/E10/D6/S6/A6/B9/R7/L6/M5）、状态（41/0/9/9/2）、pass 集合、9 个 blockers、9 个 unsupported 边界、2 个 N/A、完成判定和证据路径；G1b（1919+373）、P1b（0 目标调用）、G8（10 项）与汇总一致，分母未缩小 |
| G8 | COA 辅助边界归档 | **pass**：10 项 COA 各附能力 probe + 代表证据 + 核心文件精确词扫描 + `native-call-audit` 运行时零调用；全部 `reachability=none-observed`、`blocking=false`、`status=archived`、`unknown=0`。`auxiliary_documented=true`；不扩展 PnP/DDC/SMART/HID 主线 |

## 8. 完成判定

- `crr_pass`：CRR 61 项中，`fail=0`，`unverified=0`；`unsupported` 允许存在，但必须逐项列出原始错误码与边界，且用户显式接受该排除清单。该判定只等于 `supported_subset_pass`，不等于完整覆盖。
- `surface_pass`：每个 CRR 项的 `required_surfaces` 全部有真实值；只有 renderer 面通过、main/network 面未取值的项不计 pass。
- `derived_header_pass`：`anthropic-client-total-memory-gb`、`anthropic-client-device-class`、`anthropic-client-os-version`、`anthropic-client-os-platform`、`anthropic-client-version`、`accept-language` 六类派生值全部与 persona 自洽，且宿主不同值不出现在 persona 声明不同的 Profile 中。
- `auxiliary_documented`：COA 10 项全部有“能力存在 + 零可达证据”记录。
- `network_measured`：N-01…N-05 全部有真实值与前后对比。
- `functional_pass`：登录、会话、MCP、更新、崩溃恢复、正常退出全部可用。
- `device_image_subset_pass`：M/E/B/D/S/A 组 required 项全部 pass，且 R-07 的 Sentry 存储/事件/出站体无宿主设备值；N 组只记录。B-09 必须 A/B 全 frame 复验后才能进入 pass。
- `supported_subset_pass`：`crr_pass=true` 且 unsupported 清单已被用户显式接受；若 R-03 仍为 opaque，则必须由用户明确接受该边界，否则该项阻塞。
- `full_coverage_within_declared_scope`：`supported_subset_pass=true` 且 required unsupported=0、G1b 清点闭合、G7 独立复核通过。
- `anti_association_pass`：`supported_subset_pass=true` 且 N-01…N-06 全部闭合、D-06 零命中、R-03/R-06/R-07 可验证；共享出口 IP/ASN 时恒为 false。
- 以上判定必须分别报告，不能用 `functional_pass` 或 `device_image_subset_pass` 代替 `anti_association_pass`。
- 本修订（`2026-11-25.32`）的主交付目标是 `device_image_subset_pass`；`anti_association_pass` 明确留给后续网络隐藏目标，不因暂缓而删除 N 组证据或把 N 组改 pass。
- G6 交付通过、G1b 清点闭合、G5c 非登录交替通过，均不等于 `device_image_subset_pass` 或 `supported_subset_pass`；它们只关闭各自的门，不改变 CRR 项的 status。
- 本修订不把 COA 归档工作算入主线；PnP、DDC/EDID、SMART/NVMe/ATA、raw HID、音频端点 ID、NVML/Vulkan/DXGI、MAC、卷序列号不再阻塞任何完成判定。
- 不得声明“全设备画像无遗漏”；只有 `full_coverage_within_declared_scope=true` 才可声明声明范围内完整覆盖。
- 完成声明必须附：修订号 + 契约哈希 + 证据目录 + 原始请求头行 + 主进程读回行 + 独立复核哈希。

## 9. 当前基线（2026-11-25）

- 旧账本：6032 检查点 / 6332 source-to-sink / 222 动态边 / 77 未解析观察 / 25 场景 / 已执行 0。
- 已完成的可用证据：受控副本 renderer/preload/mainworld/IPC/serialization 观测；进程归因 `pass-bounded-with-gaps`；交付与回滚 `pass`。
- 已确认的假阳性：`SetupDi` / `DeviceIoControl` / `HidD_` 为 Go 符号表；`hostname` 为 URL 属性；`ATA` 为子串。
- 已确认的运行时事实：Claude 启动阶段只读注册表、文件、elevation、`cuIsRemoteSession`；无硬件接口调用。
- 已确认修复：`navigator.language/languages`、`Intl` timeZone/locale、`getTimezoneOffset`、`hardwareConcurrency=8`、`deviceMemory=16`、`screen=1920x1080`、WebGL `Intel UHD 630`、`document.lang=en-US` 在注入 Profile 内读回一致。
- 已确认身份：`ant-did` 3 个 Profile 3 个不同哈希，48 字符、非纯 hex、非硬件派生；同 Profile 连续两次启动哈希一致。
- 已确认负向：Profile 文件级扫描 203 文件 / 24,804,817 字节 / 0 跳过 / 0 命中；安装级身份 `Claude / 5.1231.2.0 / x64` 为 allowed-same。
- **已闭合（2026-11-25T00:22Z）**：主进程 `os.totalmem()` 读回 `17179869184`（16 GiB）；`anthropic-client-total-memory-gb=16`、`anthropic-client-device-class=16`，宿主 `32/gt16` 不再出现。证据：`goal-v2-g5a-mainpersona-20261125-002138/main-persona.jsonl` 与 `request-headers.jsonl`。
- **已闭合**：`app.getLocale()=en-US`、`app.getSystemLocale()=en-US`、`app.getPreferredSystemLanguages=["en-US","en"]`、`app.getLocaleCountryCode=US`；pre-ready 的空值只作时序证据，不计 fail。`sec-ch-ua` / `sec-ch-ua-platform` 已在真实请求中出现，与 Chromium 156 / Windows 一致。
- **M-02 口径**：`anthropic-client-os-version=10.0.22631` 与 persona 声明的 `10.0.22631` 一致；OS build 属低熵值，本 Profile 显式按 `allowed-same` 记录，不作为跨账号关联依据；若后续 persona 声明不同 build，必须由主进程面同步。
- **已闭合（preload 面）**：旧 `renderer-fingerprint` 在 preload/isolated world 读到宿主 `hc24 / dm32 / Asia/Shanghai / GTX 1050 Ti / 1440x900`；在 preload 应用同一 persona 后，A=`en-US / hc8 / dm16 / America/New_York / 1920x1080 / Intel UHD 630`，B=`en-GB / hc12 / dm8 / Europe/London / 2560x1440 / AMD RX 6600`。证据：`goal-v2-g5a-personaa2-20261125-003558`、`goal-v2-g5b-personab2-20261125-003656`。
- **已闭合（存储）**：D-02 中 `ant-did` A/B 不同（`5AF6…` / `5569…`），`Local State:os_crypt.encrypted_key` 也不同；D-03 cookies 两 Profile 均为 0 行，Local Storage/IndexedDB/Session Storage 的共享相同值全部归类为 `indexeddb-internal-schema` / `app-constant-small`，无长 ID；D-06 文件级 A `249 文件 / 33,453,605 字节 / 0 命中`、B `203 文件 / 24,803,188 字节 / 0 命中`，请求级 `anthropic-device-id` / `anthropic-anonymous-id` / `x-activity-session-id` 哈希集合不相交。
- **部分证据（进程/网络，v2.8 收紧）**：`cuIsRemoteSession=false`、`getWindowsElevationType=default`；`readProcessTree` 返回 5 个根 / 40 节点、`readProcessFootprints` 返回 2 元素 / 4 节点，CAC/探针/注入器匹配数 0（bounded，仅这两个 API）；但 OS 层仍观察到 `cac-service-injector`（PID 27008），且命令行查询被拒绝访问。S-05 不能据此判 pass。R-01 记录 9 个目的地（`assets-proxy.anthropic.com`、`claude.ai`、`s-cdn.anthropic.com`、hCaptcha、Datadog、Sentry IPC 等），R-02 头集合含 `sec-ch-ua*`/`anthropic-client-*`，R-04 窗口内 `onBeforeRedirect=0`。
- **`config.json locale` 口径（v2.8 改判）**：A、B 文件均写 `en-US`，但 B 的 renderer/main/network 三面均为 `en-GB`。在未拿到源码级 `app-default` 证明前，新增 E-10 判 `unverified`；不能再用“不是 zh-CN”当作 pass。
- **网络姿态实测（2026-11-25T00:40Z）**：出口 `64.83.13.52`，`US`，`Los Angeles / LAX`，`AS979 NetLab Global`；DNS 为 `Meta 198.18.0.2` + `以太网 127.0.0.1`；`ProxyEnable=0` 但残留 `127.0.0.1:7897`；可见 `Meta Tunnel` 与两个 VMware 虚拟网卡。N-01 对 A 的 US persona 一致、对 B 的 GB persona 不一致；两个 Profile 共享同一出口 IP/ASN，本身就是跨 Profile 关联面。因用户明确暂缓 TUN+clean，N-01…N-04 记为 `unsupported:user-deferred-network-hiding`，不冒充 pass。
- **渲染层扩展（v2.8 收紧）**：B-08 A/B 的 WebGL 扩展集合完全相同（35 项），但这只证明 allowed-same，不证明与 persona GPU 参考基线一致；改为需要参考基线，缺基线时 `unverified`。E-09 A=`1,234,567.89 / Jan 2, 2020 / $1,234.50`，B=`1,234,567.89 / 2 Jan 2020 / US$1,234.50`。A-06 旧证据只有 `audioinput=0 / audiooutput=5 / videoinput=0`，但同一 `renderer-fingerprint` 记录 `label_present=5`；未验证标签内容，A-06 改判 `unverified`。B-02 两面均 `navigator.gpu` 存在但 `requestAdapter()=null`，判 `not-applicable`。
- **v2.8 新发现（运行时）**：A/B 主 frame 与 hCaptcha iframe 均读回 `navigator.maxTouchPoints=10`；persona 未声明触屏，新增 B-09 并判 `unverified`（若确认宿主触屏即 `fail`）。hCaptcha iframe 的 preload 已应用 persona（A `en-US`、B `en-GB`），E-07 需从“只查 hl”扩展为完整 iframe 面。
- **已闭合（生命周期）**：L-01 以 004437 运行窗口做 Profile 写窗审计，37 个修改文件全部为预期（config/Local State/Preferences/Cookies/LevelDB/Cache/Crashpad/sentry 等），unexpected=0；L-02 冷启动（全新 C Profile）与热启动（A Profile 连续 3 次）均到达登录页并产出 observer 记录。
- **R-03 边界（已判定）**：JSON 事件体的设备相关键只有 `events[0].event_data.app_version`、`platform`、`screen_equals_viewport`；另有 16,546 字节体，格式为 `x` + Z85，解码后 13,236 字节、熵 `7.9608`，gzip/brotli/deflate/inflateRaw/JSON 全部失败，判 `unsupported:opaque-high-entropy-payload`，无密钥不可继续。
- **R-05 部分证据（v2.8 改判）**：`fcache` = `CLF\x02` + gzip，A 缓存 602 features（216 开 / 357 关 / 29 非布尔，`force=133`、`defaultValue=469`，mode `1p`，无 orgUuid），B 缓存 599 features（216 开 / 354 关 / 29 非布尔，`force=133`、`defaultValue=466`）；时间戳分别为 `2026-11-24T16:48:19Z` / `16:43:39Z`，均在 24h 内。真实来源为 `/api/desktop/features` 的本地磁盘缓存；这是**未登录**快照，登录后必须重取，故 R-05 判 `unverified`。
- **长窗补充**：80 秒运行内无更新器/update 主机请求；`readProcessTree` resolve 64 节点、`readProcessFootprints` 4 节点，CAC 匹配仍为 0（仅限这两个 API；OS 层 `cac-service-injector` 仍可见）；`getHcsStatus` 仍未触发。
- **L-04 已闭合**：按 `renderer-mainworld` 的登录页 `senderRendererPid=17228` 精确杀 renderer；主进程存活，8 秒内新 renderer `13048` 出现并继续上报 `https://claude.ai/login`；Crashpad 文件数 1→1（无新增），新转储宿主画像标记命中 0。
- **A-05 边界**：静态 `queryLocalFonts=0`，仅见 `document.fonts.ready/load`，无字体枚举代码路径，判 `not-applicable:no-font-enumeration`。
- 其他未闭合（v2.8）：`getHcsStatus` 未触发（S-02）；`readProcessTree`/`readProcessFootprints` 之外的进程/命令行/环境枚举未覆盖（S-04/S-05 仅 bounded）；A-01/A-02/A-03 受 computer-use/file-dialog 触发门控；A-06 设备标签、B-08 GPU 参考基线、B-09 `maxTouchPoints`、E-10 持久化 locale、M-03 CPU/OS edition、M-04 环境块、M-05 路径净化、R-05 登录后快照、R-06 TelemetryEvent 元数据均未闭合；L-03 无账号、L-06 更新器未做；G1b 清点未开始。
- 当前资源：C `23.95 GiB` / D `38.83 GiB` / E `13.10 GiB` 可用；E 盘接近 `12 GiB` 下限，下一批次必须先清理受控副本与旧 `.tmp`。

### 9.1 v2.8 定向复核：新增检查点与旧 pass 的修正

本节只记录“冻结源可复现 + 运行时可观测”的新增/修正，不把 PnP、DDC、SMART、HID 重新拉回主线。

| 发现 | 冻结源证据 | 运行时/证据 | 处置 |
|---|---|---|---|
| 主进程 CPU 型号进入遥测 | `index-C5rj.js` `Odr()` 缓存 `os.cpus()[0]?.model`；`Rgr()` 的 TelemetryEvent 含 `cpu_model` | 现有请求头未出现；TelemetryEvent 真实体未捕获 | 新增 M-03，`unverified` |
| OS build/edition/revision 进入遥测 | `Rgr()` 含 `os_release` / `os_build` / `os_build_revision` / `os_edition`；`DesktopInfo.getSystemInfo` 含 `os_pretty_name` | 现有头只有 `anthropic-client-os-version` | 并入 M-03，`unverified` |
| 主进程环境块传给子进程 | `Gyt` 白名单 + `Kyt()`；用于 MCP node host、plugin env、frame-local worker | 未见 utility-node 实际读回 | 新增 M-04，`unverified`；required surfaces=main+utility-node+network |
| `custom3p_win_account` 由 `USERDOMAIN`/`COMPUTERNAME` 判定 | `X1n(process.env)` 在 custom-3p telemetry 中返回 `local/entra/domain` | 未见真实 telemetry 体 | 并入 M-04 |
| OS 用户名可作为 principal identity fallback | `Iu()` 读 `os.userInfo().username`；`LXe()` fallback 到 `source:"os"` | 未在真实请求/日志中取证 | 并入 M-04 |
| 日志/错误路径净化 | `qhe()` 注入 `appPath`/`homedir`；`$n`/`Oue` 将 appPath→`app://`、homedir→`<home>`、用户目录→`<user>` | 受控副本 shell page 为 `file:///E:/%E7%8E%AF...`；HTTPS 请求头只有 `https://claude.ai` referer | 新增 M-05，`unverified`；必须测 Claude 自身日志/Sentry |
| TelemetryEvent 元数据 | `Rgr()` 组装 `install_id`、`app_session_id`、`organization_id`、`total_memory`、`free_memory`、`available_memory`、`system_commit_*` 等 | 现有 R-03 body 为 opaque Z85；未逐字段解码 | 新增 R-06，`unverified`；R-03 仍 unsupported |
| 当前 `maxTouchPoints=10` | Chromium `navigator.maxTouchPoints` 由宿主/设备能力决定 | A/B 主 frame 与 hCaptcha iframe 均为 `10`；persona 未声明触屏 | 新增 B-09，`unverified`（若宿主触屏确认则 `fail`） |
| 音频设备标签存在 | `enumerateDevices` 在 A 主 frame 记录 `audiooutput=5`、`label_present=5` | 旧 A-06 只记录数量，未记录标签哈希 | A-06 改判 `unverified`；要求 label/groupId 哈希 |
| 持久化 locale 不一致 | B `config.json` 为 `en-US`，运行时三面为 `en-GB` | 旧口径记为 app-default allowed-same，无源码证明 | 新增 E-10，`unverified` |
| R-05 只有未登录快照 | GrowthBook `fcache` 可在登录后变化 | A/B 均为未登录状态 | R-05 从 pass 改判 `unverified`；必须 pre/post login |
| 跨 Profile 共享出口 | 网络姿态：A/B 同一 `64.83.13.52` / `AS979` / LAX | 两个 Profile 的请求均走同一出口 | 新增 N-06，`unsupported:user-deferred-network-hiding`；`anti_association_pass=false` |

**旧 pass 修正**：R-05（未登录快照）、A-06（仅数量）、B-08（A/B 相同不等于 persona GPU 参考基线）改判 `unverified`。其余 35 项 pass 不变；新增 6 项 unverified（M-03/M-04/M-05/E-10/B-09/R-06）与 1 项 unsupported（N-06），总数 60。最终计数：pass 35 / fail 0 / unverified 17 / unsupported 6 / not-applicable 2。

**仍属辅助、不得阻塞主线**：`Win32_PnPEntity`、`SetupDi*`、WMI 磁盘/BIOS、SMART/NVMe/ATA、DDC/EDID、raw HID、NVML/Vulkan/DXGI、MAC/GetAdapters、卷序列号/MachineGuid。它们只在 COA 记录“能力存在 + 零可达证据”；一旦真实 Claude 调用命中，才升级进 CRR。

### 9.2 v2.9 Sentry 实测：R-07 / B-09 判 fail

这不是静态推断，而是 Claude 自己写出的 Sentry 事件上下文：

| 证据 | A Profile | B Profile | persona 期望 |
|---|---|---|---|
| `contexts.device.memory_size` | `17179869184`（16 GiB） | `8589934592`（8 GiB） | A 16 / B 8，已同步 |
| `contexts.device.processor_count` | `24` | `24` | A 8 / B 12，**宿主泄漏** |
| `contexts.device.cpu_description` | `Intel(R) Xeon(R) CPU E5-2678 v3 @ 2.50GHz` | 同左 | A Intel UHD 630 机器 / B AMD RX 6600 机器，**宿主 CPU 泄漏** |
| `contexts.device.screen_resolution` | `1440x900` | `1440x900` | A 1920x1080 / B 2560x1440，**宿主屏幕泄漏** |
| `contexts.gpu_1.name` | `NVIDIA GeForce GTX 1050 Ti` | 同左 | A Intel UHD 630 / B AMD RX 6600，**宿主 GPU 泄漏** |
| `contexts.gpu_1.driver_version` | `31.0.15.2647` | 同左 | 与 persona GPU 不匹配，**宿主驱动泄漏** |
| `contexts.culture.locale` | `zh-CN` | `zh-CN` | A `en-US` / B `en-GB`，**宿主语言泄漏** |
| `contexts.culture.timezone` | `Asia/Shanghai` | `Asia/Shanghai` | A `America/New_York` / B `Europe/London`，**宿主时区泄漏** |
| `contexts.app.free_memory` | `23112859648` | `23182401536` | 动态宿主值；不作为稳定 ID，但必须登记 |

证据文件与哈希：

- A scope：`E:\环境\huanjing\.tmp\goal-v2-g5-persist-profile\home\AppData\Roaming\Claude\sentry\scope_v3.json`，9,020 bytes，SHA256 `0F315F15171EED0A6D716C9CAFAC09CCCD8B770F72D11EEBB42238CF0EB194DA`
- A queue event：`...\sentry\queue\ea09866bf36448649b6075eef69818f6`，10,030 bytes，SHA256 `B73E3789F7173C53826A4C44EE37A9B5C13321544C93B6B82A1235B9C22FCDB8`
- B scope：`E:\环境\huanjing\.tmp\goal-v2-g5-b-profile\home\AppData\Roaming\Claude\sentry\scope_v3.json`，8,248 bytes，SHA256 `B0D10941642D3D63E66F3FDFDC07131712DFEB5990EE828BFDDCD7DB10F92794`

判定：

- `R-07`（新增）= `fail`：Sentry 事件上下文已含宿主 CPU/processor_count/screen/GPU/driver/culture，A/B 均存在。
- `B-09` = `fail`：A/B 主 frame 与 hCaptcha iframe 均 `maxTouchPoints=10`，persona 未声明触屏。
- `M-03` 仍 `unverified`：Sentry 不是 `getSystemInfo`/TelemetryEvent 的同一 sink；CPU 泄漏由 R-07 关闭，但 M-03 仍需主进程读回 + TelemetryEvent 真实体。
- `M-05` 仍 `unverified`：Sentry breadcrumb 已显示 `app://`（路径净化有效），但 Claude 日志/错误栈尚未全量取证。

- v2.9 计数（历史快照）：CRR 61 项，pass 35 / fail 2 / unverified 16 / unsupported 6 / not-applicable 2。

### 9.3 v2.10 修订：B-09 待复验、R-07 部分收敛但仍 fail

本修订不新增 CRR 项，只把“代码已改”和“运行时已证明”分开：

| 项 | 当前证据 | 判定 |
|---|---|---|
| B-09 | `goal-v2-g5a-personaa2-20261125-011615`：A 的 mainworld、preload、hCaptcha challenge/checkbox iframe 均读回 `maxTouchPoints=0`；旧 `renderer-fingerprint` 的 `null` 来自修复前代码 | `unverified`，B 未复跑且 fingerprint 新行未取到；不得判 pass |
| R-07 device CPU/内存 | A 最新 `scope_v3.json`：`processor_count=8`、`cpu_description=Intel(R) Core(TM) i7-9700T CPU @ 2.00GHz`、`memory_size=17179869184`、`free_memory=8589934592` | CPU/内存子面已随 hook 收敛；不关闭其他字段 |
| R-07 screen | A 最新 scope：`screen_resolution=1440x900` | 宿主值，`fail` 条件仍存在 |
| R-07 culture | A 最新 scope：`culture.locale=zh-CN`、`culture.timezone=Asia/Shanghai` | 宿主值，`fail` 条件仍存在 |
| R-07 GPU | A 最新 scope：`gpu_1.name=NVIDIA GeForce GTX 1050 Ti`、`driver_version=31.0.15.2647` | 宿主值，`fail` 条件仍存在 |
| R-07 B | B `scope_v3.json` 仍为 `processor_count=24`、Xeon E5-2678 v3、1440x900、GTX 1050 Ti、zh-CN/Asia/Shanghai | B 未复跑，旧 fail 证据仍有效 |

最新 A scope 证据：`E:\环境\huanjing\.tmp\goal-v2-g5-persist-profile\home\AppData\Roaming\Claude\sentry\scope_v3.json`，8,098 bytes，SHA256 `98B600C15A8F4289AA04A534B13A5F4660D249B071CA9F6C2B324DD9CDCAF659`。该文件是 Sentry scope 快照，**不能**证明 `addEventProcessor` 已作用于最终 queue/HTTP body；R-07 的最终验收必须另取 queue event 或 sentry-ipc body。

因此 v2.10 计数为：CRR 61 项，pass 35 / fail 1（R-07）/ unverified 17（B-09 加入）/ unsupported 6 / not-applicable 2。`device_image_subset_pass`、`supported_subset_pass`、`full_coverage_within_declared_scope`、`anti_association_pass`、`functional_pass` 全部仍为 false。

### 9.4 v2.11 复验：B-09 / R-07 关闭

本轮不是静态推断，而是 A/B 各一次真实 Claude 运行 + 各一次受控 renderer crash：

| 项 | A | B | 判定 |
|---|---|---|---|
| `maxTouchPoints`（mainworld/preload/fingerprint） | `0` / `0` / `0` | `0` / `0` / `0` | `B-09=pass` |
| Sentry scope `device` | `8 / i7-9700T / 2000 MHz / 16 GiB` | `12 / Ryzen 5 5600X / 3700 MHz / 8 GiB` | persona 一致 |
| Sentry scope `screen_resolution` | `1920x1080` | `2560x1440` | persona 一致 |
| Sentry scope `culture` | `en-US / America/New_York` | `en-GB / Europe/London` | persona 一致 |
| Sentry scope `gpu_1` | `Intel UHD 630 / 27.20.100.9316` | `AMD RX 6600 / 31.0.12027.9001` | persona 一致 |
| 真实 crash queue envelope | 同 persona；host Xeon/GTX 1050 Ti/1440x900/zh-CN/Asia/Shanghai 0 命中 | 同 persona；host 值 0 命中 | `R-07=pass` |

关键实现：

- main 进程补 `os.cpus/totalmem/freemem`、`app.getGPUInfo`、`Intl.DateTimeFormat.resolvedOptions`、`Date.getTimezoneOffset`、`process.env.TZ`。
- 在 `scope_v3.json` 的 `fs.promises.writeFile` 路径做 device/culture/GPU 的写入净化；`boot_time` 删除。
- 对 `AdditionalContext` / `Context` / `GpuContext` 安装 integration 级 sanitizer，并用真实 crash envelope 验证最终 queue body。
- `maxTouchPoints` 已在 renderer preload + mainworld 双面应用；A/B hCaptcha 子 frame 均覆盖。

证据：`native/evidence/claude-coverage/goal-v2-r07b09-20261125-0139/`（含 `a-scope.json`、`a-queue-event.envelope`、`b-scope.json`、`b-queue-event.envelope`、`verification.json`、`max-touch-points.json`）。A queue SHA256 `582518A7297830DC9970E31E8235A7C4D6AAD43A8BBE53CF6AE5C99A02F66DB3`；B queue SHA256 `0E029022BE5734290516B928EC79A53307121A34888B436BB00D23D6F87EA0B9`。

v2.11 计数：CRR 61 项，pass 37 / fail 0 / unverified 16 / unsupported 6 / not-applicable 2。`device_image_subset_pass=false` 仍因 M/E/B/D/S/A 的 12 项 unverified（不是 R-07/B-09），另有 L-03/L-06/R-05/R-06。

### 9.5 v2.12 修订：M-05 代码落地、闭合规则与批次预算（v2.12 快照；M-05 已于 v2.13 关闭）

本修订不改变计数，只把当前工作状态与收敛方式写清楚：

| 项 | 当前状态 | 说明 |
|---|---|---|
| M-05 | `unverified`（code-landed） | `scripts/main-persona-hook.js` 新增 `installMainLogSanitizer()`：包装 `fs.createWriteStream`，对 `main*.log` 写入做 `...app/resources/app.asar`→`app://`、`E:\环境\huanjing…`→`<workspace>`、`C:\Users\…`→`<user>` 替换；`node --check` 通过。尚未在新 A/B 批次复验，不能判 pass。 |
| 旧日志基线 | 84 处命中 | `goal-v2-m05-log-baseline-20261125-0142/baseline.json`；全部来自 `goal-v2-*-copy` 历史受控副本路径，不是当前出站泄漏，也不能作为新批次 pass 依据。 |
| B-09 / R-07 | `pass` | 维持 v2.11 结论与证据（`goal-v2-r07b09-20261125-0139`）。 |
| 其余 15 项 | `unverified` | S-02、S-04、S-05、A-01、A-02、A-03、A-06、B-08、E-10、L-03、L-06、M-03、M-04、R-05、R-06。 |

新增的 0.2 闭合规则用于防止三种旧问题：同一项无限复跑、每项单独起批次导致磁盘打满、`unverified` 无限期挂在交付清单里。P1b 的验收以“一次 A/B 批次同时覆盖多项”为准；具体触发方式仍须来自 Claude 真实调用，不能用探针自证。

### 9.6 v2.13 复验：M-05 关闭

本轮执行 A/B 各一次真实 Claude 冷启动（`goal-v2-p1b-a-20261125-0207`、`goal-v2-p1b-b-20261125-0211`），并先记录旧 `main.log` 基线（A 69 处 / B 15 处，共 84 处历史副本路径）：

| 面 | A | B | 判定 |
|---|---|---|---|
| 新增日志行 | 679 行 | 679 行 | 同一批次各一次冷启动 |
| `E:\环境\huanjing` / 盘符路径 / `app.asar` / `C:\Users` | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 无宿主路径 |
| 净化后 `app://` | 3 行 | 3 行 | sanitizer 实际生效 |
| Sentry 目录（4 文件）`file:///` / `%E7%8E%AF` / 宿主路径 | 0 / 0 / 0 | 0 / 0 / 0 | 负向面通过 |
| HTTPS 请求头 `file:///` / `%E7%8E%AF` | 0 / 0 | 0 / 0 | 原始 shell page 未出站 |
| 跨 Profile ant-did | 0 | 0 | 无交叉泄漏 |

实现上，`installMainLogSanitizer()` 从只包 `createWriteStream` 扩展为同时包 `appendFileSync` / `appendFile` / `writeFileSync` / `writeFile` / `fs.promises.appendFile` / `fs.promises.writeFile`，只对 basename 匹配 `main*.log` 的目标生效；`node --check` 通过。证据：`native/evidence/claude-coverage/goal-v2-m05-verification-20261125-0216/verification.json`。

同批回归：A/B 的 `anthropic-client-device-class` 仍为 16/8、`anthropic-client-total-memory-gb` 仍为 16/8、`accept-language` 仍为 en-US/en-GB；A/B Sentry scope 仍为 persona CPU/内存/屏幕/GPU/culture，R-07 未回退。

同批未触发（保持 `unverified`，不冒充通过）：`getHcsStatus`、`getSystemInfo`、`readProcessTree`/`readProcessFootprints` 在 20 秒登录页窗口内均 0 命中；A-06 仍只有 `audiooutput=5 / label_present=5`，没有 label/groupId 哈希；L-06 更新器需要长窗。上述项按 0.2 记录 blocker，不计 pass。

资源：按 `summary-only` 保留策略删除 53 个已完成批次的 `kernel-non-circular.etl`（每个父目录均有 JSON 摘要、当前契约 0 引用、无 fail 标记），释放 9.089 GiB；E 盘 13.10 → 22.01 GiB。清单：`native/evidence/claude-coverage/retention-etl-cleanup-20261125-0200/cleanup-manifest.json`。

v2.13 计数：CRR 61 项，pass 38 / fail 0 / unverified 15 / unsupported 6 / not-applicable 2。

### 9.7 v2.14 复验：A-06 音频标签 fail→pass

这不是“数量相同”的推断，而是 A/B 两次真实运行的 label 哈希对比：

| 面 | 基线（v2.13） | 修复后（v2.14） |
|---|---|---|
| A 设备 | 5 个 audiooutput，5 个非空 label | 5 个 audiooutput，`label_present=0` |
| B 设备 | 5 个 audiooutput，5 个非空 label | 5 个 audiooutput，`label_present=0` |
| label 哈希集合 | A/B 完全相同（5 个） | A/B 均为空 |
| label 长度 | 44/51/53/43/34 | 无 |
| groupId 哈希 | A/B 各 3 个唯一值，跨 Profile 不同 | 仅 SHA256(空串)，无可关联值 |
| 登录页 | 到达 | 到达（51 次 login 引用，remaining=0） |

修复点：`applyPersona()` 在 persona 未声明 `audioDevices` 时，保留原设备数量与 `kind`，把 `deviceId`/`groupId`/`label` 清空；不伪造不存在的硬件。基线证据：`goal-v2-a06-a-20261125-0220`、`goal-v2-a06-b-20261125-0222`；修复证据：`goal-v2-a06fix-a-20261125-0206`、`goal-v2-a06fix-b-20261125-0208`；汇总：`native/evidence/claude-coverage/goal-v2-a06-verification-20261125-0210/verification.json`。

v2.14 计数：CRR 61 项，pass 39 / fail 0 / unverified 14 / unsupported 6 / not-applicable 2。

### 9.8 v2.15 冻结源闭合：E-10 持久化 locale

本项不靠“文件不是 zh-CN”推断，而是从冻结 `app.asar` 取到完整写入链：

| 锚点 | 偏移 | 语义 |
|---|---|---|
| `V_="en-US"` | 12,586,835 | 默认 locale 常量 |
| `_o.set("locale",t)` | 12,588,449 | `gFt()` 持久化 locale |
| `_o.get("locale")` | 12,588,678 | `_Ft()` 启动读取 locale |
| `dFt()` | 同窗口 | `app.getPreferredSystemLanguages()` → `app.getLocale()` → catalog → 回退 `V_` |
| `_o=FEe()` | 11,379,105 | 配置存储实例；同模块含 `Opening config.json failed` |

运行值：宿主 `zh-CN` / `zh-Hans-CN`；A/B `config.json` 均为 `en-US`；main/renderer/network 三面 A=`en-US`、B=`en-GB`。因此 B 的文件/运行时差异是 app-default 与 per-launch persona 的差异，不是宿主泄漏。源码窗口与哈希：`native/evidence/claude-coverage/goal-v2-e10-verification-20261125-0215/source-locale-window.txt`（SHA256 `7084760EDE6E45334AA53BD8A6914CEAFEE3AD43EAD98FF59A30B43153E6B2B4`）。

v2.15 计数：CRR 61 项，pass 40 / fail 0 / unverified 13 / unsupported 6 / not-applicable 2。

### 9.9 v2.16 边界：B-08 WebGL 扩展基线

- A/B 扩展集合：35 项，SHA256 均为 `0D881644BA4D80299928CBD6A557797BE8323711CF2AF9E990D24085FA89F78C`；只证明 allowed-same。
- persona 参考：A=`Intel UHD 630 / 27.20.100.9316`，B=`AMD RX 6600 / 31.0.12027.9001`；工作区没有对应真机，也没有厂商 ANGLE 扩展表。宿主 `GTX 1050 Ti` 基线不是 persona 基线，不能替代。
- 终态：`unsupported:persona-gpu-reference-unavailable`，带复现与关闭条件（拿到同驱动真机或厂商表后重开）。证据：`native/evidence/claude-coverage/goal-v2-b08-verification-20261125-0222/verification.json`。

v2.16 计数：CRR 61 项，pass 40 / fail 0 / unverified 12 / unsupported 7 / not-applicable 2。

### 9.10 v2.17 边界：L-06 更新器

- 运行：`goal-v2-l06-115-20261125-0229`，Persona A，115 秒窗口（覆盖 60 秒静默检查），PID 7204，remaining=0，copy cleaned=true，network unchanged=true。
- 日志：新增 712 行，其中 1 行 `[updater] App is not installed, not enabling auto-updates`；无 `Checking for updates`、无 update 主机请求。
- 静态事件：`desktop_update_available`（current_version/update_channel/target_version）、`desktop_update_not_available`（is_manual/current_version/update_channel）、`desktop_updater_state`（current_version/update_channel/install_method）；无 CPU/内存/主机名/MAC/卷字段。
- 终态：`unsupported:updater-disabled-in-controlled-copy`。受控副本不是已安装 MSIX，真正 updater 只能在已安装包中运行。证据：`native/evidence/claude-coverage/goal-v2-l06-verification-20261125-0232/verification.json`。

v2.17 计数：CRR 61 项，pass 40 / fail 0 / unverified 11 / unsupported 8 / not-applicable 2。

### 9.11 v2.18 关闭：S-04 进程谱系/命令行

| 面 | bare（`goal-v2-bare-115-20261125-0242`） | injected（`goal-v2-s04s05-115-20261125-0237`） |
|---|---|---|
| persona | 无（renderer `zh-CN / hc24 / dm32 / 1440x900`） | A |
| `readProcessTree` | 64 节点；`pid,parentPid,workingSetBytes,privateWorkingSetBytes,commitBytes,cpuSeconds,creationTime` | 64 节点；同一字段集（两次调用） |
| `readProcessFootprints` | 4 节点；`footprintBytes,commitBytes,creationTime` | 4 节点；同一字段集（两次调用） |
| name/path/cmdline/env | 无 | 无 |
| `path_like` / `extended_flag` / `matched` | 0 / 0 / 0 | 0 / 0 / 0 |

结论：这两个 API 只返回数值字段，不返回进程名、路径、命令行或环境块；`readProcessTree`/`readProcessFootprints` 之外没有其他进程枚举调用。S-04 判 `pass`。

S-05 仍为 `unverified`：主进程 `process.env` 仍含 `CAC_*`，直接 env 枚举未被排除；不因 S-04 通过而一并判过。证据：`native/evidence/claude-coverage/goal-v2-s04-verification-20261125-0246/verification.json`。

v2.18 计数：CRR 61 项，pass 41 / fail 0 / unverified 10 / unsupported 8 / not-applicable 2。

### 9.12 v2.19：S-05 env 修复与 harness 边界

- 修复：`main-persona-hook.js` 新增 `installEnvSanitizer()`，在主 hook 安装完成后用 Proxy 替换 `process.env`，隐藏 `/^CAC_/` 键。A 运行 `goal-v2-envsan-a-20261125-0255` 读回 `env-sanitizer-armed`、`visible_cac_keys=0`。
- 回归：main persona（totalmem 16 GiB / cpus 8 / en-US）、preload persona、`https://claude.ai/login`（51 次引用）、`anthropic-client-device-class=16` / `total-memory-gb=16` / `accept-language=en-US` 全部正常；请求头 `CAC_` 0。
- 进程面：S-04 的 `readProcessTree`/`readProcessFootprints` 只返回数值字段；renderer payload 无 `argv`/`execPath`。
- 边界：受控副本从 `.tmp\goal-v2-*-copy` 启动，`process.execPath`/`process.argv` 含 harness 路径；Claude 读 argv 做 flag/relaunch，因此 S-05 记 `unsupported:controlled-copy-path-in-argv`。关闭条件：从中性路径（junction/subst 或已安装 MSIX）运行同一观察器。
- 证据：`native/evidence/claude-coverage/goal-v2-s05-verification-20261125-0258/verification.json`。

v2.19 计数：CRR 61 项，pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2。

### 9.13 v2.20：G1b 清点 partial

本轮只做只读清点，不启动 Claude、不改网络：

| 账本 | 总数 | closed | partial | open | false-positive | boundary |
|---|---:|---:|---:|---:|---:|---:|
| 未归类观察 | 77 | 22 | 38 | 14 | 1 | 2 |
| 动态边 | 373 | 1（`process-dlopen`） | 372（remote-fetch 330、wasm 12、dynamic-require 5、dynamic-import 25） | 0 | 0 | 0 |

- 22 条 closed 的依据是当前 CRR/运行时证据：独立 observer、first-read/first-document、pid+creation time、file/registry、positive control、delayed flush、renderer facets、persistence sink、runtime lock 等。
- 38 条 partial 主要是：动态加载图、source-to-sink、process/ETW 生命周期、network sink、observer effect、provenance/module hash。
- 14 条 open 主要是：PE resource tree、非 app 文件处置、optional hook refusals、async device IO、CPU flags、route error、G6/G7 交付链。
- 仍未闭合：1919 条 retained-but-not-CRR 行逐项理由、PE resource tree 逐节点、非 app 包文件逐文件 disposition。故 G1b=`partial`，不判 pass。
- 证据：`native/evidence/claude-coverage/g1b-disposition-20261125-0310/g1b-disposition.json`、`g1b-summary.md`。

v2.20 计数不变：CRR 61 项，pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2。

### 9.14 v2.21：G1b PE resource tree 关闭

只读解析 19 个 PE 文件（`resource-inventory.json` 的 `pe[]`，根为 `app_root`）：

| 指标 | 值 |
|---|---:|
| PE 文件 | 19 |
| 有资源 | 9 |
| 无资源（合法 no-resources） | 10 |
| 解析失败 | 0 |
| 资源叶 | 73 |
| `claude.exe` 资源 | 62（CURSOR 23、GROUP_CURSOR 21、ICON 14、GROUP_ICON 1、MANIFEST 1、VERSION 1、INTEGRITY 1） |
| `claude.exe` 空哈希 | 0 |
| `claude-native-binding.node` | no-resources |

每个资源叶记录 type/name/language/RVA/file offset/size/SHA256。`claude.exe` 的 MANIFEST=`2545F65A…`、VERSION=`8D446554…`、INTEGRITY=`4DF8F577…`。该项从 G1b open 移到 closed；非 app 包文件逐文件 disposition 与 1919 条 retained-but-not-CRR 行仍未闭合，G1b 仍为 `partial`。证据：`native/evidence/claude-coverage/g1b-pe-resources-20261125-0320/pe-resource-tree.json`、`g1b-pe-closure-20261125-0322/closure.json`。

v2.21 计数不变：CRR 61 项，pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2。

### 9.15 v2.22：G1b 非 app 包文件关闭

78 个非 app 包文件逐文件落 disposition：

| 类型 | 数量 | 解析/理由 |
|---|---:|---|
| MSIX manifest | 1 | `AppxManifest.xml`，regex-xml 取 Identity/Version/Architecture/Application/Capability |
| MSIX blockmap | 1 | `AppxBlockMap.xml`，regex-xml 取 File/Block 数 |
| Signature blob | 1 | `AppxSignature.p7x`，PKCS7 签名，非 app 行为 |
| Build template | 1 | `assets/AppxManifest.xml.in`，构建期模板 |
| PNG visual assets | 68 | 读取 IHDR 宽高，MSIX tile/icon |
| PRI config | 1 | `priconfig.xml`，regex-xml 取 targetOsVersion |
| PRI resource index | 5 | `resources*.pri`，二进制本地化索引 |

`unknown=0`、`scan_errors=0`。该项从 G1b open 移到 closed；G1b 观察 disposition 更新为 closed 24 / open 12。仍有 1919 条 retained-but-not-CRR 行未逐项处置，且 12 条 open / 38 条 partial 尚未清零。证据：`native/evidence/claude-coverage/g1b-nonapp-20261125-0330/nonapp-disposition.json`。

v2.22 计数不变：CRR 61 项，pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2。

### 9.16 v2.23：目标修订（范围收敛）

本修订不改变任何 CRR 状态，只改变“接下来做什么”的定义：

| 项目 | v2.22 及以前 | v2.23 |
|---|---|---|
| 主线范围 | 设备画像 + 仍保留 COA 待办 | 只做 CRR 61；COA 10 项归档，不再新增探针 |
| PnP / DDC / SMART / NVMe / ATA / raw HID / 音频端点 / NVML / Vulkan / DXGI / MAC / 卷序列号 | 作为“未来可补”的辅助面 | 明确 `archived`，不阻塞、不计 pass、不再投入主线工时 |
| 音频 | A-06 与音频端点 ID 混在一起 | 只保留 A-06（Claude 真实调用 `enumerateDevices`，已 pass）；端点 ID 归档 |
| 剩余主线 | 分散在 P1a/P1b/P2/P3 | P1b 单批（M-03/M-04/S-02/A-01…A-03）→ P2 外部输入（L-03/R-05/R-06）→ P3 G1b/G5c/G6/G7/G8 |
| 完成口径 | `device_image_subset_pass` 与 `full_coverage` 容易混读 | 主交付固定为 `device_image_subset_pass`；`full_coverage` 另要求 G1b+G7+required unsupported=0；`anti_association` 仍因共享出口为 false |

当前计数不变：CRR 61 项，pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2。`device_image_subset_pass`、`supported_subset_pass`、`full_coverage_within_declared_scope`、`anti_association_pass`、`functional_pass` 全部为 false。

### 9.17 v2.24：P1b 被登录页否证，九项 unverified 全部落 blocker

本轮对 Persona A 做了真实 Claude 运行（`goal-v2-p1b-cowork-ui-a-20261125-0250`），由 main-process hook 在渲染层执行“把路由导航到 `/cowork`，再尝试点击 Feedback”的 UI 动作。结果：

| 观察 | 实际值 |
|---|---|
| 导航后的 URL | `https://claude.ai/cowork` |
| 页面标题 | `Sign in or create an account \| Claude.ai` |
| 页面主体 | `Claude for Windows The fastest way to talk with Claude Get started` |
| `getHcsStatus` 调用 | 0 |
| `getSystemInfo` 调用 | 0 |
| `cuListInstalledApps` 调用 | 0 |
| `cuListRunningApps` 调用 | 0 |
| `enumerateNetworkDrives` 调用 | 0 |
| utility-node / nodehost 文件 | 不存在 |
| 同批 `cuIsRemoteSession` | 1 次，`false` |
| 网络摘要 before/after | 相同，未改宿主 |
| 原始 MSIX | 未修改 |

因此 P1b 的前提“未登录页面可以触发 Cowork/computer-use/settings”不成立。九个 `unverified` 的 blocker 固定为：

| ID | blocker_class | 缺什么 |
|---|---|---|
| S-02 | `blocked-external-input` | 已登录 Claude 会话 / Cowork 面 |
| M-03 | `blocked-external-input` | 已登录 Claude 会话 / CoworkFeedback 或 DesktopInfo 面 |
| M-04 | `blocked-external-input` | 已登录会话，或该 Profile 真正拉起的 MCP extension |
| A-01 | `blocked-external-input` | 已登录 Claude 会话 / computer-use 工具调用 |
| A-02 | `blocked-external-input` | 已登录 Claude 会话 / computer-use 工具调用 |
| A-03 | `blocked-external-input` | 已登录 Claude 会话 / computer-use 或网络盘路径 |
| L-03 | `blocked-external-input` | 真实测试账号（登录/登出/重登/换号） |
| R-05 | `blocked-external-input` | 登录后的远端开关快照 |
| R-06 | `blocked-external-input` | telemetry credential / 真实 TelemetryEvent |

尝试记录（均为真实运行，不冒充目标调用）：

1. `goal-v2-p1b-cowork-a-20261125-0245`：命令行 `--remote-debugging-port=9222`，Claude 拒绝启动（`refusing to start — a debugging or network-override switch is present`）。
2. `goal-v2-p1b-cowork-a2-20261125-0247`：`CAC_COPY_REMOTE_DEBUGGING_IN_PROCESS=1`，CDP 端口未打开；无目标调用。
3. `goal-v2-p1b-cowork-ui-a-20261125-0250`：主进程 `executeJavaScript` 导航到 `/cowork`，仍是登录页；5 个目标 API 全 0。

证据：`native/evidence/claude-coverage/goal-v2-p1b-cowork-ui-a-20261125-0250/p1b-verification.json`（含 `main-persona.jsonl`、`native-call-audit.jsonl`、`renderer-mainworld.jsonl`、`request-headers.jsonl`、network before/after 的 SHA256）。

后续规则：没有真实登录态时，S-02/M-03/M-04/A-01…A-03 不再重试；不再用 pushState、点击 Feedback、CDP 或 shim 直接调用绕过登录页。可推进的非账号工作只剩 G1b、G5c 的非登录部分、G6、G7、G8。计数不变：CRR 61 项，pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2；五个完成判定仍全部为 false。

### 9.18 v2.25：G1b 1919 条 retained 行关闭

本轮只做静态清点，不启动 Claude、不改网络：

| 指标 | 值 |
|---|---:|
| source-to-sink 总记录 | 6332 |
| retained（过滤后） | 5509 |
| retained-but-not-CRR | 1919 |
| 关键词 | 54 |
| 类别 | 32 |
| `unknown` | 0 |
| 每行字段 | `keyword`、`file`、`file_class`、`first_offset`、`count`、`category`、`crr_anchor`、`reason` |

过滤规则与旧 G1b 保留集一致：Chromium 引擎资源、bundled helper、Go/Rust 同计数符号簇、`.asar/.js` 中的 `hostname` URL 属性，以及已经进入 CRR 的显式关键词不进入这个 retained 账本。逐行处置把大部分行锚到已有 CRR，而不是新增检查点：

| 类别 | 行数 | 处置 |
|---|---:|---|
| `product-plugin-surface` | 637 | 插件/Chromium plugin 字符串；不是设备读取 |
| `no-signal-file-entry` | 366 | 无关键词的 asar/JS 文件条目；文件级清点 |
| `bundled-mcp-surface` | 314 | bundled MCP server/UI 字符串；不是设备读取 |
| `platform-security-text` | 64 |  attestation / Windows Hello / LogonUI / ProfileList；平台安全边界 |
| `device-id-alias` | 63 | `ant-did`、`installation_id`、`bound_device_id`、`machine_name`、`anonymous_id`、`anthropic-device-id` → D-01/D-02/D-06/R-06 |
| `tool-command-template` | 60 | 终端/MCP 命令模板 |
| `transport-alias` | 48 | XMLHttpRequest/EventSource → R-01/R-02/R-04 |
| `storage-alias` | 44 | IndexedDB/CacheStorage/serviceWorker/Local State/Network Persistent State → D-02/D-03 |

验证：`validation.json` 检查 1919 行、`unknown=0`、ID 唯一、每行有 category 和 reason；并按 `category|file_class` 给出分布和每类 3 个样本。原始账本、摘要、验证的 SHA256 记录在 `g1b-closure-20261125-0255/closure.json`。

G1b 仍为 `partial`：372 条动态边（remote-fetch 330、wasm 12、dynamic-require 5、dynamic-import 25）没有逐边 source/sink 闭合；12 open / 38 partial 观察仍未清零（optional hook refusals、async device IO、CPU flags、route error、G6/G7 未开始）。本次不改变 CRR 状态：pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2；五个完成判定仍全部为 false。

### 9.19 v2.26：G1b 373 条动态边关闭

`dynamic-load-graph.json` 的 `unresolved_dynamic_candidates` 是逐条记录（kind/path/sha256/first_offset/static_only），不是只有计数。本轮逐条处置：

| kind | 行数 | 处置 |
|---|---:|---|
| `remote-fetch` | 330 | 静态 fetch 候选，不是设备字段 sink；运行时目的地/请求头/重定向/远端开关由 R-01/R-02/R-04/R-05 覆盖 |
| `webassembly-load` | 12 | WASM 代码加载；没有关联设备 sink |
| `dynamic-require-expression` | 5 | 计算式 CommonJS 模块路径；代码加载 |
| `dynamic-import-expression` | 25 | 计算式 ESM import 路径；代码加载 |
| `process-dlopen` | 1 | 原生绑定加载；由 S-06/D-04 关闭 |

每行在 `dynamic-disposition.json` 中有 `id`、`kind`、`path`、`sha256`、`first_offset`、`static_only`、`category`、`crr_anchor`、`reason`。`validation.json` 检查 373 行、ID 唯一、`unknown=0`、所有行有 category/reason、全部 `static_only=true`。

这关闭的是 **动态边的清点账本**，不是把运行时 `G2-REMOTE-CONTENT` 观察判 pass；后者仍在 12 open / 38 partial 观察里。G1b 仍为 `partial`：只剩 12 open / 38 partial 观察（optional hook refusals、async device IO、CPU flags、route error、G6/G7 未开始）。本次不改变 CRR 状态：pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2；五个完成判定仍全部为 false。

### 9.20 v2.27：G8 COA 归档关闭

10 项 COA 全部归档。每项包含：

- capability probe（`native/dist/cac-*-probe.exe` 的存在性与 SHA256）
- 代表证据（`native/evidence/*` 的 result/log）
- 核心文件精确词扫描（`claude.exe`、`app.asar`、`ion-dist.asar`、`claude-native-binding.node`）
- 真实运行 `native-call-audit.jsonl` 的运行时调用计数
- `reachability`、`blocking`、`status`

| ID | 能力 | 运行时调用 | 归档 |
|---|---|---:|---|
| COA-01 | PnP device graph / Win32_PnPEntity | 0 | `none-observed` |
| COA-02 | SetupDi device properties | 0 | `none-observed` |
| COA-03 | WMI disk/BIOS/board/serial | 0 | `none-observed` |
| COA-04 | SMART / NVMe / ATA identify | 0 | `none-observed` |
| COA-05 | DDC/CI / EDID | 0 | `none-observed` |
| COA-06 | raw HID report descriptor | 0 | `none-observed` |
| COA-07 | audio endpoint identifiers | 0 | `none-observed` |
| COA-08 | NVML / Vulkan / DXGI | 0 | `none-observed` |
| COA-09 | MAC / NIC list | 0 | `none-observed` |
| COA-10 | volume serial / MachineGuid | 0 | `none-observed` |

注意：静态词扫描有命中（例如 `SetupDi` 29、`Vulkan` 294、`DXGI` 139）不等于 Claude 运行时读取。它们来自 PE/引擎/打包字符串，`native-call-audit` 中对应导出调用为 0。任何未来 Claude 可达的 COA 命中必须升级进 CRR 并重开对应门。

验证：`coa-archive.json` 10 项、`capability_present=true`、`evidence_present=true`、`all_runtime_calls_zero=true`、`unknown=0`、全部 `blocking=false`；`validation.json` 的检查全部为 true。`auxiliary_documented=true`，G8=`pass`。本次不改变 CRR 状态：pass 41 / fail 0 / unverified 9 / unsupported 9 / not-applicable 2；`device_image_subset_pass`、`supported_subset_pass`、`full_coverage_within_declared_scope`、`anti_association_pass`、`functional_pass` 仍为 false。

### 9.21 v2.28：G7 独立复核通过

复核脚本不信任 `status_counts` 汇总，直接从 61 项原账本重算：

| 检查 | 结果 |
|---|---|
| MD/JSON 哈希绑定 | true |
| CRR 总数 = 61、ID 唯一 | true |
| 分组 N6/E10/D6/S6/A6/B9/R7/L6/M5，合计 61 | true |
| 重算状态 41 pass / 0 fail / 9 unverified / 9 unsupported / 2 N/A | true |
| pass 集合与 `confirmed_pass` 一致 | true |
| 9 个 unverified 全部有 `blocked-external-input` + missing | true |
| 9 个 unsupported 全部有边界说明 | true |
| 2 个 N/A 的 status 为 null | true |
| pass 与 unsupported/unverified 无交集 | true |
| 没有 not-evaluated | true |
| 完成判定诚实（auxiliary=true，其余五个 false） | true |
| G8 = pass，10 项 capability/evidence/runtime-zero/unknown=0 | true |
| G1b = 1919 retained + 373 dynamic closed，12 open / 38 partial | true |
| P1b 目标 native 调用全 0，utility-node 不存在 | true |
| 关键证据路径全部存在 | true |
| 分母未缩小 | true |

证据：`native/evidence/claude-coverage/g7-review-20261125-0258/g7-review.json`。G7=`pass` 表示“分母、状态、边界、证据路径的独立重算通过”，**不表示 CRR 闭合**；`device_image_subset_pass`、`supported_subset_pass`、`full_coverage_within_declared_scope`、`anti_association_pass`、`functional_pass` 仍为 false。

### 9.22 v2.29：目标文本对齐与剩余路线重排

v2.29 是**契约维护修订**，不改变 CRR 状态，不新增证据。它解决三件事：

1. 目标栏旧文本仍绑定 `2026-11-24.1` / CRR 51 项；v2.29 明确权威分母为 CRR 61 项，旧目标文本作废但不删除。
2. `0.1` 表和 `P3` 仍写着“1919 条 retained 行未处置”；实际 v2.25 已关闭 1919 行、v2.26 已关闭 373 条动态边。v2.29 更正为“只剩 12 open / 38 partial 观察”，避免把已完成工作重复计入。
3. G1b 旧文字仍含“G7 未开始”；G7 已于 v2.28 pass。v2.29 更正，并把 G6/G5c 的验收口径与批次上限写入 `0.4`。

不变项：CRR 61 = 41 pass / 0 fail / 9 unverified / 9 unsupported / 2 N/A；G0/G1/G7/G8 pass；G1b partial；G6/G5c not_started；五个完成判定仍为 false。九项 unverified 仍全部是 `blocked-external-input`。

### 9.23 v2.30：G6 交付与回滚闭合

G6 已用当前 v2.30 契约绑定重新取证，**不是复用 2026-11-23.1 的历史结论**：

| 链路 | 结果 | 证据 |
|---|---|---|
| 源码/配置/工具链→构建 | 164 sources、31 artifacts、17 project inputs 全部哈希匹配；35 条编译命令的 85 条输入/输出路径全部可按工作区后缀解析，`unresolved=0`、`sha_mismatch=0`；31 个 artifact 均出现在命令输出中；MSVC 14.44.35207 / SDK 10.0.26100.0 路径存在 | `g6-delivery-v230-20261125-0341-final/g6-delivery.json` |
| 构建→打包 | `npm pack` 生成 `cac-windows-1.0.44.tgz`（3,505,747 bytes，SHA256 `7F721D2FA8DAEA7CF64F34CC509B6D0495F91E7BAAF23A2ED9C1DF04A99863EE`）；包内 64 个 dist 文件无缺失、无不一致，6 个核心文件齐全 | 同上 |
| 打包→安装 | `.cac/native` 6 个核心文件全部匹配；ProgramData `CacServiceInjector` 载荷从旧 NativeBridge `4285FAB2...` 同步到 `3368975C...`，6/6 文件哈希匹配，服务恢复 RUNNING；`CacKernel.sys` 与 `CacMacLwf.sys` 均匹配 | `g6-service-sync-v229-20261125-0350/service-sync.json` |
| 安装→实际加载（文件） | 真实 Claude 受控运行：`NativeBridge.dll` 文件哈希与 dist/installed 绑定 pass；`claude-native-binding.node` 加载；无 Claude 残留；网络 before/after digest 相同 | `g6-module-current-guarded-20261125-031846/g6-module-summary.json` |
| 安装→实际加载（内存） | 真实 Claude 受控运行：NativeBridge 与 native binding 的映射镜像 SHA256 均已采集；`memoryHashComparison=boundary-mapped-image-vs-raw-file`；无残留 | `g6-memory-module-current-guarded-20261125-032130/memory-module-summary.json` |
| 可执行回滚 | 临时替换 6 个已安装核心文件（哈希确实变化），恢复后 6/6 字节与哈希回到原值；服务 STOPPED→RUNNING；无 Claude 残留 | `rollback-live-g6-v230-20261125-0335/rollback-result.json` |
| Claude MSIX→实际资源 | 包身份 `Claude / 5.1231.2.0 / x64`；`app\claude.exe`（249,955,664）、`app\resources\app.asar`（84,159,539）、`app\resources\ion-dist.asar`（207,574,690）、`claude-native-binding.node`（4,253,008）的整文件 SHA256 与 AppxBlockMap `b4:FileHash` 匹配；`AppxManifest.xml` 按声明大小验证 | `g6-delivery-v230-20261125-0341-final/g6-delivery.json` |

边界与说明：

- `build-provenance.json` 的 85 条命令绝对路径带控制台编码缺陷（工作区前缀显示为 `E:\鐜\...`），但每条都按 `huanjing` 后的相对后缀确定解析，且哈希全部匹配；这是**记录编码缺陷，不是构建链缺口**。未来重建应把 PowerShell 脚本保存为 UTF-8 BOM，避免再次产生该前缀。
- `AppxManifest.xml` 在 BlockMap 中没有 `b4:FileHash`，其 Block 哈希覆盖打包流而非安装后的原始文件；因此只按声明大小验证，整文件哈希验证适用于带 `b4:FileHash` 的四个关键资源。
- 回滚只覆盖已安装文件与服务状态，不声称内存回滚、驱动回滚或服务端行为。

**G6 pass 不等于 CRR 闭合，也不等于完整覆盖**：CRR 仍为 41 pass / 0 fail / 9 unverified / 9 unsupported / 2 N/A；G1b 仍 partial；G5c 仍 not_started；五个完成判定仍为 false。

### 9.24 v2.31：G1b 来源清点闭合

G1b 的 77 条历史观察已逐条落终态 disposition，不再用“open/partial”空挂：

| disposition | 数量 | 含义 |
|---|---:|---|
| `closed` | 39 | 有具体证据，缺口已关闭 |
| `boundary` | 24 | 明确的范围/采集架构边界；有 `boundary_basis`、理由和证据，不冒充 CRR pass |
| `blocked-external-input` | 13 | 映射到 9 个 unverified CRR 项；保留 blocker，不冒充 pass |
| `false-positive` | 1 | `G7-LAUNCH-WARNING`，无设备字段 |
| `open` / `partial` / `unknown` | **0 / 0 / 0** | 无空挂、无未归类 |

关键闭合项：

- PE resource tree：19 文件、73 资源叶、0 失败（v2.21）。
- 非 app 包文件：78 文件、`unknown=0`、`scan_errors=0`（v2.22）。
- 1919 条 retained-but-not-CRR 行：54 关键词、32 类别、`unknown=0`（v2.25）。
- 373 条动态边：5 kind、4 类别、`unknown=0`（v2.26）。
- G6 三项：provenance、ProgramData 载荷、实际模块/内存哈希（v2.30）。
- G7 final catalog：v2.28 pass，v2.31 复跑仍 pass。

边界示例：legacy 6032/6332 静态账本已被 frozen CRR 61 取代；optional hook refusal、async device IO、CPU flags、route error、ETW retention/decode、observer effect 不进入 CRR，均有 `boundary_basis` 和对应证据。B-08/N-01…N-04/N-06/S-05 作为 CRR 的 unsupported 边界保留；R-03/R-05/R-06/L-03 等 blocked 项继续对应 9 个 unverified CRR 项。

证据：

- `native/evidence/claude-coverage/g1b-current-v231-20261125-0410/g1b-current-disposition.json`
- `native/evidence/claude-coverage/g1b-current-v231-20261125-0410/closure.json`
- `native/evidence/claude-coverage/g1b-current-v231-20261125-0410/sha256-manifest.json`
- `native/evidence/claude-coverage/g7-review-v231-20261125-0415/g7-review.json`

G1b pass **只关闭来源清点门**，不改变 CRR 的 41/0/9/9/2，也不使 `supported_subset_pass`、`device_image_subset_pass`、`full_coverage_within_declared_scope`、`anti_association_pass`、`functional_pass` 变为 true。剩余非账号主线只有 G5c 非登录交替 A/B。

### 9.25 v2.32：G5c 非登录交替 A/B 闭合

G5c 用两轮 8 次真实 Claude 运行完成，顺序按 A/B 交替：

| cycle | 顺序 |
|---|---|
| 1 | `bare → injected A → bare → injected B` |
| 2 | `bare → injected B → bare → injected A` |

运行结果：

- 8/8 exit 0，无 Claude 残留；E 盘从 21.92 GiB 到 21.87 GiB。
- 每次运行前后网络摘要均为 `CDD91089257B05E29B168B92B7863962A8F1204C7C3A7D9DCB99044515D6729C`，无变化。
- bare 4 次一致：`zh-CN / Asia/Shanghai / hc24 / dm32 / maxTouchPoints=10 / 1440x900 / GTX 1050 Ti`，config locale `zh-Hans`。
- injected A 2 次一致：`en-US / America/New_York / hc8 / dm16 / maxTouchPoints=0 / 1920x1080 / Intel UHD 630`；主进程读回 totalmem 16 GiB、cpuCount 8、appLocale en-US、country US。
- injected B 2 次一致：`en-GB / Europe/London / hc12 / dm8 / maxTouchPoints=0 / 2560x1440 / AMD RX 6600`；主进程读回 totalmem 8 GiB、cpuCount 12、appLocale en-GB、country GB。
- 主世界、preload、主进程三面均读回同一 persona；A/B ant-did 各自跨 cycle 稳定且互异；4 个 bare ant-did 互异且都不等于 A/B。
- 音频 `enumerateDevices`：injected A/B `label_present=0`、`audiooutput=5`；bare 保留宿主 label（基线）。
- E-10 的 `config.json` 在 A/B 均保持 app-default `en-US`，B 的运行时 `en-GB` 由主进程/renderer/preload 三面注入；这与 E-10 的既定口径一致，不是配置泄漏。

验证器 30/30 checks true，`gate_state=pass`。证据：

- `native/evidence/claude-coverage/g5c-v231-alternating-20261125-0500/sequence.json`
- `native/evidence/claude-coverage/g5c-v231-alternating-20261125-0500/g5c-verification.json`
- `native/evidence/claude-coverage/g5c-v231-alternating-20261125-0500/sha256-manifest.json`
- `native/evidence/claude-coverage/g7-review-v232-20261125-0505/g7-review.json`

**G5c pass 只关闭非登录交替门**：CRR 仍为 41 pass / 0 fail / 9 unverified / 9 unsupported / 2 N/A；`device_image_subset_pass`、`supported_subset_pass`、`full_coverage_within_declared_scope`、`anti_association_pass`、`functional_pass` 仍为 false。P3 非账号主线到此完成，剩余全部是 P2 账号/凭据门。

## 10. 修订依据

- `native/evidence/claude-coverage/catalog-contract17-static-only-r2-20261123/source-to-sink.json`
- `native/evidence/claude-coverage/renderer-followup-mainlocal-3/native-call-audit.jsonl`
- `native/evidence/claude-coverage/renderer-followup-mainlocal-3-source-sink-audit/findings.json`
- `native/evidence/claude-coverage/renderer-followup-mainlocal-3-process-attribution/findings.json`
- `native/evidence/claude-coverage/goal-v2-g0-g1-20261124155117/source-freeze.json`
- `native/evidence/claude-coverage/goal-v2-g0-g1-20261124155117/crr-ledger.json`
- `native/evidence/claude-coverage/goal-v2-g3-injected3-20261125-000454/`
- `native/evidence/claude-coverage/goal-v2-g4-injected5-20261125-000922/`
- `native/evidence/claude-coverage/goal-v2-g4-bare2-20261125-000725/`
- `native/evidence/claude-coverage/goal-v2-g4-identity-audit-20261125-0013/identity-audit.json`
- `native/evidence/claude-coverage/goal-v2-g5-persist-p2-20261125-0016/request-headers.jsonl`（`anthropic-client-*` 4 行）
- `native/evidence/claude-coverage/goal-v2-g5-persist-p2-20261125-0016/profile-identity.json`
- `native/evidence/claude-coverage/goal-v2-g5a-mainpersona-20261125-002024/`（M-01/M-02 首轮：32→16）
- `native/evidence/claude-coverage/goal-v2-g5a-mainpersona-20261125-002138/`（E-05 闭合：appLocale/systemLocale/preferred 全为 en-US）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-003558/`（preload 面修复后 A：en-US/8/16/New_York/1920x1080/Intel）
- `native/evidence/claude-coverage/goal-v2-g5b-personab2-20261125-003656/`（preload 面修复后 B：en-GB/12/8/London/2560x1440/AMD）
- `native/evidence/claude-coverage/goal-v2-storage-a2-20261125-0032/storage-audit.json`
- `native/evidence/claude-coverage/goal-v2-storage-b-20261125-0032/storage-audit.json`
- `native/evidence/claude-coverage/goal-v2-storage-compare-ab-20261125-0032/storage-compare.json`（D-02/D-03/D-06 全 pass）
- `native/evidence/claude-coverage/goal-v2-g5c-fresh-a-20261125-003425/native-call-audit.jsonl`（readProcessTree/readProcessFootprints 异步结果）
- `native/evidence/claude-coverage/goal-v2-network-posture-20261125-0040/network-posture.json`（US/AS979/LAX、DNS、代理、网卡）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-004214/renderer-fingerprint.jsonl`（A：扩展 35、区域格式、音频计数）
- `native/evidence/claude-coverage/goal-v2-g5b-personab2-20261125-004315/renderer-fingerprint.jsonl`（B：en-GB 区域格式）
- `native/evidence/claude-coverage/goal-v2-storage-compare-ab-20261125-0047/storage-compare.json`（含 localStorage 身份键）
- `native/evidence/claude-coverage/goal-v2-l01-profile-window-20261125-0049/profile-window.json`（37 文件全部预期）
- `native/evidence/claude-coverage/goal-v2-r03-body-format-20261125-0050/r03-body-format.json`（Z85、13,236 字节、熵 7.9608）
- `native/evidence/claude-coverage/goal-v2-r05-growthbook-a-20261125-0055/growthbook-cache.json`（A：602 features）
- `native/evidence/claude-coverage/goal-v2-r05-growthbook-b-20261125-0055/growthbook-cache.json`（B：599 features）
- `native/evidence/claude-coverage/goal-v2-l06-long-20261125-005131/native-call-audit.jsonl`（80 秒长窗，process tree 64 节点）
- `native/evidence/claude-coverage/goal-v2-l04-crash-20261125-005647/crash-test.json`（renderer 17228→13048，主进程存活，Crashpad 无新增）
- `native/evidence/claude-coverage/goal-v2-progress-20261125-0013/progress.json`
- `C:\Program Files\WindowsApps\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\app\resources\app.asar.unpacked\node_modules\@ant\claude-native\claude-native-binding.node`（导出表）
- `C:\Users\Administrator\AppData\Roaming\Claude\config.json`、`ant-did`（只读，未输出原值）
- `E:\环境\huanjing\.tmp\index-C5rj.js`（v2.8 定向复核；`Gyt/Kyt`、`X1n`、`qhe/$n/Oue`、`Odr`、`Rgr`、`getSystemInfo`、TelemetryEvent skipKeys）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-004437/renderer-fingerprint.jsonl`（`maxTouchPoints=10`、`label_present=5`、hCaptcha iframe）
- `native/evidence/claude-coverage/goal-v2-g5b-personab2-20261125-004315/preload-handshake.jsonl`（B hCaptcha iframe persona 读回）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-004437/request-headers.jsonl`（HTTPS referer 仅 `https://claude.ai`，无 file URL）
- `native/evidence/claude-coverage/goal-v2-storage-b3-20261125-0045/storage-audit.json`（B config locale 与运行时差异）
- `native/evidence/claude-coverage/catalog-contract17-static-only-r2-20261123/unresolved-observations.json`（77 条未归类观察）
- `native/evidence/claude-coverage/catalog-contract17-static-only-r2-20261123/scope-gap-audit.json`（373 条未解析动态边）
- `native/evidence/claude-coverage/goal-v2-revision-20261125-0110/revision-audit.json`（v2.8 源锚点与状态修正）
- `native/evidence/claude-coverage/goal-v2-revision-20261125-0110/progress.json`（v2.8 计数与开放项）
- `E:\环境\huanjing\.tmp\goal-v2-g5-persist-profile\home\AppData\Roaming\Claude\sentry\scope_v3.json`（A Sentry 上下文，宿主 CPU/GPU/屏幕/culture）
- `E:\环境\huanjing\.tmp\goal-v2-g5-persist-profile\home\AppData\Roaming\Claude\sentry\queue\ea09866bf36448649b6075eef69818f6`（A Sentry crash event）
- `E:\环境\huanjing\.tmp\goal-v2-g5-b-profile\home\AppData\Roaming\Claude\sentry\scope_v3.json`（B Sentry 上下文，宿主 CPU/GPU/屏幕/culture）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-011615/main-persona.jsonl`（v2.10：`os.cpus`/`os.totalmem`/`app.getLocale*` 已读回 persona）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-011615/renderer-mainworld.jsonl`（v2.10：A mainworld `maxTouchPoints=0`）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-011615/preload-handshake.jsonl`（v2.10：A hCaptcha challenge/checkbox preload 均 `maxTouchPoints=0`）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-011615/request-headers.jsonl`（v2.10：`anthropic-client-total-memory-gb=16`、`device-class=16`、`accept-language=en-US`）
- `native/evidence/claude-coverage/goal-v2-contract-rev10-20261125-0119/rev9-provenance.json`（上一修订 `.9` 的保留哈希）
- `native/evidence/claude-coverage/goal-v2-g5a-personaa2-20261125-013241/`（v2.11 A：B-09/R-07 源补丁）
- `native/evidence/claude-coverage/goal-v2-g5b-personab2-20261125-013621/`（v2.11 B：B-09/R-07 源补丁）
- `native/evidence/claude-coverage/goal-v2-l04-crash-20261125-013356/`（v2.11 A 受控 crash：真实 queue envelope）
- `native/evidence/claude-coverage/goal-v2-l04-crash-b-20261125-013750/`（v2.11 B 受控 crash：真实 queue envelope）
- `native/evidence/claude-coverage/goal-v2-r07b09-20261125-0139/verification.json`（B-09/R-07 A/B 复验汇总）
