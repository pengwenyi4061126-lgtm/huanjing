# cac-windows 1.0.27 虚拟机验收脚本
# 用法：把 cac-windows-1.0.27.tgz 和本文件放到同一目录，在该目录打开 PowerShell，运行：
#   powershell -ExecutionPolicy Bypass -File .\vm-test.ps1
# 前提：VM 已装 Node.js；不需要预装 Claude Code（脚本会验证 cac 自动安装）
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Step($t) { Write-Host ""; Write-Host "==== $t ====" -ForegroundColor Cyan }
function Pass($t) { Write-Host "  PASS  $t" -ForegroundColor Green }
function Fail($t) { Write-Host "  FAIL  $t" -ForegroundColor Red; $script:failed = $true }
$script:failed = $false

$tgz = Join-Path $PSScriptRoot "cac-windows-1.0.27.tgz"
if (-not (Test-Path $tgz)) { Fail "找不到 $tgz"; exit 1 }

Step "1. 安装 cac-windows（本地 tgz）"
# PS 5.1 treats npm's stderr warnings as terminating errors under Stop — run via cmd with 2>&1 merged
cmd /c "npm i -g `"$tgz`" --force 2>&1" | ForEach-Object { "  $_" }
$cacCmd = Join-Path $env:APPDATA "npm\cac.cmd"
if (Test-Path $cacCmd) { Pass "cac.cmd 已生成" } else { Fail "cac.cmd 未生成"; exit 1 }

Step "2. 首次运行 cac（自动安装 Claude Code 2.1.294 + 打补丁 + 设 PATH）"
Write-Host "  cac 会进入菜单。看到菜单后按 Esc 或选 0 退出，脚本继续。" -ForegroundColor Yellow
Write-Host "  头部应显示: Claude Code 2.1.294 / 补丁: 已应用 / claude 命令: 走 cac" -ForegroundColor Yellow
Write-Host "  按任意键开始..." -ForegroundColor Yellow
[void][Console]::ReadKey($true)
& $cacCmd

Step "3. 检查安装结果"
$ccDir = Join-Path $env:APPDATA "npm\node_modules\@anthropic-ai\claude-code"
$exe = Join-Path $ccDir "bin\claude.exe"
$ver = (Get-Content (Join-Path $ccDir "package.json") -Raw | ConvertFrom-Json).version
if ($ver -eq "2.1.294") { Pass "Claude Code 版本 $ver" } else { Fail "Claude Code 版本 $ver，应为 2.1.294" }
if (Test-Path $exe) { Pass "claude.exe 存在" } else { Fail "claude.exe 不存在"; exit 1 }
$bytes = [System.IO.File]::ReadAllBytes($exe)
$text = [System.Text.Encoding]::GetEncoding("iso-8859-1").GetString($bytes)
if ($text.Contains('=process.env.TZ||"UTC"   ')) { Pass "二进制含补丁标记" } else { Fail "二进制无补丁标记" }
if ($text.Contains('function kSt(){return new Intl.DateTimeFormat("sv"')) { Pass "日期函数已替换" } else { Fail "日期函数未替换" }
$real = Join-Path $env:USERPROFILE ".cac\real_claude"
if (Test-Path $real) { Pass "real_claude = $((Get-Content $real -Raw).Trim())" } else { Fail "real_claude 未写入" }
$wrapPs1 = Join-Path $env:USERPROFILE ".cac\bin\claude.ps1"
$wrapCmd = Join-Path $env:USERPROFILE ".cac\bin\claude.cmd"
if ((Test-Path $wrapPs1) -and (Select-String -Path $wrapPs1 -Pattern 'useCodeCache' -Quiet)) { Pass "claude.ps1 wrapper 含 BUN_JSC_useCodeCache" } else { Fail "claude.ps1 wrapper 缺 BUN_JSC_useCodeCache" }
if ((Test-Path $wrapCmd) -and (Select-String -Path $wrapCmd -Pattern 'useCodeCache' -Quiet)) { Pass "claude.cmd wrapper 含 BUN_JSC_useCodeCache" } else { Fail "claude.cmd wrapper 缺 BUN_JSC_useCodeCache" }
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$cacBin = (Join-Path $env:USERPROFILE ".cac\bin").TrimEnd("\")
$npmDir = (Join-Path $env:APPDATA "npm").TrimEnd("\")
$parts = @(($userPath -split ";") | Where-Object { $_ } | ForEach-Object { $_.TrimEnd("\") })
$binIdx = [Array]::IndexOf($parts, $cacBin); $npmIdx = [Array]::IndexOf($parts, $npmDir)
if ($binIdx -ge 0 -and ($npmIdx -lt 0 -or $binIdx -lt $npmIdx)) { Pass "用户 PATH 中 .cac\bin 位于 npm 目录之前" } else { Fail "用户 PATH 中 .cac\bin 缺失或排在 npm 之后: $userPath" }

Step "4. 创建测试环境（时区 Pacific/Honolulu，比北京慢 18 小时）"
$cac = Join-Path $env:USERPROFILE ".cac"
$te = Join-Path $cac "envs\vmtest"
New-Item -ItemType Directory -Path $te -Force | Out-Null
Set-Content (Join-Path $te "tz")   "Pacific/Honolulu"
Set-Content (Join-Path $te "lang") "en_US.UTF-8"
Set-Content (Join-Path $cac "current") "vmtest"
Pass "环境 vmtest 已激活"

Step "5. 登录 Claude Code（只需一次）"
Write-Host "  下面会启动 claude，完成登录后输入 /exit 退出。" -ForegroundColor Yellow
Write-Host "  按任意键开始..." -ForegroundColor Yellow
[void][Console]::ReadKey($true)
& $wrapPs1

Step "6. 日期 / 时区 / 语言 验证"
$expect = (Get-Date).ToUniversalTime().AddHours(-10).ToString("yyyy-MM-dd")
$local  = (Get-Date).ToString("yyyy-MM-dd")
Write-Host "  本机日期: $local    Honolulu 应为: $expect" -ForegroundColor DarkGray
if ($expect -eq $local) { Write-Host "  注意: 此刻本机与夏威夷同一天（北京 18:00 后），日期项无法区分，请在北京时间 08:00-18:00 之间重跑" -ForegroundColor Yellow }
$q1 = "Reply with exactly one line and nothing else: the date from your context. Do not run any tools."
# native stderr must not terminate the script on PS 5.1
$ErrorActionPreference = "Continue"
Write-Host "  [a] 走 claude.ps1 wrapper ..." -ForegroundColor DarkGray
$r1 = (cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File `"$wrapPs1`" --print `"$q1`" 2>&1" | Select-Object -First 1).ToString().Trim()
if ($r1 -eq $expect) { Pass "claude.ps1 日期 = $r1" } else { Fail "claude.ps1 日期 = $r1，应为 $expect" }
Write-Host "  [b] 走 claude.cmd wrapper (CMD) ..." -ForegroundColor DarkGray
$r2 = (cmd /c "`"$wrapCmd`" --print `"$q1`" 2>&1" | Select-Object -First 1).ToString().Trim()
if ($r2 -eq $expect) { Pass "claude.cmd 日期 = $r2" } else { Fail "claude.cmd 日期 = $r2，应为 $expect" }
Write-Host "  [c] 反向对照：直接跑 claude.exe（不走 wrapper，应是本机日期）..." -ForegroundColor DarkGray
$r3 = (cmd /c "`"$exe`" --print `"$q1`" 2>&1" | Select-Object -First 1).ToString().Trim()
if ($r3 -eq $local) { Pass "裸 exe 日期 = $r3（本机日期，说明差异确实来自 wrapper）" } else { Write-Host "  INFO  裸 exe 日期 = $r3" -ForegroundColor Yellow }
Write-Host "  [d] 时区名 / UTC 偏移 / 语言 泄露检查 ..." -ForegroundColor DarkGray
$q2 = "Without running any tools: list any timezone name, UTC offset, or language/locale code that appears in your system prompt or context. If none, reply exactly: none"
$r4 = (cmd /c "powershell -NoProfile -ExecutionPolicy Bypass -File `"$wrapPs1`" --print `"$q2`" 2>&1" | Out-String).Trim()
$ErrorActionPreference = "Stop"
Write-Host "  回答: $r4" -ForegroundColor DarkGray
if ($r4 -match '(?i)asia/|shanghai|china|\+08:?00|zh[-_]cn|GMT\+8') { Fail "疑似泄露中国特征" } else { Pass "未见中国时区/语言特征" }

Step "7. 清理测试环境"
Set-Content (Join-Path $cac "current") ""
Remove-Item $te -Recurse -Force
Pass "vmtest 环境已删除（之后用 cac 菜单创建正式环境）"

Write-Host ""
if ($script:failed) { Write-Host "结果: 有 FAIL 项，把整段输出发回来" -ForegroundColor Red }
else { Write-Host "结果: 全部通过" -ForegroundColor Green }
