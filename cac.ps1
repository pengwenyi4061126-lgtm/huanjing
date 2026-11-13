#Requires -Version 5.1
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$CAC_VERSION = "1.0.32"
$SUPPORTED_CC = "2.1.294"

$scriptDir = Split-Path $MyInvocation.MyCommand.Definition -Parent
. (Join-Path $scriptDir "scripts\lib.ps1")
. (Join-Path $scriptDir "scripts\menu.ps1")

# ── helpers ────────────────────────────────────────────────

function Get-CcInstallDir {
    return Join-Path $env:APPDATA "npm\node_modules\@anthropic-ai\claude-code"
}

function Get-CcVersion {
    $pkg = Join-Path (Get-CcInstallDir) "package.json"
    if (Test-Path $pkg) {
        try { return (Get-Content $pkg -Raw | ConvertFrom-Json).version } catch { return $null }
    }
    return $null
}

$script:_integrityCache = $null
function Invoke-CliVerify {
    $verify = Join-Path $scriptDir "scripts\verify-cli.js"
    $ccDir = Get-CcInstallDir
    if (-not (Test-Path $verify) -or -not (Test-Path $ccDir)) { return $null }
    $raw = @(& node $verify $ccDir $SUPPORTED_CC 2>$null)
    if ($raw.Count -eq 0) { return $null }
    try { return ($raw | Select-Object -Last 1 | ConvertFrom-Json) } catch { return $null }
}

function Get-CcIntegrityStatus {
    if ($script:_integrityCache -ne $null) { return $script:_integrityCache }
    $check = Invoke-CliVerify
    $manifestPath = Join-Path $CAC_DIR "claude-binary-manifest.json"
    $manifest = $null
    if (Test-Path $manifestPath) {
        try { $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json } catch { $manifest = $null }
    }
    if ($null -eq $check) {
        $manifestSha = $null
        if ($null -ne $manifest) { $manifestSha = $manifest.sha256 }
        $script:_integrityCache = [pscustomobject]@{
            Ok = $false; VersionOk = $false; MarkersOk = $false; ManifestPresent = ($null -ne $manifest)
            ManifestMatch = $false; Version = $null; Sha256 = $null; ManifestSha256 = $manifestSha
            Exe = $null; Reason = "Claude Code 未安装或完整性检查脚本不可用"
        }
        return $script:_integrityCache
    }
    $manifestMatch = ($null -ne $manifest -and
        [string]$manifest.claudeVersion -eq [string]$check.version -and
        ([string]$manifest.sha256).ToUpperInvariant() -eq ([string]$check.sha256).ToUpperInvariant() -and
        [bool]$manifest.markersOk)
    $versionOk = [bool]$check.versionOk
    $markersOk = [bool]$check.markersOk
    $ok = $versionOk -and $markersOk -and $manifestMatch
    $reason = "通过"
    if (-not $versionOk) { $reason = "Claude Code 版本不是 $SUPPORTED_CC" }
    elseif (-not $markersOk) { $reason = "补丁标记不完整" }
    elseif ($null -eq $manifest) { $reason = "缺少二进制完整性清单" }
    elseif (-not $manifestMatch) { $reason = "claude.exe SHA-256 与清单不一致" }
    $manifestSha = $null
    if ($null -ne $manifest) { $manifestSha = $manifest.sha256 }
    $script:_integrityCache = [pscustomobject]@{
        Ok = $ok; VersionOk = $versionOk; MarkersOk = $markersOk; ManifestPresent = ($null -ne $manifest)
        ManifestMatch = $manifestMatch; Version = $check.version; Sha256 = $check.sha256
        ManifestSha256 = $manifestSha; Exe = $check.exe; Reason = $reason
        Markers = $check.markers
    }
    return $script:_integrityCache
}

function Test-Patched {
    return [bool](Get-CcIntegrityStatus).Ok
}

function Reset-PatchCache { $script:_integrityCache = $null }

function Do-Patch {
    $ps = Join-Path $scriptDir "scripts\patch-cli.js"
    if (-not (Test-Path $ps)) { Write-Err "patch-cli.js 未找到"; return $false }
    $ccDir = Get-CcInstallDir
    $output = @(& node $ps $ccDir 2>&1)
    $output | ForEach-Object { Write-Host "  $_" }
    $ok = ($LASTEXITCODE -eq 0)
    Reset-PatchCache
    return $ok
}

function Save-CcBinaryManifest {
    $status = Get-CcIntegrityStatus
    if (-not $status.VersionOk -or -not $status.MarkersOk -or [string]::IsNullOrWhiteSpace($status.Sha256)) { return $false }
    $manifest = [ordered]@{
        schema        = 1
        cacVersion    = $CAC_VERSION
        claudeVersion = $status.Version
        executable    = $status.Exe
        sha256        = $status.Sha256
        markersOk     = $status.MarkersOk
        markers       = $status.Markers
        createdUtc    = [DateTime]::UtcNow.ToString("o")
    }
    Set-Content -LiteralPath (Join-Path $CAC_DIR "claude-binary-manifest.json") -Value ($manifest | ConvertTo-Json -Depth 5) -Encoding UTF8
    Reset-PatchCache
    return (Get-CcIntegrityStatus).ManifestMatch
}

function Ensure-CcIntegrity {
    $status = Get-CcIntegrityStatus
    if ($status.VersionOk -and -not $status.MarkersOk -and (Get-ClaudeProcesses).Count -eq 0) {
        Write-Host "  检测到补丁不完整，正在重新应用..." -ForegroundColor Cyan
        [void](Do-Patch)
        $status = Get-CcIntegrityStatus
    }
    if ($status.VersionOk -and $status.MarkersOk -and -not $status.ManifestPresent) {
        if (Save-CcBinaryManifest) { $status = Get-CcIntegrityStatus }
    }
    if (-not $status.Ok) { Write-Warn "Claude 完整性: $($status.Reason)" }
    return $status
}

# ── auto init ──────────────────────────────────────────────

function Do-Init {
    $realFile = Join-Path $CAC_DIR "real_claude"
    if (Test-Path $realFile) {
        # 已初始化：静默同步 wrapper / PATH / 补丁（cac-windows 升级后这些都可能过期，
        # 且 npm allowScripts 可能拦掉了我们的 postinstall）
        $w = Write-Wrapper
        $p = Ensure-CacInPath
        $n = Sync-NativeLayer
        $integrity = Ensure-CcIntegrity
        if ($w) { Write-Host "  wrapper 已更新" -ForegroundColor DarkGray }
        if ($p) { Write-Host "  PATH 已更新（重开终端后生效）" -ForegroundColor Yellow }
        if ($n) { Write-Host "  Native 层已同步" -ForegroundColor DarkGray }
        if ($integrity.Ok) { Write-Host "  版本/哈希/补丁校验已通过" -ForegroundColor Green }
        if ($w -or $p -or $integrity.Ok) { Start-Sleep -Milliseconds 1200 }
        return $true
    }
    Write-Host ""
    Write-Host "  正在初始化..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $ENVS_DIR -Force | Out-Null
    $ccDir = Join-Path $env:APPDATA "npm\node_modules\@anthropic-ai\claude-code"
    $claude = Find-RealClaude
    if (-not $claude -and -not (Test-Path (Join-Path $ccDir "package.json"))) {
        # Not installed at all (postinstall may have been blocked by npm allowScripts)
        Write-Host "  未找到 Claude Code，正在安装 v$SUPPORTED_CC（约 200MB，请稍候）..." -ForegroundColor Cyan
        & npm install -g "@anthropic-ai/claude-code@$SUPPORTED_CC" --registry https://registry.npmjs.org 2>&1 | ForEach-Object { Write-Host "  $_" }
        $claude = Find-RealClaude
    }
    if (-not $claude) {
        # npm package present but install.cjs never ran (allow-scripts policy)?
        $ccInstall = Join-Path $ccDir "install.cjs"
        if (Test-Path $ccInstall) {
            Write-Host "  运行 install.cjs 解包二进制..." -ForegroundColor Cyan
            & node $ccInstall 2>&1 | ForEach-Object { Write-Host "  $_" }
            $claude = Find-RealClaude
        }
    }
    if (-not $claude) {
        Write-Err "未找到 Claude Code"
        Write-Host "  请手动安装: npm i -g @anthropic-ai/claude-code@$SUPPORTED_CC" -ForegroundColor White
        Wait-AnyKey; return $false
    }
    Set-Content $realFile $claude
    Write-OK "Claude Code: $claude"
    Write-Wrapper | Out-Null
    [void](Sync-NativeLayer)
    Write-OK "Wrapper: $(Join-Path $CAC_DIR 'bin\claude.ps1')"
    if (Ensure-CacInPath) { Write-OK "PATH: 已把 $(Join-Path $CAC_DIR 'bin') 加到 npm 目录之前（重开终端后生效）" }
    else { Write-OK "PATH: 已包含 $(Join-Path $CAC_DIR 'bin')" }
    if (@(Get-Process -Name claude -ErrorAction SilentlyContinue).Count -gt 0) {
        Write-Warn "补丁: 跳过 — 有 Claude Code 在运行，二进制被锁定。退出所有 claude 后再打开 cac 会自动补丁"
    } else {
        [void](Do-Patch)
        if (Save-CcBinaryManifest) { Write-OK "补丁与 SHA-256 清单: 已登记" }
        else { Write-Warn "补丁/版本/哈希校验未通过，启动将被拒绝" }
    }
    Write-Host ""
    Wait-AnyKey
    return $true
}

# ── actions ────────────────────────────────────────────────

function Action-Launch {
    $envName = Get-CurrentEnv
    if (-not $envName) { Write-Err "未激活环境"; Wait-AnyKey; return }
    $ed = Get-EnvDir $envName
    $paths = Ensure-ProfileLayout $envName
    $integrity = Get-CcIntegrityStatus
    if (-not $integrity.Ok) {
        Write-Err "拒绝启动: Claude 完整性检查失败: $($integrity.Reason)"
        Write-Host "  运行“版本更新并应用补丁”重新安装并登记 SHA-256" -ForegroundColor White
        Wait-AnyKey
        return
    }
    $hookPath = Join-Path $CAC_DIR "fingerprint-hook.js"
    if (-not (Test-Path -LiteralPath $hookPath)) {
        Write-Err "拒绝启动: Profile identity hook 缺失，请重新初始化 cac-windows"
        Wait-AnyKey
        return
    }
    if ((Get-ClaudeProcesses).Count -gt 0) {
        Write-Err "已有 Claude 会话运行，先切换/重启 Profile 后再启动"
        Wait-AnyKey
        return
    }
    $real = (Get-Content (Join-Path $CAC_DIR "real_claude") -Raw).Trim()
    if (-not (Test-Path $real)) {
        Write-Err "claude 路径无效: $real"
        Write-Host "  请运行 '版本更新并应用补丁' 重新安装" -ForegroundColor White
        Wait-AnyKey; return
    }
    $values = Get-ProfileEnvironment $paths
    $names = @($values.Keys) + @("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "TZ")
    $snapshot = Save-ProcessEnvironment $names
    Clear-Host
    try {
        Set-ProcessEnvironment $values $names
        Update-Statsig -ConfigDir $paths.ConfigDir -StableId (Read-FileValue (Join-Path $paths.Root "stable_id"))
        Update-ClaudeJsonUserId -ConfigDir $paths.ConfigDir -HomeDir $paths.HomeDir -UserId (Read-FileValue (Join-Path $paths.Root "user_id"))
        if ($real -like "*.js") { & node $real } else { & $real }
    } finally {
        Restore-ProcessEnvironment $snapshot
    }
}

function Action-InstallAndPatch {
    Write-Host ""
    Write-Host "  将安装 Claude Code v$SUPPORTED_CC 并应用隐私补丁" -ForegroundColor Cyan
    # claude.exe is locked while any claude session is running — patch would EBUSY
    $running = @(Get-Process -Name claude -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        Write-Err "检测到 $($running.Count) 个 Claude Code 进程正在运行"
        Write-Host "  运行中无法替换/补丁 claude.exe，请先退出所有 claude 会话再试" -ForegroundColor White
        Wait-AnyKey; return
    }
    $confirm = Read-Input "  继续? (y/N)"
    if ($confirm -ne "y") { return }
    Write-Host "  正在安装..." -ForegroundColor Cyan
    $npmOutput = & npm install -g "@anthropic-ai/claude-code@$SUPPORTED_CC" --registry https://registry.npmjs.org 2>&1
    $npmExit = $LASTEXITCODE
    $npmOutput | ForEach-Object { Write-Host "  $_" }
    if ($npmExit -ne 0) { Write-Err "安装失败"; Wait-AnyKey; return }
    # npm may skip install.cjs (allow-scripts policy) — run it so bin/claude.exe exists
    $ccDir = Join-Path $env:APPDATA "npm\node_modules\@anthropic-ai\claude-code"
    $ccInstall = Join-Path $ccDir "install.cjs"
    if (-not (Find-RealClaude) -and (Test-Path $ccInstall)) {
        Write-Host "  运行 install.cjs 解包二进制..." -ForegroundColor Cyan
        & node $ccInstall 2>&1 | ForEach-Object { Write-Host "  $_" }
    }
    $claude = Find-RealClaude
    if (-not $claude) { Write-Err "安装后未找到 claude.exe"; Wait-AnyKey; return }
    Set-Content (Join-Path $CAC_DIR "real_claude") $claude
    Write-Wrapper | Out-Null
    [void](Do-Patch)
    if (Save-CcBinaryManifest) { Write-OK "完成，版本/补丁/ SHA-256 已登记" }
    else { Write-Warn "安装完成但完整性校验未通过，启动将被拒绝" }
    Wait-AnyKey
}

function Action-Cleanup {
    Write-Host ""
    $envName = Get-CurrentEnv
    if (-not $envName) { Write-Err "未激活环境"; Wait-AnyKey; return }
    if ((Get-ClaudeProcesses).Count -gt 0) {
        Write-Err "请先退出 Claude 会话，再清理当前 Profile"
        Wait-AnyKey
        return
    }
    $confirm = Read-Input "  确认清理追踪数据? (y/N)"
    if ($confirm -ne "y") { return }
    $cs = Join-Path $scriptDir "scripts\cleanup.ps1"
    $paths = Ensure-ProfileLayout $envName
    if (Test-Path $cs) {
        & $cs -ConfigDir $paths.ConfigDir -HomeDir $paths.HomeDir -ProfileRoot $paths.Root `
            -CacheDir $paths.CacheDir -TempDir $paths.TempDir -AppData $paths.AppData `
            -LocalAppData $paths.LocalAppData -XdgConfigHome $paths.XdgConfigHome `
            -XdgCacheHome $paths.XdgCacheHome -CredentialsDir $paths.CredentialsDir -LogsDir $paths.LogsDir
    } else { Write-Err "cleanup.ps1 未找到" }
    Wait-AnyKey
}

function Action-Status {
    $envName = Get-CurrentEnv
    if (-not $envName) { Write-Warn "未激活环境"; Wait-AnyKey; return }
    $paths = Ensure-ProfileLayout $envName
    $integrity = Get-CcIntegrityStatus
    Write-Host ""
    Write-Host "  环境:      $envName" -ForegroundColor White
    Write-Host "  时区:      $(Read-FileValue (Join-Path $paths.Root 'tz'))"
    Write-Host "  语言:      $(Read-FileValue (Join-Path $paths.Root 'lang'))"
    Write-Host "  代理:      $(Read-FileValue (Join-Path $paths.Root 'proxy') '(无)')"
    Write-Host "  主机名:    $(Read-FileValue (Join-Path $paths.Root 'hostname'))"
    Write-Host "  配置目录:  $($paths.ConfigDir)"
    Write-Host "  临时目录:  $($paths.TempDir)"
    $native = Get-NativeLayerStatus
    $nativeState = if ($native.Available) { "可用（用户态 NativeBridge）" } else { "未安装" }
    Write-Host "  Native层:  $nativeState"
    if ($native.Available) {
        Write-Host "  Native证据:$($paths.AuditDir)\native-hook.jsonl"
        Write-Host "  CPU清单:   $(if ($native.ManifestPresent) { '已配置' } else { '未配置（仅 API Hook）' })"
    }
    Write-Host "  完整性:    $($integrity.Reason)"
    Write-Host "  SHA-256:   $($integrity.Sha256)"
    Write-Host "  Claude:    $(Read-FileValue (Join-Path $CAC_DIR 'real_claude'))"
    Wait-AnyKey
}

# ── env sub-menu ───────────────────────────────────────────

function Action-EnvSwitch {
    $envs = @(Get-ChildItem $ENVS_DIR -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    if ($envs.Count -eq 0) { Write-Warn "暂无环境"; Wait-AnyKey; return }
    $cur = Get-CurrentEnv
    $labels = @($envs | ForEach-Object { if ($_ -eq $cur) { "$_ (当前)" } else { $_ } })
    Write-Host "  选择环境:" -ForegroundColor White
    Write-Host ""
    $idx = Show-Menu $labels
    if ($idx -lt 0) { return }
    $name = $envs[$idx]
    if ($name -eq $cur) { Write-Warn "已经是当前环境"; Wait-AnyKey; return }
    # Switching profiles while Claude is alive would mix config and identity.
    if (-not (Stop-ClaudeProcesses)) {
        Write-Err "Profile 切换已取消：Claude 会话未能全部结束"
        Wait-AnyKey
        return
    }
    Set-Content (Join-Path $CAC_DIR "current") $name
    $paths = Ensure-ProfileLayout $name
    Write-OK "已切换到 $name"
    Write-Host "  配置目录: $($paths.ConfigDir)" -ForegroundColor DarkGray
    Wait-AnyKey
}

function Action-EnvCreate {
    Write-Host ""
    $name = (Read-Input "  环境名称").Trim()
    if (-not $name) { return }
    if (-not (Test-ProfileName $name)) {
        Write-Err "环境名只能包含字母、数字、点、下划线和短横线，长度 1-64"
        Wait-AnyKey
        return
    }
    $ed = Get-EnvDir $name
    if (Test-Path $ed) { Write-Err "环境 '$name' 已存在"; Wait-AnyKey; return }
    $current = Get-CurrentEnv
    if ($current -and $current -ne $name -and (Get-ClaudeProcesses).Count -gt 0) {
        if (-not (Stop-ClaudeProcesses)) {
            Write-Err "Profile 创建/激活已取消：Claude 会话未能全部结束"
            Wait-AnyKey
            return
        }
    }
    $rawProxy = Read-Input "  代理地址 (回车跳过)"
    # Timezone is the whole point of this tool. Enter = explicit default, never a silent UTC.
    Write-Host "  时区应与你的代理出口地区一致。其他常用: America/Los_Angeles  Asia/Tokyo  Asia/Taipei" -ForegroundColor DarkGray
    $tzDefault = "Pacific/Honolulu"
    $tzInput = ""
    while (-not $tzInput) {
        $tzInput = (Read-Input "  时区 [回车 = $tzDefault]").Trim()
        if (-not $tzInput) { $tzInput = $tzDefault; break }
        if ($tzInput -notmatch '^[A-Za-z_]+(/[A-Za-z_+\-0-9]+)+$' -and $tzInput -ne "UTC") {
            Write-Warn "格式看起来不对，应为 区域/城市，如 Pacific/Honolulu"
            $tzInput = ""
        }
    }
    New-Item -ItemType Directory -Path $ed -Force | Out-Null
    $paths = Ensure-ProfileLayout $name
    Set-Content (Join-Path $ed "tz")         $tzInput
    Set-Content (Join-Path $ed "lang")       "en_US.UTF-8"
    $proxyNote = "(无)"
    if ($rawProxy) {
        $url = Parse-Proxy $rawProxy
        if ($url) { Set-Content (Join-Path $ed "proxy") $url; $proxyNote = $url }
        else { Write-Warn "代理格式无效，已跳过" }
    }
    Set-Content (Join-Path $CAC_DIR "current") $name
    [void](Ensure-ProfileLayout $name)
    Write-Host ""
    Write-OK "已创建并激活 '$name'"
    Write-Host "     时区: $tzInput" -ForegroundColor White
    Write-Host "     代理: $proxyNote" -ForegroundColor White
    Write-Host "     语言: en_US.UTF-8" -ForegroundColor White
    Write-Host "     配置: $($paths.ConfigDir)" -ForegroundColor White
    Wait-AnyKey
}

function Action-EnvSetTz {
    $envName = Get-CurrentEnv
    if (-not $envName) { Write-Err "未激活环境"; Wait-AnyKey; return }
    $cur = Read-FileValue (Join-Path (Get-EnvDir $envName) "tz")
    Write-Host "  当前时区: $cur" -ForegroundColor DarkGray
    Write-Host "  例如: Pacific/Honolulu  America/Los_Angeles  Asia/Tokyo  Asia/Taipei" -ForegroundColor DarkGray
    $tz = (Read-Input "  新时区 (回车取消)").Trim()
    if (-not $tz) { return }
    if ($tz -notmatch '^[A-Za-z_]+(/[A-Za-z_+\-0-9]+)+$' -and $tz -ne "UTC") {
        Write-Err "格式看起来不对，应为 区域/城市，如 Pacific/Honolulu"
        Wait-AnyKey; return
    }
    Set-Content (Join-Path (Get-EnvDir $envName) "tz") $tz
    Write-OK "时区 -> $tz"
    if (@(Get-Process -Name claude -ErrorAction SilentlyContinue).Count -gt 0) {
        Write-Warn "有 claude 在运行，重启后新时区才生效"
    }
    Wait-AnyKey
}

function Action-EnvSetProxy {
    $envName = Get-CurrentEnv
    if (-not $envName) { Write-Err "未激活环境"; Wait-AnyKey; return }
    $cur = Read-FileValue (Join-Path (Get-EnvDir $envName) "proxy")
    if ($cur) { Write-Host "  当前代理: $cur" -ForegroundColor DarkGray }
    $raw = Read-Input "  代理地址 (留空移除)"
    $pf = Join-Path (Get-EnvDir $envName) "proxy"
    if ($raw) {
        $url = Parse-Proxy $raw
        if ($url) { Set-Content $pf $url; Write-OK "代理 -> $url" }
        else { Write-Err "代理格式无效" }
    } else {
        if (Test-Path $pf) { Remove-Item $pf -Force; Write-OK "代理已移除" }
        else { Write-Warn "当前无代理" }
    }
    Wait-AnyKey
}

function Action-EnvDelete {
    $envs = @(Get-ChildItem $ENVS_DIR -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    if ($envs.Count -eq 0) { Write-Warn "暂无环境"; Wait-AnyKey; return }
    $cur = Get-CurrentEnv
    $deletable = @($envs | Where-Object { $_ -ne $cur })
    if ($deletable.Count -eq 0) { Write-Warn "只有当前环境，无法删除"; Wait-AnyKey; return }
    Write-Host "  选择要删除的环境:" -ForegroundColor White
    Write-Host ""
    $idx = Show-Menu $deletable
    if ($idx -lt 0) { return }
    $name = $deletable[$idx]
    $confirm = Read-Input "  确认删除 '$name'? (y/N)"
    if ($confirm -ne "y") { return }
    $recycleDir = Join-Path $CAC_DIR "recycle"
    New-Item -ItemType Directory -Path $recycleDir -Force | Out-Null
    $dest = Join-Path $recycleDir "$name-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    try {
        Move-Item (Get-EnvDir $name) $dest -Force
        Write-OK "'$name' 已移至回收站"
    } catch {
        Write-Err "删除失败: $_"
    }
    Wait-AnyKey
}

function Action-EmptyRecycle {
    $recycleDir = Join-Path $CAC_DIR "recycle"
    if (-not (Test-Path $recycleDir)) { Write-Warn "回收站为空"; Wait-AnyKey; return }
    $items = @(Get-ChildItem $recycleDir -Directory -ErrorAction SilentlyContinue)
    if ($items.Count -eq 0) { Write-Warn "回收站为空"; Wait-AnyKey; return }
    Write-Host ""
    Write-Host "  回收站内容:" -ForegroundColor White
    foreach ($i in $items) { Write-Host "    $($i.Name)" }
    $confirm = Read-Input "  确认清空回收站? (y/N)"
    if ($confirm -ne "y") { return }
    try {
        Remove-Item $recycleDir -Recurse -Force
        Write-OK "回收站已清空"
    } catch {
        Write-Err "清空失败: $_"
    }
    Wait-AnyKey
}

function Menu-EnvManage {
    while ($true) {
        $envName = Get-CurrentEnv
        if ($envName) { $tz = Read-FileValue (Join-Path (Get-EnvDir $envName) "tz") } else { $tz = "" }
        $ccVer = Get-CcVersion
        Show-Header $CAC_VERSION $envName $tz $ccVer ($ccVer -eq $SUPPORTED_CC) (Test-Patched) (Test-ClaudeResolution)
        Write-Host "  [ 环境管理 ]" -ForegroundColor White
        Write-Host ""
        $opts = @(
            "1. 切换环境"
            "2. 创建新环境"
            "3. 删除环境"
            "4. 设置当前环境时区"
            "5. 设置当前环境代理"
            "6. 清空回收站"
            "0. 返回主菜单"
        )
        $sel = Show-Menu $opts
        switch ($sel) {
            0 { Action-EnvSwitch }
            1 { Action-EnvCreate }
            2 { Action-EnvDelete }
            3 { Action-EnvSetTz }
            4 { Action-EnvSetProxy }
            5 { Action-EmptyRecycle }
            { $_ -eq 6 -or $_ -eq -1 } { return }
        }
    }
}

function Action-NetworkCheck {
    $envName = Get-CurrentEnv
    if (-not $envName) { Write-Err "未激活环境"; Wait-AnyKey; return }
    $script = Join-Path $scriptDir "scripts\network-check.ps1"
    if (-not (Test-Path $script)) { Write-Err "network-check.ps1 未找到"; Wait-AnyKey; return }
    $proxy = Read-FileValue (Join-Path (Get-EnvDir $envName) "proxy")
    if ($proxy) { & $script -EnvName $envName -RequireProxy }
    else { & $script -EnvName $envName }
    Wait-AnyKey
}

function Action-ProfileCheck {
    $script = Join-Path $scriptDir "scripts\profile-check.ps1"
    if (-not (Test-Path $script)) { Write-Err "profile-check.ps1 未找到"; Wait-AnyKey; return }
    & $script
    Wait-AnyKey
}

function Action-NativeBoundaryCheck {
    $script = Join-Path $scriptDir "scripts\native-boundary-check.ps1"
    if (-not (Test-Path $script)) { Write-Err "native-boundary-check.ps1 未找到"; Wait-AnyKey; return }
    $envName = Get-CurrentEnv
    if ($envName) { & $script -EnvName $envName } else { & $script }
    Wait-AnyKey
}

function Action-NativeCandidates {
    $envName = Get-CurrentEnv
    if (-not $envName) { Write-Err "未激活环境"; Wait-AnyKey; return }
    $scanner = Join-Path $scriptDir "native\scan-native-target.ps1"
    if (-not (Test-Path -LiteralPath $scanner)) { Write-Err "scan-native-target.ps1 未找到"; Wait-AnyKey; return }
    $real = Read-FileValue (Join-Path $CAC_DIR "real_claude")
    if (-not (Test-Path -LiteralPath $real)) { Write-Err "未找到真实 claude 路径"; Wait-AnyKey; return }
    $nativeDir = Join-Path $CAC_DIR "native"
    New-Item -ItemType Directory -Path $nativeDir -Force | Out-Null
    $output = Join-Path $nativeDir "native-hook-candidates.txt"
    & $scanner -Target $real -Output $output
    Write-Host ""
    Write-Host "  候选文件: $output" -ForegroundColor Yellow
    Write-Host "  仅把人工确认过的函数入口复制到 native-hook-manifest.txt；未确认条目不要启用。" -ForegroundColor Yellow
    Wait-AnyKey
}

function Action-DesktopProfiles {
    $desktopScript = Join-Path $scriptDir "scripts\desktop-profile.ps1"
    if (-not (Test-Path -LiteralPath $desktopScript)) {
        Write-Err "desktop-profile.ps1 未找到"
        Wait-AnyKey
        return
    }
    Write-Host ""
    Write-Host "  [ Claude Desktop Profile ]" -ForegroundColor White
    Write-Host ""
    $choices = @(
        "1. 列出 Profile"
        "2. 创建 Profile"
        "3. 启动 Profile"
        "4. 启动并注入 NativeBridge"
        "5. Desktop A/B 隔离测试"
        "6. 查看 Profile 状态"
        "7. 清理 Profile"
        "0. 返回"
    )
    $index = Show-Menu $choices
    if ($index -lt 0 -or $index -eq 7) { return }
    $action = switch ($index) {
        0 { "list" }
        1 { "create" }
        2 { "launch" }
        3 { "launch" }
        4 { "ab" }
        5 { "status" }
        6 { "cleanup" }
    }
    $profile = ""
    if ($action -ne "list" -and $action -ne "ab") {
        $profile = (Read-Input "  Profile 名称 (回车=default)").Trim()
    }
    $params = @("-Action", $action)
    if ($profile) { $params += @("-Profile", $profile) }
    if ($index -eq 3) { $params += "-Inject" }
    & $desktopScript @params
    Wait-AnyKey
}

# ── main loop ──────────────────────────────────────────────

if (-not (Do-Init)) { exit 1 }

while ($true) {
    $envName = Get-CurrentEnv
    if ($envName) { $tz = Read-FileValue (Join-Path (Get-EnvDir $envName) "tz") } else { $tz = "" }
    $ccVer = Get-CcVersion
    $supported = $ccVer -eq $SUPPORTED_CC
    $patched = Test-Patched
    Show-Header $CAC_VERSION $envName $tz $ccVer $supported $patched (Test-ClaudeResolution)

    $opts = @(
        "1. 启动 Claude Code"
        "2. 环境管理"
        "3. 版本更新并应用补丁"
        "4. 清理追踪数据"
        "5. 查看状态"
        "6. 网络隔离检查"
        "7. Profile A/B 隔离测试"
        "8. Native/硬件边界证据"
        "9. 生成 CPUID Hook 候选"
        "10. Desktop Profile 管理"
        "0. 退出"
    )
    $sel = Show-Menu $opts
    switch ($sel) {
        0 { Action-Launch; break }
        1 { Menu-EnvManage }
        2 { Action-InstallAndPatch }
        3 { Action-Cleanup }
        4 { Action-Status }
        5 { Action-NetworkCheck }
        6 { Action-ProfileCheck }
        7 { Action-NativeBoundaryCheck }
        8 { Action-NativeCandidates }
        9 { Action-DesktopProfiles }
        { $_ -eq 10 -or $_ -eq -1 } { exit 0 }
    }
}
