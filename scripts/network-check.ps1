# Profile network policy and leakage evidence check.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EnvName,
    [string]$ProbeUrl = "https://example.com",
    [switch]$RequireProxy
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "lib.ps1")

function Write-Result($status, $label, $detail) {
    $color = switch ($status) { "PASS" { "Green" } "FAIL" { "Red" } default { "Yellow" } }
    Write-Host ("  [{0}] {1}: {2}" -f $status, $label, $detail) -ForegroundColor $color
}

function Redact-Proxy([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return "(none)" }
    try {
        $uri = [Uri]$Value
        $hostPart = $uri.Host
        $portPart = ""
        if ($uri.Port -gt 0) { $portPart = ":$($uri.Port)" }
        return "$($uri.Scheme)://$hostPart$portPart"
    } catch { return "(invalid)" }
}

function Hash-Text([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToUpperInvariant()
    } finally {
        $hash.Dispose()
    }
}

function Get-HostNetworkEvidence {
    $adapters = @()
    $routes = @()
    $dnsServers = @()
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Select-Object -First 128 | ForEach-Object {
            [ordered]@{
                nameHash = Hash-Text ([string]$_.Name)
                descriptionHash = Hash-Text ([string]$_.InterfaceDescription)
                status = [string]$_.Status
                macHash = Hash-Text ([string]$_.MacAddress)
                virtualName = [bool](([string]$_.Name + ' ' + [string]$_.InterfaceDescription) -match
                    '(?i)vmware|virtualbox|hyper-v|wintun|wireguard|tailscale|zerotier|openvpn|clash|mihomo|tunnel')
            }
        })
    } catch {
        $adapters = @([ordered]@{ error = $_.Exception.Message })
    }
    try {
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Select-Object -First 32 | ForEach-Object {
            [ordered]@{
                interfaceIndex = [int]$_.ifIndex
                nextHop = [string]$_.NextHop
                routeMetric = [int]$_.RouteMetric
                policyStore = [string]$_.PolicyStore
            }
        })
    } catch {
        $routes = @([ordered]@{ error = $_.Exception.Message })
    }
    try {
        $dnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
            $servers = @($_.ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            [ordered]@{
                interfaceIndex = [int]$_.InterfaceIndex
                addressFamily = [string]$_.AddressFamily
                serverCount = $servers.Count
                serverHashes = @($servers | ForEach-Object { Hash-Text ([string]$_) })
            }
        })
    } catch {
        $dnsServers = @([ordered]@{ error = $_.Exception.Message })
    }
    return [ordered]@{
        adapters = $adapters
        defaultRoutes = $routes
        dnsServers = $dnsServers
    }
}

function Test-TcpEndpoint([string]$HostName, [int]$Port) {
    $tcp = $null
    $async = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) { return $false }
        $tcp.EndConnect($async)
        return $tcp.Connected
    } catch { return $false }
    finally {
        if ($async -and $async.AsyncWaitHandle) { $async.AsyncWaitHandle.Close() }
        if ($tcp) { $tcp.Dispose() }
    }
}

function Invoke-NodeEnvProbe([System.Collections.IDictionary]$Environment, [string]$HostName) {
    $node = (Get-Command node -ErrorAction SilentlyContinue).Source
    if (-not $node) { return $null }
    $probeDir = [string]$Environment["TEMP"]
    if ([string]::IsNullOrWhiteSpace($probeDir)) { $probeDir = $env:TEMP }
    New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
    $probe = Join-Path $probeDir "cac-network-env-probe-$([guid]::NewGuid().ToString('N')).js"
    $source = @'
const dns = require("dns").promises;
const net = require("net");
const host = process.env.CAC_PROBE_HOST || "example.com";
async function directSocket() {
  return await new Promise(resolve => {
    const socket = net.createConnection({ host, port: 443 });
    let done = false;
    const finish = value => { if (done) return; done = true; try { socket.destroy(); } catch (_) {} resolve(value); };
    socket.setTimeout(5000);
    socket.once("connect", () => finish({
      status: "CONNECTED",
      remoteAddress: socket.remoteAddress || "",
      remotePort: socket.remotePort || 0
    }));
    socket.once("timeout", () => finish({ status: "TIMEOUT" }));
    socket.once("error", error => finish({ status: "ERROR", code: error.code || "ERR", message: error.message }));
  });
}
(async () => {
  let dnsResult;
  try {
    const addresses = await dns.lookup(host, { all: true });
    dnsResult = {
      status: "RESOLVED",
      addresses: addresses.map(item => ({ address: item.address, family: item.family })),
      count: addresses.length
    };
  }
  catch (error) { dnsResult = { status: "ERROR", code: error.code || "ERR", message: error.message }; }
  console.log(JSON.stringify({
    http: process.env.HTTP_PROXY || "",
    https: process.env.HTTPS_PROXY || "",
    all: process.env.ALL_PROXY || "",
    noProxy: process.env.NO_PROXY || "",
    config: process.env.CLAUDE_CONFIG_DIR || "",
    temp: process.env.TEMP || "",
    dns: dnsResult,
    directSocket: await directSocket()
  }));
})().catch(error => { console.log(JSON.stringify({ error: error.message })); process.exit(1); });
'@
    Set-Content -LiteralPath $probe -Value $source -Encoding ASCII
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $node
        $psi.Arguments = "`"$probe`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        foreach ($key in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "TZ")) {
            [void]$psi.EnvironmentVariables.Remove($key)
        }
        foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }
        $psi.EnvironmentVariables["CAC_PROBE_HOST"] = $HostName
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $out = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        return ($out.Trim() | ConvertFrom-Json)
    } catch { return $null }
    finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
}

$paths = Ensure-ProfileLayout $EnvName
$proxyPath = Join-Path $paths.Root "proxy"
$proxy = Read-FileValue $proxyPath
$proxyConfigured = -not [string]::IsNullOrWhiteSpace($proxy)
$proxyError = $null
if ($proxyConfigured) {
    $normalizedProxy = Parse-Proxy $proxy
    if ([string]::IsNullOrWhiteSpace($normalizedProxy)) {
        $proxyError = "代理地址无效"
    } else {
        $proxy = $normalizedProxy
    }
}
$audit = [ordered]@{
    schema = 2
    profile = $EnvName
    profileRoot = $paths.Root
    checkedUtc = [DateTime]::UtcNow.ToString("o")
    scope = "PROCESS_LOCAL_EVIDENCE_ONLY"
    networkMode = if ($proxyConfigured) { "proxy" } else { "no-proxy" }
    proxy = Redact-Proxy $proxy
    hostNetwork = Get-HostNetworkEvidence
    checks = [ordered]@{}
}
$failed = $false

Write-Host ""
Write-Host "Network isolation check — $EnvName" -ForegroundColor Cyan
Write-Host "  Profile: $($paths.Root)" -ForegroundColor DarkGray

if ($proxyError) {
    Write-Result "FAIL" "proxy" $proxyError
    $audit.checks.proxy = "INVALID"
    $audit.checks.policy = "INVALID_PROXY"
    $failed = $true
} elseif (-not $proxyConfigured) {
    Write-Result "INFO" "proxy" "Profile 未配置代理；代理可达性不适用"
    $audit.checks.proxy = "NOT_CONFIGURED"
    $audit.checks.policy = if ($RequireProxy) { "PROXY_REQUIRED_MISSING" } else { "NO_PROXY_REQUESTED" }
    $audit.checks.socket = "NOT_CONFIGURED"
    $audit.checks.dns = "NOT_CONFIGURED"
    if ($RequireProxy) {
        Write-Result "FAIL" "proxy-policy" "已要求代理，但 Profile 没有配置代理"
        $failed = $true
    }
} else {
    $audit.checks.policy = "PROXY_REQUESTED"
    try { $proxyUri = [Uri]$proxy } catch { $proxyUri = $null }
    if ($null -eq $proxyUri -or $proxyUri.Host -eq "" -or $proxyUri.Port -le 0) {
        Write-Result "FAIL" "proxy" "代理地址无效"
        $audit.checks.proxy = "INVALID"
        $failed = $true
    } elseif (Test-TcpEndpoint $proxyUri.Host $proxyUri.Port) {
        Write-Result "PASS" "proxy" "TCP 可达: $(Redact-Proxy $proxy)"
        $audit.checks.proxy = "REACHABLE"
    } else {
        Write-Result "FAIL" "proxy" "TCP 不可达: $(Redact-Proxy $proxy)"
        $audit.checks.proxy = "UNREACHABLE"
        $failed = $true
    }

    if ($proxyUri.Scheme -eq "socks5") {
        Write-Result "FAIL" "DNS" "socks5 未声明远程 DNS；改用 socks5h 以避免本地解析"
        $audit.checks.dns = "LOCAL_DNS_POSSIBLE"
        $failed = $true
    } elseif ($proxyUri.Scheme -eq "socks5h") {
        Write-Result "PASS" "DNS" "socks5h 已声明远程 DNS"
        $audit.checks.dns = "REMOTE_DNS_REQUESTED"
    } else {
        Write-Result "INFO" "DNS" "HTTP/HTTPS 代理的 DNS 行为由具体客户端实现决定"
        $audit.checks.dns = "CLIENT_DEPENDENT"
    }

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $oldProgress = $ProgressPreference
        $oldErrorAction = $ErrorActionPreference
        $ProgressPreference = "SilentlyContinue"
        $ErrorActionPreference = "Continue"
        try {
            $curlOutput = @(& $curl.Source --proxy $proxy --connect-timeout 8 --max-time 15 --silent --show-error --output NUL $ProbeUrl 2>&1)
            if ($LASTEXITCODE -eq 0) {
                Write-Result "PASS" "socket" "curl 通过 Profile 代理访问探针"
                $audit.checks.socket = "PROXY_PROBE_OK"
            } else {
                Write-Result "FAIL" "socket" "curl 代理探针失败，可能无法建立代理连接"
                $audit.checks.socket = "PROXY_PROBE_FAILED"
                $failed = $true
            }
        } finally {
            $ProgressPreference = $oldProgress
            $ErrorActionPreference = $oldErrorAction
        }
    } else {
        Write-Result "INFO" "socket" "未找到 curl.exe，跳过外部代理探针"
        $audit.checks.socket = "CURL_UNAVAILABLE"
        if ($RequireProxy) { $failed = $true }
    }
}

$probe = $null
if (-not $proxyError) {
    $envValues = Get-ProfileEnvironment $paths
    $probeHost = "example.com"
    try { $probeHost = ([Uri]$ProbeUrl).Host } catch { }
    $probe = Invoke-NodeEnvProbe $envValues $probeHost
}
if ($null -eq $probe) {
    $childDetail = if ($proxyError) { "代理配置无效，跳过 Node 环境探针" } else { "无法启动 Node 环境探针" }
    Write-Result "FAIL" "child-env" $childDetail
    $audit.checks.childEnv = if ($proxyError) { "SKIPPED_INVALID_PROXY" } else { "PROBE_FAILED" }
    $failed = $true
} else {
    $proxyValues = @($probe.http, $probe.https, $probe.all) | Where-Object { $_ }
    $proxyConsistent = $false
    if ($proxy) {
        $proxyConsistent = ($proxyValues.Count -eq 3 -and
            (@($proxyValues | Select-Object -Unique).Count -eq 1) -and
            $proxyValues[0] -eq $proxy)
    } else {
        $proxyConsistent = ($proxyValues.Count -eq 0)
    }
    $pathIsolated = ($probe.config -eq $paths.ConfigDir -and $probe.temp -eq $paths.TempDir)
    if ($proxyConsistent -and $pathIsolated) {
        if ($proxyConfigured) {
            Write-Result "PASS" "child-env" "Node 子进程继承了 Profile 代理与临时目录"
            $audit.checks.childEnv = "PROFILE_ENV_MATCH_WITH_PROXY"
        } else {
            Write-Result "INFO" "child-env" "Node 子进程路径隔离；未配置代理，因此没有代理继承结果"
            $audit.checks.childEnv = "PROFILE_ENV_MATCH_NO_PROXY"
        }
    } else {
        Write-Result "FAIL" "child-env" "Node 子进程环境与 Profile 预期不一致"
        $audit.checks.childEnv = "MISMATCH"
        $failed = $true
    }
    $audit.checks.dnsRuntime = $probe.dns
    if ($probe.dns.status -eq "RESOLVED") {
        $audit.checks.dnsResolution = if ($proxyConfigured) { "OBSERVED_CLIENT_RESOLUTION" } else { "DIRECT_DNS_OBSERVED" }
    } else {
        $audit.checks.dnsResolution = "RESOLUTION_FAILED"
    }
    $audit.checks.directSocket = $probe.directSocket
    if ($probe.directSocket.status -eq "CONNECTED") {
        $message = "Node 可直接建立 TCP/443 连接；环境变量本身没有阻断直连"
        if ($proxyConfigured -and $RequireProxy) {
            Write-Result "FAIL" "direct-socket" $message
            $failed = $true
        } elseif ($proxyConfigured) {
            Write-Result "INFO" "direct-socket" $message
        } else {
            Write-Result "INFO" "direct-socket" "未配置代理；Node 直连 TCP/443 可用是预期结果"
        }
        $audit.checks.directSocketPolicy = if ($proxyConfigured) { "DIRECT_PATH_AVAILABLE" } else { "EXPECTED_DIRECT_PATH_NO_PROXY" }
    } else {
        Write-Result "INFO" "direct-socket" "Node 未建立直连 TCP/443：$($probe.directSocket.status)"
        $audit.checks.directSocketPolicy = if ($proxyConfigured) { "NO_DIRECT_SOCKET_OBSERVED" } else { "DIRECT_PATH_NOT_OBSERVED" }
    }
}

$routeItems = @($audit.hostNetwork.defaultRoutes | Where-Object { $_ -and -not $_.error })
if ($routeItems.Count -gt 0) {
    $routeIndexes = @($routeItems | ForEach-Object { $_.interfaceIndex } | Select-Object -Unique)
    Write-Result "INFO" "route" ("观察到 {0} 条默认路由；接口索引: {1}。本审计不修改系统路由" -f $routeItems.Count, ($routeIndexes -join ","))
    $audit.checks.route = [ordered]@{
        status = "HOST_DEFAULT_ROUTES_OBSERVED"
        count = $routeItems.Count
        interfaceIndexes = $routeIndexes
        mutation = "NOT_PERFORMED"
        boundary = "UNVERIFIED"
    }
} else {
    Write-Result "INFO" "route" "未能读取默认路由；本审计不宣称路由已隔离"
    $audit.checks.route = [ordered]@{ status = "UNAVAILABLE"; mutation = "NOT_PERFORMED"; boundary = "UNVERIFIED" }
}

if ($proxy) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $oldProgress = $ProgressPreference
        $oldErrorAction = $ErrorActionPreference
        $ProgressPreference = "SilentlyContinue"
        $ErrorActionPreference = "Continue"
        try {
            $directOutput = @(& $curl.Source --noproxy '*' --connect-timeout 8 --max-time 15 --silent --show-error --output NUL $ProbeUrl 2>&1)
            if ($LASTEXITCODE -eq 0) {
                if ($RequireProxy) { Write-Result "FAIL" "direct-http" "curl 在禁用代理时仍可访问探针"; $failed = $true }
                else { Write-Result "INFO" "direct-http" "curl 在禁用代理时可访问探针；未强制阻断" }
                $audit.checks.directHttp = "DIRECT_PATH_AVAILABLE"
            } else {
                Write-Result "PASS" "direct-http" "curl 禁用代理访问失败"
                $audit.checks.directHttp = "DIRECT_PATH_NOT_OBSERVED"
            }
        } finally {
            $ProgressPreference = $oldProgress
            $ErrorActionPreference = $oldErrorAction
        }
    }
}

New-Item -ItemType Directory -Path $paths.AuditDir -Force | Out-Null
$auditPath = Join-Path $paths.AuditDir "network-check.json"
$audit.result = if ($failed) { "FAIL" } elseif (-not $proxyConfigured) { "NOT_CONFIGURED" } else { "PASS_PROCESS_LOCAL" }
Set-Content -LiteralPath $auditPath -Value ($audit | ConvertTo-Json -Depth 6) -Encoding UTF8
Write-Host "  证据: $auditPath" -ForegroundColor DarkGray
Write-Host ""
Write-Result $audit.result "summary" ("网络边界结果: $($audit.result)")
if ($failed) { exit 1 }
