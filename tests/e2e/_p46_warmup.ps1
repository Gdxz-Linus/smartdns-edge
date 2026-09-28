# 问题 46 真机验证（Windows）：
#   上游是"内网权威 DNS"（只解析内网域名，对 example.com 一律 REFUSED）。
#
# ## 为什么要构造成"解析出两个 IP 的域名上游"
#
# 原缺陷（建连时强制探 example.com）**只在"多地址竞速"路径上判死上游**：
#   * 单个 IP 的上游走的是 `connection_provider.rs` 里的**快捷路径**
#     （`if let [(server, server_addrs)] = ... && let [server_addr] = ...`），
#     直接 `return new_connection(...)`，**根本不经过 warmup**；
#   * 只有"多个候选地址"才会进入下面的竞速循环，而 warmup 失败在那里
#     会 `return Err(...)`，被当作"这个地址连不上"，最终报
#     "Failed to connect to any nameserver" —— **整个上游被判死**。
# 所以本脚本把上游写成**域名**，并让内网上游把它解析成**两条 A 记录**，
# 从而确实走进竞速路径。（第一版用单 IP 上游，反向验证因此没能复现。）
#
# ## 判定
#
#   * 修复前：`example.com` 试探收到 REFUSED → 上游被判死 → **内网域名解析不出来**，
#             且上游侧会看到 `example.com` 查询。
#   * 修复后：以协议层握手成功为判据，不再发 `example.com`；
#             内网域名正常解析，且上游侧**一次 example.com 都没收到**。
#
# 用法：pwsh -NoProfile -File .\tests\e2e\_p46_warmup.ps1
# 要求：先 cargo build --offline --bin smartdns；需要 python
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'target\debug\smartdns.exe'
if (-not (Test-Path $exe)) { throw "找不到 $exe，请先 cargo build --offline --bin smartdns" }

$python = $null
foreach ($cand in @('python', 'python3', 'py')) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) { $python = $cand; break }
}
if (-not $python) { throw "需要 python 来跑内网上游模拟器" }

$tmp = Join-Path $env:TEMP ("p46-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$dnsPort = 26921
$srvPort = 26922

# 起"内网上游"：
#   * intranet.test       -> 10.1.2.3（正常解析，这是用户真正要查的域名）
#   * multi.test          -> 两条 A=127.0.0.1（迫使程序走多地址竞速路径）
#   * 其它（含 example.com）-> REFUSED
$upOut = Join-Path $tmp 'upstream.txt'
$upErr = Join-Path $tmp 'up.err.txt'
$up = Start-Process -FilePath $python `
    -ArgumentList (Join-Path $PSScriptRoot 'internal_upstream.py'), $dnsPort,
                  '--allow', 'intranet.test', '--alias', 'multi.test' `
    -RedirectStandardOutput $upOut -RedirectStandardError $upErr -PassThru

Write-Host "===== 问题 46 真机验证（内网上游 + 多地址竞速路径）====="
Write-Host "临时目录: $tmp"
Write-Host ""

$conf = Join-Path $tmp 'c.conf'
# 关键点（每一处都是踩过坑才写对的）：
#
# ① `bootstrap-dns` 是**上游行的选项**（`server <ip> -bootstrap-dns`），
#    不是独立指令 —— 写成独立一行会被当成"未识别行"，
#    于是日志出现 `not bootstrap-dns found, use system_conf instead`，
#    域名形式的 `server` 解析不出来，测试直接失败在"上游不可用"。
#
# ② 必须用**命名组**（`-group`）：原启动预热写的是
#    `server_groups.values().map(|s| s.warmup())`，而未命名的默认组
#    被存进 `default_group_servers`、**不在 `server_groups` 里** ——
#    默认组的上游从来没被启动预热碰过。这是复现原缺陷的必要条件。
#
# ③ 用**域名形式的上游**（`udp://multi.test`）并让它解析出多个地址，
#    是为了走进那条会判死上游的竞速路径；单 IP 上游走快捷路径、不经过预热。
@"
bind 127.0.0.1:$srvPort
server 127.0.0.1:$dnsPort -bootstrap-dns
server udp://multi.test:$dnsPort -group p46grp
log-file $tmp/smartdns.log
log-level debug
"@ | Set-Content -Path $conf -Encoding utf8

$out = Join-Path $tmp 'out.txt'
$proc = $null
$resolved = @()
try {
    Start-Sleep -Seconds 2

    $proc = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf `
        -RedirectStandardOutput $out -RedirectStandardError (Join-Path $tmp 'err.txt') -PassThru
    Start-Sleep -Seconds 3

    Write-Host "--- 查询内网域名 intranet.test（修复后应当解析出 10.1.2.3）---"
    #
    # ⚠️ **必须重试**（实测踩到）：这是**首次查询**，它要先经 bootstrap 解析
    # `multi.test`、再建立到上游的连接，因此比后续查询慢得多；
    # 偶尔会超出 `resolve` CLI 自身的超时并报 `request timed out` ——
    # 而上游日志显示查询其实已经发出去了（属于**脚本时序**问题，不是产品缺陷）。
    #
    # 这个重试很重要：一个**偶发失败**的验证脚本会掩盖真实回归
    # （5 次里 2 过 3 败，很容易被误读成"改坏了"）。
    # 重试期间进程一直健康、上游也一直收到查询，恰好排除了"上游被判死"这个要验证的假设。
    $resolved = @()
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $resolved = & $exe resolve -s "127.0.0.1:$srvPort" intranet.test 2>&1
        $flatTry = (($resolved -join '') -replace '\s', '')
        if ($flatTry -match '10\.1\.2\.3') { break }
        Write-Host "  （第 $attempt 次未出结果，重试…）"
        Start-Sleep -Milliseconds 800
    }
    $resolved | ForEach-Object { Write-Host "  $_" }

    Start-Sleep -Seconds 2
}
finally {
    if ($proc -and -not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(3000) | Out-Null }
    Start-Sleep -Milliseconds 500
    if ($up -and -not $up.HasExited) { $up.Kill(); $up.WaitForExit(3000) | Out-Null }
}

Write-Host ""
Write-Host "--- 上游侧收到的查询 ---"
$upLog = if (Test-Path $upOut) { Get-Content $upOut } else { @() }
if ($upLog.Count -eq 0) {
    Write-Host "  （上游没有任何输出 —— 进程可能没起来）"
    if (Test-Path $upErr) { Get-Content $upErr | ForEach-Object { Write-Host "  [err] $_" } }
} else {
    $upLog | ForEach-Object { Write-Host "  $_" }
}
Write-Host ""

# ① 内网域名必须能解析出来。
# ⚠️ 判定前先去掉所有空白：`resolve` 的表格会把 IP 折行（`10.1.2.` + 换行 + `3`），
#    直接匹配 `10.1.2.3` 会误判成失败（第一版踩过这个坑）。
$flat = (($resolved -join '') -replace '\s', '')
if ($flat -match '10\.1\.2\.3') {
    Write-Host "判定①: ✅ 内网域名解析成功（上游未被 example.com 试探判死）"
} else {
    Write-Host "判定①: ❌ 内网域名解析失败 —— 上游被 example.com 试探判死了"
}

# ② 上游侧**一次 example.com 都不应收到**（隐私暴露 / 审计噪声消失的直接证据）。
$exampleCount = 0
$statLine = $upLog | Select-String -Pattern 'EXAMPLE_COM_QUERIES=(\d+)'
if ($statLine) {
    $exampleCount = [int]$statLine.Matches[0].Groups[1].Value
} elseif ($upLog | Select-String -Pattern '收到查询:\s*example\.com') {
    # 进程被 Kill 时可能来不及打印统计行，退回按日志行判定
    $exampleCount = 1
}
if ($exampleCount -eq 0) {
    Write-Host "判定②: ✅ 上游从未收到 example.com 试探查询"
} else {
    Write-Host "判定②: ❌ 上游仍收到 example.com 试探（建连预热未去除）"
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-Host "已清理"
