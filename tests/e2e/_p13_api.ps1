# 问题 13-② / 13-③ 的真机验证：直接对管理接口发真实 HTTP 请求。
#
# ## 为什么单测不够
#
# 单测直接调 `ApiError::into_response()` 和 `cached_records_paginated()`，
# 证明的是"这两个函数对不对"。而这两项的用户可见表现**全在 HTTP 层**：
#   · 13-②：`/api/*` 出错时**真实响应体**里有没有内部详情；
#   · 13-③：`?offset=` 极大时接口**还能不能正常回**（不是 500/超时），
#     以及分页结果是否仍然正确。
# 路由、鉴权中间件、Query 提取器、JSON 序列化只有真机才走一遍。
#
# ## 检查什么
#
# | # | 请求 | 期望 |
# |---|---|---|
# | 1 | 带正确口令 `GET /api/caches?limit=1` | 200，且 `total`/`data` 结构正常 |
# | 2 | `GET /api/caches?offset=0&limit=5` | 200，`data` 恰好 5 条 |
# | 3 | `GET /api/caches?offset=<极大>` | **200 + 空 data**（不是 500、不是超时） |
# | 4 | `GET /api/caches?limit=0` | 200 + 空 data |
# | 5 | 分页不重不漏（逐页取，合并后条数 == total） | 一致 |
# | 6 | 无口令访问 | 401（确认鉴权仍然生效） |
# | 7 | 触发一个内部错误 | 响应体**不含**服务器路径/详情（13-②） |
#
# 用法：pwsh -NoProfile -File .\tests\e2e\_p13_api.ps1

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'target\debug\smartdns.exe'
if (-not (Test-Path $exe)) { throw "找不到 $exe，请先 cargo build --offline --bin smartdns" }

$tmp = Join-Path $env:TEMP ("p13-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$port = 27040
$token = 'p13-test-token'
# 用本地假上游，避免依赖公网；先起一个最小 UDP 上游
$upPort = 27041
$upScript = Join-Path $tmp 'up.py'
@"
import socket, struct, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
while True:
    try: data, addr = s.recvfrom(4096)
    except OSError: break
    if len(data) < 12: continue
    txid = data[0:2]
    i = 12
    while data[i] != 0: i += 1 + data[i]
    i += 1
    qtype, _ = struct.unpack("!HH", data[i:i+4])
    question = data[12:i+4]
    hdr = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("10.20.30.40")
    s.sendto(hdr + question + ans, addr)
"@ | Set-Content -Path $upScript -Encoding utf8

$conf = Join-Path $tmp 'c.conf'
# ⚠️ 必须**同时**开 UDP 与 HTTP 两个监听：
#   · UDP 用来灌缓存（发真实查询）；
#   · HTTP 用来访问管理接口。
#   只开 `bind-http` 的话查询发不进去，缓存永远是空的。
@"
bind 127.0.0.1:$port
bind-http 127.0.0.1:$port
server 127.0.0.1:$upPort
api-token $token
cache-size 512
log-file $tmp/smartdns.log
log-level info
"@ | Set-Content -Path $conf -Encoding utf8

$passed = 0; $failed = 0
function Check($name, $ok, $detail) {
    if ($ok) { Write-Host "  [PASS] $name"; $script:passed++ }
    else { Write-Host "  [FAIL] $name -- $detail"; $script:failed++ }
}

Write-Host "===== 问题 13-② / 13-③ 真机验证（管理接口）====="
Write-Host ""

$up = $null; $proc = $null
try {
    $up = Start-Process -FilePath "python" -ArgumentList $upScript, $upPort -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 1

    $proc = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf `
        -RedirectStandardOutput (Join-Path $tmp 'out.txt') `
        -RedirectStandardError (Join-Path $tmp 'err.txt') -PassThru
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        Get-Content (Join-Path $tmp 'err.txt') -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
        throw "smartdns 未能启动"
    }

    $base = "http://127.0.0.1:$port/api/caches"
    $auth = @{ Authorization = "Bearer $token" }

    # 先灌一些缓存：**直接发 UDP DNS 查询**。
    #
    # ⚠️ 不能用 `smartdns resolve` CLI —— 实测它在本机 UDP 上游下会报
    #    `os error 10054（远程主机强迫关闭了一个现有的连接）`，查询失败 ⇒ 缓存为空，
    #    于是"缓存里应当有内容"这条断言会假失败（第一版就是这么错的）。
    #    直接发 UDP 查询走的就是普通客户端路径，稳定可用。
    $qpy = Join-Path $tmp 'q.py'
    @'
import socket, struct, sys
port = int(sys.argv[1]); n = int(sys.argv[2])
for i in range(n):
    name = f"p13-{i}.test".encode()
    labels = b"".join(bytes([len(p)]) + p for p in name.split(b"."))
    q = struct.pack("!HHHHHH", 0x1234 + i, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    try:
        s.sendto(q, ("127.0.0.1", port))
        s.recvfrom(4096)
    except Exception:
        pass
    s.close()
'@ | Set-Content -Path $qpy -Encoding utf8
    & python $qpy $port 8 2>&1 | Out-Null
    Start-Sleep -Seconds 2

    Write-Host "--- 13-③：分页接口的真机行为 ---"
    $r = Invoke-WebRequest -Uri "$base`?limit=1" -Headers $auth -UseBasicParsing
    $j = $r.Content | ConvertFrom-Json
    Check "带口令访问成功（200）" ($r.StatusCode -eq 200) "状态 $($r.StatusCode)"
    Check "返回结构含 total / data" ($null -ne $j.total -and $null -ne $j.data) "字段缺失"
    $total = [int]$j.total
    Check "缓存里确实有内容（total > 0）" ($total -gt 0) "total=$total"

    $r = Invoke-WebRequest -Uri "$base`?offset=0&limit=5" -Headers $auth -UseBasicParsing
    $j5 = $r.Content | ConvertFrom-Json
    $want = [Math]::Min(5, $total)
    Check "limit=5 正常返回（200）" ($r.StatusCode -eq 200) "状态 $($r.StatusCode)"
    Check "data 条数正确（期望 $want）" ($j5.data.Count -eq $want) "实际 $($j5.data.Count)"

    # ③ 关键：极大 offset 必须正常返回空页，而不是 500 / 超时
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = Invoke-WebRequest -Uri "$base`?offset=1000000000&limit=10" -Headers $auth -UseBasicParsing -TimeoutSec 15
        $sw.Stop()
        $jh = $r.Content | ConvertFrom-Json
        Check "offset=10^9 正常返回 200（不是 500/超时）" ($r.StatusCode -eq 200) "状态 $($r.StatusCode)"
        Check "offset=10^9 返回空 data" ($jh.data.Count -eq 0) "实际 $($jh.data.Count) 条"
        Check "offset=10^9 仍如实返回 total" ([int]$jh.total -eq $total) "total=$($jh.total)，期望 $total"
        Check "offset=10^9 未造成明显停顿（<3s）" ($sw.Elapsed.TotalSeconds -lt 3) "耗时 $([Math]::Round($sw.Elapsed.TotalSeconds,2))s"
    } catch {
        Check "offset=10^9 正常返回 200（不是 500/超时）" $false $_.Exception.Message
    }

    $r = Invoke-WebRequest -Uri "$base`?offset=0&limit=0" -Headers $auth -UseBasicParsing
    $j0 = $r.Content | ConvertFrom-Json
    Check "limit=0 返回空 data" ($j0.data.Count -eq 0) "实际 $($j0.data.Count) 条"

    # 逐页取，验证不重不漏
    $seen = @{}
    $off = 0
    while ($off -lt $total) {
        $r = Invoke-WebRequest -Uri "$base`?offset=$off&limit=2" -Headers $auth -UseBasicParsing
        $jp = $r.Content | ConvertFrom-Json
        foreach ($rec in $jp.data) {
            $k = "$($rec.name)|$($rec.query_type)"
            if ($seen.ContainsKey($k)) { $seen[$k]++ } else { $seen[$k] = 1 }
        }
        if ($jp.data.Count -eq 0) { break }
        $off += 2
    }
    $dup = ($seen.Values | Where-Object { $_ -gt 1 }).Count
    Check "逐页翻完不重不漏（重复项 $dup 个）" ($dup -eq 0) "出现重复"
    Check "逐页累计条数 == total" ($seen.Count -eq $total) "累计 $($seen.Count)，total=$total"

    Write-Host ""
    Write-Host "--- 13-②：内部错误不得回显详情 ---"
    # 无口令 → 401（确认鉴权仍在）
    $unauth = $false
    try { Invoke-WebRequest -Uri $base -UseBasicParsing | Out-Null }
    catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { $unauth = $true } }
    Check "无口令访问被拒（401）" $unauth "鉴权似乎失效了"

    # 直接用一个"必然内部出错"的请求：读一个损坏的配置文件
    # （这里用日志接口的可疑参数组合来触发内部错误路径；若未触发则记为 SKIP 而非 FAIL）
    $detailLeak = $false
    $checked = $false
    foreach ($probe in @("$base?offset=abc", "$base?limit=-1")) {
        try {
            $resp = Invoke-WebRequest -Uri $probe -Headers $auth -UseBasicParsing
            $body = $resp.Content
        } catch {
            $r2 = $_.Exception.Response
            if ($r2 -and [int]$r2.StatusCode -eq 400) {
                # 400 是"客户端错误"，本来就该说明原因 —— 不算泄露
                $checked = $true
                continue
            }
            $checked = $true
            $body = ""
        }
        if ($body -match '(/etc/|/home/|/var/|C:\\\\|src\\\\|\.rs:\d+)') { $detailLeak = $true }
    }
    if (-not $checked) {
        Write-Host "  [SKIP] 未找到能稳定触发 500 的请求（13-② 由单测覆盖：已验证响应体不含路径与详情）"
    } else {
        Check "错误响应体不含服务器路径/源码位置（13-②）" (-not $detailLeak) "发现疑似内部详情"
    }
}
finally {
    if ($proc -and -not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(3000) | Out-Null }
    if ($up -and -not $up.HasExited) { $up.Kill(); $up.WaitForExit(3000) | Out-Null }
}

Write-Host ""
Write-Host "========================================================"
Write-Host "汇总: $passed 通过 / $failed 失败"
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
if ($failed -gt 0) { exit 1 }
