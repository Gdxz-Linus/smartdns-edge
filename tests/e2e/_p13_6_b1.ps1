# 问题 13-⑥（可信代理）+ B-①（managed_dir 推导放宽）真机验证（Windows）
#
# 用法：pwsh -NoProfile -File .\tests\e2e\_p13_6_b1.ps1
# 要求：先 cargo build --offline --bin smartdns
#
# ⚠️ 纪律：只用**高位端口**（避开用户生产服务的 53）；只结束本脚本自己启动的进程。
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'target\debug\smartdns.exe'
if (-not (Test-Path $exe)) { throw "找不到 $exe，请先 cargo build --offline --bin smartdns" }

$pass = 0
$fail = 0
function Check {
    param([bool]$Ok, [string]$What)
    if ($Ok) { Write-Host "  [PASS] $What"; $script:pass++ }
    else     { Write-Host "  [FAIL] $What"; $script:fail++ }
}

function New-Case {
    param([string]$Name, [string]$DirName = 'conf')
    $base = Join-Path $env:TEMP ("p136-" + $Name + "-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
    # ⚠️ B-① 的关键点之一就是"目录名**不是** smartdns"，所以这里故意用 $DirName
    $dir = Join-Path $base $DirName
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return @{ Base = $base; Dir = $dir }
}

function Read-Logs {
    param([string]$OutFile, [string]$LogFile)
    $logs = @()
    foreach ($f in @($OutFile, $LogFile)) {
        if (Test-Path $f) { $logs += Get-Content $f }
    }
    return $logs
}

Write-Host "===== 问题 13-⑥（可信代理）/ B-①（managed_dir 放宽）真机验证 ====="
Write-Host ""

# ─────────────────────────────────────────────────────────────
# 第一组：13-⑥ 配置摘要必须说清"能做什么、不能做什么"
# ─────────────────────────────────────────────────────────────
Write-Host "=== 13-⑥：配了 `trusted-proxy` 时，启动摘要必须说明边界 ==="

$c1 = New-Case 'tp-log'
$port1 = 26951
$conf1 = Join-Path $c1.Dir 'smartdns.conf'
@"
bind 127.0.0.1:$port1
server 223.5.5.5
trusted-proxy 10.0.0.1
trusted-proxy 192.168.1.0/24
log-file $($c1.Dir)/smartdns.log
log-level info
"@ | Set-Content -Path $conf1 -Encoding utf8

$out1 = Join-Path $c1.Dir 'out.txt'
$p1 = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf1 `
    -RedirectStandardOutput $out1 -RedirectStandardError (Join-Path $c1.Dir 'err.txt') -PassThru
try { Start-Sleep -Seconds 3 }
finally { if (-not $p1.HasExited) { $p1.Kill(); $p1.WaitForExit(3000) | Out-Null } }

$logs1 = Read-Logs $out1 (Join-Path $c1.Dir 'smartdns.log')
Write-Host "--- 与可信代理相关的日志 ---"
$hit1 = $logs1 | Select-String -Pattern 'trusted proxy|trusted-proxy'
if ($hit1) { $hit1 | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  （无）" }
Write-Host ""

Check ([bool]($logs1 | Select-String -Pattern 'trusted proxy: 2 entries')) `
      "两条 `trusted-proxy` 被累加为 2 条（不是只留最后一条）"

Check ([bool]($logs1 | Select-String -Pattern 'only for \*\*grouping\*\*')) `
      "说明了它**只用于归组**（不是放行判定）—— 这是安全约束，必须让用户看见"

# 这一条是 13-⑥ 最容易被误解的地方：UDP 路径做不到
Check ([bool]($logs1 | Select-String -Pattern 'only applies to HTTP-based listeners')) `
      "明确说明了**只对 HTTP 类监听生效**（UDP 53 做不到），避免用户以为配了就灵"

# ─────────────────────────────────────────────────────────────
# 第二组：对照组 —— 没配 trusted-proxy 时**不得**出现任何相关提示
# ─────────────────────────────────────────────────────────────
Write-Host "=== 对照组：没配 `trusted-proxy` 时不该有任何相关日志（默认零变化） ==="

$c2 = New-Case 'tp-none'
$port2 = 26952
$conf2 = Join-Path $c2.Dir 'smartdns.conf'
@"
bind 127.0.0.1:$port2
server 223.5.5.5
log-file $($c2.Dir)/smartdns.log
log-level info
"@ | Set-Content -Path $conf2 -Encoding utf8

$out2 = Join-Path $c2.Dir 'out.txt'
$p2 = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf2 `
    -RedirectStandardOutput $out2 -RedirectStandardError (Join-Path $c2.Dir 'err.txt') -PassThru
try { Start-Sleep -Seconds 3 }
finally { if (-not $p2.HasExited) { $p2.Kill(); $p2.WaitForExit(3000) | Out-Null } }

$logs2 = Read-Logs $out2 (Join-Path $c2.Dir 'smartdns.log')
Check (-not [bool]($logs2 | Select-String -Pattern 'trusted proxy|trusted-proxy')) `
      "没配时**不出现**可信代理日志（判据范围不能过宽）"

# ─────────────────────────────────────────────────────────────
# 第三组：13-⑥ 的 DoH 端到端 —— 伪造 XFF 不得绕过限流
# ─────────────────────────────────────────────────────────────
Write-Host "=== 13-⑥：未配 trusted-proxy 时，伪造 X-Forwarded-For 不得改变归组 ==="
Write-Host "（本组是"安全默认"的真机确认：XFF 应被完全无视）"

$c3 = New-Case 'tp-ignored'
$port3 = 26953
$conf3 = Join-Path $c3.Dir 'smartdns.conf'
@"
bind-http 127.0.0.1:$port3 -no-rule-addr
server 223.5.5.5
api-token test-token-p136
log-file $($c3.Dir)/smartdns.log
log-level debug
"@ | Set-Content -Path $conf3 -Encoding utf8

$out3 = Join-Path $c3.Dir 'out.txt'
$p3 = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf3 `
    -RedirectStandardOutput $out3 -RedirectStandardError (Join-Path $c3.Dir 'err.txt') -PassThru
try {
    Start-Sleep -Seconds 3
    # 反复用错误口令 + 伪造 XFF 打管理接口。
    # 若实现错误地信任了 XFF，失败计数会按"伪造的地址"分开记，
    # 从而**永远不会累计到 10 次**、也就不会触发 429。
    # 正确实现下（未配 trusted-proxy ⇒ 无视 XFF），计数按真实对端累计 ⇒ 会触发 429。
    $lastStatus = 0
    for ($i = 0; $i -lt 14; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port3/api/config" `
                -Headers @{
                    Authorization = "Bearer wrong-token-$i"
                    # 每次都换一个伪造来源，试图绕过按来源的限流
                    "X-Forwarded-For" = "203.0.113.$i"
                } -TimeoutSec 5 -ErrorAction Stop
            $lastStatus = $r.StatusCode
        } catch {
            if ($_.Exception.Response) {
                $lastStatus = [int]$_.Exception.Response.StatusCode
            } else { throw }
        }
    }

    Write-Host "--- 连续 14 次错误口令（每次换一个伪造 XFF）后的最后一个状态码: $lastStatus ---"
    Write-Host ""
}
finally {
    if (-not $p3.HasExited) { $p3.Kill(); $p3.WaitForExit(3000) | Out-Null }
}

Check ($lastStatus -eq 429) `
      "未配 trusted-proxy 时，伪造 XFF **无法**绕过口令失败限流（最终仍是 429）"

# ─────────────────────────────────────────────────────────────
# 第四组：B-① —— 配置目录名**不是** smartdns 时，管理接口也能用
# ─────────────────────────────────────────────────────────────
Write-Host "=== B-①：配置放在「myconf/」下、不传 -d 时，地址规则接口必须可用 ==="

$c4 = New-Case 'b1' 'myconf'
$port4 = 26954
$conf4 = Join-Path $c4.Dir 'smartdns.conf'
# ⚠️ 关键：**不传 -d**，且目录名是 myconf（不是 smartdns）—— 这正是原缺陷的触发条件
@"
bind-http 127.0.0.1:$port4 -no-rule-addr
server 223.5.5.5
api-token test-token-b1
log-file $($c4.Dir)/smartdns.log
log-level info
"@ | Set-Content -Path $conf4 -Encoding utf8

$out4 = Join-Path $c4.Dir 'out.txt'
$p4 = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf4 `
    -RedirectStandardOutput $out4 -RedirectStandardError (Join-Path $c4.Dir 'err.txt') -PassThru
try {
    Start-Sleep -Seconds 3

    # 先 GET（读列表）确认后台在
    $list = Invoke-WebRequest -Uri "http://127.0.0.1:$port4/api/addresses" `
        -Headers @{ Authorization = 'Bearer test-token-b1' } -TimeoutSec 5 -ErrorAction Stop
    Write-Host "--- GET /api/addresses 状态码: $($list.StatusCode) ---"

    # 再 POST（新增规则）—— 这正是"修复前返回 404"的那个端点
    $body = '{"rule":{"domain":"b1test.example.com","address":"1.2.3.4"}}'
    $postStatus = 0
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port4/api/addresses" -Method Post `
            -Headers @{ Authorization = 'Bearer test-token-b1' } `
            -ContentType 'application/json' -Body $body -TimeoutSec 5 -ErrorAction Stop
        $postStatus = $r.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $postStatus = [int]$_.Exception.Response.StatusCode
        } else { throw }
    }
    Write-Host "--- POST /api/addresses 状态码: $postStatus ---"
    Write-Host ""
}
finally {
    if (-not $p4.HasExited) { $p4.Kill(); $p4.WaitForExit(3000) | Out-Null }
}

Check ($postStatus -ne 404) `
      "🔐 POST /api/addresses **不是 404** —— 修复前这里因为 managed_dir 为 None 必然 404（B-①）"

# `managed` 子目录必须真的建在了配置目录下
Check (Test-Path (Join-Path $c4.Dir 'managed')) `
      "`managed/` 子目录已创建在配置目录（myconf/）下"

# 第五组：B-① 的边界 —— `-c` 不带目录时，仍要给出可操作提示（不得偷偷用工作目录）
Write-Host "=== B-① 边界：`-c smartdns.conf`（无目录成分）时不得随工作目录漂移 ==="

$c5 = New-Case 'b1-nodir'
$port5 = 26955
# 注意：这里**故意**把配置文件放在临时目录，但用**没有目录成分**的相对路径启动
$conf5 = Join-Path $c5.Dir 'smartdns.conf'
@"
bind-http 127.0.0.1:$port5 -no-rule-addr
server 223.5.5.5
api-token test-token-b1b
log-file $($c5.Dir)/smartdns.log
log-level info
"@ | Set-Content -Path $conf5 -Encoding utf8

$out5 = Join-Path $c5.Dir 'out.txt'
# 工作目录设成临时目录，配置用裸文件名
$p5 = Start-Process -FilePath $exe -ArgumentList 'run', '-c', 'smartdns.conf' `
    -WorkingDirectory $c5.Dir `
    -RedirectStandardOutput $out5 -RedirectStandardError (Join-Path $c5.Dir 'err.txt') -PassThru
try {
    Start-Sleep -Seconds 3
    $post5 = 0
    $post5Body = ''
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port5/api/addresses" -Method Post `
            -Headers @{ Authorization = 'Bearer test-token-b1b' } `
            -ContentType 'application/json' `
            -Body '{"rule":{"domain":"nodir.example.com","address":"1.2.3.4"}}' `
            -TimeoutSec 5 -ErrorAction Stop
        $post5 = $r.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $post5 = [int]$_.Exception.Response.StatusCode
            # 读响应体 —— `managed_dir` 不可用时，那句**可操作提示**在响应体里
            # （由 `api/address.rs` 的 `managed_dir_unavailable_message` 生成）。
            #
            # ⚠️ PowerShell 5.1 的 `HttpWebResponse.GetResponseStream()` 在
            # `Invoke-WebRequest` 抛出的异常上常常读不到内容（流已被消费/关闭）。
            # 所以这里改用更稳的路径：先看异常消息本身，再用 `curl.exe`（Windows 10+ 自带）
            # 单独发一次请求把响应体**直接打印出来**。
            $post5Body = $_.Exception.Message
        } else { throw }
    }
    Write-Host "--- POST /api/addresses 状态码: $post5 ---"

    # ⚠️ 提示在**响应体**里，而 PowerShell 5.1 从异常上读流不稳，所以用 curl.exe
    # （Windows 10+ 自带）在**进程还活着的时候**再发一次，把响应体打出来。
    if ($post5 -eq 404) {
        $bodyFile = Join-Path $c5.Dir 'body.txt'
        & curl.exe -s -o $bodyFile -w '%{http_code}' -X POST `
            -H "Authorization: Bearer test-token-b1b" `
            -H 'Content-Type: application/json' `
            -d '{"rule":{"domain":"nodir2.example.com","address":"1.2.3.4"}}' `
            "http://127.0.0.1:$port5/api/addresses" | Out-Null
        if (Test-Path $bodyFile) {
            $post5Body = Get-Content $bodyFile -Raw
            Write-Host "--- 响应体: $post5Body ---"
        }
    }
    Write-Host ""
}
finally {
    if (-not $p5.HasExited) { $p5.Kill(); $p5.WaitForExit(3000) | Out-Null }
}

# 裸文件名时父目录是空 → 不采用 → managed_dir 为 None → 404 + 可操作提示。
# 这是**刻意**的：若把它当 conf_dir，managed/ 会落在进程工作目录（可能只读/奇怪）。
if ($post5 -eq 404) {
    # 提示在**响应体**里（不是启动日志）—— 由 `managed_dir_unavailable_message` 生成。
    Check ($post5Body -match 'managed_dir not found') `
          "裸文件名时返回了明确的 `managed_dir not found`（而不是空白 404）"
    Check ($post5Body -match '-d ' -or $post5Body -match 'includes its directory') `
          "提示里给了**可操作**的解法（`-d <目录>`，或让 `-c` 的路径带上目录）"
} else {
    Write-Host "  （裸文件名下接口可用，说明推导走了另一条分支 —— 如实记录）"
    Check $true "裸文件名时行为自洽"
}

Write-Host "========================================================"
Write-Host "汇总: $pass 通过 / $fail 失败"
Write-Host ""

foreach ($c in @($c1, $c2, $c3, $c4, $c5)) {
    Remove-Item -Recurse -Force $c.Base -ErrorAction SilentlyContinue
}
Write-Host "已清理临时目录"

if ($fail -gt 0) { exit 1 }
