# 问题 32/33 的真机验证（Windows）
#
# ## 为什么单测不够
#
# 单元测试直接调 `accepts_dns_message()` / `decode_dns_param()` / `DnsResponse::from()`，
# 证明的是"这些函数对不对"。而这两个问题的用户可见表现**全在 HTTP 接线层**：
#   * 问题 32：JSON 响应体里 `AD` / `CD` 两个字段的实际取值；
#   * 问题 33：`GET /dns-query?dns=<base64url>` 能不能通、`Accept` 带 `, */*` 时
#     回的是 DNS 报文还是 JSON。
# 参数提取器（`Query<QueryParam>`）、路由、`Content-Type` 回填都只有真机才走一遍。
#
# ## 验证什么（每项都用"客户端能观测到的东西"判定）
#
# | # | 请求 | 期望 |
# |---|---|---|
# | 1 | `?name=...&type=A`（Accept: application/json） | JSON 里 `AD=false` |
# | 2 | 同上但带 `&cd=1` | JSON 里 `CD=true`（回显客户端） |
# | 3 | 同上但不带 `cd` | JSON 里 `CD=false`（**不是写死 true**） |
# | 4 | `Accept: application/dns-message, */*` | 回 `application/dns-message`（修复前会回 JSON） |
# | 5 | `?dns=<base64url>`（RFC 8484） | 回 DNS 报文（修复前 400，因为 `name` 是必填） |
# | 6 | `?dns=<base64url>` 且 Accept 只写 `*/*` | **仍回 DNS 报文**（RFC 8484 规定该形式承载报文） |
# | 7 | `?dns=<乱码>` | 400，且错误信息说明要 base64url |
# | 8 | 只给 `type=A`、不给 `name` | 400，且提示可改用 `?dns=`（修复前是提取器直接 400，无提示） |
#
# 用法：pwsh -NoProfile -File .\tests\e2e\_p32_33_doh.ps1
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'target\debug\smartdns.exe'
if (-not (Test-Path $exe)) { throw "找不到 $exe，请先 cargo build --offline --bin smartdns" }

$tmp = Join-Path $env:TEMP ("p32-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# 高位端口，避开用户的 53
$port = 26970
$conf = Join-Path $tmp 'c.conf'
@"
bind-http 127.0.0.1:$port
server 223.5.5.5
api-token p32-test-token
log-file $tmp/smartdns.log
log-level info
"@ | Set-Content -Path $conf -Encoding utf8

$passed = 0
$failed = 0
function Check($name, $ok, $detail) {
    if ($ok) {
        Write-Host "  [PASS] $name"
        $script:passed++
    } else {
        Write-Host "  [FAIL] $name -- $detail"
        $script:failed++
    }
}

Write-Host "===== 问题 32/33 真机验证（DoH）====="
Write-Host "端口 $port"
Write-Host ""

$proc = $null
try {
    $proc = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf `
        -RedirectStandardOutput (Join-Path $tmp 'out.txt') `
        -RedirectStandardError (Join-Path $tmp 'err.txt') -PassThru
    Start-Sleep -Seconds 3

    if ($proc.HasExited) {
        Write-Host "进程启动即退出，输出如下："
        Get-Content (Join-Path $tmp 'err.txt') -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
        throw "smartdns 未能启动"
    }

    $base = "http://127.0.0.1:$port/dns-query"
    # 用一个真实域名，避免依赖本地规则
    $q = "name=example.com&type=A"

    # ---------- 问题 32：AD / CD ----------
    Write-Host "--- 问题 32：JSON 响应里的 AD / CD ---"

    $r1 = Invoke-WebRequest -Uri "$base`?$q" -Headers @{ Accept = 'application/json' } -UseBasicParsing
    $j1 = $r1.Content | ConvertFrom-Json
    Check "AD 应为 false（不得拿 AA 位顶替）" ($j1.AD -eq $false) "实际 AD=$($j1.AD)"
    Check "不带 cd 时 CD 应为 false（不得写死 true）" ($j1.CD -eq $false) "实际 CD=$($j1.CD)"

    $r2 = Invoke-WebRequest -Uri "$base`?$q&cd=1" -Headers @{ Accept = 'application/json' } -UseBasicParsing
    $j2 = $r2.Content | ConvertFrom-Json
    Check "带 cd=1 时 CD 应为 true（回显客户端）" ($j2.CD -eq $true) "实际 CD=$($j2.CD)"
    Check "AD 仍应为 false" ($j2.AD -eq $false) "实际 AD=$($j2.AD)"

    # ---------- 问题 33：Accept 列表 ----------
    Write-Host ""
    Write-Host "--- 问题 33：Accept 带 ``, */*`` 时应回 DNS 报文 ---"

    $r3 = Invoke-WebRequest -Uri "$base`?$q" `
        -Headers @{ Accept = 'application/dns-message, */*' } -UseBasicParsing
    $ct3 = $r3.Headers['Content-Type']
    Check "Content-Type 应为 application/dns-message" ($ct3 -like '*application/dns-message*') "实际 $ct3"
    Check "响应体应是 DNS 报文（前 2 字节为事务 ID，非 '{'）" `
        (-not ($r3.Content -is [string] -and $r3.Content.TrimStart().StartsWith('{'))) "看起来回了 JSON"

    # ---------- 问题 33：RFC 8484 ?dns= ----------
    Write-Host ""
    Write-Host "--- 问题 33：RFC 8484 的 GET ?dns= ---"

    # 手工构造一个 A 查询报文：example.com
    # 头(12B)：id=0x1234 flags=0x0100 qd=1 an=0 ns=0 ar=0
    # 注意：PowerShell 里 'e' 是 [string]，必须显式转 [byte] 才能进 byte[]
    $wire = [byte[]]@(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7) + [System.Text.Encoding]::ASCII.GetBytes('example') +
        [byte[]]@(3) + [System.Text.Encoding]::ASCII.GetBytes('com') +
        [byte[]]@(0x00, 0x00, 0x01, 0x00, 0x01)
    # base64url 无填充
    $b64 = [Convert]::ToBase64String($wire).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $r4 = Invoke-WebRequest -Uri "$base`?dns=$b64" `
        -Headers @{ Accept = 'application/dns-message' } -UseBasicParsing
    $ct4 = $r4.Headers['Content-Type']
    Check "?dns= 应回 application/dns-message" ($ct4 -like '*application/dns-message*') "实际 $ct4"

    # RFC 8484 该形式本身承载报文 ⇒ 即便 Accept 只写 */* 也必须回报文
    $r5 = Invoke-WebRequest -Uri "$base`?dns=$b64" -Headers @{ Accept = '*/*' } -UseBasicParsing
    $ct5 = $r5.Headers['Content-Type']
    Check "?dns= 且 Accept:*/* 仍应回 DNS 报文" ($ct5 -like '*application/dns-message*') "实际 $ct5"

    # 带填充的写法也应接受（现实客户端常见）
    $b64pad = [Convert]::ToBase64String($wire).Replace('+', '-').Replace('/', '_')
    try {
        $r6 = Invoke-WebRequest -Uri "$base`?dns=$b64pad" `
            -Headers @{ Accept = 'application/dns-message' } -UseBasicParsing
        Check "带 = 填充的 base64url 也应接受" ($r6.StatusCode -eq 200) "状态 $($r6.StatusCode)"
    } catch {
        Check "带 = 填充的 base64url 也应接受" $false $_.Exception.Message
    }

    # 读错误响应体。
    # ⚠️ `Invoke-WebRequest` 抛错时，`$_.Exception.Response` 的**流可能已被释放**，
    # 直接读会报 "Cannot access a disposed object"。可靠做法是用
    # `-SkipHttpErrorCheck`（PowerShell 7+）让 4xx 也正常返回响应对象；
    # 拿不到就退回错误消息文本（`ErrorDetails.Message` 通常带着响应体）。
    function Get-ErrorBody($err) {
        $resp = $err.Exception.Response
        if ($resp -is [System.Net.Http.HttpResponseMessage]) {
            try {
                return $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            } catch {
                # 流已释放 → 退到下面的 ErrorDetails
            }
        }
        if ($err.ErrorDetails -and $err.ErrorDetails.Message) {
            return $err.ErrorDetails.Message
        }
        return $err.Exception.Message
    }

    # 乱码 → 400 且说明要 base64url
    $r7ok = $false
    $r7detail = ""
    try {
        Invoke-WebRequest -Uri "$base`?dns=!!!not-base64!!!" -UseBasicParsing | Out-Null
        $r7detail = "居然返回了成功"
    } catch {
        $resp = $_.Exception.Response
        if ($resp -and [int]$resp.StatusCode -eq 400) {
            $body = Get-ErrorBody $_
            if ($body -match 'base64url') { $r7ok = $true } else { $r7detail = "400 但信息未提 base64url：$body" }
        } else {
            $r7detail = "非 400：$($_.Exception.Message)"
        }
    }
    Check "?dns= 乱码应回 400 并说明要 base64url" $r7ok $r7detail

    # 只给 type 不给 name → 400 且提示可改用 ?dns=
    # （缺 name 时提示里应出现 `dns=`，即"可以改用 RFC 8484 形式"）
    $r8ok = $false
    $r8detail = ""
    try {
        Invoke-WebRequest -Uri "$base`?type=A" -UseBasicParsing | Out-Null
        $r8detail = "居然返回了成功"
    } catch {
        $resp = $_.Exception.Response
        if ($resp -and [int]$resp.StatusCode -eq 400) {
            $body = Get-ErrorBody $_
            if ($body -match 'dns=') { $r8ok = $true } else { $r8detail = "400 但未提示可用 ?dns=：$body" }
        } else {
            $r8detail = "非 400：$($_.Exception.Message)"
        }
    }
    Check "缺 name 时应回 400 并提示可用 ?dns=" $r8ok $r8detail
}
finally {
    if ($proc -and -not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(3000) | Out-Null }
}

Write-Host ""
Write-Host "========================================================"
Write-Host "汇总: $passed 通过 / $failed 失败"
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
if ($failed -gt 0) { exit 1 }
