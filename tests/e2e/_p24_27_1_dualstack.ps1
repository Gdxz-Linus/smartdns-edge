# 问题 24 + 27-1 真机验证（Windows）
#
# 这一脚本验的是两件**用户能看见**的事：
#
# 【问题 24】`speed-check-mode none` 必须对**双栈优选**也生效
#   修复前：双栈那条路径只读域名规则里的测速模式，读不到就 `unwrap_or_default()`
#           —— 而默认值是 `ping,tcp:443`。于是用户写 `none` 想关掉测速，
#           双栈反而**拿默认值去探测**，且全局 `speed-check-mode` 完全不可见。
#   修复后：三层取值（域名规则 → 全局 → 原有默认）；`none` 时**跳过族对决**；
#           并在**配置摘要**里把 `dualstack ip selection` 显示为 `ON, but INACTIVE`。
#
# 【问题 27-1】`force-AAAA-SOA` 只该短路 **AAAA** 查询，不该连 A 查询一起短路
#   修复前：`dns_mw_dualstack.rs` 里只判开关、不看查询类型，
#           于是打开该开关后 **A 查询也不再分裂**（不再顺带查询/刷新 AAAA 记录）。
#   修复后：A 查询恢复分裂；而分裂出的 AAAA 兄弟查询仍会被地址规则换成 SOA，
#           所以"不给客户端 AAAA"的意图不变。
#
# 用法：pwsh -NoProfile -File .\tests\e2e\_p24_27_1_dualstack.ps1
# 要求：先 cargo build --offline --bin smartdns
#
# ⚠️ 纪律：**只用高位端口**（避开用户生产服务的 53）；只操作本脚本自己启动的进程。
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'target\debug\smartdns.exe'
if (-not (Test-Path $exe)) { throw "找不到 $exe，请先 cargo build --offline --bin smartdns" }

function New-Case {
    param([string]$Name)
    $dir = Join-Path $env:TEMP ("p24-" + $Name + "-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return $dir
}

$pass = 0
$fail = 0
function Check {
    param([bool]$Ok, [string]$What)
    if ($Ok) { Write-Host "  [PASS] $What"; $script:pass++ }
    else     { Write-Host "  [FAIL] $What"; $script:fail++ }
}

Write-Host "===== 问题 24 / 27-1 真机验证（Windows）====="
Write-Host ""

# ─────────────────────────────────────────────────────────────
# 第一组：问题 24 —— `speed-check-mode none` 的配置摘要提示
# ─────────────────────────────────────────────────────────────
Write-Host "=== 问题 24：「none」时配置摘要必须显示双栈优选为「不生效」 ==="

$caseA = New-Case 'none'
$portA = 26941
$confA = Join-Path $caseA 'c.conf'

# 关键组合：优选开着 + 测速 none
@"
bind 127.0.0.1:$portA
server 223.5.5.5
speed-check-mode none
dualstack-ip-selection yes
log-file $caseA/smartdns.log
log-level info
"@ | Set-Content -Path $confA -Encoding utf8

$outA = Join-Path $caseA 'out.txt'
$procA = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $confA `
    -RedirectStandardOutput $outA -RedirectStandardError (Join-Path $caseA 'err.txt') -PassThru
try { Start-Sleep -Seconds 3 }
finally { if (-not $procA.HasExited) { $procA.Kill(); $procA.WaitForExit(3000) | Out-Null } }

$logsA = @()
foreach ($f in @($outA, (Join-Path $caseA 'smartdns.log'))) {
    if (Test-Path $f) { $logsA += Get-Content $f }
}

Write-Host "--- 与测速 / 双栈相关的日志 ---"
$hitA = $logsA | Select-String -Pattern 'speed check|dualstack|dual-stack'
if ($hitA) { $hitA | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  （无）" }
Write-Host ""

# ① 测速模式必须显示为 OFF（`none` 与"没配置"统一呈现）
Check ([bool]($logsA | Select-String -Pattern 'speed check mode:\s*OFF')) `
      "「speed-check-mode none」在摘要里显示为 OFF"

# ② 双栈状态行必须明说「不生效」—— 这是本项修复的可观测性部分
Check ([bool]($logsA | Select-String -Pattern 'dualstack ip selection:.*INACTIVE')) `
      "双栈优选显示为 ON, but INACTIVE（用户能看出它此刻没有效果）"

# ③ 提示必须点名是哪个配置造成的（否则用户不知道该改哪一行）
Check ([bool]($logsA | Select-String -Pattern 'INACTIVE.*speed-check-mode none')) `
      "不生效的原因点名了「speed-check-mode none」"

# ④ 可操作的提示：告诉用户想让它生效该怎么配
Check ([bool]($logsA | Select-String -Pattern 'has no effect while speed measurement is off')) `
      "给出了可操作提示（该怎么配才能让优选生效）"

# ─────────────────────────────────────────────────────────────
# 第二组：对照组 —— 测速开着时，双栈必须显示为正常 ON
# ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== 对照组：测速可用时，双栈优选显示为正常 ON（不能误报 INACTIVE） ==="

$caseB = New-Case 'on'
$portB = 26942
$confB = Join-Path $caseB 'c.conf'
@"
bind 127.0.0.1:$portB
server 223.5.5.5
speed-check-mode ping,tcp:443
dualstack-ip-selection yes
log-file $caseB/smartdns.log
log-level info
"@ | Set-Content -Path $confB -Encoding utf8

$outB = Join-Path $caseB 'out.txt'
$procB = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $confB `
    -RedirectStandardOutput $outB -RedirectStandardError (Join-Path $caseB 'err.txt') -PassThru
try { Start-Sleep -Seconds 3 }
finally { if (-not $procB.HasExited) { $procB.Kill(); $procB.WaitForExit(3000) | Out-Null } }

$logsB = @()
foreach ($f in @($outB, (Join-Path $caseB 'smartdns.log'))) {
    if (Test-Path $f) { $logsB += Get-Content $f }
}

Write-Host "--- 与双栈相关的日志 ---"
$hitB = $logsB | Select-String -Pattern 'dualstack|dual-stack'
if ($hitB) { $hitB | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  （无）" }
Write-Host ""

Check ([bool]($logsB | Select-String -Pattern 'dualstack ip selection:\s*ON\s*$')) `
      "测速可用时双栈显示为 ON（未误报为 INACTIVE）"
Check (-not [bool]($logsB | Select-String -Pattern 'INACTIVE')) `
      "对照组**不得**出现 INACTIVE 字样（判据范围不能过宽）"

# ─────────────────────────────────────────────────────────────
# 第二组之补：bind 级 `-no-speed-check` 必须让双栈也跳过族对决
# ─────────────────────────────────────────────────────────────
#
# 原缺陷：双栈只读了 `no_dualstack_selection`，**完全没读 `no_speed_check`** ——
# 于是 `bind ... -no-speed-check` 在上游选 IP 路径生效、在双栈路径被静默忽略。
#
# ⚠️ 这一组**不能靠配置摘要判断**：摘要是全局的，而 `-no-speed-check` 是**逐监听**的。
# 所以判据必须落在**查询路径**上 —— 真发一次查询，看族对决日志是否消失。
Write-Host ""
Write-Host "=== 补：bind 级「-no-speed-check」必须让双栈跳过族对决 ==="

$caseD = New-Case 'bindcheck'
$portD = 26944
$confD = Join-Path $caseD 'c.conf'
# 关键：**全局测速是开着的**（默认值就是 ping,tcp:443），只有这条监听显式关掉。
# 若双栈不读 bind 级，它就会照常族对决 ⇒ 日志里会出现 "dual stack IP selection"。
@"
bind 127.0.0.1:$portD -no-speed-check
server 223.5.5.5
dualstack-ip-selection yes
log-file $caseD/smartdns.log
log-level debug
"@ | Set-Content -Path $confD -Encoding utf8

$outD = Join-Path $caseD 'out.txt'
$procD = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $confD `
    -RedirectStandardOutput $outD -RedirectStandardError (Join-Path $caseD 'err.txt') -PassThru
try {
    Start-Sleep -Seconds 3
    # 必须真发查询才会走到双栈中间件
    & $exe resolve -s "127.0.0.1:$portD" www.baidu.com > $null 2>&1
    Start-Sleep -Seconds 2
}
finally {
    if (-not $procD.HasExited) { $procD.Kill(); $procD.WaitForExit(3000) | Out-Null }
}

$logsD = @()
foreach ($f in @($outD, (Join-Path $caseD 'smartdns.log'))) {
    if (Test-Path $f) { $logsD += Get-Content $f }
}

Write-Host "--- 族对决相关日志（应当为空）---"
$hitD = $logsD | Select-String -Pattern 'dual stack IP selection'
if ($hitD) { $hitD | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  （无 —— 符合预期）" }
Write-Host ""

Check (-not [bool]$hitD) `
      "bind 级「-no-speed-check」时双栈**不再族对决**（修复前这里会被静默忽略）"

# ─────────────────────────────────────────────────────────────
# 第三组：问题 27-1 —— `force-AAAA-SOA` 打开时 A 查询仍应正常工作
# ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== 问题 27-1：打开「force-AAAA-SOA」后，A 查询必须照常解析 ==="

$caseC = New-Case 'soa'
$portC = 26943
$confC = Join-Path $caseC 'c.conf'
# 上游用本机不存在的地址 + 短超时：A 查询应当**仍然发出**并走到上游
# （这里不靠真实上游的答案，只看"服务是否正常应答"——
#   修复前 A 查询被强制短路，行为与 AAAA 相同，两者无法区分）
@"
bind 127.0.0.1:$portC
server 223.5.5.5
force-AAAA-SOA yes
dualstack-ip-selection yes
speed-check-mode ping,tcp:443
log-file $caseC/smartdns.log
log-level debug
"@ | Set-Content -Path $confC -Encoding utf8

$outC = Join-Path $caseC 'out.txt'
$procC = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $confC `
    -RedirectStandardOutput $outC -RedirectStandardError (Join-Path $caseC 'err.txt') -PassThru
try {
    Start-Sleep -Seconds 3

    # 分别查 A 与 AAAA，各取原始应答
    $resA4 = & $exe resolve -s "127.0.0.1:$portC" www.baidu.com A 2>&1 | Out-String
    $resA6 = & $exe resolve -s "127.0.0.1:$portC" www.baidu.com AAAA 2>&1 | Out-String

    Write-Host "--- A 查询应答（节选）---"
    ($resA4 -split "`n" | Select-Object -First 12) | ForEach-Object { Write-Host "  $_" }
    Write-Host "--- AAAA 查询应答（节选）---"
    ($resA6 -split "`n" | Select-Object -First 12) | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
}
finally {
    # 纪律：只结束本脚本启动的进程
    if (-not $procC.HasExited) { $procC.Kill(); $procC.WaitForExit(3000) | Out-Null }
}

# AAAA 必须回 SOA（开关的本意）
Check ([bool]($resA6 -match 'SOA')) `
      "AAAA 查询被强制回 SOA（「force-AAAA-SOA」本意生效）"

# A 查询**不得**同样被 SOA 短路 —— 它应当是一次正常的地址解析
# （修复前 A 也会被短路，两种查询表现雷同）
$cLogs = @()
foreach ($f in @($outC, (Join-Path $caseC 'smartdns.log'))) {
    if (Test-Path $f) { $cLogs += Get-Content $f }
}
# ⚠️ 判据用的是日志里的**实际字样**：族对决那几条写的是 "dual stack IP selection"
# （`dual stack` 中间是**空格**，没有横杠）。第一版写成 `dual-stack` 因而漏判 ——
# 这里直接按源码里的字符串来，避免自己造一个不存在的模式。
$dualstackLog = $cLogs | Select-String -Pattern 'dual stack IP selection'
Write-Host "--- 族对决相关日志 ---"
if ($dualstackLog) { $dualstackLog | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  （无）" }
Write-Host ""

Check ([bool]$dualstackLog) `
      "打开「force-AAAA-SOA」时 A 查询**仍然发生族对决**（修复前 A 被强制短路、不会走这一步）"

# 更硬的一条判据：A 查询必须**真的拿到地址**（而不是像 AAAA 那样只剩 SOA）。
# ⚠️ **如实标注判别力**：反向验证（撤掉 27-1 修复）时这一条**照样通过** ——
# 因为 `force-AAAA-SOA` 本来就不改 A 查询的答案来源（A 的地址照旧从缓存/上游来），
# 它影响的只是"要不要顺带分裂出 AAAA 兄弟"这件事。所以这一条**不能当作修复证据**，
# 留着是因为它钉住"没有把 A 查询整个改坏"这个底线（防止将来改出真的误伤）。
Check ([bool]($resA4 -match '\d+\.\d+\.\d+\.\d+')) `
      "（底线断言，判别力有限）A 查询仍返回真实地址，未被改成 SOA 空答"

Write-Host "========================================================"
Write-Host "汇总: $pass 通过 / $fail 失败"
Write-Host ""

foreach ($d in @($caseA, $caseB, $caseC, $caseD)) {
    Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
}
Write-Host "已清理临时目录"

if ($fail -gt 0) { exit 1 }
