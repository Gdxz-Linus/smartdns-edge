# 问题 26 的语义判定实验（Windows 真机）
#
# ## 要判定的问题
#
# `domain-rules /域名/ -address #6`（只声明 v6）时，**A 查询**会返回 SOA。
# 争议点：此时应当**继续向父域规则回落**（"未匹配到 v4 → 看父域有没有"），
# 还是**就此判定"该域没有 v4"**（不再回落）？
#
# 报告说"#6 下 A 查询不再向父域回落"，而 `-address -`（忽略）**会**回落 ——
# 两种"类型不匹配"处理不一致。但报告同时标注"**待确认**"，需与 C 版语义对齐。
#
# ## 本实验怎么判
#
# 构造**父域有 v4、子域只有 #6** 的配置：
#
#   address /parent.test/1.2.3.4      # 父域：明确的 v4
#   address /sub.parent.test/#6       # 子域：只声明 v6
#
# 然后查 `sub.parent.test` 的 **A** 记录：
#
#   * 若返回 **1.2.3.4**  → 说明**会回落**（报告描述有误，或实现已修）
#   * 若返回 **SOA/空**  → 说明**不回落**（报告描述成立）
#
# 再补一组对照（子域用 `-` 忽略），确认"忽略规则会回落"这个已知行为：
#
#   address /parent2.test/1.2.3.4
#   address /sub.parent2.test/-       # 子域：忽略（类型无关）
#
# 若后者返回 1.2.3.4 而前者不返回，则"两种处理不一致"**成立**。
#
# 用法：pwsh -NoProfile -File .\tests\e2e\_p26_fallback.ps1
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'target\debug\smartdns.exe'
if (-not (Test-Path $exe)) { throw "找不到 $exe，请先 cargo build --offline --bin smartdns" }

$tmp = Join-Path $env:TEMP ("p26-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$port = 26991
$conf = Join-Path $tmp 'c.conf'
@"
bind 127.0.0.1:$port
server 223.5.5.5
# 父域给一个明确的 v4，子域只声明 v6（#6）
address /parent.test/1.2.3.4
address /sub.parent.test/#6
# 对照组：父域有 v4，子域用「忽略」
address /parent2.test/5.6.7.8
address /sub.parent2.test/-
log-file $tmp/smartdns.log
log-level info
"@ | Set-Content -Path $conf -Encoding utf8

Write-Host "===== 问题 26 语义判定实验 ====="
Write-Host ""

$proc = $null
try {
    $proc = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf `
        -RedirectStandardOutput (Join-Path $tmp 'out.txt') `
        -RedirectStandardError (Join-Path $tmp 'err.txt') -PassThru
    Start-Sleep -Seconds 3

    Write-Host "--- 实验组：查 sub.parent.test 的 A（子域规则是 #6）---"
    $r1 = & $exe resolve -s "127.0.0.1:$port" sub.parent.test a 2>&1
    $r1 | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "--- 对照：查 sub.parent.test 的 AAAA（#6 应当生效）---"
    $r2 = & $exe resolve -s "127.0.0.1:$port" sub.parent.test aaaa 2>&1
    $r2 | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "--- 对照组：查 sub.parent2.test 的 A（子域规则是 - 忽略）---"
    $r3 = & $exe resolve -s "127.0.0.1:$port" sub.parent2.test a 2>&1
    $r3 | ForEach-Object { Write-Host "  $_" }

    Write-Host ""
    Write-Host "--- 参照：查父域 parent.test 的 A（应返回 1.2.3.4）---"
    $r4 = & $exe resolve -s "127.0.0.1:$port" parent.test a 2>&1
    $r4 | ForEach-Object { Write-Host "  $_" }
}
finally {
    if ($proc -and -not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(3000) | Out-Null }
}

Write-Host ""
Write-Host "===== 判定 ====="
# 去掉空白再匹配（resolve 的表格会折行）
$f1 = (($r1 -join '') -replace '\s', '')
$f3 = (($r3 -join '') -replace '\s', '')

$p1FallsBack = $f1 -match '1\.2\.3\.4'
$p3FallsBack = $f3 -match '5\.6\.7\.8'

if ($p1FallsBack) {
    Write-Host "实验组（子域 #6 → A 查询）：✅ 回落到了父域的 1.2.3.4"
} else {
    Write-Host "实验组（子域 #6 → A 查询）：❌ 未回落（返回 SOA/空）"
}
if ($p3FallsBack) {
    Write-Host "对照组（子域 -  → A 查询）：✅ 回落到了父域的 5.6.7.8"
} else {
    Write-Host "对照组（子域 -  → A 查询）：❌ 未回落"
}

Write-Host ""
if ($p1FallsBack -eq $p3FallsBack) {
    Write-Host "结论：两者的「类型不匹配」处理**一致**（都回落 或 都不回落）"
} else {
    Write-Host "结论：两者处理**不一致** —— 问题 26 描述的现象成立"
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-Host "已清理"
