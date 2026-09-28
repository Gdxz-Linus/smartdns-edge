<#
端到端模拟测试：真正启动 smartdns 进程，真发 DNS 查询，验证真实运行路径上的行为。

设计说明见同目录 README.md（含"为什么必须有它"与踩过的坑）。

用法：
    pwsh -File .\tests\e2e\run_e2e.ps1                 # 全部
    pwsh -File .\tests\e2e\run_e2e.ps1 -Filter 52      # 只跑名称含 52 的项
    pwsh -File .\tests\e2e\run_e2e.ps1 -KeepTemp       # 保留临时目录便于排查
#>
[CmdletBinding()]
param(
    [string]$Filter = '',
    [switch]$KeepTemp
)

$ErrorActionPreference = 'Stop'

# ---------- 基本路径 ----------
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe      = Join-Path $repoRoot 'target\debug\smartdns.exe'
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "smartdns-e2e-$PID"

$script:Pass = 0
$script:Fail = 0
$script:Skip = 0
$script:Failures = @()

# 用高位端口，避免与真实服务冲突
$basePort = 25300

function Write-Section($title) { Write-Host "`n=== $title ===" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  [PASS] $msg" -ForegroundColor Green;  $script:Pass++ }
function Write-Bad($msg)  { Write-Host "  [FAIL] $msg" -ForegroundColor Red;    $script:Fail++; $script:Failures += $msg }
function Write-Skip($msg) { Write-Host "  [SKIP] $msg" -ForegroundColor Yellow; $script:Skip++ }

function Should-Run($name) {
    return [string]::IsNullOrEmpty($Filter) -or ($name -like "*$Filter*")
}

# ---------- 进程管理：确保每个用例后不留残进程 ----------
$script:Started = @()

function Start-Dns {
    param(
        [Parameter(Mandatory)][string]$ConfPath,
        [string]$WorkingDir,
        [string]$PidFile,
        # 注意：不能叫 $Debug —— 那是 PowerShell 的公共参数，重名会直接报错
        [switch]$Verbose2
    )
    $args = @()
    if ($Verbose2) { $args += @('-v', '-v') }
    $args += @('run', '-c', $ConfPath)
    if ($PidFile) { $args += @('-p', $PidFile) }

    $p = Start-Process -FilePath $exe -ArgumentList $args `
        -WorkingDirectory $WorkingDir -WindowStyle Hidden -PassThru
    $script:Started += $p
    Start-Sleep -Milliseconds 1500
    return $p
}

function Stop-All {
    foreach ($p in $script:Started) {
        try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch {}
    }
    $script:Started = @()
    Start-Sleep -Milliseconds 300
}

function Invoke-Query {
    param([int]$Port, [string]$Name, [string]$Type = 'A', [switch]$Tcp)
    $a = @('resolve')
    if ($Tcp) { $a += '-T' }
    $a += @('-s', "127.0.0.1:$Port", $Name)
    if ($Type -ne 'A') { $a += $Type }
    $out = & $exe @a 2>&1 | Out-String
    return $out
}

function New-CaseDir([string]$name) {
    $d = Join-Path $tempRoot $name
    New-Item -ItemType Directory -Force -Path (Join-Path $d 'conf'), (Join-Path $d 'logs') | Out-Null
    return $d
}

function Write-Conf([string]$dir, [string]$content, [string]$fileName = 'smartdns.conf') {
    $p = Join-Path (Join-Path $dir 'conf') $fileName
    # 用 UTF8 无 BOM，避免配置解析器把 BOM 当内容
    [System.IO.File]::WriteAllText($p, $content, (New-Object System.Text.UTF8Encoding($false)))
    return $p
}

# ---------- 前置检查 ----------
Write-Host "smartdns 端到端模拟测试" -ForegroundColor White
Write-Host "仓库: $repoRoot"

if (-not (Test-Path $exe)) {
    Write-Host "未找到二进制，请先执行: cargo build --offline --bin smartdns" -ForegroundColor Red
    exit 2
}
$srcNewest = Get-ChildItem (Join-Path $repoRoot 'src') -Recurse -File -Filter *.rs |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($srcNewest.LastWriteTime -gt (Get-Item $exe).LastWriteTime) {
    Write-Host "警告：源码比二进制新（可能是 cargo 未重编），结果可能不准。" -ForegroundColor Yellow
    Write-Host "  建议先 cargo build --offline --bin smartdns" -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

try {
    # =====================================================================
    Write-Section "基础：真实解析链路"
    if (Should-Run 'base') {
        $d = New-CaseDir 'base'
        $port = $basePort
        $conf = Write-Conf $d @"
bind 127.0.0.1:$port
bind-tcp 127.0.0.1:$port
server 223.5.5.5
address /local.test/10.11.12.13
address /blocked.test/#
cache-size 1024
log-file $($d -replace '\\','/')/logs/smartdns.log
log-level info
"@
        Start-Dns -ConfPath $conf -WorkingDir $d | Out-Null

        # 1) 公网上游
        $r = Invoke-Query -Port $port -Name 'www.baidu.com'
        if ($r -match '\d+\.\d+\.\d+' -and $r -notmatch 'Error|error') {
            Write-Ok "公网上游解析返回真实 IP"
        } else {
            Write-Bad "公网上游解析异常: $($r -replace '\s+',' ')"
        }

        # 2) 本地规则
        $r = Invoke-Query -Port $port -Name 'local.test'
        if ($r -replace '\s','' -match '10\.11\.12\.13') {
            Write-Ok "本地 address 规则生效"
        } else {
            Write-Bad "本地 address 规则未生效: $($r -replace '\s+',' ')"
        }

        # 3) TCP
        $r = Invoke-Query -Port $port -Name 'local.test' -Tcp
        if ($r -replace '\s','' -match '10\.11\.12\.13') {
            Write-Ok "TCP 传输正常"
        } else {
            Write-Bad "TCP 传输异常: $($r -replace '\s+',' ')"
        }

        # 4) 不输出 NXDOMAIN（项目基点 §6 的刻意设计）
        $r = Invoke-Query -Port $port -Name 'nonexistent-e2e-xyz.test'
        if ($r -match 'SOA' -and $r -notmatch 'NXDOMAIN') {
            Write-Ok "不存在域名回 SOA（未输出 NXDOMAIN，符合刻意设计）"
        } else {
            Write-Bad "不存在域名的应答不符合『不输出 NXDOMAIN』: $($r -replace '\s+',' ')"
        }
        Stop-All
    } else { Write-Skip "基础检查（被 Filter 排除）" }

    # =====================================================================
    Write-Section "问题 52：conf-file 不被工作目录 / 程序目录劫持"
    if (Should-Run '52') {
        $d = New-CaseDir 'p52'
        $port = $basePort + 1
        # 诱饵放在【工作目录】（不在配置同目录 —— 否则会被合法回退找到，测不出问题）
        $bait = Join-Path (Join-Path $d 'cwd') 'trap.conf'
        New-Item -ItemType Directory -Force -Path (Split-Path $bait) | Out-Null
        [System.IO.File]::WriteAllText($bait, "address /trap-cwd.test/9.9.9.9`n", (New-Object System.Text.UTF8Encoding($false)))

        $conf = Write-Conf $d @"
bind 127.0.0.1:$port
server 223.5.5.5
address /local52.test/10.11.12.13
conf-file trap.conf
log-file $($d -replace '\\','/')/logs/smartdns.log
log-level info
"@
        $out = Join-Path $d 'out.txt'
        $p = Start-Process -FilePath $exe `
            -ArgumentList @('-v','-v','run','-c',$conf,'-p',(Join-Path $d 'pid')) `
            -WorkingDirectory (Split-Path $bait) -WindowStyle Hidden `
            -RedirectStandardOutput $out -RedirectStandardError (Join-Path $d 'err.txt') -PassThru
        $script:Started += $p
        Start-Sleep -Milliseconds 1500

        # 诱饵规则【不得】生效
        $r = Invoke-Query -Port $port -Name 'trap-cwd.test'
        if ($r -replace '\s','' -notmatch '9\.9\.9\.9') {
            Write-Ok "工作目录里的诱饵配置未被加载"
        } else {
            Write-Bad "工作目录里的诱饵配置被加载了（配置劫持面复现）"
        }

        # 正常规则仍应生效
        $r = Invoke-Query -Port $port -Name 'local52.test'
        if ($r -replace '\s','' -match '10\.11\.12\.13') {
            Write-Ok "正常规则未被误伤"
        } else {
            Write-Bad "正常规则失效: $($r -replace '\s+',' ')"
        }

        # 日志里应有明确的"不去这两处找"告警
        $log = (Get-Content $out -ErrorAction SilentlyContinue | Out-String)
        if ($log -match 'not found' -and $log -match 'NOT looked up in') {
            Write-Ok "找不到时有明确告警（并说明不去工作目录/程序目录找）"
        } else {
            Write-Bad "缺少 conf-file 找不到的明确告警"
        }
        Stop-All
    } else { Write-Skip "问题 52（被 Filter 排除）" }

    # =====================================================================
    Write-Section "问题 38：代理凭据写一半必须是配置错误"
    if (Should-Run '38') {
        $d = New-CaseDir 'p38'
        $conf = Write-Conf $d @"
bind 127.0.0.1:$($basePort + 2)
proxy-server socks5://:SECRETPW@127.0.0.1:1080 -name bad
server 223.5.5.5 -proxy bad
"@
        $out = & $exe test -c $conf 2>&1 | Out-String
        $code = $LASTEXITCODE

        if ($code -ne 0) {
            Write-Ok "凭据写一半已报配置错误（退出码 $code）"
        } else {
            Write-Bad "凭据写一半竟然通过配置自检（退出码 0）"
        }
        if ($out -match 'password but no username') {
            Write-Ok "错误信息说明了缺的是用户名"
        } else {
            Write-Bad "错误信息未说明原因"
        }
        # 🔐 绝不能回显口令
        if ($out -notmatch 'SECRETPW') {
            Write-Ok "错误信息未回显口令（已脱敏）"
        } else {
            Write-Bad "错误信息回显了口令！"
        }

        # 反向保护：三种合法写法必须通过
        foreach ($case in @(
            @{n='纯匿名';     v='proxy-server socks5://127.0.0.1:1080 -name p'},
            @{n='只有用户名'; v='proxy-server socks5://user@127.0.0.1:1080 -name p'},
            @{n='用户名+口令';v='proxy-server socks5://user:pass@127.0.0.1:1080 -name p'}
        )) {
            $c2 = Write-Conf $d "bind 127.0.0.1:$($basePort + 2)`n$($case.v)`nserver 223.5.5.5 -proxy p`n" 'ok.conf'
            & $exe test -c $c2 *> $null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "合法写法「$($case.n)」仍被接受"
            } else {
                Write-Bad "合法写法「$($case.n)」被误拒（收紧过头）"
            }
        }
    } else { Write-Skip "问题 38（被 Filter 排除）" }

    # =====================================================================
    Write-Section "问题 39：明文 http 名单必须被拒绝"
    if (Should-Run '39') {
        $d = New-CaseDir 'p39'
        $conf = Write-Conf $d @"
bind 127.0.0.1:$($basePort + 3)
server 223.5.5.5
domain-set -name evil -type list -url http://127.0.0.1:9/list.txt
domain-rules /domain-set:evil/ -address #6
"@
        $out = & $exe test -c $conf 2>&1 | Out-String
        if ($out -match 'plaintext http is not allowed') {
            Write-Ok "明文 http 名单被明确拒绝（并说明原因）"
        } else {
            Write-Bad "明文 http 名单未被拒绝"
        }

        # 对照：https 应照常尝试（不是被协议校验挡住）
        $c2 = Write-Conf $d @"
bind 127.0.0.1:$($basePort + 3)
server 223.5.5.5
domain-set -name ok -type list -url https://127.0.0.1:9/list.txt
domain-rules /domain-set:ok/ -address #6
"@ 'https.conf'
        $out2 = & $exe test -c $c2 2>&1 | Out-String
        if ($out2 -notmatch 'plaintext http is not allowed') {
            Write-Ok "https 名单未被协议校验误拦（行为区分正确）"
        } else {
            Write-Bad "https 名单被误拦"
        }
    } else { Write-Skip "问题 39（被 Filter 排除）" }

    # =====================================================================
    Write-Section "问题 41-③：log-size 0 不得每行归档"
    if (Should-Run '41') {
        $d = New-CaseDir 'p413'
        $port = $basePort + 4
        # 注意：必须写 `0K` 带单位；裸 `0` 会被配置解析器判为"未识别行"，到不了守卫
        $conf = Write-Conf $d @"
bind 127.0.0.1:$port
server 223.5.5.5
address /local.test/10.11.12.13
log-file $($d -replace '\\','/')/logs/smartdns.log
log-level info
log-size 0K
log-num 5
log-console no
"@
        $p = Start-Dns -ConfPath $conf -WorkingDir $d
        Start-Sleep -Milliseconds 1000

        $count = (Get-ChildItem (Join-Path $d 'logs') -File).Count
        if ($count -eq 1) {
            Write-Ok "log-size 0K 只产生 1 个日志文件（未每行归档）"
        } else {
            Write-Bad "log-size 0K 产生了 $count 个文件（应为 1，说明每行都在归档）"
        }

        # 告警应出现在 stderr（守卫在日志系统初始化前执行，只能用 eprintln）
        Stop-All
        $err = Get-ChildItem (Join-Path $d 'logs') -File -ErrorAction SilentlyContinue
        if ($err.Count -eq 1) {
            Write-Ok "（附带）目录中仅有活动日志文件"
        }
    } else { Write-Skip "问题 41-③（被 Filter 排除）" }

    # =====================================================================
    Write-Section "问题 40：外部轮转后日志必须自愈"
    if (Should-Run '40') {
        $d = New-CaseDir 'p40'
        $port = $basePort + 5
        $logDir = Join-Path $d 'logs'
        $conf = Write-Conf $d @"
bind 127.0.0.1:$port
server 223.5.5.5
address /local.test/10.11.12.13
log-file $($d -replace '\\','/')/logs/smartdns.log
log-level info
log-size 1K
log-num 5
log-console no
"@
        # ⚠️ 必须用 debug 级制造持续日志写入：info 级下查询【不产生日志】，
        #    那样"改名后没重建"只是"没有新日志行"，不是产品缺陷（第一版就踩了这个坑）
        Start-Dns -ConfPath $conf -WorkingDir $d -Verbose2 -PidFile (Join-Path $d 'pid') | Out-Null

        # 先撑出若干归档
        for ($i = 0; $i -lt 60; $i++) { Invoke-Query -Port $port -Name 'local.test' | Out-Null }
        Start-Sleep -Milliseconds 800

        $active = Join-Path $logDir 'smartdns.log'
        if (-not (Test-Path $active)) {
            Write-Bad "未生成活动日志文件，无法继续验证"
        } else {
            $sizeBefore = (Get-Item $active).Length

            # 模拟外部 logrotate：改名搬走，【不】建新文件
            $rotated = Join-Path $logDir 'smartdns.log.rotated'
            Move-Item $active $rotated -Force

            for ($i = 0; $i -lt 80; $i++) { Invoke-Query -Port $port -Name 'local.test' | Out-Null }
            Start-Sleep -Milliseconds 1000

            if (Test-Path $active) {
                $sizeAfter = (Get-Item $active).Length
                if ($sizeAfter -gt 0) {
                    Write-Ok "外部改名后日志自愈：活动文件已重建（$sizeAfter 字节）"
                } else {
                    Write-Bad "活动文件重建了但为空"
                }
            } else {
                Write-Bad "外部改名后活动日志【未重建】—— 日志永久停写（原缺陷复现）"
            }

            # 被搬走的文件内容不得被破坏
            if (Test-Path $rotated) {
                $rotSize = (Get-Item $rotated).Length
                if ($rotSize -ge $sizeBefore) {
                    Write-Ok "被外部搬走的文件内容保留（$rotSize 字节）"
                } else {
                    Write-Bad "被搬走的文件被破坏（$rotSize < $sizeBefore）"
                }
            } else {
                Write-Bad "被外部搬走的文件消失了（自愈不得删改外部文件）"
            }
        }
        Stop-All
    } else { Write-Skip "问题 40（被 Filter 排除）" }

    # =====================================================================
    Write-Section "回归：审计档不被日志轮转误删（问题 9）"
    if (Should-Run 'reg' -or [string]::IsNullOrEmpty($Filter)) {
        $d = New-CaseDir 'reg9'
        $port = $basePort + 6
        $conf = Write-Conf $d @"
bind 127.0.0.1:$port
server 223.5.5.5
address /audit-reg.test/1.2.3.4
log-file $($d -replace '\\','/')/logs/smartdns.log
log-level info
log-size 1K
log-num 2
log-console no
audit-enable yes
audit-file $($d -replace '\\','/')/logs/smartdns-audit.log
audit-size 1K
audit-num 2
"@
        Start-Dns -ConfPath $conf -WorkingDir $d -Verbose2 -PidFile (Join-Path $d 'pid') | Out-Null
        for ($i = 0; $i -lt 80; $i++) { Invoke-Query -Port $port -Name 'audit-reg.test' | Out-Null }
        Start-Sleep -Milliseconds 1000

        $audit = Join-Path $d 'logs\smartdns-audit.log'
        if (Test-Path $audit) {
            Write-Ok "日志与审计同目录、log-num=2 时，审计档未被日志轮转删掉"
        } else {
            Write-Bad "审计档被日志轮转误删（问题 9 回归失败）"
        }

        # 日志归档数应受 log-num 约束
        #
        # ⚠️ 过滤条件必须精确，否则会把审计档算进来（第一版就写错了）：
        #   日志归档形如 `smartdns-<日期>-<时间>.log`；审计档是 `smartdns-audit.log`，
        #   它也满足 `smartdns-*`（有连字符），所以只排除 `smartdns-audit-*` 是不够的 ——
        #   活动的审计档不带时间戳，会漏进来被误算成"日志归档"。
        #   这里用正则严格匹配"基名-纯数字-纯数字.log"这一种形态。
        $archiveRe = '^smartdns-\d+-\d+\.log$'
        $logArchives = @(Get-ChildItem (Join-Path $d 'logs') -File |
            Where-Object { $_.Name -match $archiveRe })
        if ($logArchives.Count -le 2) {
            Write-Ok "日志归档数受 log-num 约束（$($logArchives.Count) 份）"
        } else {
            Write-Bad "日志归档数超出 log-num（$($logArchives.Count) 份）: $(($logArchives | ForEach-Object Name) -join ', ')"
        }
        Stop-All
    } else { Write-Skip "审计档回归（被 Filter 排除）" }

    # =====================================================================
    Write-Section "问题 41-①：日志指标在管理接口可见"
    if (Should-Run '41api') {
        $d = New-CaseDir 'p41api'
        $port = $basePort + 7
        $apiPort = $port + 100
        $conf = Write-Conf $d @"
bind 127.0.0.1:$port
bind-http 127.0.0.1:$apiPort
api-token e2etoken0123456789
server 223.5.5.5
log-file $($d -replace '\\','/')/logs/smartdns.log
log-level info
"@
        Start-Dns -ConfPath $conf -WorkingDir $d | Out-Null
        try {
            $r = Invoke-RestMethod -Uri "http://127.0.0.1:$apiPort/api/system/status" `
                -Headers @{ Authorization = 'Bearer e2etoken0123456789' } -TimeoutSec 5
            $hasAll = ($null -ne $r.log_dropped) -and ($null -ne $r.log_write_failed) -and ($null -ne $r.log_flush_failed)
            if ($hasAll) {
                Write-Ok "管理接口暴露日志指标（dropped=$($r.log_dropped) write_failed=$($r.log_write_failed) flush_failed=$($r.log_flush_failed)）"
            } else {
                Write-Bad "管理接口缺少日志指标字段"
            }
        } catch {
            Write-Bad "管理接口调用失败: $($_.Exception.Message)"
        }
        Stop-All
    } else { Write-Skip "日志指标接口（被 Filter 排除）" }

} finally {
    Stop-All
}

# ---------- 汇总 ----------
Write-Host "`n" -NoNewline
Write-Host ("=" * 56) -ForegroundColor White
Write-Host "汇总: $script:Pass 通过 / $script:Fail 失败 / $script:Skip 跳过" -ForegroundColor White
if ($script:Fail -gt 0) {
    Write-Host "`n失败项:" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

if (-not $KeepTemp) {
    Remove-Item -Recurse -Force $tempRoot -ErrorAction SilentlyContinue
} else {
    Write-Host "临时目录保留于: $tempRoot" -ForegroundColor Yellow
}

exit $(if ($script:Fail -gt 0) { 1 } else { 0 })
