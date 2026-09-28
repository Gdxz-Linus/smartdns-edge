# 问题 50 真机验证（Windows）：
#   配置 `server <ip> -interface <不存在的网卡>` —— 修复前静默退回默认网卡，
#   修复后必须出现明确的告警（说明 `-device`/`-interface` 没生效）。
#
# 为什么必须在 Windows 上跑：这段"把网卡名翻译成本机 IP"的代码
# 只在**非 Linux** 平台编译（Linux 走内核的 SO_BINDTODEVICE，是另一条路径）。
#
# 用法：pwsh -NoProfile -File .\tests\e2e\_p50_device.ps1
# 要求：先 cargo build --offline --bin smartdns
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root 'target\debug\smartdns.exe'
if (-not (Test-Path $exe)) { throw "找不到 $exe，请先 cargo build --offline --bin smartdns" }

$tmp = Join-Path $env:TEMP ("p50-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# 高位端口，避开用户的 53
$port = 26901
$conf = Join-Path $tmp 'c.conf'

# 注意选项名是 `-interface`（不是 `-device`）：
# `-device` 会走到 "unknown server options" 分支，根本到不了连接建立路径。
@"
bind 127.0.0.1:$port
server 223.5.5.5 -interface nonexistent_netdev_xyz
log-file $tmp/smartdns.log
log-level debug
"@ | Set-Content -Path $conf -Encoding utf8

Write-Host "===== 问题 50 真机验证（Windows）====="
Write-Host "临时目录: $tmp"
Write-Host ""

$out = Join-Path $tmp 'out.txt'
$proc = Start-Process -FilePath $exe -ArgumentList 'run', '-c', $conf `
    -RedirectStandardOutput $out -RedirectStandardError (Join-Path $tmp 'err.txt') -PassThru

try {
    Start-Sleep -Seconds 3
    # 必须**真发一次查询**才会走到连接建立路径（否则连接根本没建，也没有绑定动作）
    & $exe resolve -s "127.0.0.1:$port" www.baidu.com > $null 2>&1
    Start-Sleep -Seconds 3
}
finally {
    if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(3000) | Out-Null }
}

$logs = @()
foreach ($f in @($out, (Join-Path $tmp 'smartdns.log'))) {
    if (Test-Path $f) { $logs += Get-Content $f }
}

Write-Host "--- 与网卡相关的日志 ---"
$hit = $logs | Select-String -Pattern 'device|interface'
if ($hit) { $hit | ForEach-Object { Write-Host "  $_" } } else { Write-Host "  （无）" }
Write-Host ""

$warned = $logs | Select-String -Pattern 'was not found|has no effect'
if ($warned) {
    Write-Host "判定: ✅ 网卡找不到时给出了明确告警（不再是静默退回默认网卡）"
} else {
    Write-Host "判定: ❌ 未见到告警 —— 绑定网卡失败仍然是静默的"
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-Host "已清理"
