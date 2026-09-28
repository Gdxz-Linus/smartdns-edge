# 问题 48 真机语法校验：把 Rust 侧**真实生成**的 PowerShell 服务命令
# 交给 PowerShell 自己的解析器，确认语法正确。
#
# ## 为什么不能只靠 Rust 单元测试
#
# 服务安装命令是一大段拼出来的 PowerShell 脚本（含 `format!` 转义、嵌套花括号）。
# "拼装没 panic"不等于"PowerShell 能解析"——
# 修改过程中我曾误用 C 风格的 `/* */` 注释（PowerShell 不支持），
# 那会让 `service install` **整条命令语法错误**。
# 只有 PowerShell 的解析器能回答"这段脚本合法吗"。
#
# ## 用法
#
# ```powershell
# # 先生成命令文件
# cargo test --offline --bin smartdns export_generated_powershell_commands
# # 再校验语法
# pwsh -NoProfile -File .\tests\e2e\_p48_ps_syntax.ps1
# ```
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dir = Join-Path $root 'target\p48-service-commands'

if (-not (Test-Path $dir)) {
    Write-Host "找不到命令导出目录: $dir"
    Write-Host "请先运行: cargo test --offline --bin smartdns export_generated_powershell_commands"
    exit 1
}

Write-Host "===== 问题 48：服务命令的 PowerShell 语法校验 ====="
Write-Host "目录: $dir"
Write-Host ""

$files = Get-ChildItem -Path $dir -Filter '*.ps1'
if (-not $files) {
    Write-Host "目录里没有 .ps1 文件 —— 导出步骤可能没跑成功"
    exit 1
}

$failed = 0
foreach ($f in $files) {
    $text = Get-Content $f.FullName -Raw
    $ok = $true

    # ① 静态检查：**不得出现 C 风格注释**。
    #
    # ⚠️ 这一步不能省，理由是有过实测教训：
    # `/* */` 在 PowerShell 里**不是注释**，而是"除法 `/` + 乘法 `*`"的运算符组合。
    # 在某些位置（例如两条语句之间）它居然能**语法解析通过**，
    # 只在**运行时**才报"必须在 / 运算符后提供值表达式"。
    # 所以只靠下面的 ParseInput 会漏掉它 —— 必须单独静态禁止。
    # （这正是"测试没盖住真实场景"的又一例，必须用两种手段合起来。）
    if ($text -match '/\*' -or $text -match '\*/') {
        Write-Host "  [FAIL] $($f.Name) —— 含 C 风格注释 `/* */`（PowerShell 不支持，运行时会报错）"
        $ok = $false
        $failed++
    }

    # ② 用 PowerShell 自己的解析器检查语法
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors) | Out-Null

    if ($errors -and $errors.Count -gt 0) {
        Write-Host "  [FAIL] $($f.Name) —— 有 $($errors.Count) 处语法错误"
        foreach ($e in $errors) {
            Write-Host "         $($e.Message)"
            Write-Host "         位置: $($e.Extent.StartLineNumber):$($e.Extent.StartColumnNumber)"
        }
        $ok = $false
        $failed++
    }

    if ($ok) {
        Write-Host "  [PASS] $($f.Name) —— 语法正确"
    }
}

Write-Host ""
Write-Host "========================================================"
if ($failed -eq 0) {
    Write-Host "汇总: $($files.Count) 条命令全部语法正确"
    exit 0
} else {
    Write-Host "汇总: $failed 条命令存在语法错误（服务安装/管理会失败）"
    exit 1
}
