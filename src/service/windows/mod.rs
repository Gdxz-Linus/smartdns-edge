use std::{
    borrow::Cow,
    ffi::OsString, // 🌟 修复警告：删除了多余的 OsStr
};

use super::{
    SERVICE_NAME,
    installer::{InstallStrategy::*, Installer, UninstallStrategy::*},
    service_manager::{ServiceCommand, ServiceCommands, ServiceDefinition},
};

mod shell_escape;
mod windows_service;

pub const CONF_PATH: &str = "smartdns.conf";

pub use self::windows_service::run;

#[inline]
pub(super) fn create_service_definition() -> ServiceDefinition {
    let current_exe =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("smartdns.exe"));
    let current_dir = current_exe
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let conf_path_abs = current_dir.join("smartdns.conf");

    // 🌟 新增这一行：提取 exe 的绝对路径，后面配置防火墙要用
    // 🔐 P2：这个路径要插进 PowerShell 的**双引号**字符串里（下面两条防火墙规则），
    // 其中的 ` 、$ 、" 都会改变命令含义（`$` 会被当变量展开），先转义再拼。
    let exe_path_str = current_exe
        .to_string_lossy()
        .replace('`', "``")
        .replace('$', "`$")
        .replace('"', "`\"");

    let installer = Installer::builder()
        // 🌟 修复编译报错：加上 .as_bytes()，满足 Rust 的强类型检查
        .add_item((
            conf_path_abs.as_path(),
            crate::DEFAULT_CONF.as_bytes(),
            Preserve,
            Keep,
        ))
        .build();

    let mut bin_path = OsString::new();

    bin_path.push(shell_escape::escape(Cow::Borrowed(current_exe.as_os_str())));

    for arg in &[
        OsString::from("run"),
        OsString::from("-c"),
        OsString::from(conf_path_abs.as_os_str()),
        #[cfg(windows)]
        OsString::from("--ws7642ea814a90496daaa54f2820254f12"),
    ] {
        bin_path.push(" ");
        bin_path.push(shell_escape::escape(Cow::Borrowed(arg)));
    }

    let commands = ServiceCommands {
        // 🔐 问题 48：这一批改动集中在这里，**三处静默**逐条收口。
        //
        // ⚠️ 注意：PowerShell **不支持 C 风格的 `/* */` 注释**，
        // 所以下面的说明都写在 Rust 这一侧，命令字符串里保持干净
        // （往命令里塞注释会让它直接语法错误、安装失败）。
        //
        // ① `sc.exe privs` 的输出原来被 `| Out-Null` 丢弃 ——
        //    授予 SeChangeNotifyPrivilege / SeCreateGlobalPrivilege /
        //    SeImpersonatePrivilege 是服务正常运行的前提，失败时用户**完全看不到**，
        //    只会在日后遇到"服务因缺权限而行为异常"这种难查的问题。
        //    现在检查退出码并明确告警（**不中止安装**：缺权限的服务多数场景仍能跑，
        //    是否处理交给用户判断）。
        //
        // ② 防火墙规则创建原来用 `-ErrorAction SilentlyContinue` ——
        //    "没建出来"与"建出来了"在输出上完全一样。而端口被防火墙挡住时，
        //    用户看到的是"服务在跑但客户端解析不了"，根本想不到是防火墙。
        //    现在改为 `-ErrorAction Stop` + `try/catch` 收集错误，明确告警并给出补救命令。
        //
        // ③ 卸载注释与行为不符（见下面的说明），已改注释。
        install: Some(ServiceCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "[Console]::OutputEncoding =[System.Text.Encoding]::UTF8; \
                     $ErrorActionPreference = 'Continue'; \
                     $out = sc.exe create {SERVICE_NAME} type= own start= auto depend= Tcpip/Afd binpath= '{bin_path_str}' displayname= '{NAME}'; \
                     if ($LASTEXITCODE -ne 0) {{ Write-Output $out; exit 1 }} \
                     $privs = sc.exe privs {SERVICE_NAME} SeChangeNotifyPrivilege/SeCreateGlobalPrivilege/SeImpersonatePrivilege 2>&1; \
                     if ($LASTEXITCODE -ne 0) {{ \
                         Write-Output \"`n⚠️  Warning: failed to grant service privileges (sc.exe privs returned $LASTEXITCODE).\"; \
                         Write-Output \"   The service may still run, but some operations can fail. Output: $privs\"; \
                     }} \
                     $desc = 'SmartDNS local DNS server, providing fast, secure and pollution-free domain name resolution.'; \
                     sc.exe description {SERVICE_NAME} \"$desc\" | Out-Null; \
                     $fwMsg = ''; \
                     foreach ($dir in @('Inbound', 'Outbound')) {{ \
                         try {{ \
                             New-NetFirewallRule -DisplayName \"{NAME}\" -Direction $dir -Program \"{exe_path_str}\" -Action Allow -ErrorAction Stop | Out-Null; \
                         }} catch {{ \
                             $fwMsg += \"$dir($($_.Exception.Message)); \"; \
                         }} \
                     }} \
                     if ($fwMsg -ne '') {{ \
                         Write-Output \"`n⚠️  Warning: could not create all firewall rules: $fwMsg\"; \
                         Write-Output \"   Clients may be unable to reach DNS until you allow this program manually\"; \
                         Write-Output \"   (or add it yourself: New-NetFirewallRule -DisplayName '{NAME}' -Direction Inbound -Program '{exe_path_str}' -Action Allow).\"; \
                     }} \
                     Write-Output \"`n✅ SmartDNS service installed successfully.\";",
                    SERVICE_NAME = SERVICE_NAME,
                    // 🔐 P2：PowerShell 单引号字符串里，单引号要写两遍才不会被当成字符串结束 ——
                    // 原来原样插入，exe 路径含 `'` 时命令被破坏（甚至可被注入）。
                    bin_path_str = bin_path.to_string_lossy().replace('\'', "''"),
                    NAME = crate::NAME,
                    exe_path_str = exe_path_str
                ).into(),
            ],
        }),

        // 🔐 问题 48（其三）：**注释与行为必须一致**。
        //
        // 原来的注释写的是「卸载时先强杀进程，清防火墙，再删除服务」，
        // 但实现里**从来没有"强杀进程"这一步** —— 只做了 Stop-Service。
        // 注释与行为不符会持续误导后来者（以为有兜底、于是不去看 Stop 是否失败）。
        //
        // 这里的选择是**改注释、不改行为**：不强杀进程。
        // 理由：`Stop-Service` 本身就带 `-WarningAction SilentlyContinue`，
        // 若它没能停住服务，`sc.exe delete` 会把服务标记为"删除待定"，
        // 由系统在进程退出后完成删除 —— 这是 Windows 的正常语义，
        // 不需要也不应该由我们去强杀（强杀会跳过日志排空与缓存落盘，
        // 正是问题 47 花力气避免的事）。
        uninstall: Some(ServiceCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
                     Stop-Service -Name {SERVICE_NAME} -WarningAction SilentlyContinue -ErrorAction SilentlyContinue; \
                     Remove-NetFirewallRule -DisplayName \"{NAME}\" -ErrorAction SilentlyContinue | Out-Null; \
                     $out = sc.exe delete {SERVICE_NAME}; \
                     if ($LASTEXITCODE -eq 0) {{ Write-Output \"`n🗑️ SmartDNS service uninstalled successfully.`n\" }} \
                     else {{ Write-Output \"$out\"; exit 1 }}",
                    SERVICE_NAME = SERVICE_NAME,
                    NAME = crate::NAME
                ).into()
            ],
        }),

        // 🌟 终极修复：使用 Start-Service，自带友好的错误捕获
        start: ServiceCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
                     Start-Service -Name {SERVICE_NAME}; \
                     if ($?) {{ Write-Output \"`n▶️ SmartDNS service started successfully.`n\" }} \
                     else {{ exit 1 }}",
                    SERVICE_NAME = SERVICE_NAME
                ).into()
            ],
        },

        // 🌟 终极修复：Stop-Service 是同步阻塞的！它会耐心等待服务彻底停稳，杜绝重启时的竞态条件报错！
        stop: ServiceCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
                     Stop-Service -Name {SERVICE_NAME}; \
                     if ($?) {{ Write-Output \"`n⏹️ SmartDNS service stopped successfully.`n\" }} \
                     else {{ exit 1 }}",
                    SERVICE_NAME = SERVICE_NAME
                ).into()
            ],
        },

        // 🌟 终极修复：利用 PowerShell 原生的 Restart-Service 实现原子级平滑重启！
        restart: Some(ServiceCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
                     Restart-Service -Name {SERVICE_NAME}; \
                     if ($?) {{ Write-Output \"`n🔄 SmartDNS service restarted successfully.`n\" }} \
                     else {{ exit 1 }}",
                    SERVICE_NAME = SERVICE_NAME
                ).into()
            ],
        }),

        // 🌟 终极修复：抛弃原始丑陋的 sc query 文本，改用 PowerShell 面向对象查询！
        // 免疫 Windows 中英文语言差异，并输出带有状态指示灯 (🟢/🔴) 的专业级人类友好排版！
        status: Some(ServiceCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
                     $s = Get-Service -Name {SERVICE_NAME} -ErrorAction SilentlyContinue; \
                     if (-not $s) {{ \
                         Write-Output \"`n❌ SmartDNS service is NOT installed.\"; \
                         Write-Output \"   Hint: Install it via 'smartdns service install'`n\"; \
                         exit 2; \
                     }} \
                     if ($s.Status -eq 'Running') {{ \
                         Write-Output \"`n● SmartDNS Service ({SERVICE_NAME})\"; \
                         Write-Output \"  Status:  RUNNING  (🟢)\"; \
                         Write-Output \"  Type:    Standalone Process`n\"; \
                         exit 0; \
                     }} else {{ \
                         Write-Output \"`n○ SmartDNS service ({SERVICE_NAME})\"; \
                         Write-Output \"  Status:  STOPPED  (🔴)\"; \
                         Write-Output \"  Hint:    Start it via 'smartdns service start'`n\"; \
                         exit 1; \
                     }}",
                    SERVICE_NAME = SERVICE_NAME
                ).into()
            ],
        }),
    };

    ServiceDefinition::new(crate::NAME.to_string(), installer, commands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// 🔐 问题 48：把**真实生成的**服务安装命令导出成文件，供语法校验。
    ///
    /// ## 为什么需要这条测试
    ///
    /// 服务安装命令是一大段拼出来的 PowerShell 脚本，里面还嵌了 Rust 的
    /// `format!`、转义与花括号。这类"字符串里套字符串"的代码**极易写错**，
    /// 而写错的后果很直接：用户执行 `service install` 时**整条命令语法错误、安装失败**。
    ///
    /// 本轮修改（问题 48）往命令里加了 `try/catch`、`foreach` 与多个变量，
    /// 正是最容易出错的地方 —— 我在第一版里甚至误用了 C 风格的 `/* */` 注释
    /// （PowerShell 不支持），那会让命令直接报错。所以必须有一条**机器校验**。
    ///
    /// ## 它怎么校验
    ///
    /// 这里只负责把命令**原样写出来**（Rust 侧能保证的是"拼装没 panic"）；
    /// 真正的语法校验由 PowerShell 的解析器完成：
    ///
    /// ```powershell
    /// pwsh -NoProfile -File .\tests\e2e\_p48_ps_syntax.ps1
    /// ```
    ///
    /// 那个脚本会对导出的每条命令调用
    /// `[System.Management.Automation.Language.Parser]::ParseInput()`，
    /// **任何语法错误都会被报出来**。
    ///
    /// ⚠️ 之所以分成两步：Rust 测试里无法可靠地调用 PowerShell 解析器
    /// （要起子进程、还要处理路径与编码），而"能不能解析"这件事
    /// 本来就应该由 PowerShell 自己回答。
    #[test]
    fn export_generated_powershell_commands_for_syntax_check() {
        let def = create_service_definition();

        let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("p48-service-commands");
        std::fs::create_dir_all(&out_dir).expect("应当能创建导出目录");

        let mut exported = Vec::new();
        let cmds: [(&str, Option<&ServiceCommand>); 6] = [
            ("install", def.commands().install.as_ref()),
            ("uninstall", def.commands().uninstall.as_ref()),
            ("status", def.commands().status.as_ref()),
            ("start", Some(&def.commands().start)),
            ("stop", Some(&def.commands().stop)),
            ("restart", def.commands().restart.as_ref()),
        ];

        for (name, cmd) in cmds {
            let Some(cmd) = cmd else { continue };

            // 只导出 powershell 的命令（其它平台/形式不参与本次校验）
            if !cmd.program.to_string_lossy().contains("powershell") {
                continue;
            }

            // `-Command` 后面那一段就是实际脚本
            let script = cmd
                .args
                .iter()
                .skip_while(|a| a.to_string_lossy() != "-Command")
                .nth(1)
                .map(|a| a.to_string_lossy().into_owned());

            let Some(script) = script else { continue };

            let path = out_dir.join(format!("{name}.ps1"));
            std::fs::write(&path, &script).expect("应当能写出命令文件");
            exported.push(name);
        }

        assert!(
            !exported.is_empty(),
            "应当至少导出 install 一条命令用于语法校验"
        );
        // 把导出结果打到测试输出里，便于人工确认
        eprintln!(
            "已导出 {} 条 PowerShell 命令到 {}: {:?}",
            exported.len(),
            out_dir.display(),
            exported
        );
    }

    /// 🔐 问题 48：**命令里不得出现 PowerShell 不支持的 C 风格注释**。
    ///
    /// 这条是有来历的：修改过程中我一度在命令字符串里写了
    /// `/* ... */`（那是 C / Rust 的注释语法），
    /// 而 PowerShell 里 `/*` 会被当成**路径或运算符**——
    /// 整条安装命令直接语法错误。
    ///
    /// 用一条廉价但精准的断言把这类错误挡在提交之前。
    #[test]
    fn generated_powershell_commands_contain_no_c_style_comments() {
        let def = create_service_definition();

        let all: [(&str, Option<&ServiceCommand>); 6] = [
            ("install", def.commands().install.as_ref()),
            ("uninstall", def.commands().uninstall.as_ref()),
            ("status", def.commands().status.as_ref()),
            ("start", Some(&def.commands().start)),
            ("stop", Some(&def.commands().stop)),
            ("restart", def.commands().restart.as_ref()),
        ];

        for (name, cmd) in all {
            let Some(cmd) = cmd else { continue };

            for arg in &cmd.args {
                let text = arg.to_string_lossy();
                assert!(
                    !text.contains("/*") && !text.contains("*/"),
                    "🔐 问题 48：`{name}` 命令里出现了 C 风格的注释 `/* */` —— \
                     PowerShell 不支持该语法，安装/管理命令会直接语法错误。\
                     说明应当写在 Rust 侧的注释里，不要塞进命令字符串。\
                     实际内容片段: {}",
                    &text[..text.len().min(200)]
                );
            }
        }
    }

    /// 🔐 问题 48：**三处静默都收到了命令里**（用存在性断言钉住，避免日后回退）。
    ///
    /// 这类"加固是否还在"的断言看起来琐碎，但它的价值在于：
    /// 日后有人重写这段命令时，若把 `-ErrorAction Stop` 改回
    /// `SilentlyContinue`、或把 `sc.exe privs` 又接上 `| Out-Null`，
    /// 测试会立刻失败并指出是哪一处。
    #[test]
    fn install_command_keeps_the_failure_visibility_fixes() {
        let def = create_service_definition();
        let install = def
            .commands()
            .install
            .as_ref()
            .expect("Windows 服务定义必须有 install 命令");

        let script: String = install
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");

        // ① sc.exe privs 的结果不能再被丢弃
        assert!(
            !script.contains("sc.exe privs")
                || !script.contains("privs {SERVICE_NAME}) | Out-Null")
                    && !script.contains("SeImpersonatePrivilege | Out-Null"),
            "🔐 问题 48：`sc.exe privs` 的输出又被 `| Out-Null` 吞了 —— \
             授予权限失败时用户将完全看不到"
        );
        assert!(
            script.contains("failed to grant service privileges"),
            "🔐 问题 48：`sc.exe privs` 失败时应当有明确告警"
        );

        // ② 防火墙规则失败不能再静默
        assert!(
            script.contains("could not create all firewall rules"),
            "🔐 问题 48：防火墙规则创建失败时应当有明确告警"
        );
        assert!(
            !script.contains("New-NetFirewallRule")
                || !script.contains("Action Allow -ErrorAction SilentlyContinue"),
            "🔐 问题 48：防火墙规则又变回 `-ErrorAction SilentlyContinue` —— \
             失败会重新变成静默"
        );
    }
}
