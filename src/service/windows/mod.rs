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
    let current_exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("smartdns.exe"));
    let current_dir = current_exe.parent().unwrap_or_else(|| std::path::Path::new(""));
    let conf_path_abs = current_dir.join("smartdns.conf");
	
	// 🌟 新增这一行：提取 exe 的绝对路径，后面配置防火墙要用
    let exe_path_str = current_exe.to_string_lossy(); 

    let installer = Installer::builder()
        // 🌟 修复编译报错：加上 .as_bytes()，满足 Rust 的强类型检查
        .add_item((conf_path_abs.as_path(), crate::DEFAULT_CONF.as_bytes(), Preserve, Keep))
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
        install: Some(ServiceCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "[Console]::OutputEncoding =[System.Text.Encoding]::UTF8; \
                     $out = sc.exe create {SERVICE_NAME} type= own start= auto depend= Tcpip/Afd binpath= '{bin_path_str}' displayname= '{NAME}'; \
                     if ($LASTEXITCODE -ne 0) {{ Write-Output $out; exit 1 }} \
                     sc.exe privs {SERVICE_NAME} SeChangeNotifyPrivilege/SeCreateGlobalPrivilege/SeImpersonatePrivilege | Out-Null; \
                     $desc = 'SmartDNS local DNS server, providing fast, secure and pollution-free domain name resolution.'; \
                     sc.exe description {SERVICE_NAME} \"$desc\" | Out-Null; \
                     New-NetFirewallRule -DisplayName \"{NAME}\" -Direction Inbound -Program \"{exe_path_str}\" -Action Allow -ErrorAction SilentlyContinue | Out-Null; \
                     New-NetFirewallRule -DisplayName \"{NAME}\" -Direction Outbound -Program \"{exe_path_str}\" -Action Allow -ErrorAction SilentlyContinue | Out-Null; \
                     Write-Output \"`n✅ SmartDNS service installed successfully.\";",
                    SERVICE_NAME = SERVICE_NAME,
                    bin_path_str = bin_path.to_string_lossy(),
                    NAME = crate::NAME,
                    exe_path_str = exe_path_str
                ).into(),
            ],
        }),
        
        // 🌟 终极修复：卸载时先强杀进程，清防火墙，再删除服务。
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