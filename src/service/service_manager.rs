use std::{
    ffi::OsString,
    fmt::Display,
    io,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

// use regex::Regex;

use super::installer::Installer;
use crate::log::debug;

#[derive(Debug)]
pub struct ServiceDefinition {
    name: String,
    installer: Installer,
    commands: ServiceCommands,
}

impl ServiceDefinition {
    pub fn new(name: String, installer: Installer, commands: ServiceCommands) -> Self {
        Self {
            name,
            installer,
            commands,
        }
    }
}

#[derive(Debug)]
pub struct ServiceCommands {
    pub install: Option<ServiceCommand>,
    pub uninstall: Option<ServiceCommand>,
    pub status: Option<ServiceCommand>,
    pub start: ServiceCommand,
    pub stop: ServiceCommand,
    pub restart: Option<ServiceCommand>,
}

#[derive(Debug)]
pub struct ServiceManager {
    definition: ServiceDefinition,
}

impl From<ServiceDefinition> for ServiceManager {
    fn from(definition: ServiceDefinition) -> Self {
        Self { definition }
    }
}

impl ServiceManager {
    pub fn install(&self) -> io::Result<()> {
        // 🌟 P1-7 修复：只有"确实已经在运行"才算真的装好了。
        //
        // 原实现把"已停止"也算作"已安装"直接返回，而 Linux/macOS 上"服务根本不存在"
        // 又会被 status() 误读成"已停止"（退出码语义不同，见文件末尾的 classify_status），
        // 于是全新机器上执行 `service install` 只打印一句 "already installed" 就退出，
        // 装机动作整个没有发生。
        match self.status() {
            Ok(ServiceStatus::Running(_)) => {
                println!("💡 SmartDNS service is already installed and running.");
                return Ok(());
            }
            Ok(ServiceStatus::Dead(_)) => {
                // 已安装但没在跑：继续走安装流程（幂等重写文件 + 启动），
                // 这样"换了新二进制以后再 install 一次"也能真正生效。
                println!(
                    "ℹ️ SmartDNS service is installed but not running; reinstalling and starting it."
                );
            }
            Ok(ServiceStatus::NotInstalled) => {
                println!("ℹ️ SmartDNS service is not installed yet; installing now.");
            }
            _ => {}
        }

        let _ = self.uninstall(false, true);

        // install files.
        self.definition.installer.install()?;

        if let Some(install) = self.definition.commands.install.as_ref() {
            install.spawn()?;
        }

        self.start()?;
        Ok(())
    }

    pub fn uninstall(&self, purge: bool, quiet: bool) -> io::Result<()> {
        // 🌟 统一拦截：卸载空服务直接报错返回，绝不执行后续 PowerShell
        if matches!(self.status(), Ok(ServiceStatus::NotInstalled)) {
            if !quiet {
                // 🔐 B2：用户直接调用 `service uninstall` 时要给非 0 退出码；
                // quiet=true 是 install() 内部的"先卸再装"，它自己吞掉错误（`let _ =`），保持安静。
                eprintln!("❌ SmartDNS service is NOT installed.");
                return Err(not_installed_error());
            }
            return Ok(());
        }

        self.try_stop().unwrap_or_default();

        if let Some(uninstall) = self.definition.commands.uninstall.as_ref() {
            if quiet {
                let _ = uninstall.output();
            } else {
                let _ = uninstall.spawn();
            }
        }

        let _ = self.definition.installer.uninstall(purge)?;
        Ok(())
    }

    pub fn start(&self) -> io::Result<()> {
        match self.status() {
            Ok(ServiceStatus::Running(_)) => {
                println!("▶️ Service {} already started", self.definition.name);
            }
            Ok(ServiceStatus::NotInstalled) => {
                // 🔐 B2：提示之外必须**返回错误** —— 以前这里打印 ❌ 却仍返回 Ok，
                // `smartdns service start` 的退出码是 0，脚本/CI 会以为启动成功了。
                eprintln!("❌ SmartDNS service is NOT installed.");
                eprintln!("💡 Hint: Please install it via 'smartdns service install' first.");
                return Err(not_installed_error());
            }
            _ => {
                self.definition.commands.start.spawn()?;
            }
        }
        Ok(())
    }

    pub fn stop(&self) -> io::Result<()> {
        match self.status() {
            Ok(ServiceStatus::NotInstalled) => {
                // 🔐 B2：同 start —— 提示 + 非 0 退出码
                eprintln!("❌ SmartDNS service is NOT installed.");
                eprintln!("💡 Hint: Please install it via 'smartdns service install' first.");
                return Err(not_installed_error());
            }
            Ok(ServiceStatus::Dead(_)) => {
                println!("⏹️ Service {} already stopped", self.definition.name);
            }
            _ => {
                self.definition.commands.stop.spawn()?;
            }
        }
        Ok(())
    }

    pub fn try_stop(&self) -> io::Result<()> {
        // 🌟 核心修正：只在“运行中”才去执行停止动作，避免多重报错！
        if matches!(self.status(), Ok(ServiceStatus::Running(_))) {
            self.definition.commands.stop.spawn()?;
        }
        Ok(())
    }

    pub fn restart(&self) -> io::Result<()> {
        if matches!(self.status(), Ok(ServiceStatus::NotInstalled)) {
            // 🔐 B2：同 start/stop
            eprintln!("❌ SmartDNS service is NOT installed.");
            eprintln!("💡 Hint: Please install it via 'smartdns service install' first.");
            return Err(not_installed_error());
        }

        match self.definition.commands.restart.as_ref() {
            Some(restart) => {
                restart.spawn()?;
            }
            None => {
                self.try_stop().unwrap_or_default();
                std::thread::sleep(Duration::from_millis(500));
                self.start()?;
            }
        }
        Ok(())
    }

    pub fn status(&self) -> io::Result<ServiceStatus> {
        let status = match self.definition.commands.status.as_ref() {
            Some(cmd) => {
                let output = cmd.output()?;

                // 🌟 P1-7 修复：各平台对"退出码"的约定根本不一样，不能再一律按
                // Windows 自建脚本的 0/1/2 去解读（systemd/LSB 把"未找到该服务"编成 4、
                // "已停止"编成 3，于是全落进兜底分支被判成 Dead）。
                // 另外"服务不存在"这句话有时只出现在 stderr 里，所以两股输出一起看。
                let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.trim().is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(stderr.trim());
                }

                match classify_status(
                    StatusCodeConvention::for_current_os(),
                    output.status.code(),
                    output.status.success(),
                    &text,
                ) {
                    ServiceStatusKind::Running => ServiceStatus::Running(output),
                    ServiceStatusKind::Dead => ServiceStatus::Dead(output),
                    ServiceStatusKind::NotInstalled => ServiceStatus::NotInstalled,
                }
            }
            None => ServiceStatus::Unknown,
        };
        Ok(status)
    }
}

#[derive(Debug)]
pub struct ServiceCommand {
    /// Path to the service manager program to run
    ///
    /// E.g. `/usr/local/bin/my-program`
    pub program: PathBuf,

    /// Arguments to use for the program
    ///
    /// E.g. `--arg`, `value`, `--another-arg`
    pub args: Vec<OsString>,
}

impl Display for ServiceCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.program.display())?;
        for arg in self.args.iter() {
            write!(f, " {}", arg.to_string_lossy())?
        }
        Ok(())
    }
}

impl ServiceCommand {
    #[inline]
    pub fn spawn(&self) -> io::Result<()> {
        let output = self.output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            if !stdout.trim().is_empty() {
                println!("{}", stdout.trim());
            }
            Ok(())
        } else {
            let mut msg = String::new();
            if !stdout.trim().is_empty() {
                msg.push_str(stdout.trim());
            }
            if !stderr.trim().is_empty() {
                if !msg.is_empty() {
                    msg.push('\n');
                }
                msg.push_str(stderr.trim());
            }
            if msg.trim().is_empty() {
                msg = "Failed".to_string();
            }

            // 🌟 核心修复 3：彻底拔除那个丑陋的 ❌ Error executing ... 前缀！
            // 让终端直接原汁原味地输出我们在 PowerShell 里精心排版的指导语！
            eprintln!("{}", msg);
            Err(io::Error::other("Command failed"))
        }
    }

    #[inline]
    pub fn output(&self) -> io::Result<std::process::Output> {
        debug!("># {}", self);
        self.to_command().output()
    }

    fn to_command(&self) -> Command {
        let mut command: Command = self.into();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

impl From<&ServiceCommand> for Command {
    fn from(cmd: &ServiceCommand) -> Self {
        let mut command = Command::new(cmd.program.as_path());
        command.args(cmd.args.iter());
        command
    }
}

impl From<ServiceCommand> for Command {
    #[inline]
    fn from(cmd: ServiceCommand) -> Self {
        Self::from(&cmd)
    }
}

#[derive(Debug)]
pub enum ServiceStatus {
    Running(std::process::Output),
    Dead(std::process::Output),
    NotInstalled, // 🌟 新增：专门识别未安装状态
    Unknown,
}

/// 🌟 P1-7：各平台服务管理器对"退出码"的约定并不相同，必须分开解读。
///
/// 原实现一律按 Windows 自建脚本的 0/1/2 去解读，导致 Linux 上"服务不存在"（systemctl
/// 返回 4）和"装了但停了"（返回 3）都落进兜底分支被判成"已停止"，于是
/// `service install` 在全新机器上只会打印 "already installed" 就退出。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCodeConvention {
    /// Windows 自建 PowerShell 脚本：0=运行中，1=已停止，2=未安装
    WindowsScript,
    /// systemd 与 LSB init 脚本：0=运行中，3=已停止（单元存在），4=未找到该服务
    SystemdLsb,
    /// launchd：退出码不可靠，只能看输出文本
    Launchd,
}

impl StatusCodeConvention {
    /// 当前平台使用的约定。
    pub const fn for_current_os() -> Self {
        if cfg!(target_os = "windows") {
            Self::WindowsScript
        } else if cfg!(target_os = "macos") {
            Self::Launchd
        } else {
            // Linux/Android：systemd 或 initd（见 service/linux/mod.rs），
            // runit 环境也退回 initd 实现，语义一致。
            Self::SystemdLsb
        }
    }
}

/// 状态分类的中间结果（`ServiceStatus` 要携带原始 Output，不便比较，故先分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceStatusKind {
    Running,
    Dead,
    NotInstalled,
}

/// 输出里出现这些片段（不区分大小写），就说明"服务不存在 / 未安装"。
///
/// 逐条都有出处，不是随手联想：
/// - `not installed`                       → 本项目 Windows 脚本自己的措辞
/// - `could not find service`              → launchctl list（macOS）
/// - `could not be found` / `not-found`    → systemctl status（单元不存在）
/// - `failed to get unit`                  → systemctl 的另一种报法
/// - `unable to change to service directory` → runit `sv status`（Termux 等）
/// - `no such process`                     → launchctl / 部分 init 脚本
const NOT_INSTALLED_HINTS: &[&str] = &[
    "not installed",
    "could not find service",
    "could not be found",
    "not-found",
    "failed to get unit",
    "unable to change to service directory",
    "no such process",
];

fn text_says_not_installed(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    NOT_INSTALLED_HINTS.iter().any(|hint| lower.contains(hint))
}

/// 把"某个平台约定下的退出码 + 输出文本"翻译成服务状态。
///
/// 判定顺序：
/// 1. 文本里明确写着"服务不存在" —— 这是最强的证据，优先采信
///    （systemd 有时给出的退出码会随版本变化，文本能兜住）；
/// 2. 按当前平台的退出码约定翻译；
/// 3. 都不匹配时，只以"命令是否成功"作最后依据。
fn classify_status(
    convention: StatusCodeConvention,
    code: Option<i32>,
    success: bool,
    text: &str,
) -> ServiceStatusKind {
    if text_says_not_installed(text) {
        return ServiceStatusKind::NotInstalled;
    }

    let by_code = match convention {
        StatusCodeConvention::WindowsScript => match code {
            Some(0) => Some(ServiceStatusKind::Running),
            Some(1) => Some(ServiceStatusKind::Dead),
            Some(2) => Some(ServiceStatusKind::NotInstalled),
            _ => None,
        },
        StatusCodeConvention::SystemdLsb => match code {
            Some(0) => Some(ServiceStatusKind::Running),
            // LSB：1=有 pid 但已死，2=有 lock 但已死，3=没在运行
            Some(1) | Some(2) | Some(3) => Some(ServiceStatusKind::Dead),
            // systemd：单元不存在
            Some(4) => Some(ServiceStatusKind::NotInstalled),
            _ => None,
        },
        // launchd 的退出码随版本与调用方式而变，不做码位映射。
        StatusCodeConvention::Launchd => None,
    };

    by_code.unwrap_or(if success {
        ServiceStatusKind::Running
    } else {
        ServiceStatusKind::Dead
    })
}

#[cfg(test)]
mod status_tests {
    use super::*;

    const WIN: StatusCodeConvention = StatusCodeConvention::WindowsScript;
    const SD: StatusCodeConvention = StatusCodeConvention::SystemdLsb;
    const LAUNCHD: StatusCodeConvention = StatusCodeConvention::Launchd;

    #[test]
    fn windows_script_codes_keep_working() {
        assert_eq!(
            classify_status(WIN, Some(0), true, ""),
            ServiceStatusKind::Running
        );
        assert_eq!(
            classify_status(WIN, Some(1), false, ""),
            ServiceStatusKind::Dead
        );
        assert_eq!(
            classify_status(
                WIN,
                Some(2),
                false,
                "\n❌ SmartDNS service is NOT installed."
            ),
            ServiceStatusKind::NotInstalled
        );
    }

    #[test]
    fn systemd_fresh_machine_is_not_installed() {
        // 🌟 P1-7 的回归点：全新机器上单元不存在，systemctl 返回 4。
        // 修复前这里被判成 Dead → install() 直接打印 "already installed" 就返回。
        assert_eq!(
            classify_status(
                SD,
                Some(4),
                false,
                "Unit smartdns-rs.service could not be found."
            ),
            ServiceStatusKind::NotInstalled
        );
        assert_eq!(
            classify_status(SD, Some(0), true, "Active: active (running)"),
            ServiceStatusKind::Running
        );
        assert_eq!(
            classify_status(SD, Some(3), false, "Active: inactive (dead)"),
            ServiceStatusKind::Dead
        );
    }

    #[test]
    fn systemd_text_wins_when_exit_code_differs() {
        // 退出码退回 3（已停止）但文本明说单元不存在 → 仍判未安装
        assert_eq!(
            classify_status(SD, Some(3), false, "Unit smartdns-rs.service not-found"),
            ServiceStatusKind::NotInstalled
        );
    }

    #[test]
    fn lsb_initd_codes() {
        assert_eq!(
            classify_status(
                SD,
                Some(1),
                false,
                "smartdns-rs is dead but pid file exists"
            ),
            ServiceStatusKind::Dead
        );
        assert_eq!(
            classify_status(SD, Some(2), false, "smartdns-rs dead but subsys locked"),
            ServiceStatusKind::Dead
        );
    }

    #[test]
    fn runit_missing_service_is_not_installed() {
        assert_eq!(
            classify_status(
                SD,
                Some(1),
                false,
                "fail: smartdns-rs: unable to change to service directory: file does not exist"
            ),
            ServiceStatusKind::NotInstalled
        );
    }

    #[test]
    fn launchd_ignores_exit_code_and_reads_text() {
        // 未装：文本说找不到
        assert_eq!(
            classify_status(
                LAUNCHD,
                Some(113),
                false,
                "Could not find service \"smartdns-rs\" in domain for system"
            ),
            ServiceStatusKind::NotInstalled
        );
        // 已加载：不以退出码下判
        assert_eq!(
            classify_status(LAUNCHD, Some(0), true, "-\t0\tsmartdns-rs"),
            ServiceStatusKind::Running
        );
        // 装了但没加载：既没成功也没"不存在"字样 → 保守判 Dead（可用性优先）
        assert_eq!(
            classify_status(LAUNCHD, Some(1), false, "smartdns-rs: not loaded"),
            ServiceStatusKind::Dead
        );
    }

    #[test]
    fn unknown_codes_fall_back_to_exit_status() {
        assert_eq!(
            classify_status(SD, Some(7), true, "weird"),
            ServiceStatusKind::Running
        );
        assert_eq!(
            classify_status(WIN, None, false, "killed by signal"),
            ServiceStatusKind::Dead
        );
    }

    #[test]
    fn convention_follows_platform() {
        let expected = if cfg!(target_os = "windows") {
            StatusCodeConvention::WindowsScript
        } else if cfg!(target_os = "macos") {
            StatusCodeConvention::Launchd
        } else {
            StatusCodeConvention::SystemdLsb
        };
        assert_eq!(StatusCodeConvention::for_current_os(), expected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfg_if::cfg_if;

    #[test]
    fn test_service_command() {
        let cmd = {
            cfg_if! {
                if #[cfg(target_os="windows")] {
                    ServiceCommand {
                        program: "powershell.exe".into(),
                        args: vec![
                                "-NoProfile".into(),
                                "-Command".into(),
                                "Write-Output 'Windows'".into()
                            ],
                    }
                } else {
                    ServiceCommand {
                        program: "uname".into(),
                        args: vec![
                            "-a".into(),
                        ],
                    }
                }
            }
        };

        let output = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(output.stdout.as_slice()).to_string();

        #[cfg(unix)]
        assert_eq!(format!("{cmd}"), "uname -a");

        cfg_if! {
            if #[cfg(target_os="windows")] {
                assert!(stdout.contains("Windows"));
            } else if #[cfg(target_os="linux")] {
                assert!(stdout.contains("Linux"));
            } else if #[cfg(target_os="macos")] {
                assert!(stdout.contains("Darwin"));
            } else if #[cfg(target_os="android")] {
                assert!(stdout.contains("Android"));
            } else {
                unimplemented!()
            }
        }
    }
}

/// 🔐 B2：`service start/stop/restart/uninstall` 遇到"服务未安装"时统一用这个错误 ——
/// 必须能被上层察觉（退出码非 0），而不是只打印一行 ❌ 就返回 Ok（脚本/CI 会被骗）。
fn not_installed_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "smartdns service is not installed (run `smartdns service install` first)",
    )
}
